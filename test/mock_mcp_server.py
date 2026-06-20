#!/usr/bin/env python3
"""Dependency-free mock MCP server for exercising the nmap NSE scripts.

Implements enough of MCP's HTTP transports to validate detection + enumeration:

  Streamable HTTP (current):
    POST /mcp      JSON-RPC; replies application/json; issues Mcp-Session-Id.
    POST /mcpsse   Same, but frames the reply as text/event-stream (SSE parser test).

  Legacy HTTP+SSE (2024-11-05):
    GET  /sse                       Opens an SSE stream, emits `event: endpoint`
                                    pointing at /messages?sessionId=<sid>, then keeps
                                    the stream open.
    POST /messages?sessionId=<sid>  Accepts JSON-RPC (202), and pushes the JSON-RPC
                                    *response* back over the matching open SSE stream.

  OAuth-gated (auth posture test):
    POST /authmcp                            -> 401 + WWW-Authenticate: Bearer
                                                resource_metadata=".../.well-known/..."
    GET  /.well-known/oauth-protected-resource -> protected-resource metadata JSON

Usage:  python3 mock_mcp_server.py [port]      (default 8000)
"""
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

SERVER_INFO = {"name": "acme-toolserver", "version": "1.4.2"}
# Protocol version the mock advertises. Override to test that the scripts report whatever
# the server negotiates, e.g. MCP_PROTOCOL=2024-11-05 / 2025-03-26 / 2025-06-18.
PROTOCOL = os.environ.get("MCP_PROTOCOL", "2025-06-18")
SESSION_ID = "mock-session-0001"

# A valid bearer token for the OAuth-gated endpoint (/authmcp). Supplying
# `--script-args mcp.token=<this>` lets the scripts complete an authenticated
# handshake; any other/absent token gets a 401 challenge.
AUTH_TOKEN = "mock-test-token-abc123"

TOOLS = [
    {"name": "run_command",
     "description": "Execute a shell command on the host",
     "inputSchema": {"type": "object", "properties": {"cmd": {"type": "string"}}}},
    {"name": "read_file",
     "description": "Read a file from disk",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}},
    {"name": "search_web",
     "description": "Search the web for a query",
     "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}}},
    {"name": "get_weather",
     "description": "Get the weather for a city",
     "inputSchema": {"type": "object", "properties": {"city": {"type": "string"}}}},
]
RESOURCES = [
    {"uri": "file:///etc/", "name": "etc"},
    {"uri": "db://customers", "name": "customers"},
]
TEMPLATES = [{"uriTemplate": "file:///{path}", "name": "anyfile"}]
PROMPTS = [{"name": "summarize", "description": "Summarize text"}]

# Open legacy SSE streams: sessionId -> (wfile, lock)
SSE_STREAMS = {}
SID_LOCK = threading.Lock()
SID_SEQ = [0]


def handle_rpc(msg):
    method = msg.get("method")
    rid = msg.get("id")
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": PROTOCOL,
            "capabilities": {"tools": {}, "resources": {"subscribe": True},
                             "prompts": {}, "logging": {}},
            "serverInfo": SERVER_INFO}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}}
    if method == "resources/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"resources": RESOURCES}}
    if method == "resources/templates/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"resourceTemplates": TEMPLATES}}
    if method == "prompts/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"prompts": PROMPTS}}
    if method and method.startswith("notifications/"):
        return None  # notification -> no response
    return {"jsonrpc": "2.0", "id": rid,
            "error": {"code": -32601, "message": "Method not found"}}


OAUTH_METADATA = {
    "resource": "https://mcp.example.com/authmcp",
    "authorization_servers": ["https://auth.example.com"],
    "scopes_supported": ["mcp:tools", "mcp:resources"],
    "bearer_methods_supported": ["header"],
}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _json(self, code, obj, extra_headers=None):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _empty(self, code, extra_headers=None):
        self.send_response(code)
        self.send_header("Content-Length", "0")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()

    # ----- POST: streamable handshake, legacy message channel, auth gate -----
    def do_POST(self):
        path = urlparse(self.path).path.rstrip("/") or "/"

        # OAuth-gated endpoint: a valid bearer token completes the handshake like
        # /mcp; an absent/incorrect token gets a 401 challenge.
        if path == "/authmcp":
            auth = self.headers.get("Authorization", "")
            if auth != f"Bearer {AUTH_TOKEN}":
                host = self.headers.get("Host", "localhost")
                rm = f'Bearer resource_metadata="http://{host}/.well-known/oauth-protected-resource"'
                self._empty(401, {"WWW-Authenticate": rm})
                return
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length) if length else b""
            try:
                msg = json.loads(raw or b"{}")
            except json.JSONDecodeError:
                self._empty(400)
                return
            reply = handle_rpc(msg)
            if reply is None:
                self._empty(202)
                return
            self._json(200, reply, {"Mcp-Session-Id": SESSION_ID})
            return

        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b""
        try:
            msg = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            self._empty(400)
            return

        # Legacy message channel: 202, then push response onto the SSE stream.
        if path == "/messages":
            sid = (parse_qs(urlparse(self.path).query).get("sessionId") or [None])[0]
            reply = handle_rpc(msg)
            self._empty(202)
            if reply is not None and sid:
                stream = SSE_STREAMS.get(sid)
                if stream:
                    wfile, lock = stream
                    framed = b"event: message\ndata: " + json.dumps(reply).encode() + b"\n\n"
                    try:
                        with lock:
                            wfile.write(framed)
                            wfile.flush()
                    except (BrokenPipeError, ConnectionResetError, OSError):
                        pass
            return

        # Streamable HTTP handshake endpoints.
        if path not in ("/mcp", "/mcpsse"):
            self._empty(404)
            return
        reply = handle_rpc(msg)
        if reply is None:
            self._empty(202)
            return
        body = json.dumps(reply).encode()
        if path == "/mcpsse":
            framed = b"event: message\ndata: " + body + b"\n\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(framed)))
            self.send_header("Mcp-Session-Id", SESSION_ID)
            self.end_headers()
            self.wfile.write(framed)
        else:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Mcp-Session-Id", SESSION_ID)
            self.end_headers()
            self.wfile.write(body)

    # ----- GET: legacy SSE stream and OAuth metadata -----
    def do_GET(self):
        path = urlparse(self.path).path.rstrip("/") or "/"

        if path == "/.well-known/oauth-protected-resource":
            self._json(200, OAUTH_METADATA)
            return

        if path == "/sse":
            with SID_LOCK:
                SID_SEQ[0] += 1
                sid = f"legacy-{SID_SEQ[0]:04d}"
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            lock = threading.Lock()
            SSE_STREAMS[sid] = (self.wfile, lock)
            try:
                with lock:
                    self.wfile.write(
                        b"event: endpoint\ndata: /messages?sessionId=" + sid.encode() + b"\n\n")
                    self.wfile.flush()
                # Keep the stream open; ping until the client disconnects.
                for _ in range(160):
                    time.sleep(0.25)
                    with lock:
                        self.wfile.write(b": ping\n\n")
                        self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            finally:
                SSE_STREAMS.pop(sid, None)
            return

        self._empty(404)


class QuietServer(ThreadingHTTPServer):
    """The raw-socket transport closes connections early by design, which would otherwise
    spew ConnectionResetError/BrokenPipeError tracebacks. Swallow those; re-raise the rest."""
    def handle_error(self, request, client_address):
        if not isinstance(sys.exc_info()[1], (ConnectionResetError, BrokenPipeError)):
            super().handle_error(request, client_address)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    srv = QuietServer(("127.0.0.1", port), Handler)
    print(f"mock MCP server on http://127.0.0.1:{port} (protocol {PROTOCOL})")
    print("  streamable: POST /mcp, POST /mcpsse")
    print("  legacy:     GET /sse + POST /messages")
    print("  oauth-gated: POST /authmcp (Bearer token) + GET /.well-known/oauth-protected-resource")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass

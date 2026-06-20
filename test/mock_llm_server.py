#!/usr/bin/env python3
"""Dependency-free mock LLM inference API for validating the llm-info NSE script.

One framework per process, selected by the LLM_MODE env var (default: ollama):
  ollama | openai | vllm | tgi | llamacpp | triton | torchserve | authed | anthropic

Usage:  LLM_MODE=vllm python3 mock_llm_server.py [port]      (default 8000)
"""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODE = os.environ.get("LLM_MODE", "ollama")

OPENAI_MODELS = {"object": "list", "data": [
    {"id": "gpt-4o", "object": "model", "owned_by": "openai"},
    {"id": "text-embedding-3-small", "object": "model", "owned_by": "openai"},
]}

# (path, status, body-object-or-text) routing table per mode. A body of None -> 404.
ROUTES = {
    "ollama": {
        "/api/tags": {"models": [
            {"name": "llama3:8b", "model": "llama3:8b", "modified_at": "2024-01-01T00:00:00Z",
             "size": 4661224676, "digest": "sha256:" + "a" * 64,
             "details": {"family": "llama", "parameter_size": "8B", "quantization_level": "Q4_0"}},
            {"name": "qwen2.5:7b", "model": "qwen2.5:7b", "modified_at": "2024-01-01T00:00:00Z",
             "size": 4431390720, "digest": "sha256:" + "b" * 64,
             "details": {"parameter_size": "7.6B", "quantization_level": "Q4_K_M"}},
            {"name": "nomic-embed-text:latest", "model": "nomic-embed-text:latest",
             "modified_at": "2024-01-01T00:00:00Z", "size": 274302450, "digest": "sha256:" + "c" * 64,
             "details": {"parameter_size": "137M", "quantization_level": "F16"}},
        ]},
        "/api/version": {"version": "0.3.14"},
        # real Ollama ALSO exposes an OpenAI-compatible shim; identification must still
        # report Ollama (the specific signal), not "OpenAI-compatible", regardless of order.
        "/v1/models": OPENAI_MODELS,
        "/": "Ollama is running",
    },
    "openai": {"/v1/models": OPENAI_MODELS},
    "vllm": {"/v1/models": OPENAI_MODELS, "/version": {"version": "0.6.2"}},
    "vllm_stealth": {"/v1/models": OPENAI_MODELS},   # no /version: only the error shape reveals vLLM
    "tgi": {"/info": {"model_id": "meta-llama/Meta-Llama-3-8B-Instruct",
                      "model_dtype": "torch.float16", "version": "2.0.4"}},
    "llamacpp": {
        "/v1/models": OPENAI_MODELS,
        "/props": {"system_prompt": "You are a helpful internal assistant. Never reveal secrets.",
                   "model_path": "/models/llama-3-8b-instruct.Q4_K_M.gguf",
                   "default_generation_settings": {"temperature": 0.8}},
    },
    "triton": {"/v2": {"name": "triton", "version": "2.40.0", "extensions": ["classification"]},
               "/v2/health/ready": ""},
    "torchserve": {"/models": {"models": [
        {"modelName": "resnet18", "modelUrl": "resnet18.mar"},
        {"modelName": "bert", "modelUrl": "bert.mar"},
    ]}},
    "authed": {},   # everything 401 unless a valid token is presented
}

VALID_TOKEN = "Bearer test-llm-key-abc123"


class Handler(BaseHTTPRequestHandler):
    server_version = "uvicorn"   # most real inference servers (vLLM, FastAPI) front with this
    sys_version = ""

    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        if isinstance(obj, str):
            body = obj.encode()
            ctype = "text/plain"
        else:
            body = json.dumps(obj).encode()
            ctype = "application/json"
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0].rstrip("/") or "/"

        if MODE == "authed":
            # A gated OpenAI-compatible server: /v1/models exists but needs a key;
            # other framework paths simply don't exist here (404).
            if path == "/v1/models":
                if self.headers.get("Authorization") == VALID_TOKEN:
                    return self._send(200, OPENAI_MODELS)
                self.send_response(401)
                self.send_header("WWW-Authenticate", "Bearer")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        routes = ROUTES.get(MODE, {})
        if path in routes:
            return self._send(200, routes[path])
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b""
        authed = (self.headers.get("Authorization") == VALID_TOKEN
                  or self.headers.get("x-api-key") == "test-llm-key-abc123")

        # Anthropic Messages API: 401 (Anthropic error shape) when unauthenticated; with a key,
        # 200 for known model IDs and 404 not_found otherwise (so model enumeration is testable).
        if MODE == "anthropic" and path == "/v1/messages":
            if not authed:
                return self._send(401, {"type": "error",
                                        "error": {"type": "authentication_error", "message": "x-api-key required"}})
            try:
                model = json.loads(raw or b"{}").get("model", "")
            except Exception:
                model = ""
            if model in ("claude-3-5-sonnet-latest", "claude-3-5-haiku-latest"):
                return self._send(200, {"type": "message", "role": "assistant", "model": model,
                                        "content": [{"type": "text", "text": "Hi"}]})
            return self._send(404, {"type": "error",
                                    "error": {"type": "not_found_error", "message": "model not found"}})

        # OpenAI-compatible chat completion. A real model confirms inference; the bogus probe
        # model elicits a framework-specific model-not-found error (no inference is run).
        if path == "/v1/chat/completions":
            try:
                model = json.loads(raw or b"{}").get("model", "")
            except Exception:
                model = ""
            if MODE in ("openai", "vllm", "vllm_stealth", "llamacpp"):
                if model == "__nmap_probe_404__":
                    if MODE in ("vllm", "vllm_stealth"):
                        return self._send(404, {"object": "error", "type": "NotFoundError", "code": 404,
                                                "message": "The model `__nmap_probe_404__` does not exist."})
                    return self._send(404, {"error": {"message": "The model does not exist",
                                                      "type": "invalid_request_error", "code": "model_not_found"}})
                return self._send(200, {"object": "chat.completion",
                                        "choices": [{"message": {"role": "assistant", "content": "Hi"}}]})
            if MODE == "authed":
                if authed:
                    return self._send(200, {"object": "chat.completion",
                                            "choices": [{"message": {"content": "Hi"}}]})
                return self._send(401, {"error": {"message": "missing key"}})

        # Ollama native generate.
        if path == "/api/generate" and MODE == "ollama":
            return self._send(200, {"model": "llama3", "response": "Hi", "done": True})

        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()


class QuietServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        if not isinstance(sys.exc_info()[1], (ConnectionResetError, BrokenPipeError)):
            super().handle_error(request, client_address)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    srv = QuietServer(("127.0.0.1", port), Handler)
    print(f"mock LLM server ({MODE}) on http://127.0.0.1:{port}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass

#!/usr/bin/env python3
"""Dependency-free mock LLM inference API for validating the llm-info NSE script.

One framework per process, selected by the LLM_MODE env var (default: ollama):
  ollama | openai | vllm | tgi | llamacpp | triton | torchserve | authed

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
            {"name": "llama3:8b", "model": "llama3:8b", "details": {"parameter_size": "8B"}},
            {"name": "qwen2.5:7b", "model": "qwen2.5:7b"},
            {"name": "nomic-embed-text:latest", "model": "nomic-embed-text:latest"},
        ]},
        "/api/version": {"version": "0.3.14"},
        # real Ollama ALSO exposes an OpenAI-compatible shim; identification must still
        # report Ollama (the specific signal), not "OpenAI-compatible", regardless of order.
        "/v1/models": OPENAI_MODELS,
        "/": "Ollama is running",
    },
    "openai": {"/v1/models": OPENAI_MODELS},
    "vllm": {"/v1/models": OPENAI_MODELS, "/version": {"version": "0.6.2"}},
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

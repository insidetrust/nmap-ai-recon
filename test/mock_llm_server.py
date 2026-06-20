#!/usr/bin/env python3
"""Dependency-free mock LLM inference API for validating the llm-info NSE script.

One framework per process, selected by the LLM_MODE env var (default: ollama):
  ollama | openai | vllm | vllm_stealth | sglang | tgi | tei | llamacpp | koboldcpp
  | triton | torchserve | torchserve_inference | authed | anthropic | openai_plugin
  | openwebui | openwebui_open | openwebui_onboarding | librechat | nextchat | lobechat
  | flowise | anythingllm
  | xinference | localai | litellm | litellm_swagger | bentoml | comfyui | sdwebui | gradio
  | ray | chromadb | qdrant | weaviate | milvus | marqo | jan | langflow | lollms
  | lobechat_welcome

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

# Prometheus exposition fragments: a served model name leaks in the metric label, and the
# metric-name prefix (vllm:/sglang:/tgi_) confirms the framework.
VLLM_METRICS = (
    "# HELP vllm:num_requests_running Number of requests currently running.\n"
    "# TYPE vllm:num_requests_running gauge\n"
    'vllm:num_requests_running{model_name="meta-llama/Meta-Llama-3-8B-Instruct"} 1.0\n'
)
SGLANG_METRICS = (
    "# HELP sglang:num_running_reqs Number of running requests.\n"
    "# TYPE sglang:num_running_reqs gauge\n"
    'sglang:num_running_reqs{model_name="meta-llama/Meta-Llama-3-8B-Instruct"} 0.0\n'
)

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
    "vllm": {"/v1/models": OPENAI_MODELS, "/version": {"version": "0.6.2"}, "/metrics": VLLM_METRICS},
    "vllm_stealth": {"/v1/models": OPENAI_MODELS},   # no /version: only the error shape reveals vLLM
    # SGLang: OpenAI-compatible, identified by /get_model_info; /metrics confirms + leaks model.
    # Its /v1/models lists the single served model (not a generic catalogue).
    "sglang": {"/v1/models": {"object": "list", "data": [
                   {"id": "meta-llama/Meta-Llama-3-8B-Instruct", "object": "model"}]},
               "/get_model_info": {"model_path": "meta-llama/Meta-Llama-3-8B-Instruct",
                                   "is_generation": True},
               "/metrics": SGLANG_METRICS},
    "tgi": {"/info": {"model_id": "meta-llama/Meta-Llama-3-8B-Instruct",
                      "model_dtype": "torch.float16", "version": "2.0.4"}},
    # HuggingFace Text Embeddings Inference: /info marks model_type embedding (not generation).
    "tei": {"/info": {"model_id": "BAAI/bge-large-en-v1.5", "version": "1.2.0",
                      "model_type": {"embedding": {"pooling": "cls"}}}},
    # KoboldCpp: native KoboldAI endpoints AND simultaneous Ollama (/api/tags + /api/version),
    # OpenAI (/v1/models) and llama.cpp (/props) emulation - exactly as a real KoboldCpp 1.115.2
    # responds. Identification must still report KoboldCpp (the unambiguous /api/extra/version
    # banner) regardless of detector order, even though Ollama and llama.cpp also match.
    "koboldcpp": {"/api/extra/version": {"result": "KoboldCpp", "version": "1.66"},
                  "/api/v1/model": {"result": "koboldcpp/Llama-3-8B-Instruct"},
                  "/v1/models": OPENAI_MODELS,
                  "/api/tags": {"models": [{"name": "koboldcpp",
                                            "model": "koboldcpp/Llama-3-8B-Instruct:latest",
                                            "modified_at": "2024-07-19T15:26:55Z"}]},
                  "/api/version": {"version": "0.7.0"},
                  "/props": {"chat_template": "{% for message in messages %}..."}},
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
    # TorchServe exposing only its inference port (8080): no /models list, but the OpenAPI-style
    # /api-description document (title "TorchServe APIs") still identifies it.
    "torchserve_inference": {"/api-description": {
        "openapi": "3.0.1", "info": {"title": "TorchServe APIs",
                                     "description": "TorchServe is a tool for serving neural net models"},
        "paths": {"/ping": {"get": {"operationId": "ping"}}}}},
    "authed": {},   # everything 401 unless a valid token is presented
    # Web UIs / gateways: front-ends that proxy to a backend, not inference endpoints. The
    # access posture (open / self-registration / login) is read from each UI's config.
    # Open WebUI with open self-registration (enable_signup true).
    "openwebui": {"/api/config": {"status": True, "name": "Open WebUI", "version": "0.5.20",
                                  "features": {"auth": True, "enable_signup": True}},
                  "/api/version": {"version": "0.5.20"}},
    # Open WebUI with authentication disabled entirely (WEBUI_AUTH=false): fully open access.
    "openwebui_open": {"/api/config": {"status": True, "name": "Open WebUI", "version": "0.5.20",
                                       "features": {"auth": False, "enable_signup": False}}},
    # Open WebUI freshly deployed (onboarding true): no admin yet, first visitor claims admin.
    "openwebui_onboarding": {"/api/config": {"status": True, "onboarding": True,
                                             "name": "Open WebUI", "version": "0.9.6",
                                             "features": {"auth": True, "enable_signup": True}}},
    "librechat": {"/api/config": {"appTitle": "LibreChat", "registrationEnabled": True,
                                  "emailLoginEnabled": True, "socialLogins": ["google", "github"],
                                  "serverDomain": "http://localhost:3080"}},
    # NextChat / ChatGPT-Next-Web with no access code (needCode false): open use of the backend.
    "nextchat": {"/api/config": {"needCode": False, "hideUserApiKey": False,
                                 "disableGPT4": False, "customModels": ""}},
    "lobechat": {"/manifest.json": {"name": "LobeChat", "short_name": "LobeChat",
                                    "description": "LobeChat is an open-source AI chat framework"}},
    "flowise": {"/api/v1/version": {"version": "2.2.0"}},
    "anythingllm": {"/api/ping": {"online": True},
                    "/": "<!doctype html><title>AnythingLLM</title><div id=app></div>"},

    # ---- Inference / serving frameworks added beyond the original OpenAI-family set ----
    # Xinference: OpenAI-compatible; disambiguated from a plain OpenAI server by the
    # Xinference-only /v1/cluster/info (supervisor/worker metadata + version).
    "xinference": {"/v1/cluster/info": {"supervisor": "127.0.0.1:9997", "workers": 1,
                                        "version": "0.16.3", "git_version": "0.16.3"},
                   "/v1/models": {"object": "list", "data": [
                       {"id": "qwen2.5-instruct", "object": "model", "owned_by": "xinference"}]}},
    # LocalAI: OpenAI drop-in; the LocalAI-only /models/available gallery distinguishes it.
    "localai": {"/models/available": [{"name": "luna-ai-llama2", "gallery": "model-gallery"}],
                "/v1/models": {"object": "list", "data": [
                    {"id": "gpt-4", "object": "model"}, {"id": "luna-ai-llama2", "object": "model"}]}},
    # LiteLLM proxy/gateway: readiness payload carries litellm_version.
    "litellm": {"/health/readiness": {"status": "healthy", "db": "connected",
                                      "litellm_version": "1.44.8"}},
    "litellm_swagger": {"/": "<!doctype html><title>LiteLLM API - Swagger UI</title>"},
    # BentoML prediction service: OpenAPI schema names BentoML in info.title.
    "bentoml": {"/docs.json": {"openapi": "3.0.2",
                               "info": {"title": "my_service (BentoML Prediction Service)",
                                        "version": "1.3.0",
                                        "description": "BentoML prediction service"}}},
    # ComfyUI: /system_stats returns system.comfyui_version + a device inventory.
    "comfyui": {"/system_stats": {"system": {"os": "posix", "python_version": "3.11.9",
                                             "comfyui_version": "0.3.4", "pytorch_version": "2.4.1"},
                                  "devices": [{"name": "cuda:0 NVIDIA RTX 4090", "type": "cuda",
                                               "vram_total": 25757220864, "vram_free": 24000000000}]}},
    # Stable Diffusion WebUI (AUTOMATIC1111): the served page carries the unambiguous trio,
    # and /sdapi/v1/options leaks the loaded checkpoint.
    "sdwebui": {"/": ('<!doctype html><html><head><script src="hires_fix.js"></script>'
                      '<meta name="generator" content="AUTOMATIC1111"></head>'
                      '<body><script>window.gradio_config = {};</script></body></html>'),
                "/sdapi/v1/options": {"sd_model_checkpoint": "v1-5-pruned-emaonly.safetensors"}},
    # Gradio: /config returns version + a component/dependency graph (and app mode).
    "gradio": {"/config": {"version": "4.44.0", "mode": "blocks", "components": [],
                           "dependencies": []},
               "/": '<!doctype html><html><body><gradio-app></gradio-app></body></html>'},
    # Ray dashboard: /api/version is wrapped as {"result":true,"data":{...}} with the Ray version.
    "ray": {"/api/version": {"result": True, "msg": "",
                             "data": {"version": "1.0", "rayVersion": "2.35.0",
                                      "rayCommit": "abc123", "sessionName": "session_2024"}}},

    # ---- Vector databases ----
    # ChromaDB: heartbeat returns {"nanosecond heartbeat": <int>}; version endpoint is a string.
    "chromadb": {"/api/v2/heartbeat": {"nanosecond heartbeat": 1719795600000000000},
                 "/api/v2/version": "0.5.5"},
    # Qdrant: REST root is the telemetry banner; /collections lists stored collections.
    "qdrant": {"/": {"title": "qdrant - vector search engine", "version": "1.11.0",
                     "commit": "ffda0b90c8c44fc43c99adab518b9787fe57bde6"},
               "/collections": {"result": {"collections": [{"name": "documents"},
                                                            {"name": "embeddings"}]},
                                "status": "ok", "time": 0.00003}},
    # Weaviate: /v1/meta returns hostname + version + modules.
    "weaviate": {"/v1/meta": {"hostname": "http://[::]:8080", "version": "1.26.1",
                              "modules": {"text2vec-openai": {}}}},
    # Milvus / Attu console: the served page title carries "Milvus".
    "milvus": {"/": "<!doctype html><title>Milvus Insight</title><div id=root></div>"},
    # Marqo tensor search engine: the root welcome banner + version.
    "marqo": {"/": {"message": "Welcome to Marqo", "version": "2.11.0"}},

    # ---- Additional web UIs / gateways ----
    # Jan: OpenAI-compatible desktop server; the Jan-only /healthz pairs with /v1/models.
    "jan": {"/healthz": {"status": "ok"},
            "/v1/models": {"object": "list", "data": [
                {"id": "llama3.2-3b-instruct", "object": "model"}]}},
    # Langflow: BOTH it and Flowise serve /api/v1/version; Langflow's carries package=Langflow.
    "langflow": {"/api/v1/version": {"version": "1.0.19", "package": "Langflow",
                                     "main": "1.0.19"},
                 "/": "<!doctype html><title>Langflow</title><div id=root></div>"},
    # LoLLMs WebUI: the served page carries the literal welcome banner.
    "lollms": {"/": "<!doctype html><html><body><h1>LoLLMS WebUI - Welcome</h1></body></html>"},
    # LobeChat served via the /welcome page (manifest renamed/absent).
    "lobechat_welcome": {"/welcome": "<!doctype html><body><h1>Welcome to LobeChat</h1></body>"},
    # OpenAI plugin manifest: /.well-known/ai-plugin.json describes a backend API for an LLM
    # agent (schema_version + name_for_model anchor); the api.url discloses the backend endpoint.
    "openai_plugin": {"/.well-known/ai-plugin.json": {
        "schema_version": "v1", "name_for_model": "weather",
        "name_for_human": "Weather Plugin",
        "description_for_model": "Get the weather", "description_for_human": "Get the weather",
        "auth": {"type": "none"},
        "api": {"type": "openapi", "url": "https://example.com/openapi.yaml"},
        "logo_url": "https://example.com/logo.png", "contact_email": "x@example.com"}},
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

        # Triton/KServe read-only model-repository index (a listing call, not a load/unload):
        # POST /v2/repository/index -> [{"name":...,"version":...,"state":...}, ...].
        if path == "/v2/repository/index" and MODE == "triton":
            return self._send(200, [
                {"name": "resnet50", "version": "1", "state": "READY"},
                {"name": "bert_qa", "version": "2", "state": "READY"},
            ])

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

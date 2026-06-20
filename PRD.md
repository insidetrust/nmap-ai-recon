# PRD: Nmap NSE scripts for AI infrastructure recon

**Status:** MCP detection/enumeration and LLM inference-API detection shipped; active
inference probing (`llm-probe`) and upstream submission pending.
**Author:** Ben Williams (NCC Group)
**Date:** 2026-06-08 (updated 2026-06-20)

---

## 1. Problem statement

Two classes of AI infrastructure are increasingly exposed on enterprise and developer
networks, and nmap can fingerprint neither:

- **MCP (Model Context Protocol) servers** expose LLM-callable tools, resources, and
  prompts. An exposed, unauthenticated MCP server is remote-code-execution-as-a-service: it
  may offer tools such as `execute_shell`, `read_file`, or `query_database`.
- **LLM inference APIs** (OpenAI-compatible, Ollama, vLLM, TGI, llama.cpp, Triton/KServe,
  TorchServe, ...) serve model inference. An exposed, unauthenticated endpoint means free
  compute on someone else's bill, disclosure of proprietary/fine-tuned model names, and in
  some frameworks leaked system prompts or cached context.

Both are routinely deployed on dev ports bound to `0.0.0.0` with no authentication.

### Prior art (verified 2026-06)
- **nmap / Metasploit:** nothing for scanning either MCP services or inference APIs. (The
  "nmap/Metasploit + MCP" projects are the inverse - they wrap the tool *as* an MCP server.)
- **Tenable Web App Scanning** covers MCP commercially (plugins 114790 / 114791 / 114965).
  No open, free, CLI-native nmap capability exists for either class.

## 2. Goals

| # | Goal | Success criteria |
|---|------|------------------|
| G1 | Detect MCP servers and LLM inference APIs over HTTP(S) | Identifies the transports/frameworks below; integrates with `-sV` |
| G2 | Fingerprint + version | MCP: `serverInfo` + `protocolVersion`. Inference: framework, version (native endpoint + `Server` header), model inventory |
| G3 | Enumerate exposure | MCP: tools/resources/prompts. Inference: models, auth state, info leaks |
| G4 | Flag security conditions | Unauthenticated access; dangerous MCP tools/params; exposed inference (cost abuse, model/prompt disclosure) |
| G5 | Be a good NSE citizen | Correct categories, safe by default, configurable, order-independent + low-false-positive identification |

### Non-goals
- Exploiting MCP tools: the MCP scripts never call `tools/call`.
- `llm-info` sends at most a single minimal "hello" completion by default to confirm
  inference and detect list-less APIs (`llm.probe=false` disables it); it runs nothing
  heavier. Authorised testing only.
- stdio-transport MCP servers (local subprocess; not network-reachable).
- Authentication brute force / token theft.

## 3. Deliverables

### 3.1 MCP (shipped)
- **`mcp-info`** (`discovery, safe, version`) - JSON-RPC `initialize` handshake over
  Streamable HTTP with a legacy HTTP+SSE fallback; OAuth 2.1 protected-resource discovery
  (RFC 9728); reports transport, server name/version, protocol version, capabilities,
  session statefulness, auth posture; `-sV` integration. Optional `mcp.token` for
  authenticated enumeration.
- **`mcp-enum`** (`discovery, safe`) - read-only `tools/list`, `resources/list`,
  `resources/templates/list`, `prompts/list`; risk-assesses each tool across name,
  description, and JSON input schema (categories: code-exec, file-access, network/ssrf,
  sql/db, secrets, privileged); flags unauthenticated exposure.
- **`mcp.lua`** - shared transports (raw-socket), handshake, OAuth discovery, enumeration.

### 3.2 LLM inference (shipped)
- **`llm-info`** (`discovery, safe`) - detects OpenAI-compatible (vLLM, SGLang, LiteLLM,
  LocalAI, LM Studio, text-generation-webui), Ollama, HF TGI and TEI, llama.cpp, KoboldCpp,
  Triton/KServe (v2), and TorchServe via read-only model-list / metadata / health endpoints.
  Reports framework, version (native endpoint + `Server` header), auth state, model
  inventory, and leaks (e.g. a llama.cpp system prompt via `/props`, or a served model name
  via a Prometheus `/metrics` endpoint). Identification is **order-independent**: every
  detector runs and the result is chosen by signal specificity (a framework-native endpoint
  outranks the generic `/v1/models`), so a server matching several signatures (e.g. Ollama,
  which also serves `/v1/models`) is reported by its most specific match. By default it also
  sends a single minimal "hello" completion (`max_tokens=1`) to confirm the endpoint serves
  inference and to detect formats with **no list endpoint - notably Anthropic**
  (`/v1/messages`); `llm.probe=false` makes it strictly read-only. For list-less or
  list-disabled APIs it **enumerates models** by probing a small built-in set of known model
  IDs (`200` vs `404 model-not-found`). It also fingerprints the stack from error-response
  shapes (`{object:error}` vLLM, `{detail}` FastAPI/Starlette, `{error: model_not_found}`
  canonical OpenAI), which refines a generic OpenAI match. Credentials via `llm.token`
  (Bearer) / `llm.header` (e.g. `x-api-key`, session cookie) test authenticated APIs. It also
  flags the common **AI web UIs / gateways** that front a backend (Open WebUI, LibreChat,
  NextChat, LobeChat, Flowise, AnythingLLM) - reported distinctly as a UI (never sent an active
  inference probe) with each UI's **access posture** read from its config (open /
  self-registration / login / unknown). Open and self-registration both grant unauthenticated
  use of the backend model, so they raise a security finding; login-gated UIs are reported
  without one. This is the UI equivalent of the unauthenticated-inference finding for APIs.
- **`llm.lua`** - shared detection + probe library (detectors, auth, active hello probe,
  model enumeration).

### 3.3 Shared / test
- `test/mock_mcp_server.py`, `test/mock_llm_server.py` - dependency-free mocks
  (one config/framework per process via env var).
- `test/run_matrix.sh` (MCP, 23 checks) and `test/run_llm_matrix.sh` (inference, 55 checks) -
  local regression matrices asserting expected output.

## 4. On the wire

- **MCP**: JSON-RPC 2.0. Streamable HTTP (`POST /mcp` with the `initialize` handshake;
  `application/json` or SSE response; optional `Mcp-Session-Id`) and legacy HTTP+SSE
  (`GET /sse` -> `endpoint` event -> POST messages, async responses on the SSE stream).
  Detection keys on a valid `initialize` result. Auth-gated servers advertise
  `WWW-Authenticate: Bearer resource_metadata=...` (RFC 9728).
- **Inference**: read-only model-list / metadata endpoints - `GET /v1/models`
  (OpenAI-compatible catch-all), `/api/tags` + `/api/version` (Ollama), `/version` (vLLM),
  `/get_model_info` (SGLang), `/info` (TGI/TEI), `/props` (llama.cpp),
  `/api/extra/version` + `/api/v1/model` (KoboldCpp), `/v2` (Triton/KServe),
  `/models` (TorchServe), and `/metrics` (Prometheus model-name leak). Auth state from
  `200` vs `401/403`; `Server` header as a secondary fingerprint. The active
  probe adds `POST /v1/chat/completions` (a minimal hello, or a bogus model for the
  error-shape fingerprint) and `POST /v1/messages` (Anthropic, which has no list endpoint).
- **Web UIs**: read-only config endpoints that also carry the auth posture - `GET /api/config`
  (Open WebUI `features.auth`/`enable_signup`, LibreChat `registrationEnabled`, NextChat
  `needCode`), `/manifest.json` (LobeChat), `/api/v1/version` (Flowise), `/api/ping` + the
  served SPA (AnythingLLM). No active inference request is ever sent to a UI.

## 5. Safety
- MCP scripts issue only `initialize` and `*/list`; `tools/call` is never invoked.
- `llm-info` detection is read-only; by default it also sends one minimal "hello" completion
  to confirm inference and detect list-less APIs (`llm.probe=false` disables it).
- The active probe and model-ID enumeration are bounded and for authorised assessments only.
- Neutral default User-Agent (a UA containing "nmap" is WAF-blocked); honour timeouts.
- Authorised testing only; findings are reported, not exploited.

## 6. Status

| Item | State |
|---|---|
| MCP: `mcp-info`, `mcp-enum`, `mcp.lua`, mock, matrix | Done; field-tested vs FastMCP, server-everything, and live public servers |
| Inference: `llm-info`, `llm.lua`, `mock_llm_server.py`, `run_llm_matrix.sh` | Done; order-independent + credentialed; active "hello" probe (on by default), Anthropic detection, model enumeration, error-condition fingerprinting, Prometheus `/metrics` leak, and AI web UI / gateway detection with access posture; field-tested vs real Ollama and KoboldCpp; 55-check regression matrix passes |
| Upstream nmap PR + standalone repo | Repo public (`insidetrust/nmap-ai-recon`); MCP PR branch staged; submission on hold |

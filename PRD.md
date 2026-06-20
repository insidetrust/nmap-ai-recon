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
- `llm-info` never sends an inference request (no model is run). Active probing is isolated
  in the explicitly intrusive `llm-probe`.
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

### 3.2 LLM inference (`llm-info` shipped; `llm-probe` planned)
- **`llm-info`** (`discovery, safe, version`) - read-only detection of OpenAI-compatible
  (vLLM, LiteLLM, LocalAI, LM Studio, text-generation-webui), Ollama, HF TGI, llama.cpp
  server, Triton/KServe (v2), and TorchServe via their model-list / metadata / health
  endpoints. Reports framework, version (native endpoint + `Server` header), auth state,
  model inventory, and leaks (e.g. a llama.cpp system prompt via `/props`). Identification
  is **order-independent**: every detector runs and the result is chosen by signal
  specificity (a framework-native endpoint outranks the generic `/v1/models`), so a server
  matching several signatures (e.g. Ollama, which also serves `/v1/models`) is reported by
  its most specific match. Credentials via `llm.token` (Bearer) / `llm.header` (e.g.
  `x-api-key`, session cookie). Never sends an inference request.
- **`llm-probe`** (`discovery, intrusive`) **[planned]** - opt-in active confirmation via a
  minimal inference request (`max_tokens=1`): the only way to fingerprint formats with no
  list endpoint (notably **Anthropic** `/v1/messages`); credentialed auth testing; **model
  enumeration** by probing a built-in set of known model IDs (`404 model-not-found` vs
  `200`/quota-error); **error-condition fingerprinting** (the error-body shape distinguishes
  OpenAI vs vLLM vs others and can leak a version). Intrusive because it runs the model.
- **`llm.lua`** - shared detection library (framework detectors, auth, credentials).

### 3.3 Shared / test
- `test/mock_mcp_server.py`, `test/mock_llm_server.py` - dependency-free mocks
  (one config/framework per process via env var).
- `test/run_matrix.sh` - local regression matrix asserting expected output.

## 4. On the wire

- **MCP**: JSON-RPC 2.0. Streamable HTTP (`POST /mcp` with the `initialize` handshake;
  `application/json` or SSE response; optional `Mcp-Session-Id`) and legacy HTTP+SSE
  (`GET /sse` -> `endpoint` event -> POST messages, async responses on the SSE stream).
  Detection keys on a valid `initialize` result. Auth-gated servers advertise
  `WWW-Authenticate: Bearer resource_metadata=...` (RFC 9728).
- **Inference**: read-only model-list / metadata endpoints - `GET /v1/models`
  (OpenAI-compatible catch-all), `/api/tags` + `/api/version` (Ollama), `/version` (vLLM),
  `/info` (TGI), `/props` (llama.cpp), `/v2` (Triton/KServe), `/models` (TorchServe).
  Auth state from `200` vs `401/403`; `Server` header as a secondary fingerprint.

## 5. Safety
- MCP scripts issue only `initialize` and `*/list`; `tools/call` is never invoked.
- `llm-info` requests only model-list / metadata / health endpoints; no inference is run.
- `llm-probe` is explicitly `intrusive` and opt-in (it sends a minimal inference request).
- Neutral default User-Agent (a UA containing "nmap" is WAF-blocked); honour timeouts.
- Authorised testing only; findings are reported, not exploited.

## 6. Status

| Item | State |
|---|---|
| MCP: `mcp-info`, `mcp-enum`, `mcp.lua`, mock, matrix | Done; field-tested vs FastMCP, server-everything, and live public servers |
| Inference: `llm-info`, `llm.lua`, `mock_llm_server.py` | Done; order-independent + credentialed; validated against the mock for all frameworks |
| Inference: `llm-probe` (active probe, model enumeration, Anthropic, error-condition fingerprinting) | Planned |
| Upstream nmap PR + standalone repo | Repo public (`insidetrust/nmap-ai-recon`); MCP PR branch staged; submission on hold |

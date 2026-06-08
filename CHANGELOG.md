# Changelog

## 0.4.0 — 2026-06-08 (M4: submission package)
- Added `WRITEUP.md` (research/advisory write-up) and `SUBMISSION.md` (Nmap PR package +
  conformance checklist).
- Added `LICENSE` (NSE files under the Nmap license for upstream; docs/tests under MIT).
- Validated NSEDoc renders via `nmap --script-help`; initialised git repository.

## 0.3.0 — 2026-06-08 (M3: refactor + field-testing)
- Extracted shared logic into the `mcp` nselib (`scripts/mcp.lua`); `mcp-info`/`mcp-enum`
  are now thin wrappers.
- Broadened heuristics: 15 candidate paths, expanded port set, "probe `-sV`-unrecognised
  services" portrule, and `mcp.allports`.
- Field-tested against the official Python SDK (FastMCP) and
  `@modelcontextprotocol/server-everything` (streamableHttp + sse), plus the live OAuth
  target and the mock.
- Hardening forced by real servers (all automatic): **raw-socket transport** (nmap's
  `http.post` hangs on FastMCP/uvicorn streamed SSE), **TLS auto-fallback**, **Host header
  with port** (DNS-rebinding `421`), and **valid `initialize` params** (`-32602`).
- Heuristic: flag environment-variable disclosure tools (e.g. `get-env`).
- Added `test/fastmcp_server.py`; mock extended to a full legacy-SSE + OAuth implementation.

## 0.2.0 — 2026-06-08 (M2: legacy enum, OAuth, -sV)
- Full legacy HTTP+SSE enumeration via raw-socket async response correlation.
- OAuth 2.1 protected-resource metadata parsing (RFC 9728).
- `-sV` flags MCP via the version-category `set_port_version` override; added
  `nmap-service-probes.mcp` fragment.
- **Finding:** a User-Agent containing "nmap" is blocked by AWS WAF/CloudFront (403 vs
  401); scripts default to a neutral UA (`mcp.ua`).

## 0.1.0 — 2026-06-08 (M1: initial build)
- `mcp-info` (detect/fingerprint) and `mcp-enum` (tools/resources/prompts) over Streamable
  HTTP, with dangerous-tool and unauthenticated-exposure flagging.
- Dependency-free mock server; PRD and README.

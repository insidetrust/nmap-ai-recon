# Changelog

## 0.6.0 - 2026-06-20 (authenticated enumeration + upstream conformance pass)
- **Authenticated enumeration** via a supplied bearer token (`mcp.token` script-arg):
  sent as `Authorization: Bearer <token>` on the `initialize` handshake and every `*/list`
  call, across both the Streamable HTTP and legacy HTTP+SSE transports. `mcp-info` now
  reports `auth: PROVIDED (Bearer token accepted)` and feeds `-sV` an "authenticated"
  extrainfo; `mcp-enum` enumerates the gated tool surface. Still read-only: a token only
  unlocks `initialize` + `*/list`; `tools/call` is never invoked. README documents passing
  the token via a `0600 --script-args-file` to keep it off the process list.
- **Upstream-conformance pass** (toward an nmap NSE submission): `author` changed from a
  bare email to the name-only convention (`author = "Ben Williams"`; email retained in the
  nselib `@author` NSEDoc tag); added an `@xmloutput` example to `mcp-enum`; verified no
  tabs / no trailing whitespace, `script.db` regeneration, and that NSEDoc renders via
  `nmap --script-help`.
- **Risk-heuristic false-positive fix (negation-aware matching)**: cautionary disclaimers
  in tool/parameter descriptions ("Do not include any sensitive information such as API
  keys, passwords, credentials...") no longer trip the risk categories. A phrase inside a
  clause containing a negation cue (`not`/`never`/`avoid`/`without`/`cannot`/`n't`) is
  treated as a disclaimer, not a capability. Surfaced by field-testing against Context7,
  whose docs tools were previously mis-flagged `secrets`; verified the true positives on
  FastMCP and `server-everything` are unaffected.
- **Field-tested against live public MCP servers** (read-only `initialize` + `*/list`):
  DeepWiki 2.14.3 and Context7 3.2.0 (Streamable, full tool enumeration), Cloudflare docs
  (legacy SSE), and the OAuth-gated GitHub, Sentry, and Linear servers (auth-required
  fingerprint + RFC 9728 authorization-server/scope discovery, unauthenticated). Re-tested
  locally against `server-everything` 2.0.0 (streamable + sse) and the FastMCP SDK 1.28.0.
- **Mock server**: `/authmcp` now accepts a known test token, so the authenticated path is
  reproducible locally (`mcp.token=mock-test-token-abc123`); the advertised protocol
  version is overridable via `MCP_PROTOCOL` (e.g. `2024-11-05` / `2025-03-26` /
  `2025-06-18`); per-request connection-reset tracebacks are silenced.
- **`test/run_matrix.sh`**: a local regression matrix asserting expected output across
  protocol versions, all three transports, both auth states, and tools/resources/prompts
  content (23 checks).
- Removed client/engagement-specific artifacts from the repo.

## 0.5.0 - 2026-06-08 (input-schema risk analysis)
- Dangerous-tool detection now assesses each tool across its name, description, **and JSON
  input schema**: free-form parameters (string/array/object, no enum) named/described like
  commands, paths, URLs/hosts, SQL, or secrets are flagged even when the tool name and
  description look benign. Constrained params (enums, numbers, booleans) are ignored.
- Findings are **categorised** (code-exec, file-access, network/ssrf, sql/db, secrets,
  privileged); risk-contributing parameters are marked with `*` in the output, and the
  SECURITY summary lists the aggregate categories.
- Tightened SQL detection (dropped ambiguous bare "query") to remove a false positive on
  search/research tools. Validated against FastMCP (incl. a benign-named tool flagged
  purely on its schema) and `server-everything`.

## 0.4.0 - 2026-06-08 (M4: submission package)
- Added `WRITEUP.md` (research/advisory write-up) and `SUBMISSION.md` (Nmap PR package +
  conformance checklist).
- Added `LICENSE` (NSE files under the Nmap license for upstream; docs/tests under MIT).
- Validated NSEDoc renders via `nmap --script-help`; initialised git repository.

## 0.3.0 - 2026-06-08 (M3: refactor + field-testing)
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

## 0.2.0 - 2026-06-08 (M2: legacy enum, OAuth, -sV)
- Full legacy HTTP+SSE enumeration via raw-socket async response correlation.
- OAuth 2.1 protected-resource metadata parsing (RFC 9728).
- `-sV` flags MCP via the version-category `set_port_version` override; added
  `nmap-service-probes.mcp` fragment.
- **Finding:** a User-Agent containing "nmap" is blocked by AWS WAF/CloudFront (403 vs
  401); scripts default to a neutral UA (`mcp.ua`).

## 0.1.0 - 2026-06-08 (M1: initial build)
- `mcp-info` (detect/fingerprint) and `mcp-enum` (tools/resources/prompts) over Streamable
  HTTP, with dangerous-tool and unauthenticated-exposure flagging.
- Dependency-free mock server; PRD and README.

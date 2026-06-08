# PRD: Nmap NSE Plugins for Enumerating MCP Services

**Status:** Draft v0.1
**Author:** ben.williams@nccgroup.com
**Date:** 2026-06-08

---

## 1. Problem statement

Model Context Protocol (MCP) servers are proliferating rapidly inside enterprises — they
expose tools, resources, and prompts that LLM agents can invoke. From a security
perspective an MCP server is **remote-code-execution-as-a-service**: a single exposed,
unauthenticated endpoint may offer tools such as `execute_shell`, `read_file`,
`query_database`, or `send_email`. These are increasingly deployed by developers on dev
ports (3000, 8000, 8080, 8888, …) with no authentication and `0.0.0.0` binds, exactly the
DNS-rebinding / unauthenticated-exposure failure mode the MCP spec warns about.

### Prior art (verified 2026-06-08)
- **nmap:** nothing. The only "nmap + MCP" projects wrap nmap *as* an MCP tool for an LLM.
- **Metasploit:** nothing for scanning MCP. `msfmcpd`/MetasploitMCP are the inverse (expose
  Metasploit *as* an MCP server).
- **Tenable:** *does* cover this in **Web App Scanning (WAS)** — plugins `114790` MCP Server
  Detected, `114791` MCP Server Unauthenticated Access, `114965` MCP Server Tools Detected
  (family "Artificial Intelligence", released 2025-06-11), plus Nessus local plugin `241433`
  (installed MCP Python lib). So a commercial WAS capability exists; the gap is an **open,
  scriptable, CLI-native nmap** capability usable in any engagement without a WAS licence.

Engagements that review AI systems therefore have no standard, scriptable, free way to:

1. Discover MCP endpoints across an IP range / port range.
2. Fingerprint the server (implementation name, version, protocol version).
3. Enumerate the exposed attack surface (tools, resources, prompts).
4. Flag the security-relevant conditions (no auth, dangerous tools, stale protocol).

## 2. Goals

| # | Goal | Success criteria |
|---|------|------------------|
| G1 | Detect MCP servers over HTTP(S) | Identifies Streamable-HTTP and legacy HTTP+SSE endpoints; integrates with `-sV` |
| G2 | Fingerprint the server | Reports `serverInfo.name`, `serverInfo.version`, `protocolVersion`, capabilities |
| G3 | Enumerate attack surface | Lists tool names + descriptions, resource URIs, prompt names |
| G4 | Flag security conditions | Marks unauthenticated access, dangerous tool names, deprecated protocol versions |
| G5 | Be a good NSE citizen | Correct categories, safe by default, configurable, low false-positive rate |

### Non-goals
- Exploiting tools (no `tools/call` invocation by default — that executes attacker-chosen
  side effects). An opt-in, clearly-flagged probe may be considered later.
- stdio-transport servers (local subprocess only; not network-reachable, out of scope).
- Authentication brute force / OAuth token theft.

## 3. Background: how MCP looks on the wire

MCP uses **JSON-RPC 2.0**. Two network transports exist:

### 3.1 Streamable HTTP (current, spec 2025-03-26 / 2025-06-18)
- A single **MCP endpoint** path (commonly `/mcp`, sometimes `/`) serving POST + GET.
- Handshake: client POSTs an `initialize` request with header
  `Accept: application/json, text/event-stream`.

  ```json
  {"jsonrpc":"2.0","id":1,"method":"initialize",
   "params":{"protocolVersion":"2025-06-18","capabilities":{},
             "clientInfo":{"name":"nmap","version":"0.1"}}}
  ```
- Server replies `200` with either `Content-Type: application/json` (one object) or
  `text/event-stream` (SSE; JSON-RPC object on a `data:` line). The result contains:

  ```json
  {"jsonrpc":"2.0","id":1,"result":{
     "protocolVersion":"2025-06-18",
     "capabilities":{"tools":{},"resources":{"subscribe":true}},
     "serverInfo":{"name":"example-server","version":"1.0.0"}}}
  ```
- Server MAY return an `Mcp-Session-Id` header; subsequent requests must echo it plus
  `MCP-Protocol-Version`.

### 3.2 Legacy HTTP+SSE (spec 2024-11-05, deprecated but widely deployed)
- Client GETs `/sse` with `Accept: text/event-stream`. First SSE event is
  `event: endpoint` whose `data:` is the POST URL (e.g. `/messages?sessionId=…`) used for
  subsequent JSON-RPC.

### 3.3 Discovery & auth signals
- `.well-known/mcp.json` — optional discovery document.
- OAuth 2.1 protected resources advertise `WWW-Authenticate: Bearer resource_metadata=…`
  and host `.well-known/oauth-protected-resource`.

## 4. Deliverables

### 4.1 `mcp-info.nse` — detection & fingerprint (categories: `discovery`, `safe`, `version`)
Probes candidate paths with an `initialize` handshake (Streamable HTTP), falls back to a
legacy `/sse` probe, and checks `.well-known/mcp.json`. On success reports transport,
endpoint path, `serverInfo`, `protocolVersion`, advertised capabilities, session-id
presence, and auth posture. Sets the service version via `-sV` integration.

### 4.2 `mcp-enum.nse` — attack-surface enumeration (categories: `discovery`, `safe`)
Completes the handshake (handles session id + protocol-version header, SSE or JSON
responses), then calls `tools/list`, `resources/list`, `resources/templates/list`, and
`prompts/list`. Reports each tool's name + description (+ input-schema param names),
resource URIs, and prompt names. Heuristically flags **dangerous tools** (exec/shell/eval/
file write/delete/sql/http patterns) and **unauthenticated exposure** as security findings.

### 4.3 `mcp.lua` (nselib helper, optional/refactor)
Shared handshake + SSE-parsing + JSON-extraction helpers once both scripts stabilise.

### 4.4 `test/mock_mcp_server.py`
A dependency-free mock MCP server (Streamable HTTP + legacy SSE modes) used to validate the
scripts in CI / locally without a real target.

## 5. Detection algorithm (per candidate path)

```
for path in [ /mcp, /, /sse, /messages, /api/mcp, /mcp/v1, /rpc, /jsonrpc ]:
    POST initialize (Accept: application/json, text/event-stream)
    if response body has JSON-RPC result.serverInfo or result.protocolVersion:
        -> MCP via Streamable HTTP. Record. (this is high confidence)
    elif response 4xx with WWW-Authenticate Bearer / 401:
        -> probable MCP behind auth. Record as "auth required".
    else:
        GET path (Accept: text/event-stream)
        if SSE 'event: endpoint': -> MCP via legacy HTTP+SSE. Record.
also: GET /.well-known/mcp.json -> discovery doc present
```

Confidence is keyed on a valid JSON-RPC `initialize` result, not on path or banner, to keep
false positives near zero.

## 6. Output (example)

```
PORT     STATE SERVICE
8000/tcp open  http
| mcp-info:
|   transport: streamable-http
|   endpoint: /mcp
|   protocolVersion: 2025-06-18
|   server: acme-toolserver 1.4.2
|   capabilities: tools, resources, prompts, logging
|   session: stateful (Mcp-Session-Id issued)
|_  auth: NONE (unauthenticated)
| mcp-enum:
|   tools (4):
|     run_command   - Execute a shell command on the host   [!! DANGEROUS]
|     read_file     - Read a file from disk                  [!! DANGEROUS]
|     search_web    - Search the web
|     get_weather   - Get the weather for a city
|   resources (2): file:///etc/, db://customers
|   prompts (1): summarize
|_  SECURITY: unauthenticated server exposes 2 dangerous tool(s)
```

## 7. CLI usage

```
nmap -p 8000,3000,8080 --script mcp-info <target>
nmap -sV --script "mcp-info,mcp-enum" -p- <target>
nmap --script mcp-info --script-args mcp.paths=/custom,mcp.tls=true <target>
```

Script args: `mcp.paths` (override path list), `mcp.timeout`, `mcp.tls` (force https),
`mcp-enum.schemas` (dump full input schemas).

## 8. Security, safety & legal considerations
- **Safe category:** scripts only call read-only/idempotent MCP methods (`initialize`,
  `*/list`). They never call `tools/call`. `initialize` is the protocol's own handshake and
  is the minimum needed to identify the service.
- Honour `--max-rate`, timeouts, and `host.targetname` (for SNI/Host).
- The `notifications/initialized` notification is sent only where required to unlock
  `*/list` on strict servers; it has no side effects.
- Authorised-testing only; this is standard recon tooling. Findings (unauth + dangerous
  tools) are reported, not exploited.

## 9. Milestones
1. **M1:** PRD, `mcp-info.nse`, `mcp-enum.nse`, mock server, README, local verification
   against the mock. ✅ **DONE**
2. **M2:** legacy-SSE full enumeration (raw-socket transport, async response correlation);
   `.well-known/oauth-protected-resource` parsing; `-sV` flags MCP (via version-category
   `set_port_version` override; `nmap-service-probes.mcp` fragment as a supplement).
   ✅ **DONE** — verified against the mock and against a real authorised target
   (a managed OAuth-protected MCP service: the unauthenticated probe extracted the auth server
   and scope). **Finding:** a User-Agent containing "nmap" is blocked by AWS WAF/CloudFront
   (403 vs 401), so scripts now default to a neutral UA (`mcp.ua` to override).
3. **M3:** refactor shared logic into the `mcp.lua` nselib; broaden path/port heuristics
   (15 paths, common-port set, unrecognized-service heuristic, `mcp.allports`); field-test
   against popular MCP frameworks. ✅ **DONE** — verified against the official Python SDK
   (FastMCP), `@modelcontextprotocol/server-everything` in both `streamableHttp` and `sse`
   modes, and the real OAuth target. Field-testing forced real-world hardening, all now
   automatic: **raw-socket transport** (nmap's `http.post` hangs on FastMCP/uvicorn streamed
   SSE), **TLS auto-fallback**, **Host header with port** (servers return `421` for
   DNS-rebinding protection otherwise), and **correct `initialize` params** (strict servers
   reject empty params with `-32602`).
4. **M4:** submit to nmap NSE repo + write up.

## 10. Open questions
- Default port set vs. `-sV`-driven only? (Lean: match http/https + a small common-dev-port
  list, gated behind a script-arg to avoid scanning noise.)
- Should an opt-in `--script-args mcp.unsafe=true` ever call a benign `tools/call`? (Deferred
  — high blast radius, out of M1–M3.)

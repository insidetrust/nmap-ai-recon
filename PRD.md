# PRD: Nmap NSE Plugins for Enumerating MCP Services

**Status:** Implemented (detection, enumeration, and OAuth discovery shipped; upstream
submission pending)
**Author:** Ben Williams (NCC Group)
**Date:** 2026-06-08

---

## 1. Problem statement

Model Context Protocol (MCP) servers are proliferating rapidly inside enterprises - they
expose tools, resources, and prompts that LLM agents can invoke. From a security
perspective an MCP server is **remote-code-execution-as-a-service**: a single exposed,
unauthenticated endpoint may offer tools such as `execute_shell`, `read_file`,
`query_database`, or `send_email`. These are increasingly deployed by developers on dev
ports (3000, 8000, 8080, 8888, ...) with no authentication and `0.0.0.0` binds, exactly the
DNS-rebinding / unauthenticated-exposure failure mode the MCP spec warns about.

### Prior art (verified 2026-06-08)
- **nmap:** nothing. The only "nmap + MCP" projects wrap nmap *as* an MCP tool for an LLM.
- **Metasploit:** nothing for scanning MCP. `msfmcpd`/MetasploitMCP are the inverse (expose
  Metasploit *as* an MCP server).
- **Tenable:** *does* cover this in **Web App Scanning (WAS)** - plugins `114790` MCP Server
  Detected, `114791` MCP Server Unauthenticated Access, `114965` MCP Server Tools Detected
  (family "Artificial Intelligence", released 2025-06-11), plus Nessus local plugin `241433`
  (installed MCP Python lib). So a commercial WAS capability exists; the gap is an **open,
  scriptable, CLI-native nmap** capability usable in any engagement without a WAS licence.

Engagements that review AI systems therefore have no standard, scriptable, free way to:

1. Discover MCP endpoints across an IP range / port range.
2. Fingerprint the server (implementation name, version, protocol version).
3. Enumerate the exposed attack surface (tools, resources, prompts).
4. Flag the security-relevant conditions (no authentication, dangerous tools).

## 2. Goals

| # | Goal | Success criteria |
|---|------|------------------|
| G1 | Detect MCP servers over HTTP(S) | Identifies Streamable-HTTP and legacy HTTP+SSE endpoints; integrates with `-sV` |
| G2 | Fingerprint the server | Reports `serverInfo.name`, `serverInfo.version`, `protocolVersion`, capabilities |
| G3 | Enumerate attack surface | Lists tool names + descriptions, resource URIs, prompt names |
| G4 | Flag security conditions | Marks unauthenticated access and dangerous tool names/parameters |
| G5 | Be a good NSE citizen | Correct categories, safe by default, configurable, low false-positive rate |

### Non-goals
- Exploiting tools: the scripts never call `tools/call` (that would execute attacker-chosen
  side effects), with or without a supplied token.
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
  `event: endpoint` whose `data:` is the POST URL (e.g. `/messages?sessionId=...`) used for
  subsequent JSON-RPC.

### 3.3 Auth signals
- OAuth 2.1 protected resources advertise `WWW-Authenticate: Bearer resource_metadata=...`
  and host `.well-known/oauth-protected-resource` (RFC 9728).

## 4. Deliverables

### 4.1 `mcp-info.nse` - detection & fingerprint (categories: `discovery`, `safe`, `version`)
Probes candidate paths with an `initialize` handshake (Streamable HTTP) and falls back to a
legacy `/sse` probe. For auth-gated servers it parses the OAuth 2.1 protected-resource
metadata (RFC 9728, `.well-known/oauth-protected-resource`) to reveal the authorization
server(s) and scopes. On success reports transport, endpoint path, `serverInfo`,
`protocolVersion`, advertised capabilities, session-id presence, and auth posture. Sets the
service version via `-sV` integration. An optional `mcp.token` bearer token enables
authenticated enumeration of a gated server (still read-only).

### 4.2 `mcp-enum.nse` - attack-surface enumeration (categories: `discovery`, `safe`)
Completes the handshake (handles session id + protocol-version header, SSE or JSON
responses), then calls `tools/list`, `resources/list`, `resources/templates/list`, and
`prompts/list`. Reports each tool's name + description (+ input-schema param names),
resource URIs, and prompt names. Risk-assesses each tool across its name, description, **and
JSON input schema**, bucketing findings into categories (code-exec, file-access,
network/ssrf, sql/db, secrets, privileged), and flags **unauthenticated exposure** as a
security finding.

### 4.3 `mcp.lua` - shared nselib
The library both scripts build on: the two transports (raw sockets), the `initialize`
handshake, SSE/JSON response parsing, OAuth metadata discovery, and the tool risk-assessment
helpers. Installs into nmap's `nselib/`.

### 4.4 `test/mock_mcp_server.py`
A dependency-free mock MCP server (Streamable HTTP + legacy SSE modes) used to validate the
scripts locally without a real target. `test/run_matrix.sh` drives it across protocol
versions, transports, and auth states.

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
on a Bearer challenge: GET /.well-known/oauth-protected-resource
        -> record authorization server(s) + scopes (RFC 9728)
```

Confidence is keyed on a valid JSON-RPC `initialize` result, not on path or banner, to keep
false positives near zero.

## 6. Output (example)

```
PORT     STATE SERVICE
8000/tcp open  mcp
| mcp-info:
|   transport: streamable-http
|   endpoint: /mcp
|   protocolVersion: 2025-06-18
|   server: acme-toolserver 1.4.2
|   capabilities: logging, prompts, resources, tools
|   session: stateful (Mcp-Session-Id issued)
|_  auth: NONE (unauthenticated)
| mcp-enum:
|   transport: streamable-http
|   server: acme-toolserver 1.4.2 (protocol 2025-06-18)
|   tools (4):
|     run_command [RISK: code-exec] - Execute a shell command on the host  (params: cmd*)
|     read_file [RISK: file-access] - Read a file from disk  (params: path*)
|     search_web - Search the web  (params: q)
|     get_weather - Get the weather for a city  (params: city)
|   resources (2): file:///etc/, db://customers
|   prompts (1): summarize
|_  SECURITY: unauthenticated server exposes 2 risky tool(s) [code-exec, file-access]: run_command, read_file
```

## 7. CLI usage

```
nmap -p 8000,3000,8080 --script mcp-info <target>
nmap -sV --script "mcp-info,mcp-enum" -p- <target>
nmap --script mcp-enum --script-args mcp.paths=/mcp,mcp-enum.schemas=true <target>
```

Script args: `mcp.paths` (override path list), `mcp.timeout`, `mcp.ua` (User-Agent),
`mcp.sse_path` (legacy SSE path), `mcp.token` (bearer token for authenticated enumeration),
`mcp.allports` (probe every open port), `mcp-enum.schemas` (dump full input schemas). TLS is
auto-detected, so there is no force-https flag.

## 8. Security, safety & legal considerations
- **Safe category:** scripts only call read-only/idempotent MCP methods (`initialize`,
  `*/list`). They never call `tools/call`. `initialize` is the protocol's own handshake and
  is the minimum needed to identify the service.
- Honour the configured timeouts; use `host.targetname` for the Host/SNI header.
- The `notifications/initialized` notification is sent only where required to unlock
  `*/list` on strict servers; it has no side effects.
- Authorised-testing only; this is standard recon tooling. Findings (unauth + dangerous
  tools) are reported, not exploited.

## 9. Milestones
1. **M1** - PRD, both scripts, mock server, README, local verification. **DONE**
2. **M2** - legacy-SSE enumeration (raw-socket async correlation), OAuth `resource_metadata`
   parsing, `-sV` integration via `set_port_version`. **DONE**
3. **M3** - shared `mcp.lua` nselib; broader path/port heuristics; field-testing that forced
   the raw-socket transport, TLS auto-fallback, port-qualified Host header, and valid
   `initialize` params (see `WRITEUP.md` for the detail). **DONE**
4. **M4** - upstream submission package: conformance, format alignment, public field-testing.
   **DONE**; opening the nmap PR + dev-list notification remains.

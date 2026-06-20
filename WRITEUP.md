# Scanning for Model Context Protocol servers with Nmap

**Author:** Ben Williams (NCC Group), **Date:** 2026-06-08

> Tooling and research notes accompanying the `mcp-info` / `mcp-enum` NSE scripts. This
> document is written so it can double as a public write-up / advisory and as the basis
> for the upstream Nmap PR description.

## TL;DR

Model Context Protocol (MCP) servers are spreading fast inside enterprises and are, in
effect, *remote-code-execution-as-a-service*: a single exposed, unauthenticated endpoint
can offer an LLM agent tools like `run_command`, `read_file`, or `get-env`. Until now there
was **no open, scriptable way to scan for MCP services from the network** - nmap and
Metasploit had nothing; only Tenable Web App Scanning covered it commercially.

This project adds two Nmap NSE scripts - `mcp-info` (detect + fingerprint) and `mcp-enum`
(enumerate the tool/resource/prompt attack surface) - plus a shared `mcp` nselib. They are
**read-only** (never invoke `tools/call`) and were field-tested against the official Python
SDK (FastMCP), the reference `server-everything` (both transports), and a live
OAuth-protected production server.

Field-testing against real servers exposed four issues a naive implementation gets wrong -
documented below - which is exactly why generic HTTP tooling and a permissive mock are not
enough to scan MCP reliably.

## Background: why an exposed MCP server matters

MCP is the protocol LLM clients use to discover and call **tools** (functions with side
effects), read **resources** (data), and fetch **prompts**. The spec itself warns that
remote servers **MUST** validate the `Origin`/`Host` headers (DNS-rebinding), **SHOULD**
bind to localhost when local, and **SHOULD** authenticate - but none of this is enforced.
In practice developers expose MCP servers on dev ports (3000/5000/8000/8080/8888/...) bound
to `0.0.0.0`, frequently with no auth. An unauthenticated server that exposes a shell or
file tool is a critical finding; one that exposes `get-env` leaks secrets.

## Prior art (verified June 2026)

| Scanner | MCP service enumeration? |
|---|---|
| **Nmap** | None. "nmap + MCP" projects wrap nmap *as* an MCP server for an LLM. |
| **Metasploit** | None. `msfmcpd` / MetasploitMCP are the inverse (MSF as an MCP server). |
| **Tenable** | **Yes**, in Web App Scanning: plugins 114790 (Detected), 114791 (Unauthenticated Access), 114965 (Tools Detected), family "Artificial Intelligence", released 2025-06-11. Plus Nessus local plugin 241433 (installed Python lib). |

So the gap these scripts fill is an **open, free, CLI-native** capability usable in any
engagement without a WAS licence.

## How MCP looks on the wire

JSON-RPC 2.0 over two HTTP transports:

- **Streamable HTTP** (current). One endpoint (commonly `/mcp`) serving POST + GET. The
  client POSTs `initialize` with `Accept: application/json, text/event-stream`. The server
  replies as `application/json` *or* `text/event-stream`, may issue an `Mcp-Session-Id`,
  and carries `serverInfo`, `protocolVersion`, and `capabilities` in the result.
- **Legacy HTTP+SSE** (2024-11-05, deprecated but widely deployed). GET `/sse` opens an SSE
  stream whose first `endpoint` event names a `/messages?sessionId=...` URL; JSON-RPC is then
  POSTed there and the **responses come back asynchronously on the SSE stream**.

Detection keys on a valid JSON-RPC `initialize` result (not a banner/path), keeping false
positives near zero. Enumeration then calls the read-only `tools/list`, `resources/list`,
`resources/templates/list`, and `prompts/list`.

## The four things real servers break (and the mock hid)

A permissive mock passes trivially. Real servers did not - each failure is a lesson:

1. **`http.post` hangs on streamed SSE.** FastMCP/uvicorn keep the SSE response stream open
   after delivering the reply (`keep-alive`, chunked, `x-accel-buffering: no`). Nmap's HTTP
   library waits for the body to terminate, times out, and discards data it already
   received. **Fix:** speak HTTP over a **raw socket** and stop reading the instant the
   JSON-RPC reply for our id appears.

2. **Host-header validation -> `421 Misdirected Request`.** MCP servers implement the
   spec-mandated DNS-rebinding protection by validating `Host`. A request with
   `Host: 127.0.0.1` (no port) is rejected; `Host: 127.0.0.1:9001` is accepted. **Fix:**
   always include the non-default port in `Host`.

3. **Strict `initialize` params -> `-32602`.** Real servers reject an empty `params` object;
   `initialize` **must** carry `protocolVersion` and `clientInfo`. **Fix:** send valid
   params (the mock accepted empty ones, masking this for a whole milestone).

4. **WAF blocks the word "nmap".** A live CloudFront-fronted target returned `403` to a
   User-Agent containing `nmap` but `401` to a neutral one - silently masking a real MCP
   server. **Fix:** default to a neutral browser UA (`mcp.ua=` to override).

Two further engineering notes: **TLS auto-detection** can't be trusted from the port
(`shortport.ssl` flagged 9001 as `tor-orport`/TLS for a plaintext server), so the transport
tries the preferred mode and falls back; and MCP behind uvicorn is **often not recognised as
HTTP** by `-sV`, so the portrule also fires on services that returned data but went
unidentified (`mcp.allports=true` forces every open port).

## Field-test results

| Server | Transport | Outcome |
|---|---|---|
| Official Python SDK (FastMCP) | Streamable HTTP | name/version, 3 tools (`run_shell`, `read_file` flagged), resource, prompt |
| `@modelcontextprotocol/server-everything` | `streamableHttp` | 13 tools, 9 resources, 4 prompts; `get-env`, `gzip-file-as-resource` flagged |
| `@modelcontextprotocol/server-everything` | `sse` (legacy) | identical enumeration over the async SSE path |
| Live production server | Streamable + OAuth | reported auth-required; **authorization server and scope discovered unauthenticated** |

The OAuth case is the most useful for assessments: even fully locked down, the
*unauthenticated* probe fingerprints the server and - via RFC 9728
`.well-known/oauth-protected-resource` - reveals the authorization server and required
scopes, all without credentials.

## Using it

```bash
nmap -sV --script "mcp-info,mcp-enum" -p- <target>
nmap --script mcp-info --script-args mcp.allports=true <target>     # arbitrary ports
nmap --script mcp-info --script-args mcp.ua="Mozilla/5.0" <target>  # WAF evasion
```

See `README.md` for full arguments and `SUBMISSION.md` for the Nmap PR package.

## Defensive guidance (for the blue team / report)

- Require authentication on every network-reachable MCP server (OAuth 2.1 per the spec).
- Bind local servers to `127.0.0.1`, never `0.0.0.0`; validate `Origin` and `Host`.
- Treat the tool list as an attack surface: avoid shell/file/exec/`get-env`-style tools on
  exposed servers; apply least privilege to whatever the tools can reach.
- Network-segment MCP endpoints; they are RCE brokers, not ordinary web apps.

## Responsible use

Authorised testing only. The scripts perform standard service reconnaissance - handshake
and `*/list` - and **never** call `tools/call`, so no server-side tool is executed.
Findings (unauthenticated access, dangerous tools) are reported, not exploited.

## Future work

- Optional, clearly-flagged input-schema risk analysis (params that take raw paths/commands).
- `nmap-service-probes` upstreaming so bare `-sV` flags MCP without the script.
- Coverage for additional frameworks and auth schemes as the ecosystem evolves.

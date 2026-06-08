# Upstream submission package (Nmap NSE)

This is everything needed to submit `mcp-info`, `mcp-enum`, and the `mcp` nselib to the
Nmap project. The maintainer-facing PR lives at <https://github.com/nmap/nmap>.

> Note: opening the PR requires a GitHub fork of `nmap/nmap` under your account and is a
> manual step (it cannot be pushed from the build environment). The commands and the draft
> PR description below make that a copy-paste exercise.

## 1. File placement in the nmap tree

| This repo | Nmap tree |
|---|---|
| `scripts/mcp-info.nse` | `scripts/mcp-info.nse` |
| `scripts/mcp-enum.nse` | `scripts/mcp-enum.nse` |
| `scripts/mcp.lua` | `nselib/mcp.lua` |
| `nmap-service-probes.mcp` | merge entries into `nmap-service-probes` (optional, separate PR) |

After placing files, regenerate the script DB:

```bash
nmap --script-updatedb
```

## 2. Conformance checklist

- [x] **NSEDoc complete** — `description`, `@usage`, `@args`, `@output`, `@xmloutput`
      (mcp-info), verified to render via `nmap --script-help mcp-info,mcp-enum`.
- [x] **License header** — each file carries `Same as Nmap--See https://nmap.org/book/man-legal.html`.
- [x] **`author` set**, single string.
- [x] **Categories** — `mcp-info`: `discovery, safe, version`; `mcp-enum`: `discovery, safe`.
- [x] **`safe` justification** — only the protocol handshake and idempotent `*/list`
      methods are sent; **`tools/call` is never invoked**, so no server-side side effects.
- [x] **No banned APIs** — uses `nmap`, `http`, `json`, `shortport`, `stdnse`, `stringaux`,
      `string`, `table` only. No `os`/`io`/filesystem; no `Math.random`/wallclock deps.
- [x] **2-space indentation**, locals required at top, `_ENV = stdnse.module(...)`/`return _ENV`
      idiom in the nselib.
- [x] **Timeouts honoured** — `mcp.timeout` (default 7000 ms); raw sockets set timeouts.
- [x] **Low false-positive design** — match keyed on a valid JSON-RPC `initialize` result.
- [x] **Tested** — mock (all transports + OAuth) and real servers (FastMCP,
      `server-everything` streamable + sse, live OAuth target). nmap 7.94 / Lua 5.4.

## 3. Suggested commit / branch

```bash
# in a fork of nmap/nmap
git checkout -b nse-mcp
cp <thisrepo>/scripts/mcp-info.nse scripts/
cp <thisrepo>/scripts/mcp-enum.nse scripts/
cp <thisrepo>/scripts/mcp.lua      nselib/
git add scripts/mcp-info.nse scripts/mcp-enum.nse nselib/mcp.lua
git commit -m "NSE: add mcp-info, mcp-enum and mcp nselib for MCP server enumeration"
git push origin nse-mcp
# then open a PR against nmap/nmap
```

## 4. Draft PR description

> **Title:** NSE: detect and enumerate Model Context Protocol (MCP) servers
>
> Adds two scripts and a shared library for discovering and enumerating Model Context
> Protocol (MCP) servers over HTTP(S):
>
> - **`mcp-info`** (`discovery, safe, version`) — performs the JSON-RPC `initialize`
>   handshake (Streamable HTTP), falls back to the legacy HTTP+SSE transport, and parses
>   OAuth 2.1 protected-resource metadata (RFC 9728) for auth-gated servers. Reports
>   transport, endpoint, server name/version, protocol version, capabilities, session
>   statefulness, and auth posture; integrates with `-sV`.
> - **`mcp-enum`** (`discovery, safe`) — completes the handshake and calls the read-only
>   `tools/list`, `resources/list`, `resources/templates/list`, and `prompts/list`,
>   reporting the tool/resource/prompt attack surface and heuristically flagging dangerous
>   tools and unauthenticated exposure.
> - **`nselib/mcp.lua`** — shared transport (both Streamable HTTP and legacy SSE over raw
>   sockets), handshake, OAuth discovery, and enumeration helpers.
>
> **Safety:** read-only — only `initialize` and `*/list` are issued; `tools/call` is never
> invoked.
>
> **Why raw sockets:** real Streamable-HTTP servers (FastMCP/uvicorn) keep the SSE response
> stream open after replying, which makes `http.post` block until timeout; the library
> reads only until the JSON-RPC reply arrives. It also sends a correct `Host` header
> (servers return `421` for DNS-rebinding protection otherwise) and valid `initialize`
> params (strict servers reject empty params with `-32602`).
>
> **Testing:** validated against the official Python SDK (FastMCP),
> `@modelcontextprotocol/server-everything` in both `streamableHttp` and `sse` modes, an
> OAuth-protected production server, and a bundled mock covering every transport. Tested on
> nmap 7.94 / Lua 5.4.

## 5. Alternatives to a GitHub PR

- Email the dev list (`dev@nmap.org`) with the scripts attached, per the
  [NSE submission guidance](https://nmap.org/book/nse-script-format.html).
- Ship as a standalone NCC Group tool/blog post (see `WRITEUP.md`) independent of upstream.

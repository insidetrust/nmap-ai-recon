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

- [x] **NSEDoc complete** - `description`, `@usage`, `@args`, `@output`, `@xmloutput`
      (both `mcp-info` and `mcp-enum`), verified to render via
      `nmap --script-help mcp-info,mcp-enum`.
- [x] **License header** - each file carries the exact string
      `Same as Nmap--See https://nmap.org/book/man-legal.html`.
- [x] **`author`** - `author = "Ben Williams <ben.williams@nccgroup.com>"`, the `Name
      <email>` form used by 80 shipped scripts (NCC Group credited via the domain); the
      nselib carries the same in its `@author` NSEDoc tag.
- [x] **Categories** - `mcp-info`: `discovery, safe, version`; `mcp-enum`: `discovery, safe`.
      Each script carries `safe` (the required safe/intrusive classification); `mcp-info`
      additionally carries `version` so it runs under `-sV`.
- [x] **`safe` justification** - only the protocol handshake and idempotent `*/list`
      methods are sent; **`tools/call` is never invoked**, so no server-side side effects.
- [x] **No banned APIs** - uses `nmap`, `http`, `json`, `shortport`, `stdnse`, `stringaux`,
      `string`, `table` only. No `os`/`io`/filesystem; no `Math.random`/wallclock deps.
- [x] **2-space indentation**, no tabs, no trailing whitespace; locals `require`d at top,
      `_ENV = stdnse.module(...)`/`return _ENV` idiom in the nselib.
- [x] **`shortport` portrule** - built on `shortport.http` / `shortport.ssl` plus an
      MCP-specific port/`-sV`-unrecognised heuristic; no hand-rolled port parsing.
- [x] **`stdnse.output_table()`** for ordered, XML-renderable structured output.
- [x] **Timeouts honoured** - `mcp.timeout` (default 7000 ms); raw sockets set timeouts.
- [x] **Low false-positive design** - match keyed on a valid JSON-RPC `initialize` result.
- [x] **`script.db` regenerated** - `nmap --script-updatedb` registers both scripts with
      their categories; commit the updated `scripts/script.db` in the PR.
- [x] **Tested** - bundled mock covers every transport + OAuth + authenticated token.
      Field-tested previously against FastMCP and `server-everything` (streamable + sse)
      and a live OAuth target. nmap 7.94 / Lua 5.4. (Re-run the real-framework matrix on a
      current nmap before opening the PR.)

## 3. Suggested commit / branch

```bash
# in a fork of nmap/nmap
git checkout -b nse-mcp
cp <thisrepo>/scripts/mcp-info.nse scripts/
cp <thisrepo>/scripts/mcp-enum.nse scripts/
cp <thisrepo>/scripts/mcp.lua      nselib/
nmap --script-updatedb                       # regenerate scripts/script.db
git add scripts/mcp-info.nse scripts/mcp-enum.nse nselib/mcp.lua scripts/script.db
git commit -m "NSE: add mcp-info, mcp-enum and mcp nselib for MCP server enumeration"
git push origin nse-mcp
# then open a PR against nmap/nmap
```

**Then notify the dev list.** Per `CONTRIBUTING.md`, after opening the PR send a short
email to `dev@nmap.org` referencing it (not all committers watch GitHub; PRs left only on
GitHub can sit unreviewed). Subscribe first via `dev-subscribe@nmap.org`; archive:
<https://seclists.org/nmap-dev/>.

**Contribution licensing.** Per the nmap `HACKING` file, submitting a patch/PR is taken as
offering the Nmap Project (Nmap Software LLC) an unlimited, non-exclusive right to reuse,
modify, and relicense the code. State any alternative terms explicitly in the PR if needed.

## 4. Draft PR description

> **Title:** NSE: detect and enumerate Model Context Protocol (MCP) servers
>
> Adds two scripts and a shared library for discovering and enumerating Model Context
> Protocol (MCP) servers over HTTP(S):
>
> - **`mcp-info`** (`discovery, safe, version`) - performs the JSON-RPC `initialize`
>   handshake (Streamable HTTP), falls back to the legacy HTTP+SSE transport, and parses
>   OAuth 2.1 protected-resource metadata (RFC 9728) for auth-gated servers. Reports
>   transport, endpoint, server name/version, protocol version, capabilities, session
>   statefulness, and auth posture; integrates with `-sV`.
> - **`mcp-enum`** (`discovery, safe`) - completes the handshake and calls the read-only
>   `tools/list`, `resources/list`, `resources/templates/list`, and `prompts/list`,
>   reporting the tool/resource/prompt attack surface and heuristically flagging dangerous
>   tools and unauthenticated exposure.
> - **`nselib/mcp.lua`** - shared transport (both Streamable HTTP and legacy SSE over raw
>   sockets), handshake, OAuth discovery, and enumeration helpers.
>
> Both scripts accept an optional `mcp.token` bearer token to enumerate auth-gated
> servers; without it, OAuth-protected servers are still fingerprinted and their
> authorization server/scopes discovered from RFC 9728 metadata.
>
> **Safety:** read-only - only `initialize` and `*/list` are issued; `tools/call` is never
> invoked, with or without a token.
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

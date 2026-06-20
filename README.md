# nmap-mcp - NSE scripts for enumerating MCP servers

Nmap Scripting Engine (NSE) plugins to **discover, fingerprint, and enumerate the attack
surface of Model Context Protocol (MCP) servers** during authorised security assessments.

Neither **nmap** nor **Metasploit** can scan MCP *services* on the network (their "MCP"
projects wrap those tools *as* MCP servers for an LLM - the inverse). **Tenable Web App
Scanning** does cover it commercially (plugins 114790/114791/114965). These scripts are the
open, free, CLI-native equivalent. See [`PRD.md`](PRD.md) for the spec/roadmap and
[`WRITEUP.md`](WRITEUP.md) for the research write-up.

## Scripts

| File | Category | What it does |
|--------|----------|--------------|
| `scripts/mcp-info.nse` | `discovery, safe, version` | Detects MCP over HTTP(S) via the JSON-RPC `initialize` handshake (Streamable HTTP) with a legacy HTTP+SSE fallback and OAuth metadata parsing. Reports transport, endpoint, server name/version, protocol version, capabilities, session statefulness, and auth posture. Feeds `-sV`. |
| `scripts/mcp-enum.nse` | `discovery, safe` | Completes the handshake then calls `tools/list`, `resources/list`, `resources/templates/list`, `prompts/list`. Lists tools/params, resources, prompts; **risk-assesses each tool across its name, description, and JSON input schema** (categorised: code-exec / file-access / network-ssrf / sql-db / secrets / privileged), and flags **unauthenticated exposure**. |
| `scripts/mcp.lua` | nselib | Shared library: both transports (raw-socket), the handshake, OAuth discovery, and enumeration. Must be installed into nmap's `nselib/`. |

Both scripts are **read-only**: they issue only the protocol handshake and `*/list`
methods. They never call `tools/call`, so no server-side tool is ever executed.

### Field-tested against real servers
Local frameworks:
- **Official Python SDK (FastMCP 1.28.0)** - Streamable HTTP
- **`@modelcontextprotocol/server-everything` 2.0.0** - `streamableHttp` and `sse` (legacy)

Live public servers (read-only `initialize` + `*/list`):
- **DeepWiki 2.14.3**, **Context7 3.2.0** - Streamable HTTP, full tool enumeration
- **Cloudflare docs MCP** - legacy HTTP+SSE
- **GitHub, Sentry, Linear** (OAuth-gated) - reported as auth-required with the
  authorization server and scopes discovered from RFC 9728 metadata, unauthenticated
- **OAuth-protected production server** (CloudFront-fronted) - same, unauthenticated

Real servers forced hardening, all automatic: a **raw-socket transport** (nmap's
`http.post` hangs on FastMCP/uvicorn, which hold the SSE stream open after replying),
**TLS auto-fallback**, a **port-qualified Host header** (servers return `421` otherwise),
and valid `initialize` params (strict servers reject empty params with `-32602`).

## Usage

```bash
# Detect MCP on common dev ports
nmap -p 3000,5000,8000,8080,8888 --script ./scripts/mcp-info.nse <target>

# Detect + enumerate, with service/version detection
nmap -sV --script "./scripts/mcp-info.nse,./scripts/mcp-enum.nse" -p- <target>

# Custom endpoint paths / dump full tool input schemas
nmap --script ./scripts/mcp-enum.nse \
     --script-args mcp.paths=/mcp,/api/mcp,mcp-enum.schemas=true <target>
```

### Install

The scripts `require` the `mcp` nselib, so install both the `.nse` scripts and `mcp.lua`:

```bash
sudo cp scripts/mcp-*.nse /usr/share/nmap/scripts/
sudo cp scripts/mcp.lua   /usr/share/nmap/nselib/
sudo nmap --script-updatedb
# now usable by name:  nmap --script mcp-info,mcp-enum <target>
```

To run from the repo **without installing** (as in the examples here), point nmap at a
data dir that contains the lib:

```bash
mkdir -p /tmp/mcp-datadir/nselib && cp scripts/mcp.lua /tmp/mcp-datadir/nselib/
nmap --datadir /tmp/mcp-datadir --script ./scripts/mcp-info.nse <target>
```

### Script arguments
| Arg | Default | Meaning |
|-----|---------|---------|
| `mcp.paths` | 15 common paths (`/mcp`, `/`, `/sse`, `/api/mcp`, ...) | Endpoint paths to probe |
| `mcp.timeout` | `7000` | Per-request HTTP/socket timeout (ms) |
| `mcp.ua` | a neutral Chrome UA | User-Agent to send (see WAF note below) |
| `mcp.sse_path` | `/sse` | Legacy HTTP+SSE path |
| `mcp.token` | _none_ | Bearer token sent as `Authorization: Bearer <token>` on the handshake and every `*/list` call - enumerates an auth-gated server (see below) |
| `mcp.allports` | _off_ | Probe **every** open TCP port (ignore the port heuristic) |
| `mcp-enum.schemas` | _off_ | Dump each tool's full JSON input schema |

> **Auth posture:** with no token, an OAuth-gated server is reported as `auth: REQUIRED
> (OAuth/Bearer)` and its authorization server/scopes are discovered from RFC 9728
> metadata. With a valid `mcp.token`, the handshake completes and `mcp-info` reports
> `auth: PROVIDED (Bearer token accepted)`; `mcp-enum` then enumerates the tool surface.

#### Authenticated enumeration

To enumerate a server that requires a bearer token, pass it via `mcp.token`. Avoid
putting a token on the command line (it is visible in `ps`/shell history); use a
`--script-args-file` with mode `0600` instead:

```bash
umask 077
printf 'mcp.paths=/mcp\nmcp.token=%s\n' "$TOKEN" > mcp.args   # 0600, off the process list
nmap -sT -Pn -p 443 --script "mcp-info,mcp-enum" --script-args-file mcp.args <target>
rm -f mcp.args
```

The scripts remain **read-only** when authenticated: a supplied token is used only to
complete `initialize` and the `*/list` calls - `tools/call` is never invoked.

> **Port heuristic:** by default the scripts run on HTTP-fingerprinted ports, a built-in
> list of common MCP/dev ports, and any service `-sV` could not identify but which
> returned data (MCP behind uvicorn/ASGI is often not recognised as HTTP). Use `-sV` for
> best coverage, or `mcp.allports=true` to force a probe on every open port.

> **WAF note:** a User-Agent containing the string `nmap` is blocked by common WAFs - e.g.
> AWS WAF/CloudFront returns `403`, masking a real MCP server that would otherwise return
> `401`/`200`. These scripts therefore default to a neutral browser UA. Verified live
> against an authorised CloudFront-fronted target: `nmap`-UA -> 403, neutral UA -> 401.

### `-sV` integration
`nmap -sV --script mcp-info` makes the service column show `mcp` with the server
name/version - the version-category script overrides the generic `http` match via
`set_port_version`. The standalone `nmap-service-probes.mcp` fragment is a *supplement*
(useful on ports not already hard-matched as HTTP); for MCP-over-HTTP the script override
is the authoritative path because nmap's HTTP probe hard-matches first.

## Example output

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
|   server: acme-toolserver 1.4.2 (protocol 2025-06-18)
|   tools (5):
|     run_command [RISK: code-exec] - Execute a shell command on the host  (params: cmd*)
|     read_file [RISK: file-access] - Read a file from disk  (params: path*)
|     process [RISK: file-access, network/ssrf] - Process the input data  (params: count, output_path*, target_url*)
|     search_web - Search the web for a query  (params: q)
|     get_weather - Get the weather for a city  (params: city)
|   resources (3): file:///etc/, db://customers, file:///{path} (template)
|   prompts (1): summarize
|_  SECURITY: unauthenticated server exposes 3 risky tool(s) [code-exec, file-access, network/ssrf]: run_command, read_file, process
```

Risk is assessed across the tool name, description, **and JSON input schema**: `process`
above has a benign name/description but is flagged purely from its `output_path` and
`target_url` parameters (the constrained integer `count` is ignored). Risk-contributing
parameters are marked `*`.

## Testing

Either install the lib or use the `--datadir` harness above (omitted below for brevity).

**Regression matrix** (fastest check) drives the mock across protocol versions, all three
transports, and both auth states, asserting the expected output (23 checks):

```bash
test/run_matrix.sh        # exits non-zero on any failure
```

**Mock server** (dependency-free) for ad-hoc probing; `MCP_PROTOCOL` overrides the
advertised protocol version:

```bash
python3 test/mock_mcp_server.py 8000 &
nmap -sT -Pn -p 8000 --script "mcp-info,mcp-enum" 127.0.0.1                       # streamable
nmap -sT -Pn -p 8000 --script mcp-info --script-args mcp.paths=/sse 127.0.0.1     # legacy SSE
nmap -sT -Pn -p 8000 --script "mcp-info,mcp-enum" \
     --script-args mcp.paths=/authmcp,mcp.token=mock-test-token-abc123 127.0.0.1  # authenticated
```

**Real frameworks:**

```bash
pip install "mcp[cli]" uvicorn && python test/fastmcp_server.py 9001 &   # Python SDK
PORT=9002 npx -y @modelcontextprotocol/server-everything streamableHttp &
nmap -sT -Pn -p 9001,9002 --script "mcp-info,mcp-enum" --script-args mcp.allports=true 127.0.0.1
```

Verified against nmap 7.94 (Lua 5.4).

## Real-target example (authorised)

Against an OAuth-protected production MCP server, the *unauthenticated* probe still
fingerprints it and discovers its authorization server - without credentials:

```
443/tcp open  ssl/mcp MCP server (auth required) (OAuth-protected)
| mcp-info:
|   transport: streamable-http
|   endpoint: /mcp
|   auth: REQUIRED (OAuth/Bearer)
|   oauth_resource: https://mcp.example.ai/mcp
|   oauth_authorization_servers: https://mcp-auth.example.ai
|   oauth_scopes: mcp
|_  oauth_metadata_url: /.well-known/oauth-protected-resource
```

`mcp-enum` correctly produces no output here (tool enumeration requires authentication).

## Scope & ethics
Authorised testing only. The scripts perform standard service recon; the security
findings (unauthenticated access, dangerous tools) are **reported, not exploited**.
stdio-transport MCP servers (local subprocess) are out of scope as they are not
network-reachable.

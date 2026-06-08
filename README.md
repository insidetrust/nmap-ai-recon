# nmap-mcp — NSE scripts for enumerating MCP servers

Nmap Scripting Engine (NSE) plugins to **discover, fingerprint, and enumerate the attack
surface of Model Context Protocol (MCP) servers** during authorised security assessments.

Neither **nmap** nor **Metasploit** can scan MCP *services* on the network (their "MCP"
projects wrap those tools *as* MCP servers for an LLM — the inverse). **Tenable Web App
Scanning** does cover it commercially (plugins 114790/114791/114965). These scripts are the
open, free, CLI-native equivalent. See [`PRD.md`](PRD.md) for the spec/roadmap and
[`WRITEUP.md`](WRITEUP.md) for the research write-up.

## Scripts

| File | Category | What it does |
|--------|----------|--------------|
| `scripts/mcp-info.nse` | `discovery, safe, version` | Detects MCP over HTTP(S) via the JSON-RPC `initialize` handshake (Streamable HTTP) with a legacy HTTP+SSE fallback and OAuth metadata parsing. Reports transport, endpoint, server name/version, protocol version, capabilities, session statefulness, and auth posture. Feeds `-sV`. |
| `scripts/mcp-enum.nse` | `discovery, safe` | Completes the handshake then calls `tools/list`, `resources/list`, `resources/templates/list`, `prompts/list`. Lists tools/params, resources, prompts; flags **dangerous tools** and **unauthenticated exposure**. |
| `scripts/mcp.lua` | nselib | Shared library: both transports (raw-socket), the handshake, OAuth discovery, and enumeration. Must be installed into nmap's `nselib/`. |

Both scripts are **read-only**: they issue only the protocol handshake and `*/list`
methods. They never call `tools/call`, so no server-side tool is ever executed.

### Field-tested against real servers
- **Official Python SDK (FastMCP)** — Streamable HTTP ✅
- **`@modelcontextprotocol/server-everything`** — `streamableHttp` and `sse` (legacy) ✅
- **Live OAuth-protected production server** (CloudFront-fronted) — correctly reported as
  auth-required with its authorization server discovered, unauthenticated ✅

Hardening these field tests forced (all handled automatically):
- nmap's `http.post` **hangs** on servers that keep the SSE response stream open
  (FastMCP/uvicorn), so the transport uses **raw sockets**, reading only until the
  JSON-RPC reply arrives.
- **TLS auto-fallback**: tries the heuristically-preferred mode, falls back on the other.
- **Host header includes the port** — MCP servers validate it for DNS-rebinding protection
  and return `421` otherwise.
- **`initialize` sends `protocolVersion` + `clientInfo`** — strict servers reject empty
  params with `-32602`.

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
| `mcp.paths` | 15 common paths (`/mcp`, `/`, `/sse`, `/api/mcp`, …) | Endpoint paths to probe |
| `mcp.timeout` | `7000` | Per-request HTTP/socket timeout (ms) |
| `mcp.ua` | a neutral Chrome UA | User-Agent to send (see WAF note below) |
| `mcp.sse_path` | `/sse` | Legacy HTTP+SSE path |
| `mcp.allports` | _off_ | Probe **every** open TCP port (ignore the port heuristic) |
| `mcp-enum.schemas` | _off_ | Dump each tool's full JSON input schema |

> **Port heuristic:** by default the scripts run on HTTP-fingerprinted ports, a built-in
> list of common MCP/dev ports, and any service `-sV` could not identify but which
> returned data (MCP behind uvicorn/ASGI is often not recognised as HTTP). Use `-sV` for
> best coverage, or `mcp.allports=true` to force a probe on every open port.

> **WAF note:** a User-Agent containing the string `nmap` is blocked by common WAFs — e.g.
> AWS WAF/CloudFront returns `403`, masking a real MCP server that would otherwise return
> `401`/`200`. These scripts therefore default to a neutral browser UA. Verified live
> against an authorised CloudFront-fronted target: `nmap`-UA → 403, neutral UA → 401.

### `-sV` integration
`nmap -sV --script mcp-info` makes the service column show `mcp` with the server
name/version — the version-category script overrides the generic `http` match via
`set_port_version`. The standalone `nmap-service-probes.mcp` fragment is a *supplement*
(useful on ports not already hard-matched as HTTP); for MCP-over-HTTP the script override
is the authoritative path because nmap's HTTP probe hard-matches first.

### Prior art / how this differs
No open nmap or Metasploit capability scans MCP *services* (their "MCP" projects wrap the
tool *as* an MCP server). Tenable **Web App Scanning** does cover it (plugins 114790 /
114791 / 114965, "Artificial Intelligence" family, 2025). This project is the free,
scriptable, CLI-native equivalent for any engagement.

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
|   tools (4):
|     run_command [!! DANGEROUS] - Execute a shell command on the host  (params: cmd)
|     read_file [!! DANGEROUS] - Read a file from disk  (params: path)
|     search_web - Search the web for a query  (params: q)
|     get_weather - Get the weather for a city  (params: city)
|   resources (3): file:///etc/, db://customers, file:///{path} (template)
|   prompts (1): summarize
|_  SECURITY: unauthenticated server exposes 2 dangerous tool(s): run_command, read_file
```

## Testing

All examples assume the lib is reachable; either install it or use the `--datadir`
harness shown above (commands below omit `--datadir` for brevity).

**Mock server** (dependency-free) exercises every transport + the OAuth path:

```bash
python3 test/mock_mcp_server.py 8000 &
nmap -sT -Pn -p 8000 --script "mcp-info,mcp-enum" 127.0.0.1                       # streamable JSON
nmap -sT -Pn -p 8000 --script mcp-info --script-args mcp.paths=/mcpsse 127.0.0.1  # SSE-framed
nmap -sT -Pn -p 8000 --script mcp-info --script-args mcp.paths=/nope 127.0.0.1    # legacy fallback
nmap -sT -Pn -p 8000 --script mcp-info --script-args mcp.paths=/authmcp 127.0.0.1 # OAuth-gated
```

**Real servers** (field tests):

```bash
# Official Python SDK (FastMCP)
/tmp/mcpvenv/bin/pip install "mcp[cli]" uvicorn
/tmp/mcpvenv/bin/python test/fastmcp_server.py 9001 &
nmap -sT -Pn -p 9001 --script "mcp-info,mcp-enum" --script-args mcp.allports=true 127.0.0.1

# Reference server, both transports
PORT=9002 npx -y @modelcontextprotocol/server-everything streamableHttp &
PORT=9003 npx -y @modelcontextprotocol/server-everything sse &
nmap -sT -Pn -p 9002,9003 --script "mcp-info,mcp-enum" --script-args mcp.allports=true 127.0.0.1
```

Verified against nmap 7.94 (Lua 5.4).

## Real-target example (authorised)

Against an OAuth-protected production MCP server, the *unauthenticated* probe still
fingerprints it and discovers its authorization server — without credentials:

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

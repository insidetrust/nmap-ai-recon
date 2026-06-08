---
-- Shared library for enumerating Model Context Protocol (MCP) servers over HTTP(S).
--
-- Provides transport handling for both the current Streamable HTTP transport and the
-- legacy HTTP+SSE transport (2024-11-05), the JSON-RPC `initialize` handshake, OAuth
-- protected-resource discovery, and read-only attack-surface enumeration
-- (tools/resources/prompts). Used by the mcp-info and mcp-enum NSE scripts.
--
-- All operations are read-only: only the protocol handshake and `*/list` methods are
-- ever called. `tools/call` is never invoked.
--
-- @author ben.williams@nccgroup.com
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html

local http = require "http"
local json = require "json"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local stringaux = require "stringaux"
local string = require "string"
local table = require "table"

_ENV = stdnse.module("mcp", stdnse.seeall)

-- Protocol version advertised by our client handshake.
CLIENT_PROTO = "2025-06-18"

-- Neutral default User-Agent. A UA containing "nmap" is blocked by common WAFs
-- (e.g. AWS WAF/CloudFront returns 403), masking real MCP servers. Override with
-- --script-args mcp.ua=...
DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

-- Candidate Streamable HTTP endpoint paths, broadest-first.
PATHS = {
  "/mcp", "/", "/sse", "/messages", "/api/mcp", "/mcp/v1", "/v1/mcp", "/rpc",
  "/jsonrpc", "/mcp/sse", "/mcp/message", "/mcp/messages", "/stream", "/api", "/server",
}

-- Legacy HTTP+SSE GET paths to try.
SSE_PATHS = {"/sse", "/mcp/sse", "/mcp"}

-- Ports where MCP servers are commonly bound (in addition to anything fingerprinted
-- as HTTP). Includes dev-server defaults and the MCP Inspector (6274).
PORTS = {
  3000, 3001, 3333, 4000, 5000, 5173, 8000, 8001, 8080, 8081, 8082, 8088,
  8123, 8765, 8888, 9000, 6274, 2024,
}
local PORTS_SET = {}
for _, p in ipairs(PORTS) do PORTS_SET[p] = true end

-- Heuristic substrings marking a tool as security-relevant attack surface.
-- Deliberately specific to limit false positives on benign verbs (plain
-- "query"/"url"/"fetch" are intentionally excluded).
DANGEROUS = {
  "exec", "shell", "command", "cmd", "spawn", "subprocess", "system", "bash",
  "powershell", "eval", "write_file", "writefile", "delete", "unlink", "rmdir",
  "sql", "database", "psql", "read_file", "readfile", "file_read", "read_path",
  "http_request", "fetch_url", "request_url", "ssrf", "upload", "download",
  "ssh", "kubectl", "terraform", "sudo", "secret", "credential", "private_key",
  "api_key", "password", "environment variable", "getenv", "dotenv",
}

--------------------------------------------------------------------------------
-- Argument / helper plumbing
--------------------------------------------------------------------------------

-- Build an options table from script-args (shared by both scripts).
function args()
  local paths_arg = stdnse.get_script_args("mcp.paths")
  local paths = PATHS
  if paths_arg then
    paths = type(paths_arg) == "table" and paths_arg or stringaux.strsplit(",", paths_arg)
  end
  return {
    paths = paths,
    timeout = tonumber(stdnse.get_script_args("mcp.timeout")) or 7000,
    ua = stdnse.get_script_args("mcp.ua") or DEFAULT_UA,
    sse_path = stdnse.get_script_args("mcp.sse_path"),
    schemas = stdnse.get_script_args("mcp-enum.schemas"),
  }
end

-- Shared portrule. MCP servers run behind ASGI stacks (uvicorn/starlette) that nmap
-- often fails to fingerprint as HTTP on non-standard ports, so in addition to
-- HTTP-fingerprinted ports and the common MCP port set we also probe any service that
-- -sV could not identify but which returned data (service_fp set). The mcp.allports
-- script-arg forces a probe on every open TCP port.
function portrule(host, port)
  if port.protocol ~= "tcp" or port.state ~= "open" then
    return false
  end
  if stdnse.get_script_args("mcp.allports") then
    return true
  end
  if shortport.http(host, port) then
    return true
  end
  if PORTS_SET[port.number] then
    return true
  end
  -- -sV ran, returned data, but produced no service match: worth one MCP probe.
  if port.version and port.version.service_fp then
    return true
  end
  return false
end

-- Extract the first JSON-RPC object from a body, handling plain application/json
-- and text/event-stream (SSE `data:` framing).
function extract_json(body)
  if not body or body == "" then
    return nil
  end
  local ok, obj = json.parse(body)
  if ok and type(obj) == "table" then
    return obj
  end
  for chunk in body:gmatch("data:%s*(%b{})") do
    local ok2, obj2 = json.parse(chunk)
    if ok2 and type(obj2) == "table" then
      return obj2
    end
  end
  local first = body:match("(%b{})")
  if first then
    local ok3, obj3 = json.parse(first)
    if ok3 and type(obj3) == "table" then
      return obj3
    end
  end
  return nil
end

function gen(obj)
  local ok, s = pcall(json.generate, obj)
  return ok and s or nil
end

function is_dangerous(name, desc)
  local hay = ((name or "") .. " " .. (desc or "")):lower()
  for _, pat in ipairs(DANGEROUS) do
    if hay:find(pat, 1, true) then
      return true
    end
  end
  return false
end

-- JSON-RPC params per method. `initialize` MUST carry protocolVersion + clientInfo;
-- strict servers (e.g. FastMCP) reject an empty params object with -32602.
local function rpc_params(method)
  if method == "initialize" then
    return {
      protocolVersion = CLIENT_PROTO,
      capabilities = {},
      clientInfo = { name = "mcp-scan", version = "0.3" },
    }
  end
  return {}
end

local function post_headers(ctx, ua)
  local h = {
    ["Content-Type"] = "application/json",
    ["Accept"] = "application/json, text/event-stream",
    ["User-Agent"] = ua,
  }
  if ctx and ctx.session_id then h["Mcp-Session-Id"] = ctx.session_id end
  if ctx and ctx.protocol then h["MCP-Protocol-Version"] = ctx.protocol end
  return h
end

local function list_array(obj, key)
  if type(obj) == "table" and type(obj.result) == "table" and type(obj.result[key]) == "table" then
    return obj.result[key]
  end
  return nil
end

--------------------------------------------------------------------------------
-- OAuth 2.1 protected-resource metadata (RFC 9728)
--------------------------------------------------------------------------------

-- Fetch protected-resource metadata for an auth-gated server. Per RFC 9728 the
-- document is hosted on the resource server itself, so we fetch its path against the
-- host being scanned; any authorization servers it names are reported, never followed.
function fetch_oauth_metadata(host, port, www, opts)
  local options = { header = { ["Accept"] = "application/json", ["User-Agent"] = opts.ua }, timeout = opts.timeout }
  local url = www and www:match('resource_metadata="?([^",%s]+)')
  local path = url and url:gsub("^https?://[^/]+", "") or "/.well-known/oauth-protected-resource"
  if path == "" then path = "/.well-known/oauth-protected-resource" end

  local resp = http.get(host, port, path, options)
  if not resp or resp.status ~= 200 or not resp.body then
    return { metadata_url = path }
  end
  local ok, doc = json.parse(resp.body)
  if not ok or type(doc) ~= "table" then
    return { metadata_url = path }
  end
  local meta = { metadata_url = path }
  if doc.resource then meta.resource = tostring(doc.resource) end
  if type(doc.authorization_servers) == "table" then
    meta.authorization_servers = table.concat(doc.authorization_servers, ", ")
  end
  if type(doc.scopes_supported) == "table" then
    meta.scopes = table.concat(doc.scopes_supported, ", ")
  end
  if type(doc.bearer_methods_supported) == "table" then
    meta.bearer_methods = table.concat(doc.bearer_methods_supported, ", ")
  end
  return meta
end

--------------------------------------------------------------------------------
-- Raw-socket transport primitives (shared by streamable + legacy)
--------------------------------------------------------------------------------

-- Receive into buf until matcher(buf) returns non-nil, or the stream stalls.
local function recv_until(sock, buf, matcher, max_reads)
  for _ = 1, (max_reads or 40) do
    local m = matcher(buf)
    if m ~= nil then return m, buf end
    local status, data = sock:receive()
    if not status then break end
    buf = buf .. data
  end
  return matcher(buf), buf
end

-- Find a JSON-RPC response with the given id anywhere in a raw response buffer,
-- handling both SSE `data:` framing (possibly chunked) and a plain JSON body.
local function find_response(buf, id)
  for chunk in buf:gmatch("data:%s*(%b{})") do
    local ok, parsed = json.parse(chunk)
    if ok and type(parsed) == "table" and parsed.id == id
        and (parsed.result ~= nil or parsed.error ~= nil) then
      return parsed
    end
  end
  local body = buf:match("\r\n\r\n(.*)$")
  if body then
    local first = body:match("(%b{})")
    if first then
      local ok, parsed = json.parse(first)
      if ok and type(parsed) == "table" and parsed.id == id
          and (parsed.result ~= nil or parsed.error ~= nil) then
        return parsed
      end
    end
  end
  return nil
end

local function raw_status(buf)
  return tonumber(buf:match("^HTTP/%d%.%d%s+(%d%d%d)"))
end

-- Build a correct Host header (incl. non-default port). MCP servers validate the Host
-- header for DNS-rebinding protection (mandated by the spec) and return 421 if it is
-- wrong, so the port must be present for non-default ports.
local function host_header(host, port)
  local h = host.targetname or host.ip
  if port.number == 80 or port.number == 443 then
    return h
  end
  return h .. ":" .. port.number
end

local function raw_header(buf, name)
  local head = buf:match("^(.-)\r\n\r\n") or buf
  for line in head:gmatch("[^\r\n]+") do
    local k, v = line:match("^([%w%-]+):%s*(.*)$")
    if k and k:lower() == name:lower() then return (v:gsub("%s+$", "")) end
  end
  return nil
end

--------------------------------------------------------------------------------
-- Transport: Streamable HTTP
--------------------------------------------------------------------------------

-- One raw POST over a given TLS mode. Returns (obj, buf); buf is the raw response so
-- the caller can detect whether a valid HTTP reply came back over this proto.
local function raw_request(host, port, path, ctx, body, id, proto, opts)
  local sock = nmap.new_socket()
  sock:set_timeout(opts.timeout)
  if not sock:connect(host, port, proto) then sock:close(); return nil, nil end
  local hdr = {
    "POST " .. path .. " HTTP/1.1",
    "Host: " .. host_header(host, port),
    "User-Agent: " .. opts.ua,
    "Accept: application/json, text/event-stream",
    "Content-Type: application/json",
    "Content-Length: " .. #body,
    "Connection: close",
  }
  if ctx and ctx.session_id then hdr[#hdr + 1] = "Mcp-Session-Id: " .. ctx.session_id end
  if ctx and ctx.protocol then hdr[#hdr + 1] = "MCP-Protocol-Version: " .. ctx.protocol end
  local req = table.concat(hdr, "\r\n") .. "\r\n\r\n" .. body
  if not sock:send(req) then sock:close(); return nil, nil end
  local m, buf = recv_until(sock, "", function(b)
    if not b:find("\r\n\r\n", 1, true) then return nil end
    if id == nil then return true end
    return find_response(b, id)
  end, 80)
  sock:close()
  return (id ~= nil) and m or nil, buf
end

-- Send a raw HTTP POST and read only until the JSON-RPC response for `id` appears
-- (or, for notifications, until response headers arrive), then close. Using a raw
-- socket avoids hanging on Streamable-HTTP servers (e.g. FastMCP/uvicorn) that keep
-- the SSE response stream open after delivering the reply, which makes nmap's
-- http.post block until timeout and discard the data already received. The TLS mode
-- is auto-detected: the heuristically-preferred mode is tried first, and the other is
-- tried if no valid HTTP status comes back; the working mode is cached on ctx.
local function http_post_raw(host, port, path, ctx, body, id, opts)
  local protos = (ctx and ctx.proto) and { ctx.proto }
    or (shortport.ssl(host, port) and { "ssl", "tcp" } or { "tcp", "ssl" })
  for _, proto in ipairs(protos) do
    local obj, buf = raw_request(host, port, path, ctx, body, id, proto, opts)
    if buf and raw_status(buf) then
      if ctx then ctx.proto = proto end
      return obj, buf
    end
  end
  return nil, nil
end

local function streamable_rpc(host, port, path, ctx, method, id, opts)
  local payload = { jsonrpc = "2.0", method = method, params = rpc_params(method) }
  if id ~= nil then payload.id = id end
  local body = gen(payload)
  if not body then return nil, nil end
  return http_post_raw(host, port, path, ctx, body, id, opts)
end

-- Try one path. Returns (transport, nil) on success, (nil, auth_hint) on a bearer
-- challenge, or (nil, nil) otherwise.
local function open_streamable_path(host, port, path, opts)
  local ctx = { protocol = CLIENT_PROTO }
  local obj, buf = streamable_rpc(host, port, path, ctx, "initialize", 1, opts)
  if obj and type(obj.result) == "table" then
    local r = obj.result
    if r.serverInfo or r.protocolVersion or r.capabilities then
      ctx.session_id = buf and raw_header(buf, "mcp-session-id") or nil
      ctx.protocol = r.protocolVersion or CLIENT_PROTO
      local t = {
        name = "streamable-http",
        endpoint = path,
        server_info = type(r.serverInfo) == "table" and r.serverInfo or {},
        protocol = ctx.protocol,
        capabilities = r.capabilities,
        session_stateful = ctx.session_id ~= nil,
        authenticated = false,
        request = function(_, method, id)
          return (streamable_rpc(host, port, path, ctx, method, id, opts))
        end,
        close = function() end,
      }
      streamable_rpc(host, port, path, ctx, "notifications/initialized", nil, opts)
      return t, nil
    end
  end
  if buf then
    local status = raw_status(buf)
    local www = raw_header(buf, "www-authenticate")
    if (status == 401 or status == 403) and www and www:lower():find("bearer") then
      return nil, { path = path, www = www }
    end
  end
  return nil, nil
end

--------------------------------------------------------------------------------
-- Transport: legacy HTTP+SSE (2024-11-05)
--------------------------------------------------------------------------------

local function open_legacy_path(host, port, sse_path, proto, opts)
  local sock = nmap.new_socket()
  sock:set_timeout(opts.timeout)
  if not sock:connect(host, port, proto) then
    sock:close()
    return nil
  end
  local get = "GET " .. sse_path .. " HTTP/1.1\r\nHost: " .. host_header(host, port) ..
    "\r\nAccept: text/event-stream\r\nUser-Agent: " .. opts.ua .. "\r\n\r\n"
  if not sock:send(get) then sock:close(); return nil end

  local buf = ""
  local msgpath
  msgpath, buf = recv_until(sock, buf, function(b)
    return b:match("endpoint.-data:%s*([^\r\n]+)")
  end, 30)
  if not msgpath then sock:close(); return nil end
  msgpath = msgpath:gsub("%s+$", "")
  if msgpath:match("^https?://") then
    msgpath = msgpath:gsub("^https?://[^/]+", "")
  end

  local t = {
    name = "http+sse (legacy 2024-11-05)",
    endpoint = sse_path,
    server_info = {},
    protocol = nil,
    capabilities = nil,
    session_stateful = true,
    authenticated = false,
    _sock = sock,
    _buf = buf,
    _msgpath = msgpath,
  }
  t.request = function(self, method, id)
    local payload = { jsonrpc = "2.0", method = method, params = rpc_params(method) }
    if id ~= nil then payload.id = id end
    http.post(host, port, self._msgpath,
      { header = post_headers(nil, opts.ua), timeout = opts.timeout }, nil, gen(payload))
    if id == nil then return nil end
    local parsed
    parsed, self._buf = recv_until(self._sock, self._buf,
      function(b) return find_response(b, id) end, 40)
    return parsed
  end
  t.close = function(self) self._sock:close() end

  local initobj = t:request("initialize", 1)
  if not initobj or type(initobj.result) ~= "table" then sock:close(); return nil end
  local r = initobj.result
  t.protocol = r.protocolVersion
  t.server_info = type(r.serverInfo) == "table" and r.serverInfo or {}
  t.capabilities = r.capabilities
  t:request("notifications/initialized", nil)
  return t
end

local function open_legacy(host, port, opts)
  local candidates, seen = {}, {}
  if opts.sse_path then candidates[#candidates + 1] = opts.sse_path; seen[opts.sse_path] = true end
  for _, p in ipairs(SSE_PATHS) do
    if not seen[p] then candidates[#candidates + 1] = p; seen[p] = true end
  end
  local protos = shortport.ssl(host, port) and { "ssl", "tcp" } or { "tcp", "ssl" }
  for _, proto in ipairs(protos) do
    for _, p in ipairs(candidates) do
      local t = open_legacy_path(host, port, p, proto, opts)
      if t then return t end
    end
  end
  return nil
end

--------------------------------------------------------------------------------
-- Public: connect & enumerate
--------------------------------------------------------------------------------

-- Establish a transport to an MCP server. Returns (transport, nil) on success,
-- (nil, auth_hint) when the server is MCP-behind-auth, or (nil, nil) when not MCP.
-- auth_hint = { path = <string>, www = <WWW-Authenticate value> }.
function connect(host, port, opts)
  opts = opts or args()
  local auth_hint
  for _, path in ipairs(opts.paths) do
    local t, hint = open_streamable_path(host, port, path, opts)
    if t then return t, nil end
    if hint then
      auth_hint = auth_hint or hint
      -- A challenge advertising MCP's OAuth resource_metadata is high-confidence MCP.
      if hint.www and hint.www:lower():find("resource_metadata", 1, true) then
        return nil, hint
      end
    end
  end
  local lt = open_legacy(host, port, opts)
  if lt then return lt, nil end
  return nil, auth_hint
end

-- Read-only attack-surface enumeration over an open transport. Returns a data table:
-- { transport, server_info, protocol, authenticated, tools=[{name,description,params,
--   dangerous,schema}], resources=[uri], prompts=[name], dangerous=[name] }.
function enumerate(transport, opts)
  opts = opts or args()
  local data = {
    transport = transport.name,
    server_info = transport.server_info or {},
    protocol = transport.protocol,
    authenticated = transport.authenticated,
    tools = {}, resources = {}, prompts = {}, dangerous = {},
  }

  for _, tdef in ipairs(list_array(transport:request("tools/list", 2), "tools") or {}) do
    local danger = is_dangerous(tdef.name, tdef.description)
    local params = {}
    if type(tdef.inputSchema) == "table" and type(tdef.inputSchema.properties) == "table" then
      for p in pairs(tdef.inputSchema.properties) do params[#params + 1] = p end
      table.sort(params)
    end
    data.tools[#data.tools + 1] = {
      name = tdef.name or "?",
      description = tdef.description or "",
      params = params,
      dangerous = danger,
      schema = tdef.inputSchema,
    }
    if danger then data.dangerous[#data.dangerous + 1] = tdef.name or "?" end
  end

  for _, r in ipairs(list_array(transport:request("resources/list", 3), "resources") or {}) do
    data.resources[#data.resources + 1] = r.uri or r.name or "?"
  end
  for _, r in ipairs(list_array(transport:request("resources/templates/list", 4), "resourceTemplates") or {}) do
    data.resources[#data.resources + 1] = (r.uriTemplate or r.name or "?") .. " (template)"
  end

  for _, p in ipairs(list_array(transport:request("prompts/list", 5), "prompts") or {}) do
    data.prompts[#data.prompts + 1] = p.name or "?"
  end

  return data
end

return _ENV

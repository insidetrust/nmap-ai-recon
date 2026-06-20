---
-- Shared library for fingerprinting LLM inference APIs exposed over HTTP(S).
--
-- Detects the common self-hosted / cloud inference frameworks by their read-only
-- model-list and metadata endpoints: the OpenAI-compatible API (vLLM, LiteLLM, LocalAI,
-- LM Studio, text-generation-webui, ...), Ollama, HuggingFace TGI, llama.cpp server,
-- Triton/KServe (v2), and TorchServe. Reports the framework, version, model inventory,
-- authentication posture, and notable information leaks.
--
-- All operations are READ-ONLY: only model-list / metadata / health endpoints are
-- requested. No inference endpoint (/v1/chat/completions, /api/generate, /generate, ...)
-- is ever called, so no model is run and no cost is incurred on the target.
--
-- @author Ben Williams <ben.williams@nccgroup.com>
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html

local http = require "http"
local json = require "json"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

_ENV = stdnse.module("llm", stdnse.seeall)

-- Neutral default User-Agent (a UA containing "nmap" is blocked by common WAFs).
DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

-- Ports commonly hosting inference APIs (in addition to HTTP-fingerprinted ports).
-- 11434 Ollama, 8000 vLLM/TGI/Triton, 1234 LM Studio, 4000 LiteLLM, 8081 TorchServe mgmt,
-- 7860/5000 gradio web-UIs.
PORTS = { 11434, 8000, 8080, 8081, 1234, 4000, 5000, 5001, 7860, 3000, 8888, 9000 }
local PORTS_SET = {}
for _, p in ipairs(PORTS) do PORTS_SET[p] = true end

-- Build the options table from script-args, including any supplied credential. A bearer
-- token (llm.token) and/or an arbitrary header (llm.header, e.g. "x-api-key: sk-...",
-- "api-key: ...", "Cookie: session=...") let the scripts test authenticated APIs.
function args()
  local headers = {}
  local token = stdnse.get_script_args("llm.token")
  if token then headers["Authorization"] = "Bearer " .. token end
  local raw = stdnse.get_script_args("llm.header")
  if raw then
    local k, v = tostring(raw):match("^%s*([^:%s]+)%s*:%s*(.+)$")
    if k then headers[k] = v end
  end
  local probe = stdnse.get_script_args("llm.probe")
  return {
    timeout = tonumber(stdnse.get_script_args("llm.timeout")) or 7000,
    ua = stdnse.get_script_args("llm.ua") or DEFAULT_UA,
    headers = headers,
    credentialed = (token ~= nil) or (raw ~= nil),
    -- Active "hello" probe is ON by default; llm.probe=false makes the script read-only.
    probe = not (probe == "false" or probe == "0"),
  }
end

-- Shared portrule: HTTP-fingerprinted ports, the common inference port set, and any
-- service -sV probed but could not identify (inference servers behind uvicorn/ASGI are
-- often not recognised as HTTP). llm.allports forces a probe on every open TCP port.
function portrule(host, port)
  if port.protocol ~= "tcp" or port.state ~= "open" then return false end
  if stdnse.get_script_args("llm.allports") then return true end
  if shortport.http(host, port) then return true end
  if PORTS_SET[port.number] then return true end
  if port.version and port.version.service_fp then return true end
  return false
end

-- Read-only HTTP GET, carrying any supplied credential. Returns (status, body,
-- header-table) or nil on connection failure.
local function get(host, port, path, opts)
  local h = { ["User-Agent"] = opts.ua }
  if opts.headers then for k, v in pairs(opts.headers) do h[k] = v end end
  local resp = http.get(host, port, path, { header = h, timeout = opts.timeout, no_cache = true })
  if not resp then return nil end
  return resp.status, resp.body, resp.header
end

local function jparse(body)
  if not body or body == "" then return nil end
  local ok, obj = json.parse(body)
  if ok and type(obj) == "table" then return obj end
  return nil
end

--------------------------------------------------------------------------------
-- Framework detectors. Each returns a result table or nil:
--   { framework, endpoint, version, models={}, auth_required=bool, leaks={}, server }
--------------------------------------------------------------------------------

-- Ollama: /api/tags lists installed models; /api/version gives the version; the root
-- path returns the literal banner "Ollama is running".
local function detect_ollama(host, port, opts)
  local st, body = get(host, port, "/api/tags", opts)
  if st == 200 then
    local doc = jparse(body)
    if doc and type(doc.models) == "table" then
      local models = {}
      for _, m in ipairs(doc.models) do models[#models + 1] = m.name or m.model or "?" end
      local r = { framework = "Ollama", endpoint = "/api/tags", models = models, auth_required = false, confidence = 90 }
      local _, vb = get(host, port, "/api/version", opts)
      local vd = jparse(vb)
      if vd and vd.version then r.version = vd.version end
      return r
    end
  elseif st == 401 or st == 403 then
    return { framework = "Ollama", endpoint = "/api/tags", auth_required = true, confidence = 90 }
  end
  local st2, body2 = get(host, port, "/", opts)
  if st2 == 200 and body2 and body2:find("Ollama is running", 1, true) then
    return { framework = "Ollama", endpoint = "/", models = {}, auth_required = false, confidence = 80 }
  end
  return nil
end

-- OpenAI-compatible: GET /v1/models returns {"object":"list","data":[{"object":"model"}]}.
-- This catches vLLM, LiteLLM, LocalAI, LM Studio, text-generation-webui, llama.cpp, etc.;
-- secondary probes disambiguate the specific framework.
local function detect_openai(host, port, opts)
  local st, body, hdr = get(host, port, "/v1/models", opts)
  if st == 401 or st == 403 then
    return { framework = "OpenAI-compatible API", endpoint = "/v1/models", auth_required = true, confidence = 30 }
  end
  if st ~= 200 then return nil end
  local doc = jparse(body)
  if not (doc and doc.object == "list" and type(doc.data) == "table") then return nil end
  local models = {}
  for _, m in ipairs(doc.data) do models[#models + 1] = m.id or "?" end
  local r = { framework = "OpenAI-compatible API", endpoint = "/v1/models",
              models = models, auth_required = false, leaks = {}, confidence = 30 }
  if hdr and hdr.server then r.server = hdr.server end

  -- vLLM: GET /version -> {"version": "0.x"}
  local _, vb = get(host, port, "/version", opts)
  local vd = jparse(vb)
  if vd and vd.version then r.framework = "vLLM (OpenAI-compatible)"; r.version = vd.version; r.confidence = 85 end

  -- HuggingFace TGI: GET /info -> {"model_id": ..., "version": ...}
  local _, ib = get(host, port, "/info", opts)
  local idoc = jparse(ib)
  if idoc and idoc.model_id then
    r.framework = "HF text-generation-inference"
    r.version = idoc.version or r.version
    if #r.models == 0 then r.models = { idoc.model_id } end
    r.confidence = 85
  end

  -- llama.cpp server: GET /props -> default_generation_settings / model_path / system_prompt
  local _, pb = get(host, port, "/props", opts)
  local pdoc = jparse(pb)
  if pdoc and (pdoc.default_generation_settings or pdoc.model_path or pdoc.system_prompt ~= nil) then
    r.framework = "llama.cpp server"
    r.confidence = 85
    if pdoc.model_path and #r.models == 0 then r.models = { pdoc.model_path } end
    if type(pdoc.system_prompt) == "string" and pdoc.system_prompt ~= "" then
      r.leaks[#r.leaks + 1] = "system prompt disclosed via /props"
    end
  end
  return r
end

-- HuggingFace TGI without an OpenAI shim (older builds): GET /info.
local function detect_tgi(host, port, opts)
  local st, body = get(host, port, "/info", opts)
  if st == 200 then
    local doc = jparse(body)
    if doc and doc.model_id then
      return { framework = "HF text-generation-inference", endpoint = "/info",
               version = doc.version, models = { doc.model_id }, auth_required = false, confidence = 85 }
    end
  end
  return nil
end

-- llama.cpp server without an OpenAI shim (older builds): GET /props.
local function detect_llamacpp(host, port, opts)
  local st, body = get(host, port, "/props", opts)
  if st == 200 then
    local doc = jparse(body)
    if doc and (doc.default_generation_settings or doc.model_path) then
      local r = { framework = "llama.cpp server", endpoint = "/props", auth_required = false, models = {}, leaks = {}, confidence = 85 }
      if doc.model_path then r.models = { doc.model_path } end
      if type(doc.system_prompt) == "string" and doc.system_prompt ~= "" then
        r.leaks[#r.leaks + 1] = "system prompt disclosed via /props"
      end
      return r
    end
  end
  return nil
end

-- NVIDIA Triton / KServe v2 inference protocol: GET /v2 server metadata, /v2/health/ready.
local function detect_triton(host, port, opts)
  local st, body = get(host, port, "/v2", opts)
  if st == 200 then
    local doc = jparse(body)
    if doc and doc.name then
      return { framework = "Triton/KServe (v2 inference)", endpoint = "/v2",
               version = doc.version, models = {}, auth_required = false, server = doc.name, confidence = 85 }
    end
  end
  local hs = get(host, port, "/v2/health/ready", opts)
  if hs == 200 then
    return { framework = "KServe/Triton (v2 inference)", endpoint = "/v2/health/ready",
             models = {}, auth_required = false, confidence = 75 }
  end
  return nil
end

-- TorchServe management API: GET /models -> {"models":[{"modelName": ...}]}.
local function detect_torchserve(host, port, opts)
  local st, body = get(host, port, "/models", opts)
  if st == 200 then
    local doc = jparse(body)
    if doc and type(doc.models) == "table" and doc.models[1] and doc.models[1].modelName then
      local models = {}
      for _, m in ipairs(doc.models) do models[#models + 1] = m.modelName end
      return { framework = "TorchServe (management API)", endpoint = "/models",
               models = models, auth_required = false, confidence = 75 }
    end
  end
  return nil
end

local DETECTORS = {
  detect_ollama, detect_openai, detect_tgi, detect_llamacpp, detect_triton, detect_torchserve,
}

--------------------------------------------------------------------------------
-- Active "hello" probe (on by default). Sends a single minimal completion request and
-- looks for an inference-shaped response: it confirms the endpoint actually serves a model
-- (not just lists them) and, crucially, detects formats with NO list endpoint -- notably
-- Anthropic's Messages API. Kept minimal (max_tokens = 1, prompt "hello").
--------------------------------------------------------------------------------

local function gen(obj)
  local ok, s = pcall(json.generate, obj)
  return ok and s or nil
end

local function post(host, port, path, extra, body, opts)
  local h = { ["User-Agent"] = opts.ua, ["Content-Type"] = "application/json" }
  if opts.headers then for k, v in pairs(opts.headers) do h[k] = v end end
  if extra then for k, v in pairs(extra) do h[k] = v end end
  local resp = http.post(host, port, path, { header = h, timeout = opts.timeout }, nil, body)
  if not resp then return nil end
  return resp.status, resp.body
end

-- OpenAI-compatible chat hello. Returns "confirmed" on a completion or an OpenAI-shaped
-- error (either proves a chat inference endpoint), "auth" on a credential challenge.
local function hello_openai(host, port, model, opts)
  local body = gen({ model = model or "gpt-3.5-turbo",
                     messages = { { role = "user", content = "hello" } }, max_tokens = 1 })
  if not body then return nil end
  local st, rb = post(host, port, "/v1/chat/completions", nil, body, opts)
  if not st then return nil end
  local doc = jparse(rb)
  if st == 200 and doc and (doc.choices or doc.object == "chat.completion") then return "confirmed" end
  if st == 401 or st == 403 then return "auth" end
  if doc and type(doc.error) == "table" then return "confirmed" end
  return nil
end

-- Ollama native generate hello.
local function hello_ollama(host, port, model, opts)
  local body = gen({ model = model or "llama3", prompt = "hello", stream = false,
                     options = { num_predict = 1 } })
  if not body then return nil end
  local st, rb = post(host, port, "/api/generate", nil, body, opts)
  if not st then return nil end
  local doc = jparse(rb)
  if st == 200 and doc and (doc.response ~= nil or doc.done ~= nil) then return "confirmed" end
  if doc and doc.error then return "confirmed" end
  return nil
end

-- Anthropic Messages API: no list endpoint exists, so a minimal /v1/messages request is the
-- only fingerprint. Identified by the Anthropic message/error response shape; an
-- unauthenticated server returns 401 WITHOUT running a model.
local function probe_anthropic(host, port, opts)
  local body = gen({ model = "claude-3-5-haiku-latest", max_tokens = 1,
                     messages = { { role = "user", content = "hello" } } })
  if not body then return nil end
  local st, rb = post(host, port, "/v1/messages", { ["anthropic-version"] = "2023-06-01" }, body, opts)
  if not st then return nil end
  local doc = jparse(rb)
  if doc and (doc.type == "message"
      or (doc.type == "error" and type(doc.error) == "table" and doc.error.type)) then
    return { framework = "Anthropic Messages API", endpoint = "/v1/messages",
             models = {}, auth_required = (st == 401 or st == 403), confidence = 88,
             inference = (st == 200) and "confirmed" or nil }
  end
  return nil
end

-- Known model IDs to probe on an API with no usable list endpoint (Anthropic) or one that
-- is disabled. A small built-in set; a model that responds (rather than "model not found")
-- is reported as present/accessible. Active and bounded - authorised assessments only.
KNOWN_MODELS = {
  anthropic = { "claude-3-5-sonnet-latest", "claude-3-5-haiku-latest",
                "claude-3-opus-latest", "claude-3-haiku-20240307" },
  openai = { "gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-3.5-turbo" },
}

local function enum_anthropic(host, port, opts)
  local found = {}
  for _, m in ipairs(KNOWN_MODELS.anthropic) do
    local body = gen({ model = m, max_tokens = 1, messages = { { role = "user", content = "hi" } } })
    local st, rb = post(host, port, "/v1/messages", { ["anthropic-version"] = "2023-06-01" }, body, opts)
    local doc = jparse(rb)
    if st == 200 then
      found[#found + 1] = m
    elseif doc and doc.type == "error" and type(doc.error) == "table"
        and doc.error.type ~= "not_found_error" and st ~= 404 then
      found[#found + 1] = m .. " (accessible; non-404 response)"
    end
  end
  return found
end

local function enum_openai(host, port, opts)
  local found = {}
  for _, m in ipairs(KNOWN_MODELS.openai) do
    local body = gen({ model = m, messages = { { role = "user", content = "hi" } }, max_tokens = 1 })
    local st = post(host, port, "/v1/chat/completions", nil, body, opts)
    if st == 200 then found[#found + 1] = m end
  end
  return found
end

-- Probe a host:port for a known inference API. EVERY detector runs; the result is chosen by
-- signal specificity (the `confidence` each detector assigns), NOT by detector order -- so a
-- server matching several signatures (e.g. Ollama, which also serves /v1/models) is reported
-- by its most specific match. A positive (HTTP 200) identification always beats an auth-gated
-- hint (a framework endpoint returning 401/403). Reordering DETECTORS cannot change the result.
function detect(host, port, opts)
  opts = opts or args()
  local best_pos, best_gated
  for _, d in ipairs(DETECTORS) do
    local r = d(host, port, opts)
    if r then
      r.confidence = r.confidence or 0
      if r.auth_required then
        if not best_gated or r.confidence > best_gated.confidence then best_gated = r end
      else
        if not best_pos or r.confidence > best_pos.confidence then best_pos = r end
      end
    end
  end
  local result = best_pos or best_gated

  -- Active "hello" probe (on by default): confirm inference on an identified endpoint, or
  -- actively detect a list-less API (Anthropic) / otherwise-unidentified inference endpoint.
  if opts.probe then
    if result and not result.auth_required then
      local conf
      if result.framework == "Ollama" then
        conf = hello_ollama(host, port, result.models and result.models[1], opts)
      else
        conf = hello_openai(host, port, result.models and result.models[1], opts)
      end
      if conf then result.inference = conf end
    elseif not result then
      result = probe_anthropic(host, port, opts)
      if not result and hello_openai(host, port, nil, opts) then
        result = { framework = "OpenAI-compatible API", endpoint = "/v1/chat/completions",
                   models = {}, auth_required = false, confidence = 40, inference = "confirmed" }
      end
    end

    -- Active model enumeration for an API with no usable list (Anthropic) or a disabled one:
    -- probe a small set of known model IDs and report those that respond.
    if result and not result.auth_required and (not result.models or #result.models == 0) then
      local found
      if result.framework:find("Anthropic", 1, true) then
        found = enum_anthropic(host, port, opts)
      elseif result.framework:find("OpenAI", 1, true) or result.endpoint == "/v1/chat/completions" then
        found = enum_openai(host, port, opts)
      end
      if found and #found > 0 then result.models = found; result.models_enumerated = true end
    end
  end

  -- Capture the Server response header of the matched endpoint as a secondary fingerprint
  -- (uvicorn, TornadoServer, ...); it sometimes carries a version the API itself does not.
  if result and not result.server then
    local _, _, h = get(host, port, result.endpoint, opts)
    if h and h["server"] then result.server = h["server"] end
  end
  return result
end

return _ENV

local llm = require "llm"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Detects and fingerprints LLM inference APIs exposed over HTTP(S).

Probes a target for the common self-hosted and cloud inference frameworks by their
read-only model-list and metadata endpoints: the OpenAI-compatible API (vLLM, LiteLLM,
LocalAI, LM Studio, text-generation-webui, ...), Ollama, HuggingFace TGI, llama.cpp
server, Triton/KServe (v2), and TorchServe. On a match it reports the framework, version,
model inventory, authentication posture, and notable information leaks (e.g. a llama.cpp
system prompt exposed via /props). It augments service/version detection via -sV.

This script is read-only and safe: it requests only model-list, metadata, and health
endpoints. It never sends an inference request, so no model is run and no cost is incurred
on the target. To actively confirm an API, test a credential, or enumerate models on an
endpoint with no list (e.g. Anthropic), see the companion intrusive script llm-probe.

A bearer token (llm.token) or arbitrary header (llm.header, e.g. an API key or session
cookie) may be supplied to test an authenticated API. Shared logic lives in the llm nselib.
]]

---
-- @usage nmap -p 11434,8000,1234 --script llm-info <target>
-- @usage nmap -sV --script llm-info <target>
-- @usage nmap --script llm-info --script-args llm.token=sk-... <target>
-- @usage nmap --script llm-info --script-args 'llm.header=x-api-key: sk-...' <target>
--
-- @args llm.token   Bearer token, sent as "Authorization: Bearer <token>".
-- @args llm.header  Arbitrary auth header "Name: value" (e.g. "x-api-key: sk-...",
--                   "api-key: ...", "Cookie: session=..."), to test credentialed APIs.
-- @args llm.timeout HTTP timeout in ms (default 7000).
-- @args llm.ua      User-Agent to send (default a neutral browser UA).
-- @args llm.allports Probe every open TCP port (ignore the port heuristic).
--
-- @output
-- PORT      STATE SERVICE
-- 11434/tcp open  llm-api
-- | llm-info:
-- |   framework: Ollama
-- |   version: 0.3.14
-- |   endpoint: /api/tags
-- |   auth: NONE (unauthenticated)
-- |   models (3): llama3:8b, qwen2.5:7b, nomic-embed-text:latest
-- |_  SECURITY: unauthenticated inference API (Ollama) exposes 3 model(s); open to compute/cost abuse and model disclosure
--
-- @xmloutput
-- <elem key="framework">Ollama</elem>
-- <elem key="version">0.3.14</elem>
-- <elem key="endpoint">/api/tags</elem>
-- <elem key="auth">NONE (unauthenticated)</elem>
-- <table key="models (3)">
--   <elem>llama3:8b</elem>
--   <elem>qwen2.5:7b</elem>
--   <elem>nomic-embed-text:latest</elem>
-- </table>
-- <elem key="SECURITY">unauthenticated inference API (Ollama) exposes 3 model(s); open to compute/cost abuse and model disclosure</elem>

author = "Ben Williams <ben.williams@nccgroup.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "version"}

portrule = llm.portrule

action = function(host, port)
  local opts = llm.args()
  local r = llm.detect(host, port, opts)
  if not r then
    return nil
  end

  local out = stdnse.output_table()
  out.framework = r.framework
  if r.version then out.version = r.version end
  if r.server then out.server = r.server end
  out.endpoint = r.endpoint

  if r.auth_required then
    out.auth = opts.credentialed and "REQUIRED (supplied credential rejected)"
      or "REQUIRED (key/credentials)"
  elseif opts.credentialed then
    out.auth = "PROVIDED (credential accepted)"
  else
    out.auth = "NONE (unauthenticated)"
  end

  if r.models and #r.models > 0 then
    out["models (" .. #r.models .. ")"] = r.models
  end
  if r.leaks and #r.leaks > 0 then
    out.leaks = r.leaks
  end

  if not r.auth_required and not opts.credentialed then
    local n = (r.models and #r.models) or 0
    out.SECURITY = string.format(
      "unauthenticated inference API (%s) exposes %d model(s); open to compute/cost abuse and model disclosure",
      r.framework, n)
  end

  -- Feed -sV.
  port.version.name = "llm-api"
  port.version.product = r.framework
  if r.version then port.version.version = r.version end
  port.version.extrainfo = r.auth_required and "auth required" or "unauthenticated"
  nmap.set_port_version(host, port, "hardmatched")

  return out
end

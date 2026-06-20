#!/usr/bin/env bash
#
# Local regression matrix for the llm-info NSE script.
#
# Brings up the bundled mock in each framework / auth configuration and asserts the expected
# output: detection (order-independent), version, auth state, credentials, the active hello
# probe, model listing + enumeration, and error-condition fingerprinting.
#
# Requires: nmap, python3.  Usage: test/run_llm_matrix.sh
#
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT=8771
TOKEN=test-llm-key-abc123
TMPROOT="$(mktemp -d)"
DD="$TMPROOT/datadir"

mkdir -p "$DD/scripts" "$DD/nselib"
cp "$ROOT"/scripts/llm-info.nse "$DD/scripts/"
cp "$ROOT"/nselib/llm.lua "$DD/nselib/"
cp /usr/share/nmap/scripts/script.db "$DD/scripts/" 2>/dev/null
nmap --datadir "$DD" --script-updatedb >/dev/null 2>&1

pass=0; fail=0; MOCKPID=""
start() { LLM_MODE="$1" python3 "$ROOT/test/mock_llm_server.py" "$PORT" >/tmp/llm-matrix-mock.log 2>&1 & MOCKPID=$!; sleep 1.1; }
stop() { [ -n "$MOCKPID" ] && kill "$MOCKPID" 2>/dev/null; wait "$MOCKPID" 2>/dev/null; MOCKPID=""; }
trap 'stop; rm -rf "$TMPROOT"' EXIT

scan() {  # optional extra script-args; llm.allports lets the probe fire on any test port
  local sargs="llm.allports=true"
  [ -n "${1:-}" ] && sargs="$sargs,$1"
  nmap --datadir "$DD" -sT -Pn -p "$PORT" --script llm-info --script-args "$sargs" 127.0.0.1 2>/dev/null
}
check() { if grep -qE "$2" <<<"$3"; then printf '  PASS  %s\n' "$1"; pass=$((pass+1))
  else printf '  FAIL  %s  (expected /%s/)\n' "$1" "$2"; fail=$((fail+1)); fi; }
absent() { if grep -qE "$2" <<<"$3"; then printf '  FAIL  %s  (unexpected /%s/)\n' "$1" "$2"; fail=$((fail+1))
  else printf '  PASS  %s\n' "$1"; pass=$((pass+1)); fi; }

echo "== Framework detection + version =="
start ollama;     o=$(scan); check "ollama"     "framework: Ollama" "$o"; check "ollama version" "version: 0.3.14" "$o"; stop
start openai;     o=$(scan); check "openai"     "framework: OpenAI-compatible API" "$o"; stop
start vllm;       o=$(scan); check "vllm"       "framework: vLLM" "$o"; check "vllm version" "version: 0.6.2" "$o"; stop
start tgi;        o=$(scan); check "tgi"        "framework: HF text-generation-inference" "$o"; stop
start llamacpp;   o=$(scan); check "llamacpp"   "framework: llama.cpp server" "$o"; check "llamacpp leak" "system prompt" "$o"; stop
start triton;     o=$(scan); check "triton"     "framework: Triton/KServe" "$o"; stop
start torchserve; o=$(scan); check "torchserve" "framework: TorchServe \(management API\)" "$o"; stop
start torchserve_inference; o=$(scan)
check "torchserve inference-port (/api-description)" "framework: TorchServe \(inference API\)" "$o"
check "torchserve inference endpoint" "endpoint: /api-description" "$o"; stop
start sglang;     o=$(scan); check "sglang"     "framework: SGLang" "$o"; check "sglang model" "meta-llama" "$o"; stop
start koboldcpp;  o=$(scan); check "koboldcpp"  "framework: KoboldCpp" "$o"; check "kobold version" "version: 1.66" "$o"; stop
start tei;        o=$(scan); check "tei"        "framework: HF text-embeddings-inference" "$o"; stop

echo "== Order-independent identification =="
start ollama; o=$(scan)
check "ollama beats generic /v1/models" "framework: Ollama" "$o"
absent "not mislabeled OpenAI" "framework: OpenAI" "$o"; stop
start koboldcpp; o=$(scan)
check "kobold beats generic /v1/models" "framework: KoboldCpp" "$o"
absent "kobold not mislabeled OpenAI" "framework: OpenAI-compatible" "$o"
absent "kobold not mislabeled Ollama" "framework: Ollama" "$o"
absent "kobold not mislabeled llama.cpp" "framework: llama.cpp" "$o"
check "kobold real version not emulated 0.7.0" "version: 1.66" "$o"; stop

echo "== Prometheus /metrics model-name leak =="
start vllm; o=$(scan); check "vllm /metrics leak" "model name disclosed via /metrics" "$o"; stop
start sglang; o=$(scan); check "sglang /metrics leak" "model name disclosed via /metrics" "$o"; stop

echo "== AI web UIs / gateways (access posture; no active probe) =="
start openwebui; o=$(scan)
check "open webui" "framework: Open WebUI" "$o"
check "openwebui self-registration access" "access: self-registration enabled" "$o"
check "openwebui self-reg security" "allows self-registration for unauthenticated access" "$o"
absent "ui gets no inference hello" "inference: confirmed" "$o"; stop
start openwebui_open; o=$(scan)
check "openwebui auth-disabled detected" "framework: Open WebUI" "$o"
check "openwebui open access" "access: open" "$o"
check "openwebui open security" "grants open access to a backend" "$o"; stop
start openwebui_onboarding; o=$(scan)
check "openwebui onboarding access" "access: no admin account yet" "$o"
check "openwebui onboarding security" "first visitor can claim admin" "$o"; stop
start nextchat; o=$(scan)
check "nextchat" "framework: NextChat" "$o"
check "nextchat open access (needCode false)" "access: open" "$o"
check "nextchat open security" "grants open access to a backend" "$o"; stop
start librechat; o=$(scan)
check "librechat" "framework: LibreChat" "$o"
check "librechat self-registration access" "access: self-registration enabled" "$o"; stop
start lobechat; o=$(scan)
check "lobechat" "framework: LobeChat" "$o"
check "lobechat access unknown" "access: unknown" "$o"; stop
start flowise; o=$(scan)
check "flowise gateway" "framework: Flowise" "$o"
check "flowise prediction-endpoint note" "prediction endpoints may be publicly callable" "$o"; stop
start anythingllm; o=$(scan); check "anythingllm" "framework: AnythingLLM" "$o"; stop

echo "== Inference / serving frameworks (OpenAI-compatible disambiguation) =="
start xinference; o=$(scan)
check "xinference detected" "framework: Xinference" "$o"
check "xinference version" "version: 0.16.3" "$o"
check "xinference model" "qwen2.5-instruct" "$o"
absent "xinference not mislabeled OpenAI" "framework: OpenAI-compatible" "$o"; stop
start localai; o=$(scan)
check "localai detected" "framework: LocalAI" "$o"
check "localai loaded model (not gallery)" "luna-ai-llama2" "$o"
absent "localai not mislabeled OpenAI" "framework: OpenAI-compatible API" "$o"; stop
start jan; o=$(scan)
check "jan detected" "framework: Jan" "$o"
check "jan model" "llama3.2-3b-instruct" "$o"
absent "jan not mislabeled OpenAI" "framework: OpenAI-compatible API" "$o"; stop
start litellm; o=$(scan)
check "litellm gateway" "framework: LiteLLM" "$o"
check "litellm version" "version: 1.44.8" "$o"
check "litellm kind=gateway" "kind: gateway" "$o"
check "litellm gateway security" "fronts backend compute/inference" "$o"
absent "litellm gateway gets no inference hello" "inference: confirmed" "$o"; stop
start litellm_swagger; o=$(scan)
check "litellm via swagger title" "framework: LiteLLM" "$o"; stop
start bentoml; o=$(scan)
check "bentoml detected" "framework: BentoML" "$o"
check "bentoml version" "version: 1.3.0" "$o"; stop

echo "== Image-generation / ML-app servers =="
start comfyui; o=$(scan)
check "comfyui detected" "framework: ComfyUI" "$o"
check "comfyui version" "version: 0.3.4" "$o"
check "comfyui GPU leak" "GPU/device inventory disclosed via /system_stats" "$o"; stop
start sdwebui; o=$(scan)
check "sdwebui detected (AUTOMATIC1111)" "framework: Stable Diffusion WebUI" "$o"
check "sdwebui leaks checkpoint" "v1-5-pruned-emaonly.safetensors" "$o"; stop
start gradio; o=$(scan)
check "gradio detected" "framework: Gradio" "$o"
check "gradio version" "version: 4.44.0" "$o"
check "gradio kind=ui" "kind: web UI" "$o"
absent "gradio ui gets no inference hello" "inference: confirmed" "$o"; stop
start ray; o=$(scan)
check "ray dashboard detected" "framework: Ray dashboard" "$o"
check "ray version" "version: 2.35.0" "$o"
check "ray kind=gateway" "kind: gateway" "$o"
check "ray job-submission RCE security" "job submission \(remote code execution\)" "$o"; stop

echo "== Vector databases (data finding; no active probe) =="
start chromadb; o=$(scan)
check "chromadb detected" "framework: ChromaDB" "$o"
check "chromadb version" "version: 0.5.5" "$o"
check "chromadb kind=vectordb" "kind: vector database" "$o"
check "chromadb data security" "exposes stored embeddings/collections" "$o"
absent "chromadb vectordb gets no inference hello" "inference: confirmed" "$o"; stop
start qdrant; o=$(scan)
check "qdrant detected" "framework: Qdrant" "$o"
check "qdrant version" "version: 1.11.0" "$o"
check "qdrant collection-inventory leak" "collection inventory exposed via /collections" "$o"; stop
start weaviate; o=$(scan)
check "weaviate detected" "framework: Weaviate" "$o"
check "weaviate version" "version: 1.26.1" "$o"; stop
start milvus; o=$(scan)
check "milvus detected" "framework: Milvus" "$o"
check "milvus kind=vectordb" "kind: vector database" "$o"; stop
start marqo; o=$(scan)
check "marqo detected" "framework: Marqo" "$o"
check "marqo version" "version: 2.11.0" "$o"; stop

echo "== Additional web UIs / gateways =="
start langflow; o=$(scan)
check "langflow detected" "framework: Langflow" "$o"
check "langflow version" "version: 1.0.19" "$o"
check "langflow kind=ui" "kind: web UI" "$o"
absent "langflow not mislabeled Flowise" "framework: Flowise" "$o"; stop
start lollms; o=$(scan)
check "lollms detected" "framework: LoLLMs WebUI" "$o"
check "lollms kind=ui" "kind: web UI" "$o"; stop
start lobechat_welcome; o=$(scan)
check "lobechat via /welcome page" "framework: LobeChat" "$o"
check "lobechat welcome endpoint" "endpoint: /welcome" "$o"; stop

echo "== Plugin / integration descriptors =="
start openai_plugin; o=$(scan)
check "openai plugin manifest detected" "framework: OpenAI plugin manifest" "$o"
check "openai plugin endpoint" "endpoint: /.well-known/ai-plugin.json" "$o"
check "openai plugin kind" "kind: plugin manifest" "$o"
check "openai plugin name extracted" "plugin: Weather Plugin" "$o"
check "openai plugin backend-url leak" "backend API URL disclosed via plugin manifest" "$o"
check "openai plugin security finding" "discloses the backend API and auth scheme" "$o"
absent "openai plugin gets no inference hello" "inference: confirmed" "$o"; stop

echo "== Active hello probe (on by default) =="
start openai; o=$(scan); check "inference confirmed" "inference: confirmed" "$o"; stop
start openai; o=$(scan "llm.probe=false"); absent "probe=false is read-only" "inference:" "$o"; stop

echo "== Auth state + credentials =="
start authed; o=$(scan); check "gated -> REQUIRED" "auth: REQUIRED" "$o"; stop
start authed; o=$(scan "llm.token=$TOKEN"); check "gated +token -> PROVIDED" "auth: PROVIDED" "$o"; stop

echo "== Model listing + enumeration =="
start ollama; o=$(scan); check "models listed" "models \(3\)" "$o"; check "lists llama3:8b" "llama3:8b" "$o"; stop
start anthropic; o=$(scan)
check "anthropic detected (no list endpoint)" "framework: Anthropic" "$o"
check "anthropic no key -> REQUIRED" "auth: REQUIRED" "$o"; stop
start anthropic; o=$(scan "llm.token=$TOKEN")
check "anthropic +key enumerates models" "enumerated by probing" "$o"
check "enumerated claude-3-5-sonnet" "claude-3-5-sonnet-latest" "$o"; stop

echo "== Error-condition fingerprinting =="
start vllm_stealth; o=$(scan)
check "error shape refines generic OpenAI to vLLM" "framework: vLLM" "$o"
check "error_sig object:error" "object:error" "$o"; stop
start openai; o=$(scan); check "openai error_sig model_not_found" "model_not_found" "$o"; stop

echo "== Unauthenticated exposure finding =="
start ollama; o=$(scan); check "SECURITY finding" "SECURITY: unauthenticated inference API" "$o"; stop

echo
echo "==== $pass passed, $fail failed ===="
[ "$fail" -eq 0 ]

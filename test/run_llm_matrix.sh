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
cp "$ROOT"/scripts/llm.lua "$DD/nselib/"
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
start torchserve; o=$(scan); check "torchserve" "framework: TorchServe" "$o"; stop
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

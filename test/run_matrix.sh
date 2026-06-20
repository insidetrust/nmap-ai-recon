#!/usr/bin/env bash
#
# Local regression matrix for the mcp-info / mcp-enum NSE scripts.
#
# Brings up the bundled dependency-free mock in several configurations and runs both
# scripts across transports, auth states, MCP protocol versions, and content
# (tools / resources / prompts). Asserts the expected output for each cell.
#
# Requires: nmap, python3.  Usage: test/run_matrix.sh
#
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT=8765
TOKEN=mock-test-token-abc123
DD="$(mktemp -d)/datadir"

mkdir -p "$DD/scripts" "$DD/nselib"
cp "$ROOT"/scripts/mcp-info.nse "$ROOT"/scripts/mcp-enum.nse "$DD/scripts/"
cp "$ROOT"/scripts/mcp.lua "$DD/nselib/"
cp /usr/share/nmap/scripts/script.db "$DD/scripts/" 2>/dev/null
nmap --datadir "$DD" --script-updatedb >/dev/null 2>&1

pass=0; fail=0
MOCKPID=""
start_mock() {  # $1 = protocol version to advertise
  MCP_PROTOCOL="$1" python3 "$ROOT/test/mock_mcp_server.py" "$PORT" >/tmp/mcp-matrix-mock.log 2>&1 &
  MOCKPID=$!
  sleep 1.2
}
stop_mock() { [ -n "$MOCKPID" ] && kill "$MOCKPID" 2>/dev/null; wait "$MOCKPID" 2>/dev/null; MOCKPID=""; }
trap stop_mock EXIT

scan() {  # remaining args -> nmap script-args; echoes script output
  nmap --datadir "$DD" -sT -Pn -p "$PORT" --script "$1" --script-args "$2" 127.0.0.1 2>/dev/null
}
check() {  # $1 desc  $2 expected-regex  $3 haystack
  if grep -qE "$2" <<<"$3"; then printf '  PASS  %s\n' "$1"; pass=$((pass+1))
  else printf '  FAIL  %s  (expected /%s/)\n' "$1" "$2"; fail=$((fail+1)); fi
}
check_absent() {  # $1 desc  $2 regex-that-must-NOT-appear  $3 haystack
  if grep -qE "$2" <<<"$3"; then printf '  FAIL  %s  (unexpected /%s/)\n' "$1" "$2"; fail=$((fail+1))
  else printf '  PASS  %s\n' "$1"; pass=$((pass+1)); fi
}

echo "== Protocol versions (streamable /mcp, mcp-info) =="
for proto in 2024-11-05 2025-03-26 2025-06-18; do
  start_mock "$proto"
  out=$(scan mcp-info "mcp.paths=/mcp")
  check "protocol $proto reported" "protocolVersion: $proto" "$out"
  stop_mock
done

start_mock 2025-06-18

echo "== Transports (unauth) =="
out=$(scan mcp-info "mcp.paths=/mcp")
check "streamable JSON: transport"   "transport: streamable-http"   "$out"
check "streamable JSON: capabilities" "capabilities: .*tools"       "$out"
out=$(scan mcp-info "mcp.paths=/mcpsse")
check "streamable SSE-framed: transport" "transport: streamable-http" "$out"
out=$(scan mcp-info "mcp.paths=/none,mcp.sse_path=/sse")
check "legacy HTTP+SSE: transport"   "transport: http\+sse \(legacy" "$out"

echo "== Enumeration content (unauth, /mcp) =="
out=$(scan mcp-enum "mcp.paths=/mcp")
check "tools listed"        "tools \(4\)"                     "$out"
check "tool risk: code-exec" "run_command .*RISK: code-exec"  "$out"
check "tool risk: file"     "read_file .*RISK: file-access"   "$out"
check "benign tool unflagged" "get_weather - Get the weather" "$out"
check "resources listed"    "resources \(3\)"                 "$out"
check "resource template"   "file:///\{path\} \(template\)"   "$out"
check "prompts listed"      "prompts \(1\)"                   "$out"
check "security: unauth exposure" "SECURITY: unauthenticated server exposes 2" "$out"

echo "== Auth: OAuth-gated, NO token (/authmcp) =="
out=$(scan mcp-info "mcp.paths=/authmcp")
check "info: auth REQUIRED"       "auth: REQUIRED \(OAuth/Bearer\)"          "$out"
check "info: authz server found"  "oauth_authorization_servers: https?://"   "$out"
check "info: scopes found"        "oauth_scopes: "                            "$out"
out=$(scan mcp-enum "mcp.paths=/authmcp")
check_absent "enum: no tool surface without creds" "tools \(" "$out"

echo "== Auth: OAuth-gated, WITH token (/authmcp) =="
out=$(scan mcp-info "mcp.paths=/authmcp,mcp.token=$TOKEN")
check "info: auth PROVIDED"  "auth: PROVIDED \(Bearer token accepted\)" "$out"
out=$(scan mcp-enum "mcp.paths=/authmcp,mcp.token=$TOKEN")
check "enum(auth): tools"    "tools \(4\)"   "$out"
check "enum(auth): prompts"  "prompts \(1\)" "$out"
check_absent "enum(auth): no unauth finding" "SECURITY: unauthenticated" "$out"

stop_mock
echo
echo "==== $pass passed, $fail failed ===="
[ "$fail" -eq 0 ]

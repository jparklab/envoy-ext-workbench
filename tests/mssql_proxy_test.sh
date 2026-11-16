#!/usr/bin/env bash
# Starts Envoy with configs/mssql_proxy.yaml pointed at a local TCP echo server
# instead of SQL Server, and checks the mssql_proxy module's edge cases that a
# real server can't easily produce:
# - a connection that doesn't open with PRELOGIN passes through unchanged and
#   is counted as unparsed;
# - a malformed PRELOGIN gets the connection closed and counted as an error.
# Real client traffic is covered by mssql_server_test.sh.
# Needs: scripts/build-envoy.sh and scripts/build-modules.sh already run, python3.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
pids=()
cleanup() {
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

fail() { echo "FAIL: mssql_proxy_test: $*" >&2; cat "$TMP/envoy.log" >&2 2>/dev/null || true; exit 1; }

# Echo backend on a free port; it writes the port to a file once listening.
python3 -I - "$TMP/port" <<'EOF' &
import socketserver, sys
class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        while data := self.request.recv(65536):
            self.request.sendall(data)
srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo)
open(sys.argv[1], "w").write(str(srv.server_address[1]))
srv.serve_forever()
EOF
pids+=($!)
for _ in $(seq 50); do [[ -s "$TMP/port" ]] && break; sleep 0.1; done
[[ -s "$TMP/port" ]] || fail "echo backend did not start"
port="$(cat "$TMP/port")"

sed "s/port_value: 1433 }/port_value: $port }/" \
  "$REPO_ROOT/configs/mssql_proxy.yaml" >"$TMP/envoy.yaml"
grep -q "port_value: $port }" "$TMP/envoy.yaml" || fail "could not rewrite backend port"

"$REPO_ROOT/scripts/run.sh" "$TMP/envoy.yaml" --log-path "$TMP/envoy.log" &
pids+=($!)
for _ in $(seq 50); do
  curl -sf http://127.0.0.1:9901/ready >/dev/null 2>&1 && break
  kill -0 "${pids[-1]}" 2>/dev/null || fail "Envoy exited during startup"
  sleep 0.2
done

# exchange <hex bytes to send>: prints the hex of everything echoed back
# before the connection closes or 2s pass.
exchange() {
  python3 -I - "$1" <<'EOF'
import socket, sys
payload = bytes.fromhex(sys.argv[1])
got = b""
with socket.create_connection(("127.0.0.1", 11433), timeout=2) as s:
    s.sendall(payload)
    try:
        while len(got) < len(payload):
            chunk = s.recv(65536)
            if not chunk:
                break
            got += chunk
    except (socket.timeout, ConnectionResetError):
        pass
print(got.hex())
EOF
}
counter() {
  curl -s http://127.0.0.1:9901/stats | sed -n "s/^dynamicmodulescustom\.mssql_proxy_$1: //p"
}

# A complete SQLBatch packet as the first message: not a TDS 7.x login, so the
# module stops parsing and passes it through unchanged.
batch="0101001000000100""73656c6563742031"
[[ "$(exchange "$batch")" == "$batch" ]] || fail "non-PRELOGIN connection not passed through"
[[ "$(counter unparsed_connections_total)" == 1 ]] || fail "unparsed connection not counted"

# A PRELOGIN whose option table is truncated: the module closes the connection
# before anything reaches the backend, so nothing is echoed.
bad_prelogin="1201000c00000100""70696e67"
[[ -z "$(exchange "$bad_prelogin")" ]] || fail "malformed PRELOGIN was passed through"
[[ "$(counter protocol_errors_total)" == 1 ]] || fail "protocol error not counted"

[[ "$(counter connections_total)" == 2 ]] || fail "connections not counted"
echo "PASS: mssql_proxy_test"

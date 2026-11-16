#!/usr/bin/env bash
# Starts Envoy with configs/mssql_proxy.yaml pointed at a local TCP echo server
# instead of SQL Server, and checks that bytes pass through the mssql_proxy
# module unchanged and that its counters move.
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

# Send a TDS-shaped PRELOGIN header plus payload; expect the same bytes back.
reply="$(python3 -I - <<'EOF'
import socket
payload = bytes([0x12, 0x01, 0x00, 0x0c, 0, 0, 1, 0]) + b"ping"
with socket.create_connection(("127.0.0.1", 11433), timeout=5) as s:
    s.sendall(payload)
    got = b""
    while len(got) < len(payload):
        chunk = s.recv(65536)
        if not chunk:
            break
        got += chunk
print("ok" if got == payload else "mismatch: " + got.hex())
EOF
)"
[[ "$reply" == ok ]] || fail "passthrough: $reply"

stats="$(curl -s http://127.0.0.1:9901/stats)"
for c in connections_total downstream_rx_bytes_total upstream_rx_bytes_total; do
  grep -Eq "mssql_proxy_${c}: [1-9]" <<<"$stats" || fail "counter mssql_proxy_${c} not incremented"
done
echo "PASS: mssql_proxy_test"

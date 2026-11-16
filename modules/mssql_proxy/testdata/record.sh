#!/usr/bin/env bash
# Re-record the TDS fixtures in this directory from a real SQL Server.
#
# Runs tests/mssql_server_test.sh with MSSQL_TAP_DIR set, so Envoy's tap
# transport socket records every module-chain connection, then converts each
# recording to <mode>.tds: one line per socket event, in order,
#   C <hex>   bytes the client sent (Envoy read)
#   S <hex>   bytes the server sent (Envoy wrote)
# Credentials are throwaway (generated per run), and the logins in these modes
# travel inside TLS, so no password appears in the fixtures.
# Needs what tests/mssql_server_test.sh needs.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
TAPS="$(mktemp -d)"
trap 'rm -rf "$TAPS"' EXIT

MSSQL_TAP_DIR="$TAPS" bash "$REPO_ROOT/tests/mssql_server_test.sh" | tee "$TAPS/test.log"
grep -q '^PASS' "$TAPS/test.log" || { echo "server test did not pass; fixtures unchanged" >&2; exit 1; }

image="${MSSQL_IMAGE:-mcr.microsoft.com/mssql/server:2025-latest}"
for tap in "$TAPS"/*.json; do
  name="$(basename "$tap" .json)"
  python3 -I - "$tap" "$HERE/$name.tds" "$name" "$image" <<'EOF'
import base64, json, sys
src, dst, name, image = sys.argv[1:]
trace = json.load(open(src))["socket_buffered_trace"]
if trace.get("read_truncated") or trace.get("write_truncated"):
    sys.exit(f"{name}: tap output truncated; raise max_buffered_*_bytes")
lines = [
    f"# {name}: recorded by record.sh through Envoy from {image}.",
    "# One line per socket event: C = client to server, S = server to client, hex bytes.",
]
for event in trace["events"]:
    for kind, tag in (("read", "C"), ("write", "S")):
        if kind in event:
            data = base64.b64decode(event[kind].get("data", {}).get("as_bytes", ""))
            if data:
                lines.append(f"{tag} {data.hex()}")
open(dst, "w").write("\n".join(lines) + "\n")
print(f"wrote {dst} ({len(lines) - 2} events)")
EOF
done

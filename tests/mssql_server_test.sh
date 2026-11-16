#!/usr/bin/env bash
# Runs real SQL Server clients through Envoy (configs/mssql_proxy.yaml) to a
# SQL Server container, once per encryption mode, and checks that each query
# succeeds with the expected encryption and lands on the expected filter chain:
#   ODBC 17 sqlcmd, default        -> login-only TLS   -> mssql_proxy chain
#   ODBC 18 sqlcmd, -N mandatory   -> full TLS (TDS 7) -> mssql_proxy chain
#   ODBC 18 sqlcmd, -N s strict    -> TDS 8.0          -> passthrough chain
#
# Uses SQL Server 2025: the 2022 Linux image rejects TDS 8.0 strict connections
# (error 17821) even with a configured certificate. Strict mode always verifies
# the server certificate, so the test generates one for "127.0.0.1" and points
# the client at it with SSL_CERT_FILE. Everything (SA password, certificate) is
# throwaway and generated per run.
#
# Skips (exit 0) when Docker or the mssql-tools sqlcmd binaries are missing.
# Needs: scripts/build-envoy.sh and scripts/build-modules.sh already run,
# openssl, python3 with PyYAML. Override the image with MSSQL_IMAGE.
#
# Set MSSQL_TAP_DIR=<dir> to also record each module-chain connection with
# Envoy's tap transport socket, as <dir>/<mode>.json (see
# modules/mssql_proxy/testdata/record.sh).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${MSSQL_IMAGE:-mcr.microsoft.com/mssql/server:2025-latest}"
SQLCMD17=/opt/mssql-tools/bin/sqlcmd
SQLCMD18=/opt/mssql-tools18/bin/sqlcmd
NAME="wb-mssql-test-$$"

skip() { echo "SKIP: mssql_server_test: $*"; exit 0; }
command -v docker >/dev/null && docker info >/dev/null 2>&1 || skip "Docker is not available"
[[ -x "$SQLCMD17" && -x "$SQLCMD18" ]] || skip "need $SQLCMD17 and $SQLCMD18"

TMP="$(mktemp -d)"
chmod 755 "$TMP" # the container's mssql user must read the certificate files
envoy_pid=""
cleanup() {
  [[ -n "$envoy_pid" ]] && { kill "$envoy_pid" 2>/dev/null || true; wait "$envoy_pid" 2>/dev/null || true; }
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  rm -rf "$TMP"
}
trap cleanup EXIT

fail() {
  echo "FAIL: mssql_server_test: $*" >&2
  echo "--- envoy log" >&2; tail -50 "$TMP/envoy.log" >&2 2>/dev/null || true
  echo "--- sql server log" >&2; docker logs "$NAME" 2>&1 | tail -20 >&2 || true
  exit 1
}

# Throwaway certificate. The ODBC driver matches the host it was given against
# DNS names, so "127.0.0.1" is listed as a DNS name as well as an IP address.
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=127.0.0.1" \
  -addext "subjectAltName=DNS:127.0.0.1,IP:127.0.0.1" \
  -addext "extendedKeyUsage=serverAuth" \
  -addext "keyUsage=digitalSignature,keyEncipherment" \
  -keyout "$TMP/mssql.key" -out "$TMP/mssql.pem" 2>/dev/null
chmod 644 "$TMP/mssql.key" "$TMP/mssql.pem"
cat >"$TMP/mssql.conf" <<'EOF'
[network]
tlscert = /certs/mssql.pem
tlskey = /certs/mssql.key
tlsprotocols = 1.2
forceencryption = 0
EOF

export SQLCMDPASSWORD="Wb1!$(openssl rand -hex 12)"
docker run -d --name "$NAME" --hostname mssql \
  -e ACCEPT_EULA=Y -e MSSQL_SA_PASSWORD="$SQLCMDPASSWORD" \
  -v "$TMP/mssql.conf:/var/opt/mssql/mssql.conf:ro" -v "$TMP:/certs:ro" \
  -p 127.0.0.1::1433 "$IMAGE" >/dev/null || fail "could not start $IMAGE"
port="$(docker port "$NAME" 1433 | head -1 | cut -d: -f2)"

ready=""
for _ in $(seq 120); do
  if "$SQLCMD18" -S "tcp:127.0.0.1,$port" -U sa -C -l 2 -h -1 -Q "SELECT 1" >/dev/null 2>&1; then
    ready=1; break
  fi
  sleep 1
done
[[ -n "$ready" ]] || fail "SQL Server did not become ready"

# Copy the config with the container's port, and with the tap on the module
# chain when recording.
TAP_TMP=""
if [[ -n "${MSSQL_TAP_DIR:-}" ]]; then
  mkdir -p "$MSSQL_TAP_DIR" "$TMP/tap"
  TAP_TMP="$TMP/tap"
fi
python3 -I - "$REPO_ROOT/configs/mssql_proxy.yaml" "$TMP/envoy.yaml" "$port" "$TAP_TMP" <<'EOF' \
  || fail "could not write the Envoy config"
import sys, yaml
src, dst, port, tap_dir = sys.argv[1:]
cfg = yaml.safe_load(open(src))
res = cfg["static_resources"]
ep = res["clusters"][0]["load_assignment"]["endpoints"][0]["lb_endpoints"][0]["endpoint"]
ep["address"]["socket_address"]["port_value"] = int(port)
if tap_dir:
    chain = next(c for c in res["listeners"][0]["filter_chains"]
                 if c["filter_chain_match"]["transport_protocol"] == "raw_buffer")
    chain["transport_socket"] = {
        "name": "envoy.transport_sockets.tap",
        "typed_config": {
            "@type": "type.googleapis.com/envoy.extensions.transport_sockets.tap.v3.Tap",
            "common_config": {"static_config": {
                "match": {"any_match": True},
                "output_config": {
                    "max_buffered_rx_bytes": 1 << 20,
                    "max_buffered_tx_bytes": 1 << 20,
                    "sinks": [{"format": "JSON_BODY_AS_BYTES",
                               "file_per_tap": {"path_prefix": tap_dir + "/conn"}}],
                },
            }},
            "transport_socket": {
                "name": "envoy.transport_sockets.raw_buffer",
                "typed_config": {"@type": "type.googleapis.com/envoy.extensions.transport_sockets.raw_buffer.v3.RawBuffer"},
            },
        },
    }
yaml.safe_dump(cfg, open(dst, "w"), sort_keys=False)
EOF
"$REPO_ROOT/scripts/run.sh" "$TMP/envoy.yaml" --log-path "$TMP/envoy.log" &
envoy_pid=$!
for _ in $(seq 50); do
  curl -sf http://127.0.0.1:9901/ready >/dev/null 2>&1 && break
  kill -0 "$envoy_pid" 2>/dev/null || fail "Envoy exited during startup"
  sleep 0.2
done

stat() { curl -s http://127.0.0.1:9901/stats | sed -n "s/^$1: //p"; }
module_cx() { stat "dynamicmodulescustom.mssql_proxy_connections_total" | grep . || echo 0; }
strict_cx() { stat "tcp.mssql_strict.downstream_cx_total" | grep . || echo 0; }

QUERY="SET NOCOUNT ON; SELECT encrypt_option FROM sys.dm_exec_connections WHERE session_id = @@SPID"

# When recording, move the tap file of the connection that just closed to
# $MSSQL_TAP_DIR/<name>.json. Envoy writes it on connection close.
save_tap() {
  local name="$1" f=""
  for _ in $(seq 50); do
    f="$(ls "$TAP_TMP"/conn_*.json 2>/dev/null | head -1)"
    [[ -n "$f" ]] && break
    sleep 0.1
  done
  [[ -n "$f" ]] || fail "$name: no tap file recorded"
  mv "$f" "$MSSQL_TAP_DIR/$name.json"
}

# run_mode <name> <label> <expected encrypt_option> <expected chain: module|strict> <sqlcmd args...>
run_mode() {
  local name="$1" label="$2" want_enc="$3" want_chain="$4"
  shift 4
  local m0 s0 out
  m0="$(module_cx)"; s0="$(strict_cx)"
  out="$("$@" -l 10 -h -1 -Q "$QUERY" 2>&1)" || fail "$label: sqlcmd failed: $out"
  [[ "$(echo "$out" | tr -d ' \r' | head -1)" == "$want_enc" ]] \
    || fail "$label: expected encrypt_option $want_enc, got: $out"
  local dm=$(( $(module_cx) - m0 )) ds=$(( $(strict_cx) - s0 ))
  case "$want_chain" in
    module) [[ $dm -eq 1 && $ds -eq 0 ]] || fail "$label: expected module chain (module +$dm, strict +$ds)" ;;
    strict) [[ $dm -eq 0 && $ds -eq 1 ]] || fail "$label: expected strict chain (module +$dm, strict +$ds)" ;;
  esac
  [[ -n "$TAP_TMP" && "$want_chain" == module ]] && save_tap "$name"
  echo "  ok: $label"
}

run_mode odbc17_login_only "ODBC 17, login-only TLS" FALSE module \
  "$SQLCMD17" -S tcp:127.0.0.1,11433 -U sa
run_mode odbc18_mandatory "ODBC 18, mandatory TLS" TRUE module \
  "$SQLCMD18" -S tcp:127.0.0.1,11433 -U sa -N -C
run_mode odbc18_strict "ODBC 18, TDS 8.0 strict" TRUE strict \
  env SSL_CERT_FILE="$TMP/mssql.pem" "$SQLCMD18" -S tcp:127.0.0.1,11433 -U sa -N s

# The module followed both TDS 7.x connections' encryption and found no errors.
module_stat() { stat "dynamicmodulescustom.mssql_proxy_$1" | grep . || echo 0; }
[[ "$(module_stat encryption_login_only_total)" == 1 ]] || fail "login-only connection not recognised"
[[ "$(module_stat encryption_full_total)" == 1 ]] || fail "full-encryption connection not recognised"
[[ "$(module_stat protocol_errors_total)" == 0 ]] || fail "protocol errors on real clients"
[[ "$(module_stat unparsed_connections_total)" == 0 ]] || fail "real clients left unparsed"

echo "PASS: mssql_server_test"

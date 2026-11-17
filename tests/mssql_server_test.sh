#!/usr/bin/env bash
# Runs real SQL Server clients through Envoy (configs/mssql_proxy.yaml) to a
# SQL Server container, once per encryption mode, and checks that each query
# succeeds with the expected encryption and lands on the expected filter chain:
#   ODBC 17 sqlcmd, default        -> login-only TLS   -> mssql_proxy chain
#   ODBC 18 sqlcmd, -N mandatory   -> full TLS (TDS 7) -> mssql_proxy chain
#   ODBC 18 sqlcmd, -N s strict    -> TDS 8.0          -> passthrough chain
#   ODBC 17 sqlcmd, -a 512         -> login-only TLS   -> mssql_proxy chain
#     (512-byte packets, which the module then enforces)
#   ODBC 17 isql, MARS, Encrypt=no -> login-only TLS   -> mssql_proxy chain
#     (skipped when unixODBC's isql is missing)
#
# Uses SQL Server 2025: the 2022 Linux image rejects TDS 8.0 strict connections
# (error 17821) even with a configured certificate. Strict mode always verifies
# the server certificate, so the test generates one for "127.0.0.1" and points
# the client at it with SSL_CERT_FILE. Everything (SA password, certificate) is
# throwaway and generated per run.
#
# Skips (exit 0) when Docker or the mssql-tools sqlcmd binaries are missing.
# Needs: scripts/build-envoy.sh and scripts/build-modules.sh already run,
# openssl, python3 with PyYAML. Override the image with MSSQL_IMAGE; set
# MSSQL_MODULE_LOG_LEVEL=debug to log why the module closes connections.
#
# Runs twice: with the module observing only, then with it terminating TLS on
# both legs (a throwaway proxy certificate toward the clients, verifying the
# server's certificate upstream).
#
# Set MSSQL_TAP_DIR=<dir> to also record each module-chain connection of the
# observe pass with Envoy's tap transport socket, as <dir>/<mode>.json (see
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
  echo "--- module counters" >&2
  curl -s http://127.0.0.1:9901/stats 2>/dev/null | grep mssql_proxy_ >&2 || true
  # Envoy flushes its log file on exit.
  [[ -n "$envoy_pid" ]] && { kill "$envoy_pid" 2>/dev/null || true; wait "$envoy_pid" 2>/dev/null || true; envoy_pid=""; }
  echo "--- envoy log" >&2
  grep -v "statically linked\|server.cc:467" "$TMP/envoy.log" 2>/dev/null | tail -40 >&2 || true
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

# Writes the Envoy config for one pass (observe|terminate): the container's
# port, the module's TLS settings when terminating, and the tap on the module
# chain when recording.
TAP_TMP=""
if [[ -n "${MSSQL_TAP_DIR:-}" ]]; then
  mkdir -p "$MSSQL_TAP_DIR" "$TMP/tap"
  TAP_TMP="$TMP/tap"
fi
write_config() {
  local pass="$1" tap="" tls=""
  [[ "$pass" == observe ]] && tap="$TAP_TMP"
  [[ "$pass" == terminate ]] && tls="$TMP"
  python3 -I - "$REPO_ROOT/configs/mssql_proxy.yaml" "$TMP/envoy.yaml" "$port" "$tap" "$tls" <<'EOF' \
    || fail "could not write the Envoy config"
import sys, yaml
src, dst, port, tap_dir, tls_dir = sys.argv[1:]
cfg = yaml.safe_load(open(src))
res = cfg["static_resources"]
ep = res["clusters"][0]["load_assignment"]["endpoints"][0]["lb_endpoints"][0]["endpoint"]
ep["address"]["socket_address"]["port_value"] = int(port)
chain = next(c for c in res["listeners"][0]["filter_chains"]
             if c["filter_chain_match"]["transport_protocol"] == "raw_buffer")
if tls_dir:
    module = next(f for f in chain["filters"] if f["name"] == "mssql_proxy")
    module["typed_config"]["filter_config"] = {
        "@type": "type.googleapis.com/google.protobuf.Struct",
        "value": {"tls": {
            "cert_file": tls_dir + "/proxy.pem",
            "key_file": tls_dir + "/proxy.key",
            "upstream_ca_file": tls_dir + "/mssql.pem",
            "upstream_server_name": "127.0.0.1",
        }},
    }
if tap_dir:
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
}

start_envoy() {
  write_config "$1"
  "$REPO_ROOT/scripts/run.sh" "$TMP/envoy.yaml" --log-path "$TMP/envoy.log" \
    --component-log-level "dynamic_modules:${MSSQL_MODULE_LOG_LEVEL:-info}" &
  envoy_pid=$!
  for _ in $(seq 50); do
    curl -sf http://127.0.0.1:9901/ready >/dev/null 2>&1 && return
    kill -0 "$envoy_pid" 2>/dev/null || fail "Envoy exited during startup"
    sleep 0.2
  done
  fail "Envoy did not become ready"
}
stop_envoy() {
  kill "$envoy_pid" 2>/dev/null || true
  wait "$envoy_pid" 2>/dev/null || true
  envoy_pid=""
}

stat() { curl -s http://127.0.0.1:9901/stats | sed -n "s/^$1: //p"; }
module_stat() { stat "dynamicmodulescustom.mssql_proxy_$1" | grep . || echo 0; }
module_cx() { module_stat connections_total; }
strict_cx() { stat "tcp.mssql_strict.downstream_cx_total" | grep . || echo 0; }

QUERY="SET NOCOUNT ON; SELECT encrypt_option, net_transport FROM sys.dm_exec_connections WHERE session_id = @@SPID"

# Clients, each running $QUERY and printing the result.
sqlcmd_query() { "$@" -l 10 -h -1 -Q "$QUERY"; }
isql_query() { echo "$QUERY" | isql -b -k "$1"; }
# Negotiates 512-byte packets and pulls a result set many packets long, so the
# module enforces the size the login response announced on real traffic.
sqlcmd_small_packets() {
  "$@" -a 512 -l 10 -h -1 -Q "SET NOCOUNT ON;
    SELECT encrypt_option, net_packet_size FROM sys.dm_exec_connections WHERE session_id = @@SPID;
    SELECT TOP 500 name FROM sys.all_objects"
}

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

# run_mode <name> <label> <output regex> <expected chain: module|strict> <client command...>
run_mode() {
  local name="$1" label="$2" want="$3" want_chain="$4"
  shift 4
  local m0 s0 out
  m0="$(module_cx)"; s0="$(strict_cx)"
  out="$("$@" 2>&1)" || fail "$pass: $label: client failed: $out"
  grep -Eq "$want" <<<"$out" || fail "$pass: $label: expected output matching '$want', got: $out"
  local dm=$(( $(module_cx) - m0 )) ds=$(( $(strict_cx) - s0 ))
  case "$want_chain" in
    module) [[ $dm -eq 1 && $ds -eq 0 ]] || fail "$pass: $label: expected module chain (module +$dm, strict +$ds)" ;;
    strict) [[ $dm -eq 0 && $ds -eq 1 ]] || fail "$pass: $label: expected strict chain (module +$dm, strict +$ds)" ;;
  esac
  [[ -n "$TAP_TMP" && "$pass" == observe && "$want_chain" == module ]] && save_tap "$name"
  echo "  ok: $pass: $label"
}

# The client-facing certificate for the terminating pass (throwaway). The
# clients below either don't verify it (login-only) or trust it (-C).
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=127.0.0.1" \
  -addext "subjectAltName=DNS:127.0.0.1,IP:127.0.0.1" \
  -keyout "$TMP/proxy.key" -out "$TMP/proxy.pem" 2>/dev/null

# Each pass runs every client: "observe" with the module only following the
# connection, "terminate" with it terminating TLS on both legs.
for pass in observe terminate; do
  start_envoy "$pass"

  run_mode odbc17_login_only "ODBC 17, login-only TLS" '^FALSE +TCP' module \
    sqlcmd_query "$SQLCMD17" -S tcp:127.0.0.1,11433 -U sa
  run_mode odbc18_mandatory "ODBC 18, mandatory TLS" '^TRUE +TCP' module \
    sqlcmd_query "$SQLCMD18" -S tcp:127.0.0.1,11433 -U sa -N -C
  run_mode odbc18_strict "ODBC 18, TDS 8.0 strict" '^TRUE +TCP' strict \
    sqlcmd_query env SSL_CERT_FILE="$TMP/mssql.pem" "$SQLCMD18" -S tcp:127.0.0.1,11433 -U sa -N s
  run_mode odbc17_small_packets "ODBC 17, 512-byte packets, login-only TLS" '^FALSE +512' module \
    sqlcmd_small_packets "$SQLCMD17" -S tcp:127.0.0.1,11433 -U sa

  # MARS over login-only TLS, so the module sees the SMP packets after login.
  # sqlcmd can't enable MARS; unixODBC's isql can, through a connection string.
  login_only=2 mars=0
  if command -v isql >/dev/null; then
    run_mode odbc17_mars "ODBC 17, MARS, login-only TLS" 'FALSE +\| +Session' module \
      isql_query "Driver={ODBC Driver 17 for SQL Server};Server=tcp:127.0.0.1,11433;UID=sa;PWD=$SQLCMDPASSWORD;Encrypt=no;MARS_Connection=yes"
    login_only=3 mars=1
  elif [[ "$pass" == observe ]]; then
    echo "  skip: MARS (isql from unixODBC not installed)"
  fi

  # The module followed every TDS 7.x connection's encryption and found no errors.
  [[ "$(module_stat encryption_login_only_total)" == "$login_only" ]] || fail "$pass: login-only connections not recognised"
  [[ "$(module_stat encryption_full_total)" == 1 ]] || fail "$pass: full-encryption connection not recognised"
  [[ "$(module_stat mars_connections_total)" == "$mars" ]] || fail "$pass: MARS connection not recognised"
  [[ "$(module_stat protocol_errors_total)" == 0 ]] || fail "$pass: protocol errors on real clients"
  [[ "$(module_stat tls_errors_total)" == 0 ]] || fail "$pass: TLS errors on real clients"
  [[ "$(module_stat unparsed_connections_total)" == 0 ]] || fail "$pass: real clients left unparsed"
  if [[ "$pass" == terminate ]]; then
    # Every connection had TLS terminated on both legs, and its LOGIN7 read.
    connections=$(( login_only + 1 ))
    [[ "$(module_stat tls_terminated_total)" == "$connections" ]] || fail "terminate: TLS not terminated on every connection"
    [[ "$(module_stat login7_seen_total)" == "$connections" ]] || fail "terminate: LOGIN7 not seen on every connection"
  fi
  stop_envoy
done

echo "PASS: mssql_server_test"

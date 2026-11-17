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
# Runs three times: with the module observing only; terminating TLS on both
# legs (a throwaway proxy certificate toward the clients, verifying the
# server's certificate upstream); and also routing on LOGIN7
# (configs/mssql_proxy_routing.yaml), checking the cluster each login reached
# and the access log. The terminating passes also refuse one login by name
# (filter_config auth.deny) and check that the client gets error 18456 from
# the module without the server being asked. When the MIT KDC tools are
# installed, a throwaway realm (modules/mssql_proxy/testdata/mit_kdc.sh) lets
# those passes also run an ODBC Kerberos login: the module reads the client
# principal from the ticket with the service keytab (auth.kerberos
# read_ticket). The SQL Server container has no Kerberos set up, so it refuses
# the login; what is checked is the principal the module read.
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
  [[ -f "$TMP/kdc/kdc.pid" ]] && kill "$(cat "$TMP/kdc/kdc.pid")" 2>/dev/null || true
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

# Writes the Envoy config for one pass: the container's port for every
# cluster, the module's TLS settings (terminate, route), the access log path
# (route), and the tap on the module chain when recording (observe).
TAP_TMP=""
if [[ -n "${MSSQL_TAP_DIR:-}" ]]; then
  mkdir -p "$MSSQL_TAP_DIR" "$TMP/tap"
  TAP_TMP="$TMP/tap"
fi
write_config() {
  local pass="$1" tap="" tls="" src="$REPO_ROOT/configs/mssql_proxy.yaml"
  [[ "$pass" == observe ]] && tap="$TAP_TMP"
  [[ "$pass" != observe ]] && tls="$TMP"
  [[ "$pass" == route ]] && src="$REPO_ROOT/configs/mssql_proxy_routing.yaml"
  local keytab=""
  [[ -n "$tls" && -n "$KERBEROS" ]] && keytab="$TMP/kdc/service.keytab"
  python3 -I - "$src" "$TMP/envoy.yaml" "$port" "$tap" "$tls" "$keytab" <<'EOF' \
    || fail "could not write the Envoy config"
import sys, yaml
src, dst, port, tap_dir, tls_dir, keytab = sys.argv[1:]
cfg = yaml.safe_load(open(src))
res = cfg["static_resources"]
for cluster in res["clusters"]:
    ep = cluster["load_assignment"]["endpoints"][0]["lb_endpoints"][0]["endpoint"]
    ep["address"]["socket_address"]["port_value"] = int(port)
chain = next(c for c in res["listeners"][0]["filter_chains"]
             if c["filter_chain_match"]["transport_protocol"] == "raw_buffer")
module = next(f for f in chain["filters"] if f["name"] == "mssql_proxy")
if tls_dir:
    fc = module["typed_config"].setdefault(
        "filter_config", {"@type": "type.googleapis.com/google.protobuf.Struct", "value": {}})
    fc["value"]["tls"] = {
        "cert_file": tls_dir + "/proxy.pem",
        "key_file": tls_dir + "/proxy.key",
        "upstream_ca_file": tls_dir + "/mssql.pem",
        "upstream_server_name": "127.0.0.1",
    }
    fc["value"]["auth"] = {"deny": ["denied_login"]}
    if keytab:
        fc["value"]["auth"]["kerberos"] = {"mode": "read_ticket", "keytab_file": keytab}
    for f in chain["filters"]:
        for log in f["typed_config"].get("access_log", []):
            log["typed_config"]["path"] = tls_dir + "/access.log"
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
DB_QUERY="SET NOCOUNT ON; SELECT DB_NAME(), encrypt_option FROM sys.dm_exec_connections WHERE session_id = @@SPID"

# Clients, each running $QUERY and printing the result.
sqlcmd_query() { "$@" -l 10 -h -1 -Q "$QUERY"; }
sqlcmd_db_query() { "$@" -l 10 -h -1 -Q "$DB_QUERY"; }
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

# A login the module refuses (auth.deny): the client reports error 18456 from
# the module, and in the route pass no upstream connection is opened.
run_denied() {
  local backend0 out
  backend0="$(stat cluster.mssql_backend.upstream_cx_total | grep . || echo 0)"
  out="$(SQLCMDPASSWORD=not-a-real-password "$SQLCMD17" -S tcp:127.0.0.1,11433 -U denied_login \
    -l 10 -h -1 -Q "SELECT 1" 2>&1)" && fail "$pass: denied login succeeded: $out"
  grep -q "Login failed for user 'denied_login'" <<<"$out" \
    || fail "$pass: denied login: expected error 18456, got: $out"
  [[ "$(module_stat login_denied_total)" == 1 ]] || fail "$pass: denial not counted"
  if [[ "$pass" == route ]]; then
    [[ "$(stat cluster.mssql_backend.upstream_cx_total | grep . || echo 0)" == "$backend0" ]] \
      || fail "route: a denied login connected upstream"
  fi
  echo "  ok: $pass: login refused by name"
}

# An ODBC Kerberos login (alice@TEST.REALM, ticket for MSSQLSvc/sql.test:1433).
# The server can't verify it and refuses; the module must have read the
# principal from the ticket and seen the refusal.
run_kerberos() {
  local out
  out="$(KRB5_CONFIG="$TMP/kdc/krb5.conf" KRB5CCNAME="FILE:$TMP/kdc/alice.ccache" isql -b -k \
    "Driver={ODBC Driver 17 for SQL Server};Server=tcp:127.0.0.1,11433;Trusted_Connection=yes;ServerSPN=MSSQLSvc/sql.test:1433;Encrypt=no" \
    </dev/null 2>&1)" && fail "$pass: Kerberos login unexpectedly succeeded: $out"
  [[ "$(module_stat login_kerberos_total)" == 1 ]] \
    || fail "$pass: Kerberos login not recognised (client said: $out)"
  [[ "$(module_stat login_failed_total)" == 1 ]] || fail "$pass: the server's refusal not seen: $out"
  [[ "$(module_stat login_denied_total)" == 1 ]] || fail "$pass: the Kerberos login was refused by the module"
  echo "  ok: $pass: Kerberos principal read from the ticket"
}

# A throwaway Kerberos realm, when the MIT KDC tools are installed.
KERBEROS=""
if [[ -x /usr/bin/isql ]] && bash "$REPO_ROOT/modules/mssql_proxy/testdata/mit_kdc.sh" "$TMP/kdc" >"$TMP/kdc.out" 2>&1; then
  KERBEROS=1
else
  echo "  skip: Kerberos (no MIT KDC tools or isql; see mit_kdc.sh)"
fi

# The client-facing certificate for the terminating pass (throwaway). The
# clients below either don't verify it (login-only) or trust it (-C).
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=127.0.0.1" \
  -addext "subjectAltName=DNS:127.0.0.1,IP:127.0.0.1" \
  -keyout "$TMP/proxy.key" -out "$TMP/proxy.pem" 2>/dev/null

# Each pass runs every client: "observe" with the module only following the
# connection, "terminate" with it terminating TLS on both legs, "route" with it
# also answering PRELOGIN itself and picking the cluster from LOGIN7
# (configs/mssql_proxy_routing.yaml: database tempdb -> mssql_tempdb).
for pass in observe terminate route; do
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

  if [[ "$pass" == route ]]; then
    run_mode odbc17_tempdb "ODBC 17, routed by database" '^tempdb +FALSE' module \
      sqlcmd_db_query "$SQLCMD17" -S tcp:127.0.0.1,11433 -U sa -d tempdb
    run_mode odbc18_tempdb "ODBC 18, mandatory TLS, routed by database" '^tempdb +TRUE' module \
      sqlcmd_db_query "$SQLCMD18" -S tcp:127.0.0.1,11433 -U sa -N -C -d tempdb
    login_only=$(( login_only + 1 ))
    full=2
  else
    full=1
  fi

  # The module followed every TDS 7.x connection's encryption and found no errors.
  [[ "$(module_stat encryption_login_only_total)" == "$login_only" ]] || fail "$pass: login-only connections not recognised"
  [[ "$(module_stat encryption_full_total)" == "$full" ]] || fail "$pass: full-encryption connections not recognised"
  [[ "$(module_stat mars_connections_total)" == "$mars" ]] || fail "$pass: MARS connection not recognised"
  [[ "$(module_stat protocol_errors_total)" == 0 ]] || fail "$pass: protocol errors on real clients"
  [[ "$(module_stat tls_errors_total)" == 0 ]] || fail "$pass: TLS errors on real clients"
  [[ "$(module_stat unparsed_connections_total)" == 0 ]] || fail "$pass: real clients left unparsed"
  if [[ "$pass" != observe ]]; then
    # Every connection had TLS terminated on both legs, and its LOGIN7 read.
    connections=$(( login_only + full ))
    [[ "$(module_stat tls_terminated_total)" == "$connections" ]] || fail "$pass: TLS not terminated on every connection"
    [[ "$(module_stat login7_seen_total)" == "$connections" ]] || fail "$pass: LOGIN7 not seen on every connection"
    # Every login reached the server and was accepted, as a SQL login.
    [[ "$(module_stat login_succeeded_total)" == "$connections" ]] || fail "$pass: login results not seen"
    [[ "$(module_stat login_sql_total)" == "$connections" ]] || fail "$pass: SQL logins not counted"
  fi
  if [[ "$pass" == route ]]; then
    # The two tempdb logins went to mssql_tempdb, the rest to tcp_proxy's cluster.
    [[ "$(module_stat routed_total)" == 2 ]] || fail "route: tempdb logins not routed"
    [[ "$(module_stat unrouted_total)" == $(( connections - 2 )) ]] || fail "route: other logins not left to tcp_proxy"
    [[ "$(module_stat server_incompatible_total)" == 0 ]] || fail "route: server PRELOGIN answers didn't fit"
    [[ "$(stat cluster.mssql_tempdb.upstream_cx_total)" == 2 ]] || fail "route: mssql_tempdb not used"
    [[ "$(stat cluster.mssql_backend.upstream_cx_total)" == $(( connections - 2 + 1 )) ]] \
      || fail "route: mssql_backend not used for the rest (and the strict client)"
  fi
  [[ "$pass" != observe ]] && run_denied
  [[ "$pass" != observe && -n "$KERBEROS" ]] && run_kerberos
  stop_envoy
  if [[ "$pass" == route ]]; then
    # The access log carries the LOGIN7 fields (Envoy flushed it on exit).
    grep -q "cluster=mssql_tempdb user=sa database=tempdb .*auth=sql identity=sa result=succeeded" "$TMP/access.log" \
      || fail "route: access log lacks the LOGIN7 fields: $(cat "$TMP/access.log")"
    grep -q "user=denied_login .*result=denied details=mssql_proxy_login_denied" "$TMP/access.log" \
      || fail "route: access log lacks the refused login: $(cat "$TMP/access.log")"
    if [[ -n "$KERBEROS" ]]; then
      grep -q "auth=kerberos identity=alice@TEST.REALM result=failed" "$TMP/access.log" \
        || fail "route: access log lacks the Kerberos principal: $(cat "$TMP/access.log")"
    fi
    echo "  ok: route: access log has LOGIN7 fields and login results"
  fi
done

echo "PASS: mssql_server_test"

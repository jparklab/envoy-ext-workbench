#!/usr/bin/env bash
# Runs integrated-authentication logins through Envoy and the MSSQL proxy
# module against a real SQL Server that is joined to a throwaway Active
# Directory domain (tests/ad/ad_env.sh: a Samba AD DC and SQL Server 2025).
# The module terminates TLS on both legs, as in mssql_server_test.sh's second
# pass, so it reads LOGIN7, and runs auth.kerberos read_ticket with SQL
# Server's own service keytab (the account the clients' tickets are for).
#
#   Kerberos  ODBC 17 (isql -k) as alice and as bob, ServerSPN = SQL Server's
#             SPN, tickets from the domain's KDC. The module reads the client
#             principal from each ticket and forwards LOGIN7 unchanged, and the
#             server accepts the login: SUSER_NAME() is ADTEST\alice /
#             ADTEST\bob with auth_scheme KERBEROS, and the module's debug log
#             and the access log show alice@AD.TEST / bob@AD.TEST.
#   NTLM      FreeTDS tsql (in the ad-env client container: it has no host
#             equivalent) as ADTEST\alice with her password. SQL Server on
#             Linux refuses NTLM (ad_env_test.sh: error 18452, "The login is
#             from an untrusted domain...", right after the client's NTLMSSP
#             NEGOTIATE and before any CHALLENGE), so what is shown is that the
#             module passes the login on, does not refuse it itself, and that
#             the server's own refusal reaches the client unchanged: the same
#             error lines as when the client talks to the server directly, and
#             the server's error log shows the refusal for the login that came
#             through Envoy. A SQL Server that does accept NTLM (Windows) would
#             take the other branch: SUSER_NAME() = ADTEST\alice and the
#             module's log shows that identity from AUTHENTICATE.
#
# Skips (exit 0) when Docker or a client tool is missing. Needs
# scripts/build-modules.sh already run and a built Envoy (ENVOY_BIN overrides
# envoy/bazel-bin/source/exe/envoy-static), openssl, kinit, unixODBC's isql
# with ODBC Driver 17, python3 with PyYAML. The first run builds the DC and
# client images (needs network). Uses its own AD_ENV_DIR, free ports for
# Envoy's listener and admin interface, and removes everything on exit.
# MSSQL_MODULE_LOG_LEVEL (default debug) sets the module's log level.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AD="$REPO_ROOT/tests/ad/ad_env.sh"
export ENVOY_BIN="${ENVOY_BIN:-$REPO_ROOT/envoy/bazel-bin/source/exe/envoy-static}"

skip() { echo "SKIP: mssql_ad_relay_test: $*"; exit 0; }
command -v docker >/dev/null && docker info >/dev/null 2>&1 || skip "Docker is not available"
for tool in kinit isql openssl python3 curl; do
  command -v "$tool" >/dev/null || skip "$tool not found"
done
python3 -I -c 'import yaml' 2>/dev/null || skip "python3 PyYAML not found"
odbcinst -q -d 2>/dev/null | grep -q "ODBC Driver 17 for SQL Server" || skip "ODBC Driver 17 for SQL Server not installed"

TMP="$(mktemp -d)"
chmod 755 "$TMP"
export AD_ENV_DIR="$TMP/ad"
envoy_pid=""
cleanup() {
  [[ -n "$envoy_pid" ]] && { kill "$envoy_pid" 2>/dev/null || true; wait "$envoy_pid" 2>/dev/null || true; }
  "$AD" down >/dev/null 2>&1 || true
  rm -rf "$TMP"
}
trap cleanup EXIT

fail() {
  echo "FAIL: mssql_ad_relay_test: $*" >&2
  echo "--- module counters" >&2
  curl -s "http://127.0.0.1:${ADMIN_PORT:-0}/stats" 2>/dev/null | grep mssql_proxy_ >&2 || true
  # Envoy flushes its log file on exit.
  [[ -n "$envoy_pid" ]] && { kill "$envoy_pid" 2>/dev/null || true; wait "$envoy_pid" 2>/dev/null || true; envoy_pid=""; }
  echo "--- envoy log" >&2
  grep -v "statically linked\|server.cc:467" "$TMP/envoy.log" 2>/dev/null | tail -40 >&2 || true
  echo "--- access log" >&2; tail -10 "$TMP/access.log" >&2 2>/dev/null || true
  [[ -n "${AD_SQL_CONTAINER:-}" ]] && { echo "--- sql server log" >&2; docker logs "$AD_SQL_CONTAINER" 2>&1 | tail -20 >&2 || true; }
  exit 1
}

[[ -x "$ENVOY_BIN" ]] || fail "no Envoy binary at $ENVOY_BIN (scripts/build-envoy.sh)"
[[ -f "$REPO_ROOT/build/modules/libmssql_proxy.so" ]] || fail "module not built (scripts/build-modules.sh)"

"$AD" up || fail "could not bring up the AD environment"
# shellcheck disable=SC1091
source "$AD_ENV_DIR/env.sh"

free_port() { python3 -I -c 'import socket; s = socket.socket(); s.bind(("0.0.0.0", 0)); print(s.getsockname()[1])'; }
PROXY_PORT="$(free_port)"
ADMIN_PORT="$(free_port)"

# The client-facing certificate (throwaway). The clients below encrypt the
# login only and don't verify it.
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=127.0.0.1" \
  -addext "subjectAltName=DNS:127.0.0.1,IP:127.0.0.1" \
  -keyout "$TMP/proxy.key" -out "$TMP/proxy.pem" 2>/dev/null

# The Envoy config: configs/mssql_proxy.yaml on free ports with SQL Server's
# published port as the backend, the module terminating TLS (the server's
# certificate is its own, self-signed, so it isn't verified), reading Kerberos
# tickets with SQL Server's keytab and relaying NTLM, and an access log of what
# the module learned from each login.
python3 -I - "$REPO_ROOT/configs/mssql_proxy.yaml" "$TMP/envoy.yaml" \
  "$PROXY_PORT" "$ADMIN_PORT" "$AD_SQL_PORT" "$TMP" "$AD_SQLSVC_KEYTAB" <<'EOF' || fail "could not write the Envoy config"
import sys, yaml
src, dst, proxy_port, admin_port, sql_port, tmp, keytab = sys.argv[1:]
cfg = yaml.safe_load(open(src))
cfg["admin"]["address"]["socket_address"]["port_value"] = int(admin_port)
res = cfg["static_resources"]
res["listeners"][0]["address"]["socket_address"]["port_value"] = int(proxy_port)
for cluster in res["clusters"]:
    ep = cluster["load_assignment"]["endpoints"][0]["lb_endpoints"][0]["endpoint"]
    ep["address"]["socket_address"]["port_value"] = int(sql_port)
chain = next(c for c in res["listeners"][0]["filter_chains"]
             if c["filter_chain_match"]["transport_protocol"] == "raw_buffer")
module = next(f for f in chain["filters"] if f["name"] == "mssql_proxy")
module["typed_config"]["filter_config"] = {
    "@type": "type.googleapis.com/google.protobuf.Struct",
    "value": {
        "tls": {"cert_file": tmp + "/proxy.pem", "key_file": tmp + "/proxy.key",
                "upstream_verify": False},
        "auth": {"ntlm": "pass_through",
                 "kerberos": {"mode": "read_ticket", "keytab_file": keytab}},
    },
}
fmt = ("%START_TIME% auth=%DYNAMIC_METADATA(mssql_proxy:auth)% "
       "user=%DYNAMIC_METADATA(mssql_proxy:user)% "
       "identity=%DYNAMIC_METADATA(mssql_proxy:identity)% "
       "result=%DYNAMIC_METADATA(mssql_proxy:login_result)% "
       "server_error=%DYNAMIC_METADATA(mssql_proxy:server_error)% "
       "details=%CONNECTION_TERMINATION_DETAILS%\n")
tcp = next(f for f in chain["filters"] if f["name"] == "envoy.filters.network.tcp_proxy")
tcp["typed_config"]["access_log"] = [{
    "name": "envoy.access_loggers.file",
    "typed_config": {
        "@type": "type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog",
        "path": tmp + "/access.log",
        "log_format": {"text_format_source": {"inline_string": fmt}},
    },
}]
yaml.safe_dump(cfg, open(dst, "w"), sort_keys=False)
EOF

# The domain's krb5.conf for the module's Kerberos, and its replay cache dir.
# A dynamic base id lets this run beside another Envoy on the machine.
KRB5_CONFIG="$AD_KRB5_CONF" KRB5RCACHEDIR="$TMP" \
  "$REPO_ROOT/scripts/run.sh" "$TMP/envoy.yaml" --log-path "$TMP/envoy.log" --use-dynamic-base-id \
  --component-log-level "dynamic_modules:${MSSQL_MODULE_LOG_LEVEL:-debug}" &
envoy_pid=$!
for _ in $(seq 50); do
  curl -sf "http://127.0.0.1:$ADMIN_PORT/ready" >/dev/null 2>&1 && break
  kill -0 "$envoy_pid" 2>/dev/null || fail "Envoy exited during startup"
  sleep 0.2
done
curl -sf "http://127.0.0.1:$ADMIN_PORT/ready" >/dev/null 2>&1 || fail "Envoy did not become ready"

stat() { curl -s "http://127.0.0.1:$ADMIN_PORT/stats" | sed -n "s/^$1: //p"; }
module_stat() { stat "dynamicmodulescustom.mssql_proxy_$1" | grep . || echo 0; }
expect_stat() { # <stat> <value> <what>
  [[ "$(module_stat "$1")" == "$2" ]] || fail "$3 (mssql_proxy_$1 = $(module_stat "$1"), expected $2)"
}

# --- Kerberos: read_ticket, the server accepts the login.
WHO_QUERY="SET NOCOUNT ON; SELECT SUSER_NAME() AS who, auth_scheme FROM sys.dm_exec_connections WHERE session_id = @@SPID"
kerberos_login() {
  local user="$1" ccache="$2" n="$3" out
  out="$(echo "$WHO_QUERY" \
    | KRB5_CONFIG="$AD_KRB5_CONF" KRB5CCNAME="FILE:$ccache" isql -b -d'|' -k \
      "Driver={ODBC Driver 17 for SQL Server};Server=tcp:127.0.0.1,$PROXY_PORT;Trusted_Connection=yes;ServerSPN=$AD_SQL_SPN;Encrypt=no" 2>&1)" \
    || fail "Kerberos login as $user through Envoy failed: $out"
  grep -q "^$AD_DOMAIN\\\\$user|KERBEROS" <<<"$out" || fail "Kerberos login as $user: unexpected result: $out"
  expect_stat tls_terminated_total "$n" "TLS not terminated on every connection"
  expect_stat login7_seen_total "$n" "LOGIN7 not seen on every connection"
  expect_stat login_kerberos_total "$n" "Kerberos login by $user not recognised"
  expect_stat login_succeeded_total "$n" "the server's acceptance of $user not seen"
  expect_stat login_denied_total 0 "the module refused the login of $user"
  expect_stat login_failed_total 0 "the server refused the login of $user"
  echo "  ok: Kerberos through Envoy as $user: SUSER_NAME() = $AD_DOMAIN\\$user, auth_scheme KERBEROS"
}
kerberos_login alice "$AD_ALICE_CCACHE" 1
kerberos_login bob "$AD_BOB_CCACHE" 2

# --- NTLM: relayed to the server, which refuses it (or accepts it).
client_tag="wb-ad-client:$(sha256sum "$REPO_ROOT/tests/ad/client/Dockerfile" | cut -c1-12)"
docker image inspect "$client_tag" >/dev/null 2>&1 \
  || docker build -q -t "$client_tag" "$REPO_ROOT/tests/ad/client" >/dev/null || fail "could not build the client image"
# FreeTDS sends a bare NTLMSSP NEGOTIATE in LOGIN7; "request" encrypts the
# login (the module terminates that TLS) and leaves the rest in plain text.
ntlm_login() { # <host> <port>
  docker run --rm --network "$AD_NETWORK" --dns "$AD_DC_IP" --dns-search "$AD_DNS_DOMAIN" \
    -e PW="$AD_ALICE_PASSWORD" -e HOST="$1" -e PORT="$2" "$client_tag" bash -c '
      printf "[global]\ntds version = 7.4\nencryption = request\n" > /tmp/freetds.conf
      printf "SET NOCOUNT ON; SELECT SUSER_NAME(), auth_scheme FROM sys.dm_exec_connections WHERE session_id = @@SPID\ngo\nquit\n" \
        | FREETDSCONF=/tmp/freetds.conf tsql -H "$HOST" -p "$PORT" -U "ADTEST\\alice" -P "$PW"' 2>&1 || true
}
# The refusal as the client reports it: the error line and its message.
refusal() { grep -A1 '^Msg 18452' <<<"$1" || true; }
sql_errorlog_refusals() {
  docker exec "$AD_SQL_CONTAINER" bash -c "tr -d '\\000' </var/opt/mssql/log/errorlog | grep -c 'untrusted domain'" 2>/dev/null || true
}

direct_out="$(ntlm_login "$AD_SQL_HOST" 1433)"
refusals0="$(sql_errorlog_refusals)"
via_out="$(ntlm_login "$AD_GATEWAY_IP" "$PROXY_PORT")"
refusals1="$(sql_errorlog_refusals)"

ntlm_accepted=""
if grep -q '^Msg 18452' <<<"$via_out"; then
  [[ "$(refusal "$via_out")" == "$(refusal "$direct_out")" && -n "$(refusal "$direct_out")" ]] \
    || fail "the refusal through Envoy differs from the server's own: direct: $(refusal "$direct_out") / through Envoy: $(refusal "$via_out")"
  [[ "$refusals1" -gt "$refusals0" ]] \
    || fail "the server's error log shows no refusal for the login through Envoy ($refusals0 -> $refusals1)"
  expect_stat login_denied_total 0 "the module refused the NTLM login itself"
  expect_stat login_ntlm_total 1 "the NTLM login was not recognised"
  expect_stat login_failed_total 1 "the server's refusal was not seen"
  expect_stat protocol_errors_total 0 "protocol errors on the NTLM login"
  echo "  ok: NTLM through Envoy: the server's own refusal reached the client unchanged: $(refusal "$via_out" | tr -s '\t\n' ' ')"
elif grep -q 'ADTEST.alice' <<<"$via_out"; then
  ntlm_accepted=1
  expect_stat login_ntlm_total 1 "the NTLM login was not recognised"
  expect_stat login_succeeded_total 3 "the server's acceptance of the NTLM login was not seen"
  echo "  ok: NTLM through Envoy: accepted as ADTEST\\alice"
else
  fail "NTLM through Envoy: neither accepted nor the server's refusal: $via_out"
fi

# --- What the module logged (Envoy flushes its logs on exit).
kill "$envoy_pid" 2>/dev/null || true
wait "$envoy_pid" 2>/dev/null || true
envoy_pid=""
for who in alice bob; do
  grep -q "login succeeded (kerberos, '$who@$AD_REALM')" "$TMP/envoy.log" \
    || fail "the module log lacks the principal $who@$AD_REALM: $(grep 'mssql_proxy' "$TMP/envoy.log" | tail -10)"
  grep -q "auth=kerberos user= identity=$who@$AD_REALM result=succeeded" "$TMP/access.log" \
    || fail "the access log lacks the principal $who@$AD_REALM: $(cat "$TMP/access.log")"
done
echo "  ok: the module read alice@$AD_REALM and bob@$AD_REALM from the tickets (log and access log)"
if [[ -n "$ntlm_accepted" ]]; then
  grep -qi "login succeeded (ntlm, '$AD_DOMAIN\\\\alice')" "$TMP/envoy.log" \
    || fail "the module log lacks the NTLM identity: $(cat "$TMP/access.log")"
else
  grep -q "login failed (ntlm, '')" "$TMP/envoy.log" \
    || fail "the module log lacks the failed NTLM login: $(grep 'mssql_proxy' "$TMP/envoy.log" | tail -10)"
  # No AUTHENTICATE was sent (the server refused after NEGOTIATE), so there is
  # no identity to log: Envoy prints "-" for it.
  grep -q "auth=ntlm user= identity=- result=failed server_error=18452" "$TMP/access.log" \
    || fail "the access log lacks the NTLM login and the server's error: $(cat "$TMP/access.log")"
  echo "  ok: the module logged an NTLM login the server failed with error 18452"
fi

echo "PASS: mssql_ad_relay_test"

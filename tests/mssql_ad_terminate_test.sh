#!/usr/bin/env bash
# Kerberos terminate (auth.kerberos mode terminate) against a real AD-joined
# SQL Server: the throwaway Samba AD domain and SQL Server 2025 of
# tests/ad/ad_env.sh. ODBC 17 logs in to Envoy (the module terminating TLS and
# Kerberos) with ServerSPN=MSSQLSvc/proxy.ad.test:1433, the proxy's own SPN;
# the module accepts the ticket with the proxy's keytab and logs in to SQL
# Server with a Kerberos exchange of its own. SQL Server must accept it, and
# SUSER_NAME() says as whom:
#   1. identity service_account    -> ADTEST\svc-proxy, whoever the client is
#   2. identity delegate, the client's TGT forwarded
#                                  -> ADTEST\alice
#   3. identity delegate, no TGT forwarded (S4U2Proxy: svc-proxy is allowed to
#      delegate to MSSQLSvc/sql.ad.test:1433)
#                                  -> ADTEST\alice
#   4. channel_binding tls_server_end_point (reported, never fails the test:
#      whether SQL Server takes the binding is an open question in plan.md)
#
# The forwarding client is ODBC Driver 17 itself: on Linux it asks for
# delegation (GSS_C_DELEG_FLAG) in every login, and MIT forwards the user's
# forwardable TGT. The client that forwards nothing is the same driver, real
# TDS login included, with tests/ad/gss_nodeleg_shim.c preloaded: it only takes
# that flag out of the driver's gss_init_sec_context calls. To tell the two
# delegate paths apart the test removes the S4U2Proxy permission: the
# forwarding client must still get in (it never needed it), the other must be
# refused.
#
# The proxy's own TGT for S4U2Proxy has to be the account's: Samba AD refuses
# an AS-REQ for the SPN (Client 'MSSQLSvc/proxy.ad.test:1433@AD.TEST' not found
# in Kerberos database). So with delegate the module's upstream names the
# account (principal svc-proxy, keytab_file the account's keys), while
# auth.kerberos.keytab_file stays the SPN's keys it accepts clients with.
#
# Skips (exit 0) when Docker, the Kerberos or ODBC client tools, gcc with the
# GSS-API headers (for the shim), openssl, python3 with PyYAML or the built
# Envoy and module are missing. Needs scripts/build-modules.sh run; Envoy is
# $ENVOY_BIN (default envoy/bazel-bin/source/exe/envoy-static). Everything
# (domain, passwords, certificates) is throwaway and generated per run, in a
# state directory of its own, removed on exit. Set MSSQL_MODULE_LOG_LEVEL=debug
# to log why the module closes connections; AD_ENV_KEEP=1 keeps a failed AD up.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AD="$REPO_ROOT/tests/ad/ad_env.sh"
export ENVOY_BIN="${ENVOY_BIN:-$REPO_ROOT/envoy/bazel-bin/source/exe/envoy-static}"
export ENVOY_DYNAMIC_MODULES_SEARCH_PATH="${ENVOY_DYNAMIC_MODULES_SEARCH_PATH:-$REPO_ROOT/build/modules}"

skip() { echo "SKIP: mssql_ad_terminate_test: $*"; exit 0; }
command -v docker >/dev/null && docker info >/dev/null 2>&1 || skip "Docker is not available"
for tool in kinit isql openssl python3 gcc curl; do
  command -v "$tool" >/dev/null || skip "$tool not found"
done
python3 -c "import yaml" 2>/dev/null || skip "python3 PyYAML not installed"
odbcinst -q -d 2>/dev/null | grep -q "ODBC Driver 17 for SQL Server" || skip "ODBC Driver 17 for SQL Server not installed"
[[ -f /usr/include/gssapi/gssapi.h ]] || skip "GSS-API headers not installed (libkrb5-dev)"
[[ -x "$ENVOY_BIN" ]] || skip "Envoy not built ($ENVOY_BIN)"
[[ -f "$ENVOY_DYNAMIC_MODULES_SEARCH_PATH/libmssql_proxy.so" ]] \
  || skip "module not built ($ENVOY_DYNAMIC_MODULES_SEARCH_PATH/libmssql_proxy.so; scripts/build-modules.sh)"

TMP="$(mktemp -d)"
chmod 755 "$TMP"
export AD_ENV_DIR="$TMP/ad"
envoy_pid=""
stop_envoy() {
  if [[ -n "$envoy_pid" ]]; then
    kill "$envoy_pid" 2>/dev/null || true
    wait "$envoy_pid" 2>/dev/null || true
    envoy_pid=""
  fi
}
restore_delegation() { :; }
cleanup() {
  stop_envoy
  restore_delegation
  "$AD" down >/dev/null 2>&1 || true
  rm -rf "$TMP"
}
trap cleanup EXIT

fail() {
  echo "FAIL: mssql_ad_terminate_test: $*" >&2
  echo "--- module counters" >&2
  curl -s "http://127.0.0.1:${admin_port:-0}/stats" 2>/dev/null | grep mssql_proxy_ >&2 || true
  stop_envoy # Envoy flushes its log file on exit.
  echo "--- envoy log" >&2
  grep -v "statically linked\|server.cc:467" "$TMP/envoy.log" 2>/dev/null | tail -40 >&2 || true
  if [[ -n "${AD_DC_CONTAINER:-}" ]]; then
    echo "--- domain controller (KDC) log" >&2
    docker logs --tail 400 "$AD_DC_CONTAINER" 2>&1 | grep -v "Remote set of debug" | tail -25 >&2 || true
    echo "--- sql server log" >&2
    docker logs --tail 15 "$AD_SQL_CONTAINER" >&2 2>&1 || true
  fi
  exit 1
}

rc=0
"$AD" up >"$TMP/ad-up.log" 2>&1 || rc=$?
if [[ $rc -ne 0 ]]; then
  [[ $rc -eq 77 ]] && skip "Docker is not available"
  cat "$TMP/ad-up.log" >&2
  fail "the AD environment did not come up"
fi
# shellcheck disable=SC1091
source "$AD_ENV_DIR/env.sh"

free_port() { python3 -I -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'; }
proxy_port="$(free_port)"
admin_port="$(free_port)"

# The proxy's certificate for the clients (ODBC 17 with Encrypt=no only
# encrypts the login and does not check it).
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=$AD_PROXY_HOST" \
  -addext "subjectAltName=DNS:$AD_PROXY_HOST" \
  -keyout "$TMP/proxy.key" -out "$TMP/proxy.pem" 2>/dev/null
gcc -Wall -shared -fPIC -o "$TMP/gss_nodeleg_shim.so" "$REPO_ROOT/tests/ad/gss_nodeleg_shim.c" -ldl \
  || fail "could not build the no-delegation shim"

# --- The domain as the proxy needs it.
dc() { "$AD" dc "$@"; }
dc samba-tool delegation show "$AD_PROXY_ACCOUNT" | grep -q "$AD_SQL_SPN" \
  || fail "$AD_PROXY_ACCOUNT is not allowed to delegate to $AD_SQL_SPN"
klist -k "$AD_PROXY_KEYTAB" | grep -q "$AD_PROXY_SPN@$AD_REALM" \
  || fail "the proxy keytab has no keys for $AD_PROXY_SPN"
echo "  ok: domain: $AD_PROXY_SPN on $AD_PROXY_ACCOUNT, delegation to $AD_SQL_SPN allowed"

# Writes the Envoy config: the module terminating TLS on both legs and
# Kerberos, logging in to SQL Server as <identity> with the given channel
# binding. The server's certificate is generated by SQL Server at startup and
# is not on disk, so the upstream is not verified (TLS itself is not the
# subject here).
write_config() {
  local identity="$1" binding="$2"
  python3 -I - "$REPO_ROOT/configs/mssql_proxy.yaml" "$TMP/envoy.yaml" "$proxy_port" "$admin_port" \
    "$AD_SQL_PORT" "$TMP" "$identity" "$binding" "$AD_PROXY_KEYTAB" "$AD_PROXY_ACCOUNT_KEYTAB" \
    "$AD_PROXY_ACCOUNT" "$AD_SQL_SPN" <<'EOF' || fail "could not write the Envoy config"
import sys, yaml
(src, dst, proxy_port, admin_port, sql_port, tmp, identity, binding, proxy_keytab,
 account_keytab, account, sql_spn) = sys.argv[1:]
cfg = yaml.safe_load(open(src))
cfg["admin"]["address"]["socket_address"]["port_value"] = int(admin_port)
res = cfg["static_resources"]
listener = res["listeners"][0]
listener["address"]["socket_address"] = {"address": "127.0.0.1", "port_value": int(proxy_port)}
for cluster in res["clusters"]:
    ep = cluster["load_assignment"]["endpoints"][0]["lb_endpoints"][0]["endpoint"]
    ep["address"]["socket_address"] = {"address": "127.0.0.1", "port_value": int(sql_port)}
chain = next(c for c in listener["filter_chains"]
             if c["filter_chain_match"]["transport_protocol"] == "raw_buffer")
module = next(f for f in chain["filters"] if f["name"] == "mssql_proxy")
# The account the proxy logs in as (service_account) or asks for constrained
# delegation as (delegate); the acceptor's SPN keys are keytab_file either way.
upstream = {"identity": identity, "spn": sql_spn,
            "keytab_file": account_keytab, "principal": account}
kerberos = {"mode": "terminate", "keytab_file": proxy_keytab, "upstream": upstream}
if binding != "none":
    kerberos["channel_binding"] = binding
module["typed_config"]["filter_config"] = {
    "@type": "type.googleapis.com/google.protobuf.Struct",
    "value": {
        "tls": {"cert_file": tmp + "/proxy.pem", "key_file": tmp + "/proxy.key",
                "upstream_verify": False},
        "auth": {"kerberos": kerberos},
    },
}
yaml.safe_dump(cfg, open(dst, "w"), sort_keys=False)
EOF
}

# Starts Envoy fresh, so the module's ticket caches are empty.
start_envoy() {
  write_config "$1" "${2:-none}"
  : >"$TMP/envoy.log"
  # The domain's krb5.conf for the module's Kerberos, and its replay cache.
  KRB5_CONFIG="$AD_KRB5_CONF" KRB5RCACHEDIR="$TMP" \
    "$REPO_ROOT/scripts/run.sh" "$TMP/envoy.yaml" --log-path "$TMP/envoy.log" \
    --component-log-level "dynamic_modules:${MSSQL_MODULE_LOG_LEVEL:-info}" &
  envoy_pid=$!
  for _ in $(seq 100); do
    curl -sf "http://127.0.0.1:$admin_port/ready" >/dev/null 2>&1 && return
    kill -0 "$envoy_pid" 2>/dev/null || fail "Envoy exited during startup"
    sleep 0.2
  done
  fail "Envoy did not become ready"
}
module_stat() {
  curl -s "http://127.0.0.1:$admin_port/stats" | sed -n "s/^dynamicmodulescustom.mssql_proxy_$1: //p" | grep . || echo 0
}

# An ODBC 17 Kerberos login to the proxy as <user> (ServerSPN is the proxy's).
# The driver asks for delegation; with <nodeleg> the shim takes that out.
# Prints the output.
QUERY="SET NOCOUNT ON; SELECT SUSER_NAME() AS who, auth_scheme FROM sys.dm_exec_connections WHERE session_id = @@SPID"
odbc_login() {
  local user="$1" nodeleg="${2:-}" ccache="$TMP/$1.login.ccache" preload=""
  cp "$AD_ENV_DIR/$user.ccache" "$ccache" # the login adds service tickets to it
  [[ "$nodeleg" == nodeleg ]] && preload="$TMP/gss_nodeleg_shim.so"
  echo "$QUERY" | env KRB5_CONFIG="$AD_KRB5_CONF" KRB5CCNAME="FILE:$ccache" ${preload:+LD_PRELOAD=$preload} \
    timeout 60 isql -b -d'|' -k \
    "Driver={ODBC Driver 17 for SQL Server};Server=tcp:127.0.0.1,$proxy_port;Trusted_Connection=yes;ServerSPN=$AD_PROXY_SPN;Encrypt=no" \
    2>&1
}

# expect_login <label> <expected SUSER_NAME()> <user> [nodeleg]: the login is
# accepted by SQL Server as the expected identity over Kerberos.
expect_login() {
  local label="$1" want="$2" out
  shift 2
  out="$(odbc_login "$@")" || fail "$label: login failed: $out"
  grep -qxF "$want|KERBEROS" <<<"$out" || fail "$label: expected $want|KERBEROS, got: $out"
  [[ "$(module_stat login_kerberos_total)" == 1 ]] || fail "$label: the module did not see a Kerberos login"
  [[ "$(module_stat login_succeeded_total)" == 1 ]] || fail "$label: the module saw no login success"
  [[ "$(module_stat login_denied_total)" == 0 ]] || fail "$label: the module refused the login"
  echo "  ok: $label: SUSER_NAME() = $want"
}
# expect_refused <label> <user> [nodeleg]: the login does not succeed.
expect_refused() {
  local label="$1" out
  shift
  if out="$(odbc_login "$@")"; then fail "$label: the login unexpectedly succeeded: $out"; fi
  echo "  ok: $label: refused ($(tr '\n' ' ' <<<"$out" | cut -c1-160))"
}

# --- 1. service_account
start_envoy service_account
expect_login "service_account: alice logs in, the server sees the proxy's account" \
  "$AD_DOMAIN\\$AD_PROXY_ACCOUNT" alice
stop_envoy

# --- 4. The channel binding (reported only).
start_envoy service_account tls_server_end_point
out="$(odbc_login alice)" || true
if grep -qxF "$AD_DOMAIN\\$AD_PROXY_ACCOUNT|KERBEROS" <<<"$out"; then
  echo "  channel_binding tls_server_end_point: ACCEPTED by SQL Server"
else
  echo "  channel_binding tls_server_end_point: REFUSED: $(tr '\n' ' ' <<<"$out" | cut -c1-200)"
fi
stop_envoy

# --- 2, 3. delegate
start_envoy delegate
expect_login "delegate, TGT forwarded by the client: alice" "$AD_DOMAIN\\alice" alice
stop_envoy
start_envoy delegate
expect_login "delegate, TGT forwarded by the client: bob" "$AD_DOMAIN\\bob" bob
stop_envoy
start_envoy delegate
expect_login "delegate, nothing forwarded (S4U2Proxy): alice" "$AD_DOMAIN\\alice" alice nodeleg
stop_envoy
start_envoy delegate
expect_login "delegate, nothing forwarded (S4U2Proxy): bob" "$AD_DOMAIN\\bob" bob nodeleg
stop_envoy

# --- Which path was which: without the S4U2Proxy permission the forwarding
# client still gets in, the other one does not.
restore_delegation() {
  dc samba-tool delegation add-service "$AD_PROXY_ACCOUNT" "$AD_SQL_SPN" >/dev/null 2>&1 || true
}
dc samba-tool delegation del-service "$AD_PROXY_ACCOUNT" "$AD_SQL_SPN" >/dev/null \
  || fail "could not remove the delegation permission"
start_envoy delegate
expect_login "delegate, TGT forwarded, S4U2Proxy not allowed: alice" "$AD_DOMAIN\\alice" alice
stop_envoy
start_envoy delegate
expect_refused "delegate, nothing forwarded, S4U2Proxy not allowed: alice" alice nodeleg
stop_envoy

echo "PASS: mssql_ad_terminate_test"

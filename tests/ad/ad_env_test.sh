#!/usr/bin/env bash
# Proves the AD environment (ad_env.sh) works without the proxy:
#   1. up, then a direct ODBC 17 Kerberos login as alice and as bob from the
#      host (kinit through the env's krb5.conf); SELECT SUSER_NAME() must be
#      ADTEST\alice / ADTEST\bob with auth_scheme KERBEROS;
#   2. a direct NTLM login as ADTEST\alice, from a throwaway client container
#      on the domain's network (the host has no NTLM-capable client). The
#      result is reported, not asserted either way: SQL Server on Linux is
#      expected to refuse NTLM with error 18452 ("Login failed. The login is
#      from an untrusted domain and cannot be used with Integrated
#      authentication.") right after the client's NTLMSSP NEGOTIATE;
#   3. down, then no container, network or file of the run is left.
# Needs docker, kinit, unixODBC's isql with ODBC Driver 17, openssl. Exits 77
# (skip) when one is missing. Uses its own state directory, so a development
# environment brought up with ad_env.sh up is left alone.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AD="$HERE/ad_env.sh"
skip() { echo "SKIP: ad_env_test: $*"; exit 77; }
command -v docker >/dev/null && docker info >/dev/null 2>&1 || skip "Docker is not available"
for tool in kinit isql openssl; do command -v "$tool" >/dev/null || skip "$tool not found"; done
odbcinst -q -d 2>/dev/null | grep -q "ODBC Driver 17 for SQL Server" || skip "ODBC Driver 17 for SQL Server not installed"

TMP="$(mktemp -d)"
export AD_ENV_DIR="$TMP/state"
cleanup() { "$AD" down >/dev/null 2>&1 || true; rm -rf "$TMP"; }
trap cleanup EXIT
fail() { echo "FAIL: ad_env_test: $*" >&2; exit 1; }

"$AD" up || fail "up failed"
# shellcheck disable=SC1091
source "$AD_ENV_DIR/env.sh"

# --- Kerberos, direct, from the host.
kerberos_login() {
  local user="$1" ccache="$2" out
  out="$(echo "SET NOCOUNT ON; SELECT SUSER_NAME() AS who, auth_scheme FROM sys.dm_exec_connections WHERE session_id = @@SPID" \
    | KRB5_CONFIG="$AD_KRB5_CONF" KRB5CCNAME="FILE:$ccache" isql -b -d'|' -k \
      "Driver={ODBC Driver 17 for SQL Server};Server=tcp:127.0.0.1,$AD_SQL_PORT;Trusted_Connection=yes;ServerSPN=$AD_SQL_SPN;Encrypt=no" 2>&1)" \
    || fail "Kerberos login as $user failed: $out"
  grep -q "^$AD_DOMAIN\\\\$user|KERBEROS" <<<"$out" || fail "Kerberos login as $user: unexpected result: $out"
  echo "  ok: ODBC 17 Kerberos login: SUSER_NAME() = $(grep -o "^$AD_DOMAIN\\\\$user|KERBEROS" <<<"$out")"
}
kerberos_login alice "$AD_ALICE_CCACHE"
kerberos_login bob "$AD_BOB_CCACHE"

# Without a ticket the same login must fail (the success above was Kerberos).
if echo "SELECT 1" | KRB5_CONFIG="$AD_KRB5_CONF" KRB5CCNAME="FILE:$TMP/none.ccache" isql -b -k \
  "Driver={ODBC Driver 17 for SQL Server};Server=tcp:127.0.0.1,$AD_SQL_PORT;Trusted_Connection=yes;ServerSPN=$AD_SQL_SPN;Encrypt=no" \
  >/dev/null 2>&1; then
  fail "a login without a Kerberos ticket succeeded"
fi
echo "  ok: no ticket, no login"

# --- NTLM, direct, from a client container on the domain's network.
client_tag="wb-ad-client:$(sha256sum "$HERE/client/Dockerfile" | cut -c1-12)"
docker image inspect "$client_tag" >/dev/null 2>&1 \
  || docker build -q -t "$client_tag" "$HERE/client" >/dev/null || fail "could not build the client image"
run_client() {
  docker run --rm --network "$AD_NETWORK" --dns "$AD_DC_IP" --dns-search "$AD_DNS_DOMAIN" \
    -e PW="$AD_ALICE_PASSWORD" "$client_tag" bash -c "$1" 2>&1
}
# FreeTDS sends a bare NTLMSSP NEGOTIATE in LOGIN7 (encryption off so a capture
# of port 1433 shows it); ODBC 17 with gss-ntlmssp never gets that far.
ntlm_out="$(run_client '
  printf "[global]\ntds version = 7.4\nencryption = off\n" > /tmp/freetds.conf
  printf "SELECT SUSER_NAME()\ngo\nquit\n" | FREETDSCONF=/tmp/freetds.conf \
    tsql -H '"$AD_SQL_HOST"' -p 1433 -U "ADTEST\\alice" -P "$PW"')" || true
if grep -q "Msg 18452" <<<"$ntlm_out"; then
  echo "  NTLM: REFUSED by SQL Server (FreeTDS, ADTEST\\alice): $(grep -A1 'Msg 18452' <<<"$ntlm_out" | tr -s '\t\n' ' ')"
elif grep -q 'ADTEST.alice' <<<"$ntlm_out"; then
  echo "  NTLM: ACCEPTED by SQL Server (FreeTDS, ADTEST\\alice)"
else
  fail "NTLM probe: neither accepted nor the expected refusal: $ntlm_out"
fi
odbc_out="$(run_client 'echo "ADTEST:alice:$PW" > /tmp/ntlm; NTLM_USER_FILE=/tmp/ntlm /opt/mssql-tools/bin/sqlcmd -E -S tcp:'"$AD_SQL_HOST"',1433 -l 10 -Q "SELECT SUSER_NAME()" | head -3')" || true
echo "  NTLM via ODBC 17 + gss-ntlmssp: $(head -1 <<<"$odbc_out")"

# --- Teardown leaves nothing.
state="$AD_ENV_DIR"
"$AD" down >/dev/null
[[ -z "$(docker ps -aq --filter "label=wb-ad-env=$state")" ]] || fail "down left containers"
[[ -z "$(docker network ls -q --filter "label=wb-ad-env=$state")" ]] || fail "down left a network"
[[ ! -e "$state" ]] || fail "down left $state"
echo "  ok: down removed every container, network and file"

echo "PASS: ad_env_test"

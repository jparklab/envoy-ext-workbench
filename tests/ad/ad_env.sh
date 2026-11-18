#!/usr/bin/env bash
# A throwaway Active Directory domain for the MSSQL proxy's AD tests: a Samba
# AD domain controller and a SQL Server 2025 container that accepts the
# domain's Kerberos logins. Everything is generated per run; nothing secret is
# committed.
#
#   ad_env.sh up           build (once) and start the domain, write <state>/env.sh
#   ad_env.sh down         remove every container, network and file `up` made
#   ad_env.sh status       print the state directory and whether the env is up
#   ad_env.sh dc <cmd..>   run a command in the DC container (samba-tool, ...)
#   ad_env.sh sql <query>  run a T-SQL query on the SQL Server as sa
#
# Needs: docker (exit 77 with a message when it is missing), openssl, and for
# the host-side ccaches kinit (MIT krb5-user). The first `up` builds the DC
# image from a digest-pinned ubuntu:24.04 (apt install samba, needs network)
# and pulls mcr.microsoft.com/mssql/server:2025-latest if it is not local
# (override with MSSQL_IMAGE). The DC image is a cache shared by all checkouts;
# `down --image` removes it as well.
#
# State directory: $AD_ENV_DIR, default ${TMPDIR:-/tmp}/wb-ad-env-<hash of this
# checkout's path>, so each worktree has its own and `down` finds it again.
# Everything lives there: env.sh, krb5.conf, keytabs/, ccaches, SQL config.
#
# The domain
#   realm AD.TEST, NetBIOS domain ADTEST, DNS domain ad.test, DC dc.ad.test
#   users           alice, bob (ADTEST\alice, ADTEST\bob), random passwords
#   sqlsvc          the SQL Server's service account, SPN MSSQLSvc/sql.ad.test:1433
#                   (and MSSQLSvc/sql.ad.test); the SQL Server runs as it for
#                   Kerberos (mssql-conf network.privilegedadaccount)
#   svc-proxy       the proxy's service account, SPN MSSQLSvc/proxy.ad.test:1433,
#                   constrained delegation (msDS-AllowedToDelegateTo) already
#                   allowed to MSSQLSvc/sql.ad.test:1433. Protocol transition
#                   is off: `ad_env.sh dc samba-tool delegation for-any-protocol
#                   svc-proxy on` turns it on, `delegation add-service` /
#                   `del-service` change the targets.
#   DNS             sql.ad.test -> the SQL container, proxy.ad.test -> the
#                   docker bridge's host address (where a proxy on the host
#                   listening on 0.0.0.0 is reachable from the containers);
#                   host-side clients don't resolve these, so they connect to
#                   127.0.0.1 and name the SPN explicitly (ServerSPN=...).
#   SQL logins      [ADTEST\alice], [ADTEST\bob], [ADTEST\svc-proxy], each with
#                   VIEW SERVER STATE (so sys.dm_exec_connections shows the
#                   auth_scheme); plus sa. Service tickets are AES only
#                   (msDS-SupportedEncryptionTypes = 24 on the service accounts).
#
# <state>/env.sh (source it) exports, all AD_-prefixed:
#   AD_REALM AD_DOMAIN AD_DNS_DOMAIN           AD.TEST ADTEST ad.test
#   AD_KRB5_CONF                               krb5.conf for host-side clients
#                                              (KRB5_CONFIG; KDC over TCP at the
#                                              published loopback port)
#   AD_KDC_HOST AD_KDC_PORT                    the KDC as the host reaches it
#   AD_DC_IP AD_SQL_IP AD_GATEWAY_IP           addresses on the bridge network
#   AD_ADMIN_PASSWORD                          Administrator
#   AD_ALICE_PASSWORD AD_BOB_PASSWORD
#   AD_ALICE_CCACHE AD_BOB_CCACHE              FILE: ccaches with a forwardable
#                                              TGT (KRB5CCNAME=FILE:...), 10 h
#   AD_SQL_HOST AD_SQL_SPN                     sql.ad.test MSSQLSvc/sql.ad.test:1433
#   AD_SQL_ADDR AD_SQL_PORT                    127.0.0.1:<port> the host reaches
#                                              the SQL Server at (published port)
#   AD_SQL_SA_PASSWORD
#   AD_SQLSVC_KEYTAB                           the SQL Server's keytab
#   AD_PROXY_HOST AD_PROXY_SPN AD_PROXY_ACCOUNT
#                                              proxy.ad.test MSSQLSvc/proxy.ad.test:1433 svc-proxy
#   AD_PROXY_KEYTAB                            keys under the proxy's SPN
#                                              (an acceptor keytab, like the
#                                              module's keytab_file)
#   AD_PROXY_ACCOUNT_KEYTAB AD_PROXY_PASSWORD  keys / password of svc-proxy@AD.TEST
#                                              (the initiator, auth.kerberos upstream)
#   AD_NETWORK AD_DC_CONTAINER AD_SQL_CONTAINER
#   AD_ENV_DIR
#
# Host-side Kerberos client, no proxy:
#   source <state>/env.sh
#   KRB5_CONFIG=$AD_KRB5_CONF KRB5CCNAME=FILE:$AD_ALICE_CCACHE \
#     isql -v -b -k "Driver={ODBC Driver 17 for SQL Server};Server=tcp:127.0.0.1,$AD_SQL_PORT;\
#       Trusted_Connection=yes;ServerSPN=$AD_SQL_SPN;Encrypt=no"
#
# What ad_env_test.sh shows against this environment (no proxy):
#   Kerberos  ODBC 17 (isql -k) with a kinit'ed ticket: SUSER_NAME() returns
#             ADTEST\alice, sys.dm_exec_connections.auth_scheme is KERBEROS.
#   NTLM      SQL Server on Linux refuses it. A client's LOGIN7 carrying an
#             NTLMSSP NEGOTIATE (FreeTDS tsql -U 'ADTEST\alice') is answered at
#             once with error 18452, "Login failed. The login is from an
#             untrusted domain and cannot be used with Integrated
#             authentication.", with no NTLM CHALLENGE. ODBC 17 + gss-ntlmssp
#             never offers NTLM ("No Kerberos credentials available"), so a
#             SPNEGO-wrapped NTLM token was not tried.
#
# Why the SQL container has /etc/hosts entries for the DC: to resolve
# [ADTEST\alice] SQL Server looks up "ADTEST" to find a DC, reverse-resolves the
# address, and binds to LDAP on the name that comes back. Docker's embedded DNS
# answers that reverse lookup with the container's own name, which nothing
# resolves; /etc/hosts is read first and gives dc.ad.test. (Without it:
# "Windows NT user or group 'ADTEST\alice' not found".) To see why a lookup or
# login fails, put a logger.ini enabling security.kerberos / security.ldap in
# the container's /var/opt/mssql and read /var/opt/mssql/log/security.log.
#
# Creating another service account the same way (see dc/setup.sh): samba-tool
# user create + `samba-tool spn add`, msDS-SupportedEncryptionTypes = 24, then
# `samba-tool domain exportkeytab <file> --principal=<spn>@AD.TEST`.
#
# Set AD_ENV_KEEP=1 to keep a failed `up` for inspection (then run `down`).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
REALM=AD.TEST
DOMAIN=ADTEST
DNS_DOMAIN=ad.test
SQL_IMAGE="${MSSQL_IMAGE:-mcr.microsoft.com/mssql/server:2025-latest}"
STATE="${AD_ENV_DIR:-${TMPDIR:-/tmp}/wb-ad-env-$(printf %s "$REPO_ROOT" | sha1sum | cut -c1-8)}"
LABEL="wb-ad-env=$STATE"
DC_TAG="wb-ad-dc:$(cat "$HERE"/dc/* | sha256sum | cut -c1-12)"

die() { echo "ad_env: $*" >&2; exit 1; }
need_docker() {
  command -v docker >/dev/null && docker info >/dev/null 2>&1 \
    || { echo "SKIP: ad_env: Docker is not available" >&2; exit 77; }
}
secret() { echo "Wb1!$(openssl rand -hex 12)"; }

# Removes what `up` made: labelled containers (and their volumes) and
# networks, then the state directory.
teardown() {
  local ids
  ids="$(docker ps -aq --filter "label=$LABEL")"
  # shellcheck disable=SC2086
  [[ -z "$ids" ]] || docker rm -fv $ids >/dev/null
  ids="$(docker network ls -q --filter "label=$LABEL")"
  # shellcheck disable=SC2086
  [[ -z "$ids" ]] || docker network rm $ids >/dev/null
  if [[ -e "$STATE" ]] && ! rm -rf "$STATE" 2>/dev/null; then
    # Files a container left behind as root.
    docker run --rm -v "$STATE:/s" --entrypoint sh ubuntu:24.04 -c 'rm -rf /s/* /s/.[!.]*' >/dev/null 2>&1 || true
    rm -rf "$STATE"
  fi
}

load_env() {
  [[ -f "$STATE/env.sh" ]] || die "not up (no $STATE/env.sh); run: $0 up"
  # shellcheck disable=SC1091
  source "$STATE/env.sh"
}

cmd_up() {
  need_docker
  [[ ! -e "$STATE" ]] || die "$STATE exists; run '$0 down' first"
  local name="wb-ad-$$"
  mkdir -p "$STATE/keytabs" "$STATE/sql"
  chmod 755 "$STATE" "$STATE/keytabs" "$STATE/sql"
  # shellcheck disable=SC2154
  trap 'rc=$?; if [[ $rc -ne 0 && -z "${AD_ENV_KEEP:-}" ]]; then echo "ad_env: up failed, cleaning up" >&2; teardown; fi' EXIT

  local admin_pw alice_pw bob_pw sqlsvc_pw proxy_pw sa_pw
  admin_pw="$(secret)"; alice_pw="$(secret)"; bob_pw="$(secret)"
  sqlsvc_pw="$(secret)"; proxy_pw="$(secret)"; sa_pw="$(secret)"

  # A private /24 for the two containers (a fixed address needs a configured
  # subnet); gateway .1 is the host.
  local net="$name" subnet="" prefix=""
  for _ in $(seq 40); do
    subnet="10.$((RANDOM % 100 + 100)).$((RANDOM % 250 + 1)).0/24"
    docker network create --label "$LABEL" --subnet "$subnet" "$net" >/dev/null 2>&1 && break
    subnet=""
  done
  [[ -n "$subnet" ]] || die "could not create a docker network"
  prefix="${subnet%.0/24}"
  local gw_ip="$prefix.1" dc_ip="$prefix.2" sql_ip="$prefix.3"

  docker image inspect "$DC_TAG" >/dev/null 2>&1 || {
    echo "ad_env: building $DC_TAG"
    docker build -q -t "$DC_TAG" "$HERE/dc" >/dev/null || die "could not build the DC image"
  }

  local dc="$name-dc" sql="$name-sql"
  AD_ADMIN_PASSWORD="$admin_pw" docker run -d --name "$dc" --hostname "dc.$DNS_DOMAIN" \
    --network "$net" --ip "$dc_ip" --label "$LABEL" -v "$STATE/keytabs:/out" \
    -e AD_REALM="$REALM" -e AD_DOMAIN="$DOMAIN" -e AD_ADMIN_PASSWORD -e AD_HOST_IP="$dc_ip" \
    -p 127.0.0.1::88/tcp "$DC_TAG" >/dev/null || die "could not start the DC"
  local ready=""
  for _ in $(seq 120); do
    docker exec "$dc" bash -c "kinit Administrator@$REALM <<<\"\$AD_ADMIN_PASSWORD\"" >/dev/null 2>&1 \
      && { ready=1; break; }
    [[ -n "$(docker ps -q --filter "name=^$dc\$")" ]] || break
    sleep 1
  done
  [[ -n "$ready" ]] || { docker logs "$dc" 2>&1 | tail -20 >&2; die "the DC did not become ready"; }

  docker exec -e AD_REALM="$REALM" -e AD_DOMAIN="$DOMAIN" -e AD_DC_IP="$dc_ip" -e AD_ADMIN_PASSWORD="$admin_pw" \
    -e AD_SQL_IP="$sql_ip" -e AD_PROXY_IP="$gw_ip" \
    -e AD_USERS="alice:$alice_pw bob:$bob_pw" \
    -e AD_SQLSVC_PASSWORD="$sqlsvc_pw" -e AD_PROXY_PASSWORD="$proxy_pw" \
    -e AD_OUT_UID="$(id -u)" -e AD_OUT_GID="$(id -g)" \
    "$dc" /opt/ad/setup.sh || die "could not set up the domain accounts"

  local kdc_port
  kdc_port="$(docker port "$dc" 88/tcp | head -1 | sed 's/.*://')"

  # krb5.conf for clients on the host: the KDC over TCP through the published
  # port, no DNS lookups, no reverse lookups.
  cat >"$STATE/krb5.conf" <<EOF
[libdefaults]
  default_realm = $REALM
  dns_lookup_kdc = false
  dns_lookup_realm = false
  dns_canonicalize_hostname = false
  rdns = false
  forwardable = true
  udp_preference_limit = 1
[realms]
  $REALM = {
    kdc = 127.0.0.1:$kdc_port
  }
[domain_realm]
  .$DNS_DOMAIN = $REALM
  $DNS_DOMAIN = $REALM
EOF
  # The same for the SQL Server container, which reaches the DC directly.
  cat >"$STATE/sql/krb5.conf" <<EOF
[libdefaults]
  default_realm = $REALM
  dns_lookup_kdc = false
  dns_lookup_realm = false
  dns_canonicalize_hostname = false
  rdns = false
  udp_preference_limit = 1
[realms]
  $REALM = {
    kdc = $dc_ip
    admin_server = $dc_ip
  }
[domain_realm]
  .$DNS_DOMAIN = $REALM
  $DNS_DOMAIN = $REALM
EOF
  cat >"$STATE/sql/mssql.conf" <<'EOF'
[network]
kerberoskeytabfile = /var/opt/mssql/secrets/mssql.keytab
privilegedadaccount = sqlsvc
EOF
  chmod 644 "$STATE/krb5.conf" "$STATE/sql/krb5.conf" "$STATE/sql/mssql.conf"

  MSSQL_SA_PASSWORD="$sa_pw" docker run -d --name "$sql" --hostname "sql.$DNS_DOMAIN" \
    --network "$net" --ip "$sql_ip" --label "$LABEL" \
    --dns "$dc_ip" --dns-search "$DNS_DOMAIN" \
    --add-host "dc.$DNS_DOMAIN:$dc_ip" --add-host "$DNS_DOMAIN:$dc_ip" --add-host "${DOMAIN,,}:$dc_ip" \
    -e ACCEPT_EULA=Y -e MSSQL_SA_PASSWORD \
    -v "$STATE/sql/mssql.conf:/var/opt/mssql/mssql.conf:ro" \
    -v "$STATE/sql/krb5.conf:/etc/krb5.conf:ro" \
    -v "$STATE/keytabs/sqlsvc.keytab:/var/opt/mssql/secrets/mssql.keytab:ro" \
    -p 127.0.0.1::1433 "$SQL_IMAGE" >/dev/null || die "could not start $SQL_IMAGE"

  local sqlcmd=(docker exec -e SQLCMDPASSWORD="$sa_pw" "$sql" /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -C)
  ready=""
  for _ in $(seq 120); do
    "${sqlcmd[@]}" -l 2 -h -1 -Q "SELECT 1" >/dev/null 2>&1 && { ready=1; break; }
    sleep 1
  done
  [[ -n "$ready" ]] || { docker logs "$sql" 2>&1 | tail -20 >&2; die "SQL Server did not become ready"; }

  local sql_port tsql="" acct
  sql_port="$(docker port "$sql" 1433/tcp | head -1 | sed 's/.*://')"
  for acct in alice bob svc-proxy; do
    tsql+="CREATE LOGIN [$DOMAIN\\$acct] FROM WINDOWS; GRANT VIEW SERVER STATE TO [$DOMAIN\\$acct]; "
  done
  "${sqlcmd[@]}" -b -Q "$tsql" >/dev/null \
    || { "${sqlcmd[@]}" -Q "$tsql" 2>&1 | tail -5 >&2; docker logs "$sql" 2>&1 | grep -i -E "krb|kerb|ad |ldap|sssd" | tail -10 >&2; die "could not create the Windows logins"; }

  # Host-side ccaches with a forwardable TGT for the two users.
  if command -v kinit >/dev/null; then
    local u pw
    for u in alice bob; do
      pw="$alice_pw"; [[ "$u" == bob ]] && pw="$bob_pw"
      printf '%s\n' "$pw" | KRB5_CONFIG="$STATE/krb5.conf" KRB5CCNAME="FILE:$STATE/$u.ccache" \
        kinit -f "$u@$REALM" >/dev/null 2>&1 || die "host kinit as $u failed (KDC 127.0.0.1:$kdc_port)"
    done
  else
    echo "ad_env: kinit not found, no ccaches written" >&2
  fi

  {
    printf 'export AD_ENV_DIR=%q\n' "$STATE"
    printf 'export AD_REALM=%q AD_DOMAIN=%q AD_DNS_DOMAIN=%q\n' "$REALM" "$DOMAIN" "$DNS_DOMAIN"
    printf 'export AD_KRB5_CONF=%q AD_KDC_HOST=127.0.0.1 AD_KDC_PORT=%q\n' "$STATE/krb5.conf" "$kdc_port"
    printf 'export AD_DC_IP=%q AD_SQL_IP=%q AD_GATEWAY_IP=%q\n' "$dc_ip" "$sql_ip" "$gw_ip"
    printf 'export AD_ADMIN_PASSWORD=%q\n' "$admin_pw"
    printf 'export AD_ALICE_PASSWORD=%q AD_BOB_PASSWORD=%q\n' "$alice_pw" "$bob_pw"
    printf 'export AD_ALICE_CCACHE=%q AD_BOB_CCACHE=%q\n' "$STATE/alice.ccache" "$STATE/bob.ccache"
    printf 'export AD_SQL_HOST=%q AD_SQL_SPN=%q\n' "sql.$DNS_DOMAIN" "MSSQLSvc/sql.$DNS_DOMAIN:1433"
    printf 'export AD_SQL_ADDR=%q AD_SQL_PORT=%q AD_SQL_SA_PASSWORD=%q\n' "127.0.0.1:$sql_port" "$sql_port" "$sa_pw"
    printf 'export AD_SQLSVC_KEYTAB=%q\n' "$STATE/keytabs/sqlsvc.keytab"
    printf 'export AD_PROXY_HOST=%q AD_PROXY_SPN=%q AD_PROXY_ACCOUNT=svc-proxy\n' "proxy.$DNS_DOMAIN" "MSSQLSvc/proxy.$DNS_DOMAIN:1433"
    printf 'export AD_PROXY_KEYTAB=%q AD_PROXY_ACCOUNT_KEYTAB=%q AD_PROXY_PASSWORD=%q\n' \
      "$STATE/keytabs/proxy.keytab" "$STATE/keytabs/svc-proxy.keytab" "$proxy_pw"
    printf 'export AD_NETWORK=%q AD_DC_CONTAINER=%q AD_SQL_CONTAINER=%q\n' "$net" "$dc" "$sql"
  } >"$STATE/env.sh"
  chmod 600 "$STATE/env.sh"
  echo "ad_env: up; source $STATE/env.sh"
}

cmd_down() {
  need_docker
  local image=""
  [[ "${1:-}" == --image ]] && image=1
  teardown
  [[ -z "$image" ]] || docker rmi "$DC_TAG" >/dev/null 2>&1 || true
  echo "ad_env: down"
}

case "${1:-}" in
  up) cmd_up ;;
  down) shift; cmd_down "$@" ;;
  status)
    echo "state: $STATE"
    if [[ -f "$STATE/env.sh" ]]; then echo "up: yes ($STATE/env.sh)"; else echo "up: no"; fi ;;
  dc) shift; need_docker; load_env; docker exec -i "$AD_DC_CONTAINER" "$@" ;;
  sql) shift; need_docker; load_env
    docker exec -e SQLCMDPASSWORD="$AD_SQL_SA_PASSWORD" "$AD_SQL_CONTAINER" \
      /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -C -Q "$*" ;;
  *) sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//' >&2; exit 2 ;;
esac

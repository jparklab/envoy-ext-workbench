#!/usr/bin/env bash
# Starts a throwaway MIT Kerberos KDC for tests, realm TEST.REALM on a free
# 127.0.0.1 port, everything under <dir>:
#   krb5.conf, kdc.conf      KRB5_CONFIG / KRB5_KDC_PROFILE for this realm
#   service.keytab           MSSQLSvc/sql.test:1433 (the SQL Server's key)
#   proxy.keytab             MSSQLSvc/proxy.test:1433 (the proxy's own SPN)
#   svc-proxy.keytab         svc-proxy (the proxy's service account)
#   alice.ccache             alice@TEST.REALM's TGT (forwardable)
#   kdc.pid                  stop with: kill "$(cat <dir>/kdc.pid)"
#   other.keytab             MSSQLSvc/other.test:1433
#   proxy-other.keytab       MSSQLSvc/proxy.test:1433 and MSSQLSvc/other.test:1433
#   ghost.keytab             a principal the KDC no longer has
# Every key is random and throwaway.
# Usage: mit_kdc.sh <dir>. Exits 77 when the MIT KDC tools are missing.
set -euo pipefail
dir="$1"
export PATH="$PATH:/usr/sbin:/sbin"
for tool in kdb5_util kadmin.local krb5kdc kinit; do
  command -v "$tool" >/dev/null || { echo "mit_kdc.sh: $tool not found" >&2; exit 77; }
done
mkdir -p "$dir"
port="$(python3 -I -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"

cat >"$dir/krb5.conf" <<CONF
[libdefaults]
  default_realm = TEST.REALM
  dns_lookup_kdc = false
  dns_lookup_realm = false
  dns_canonicalize_hostname = false
  rdns = false
  forwardable = true
  udp_preference_limit = 1
[realms]
  TEST.REALM = {
    kdc = 127.0.0.1:$port
  }
[domain_realm]
  .test = TEST.REALM
  sql.test = TEST.REALM
CONF
cat >"$dir/kdc.conf" <<CONF
[kdcdefaults]
  kdc_listen = 127.0.0.1:$port
  kdc_tcp_listen = 127.0.0.1:$port
[realms]
  TEST.REALM = {
    database_name = $dir/principal
    key_stash_file = $dir/stash
    acl_file = $dir/kadm5.acl
    max_life = 1h
  }
[logging]
  kdc = FILE:$dir/kdc.log
CONF
: >"$dir/kadm5.acl"
export KRB5_CONFIG="$dir/krb5.conf" KRB5_KDC_PROFILE="$dir/kdc.conf"

kdb5_util create -s -r TEST.REALM -P "$(python3 -I -c 'import secrets; print(secrets.token_hex(16))')" >/dev/null
kadmin.local -q "addprinc -randkey MSSQLSvc/sql.test:1433" >/dev/null
kadmin.local -q "addprinc -randkey MSSQLSvc/other.test:1433" >/dev/null
kadmin.local -q "addprinc -randkey alice" >/dev/null
kadmin.local -q "addprinc -randkey MSSQLSvc/proxy.test:1433" >/dev/null
kadmin.local -q "addprinc -randkey svc-proxy" >/dev/null
kadmin.local -q "ktadd -k $dir/service.keytab MSSQLSvc/sql.test:1433" >/dev/null
kadmin.local -q "ktadd -k $dir/proxy.keytab MSSQLSvc/proxy.test:1433" >/dev/null
kadmin.local -q "ktadd -k $dir/svc-proxy.keytab svc-proxy" >/dev/null
kadmin.local -q "ktadd -norandkey -k $dir/alice.keytab alice" >/dev/null
# For the rotation tests: the key of MSSQLSvc/other.test:1433 alone, and with
# the proxy's, in one keytab (same keys as in the other files); and a
# principal the KDC doesn't know (its keytab remains, the principal doesn't).
kadmin.local -q "ktadd -k $dir/other.keytab MSSQLSvc/other.test:1433" >/dev/null
kadmin.local -q "ktadd -norandkey -k $dir/proxy-other.keytab MSSQLSvc/proxy.test:1433" >/dev/null
kadmin.local -q "ktadd -norandkey -k $dir/proxy-other.keytab MSSQLSvc/other.test:1433" >/dev/null
kadmin.local -q "addprinc -randkey ghost" >/dev/null
kadmin.local -q "ktadd -k $dir/ghost.keytab ghost" >/dev/null
kadmin.local -q "delprinc -force ghost" >/dev/null
krb5kdc -P "$dir/kdc.pid"
for _ in $(seq 50); do
  KRB5CCNAME="FILE:$dir/alice.ccache" kinit -f -k -t "$dir/alice.keytab" alice 2>/dev/null && exit 0
  sleep 0.1
done
echo "mit_kdc.sh: the KDC did not answer; $dir/kdc.log:" >&2
cat "$dir/kdc.log" >&2 || true
exit 1

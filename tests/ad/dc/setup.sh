#!/bin/bash
# Creates the test accounts, DNS records and keytabs on a running, provisioned
# DC (docker exec). Run once by ad_env.sh up. Environment:
#   AD_REALM AD_DOMAIN AD_ADMIN_PASSWORD AD_DC_IP
#   AD_SQL_IP AD_PROXY_IP     addresses of sql.<domain> and proxy.<domain>
#   AD_USERS="alice:pw bob:pw"  AD_SQLSVC_PASSWORD AD_PROXY_PASSWORD
#   AD_OUT_UID AD_OUT_GID     owner of the keytabs written to /out
set -euo pipefail
domain_dns="${AD_REALM,,}"
adm="Administrator%$AD_ADMIN_PASSWORD"
SQL_SPN="MSSQLSvc/sql.$domain_dns:1433"
PROXY_SPN="MSSQLSvc/proxy.$domain_dns:1433"

for u in $AD_USERS; do
  samba-tool user create "${u%%:*}" "${u#*:}" --use-username-as-cn >/dev/null
  samba-tool user setexpiry "${u%%:*}" --noexpiry >/dev/null
done

# The SQL Server's service account, and the proxy's (which ad-terminate logs in
# as and configures constrained delegation for).
samba-tool user create sqlsvc "$AD_SQLSVC_PASSWORD" --use-username-as-cn >/dev/null
samba-tool user setexpiry sqlsvc --noexpiry >/dev/null
samba-tool spn add "$SQL_SPN" sqlsvc >/dev/null
samba-tool spn add "MSSQLSvc/sql.$domain_dns" sqlsvc >/dev/null

samba-tool user create svc-proxy "$AD_PROXY_PASSWORD" --use-username-as-cn >/dev/null
samba-tool user setexpiry svc-proxy --noexpiry >/dev/null
samba-tool spn add "$PROXY_SPN" svc-proxy >/dev/null
# Constrained delegation (S4U2Proxy) from the proxy to the SQL Server's SPN.
samba-tool delegation add-service svc-proxy "$SQL_SPN" >/dev/null

# Like Windows, Samba issues RC4 service tickets and exports RC4-only SPN keys
# for an account that doesn't say which encryption types it supports. Say AES
# (24 = AES128 + AES256) so the service tickets and the keytabs are AES.
for u in sqlsvc svc-proxy; do
  dn="$(ldbsearch -H /var/lib/samba/private/sam.ldb "(sAMAccountName=$u)" dn 2>/dev/null | sed -n 's/^dn: //p')"
  printf 'dn: %s\nchangetype: modify\nreplace: msDS-SupportedEncryptionTypes\nmsDS-SupportedEncryptionTypes: 24\n' "$dn" \
    | ldbmodify -H /var/lib/samba/private/sam.ldb >/dev/null
done

# Host names the clients and the SQL Server use.
samba-tool dns add 127.0.0.1 "$domain_dns" sql A "$AD_SQL_IP" -U "$adm" >/dev/null
samba-tool dns add 127.0.0.1 "$domain_dns" "${AD_DOMAIN,,}" A "$AD_DC_IP" -U "$adm" >/dev/null
samba-tool dns add 127.0.0.1 "$domain_dns" proxy A "$AD_PROXY_IP" -U "$adm" >/dev/null

# Keytabs: the account's own keys, under the account principal and its SPN.
mkdir -p /out
samba-tool domain exportkeytab /out/sqlsvc.keytab --principal="sqlsvc@$AD_REALM" >/dev/null
samba-tool domain exportkeytab /out/sqlsvc.keytab --principal="$SQL_SPN@$AD_REALM" >/dev/null
samba-tool domain exportkeytab /out/svc-proxy.keytab --principal="svc-proxy@$AD_REALM" >/dev/null
samba-tool domain exportkeytab /out/proxy.keytab --principal="$PROXY_SPN@$AD_REALM" >/dev/null
chown "$AD_OUT_UID:$AD_OUT_GID" /out/*.keytab
chmod 644 /out/*.keytab

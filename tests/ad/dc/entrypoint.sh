#!/bin/bash
# Provisions the domain on first start, then runs Samba in the foreground.
# NT ACLs go to the user.* xattr namespace: security.NTACL needs capabilities
# a plain container lacks (provisioning fails with ACCESS_DENIED on sysvol).
# Environment: AD_REALM (AD.TEST), AD_DOMAIN (ADTEST), AD_ADMIN_PASSWORD, AD_HOST_IP.
set -euo pipefail
if [[ ! -f /var/lib/samba/private/sam.ldb ]]; then
  samba-tool domain provision \
    --realm="$AD_REALM" --domain="$AD_DOMAIN" --server-role=dc \
    --dns-backend=SAMBA_INTERNAL --use-rfc2307 \
    --adminpass="$AD_ADMIN_PASSWORD" --host-ip="$AD_HOST_IP" \
    --option="dns forwarder = 127.0.0.11" \
    --option="vfs objects = dfs_samba4 acl_xattr" \
    --option="acl_xattr:security_acl_name = user.NTACL" >/var/log/provision.log 2>&1 \
    || { cat /var/log/provision.log >&2; exit 1; }
fi
# Samba's own krb5.conf finds the KDC through DNS SRV records, which this
# container's resolver (docker's) can't answer; point at the local KDC.
cat >/etc/krb5.conf <<CONF
[libdefaults]
  default_realm = $AD_REALM
  dns_lookup_kdc = false
  dns_lookup_realm = false
[realms]
  $AD_REALM = {
    kdc = 127.0.0.1
  }
CONF
exec samba --interactive --debug-stdout -d 1

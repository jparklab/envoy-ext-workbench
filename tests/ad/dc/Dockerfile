# Samba AD domain controller for the MSSQL proxy's AD tests (tests/ad/ad_env.sh).
# Ubuntu 24.04 pinned by digest; Samba comes from the distro (4.19).
FROM ubuntu:24.04@sha256:73b999393d07f2bf65a40373778a44dc9a6d54ad7718d29247d8ff9413c4d6a8
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      samba samba-ad-dc samba-ad-provision smbclient krb5-user ldb-tools \
      ldap-utils dnsutils iproute2 ca-certificates \
 && rm -rf /var/lib/apt/lists/* /etc/samba/smb.conf
COPY entrypoint.sh setup.sh /opt/ad/
RUN chmod 755 /opt/ad/*.sh
ENTRYPOINT ["/opt/ad/entrypoint.sh"]

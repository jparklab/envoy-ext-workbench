# Throwaway client for the AD tests that the host can't run: NTLM through
# gss-ntlmssp (ODBC 17 sqlcmd, SPNEGO-wrapped NTLM) and FreeTDS (bare NTLMSSP).
FROM ubuntu:24.04@sha256:73b999393d07f2bf65a40373778a44dc9a6d54ad7718d29247d8ff9413c4d6a8
ENV DEBIAN_FRONTEND=noninteractive ACCEPT_EULA=Y
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl gnupg unixodbc gss-ntlmssp krb5-user freetds-bin \
 && curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor -o /usr/share/keyrings/microsoft.gpg \
 && echo "deb [signed-by=/usr/share/keyrings/microsoft.gpg] https://packages.microsoft.com/ubuntu/24.04/prod noble main" > /etc/apt/sources.list.d/mssql.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends msodbcsql17 mssql-tools \
 && rm -rf /var/lib/apt/lists/*

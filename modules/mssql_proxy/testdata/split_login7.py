#!/usr/bin/env python3
"""A SQL login whose LOGIN7 spans several TDS packets under login-only TLS.

Sends LOGIN7 the way MS-TDS requires when the server only encrypts the login
(PRELOGIN ENCRYPTION off on both sides): the first packet inside TLS, every
other packet in plain TDS. mssql-jdbc does this with long Kerberos logins.

Usage: split_login7.py HOST PORT USER   (password in $SQLCMDPASSWORD)
Prints "LOGINACK split=<packets>" and exits 0 when the server accepts the
login; prints the server's error, or what went wrong, and exits 1 otherwise.
Standard library only; the server certificate is not checked (test only).
"""

import os
import socket
import ssl
import struct
import sys

PRELOGIN, LOGIN7, TABULAR = 0x12, 0x10, 0x04
PACKET_SIZE = 512  # The smallest TDS packet size, so the login spans packets.


def packets(kind, payload, size):
    chunk = size - 8
    parts = [payload[i:i + chunk] for i in range(0, len(payload), chunk)] or [b""]
    out = []
    for n, part in enumerate(parts):
        status = 0x01 if n == len(parts) - 1 else 0x00
        out.append(struct.pack(">BBHHBB", kind, status, len(part) + 8, 0, (n + 1) & 0xFF, 0) + part)
    return out


def read_exact(sock, n):
    data = b""
    while len(data) < n:
        more = sock.recv(n - len(data))
        if not more:
            raise ConnectionError("connection closed by the server")
        data += more
    return data


def read_message(sock):
    """Reads one plain TDS message; returns (type, payload)."""
    payload, kind = b"", None
    while True:
        kind, status, length = struct.unpack(">BBH", read_exact(sock, 4))
        read_exact(sock, 4)
        payload += read_exact(sock, length - 8)
        if status & 0x01:
            return kind, payload


def prelogin_payload():
    options = [
        (0x00, b"\x11\x00\x00\x00\x00\x00"),  # VERSION
        (0x01, b"\x00"),  # ENCRYPTION: off (login-only)
        (0x02, b"\x00"),  # INSTOPT
        (0x03, struct.pack(">I", os.getpid())),  # THREADID
    ]
    offset = len(options) * 5 + 1
    head, data = b"", b""
    for token, value in options:
        head += struct.pack(">BHH", token, offset + len(data), len(value))
        data += value
    return head + b"\xff" + data


def prelogin_encryption(payload):
    i = 0
    while payload[i] != 0xFF:
        token, offset, length = struct.unpack(">BHH", payload[i:i + 5])
        if token == 0x01:
            return payload[offset]
        i += 5
    return None


def obfuscate(password):
    return bytes((((b << 4) & 0xF0) | (b >> 4)) ^ 0xA5 for b in password.encode("utf-16-le"))


def login7_payload(user, password):
    host, app, library = "h" * 128, "a" * 128, "l" * 128  # Long enough to span packets.
    fields = [  # In data order; the password lands in the first packet.
        (36, host.encode("utf-16-le"), len(host)),
        (40, user.encode("utf-16-le"), len(user)),
        (44, obfuscate(password), len(password)),
        (48, app.encode("utf-16-le"), len(app)),
        (52, b"", 0),  # ServerName
        (60, library.encode("utf-16-le"), len(library)),
        (64, b"", 0),  # Language
        (68, "master".encode("utf-16-le"), 6),
    ]
    fixed = bytearray(94)
    struct.pack_into("<IIIII", fixed, 4, 0x74000004, 4096, 0x07000000, os.getpid(), 0)
    fixed[24:28] = bytes([0xE0, 0x03, 0x00, 0x00])  # USE_DB, INIT_DB_FATAL, SET_LANG; ODBC
    struct.pack_into("<i I", fixed, 28, 0, 0x0409)
    data = b""
    for at, value, chars in fields:
        struct.pack_into("<HH", fixed, at, 94 + len(data), chars)
        data += value
    for at in (56, 78, 82, 86):  # Extension, SSPI, AtchDBFile, ChangePassword: empty.
        struct.pack_into("<HH", fixed, at, 94 + len(data), 0)
    struct.pack_into("<I", fixed, 0, 94 + len(data))
    return bytes(fixed) + data


def login_result(payload):
    """Walks the login response tokens; returns (ok, error text)."""
    i, error = 0, ""
    while i < len(payload):
        token = payload[i]
        if token == 0xFD:  # DONE
            i += 13
            continue
        if token not in (0xAA, 0xAB, 0xAD, 0xE3):
            return False, f"unexpected token 0x{token:02x}"
        (length,) = struct.unpack("<H", payload[i + 1:i + 3])
        body = payload[i + 3:i + 3 + length]
        if token == 0xAD:
            return True, ""
        if token == 0xAA:  # ERROR: number, state, class, US_VARCHAR message.
            (chars,) = struct.unpack("<H", body[6:8])
            error = body[8:8 + 2 * chars].decode("utf-16-le")
        i += 3 + length
    return False, error or "no LOGINACK"


def main():
    host, port, user = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    password = os.environ["SQLCMDPASSWORD"]
    sock = socket.create_connection((host, port), timeout=10)

    for p in packets(PRELOGIN, prelogin_payload(), 4096):
        sock.sendall(p)
    kind, response = read_message(sock)
    if kind != TABULAR or prelogin_encryption(response) != 0x00:
        print(f"expected a login-only PRELOGIN answer, got type 0x{kind:02x}")
        return 1

    # TLS handshake carried in PRELOGIN packets.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = ctx.wrap_bio(incoming, outgoing, server_side=False)
    while True:
        try:
            tls.do_handshake()
            break
        except ssl.SSLWantReadError:
            flight = outgoing.read()
            if flight:
                for p in packets(PRELOGIN, flight, 4096):
                    sock.sendall(p)
            kind, payload = read_message(sock)
            if kind != PRELOGIN and kind != TABULAR:
                print(f"unexpected TDS type 0x{kind:02x} during the TLS handshake")
                return 1
            incoming.write(payload)
    if flight := outgoing.read():
        for p in packets(PRELOGIN, flight, 4096):
            sock.sendall(p)

    # LOGIN7: first packet inside TLS (raw records), the rest plain.
    login = packets(LOGIN7, login7_payload(user, password), PACKET_SIZE)
    if len(login) < 2:
        print("LOGIN7 fits one packet; nothing to split")
        return 1
    tls.write(login[0])
    sock.sendall(outgoing.read())
    for p in login[1:]:
        sock.sendall(p)

    kind, response = read_message(sock)
    ok, error = login_result(response) if kind == TABULAR else (False, f"type 0x{kind:02x}")
    if not ok:
        print(f"login failed: {error}")
        return 1
    print(f"LOGINACK split={len(login)}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ConnectionError, ssl.SSLError) as e:
        print(f"split_login7: {e}")
        sys.exit(1)

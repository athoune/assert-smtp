import smtplib
import ssl
from base64 import b64encode
from dataclasses import dataclass
from typing import cast

PORTS = [25, 465, 587]


def tls_then_starttls(
    host: str, port: int, timeout=5, context: ssl.SSLContext | None = None
) -> tuple[smtplib.SMTP | smtplib.SMTP_SSL, str]:
    "Try to connect with TLS, and fallback to PLAIN+STARTTLS"
    try:
        server = smtplib.SMTP_SSL(host=host, port=port, timeout=timeout, context=context)
        return server, "smtps"
    except (ssl.SSLError, TimeoutError):
        print(f"smtps://{host}:{port} connection didn't work, lets try SMTP+STARTTLS")
        server = smtplib.SMTP(host=host, port=port, timeout=timeout)
        server.starttls(context=context)
        return server, "smtp+starttls"


@dataclass
class Audit:
    protocol: str
    port: int
    name: str
    commands: list[bytes]
    cipher: tuple[str, str, str] | None
    cert: None # FIXME it's a _PeerCertRetDictType


def auth_plain_utf8(server:smtplib.SMTP | smtplib.SMTP_SSL, user: str, password: str) -> tuple[int, bytes]:
    "PLAIN AUTH with UTF8"
    # status, msg = server.login(user, password)
    # login method does exist, but doesn't handle UTF8 password
    # see https://github.com/python/cpython/issues/73936
    return server.docmd(
        "AUTH PLAIN",
        b64encode(f"\0{user}\0{password}".encode("utf8")).decode("ascii"),
    )


def assert_smtp_auth(host: str, user: str, password: str, port: int = 0, context: ssl.SSLContext | None = None) -> Audit:
    "Connect to a SMTP server, with smtps or smtp+starttls and PLAIN AUTH"
    server: smtplib.SMTP | smtplib.SMTP_SSL
    status: int
    msg: bytes
    protocol: str
    if context is None:
        context = ssl.create_default_context()
    context.check_hostname = True
    server, protocol = tls_then_starttls(host, port=port, context=context)
    ssl_sock = cast(ssl.SSLSocket, server.sock) # smtps or starttls : its a SSLSocket
    cert = ssl_sock.getpeercert()
    cipher = ssl_sock.cipher()

    status, msg = server.ehlo()
    assert status == 250
    ehlo = msg.split(b"\n")
    auths = []
    for option in ehlo:
        if option.startswith(b"AUTH "):
            auths = option.split(b" ")[1:]
            break
    assert b"PLAIN" in auths, f"PLAIN not in {auths}"
    status, msg = auth_plain_utf8(server, user, password)
    assert status == 235, f"wrong status {status} : {msg}"
    return Audit(protocol=protocol, port=port, name=ehlo[0].decode('utf8'), commands=ehlo[1:], cert=cert, cipher=cipher)


if __name__ == "__main__":
    import os
    from pprint import pprint

    host = os.getenv("SMTP_HOST")
    for port in PORTS:
        try:
            a = assert_smtp_auth(
                host, os.getenv("SMTP_USER"), os.getenv("SMTP_PASSWORD"), port=port)
        except (TimeoutError, smtplib.SMTPServerDisconnected):
            print(f"Can't connect {host}:{port}")
        else:
            pprint(a)

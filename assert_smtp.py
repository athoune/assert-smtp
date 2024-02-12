import smtplib
import ssl
from base64 import b64encode
from dataclasses import dataclass
from typing import cast

PORTS = [25, 465, 587]


def tls_then_starttls(
    host: str, port: int, timeout=5, context: ssl.SSLContext | None = None
) -> tuple[smtplib.SMTP | smtplib.SMTP_SSL, str]:
    try:
        return smtplib.SMTP_SSL(host=host, port=port, timeout=timeout, context=context), "smtps"
    except (TimeoutError, ssl.SSLError):
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


def assert_smtp_auth(host: str, user: str, password: str, port: int = 0, context: ssl.SSLContext | None = None) -> Audit:
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
    assert b"AUTH PLAIN" in ehlo
    # status, msg = server.login(user, password)
    # login method does exist, but doesn't handle UTF8 password
    # see https://github.com/python/cpython/issues/73936
    status, msg = server.docmd(
        "AUTH PLAIN",
        b64encode(f"\0{user}\0{password}".encode("utf8")).decode("ascii"),
    )
    return Audit(protocol=protocol, port=port, name=ehlo[0].decode('utf8'), commands=ehlo[1:], cert=cert, cipher=cipher)


if __name__ == "__main__":
    import os
    from pprint import pprint

    host = os.getenv("SMTP_HOST")
    for port in PORTS:
        try:
            a = assert_smtp_auth(
                host, os.getenv("SMTP_USER"), os.getenv("SMTP_PASSWORD"), port=port)
        except TimeoutError:
            print(f"Can't connect {host}:{port}")
        else:
            pprint(a)

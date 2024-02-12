from base64 import b64encode
import smtplib
import ssl
from dataclasses import dataclass
from typing import Generator


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


def assert_smtp(host: str, user: str, password: str, ports: list[int] | None = None, context: ssl.SSLContext | None = None) -> Generator[Audit, None, None]:
    server: smtplib.SMTP | smtplib.SMTP_SSL
    status: int
    msg: bytes
    protocol: str
    if context is None:
        context = ssl.create_default_context()
    context.check_hostname = True
    if ports is None:
        ports = PORTS

    for port in ports:
        try:
            server, protocol = tls_then_starttls(host, port=port, context=context)
        except TimeoutError:
            print(f"Timeout {host}:{port}")
            continue

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
        yield Audit(protocol=protocol, port=port, name=ehlo[0].decode('utf8'), commands=ehlo[1:])


if __name__ == "__main__":
    import os

    for a in assert_smtp(
        os.getenv("SMTP_HOST"), os.getenv("SMTP_USER"), os.getenv("SMTP_PASSWORD")
    ):
        print(a)

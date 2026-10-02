from __future__ import annotations

import datetime as dt
import ssl
import threading
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


class Site:
    """A tiny configurable HTTP(S) server: routes map path -> (status, headers, body)."""

    def __init__(self, tls: tuple[Path, Path] | None = None):
        self.routes: dict[str, tuple[int, list[tuple[str, str]], str]] = {}
        self.reflect_origin = False
        self.hits: list[str] = []
        site = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                site.hits.append(self.path)
                status, headers, body = site.routes.get(
                    self.path, site.routes.get("*", (404, [], "not found")))
                self.send_response(status)
                for k, v in headers:
                    self.send_header(k, v)
                origin = self.headers.get("Origin")
                if site.reflect_origin and origin:
                    self.send_header("Access-Control-Allow-Origin", origin)
                    self.send_header("Access-Control-Allow-Credentials", "true")
                data = body.encode()
                self.send_header("Content-Length", str(len(data)))
                if not any(k.lower() == "content-type" for k, _ in headers):
                    self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(data)

            def version_string(self):
                return "test"  # the stdlib default discloses version and trips WSS009

            def log_message(self, *args):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        scheme = "http"
        if tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")  # allow deliberately weak test certs
            ctx.load_cert_chain(*tls)
            self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
            scheme = "https"
        self.port = self.server.server_port
        self.url = f"{scheme}://127.0.0.1:{self.port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def make_cert(
    tmp: Path,
    *,
    days_valid: int = 30,
    started_days_ago: int = 1,
    key_bits: int = 2048,
    signature: hashes.HashAlgorithm | None = None,
) -> tuple[Path, Path]:
    """Create a self-signed certificate (for 127.0.0.1/localhost) with controllable flaws."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_bits)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=started_days_ago))
        .not_valid_after(now - dt.timedelta(days=started_days_ago) + dt.timedelta(days=days_valid))
        .add_extension(x509.SubjectAlternativeName(
            [x509.DNSName("localhost"), x509.IPAddress(__import__("ipaddress").ip_address(
                "127.0.0.1"))]), critical=False)
        .sign(key, signature or hashes.SHA256())
    )
    cert_path, key_path = tmp / "cert.pem", tmp / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))
    return cert_path, key_path


@pytest.fixture
def make_site() -> Iterator[Callable[..., Site]]:
    created: list[Site] = []

    def factory(tls: tuple[Path, Path] | None = None) -> Site:
        s = Site(tls)
        created.append(s)
        return s

    yield factory
    for s in created:
        s.close()


@pytest.fixture
def site(make_site: Callable[..., Site]) -> Site:
    return make_site()


@pytest.fixture
def https_site(make_site: Callable[..., Site], tmp_path: Path) -> Site:
    s = make_site(make_cert(tmp_path))
    s.routes["*"] = (200, [], "<html></html>")
    return s


HARDENED = [
    ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'self'"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("Permissions-Policy", "camera=()"),
]

from __future__ import annotations

import shutil
import ssl
import subprocess
import threading
from http.server import HTTPServer

import pytest

from conftest import Site
from websec.checks import CHECKS
from websec.checks.tls import accepts_protocol, inspect_certificate
from websec.scanner import scan

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl CLI needed")


@pytest.fixture
def https_site(tmp_path):
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
         "-out", str(cert), "-days", "30", "-subj", "/CN=localhost",
         "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
        check=True, capture_output=True)
    site = Site()
    site.server.shutdown()  # reuse its handler on a TLS-wrapped socket
    server = HTTPServer(("127.0.0.1", 0), site.server.RequestHandlerClass)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    site.routes["*"] = (200, [], "<html></html>")
    site.url = f"https://127.0.0.1:{server.server_port}"
    site.port = server.server_port
    yield site
    server.shutdown()


def test_self_signed_cert_reported_and_page_still_scanned(https_site):
    result = scan(https_site.url, {g: CHECKS[g] for g in ("tls", "headers")})
    ids = {f.rule.id for f in result.findings}
    assert "WSS035" in ids  # untrusted certificate
    assert "WSS003" in ids  # headers were still checked despite the SSL failure
    assert not result.errors


def test_inspect_certificate_untrusted(https_site):
    res = inspect_certificate("127.0.0.1", https_site.port, 5)
    assert not res.verified and not res.expired and res.error


def test_modern_server_rejects_nothing_extra(https_site):
    # Python's default server context is TLS1.2+; legacy handshakes must not succeed.
    assert not accepts_protocol("127.0.0.1", https_site.port, ssl.TLSVersion.TLSv1, 5)

from __future__ import annotations

import socket
import ssl
import time
import warnings
from dataclasses import dataclass
from urllib.parse import urlsplit

import certifi

from .. import rules
from ..models import Finding
from ..scanner import ScanContext

EXPIRY_WARN_DAYS = 14
X509_V_ERR_CERT_HAS_EXPIRED = 10
LEGACY_VERSIONS = {
    "TLS 1.0": ssl.TLSVersion.TLSv1,
    "TLS 1.1": ssl.TLSVersion.TLSv1_1,
}


@dataclass
class CertResult:
    verified: bool
    expired: bool = False
    error: str = ""
    days_left: float | None = None


def inspect_certificate(host: str, port: int, timeout: float) -> CertResult:
    """Handshake with full verification; classify the outcome."""
    # Same trust store as `requests`, so TLS findings agree with the page fetch and don't
    # depend on whether the host Python ships CA certificates (python.org macOS builds don't).
    ctx = ssl.create_default_context(cafile=certifi.where())
    try:
        with (socket.create_connection((host, port), timeout=timeout) as sock,
              ctx.wrap_socket(sock, server_hostname=host) as tls):
            cert = tls.getpeercert()
    except ssl.SSLCertVerificationError as exc:
        return CertResult(verified=False,
                          expired=exc.verify_code == X509_V_ERR_CERT_HAS_EXPIRED,
                          error=exc.verify_message)
    not_after = ssl.cert_time_to_seconds(cert["notAfter"])
    return CertResult(verified=True, days_left=(not_after - time.time()) / 86400)


def accepts_protocol(host: str, port: int, version: ssl.TLSVersion, timeout: float) -> bool:
    """True if the server completes a handshake pinned to `version`.

    Returns False if the handshake fails *or* the local OpenSSL cannot speak the
    legacy protocol; in the latter case the result is inconclusive, never a finding.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)  # pinning TLS 1.0/1.1 is the point
            ctx.minimum_version = version
            ctx.maximum_version = version
        with (socket.create_connection((host, port), timeout=timeout) as sock,
              ctx.wrap_socket(sock, server_hostname=host)):
            return True
    except (ssl.SSLError, ValueError, OSError):
        return False


def _tls_endpoint(ctx: ScanContext) -> tuple[str, int] | None:
    """Where to run TLS checks: the target itself, or port 443 for a plain-HTTP URL."""
    p = urlsplit(ctx.url)
    if p.scheme == "https":
        return p.hostname, p.port or 443
    if p.port is None and p.hostname:
        try:
            with socket.create_connection((p.hostname, 443), timeout=ctx.timeout):
                return p.hostname, 443
        except OSError:
            return None
    return None


def check_tls(ctx: ScanContext) -> list[Finding]:
    out: list[Finding] = []
    endpoint = _tls_endpoint(ctx)
    start_url = ctx.url

    if urlsplit(start_url).scheme == "http":
        if endpoint is None:
            out.append(Finding(rules.get("WSS030"), start_url,
                               "Target is served over plain HTTP and no HTTPS endpoint was found."))
        elif not ctx.is_https:
            out.append(Finding(rules.get("WSS031"), start_url,
                               "HTTP request was served directly rather than redirecting to HTTPS."))

    if endpoint is None:
        return out
    host, port = endpoint
    where = f"https://{host}:{port}/"

    cert = inspect_certificate(host, port, ctx.timeout)
    if cert.expired:
        out.append(Finding(rules.get("WSS033"), where, f"Certificate for {host} has expired.",
                           evidence=cert.error))
    elif not cert.verified:
        out.append(Finding(rules.get("WSS035"), where,
                           f"Certificate for {host} failed validation: {cert.error}.",
                           evidence=cert.error))
    elif cert.days_left is not None and cert.days_left < EXPIRY_WARN_DAYS:
        out.append(Finding(rules.get("WSS034"), where,
                           f"Certificate for {host} expires in {cert.days_left:.0f} days.",
                           evidence=f"{cert.days_left:.1f} days remaining"))

    legacy = [name for name, v in LEGACY_VERSIONS.items()
              if accepts_protocol(host, port, v, ctx.timeout)]
    if legacy:
        out.append(Finding(rules.get("WSS032"), where,
                           f"Server accepts deprecated protocol(s): {', '.join(legacy)}.",
                           evidence=", ".join(legacy)))
    return out

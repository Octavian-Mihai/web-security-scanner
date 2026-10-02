from __future__ import annotations

import ipaddress
import socket
import ssl
import warnings
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlsplit

import certifi
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from .. import rules
from ..models import Finding
from ..scanner import ScanContext

EXPIRY_WARN_DAYS = 14
MIN_RSA_BITS = 2048
MIN_EC_BITS = 224
WEAK_SIGNATURE_HASHES = {"sha1", "md5"}
X509_V_ERR_CERT_HAS_EXPIRED = 10
LEGACY_VERSIONS = {
    "TLS 1.0": ssl.TLSVersion.TLSv1,
    "TLS 1.1": ssl.TLSVersion.TLSv1_1,
}


@dataclass
class CertInfo:
    days_left: float
    key_type: str  # "RSA" | "EC" | "other"
    key_bits: int | None
    signature_hash: str | None
    verify_error: str = ""  # empty if the chain validated
    verify_code: int = 0

    @property
    def expired_only(self) -> bool:
        return self.verify_code == X509_V_ERR_CERT_HAS_EXPIRED


def is_loopback(host: str) -> bool:
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _leaf_der(host: str, port: int, timeout: float) -> bytes:
    """Fetch the leaf certificate without validating it, so we can analyse bad certs too."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    # Inspection only: the connection is closed before any data is sent.
    ctx.verify_mode = ssl.CERT_NONE  # nosec B501
    # Level 0 so a weak certificate (short key, SHA-1) can be *retrieved and reported*
    # rather than rejected by our own client before we get to analyse it.
    ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    with (socket.create_connection((host, port), timeout=timeout) as sock,
          ctx.wrap_socket(sock, server_hostname=host) as tls):
        der = tls.getpeercert(binary_form=True)
    if der is None:
        raise ssl.SSLError("server presented no certificate")
    return der


def _verify(host: str, port: int, timeout: float) -> tuple[str, int]:
    # Same trust store as `requests`, so TLS findings agree with the page fetch and don't
    # depend on whether the host Python ships CA certificates (python.org macOS builds don't).
    ctx = ssl.create_default_context(cafile=certifi.where())
    try:
        with (socket.create_connection((host, port), timeout=timeout) as sock,
              ctx.wrap_socket(sock, server_hostname=host)):
            return "", 0
    except ssl.SSLCertVerificationError as exc:
        return exc.verify_message, exc.verify_code


def describe_certificate(der: bytes, now: datetime | None = None) -> CertInfo:
    cert = x509.load_der_x509_certificate(der)
    now = now or datetime.now(UTC)
    days_left = (cert.not_valid_after_utc - now).total_seconds() / 86400

    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        key_type, key_bits = "RSA", key.key_size
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key_type, key_bits = "EC", key.key_size
    else:
        key_type, key_bits = "other", None
    try:
        sig = cert.signature_hash_algorithm
        sig_name = sig.name if sig is not None else None
    except UnsupportedAlgorithm:
        sig_name = None
    return CertInfo(days_left, key_type, key_bits, sig_name)


def inspect_certificate(host: str, port: int, timeout: float) -> CertInfo:
    info = describe_certificate(_leaf_der(host, port, timeout))
    info.verify_error, info.verify_code = _verify(host, port, timeout)
    return info


def accepts_protocol(host: str, port: int, version: ssl.TLSVersion, timeout: float) -> bool:
    """True if the server completes a handshake pinned to `version`.

    Returns False if the handshake fails *or* the local OpenSSL cannot speak the
    legacy protocol; in the latter case the result is inconclusive, never a finding.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    # Protocol probe only: the connection is closed before any data is sent.
    ctx.verify_mode = ssl.CERT_NONE  # nosec B501
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
    if not p.hostname:
        return None
    if p.scheme == "https":
        return p.hostname, p.port or 443
    if p.port is None:
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
    host_of_url = urlsplit(start_url).hostname or ""

    if urlsplit(start_url).scheme == "http":
        if endpoint is None:
            if is_loopback(host_of_url):
                out.append(Finding(rules.get("WSS038"), start_url,
                                   "Loopback target is served over plain HTTP."))
            else:
                out.append(Finding(
                    rules.get("WSS030"), start_url,
                    "Target is served over plain HTTP and no HTTPS endpoint was found."))
        elif not ctx.is_https:
            out.append(Finding(rules.get("WSS031"), start_url,
                               "HTTP request was served directly rather than redirecting "
                               "to HTTPS."))

    if endpoint is None:
        return out
    host, port = endpoint
    where = f"https://{host}:{port}/"

    cert = inspect_certificate(host, port, ctx.timeout)
    if cert.days_left < 0:
        out.append(Finding(rules.get("WSS033"), where,
                           f"Certificate for {host} expired {-cert.days_left:.0f} days ago.",
                           evidence=f"{cert.days_left:.1f} days remaining"))
    elif cert.days_left < EXPIRY_WARN_DAYS:
        out.append(Finding(rules.get("WSS034"), where,
                           f"Certificate for {host} expires in {cert.days_left:.0f} days.",
                           evidence=f"{cert.days_left:.1f} days remaining"))
    if cert.verify_error and not cert.expired_only:
        out.append(Finding(rules.get("WSS035"), where,
                           f"Certificate for {host} failed validation: {cert.verify_error}.",
                           evidence=cert.verify_error))

    weak_key = (
        (cert.key_type == "RSA" and (cert.key_bits or 0) < MIN_RSA_BITS)
        or (cert.key_type == "EC" and (cert.key_bits or 0) < MIN_EC_BITS))
    if weak_key:
        out.append(Finding(rules.get("WSS036"), where,
                           f"Certificate uses a weak {cert.key_type} key ({cert.key_bits} bits).",
                           evidence=f"{cert.key_type}-{cert.key_bits}"))
    if cert.signature_hash in WEAK_SIGNATURE_HASHES:
        out.append(Finding(rules.get("WSS037"), where,
                           f"Certificate is signed with {cert.signature_hash.upper()}.",
                           evidence=str(cert.signature_hash)))

    legacy = [name for name, v in LEGACY_VERSIONS.items()
              if accepts_protocol(host, port, v, ctx.timeout)]
    if legacy:
        out.append(Finding(rules.get("WSS032"), where,
                           f"Server accepts deprecated protocol(s): {', '.join(legacy)}.",
                           evidence=", ".join(legacy)))
    return out

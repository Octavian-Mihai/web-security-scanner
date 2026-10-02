"""Rule catalog. Every finding the scanner can emit is defined here, with its
CWE and OWASP Top 10 (2021) mapping, so reports and SARIF stay consistent."""

from __future__ import annotations

from .models import Rule, Severity

A01 = "A01:2021 Broken Access Control"
A02 = "A02:2021 Cryptographic Failures"
A03 = "A03:2021 Injection"
A05 = "A05:2021 Security Misconfiguration"

_RULES = [
    # --- security headers -------------------------------------------------
    Rule("WSS001", "Missing Content-Security-Policy", Severity.MEDIUM,
         "The response has no Content-Security-Policy header, so the browser applies no "
         "restrictions on script sources. CSP is the main defence-in-depth control against XSS.",
         "Add a Content-Security-Policy header, starting with `default-src 'self'`.",
         693, A05),
    Rule("WSS002", "Weak Content-Security-Policy", Severity.MEDIUM,
         "The Content-Security-Policy allows 'unsafe-inline', 'unsafe-eval' or a wildcard "
         "source in a script-executing directive, which largely defeats its XSS protection.",
         "Remove 'unsafe-inline'/'unsafe-eval' and wildcard sources; use nonces or hashes.",
         79, A03),
    Rule("WSS003", "Missing Strict-Transport-Security", Severity.MEDIUM,
         "An HTTPS response has no Strict-Transport-Security header, leaving users open to "
         "TLS-stripping attacks on their first or any downgraded request.",
         "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains`.",
         319, A02),
    Rule("WSS004", "Weak Strict-Transport-Security", Severity.LOW,
         "The HSTS max-age is shorter than six months, so protection lapses quickly.",
         "Use a max-age of at least 15552000 (180 days); 31536000 is recommended.",
         319, A02),
    Rule("WSS005", "Missing clickjacking protection", Severity.MEDIUM,
         "The response sets neither X-Frame-Options nor a CSP frame-ancestors directive, so "
         "the page can be framed by any site.",
         "Send `Content-Security-Policy: frame-ancestors 'self'` (and X-Frame-Options: "
         "SAMEORIGIN for legacy browsers).",
         1021, A05),
    Rule("WSS006", "Missing X-Content-Type-Options", Severity.LOW,
         "Without `X-Content-Type-Options: nosniff`, browsers may MIME-sniff responses and "
         "execute content as a different type than declared.",
         "Send `X-Content-Type-Options: nosniff`.",
         693, A05),
    Rule("WSS007", "Missing Referrer-Policy", Severity.LOW,
         "No Referrer-Policy is set, so full URLs (possibly containing tokens or identifiers) "
         "may leak to third parties via the Referer header.",
         "Send `Referrer-Policy: strict-origin-when-cross-origin` or stricter.",
         200, A05),
    Rule("WSS008", "Missing Permissions-Policy", Severity.LOW,
         "No Permissions-Policy (or legacy Feature-Policy) is set, so powerful browser "
         "features are not explicitly restricted.",
         "Send a Permissions-Policy header disabling features the site does not use.",
         693, A05),
    Rule("WSS009", "Server technology/version disclosure", Severity.LOW,
         "Server or X-Powered-By headers reveal software names and versions, helping "
         "attackers pick known exploits.",
         "Remove or genericise Server, X-Powered-By and similar headers.",
         200, A05),
    # --- CORS -------------------------------------------------------------
    Rule("WSS010", "Wildcard CORS policy", Severity.MEDIUM,
         "Access-Control-Allow-Origin is `*`, so any website can read this response from "
         "a visitor's browser.",
         "Restrict Access-Control-Allow-Origin to an explicit allow-list of trusted origins.",
         942, A05),
    Rule("WSS011", "CORS reflects arbitrary origin with credentials", Severity.HIGH,
         "The server reflects an attacker-controlled Origin and allows credentials, so a "
         "malicious site can make authenticated cross-origin reads.",
         "Validate Origin against a strict allow-list; never combine reflection with "
         "Access-Control-Allow-Credentials: true.",
         942, A01),
    # --- cookies ----------------------------------------------------------
    Rule("WSS020", "Cookie without Secure flag", Severity.MEDIUM,
         "A cookie set over HTTPS lacks the Secure attribute and may be sent over "
         "unencrypted connections.",
         "Add the Secure attribute to all cookies.",
         614, A05),
    Rule("WSS021", "Cookie without HttpOnly flag", Severity.MEDIUM,
         "A cookie lacks HttpOnly, so any XSS can read it from JavaScript.",
         "Add HttpOnly to cookies that JavaScript does not need to read.",
         1004, A05),
    Rule("WSS022", "Cookie without SameSite attribute", Severity.LOW,
         "A cookie has no SameSite attribute (or SameSite=None), weakening CSRF defences.",
         "Add SameSite=Lax (or Strict) unless cross-site use is required.",
         1275, A01),
    # --- transport --------------------------------------------------------
    Rule("WSS030", "Site served over plain HTTP", Severity.HIGH,
         "The target is reachable only over unencrypted HTTP, exposing all traffic, "
         "including credentials and session cookies, to interception and modification.",
         "Serve the site over HTTPS and redirect all HTTP traffic to it.",
         319, A02),
    Rule("WSS031", "HTTP does not redirect to HTTPS", Severity.MEDIUM,
         "The HTTP version of the site serves content instead of redirecting to HTTPS.",
         "Redirect all HTTP requests to HTTPS with a 301/308 response.",
         319, A02),
    Rule("WSS032", "Deprecated TLS protocol supported", Severity.HIGH,
         "The server accepts TLS 1.0 or 1.1, which are deprecated (RFC 8996) and "
         "vulnerable to downgrade and cipher-block attacks.",
         "Disable TLS 1.0 and 1.1; support TLS 1.2 and 1.3 only.",
         327, A02),
    Rule("WSS033", "TLS certificate expired", Severity.HIGH,
         "The server certificate has expired; browsers will warn users and clients "
         "may skip validation.",
         "Renew the certificate and automate renewal.",
         298, A02),
    Rule("WSS034", "TLS certificate expires soon", Severity.MEDIUM,
         "The server certificate expires within 14 days.",
         "Renew the certificate and automate renewal.",
         298, A02),
    Rule("WSS035", "TLS certificate validation failed", Severity.HIGH,
         "The certificate could not be validated (self-signed, untrusted issuer, or "
         "hostname mismatch), enabling man-in-the-middle attacks.",
         "Install a certificate from a trusted CA that matches the hostname.",
         295, A02),
    # --- exposure ---------------------------------------------------------
    Rule("WSS040", "Exposed version-control metadata", Severity.HIGH,
         "Repository metadata (e.g. /.git/) is publicly readable, which can leak "
         "full source code and secrets.",
         "Block access to dotfiles/VCS directories and remove them from deployments.",
         538, A05),
    Rule("WSS041", "Exposed environment file", Severity.CRITICAL,
         "A .env-style file is publicly readable and appears to contain secrets.",
         "Remove the file from the web root and rotate every exposed secret.",
         200, A05),
    Rule("WSS042", "Directory listing enabled", Severity.MEDIUM,
         "A directory index is served, exposing file names and potentially sensitive files.",
         "Disable automatic directory listing on the web server.",
         548, A05),
]

RULES: dict[str, Rule] = {r.id: r for r in _RULES}


def get(rule_id: str) -> Rule:
    return RULES[rule_id]

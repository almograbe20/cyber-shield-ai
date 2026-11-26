"""
Website Scanner — Cyber Shield AI (Phase 4: "attack" / live website scanning)
=============================================================================
Scans a LIVE website for security issues. Designed defensively and legally:

  • PASSIVE checks (always allowed): we only read what a normal browser reads
    when visiting the page — security headers, TLS certificate, cookie flags,
    information disclosure. This is NOT an attack; it is analyzing a normal
    page load, and is legal for any site.

  • ACTIVE checks (require verified ownership): probing sensitive paths /
    sending test payloads. These run ONLY after the user proves they own the
    target (ownership token), to keep the platform legal and non-abusable.

We never send exploit payloads to a site the user has not verified. The goal
is defense (reporting + remediation), not exploitation.

Dependencies: requests (HTTP), ssl + socket (TLS, stdlib).
"""

import os
import ssl
import socket
import hashlib
import datetime
import ipaddress
from urllib.parse import urlparse

import requests

VERIFY_PATH = "/.well-known/cybershield-verify.txt"
USER_AGENT = "CyberShieldAI-Scanner/1.0 (+security self-check)"  # generic, no user data
TIMEOUT = 8
MAX_BYTES = 2 * 1024 * 1024  # cap response size (2 MB) to protect the scanner from huge replies

# Allow scanning loopback (localhost) — ON for local dev/testing, turn OFF in production
# by setting CYBERSHIELD_ALLOW_LOCALHOST=0
ALLOW_LOCALHOST = os.getenv("CYBERSHIELD_ALLOW_LOCALHOST", "1") != "0"

# Secret salt for deriving ownership tokens (in production: load from env/secret store)
_TOKEN_SALT = "cyber-shield-ai-ownership-v1"


class SSRFBlocked(Exception):
    """Raised when a target resolves to a disallowed (internal/reserved) address."""


# ---------------------------------------------------------------------------
# SSRF protection
# ---------------------------------------------------------------------------
def _ip_allowed(ip_str: str) -> bool:
    """Reject private / reserved / link-local / metadata addresses (SSRF guard)."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if ip.is_loopback:
        return ALLOW_LOCALHOST  # localhost only when explicitly allowed
    # Block everything internal or special-purpose (incl. 169.254.169.254 cloud metadata)
    if (ip.is_private or ip.is_link_local or ip.is_reserved
            or ip.is_multicast or ip.is_unspecified):
        return False
    return True


def ssrf_check(url: str) -> None:
    """
    Resolves the target host and blocks it if any resolved IP is internal/reserved.
    Raises SSRFBlocked on a disallowed target. This prevents the scanner from being
    pointed at internal infrastructure or cloud metadata endpoints.
    """
    host = urlparse(normalize_url(url)).hostname
    if not host:
        raise SSRFBlocked("invalid host")
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise SSRFBlocked(f"could not resolve host: {host}")
    for info in infos:
        ip_str = info[4][0]
        if not _ip_allowed(ip_str):
            raise SSRFBlocked(f"target resolves to a disallowed address ({ip_str})")


def _safe_get(url: str, allow_redirects: bool = True):
    """requests.get with a size cap, so a huge response can't exhaust the scanner."""
    r = requests.get(url, timeout=TIMEOUT, headers={"User-Agent": USER_AGENT},
                     allow_redirects=allow_redirects, stream=True)
    body = b""
    for chunk in r.iter_content(8192):
        body += chunk
        if len(body) >= MAX_BYTES:
            break
    r._content = body  # materialize capped body for .text / .content
    return r


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _finding(fid, title, severity, cwe, evidence, description, remediation):
    return {
        "id": fid, "title": title, "severity": severity, "cwe": cwe,
        "line": 0, "snippet": evidence[:200] if evidence else "",
        "description": description, "remediation": remediation,
    }


def normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def ownership_token(user_id: int, url: str) -> str:
    """Deterministic ownership token for a given user + domain."""
    host = urlparse(normalize_url(url)).hostname or ""
    raw = f"{_TOKEN_SALT}:{user_id}:{host}".encode()
    return "cybershield-" + hashlib.sha256(raw).hexdigest()[:32]


def verify_ownership(url: str, expected_token: str) -> dict:
    """
    Checks whether `expected_token` is present at the target, via either:
      1) https://host/.well-known/cybershield-verify.txt  (file contains the token)
      2) a <meta name="cybershield-verify" content="TOKEN"> tag on the homepage
    Localhost / 127.0.0.1 is auto-trusted (your own machine, for testing).
    """
    url = normalize_url(url)
    host = (urlparse(url).hostname or "").lower()
    if host in ("localhost", "127.0.0.1", "::1"):
        return {"verified": True, "method": "localhost"}

    try:
        ssrf_check(url)
    except SSRFBlocked:
        return {"verified": False, "method": None}

    # 1) well-known file
    try:
        base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        r = _safe_get(base + VERIFY_PATH)
        if r.status_code == 200 and expected_token in r.text:
            return {"verified": True, "method": "well-known-file"}
    except requests.RequestException:
        pass

    # 2) meta tag on homepage
    try:
        r = _safe_get(url)
        if expected_token in r.text:
            return {"verified": True, "method": "meta-tag"}
    except requests.RequestException:
        pass

    return {"verified": False, "method": None}


# ---------------------------------------------------------------------------
# PASSIVE checks (safe, no ownership required)
# ---------------------------------------------------------------------------
def _check_tls(url: str, findings: list):
    parsed = urlparse(url)
    if parsed.scheme != "https":
        findings.append(_finding(
            "WEB-TLS-000", "Site not served over HTTPS", "high", "CWE-319",
            url, "The site is served over plain HTTP; traffic can be read or modified.",
            "Serve the site over HTTPS and redirect all HTTP traffic to HTTPS."))
        return
    host = parsed.hostname
    port = parsed.port or 443
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        not_after = cert.get("notAfter")
        if not_after:
            exp = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days = (exp - datetime.datetime.utcnow()).days
            if days < 0:
                findings.append(_finding(
                    "WEB-TLS-001", "TLS certificate expired", "critical", "CWE-298",
                    f"expired {-days} days ago", "The TLS certificate has expired.",
                    "Renew the TLS certificate immediately."))
            elif days < 15:
                findings.append(_finding(
                    "WEB-TLS-002", "TLS certificate expiring soon", "medium", "CWE-298",
                    f"expires in {days} days", "The TLS certificate expires very soon.",
                    "Renew the certificate and enable auto-renewal."))
    except ssl.SSLCertVerificationError as e:
        findings.append(_finding(
            "WEB-TLS-003", "Invalid TLS certificate", "high", "CWE-295",
            str(e), "The TLS certificate failed verification (self-signed or wrong host).",
            "Install a valid certificate from a trusted CA (e.g. Let's Encrypt)."))
    except Exception:
        pass  # network/timeout — skip TLS check silently


_SECURITY_HEADERS = {
    "strict-transport-security": ("WEB-HDR-001", "Missing HSTS header", "medium", "CWE-319",
        "Strict-Transport-Security is not set, so browsers may use HTTP.",
        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"),
    "content-security-policy": ("WEB-HDR-002", "Missing Content-Security-Policy", "medium", "CWE-1021",
        "No CSP header; reduces protection against XSS and injection.",
        "Add a Content-Security-Policy header scoped to your trusted sources."),
    "x-frame-options": ("WEB-HDR-003", "Missing X-Frame-Options", "medium", "CWE-1021",
        "No clickjacking protection (X-Frame-Options / frame-ancestors).",
        "Add: X-Frame-Options: DENY (or a CSP frame-ancestors directive)."),
    "x-content-type-options": ("WEB-HDR-004", "Missing X-Content-Type-Options", "low", "CWE-693",
        "Browsers may MIME-sniff responses.",
        "Add: X-Content-Type-Options: nosniff"),
    "referrer-policy": ("WEB-HDR-005", "Missing Referrer-Policy", "low", "CWE-200",
        "Referrer information may leak to third parties.",
        "Add: Referrer-Policy: strict-origin-when-cross-origin"),
}


def _check_headers_and_cookies(resp, findings: list):
    headers = {k.lower(): v for k, v in resp.headers.items()}

    for key, (fid, title, sev, cwe, desc, fix) in _SECURITY_HEADERS.items():
        if key not in headers:
            findings.append(_finding(fid, title, sev, cwe, f"header '{key}' absent", desc, fix))

    # Information disclosure
    for h in ("server", "x-powered-by", "x-aspnet-version"):
        if h in headers and any(ch.isdigit() for ch in headers[h]):
            findings.append(_finding(
                "WEB-INFO-001", f"Version disclosure via '{h}' header", "low", "CWE-200",
                f"{h}: {headers[h]}", "The server reveals software/version info to attackers.",
                f"Remove or obscure the '{h}' header."))

    # Cookie flags
    raw_cookies = resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw.headers, "getlist") else \
        ([resp.headers["set-cookie"]] if "set-cookie" in headers else [])
    for c in raw_cookies:
        low = c.lower()
        name = c.split("=", 1)[0]
        missing = [flag for flag in ("secure", "httponly") if flag not in low]
        if "samesite" not in low:
            missing.append("samesite")
        if missing:
            findings.append(_finding(
                "WEB-COOKIE-001", f"Cookie '{name}' missing flags: {', '.join(missing)}",
                "medium", "CWE-614", c[:120],
                "A cookie is missing security flags (Secure/HttpOnly/SameSite).",
                "Set Secure, HttpOnly and SameSite on sensitive cookies."))


# ---------------------------------------------------------------------------
# ACTIVE checks (require verified ownership)
# ---------------------------------------------------------------------------
_SENSITIVE_PATHS = ["/.env", "/.git/HEAD", "/.git/config", "/config.php.bak", "/backup.zip"]


def _check_sensitive_paths(url: str, findings: list):
    base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    for path in _SENSITIVE_PATHS:
        try:
            r = _safe_get(base + path, allow_redirects=False)
            if r.status_code == 200 and r.content:
                findings.append(_finding(
                    "WEB-EXPOSE-001", f"Sensitive file exposed: {path}", "high", "CWE-538",
                    f"{path} -> 200 OK", "A sensitive file is publicly accessible.",
                    f"Block access to {path} at the web server / remove it from the web root."))
        except requests.RequestException:
            pass


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------
def scan_website(url: str, active: bool = False) -> dict:
    """
    Runs a passive scan always; runs active checks only when active=True
    (the caller must have verified ownership first).
    """
    url = normalize_url(url)
    if not url:
        return {"error": "empty URL"}

    # SSRF guard: refuse internal / reserved targets before any request
    try:
        ssrf_check(url)
    except SSRFBlocked as e:
        return {"error": f"Target blocked by SSRF protection: {e}"}

    findings: list = []
    reachable = True
    try:
        resp = _safe_get(url)
    except requests.RequestException as e:
        reachable = False
        resp = None
        findings.append(_finding(
            "WEB-NET-000", "Site unreachable", "low", "CWE-0", str(e),
            "The scanner could not reach the site (DNS, timeout, or network error).",
            "Check that the URL is correct and the site is online."))

    if reachable and resp is not None:
        _check_tls(url, findings)
        _check_headers_and_cookies(resp, findings)
        if active:
            _check_sensitive_paths(url, findings)

    # severity ordering + summary (same shape as the code scanner)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: order.get(f["severity"], 9))
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        summary[f["severity"]] = summary.get(f["severity"], 0) + 1
    weights = {"critical": 25, "high": 12, "medium": 5, "low": 2}
    score = max(0, 100 - sum(weights.get(f["severity"], 0) for f in findings))

    return {
        "target": url,
        "language": "website",
        "lines_scanned": 0,
        "scan_type": "active" if active else "passive",
        "total_findings": len(findings),
        "summary": summary,
        "security_score": score,
        "findings": findings,
    }


if __name__ == "__main__":
    import json
    print(json.dumps(scan_website("https://example.com"), ensure_ascii=False, indent=2))

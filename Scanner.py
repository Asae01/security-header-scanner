#!/usr/bin/env python3
"""
Security Header & Misconfig Scanner
====================================

A beginner-friendly tool that checks a website for:
  1. Missing HTTP security headers (things that protect visitors' browsers)
  2. Commonly exposed sensitive files (like .env or .git/config)
  3. Whether HTTPS is actually enforced
  4. How close the SSL/TLS certificate is to expiring

Usage:
    python3 scanner.py https://example.com
    python3 scanner.py example.com --json
    python3 scanner.py example.com --output report.json --json
    python3 scanner.py example.com --timeout 15

New to this? See the README.md in this repo - it explains what each
check means and why it matters, in plain language.
"""

from __future__ import annotations

import argparse
import json
import socket
import ssl
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import requests

# --------------------------------------------------------------------------
# Configuration: what we check for and why.
# Editing these dictionaries is the easiest way to extend the tool.
# --------------------------------------------------------------------------

SECURITY_HEADERS = {
    "Content-Security-Policy": "Blocks malicious inline scripts (XSS attacks)",
    "Strict-Transport-Security": "Forces HTTPS, blocks downgrade attacks",
    "X-Frame-Options": "Prevents clickjacking via hidden iframes",
    "X-Content-Type-Options": "Stops the browser from mis-reading file types",
    "Referrer-Policy": "Controls what leaks in the Referer header",
    "Permissions-Policy": "Restricts access to camera, mic, location, etc.",
}

SENSITIVE_PATHS = [
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/config.php.bak",
    "/wp-config.php",
    "/.DS_Store",
    "/backup.zip",
    "/.aws/credentials",
    "/phpinfo.php",
]

DEFAULT_TIMEOUT = 10
CERT_WARNING_DAYS = 30  # warn if the SSL cert expires within this many days

# Some CDNs/WAFs (Cloudflare included) serve different responses - or block
# the request outright - when they detect a non-browser User-Agent like the
# requests library's default ("python-requests/x.x"). Identifying as a
# normal browser gets a more accurate picture of what real visitors see.
REQUEST_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"
    )
}


# --------------------------------------------------------------------------
# Data structures: these just hold results in an organized way so the
# reporting code (text or JSON) doesn't need to know how checks were done.
# --------------------------------------------------------------------------

@dataclass
class HeaderResult:
    name: str
    present: bool
    reason: str
    value: Optional[str] = None


@dataclass
class PathResult:
    path: str
    exposed: bool
    status_code: Optional[int] = None


@dataclass
class ScanReport:
    url: str
    http_status: int
    https_enforced: bool
    headers: list[HeaderResult] = field(default_factory=list)
    exposed_paths: list[PathResult] = field(default_factory=list)
    cert_days_remaining: Optional[int] = None
    cert_warning: Optional[str] = None
    errors: list[str] = field(default_factory=list)

    @property
    def header_score(self) -> tuple[int, int]:
        passed = sum(1 for h in self.headers if h.present)
        return passed, len(self.headers)

    @property
    def path_score(self) -> tuple[int, int]:
        safe = sum(1 for p in self.exposed_paths if not p.exposed)
        return safe, len(self.exposed_paths)

    @property
    def overall_grade(self) -> str:
        """A rough A-F grade, similar in spirit to securityheaders.com."""
        h_passed, h_total = self.header_score
        p_safe, p_total = self.path_score
        total_checks = h_total + p_total + 1
        total_passed = h_passed + p_safe + (1 if self.https_enforced else 0)

        if total_checks == 0:
            return "N/A"

        pct = total_passed / total_checks
        if pct >= 0.95:
            return "A"
        if pct >= 0.80:
            return "B"
        if pct >= 0.60:
            return "C"
        if pct >= 0.40:
            return "D"
        return "F"


# --------------------------------------------------------------------------
# Core logic. These functions are intentionally separate from printing,
# so they can be unit-tested without needing a real network connection
# (see tests/test_scanner.py).
# --------------------------------------------------------------------------

def normalize_url(raw_url: str) -> str:
    """Turn user input like 'example.com' into 'https://example.com'."""
    raw_url = raw_url.strip()
    if not raw_url.startswith(("http://", "https://")):
        raw_url = "https://" + raw_url
    return raw_url.rstrip("/")


def evaluate_headers(response_headers) -> list[HeaderResult]:
    """Pure function: given response headers, return pass/fail for each check.

    This does not touch the network, which makes it easy to unit test.
    """
    results = []
    for header, reason in SECURITY_HEADERS.items():
        present = header in response_headers
        value = response_headers.get(header)
        results.append(HeaderResult(name=header, present=present, reason=reason, value=value))
    return results


def check_https_enforced(url: str, timeout: int) -> bool:
    """Check whether the plain-HTTP version of the site redirects to HTTPS.

    If the site is already HTTPS-only and http:// fails to connect at all,
    we treat that as enforced too (nothing to downgrade to).
    """
    parsed = urlparse(url)
    http_url = f"http://{parsed.netloc}{parsed.path}"
    try:
        resp = requests.get(http_url, timeout=timeout, allow_redirects=True, headers=REQUEST_HEADERS)
        return resp.url.startswith("https://")
    except requests.RequestException:
        # http:// didn't even respond - not a downgrade risk.
        return True


def check_sensitive_paths(base_url: str, timeout: int) -> list[PathResult]:
    """Try each known-sensitive path and flag any that return HTTP 200."""
    results = []
    for path in SENSITIVE_PATHS:
        full_url = base_url + path
        try:
            resp = requests.get(full_url, timeout=timeout, allow_redirects=False, headers=REQUEST_HEADERS)
            exposed = resp.status_code == 200
            results.append(PathResult(path=path, exposed=exposed, status_code=resp.status_code))
        except requests.RequestException:
            results.append(PathResult(path=path, exposed=False, status_code=None))
    return results


def check_certificate(url: str, timeout: int) -> tuple[Optional[int], Optional[str]]:
    """Return (days_remaining, warning_message) for the site's SSL certificate.

    Returns (None, None) if the site isn't HTTPS or the check fails for any
    reason - certificate problems shouldn't crash the whole scan.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return None, None

    host = parsed.netloc
    port = 443
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        expires_str = cert["notAfter"]
        expires = datetime.strptime(expires_str, "%b %d %H:%M:%S %Y %Z")
        expires = expires.replace(tzinfo=timezone.utc)
        days_remaining = (expires - datetime.now(timezone.utc)).days

        warning = None
        if days_remaining < 0:
            warning = "Certificate has EXPIRED"
        elif days_remaining < CERT_WARNING_DAYS:
            warning = f"Certificate expires soon ({days_remaining} days)"
        return days_remaining, warning
    except Exception as e:  # noqa: BLE001 - deliberately broad, this is a best-effort check
        return None, f"Could not check certificate: {e}"


def run_scan(url: str, timeout: int = DEFAULT_TIMEOUT) -> ScanReport:
    """Run the full scan and return a ScanReport. Exits the program on fatal errors."""
    url = normalize_url(url)

    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True, headers=REQUEST_HEADERS)
    except requests.RequestException as e:
        print(f"[ERROR] Could not reach {url}: {e}", file=sys.stderr)
        sys.exit(1)

    headers = evaluate_headers(resp.headers)
    https_enforced = check_https_enforced(url, timeout)
    exposed_paths = check_sensitive_paths(url, timeout)
    cert_days, cert_warning = check_certificate(resp.url, timeout)

    return ScanReport(
        url=resp.url,
        http_status=resp.status_code,
        https_enforced=https_enforced,
        headers=headers,
        exposed_paths=exposed_paths,
        cert_days_remaining=cert_days,
        cert_warning=cert_warning,
    )


# --------------------------------------------------------------------------
# Output formatting
# --------------------------------------------------------------------------

def report_to_dict(report: ScanReport) -> dict:
    h_passed, h_total = report.header_score
    p_safe, p_total = report.path_score
    return {
        "url": report.url,
        "http_status": report.http_status,
        "https_enforced": report.https_enforced,
        "grade": report.overall_grade,
        "headers": {
            "passed": h_passed,
            "total": h_total,
            "details": [
                {"name": h.name, "present": h.present, "value": h.value, "reason": h.reason}
                for h in report.headers
            ],
        },
        "exposed_paths": {
            "safe": p_safe,
            "total": p_total,
            "details": [
                {"path": p.path, "exposed": p.exposed, "status_code": p.status_code}
                for p in report.exposed_paths
            ],
        },
        "certificate": {
            "days_remaining": report.cert_days_remaining,
            "warning": report.cert_warning,
        },
    }


def print_text_report(report: ScanReport) -> None:
    print(f"\nScanning: {report.url}")
    print(f"HTTP status: {report.http_status}")
    print(f"HTTPS enforced: {'yes' if report.https_enforced else 'no - plain HTTP is allowed'}")

    print("\n-- Security Headers --")
    for h in report.headers:
        status = "[PASS]" if h.present else "[FAIL]"
        print(f"{status} {h.name:<28} {h.reason}")
    h_passed, h_total = report.header_score
    print(f"Header score: {h_passed}/{h_total}")

    print("\n-- Exposed File Check --")
    for p in report.exposed_paths:
        if p.exposed:
            print(f"[FAIL] {p.path:<22} reachable (HTTP {p.status_code}) - should be blocked!")
        else:
            print(f"[PASS] {p.path:<22} not reachable")
    p_safe, p_total = report.path_score
    print(f"Exposed files found: {p_total - p_safe}/{p_total}")

    print("\n-- SSL/TLS Certificate --")
    if report.cert_days_remaining is not None:
        print(f"Days until expiry: {report.cert_days_remaining}")
    if report.cert_warning:
        print(f"[WARN] {report.cert_warning}")
    elif report.cert_days_remaining is not None:
        print("[PASS] Certificate is valid and not expiring soon")

    print(f"\nOverall grade: {report.overall_grade}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scan a website for missing security headers and exposed files.",
        epilog="Only scan sites you own or have permission to test.",
    )
    parser.add_argument("url", help="Target URL or domain, e.g. example.com")
    parser.add_argument(
        "--timeout", type=int, default=DEFAULT_TIMEOUT,
        help=f"Request timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--output", metavar="FILE", help="Write report to a file as well as stdout")
    args = parser.parse_args()

    report = run_scan(args.url, timeout=args.timeout)

    report_json = json.dumps(report_to_dict(report), indent=2)

    if args.json:
        print(report_json)
    else:
        print_text_report(report)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report_json)
        print(f"\nReport also saved to {args.output}")


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        # Happens when output is piped into something like `head` that
        # closes the pipe early. Exit quietly instead of printing a
        # traceback - this is normal, expected behavior, not a bug.
        sys.exit(0)
    except KeyboardInterrupt:
        print("\nScan cancelled.", file=sys.stderr)
        sys.exit(130)
"""
Unit tests for scanner.py

These test the pure logic functions directly, without making real network
calls - that keeps tests fast and reliable (no internet needed to run them).

Run with:
    pip install pytest
    pytest tests/
"""

import sys
import os

# Allow running tests without installing the package
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scanner import (
    normalize_url,
    evaluate_headers,
    ScanReport,
    HeaderResult,
    PathResult,
)


def test_normalize_url_adds_https():
    assert normalize_url("example.com") == "https://example.com"


def test_normalize_url_keeps_existing_scheme():
    assert normalize_url("http://example.com") == "http://example.com"


def test_normalize_url_strips_trailing_slash():
    assert normalize_url("https://example.com/") == "https://example.com"


def test_evaluate_headers_all_present():
    fake_headers = {
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=31536000",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
    }
    results = evaluate_headers(fake_headers)
    assert all(r.present for r in results)
    assert len(results) == 6


def test_evaluate_headers_all_missing():
    results = evaluate_headers({})
    assert all(not r.present for r in results)


def test_evaluate_headers_partial():
    fake_headers = {"X-Frame-Options": "DENY"}
    results = evaluate_headers(fake_headers)
    present_names = [r.name for r in results if r.present]
    assert present_names == ["X-Frame-Options"]


def test_grade_is_a_when_everything_passes():
    headers = [HeaderResult(name="H1", present=True, reason="r")] * 6
    paths = [PathResult(path="/x", exposed=False)] * 9
    report = ScanReport(
        url="https://example.com",
        http_status=200,
        https_enforced=True,
        headers=headers,
        exposed_paths=paths,
    )
    assert report.overall_grade == "A"


def test_grade_is_f_when_everything_fails():
    headers = [HeaderResult(name="H1", present=False, reason="r")] * 6
    paths = [PathResult(path="/x", exposed=True)] * 9
    report = ScanReport(
        url="https://example.com",
        http_status=200,
        https_enforced=False,
        headers=headers,
        exposed_paths=paths,
    )
    assert report.overall_grade == "F"


def test_header_score_counts_correctly():
    headers = [
        HeaderResult(name="A", present=True, reason="r"),
        HeaderResult(name="B", present=False, reason="r"),
        HeaderResult(name="C", present=True, reason="r"),
    ]
    report = ScanReport(url="x", http_status=200, https_enforced=True, headers=headers)
    passed, total = report.header_score
    assert passed == 2
    assert total == 3
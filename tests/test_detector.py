"""
Unit Tests for PhishNet AI Detection Engine
Module: tests/test_detector.py
"""

import pytest
import detector


def test_valid_https_url():
    """Verify standard legitimate HTTPS URL parses cleanly with low risk."""
    res = detector.analyze_url("https://www.google.com")
    assert res["risk_level"] == "Low"
    assert res["risk_score"] < 30
    assert res["hostname"] == "www.google.com"
    assert res["is_ip"] is False


def test_valid_http_url():
    """Verify unencrypted HTTP triggers protocol warning signal."""
    res = detector.analyze_url("http://example.com")
    assert any(s["id"] == "unencrypted_http" for s in res["signals"])
    assert res["risk_score"] >= 12


def test_ip_address_hostname():
    """Verify IPv4 hostname is flagged with high severity."""
    res = detector.analyze_url("http://192.0.2.1/login")
    assert res["is_ip"] is True
    assert any(s["id"] == "ip_hostname" for s in res["signals"])
    assert res["risk_score"] >= 40


def test_at_symbol_spoofing():
    """Verify userinfo @ symbol spoofing is detected."""
    res = detector.analyze_url("https://example.com@evil.example")
    assert any(s["id"] == "at_symbol_spoofing" for s in res["signals"])
    assert res["risk_score"] >= 30


def test_punycode_homograph():
    """Verify IDN punycode 'xn--' domain is detected."""
    res = detector.analyze_url("https://xn--pypal-4ve.com/account/login")
    assert any(s["id"] == "punycode_homograph" for s in res["signals"])
    assert res["risk_score"] >= 25


def test_long_url():
    """Verify abnormally long URLs are flagged."""
    long_path = "a" * 150
    res = detector.analyze_url(f"https://example.com/{long_path}")
    assert any("url_length" in s["id"] for s in res["signals"])


def test_non_standard_port():
    """Verify non-standard web ports are flagged."""
    res = detector.analyze_url("http://example.com:2082/login")
    assert any(s["id"] == "non_standard_port" for s in res["signals"])


def test_brand_impersonation_subdomain():
    """Verify high-confidence brand in subdomain triggers brand impersonation."""
    res = detector.analyze_url("https://paypal.com.attacker-controlled.xyz/verify")
    assert any(s["id"] == "brand_impersonation" for s in res["signals"])
    assert res["risk_level"] == "High"
    assert res["risk_score"] >= 60


def test_unsupported_javascript_scheme():
    """Verify dangerous javascript: scheme is rejected with URLValidationError."""
    with pytest.raises(detector.URLValidationError):
        detector.analyze_url("javascript:alert(document.cookie)")


def test_unsupported_file_scheme():
    """Verify dangerous file: scheme is rejected with URLValidationError."""
    with pytest.raises(detector.URLValidationError):
        detector.analyze_url("file:///etc/passwd")


def test_unsupported_data_scheme():
    """Verify dangerous data: scheme is rejected with URLValidationError."""
    with pytest.raises(detector.URLValidationError):
        detector.analyze_url("data:text/html,<script>alert(1)</script>")


def test_empty_url():
    """Verify empty URL triggers validation error."""
    with pytest.raises(detector.URLValidationError):
        detector.analyze_url("")


def test_excessive_length_url():
    """Verify URLs exceeding 2048 chars are rejected."""
    oversized = "https://example.com/" + ("x" * 2100)
    with pytest.raises(detector.URLValidationError):
        detector.analyze_url(oversized)


def test_score_boundaries():
    """Verify risk scores never exceed 100 or drop below 0."""
    phish_res = detector.analyze_url("http://user:pass@192.168.1.1:8888/paypal.com.login-verify-account.xyz//auth?token=" + ("9" * 150))
    assert 0 <= phish_res["risk_score"] <= 100
    assert phish_res["risk_level"] == "High"

    clean_res = detector.analyze_url("https://example.com")
    assert 0 <= clean_res["risk_score"] <= 100
    assert clean_res["risk_level"] == "Low"


def test_feature_vector_extraction():
    """Verify numeric feature vector has 12 items."""
    vec = detector.extract_features_vector("https://example.org/test")
    assert len(vec) == 12
    assert all(isinstance(v, float) for v in vec)

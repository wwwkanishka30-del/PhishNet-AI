"""
Integration and Route Tests for PhishNet AI Web Application
Module: tests/test_routes.py
"""

import os
import pytest
from app import app
import database


@pytest.fixture
def client(tmp_path):
    """Sets up an isolated test database and test Flask client."""
    test_db_file = str(tmp_path / "test_phishnet.db")
    app.config["TESTING"] = True
    database.init_db(test_db_file)

    # Monkeypatch the database path
    orig_path = database.DEFAULT_DB_PATH
    database.DEFAULT_DB_PATH = test_db_file

    with app.test_client() as client:
        yield client

    database.DEFAULT_DB_PATH = orig_path


def test_index_redirects_to_dashboard(client):
    """Verify / redirects to /dashboard."""
    resp = client.get("/")
    assert resp.status_code == 302
    assert "/dashboard" in resp.headers["Location"]


def test_dashboard_renders(client):
    """Verify dashboard page loads successfully with 200 OK."""
    resp = client.get("/dashboard")
    assert resp.status_code == 200
    assert b"PhishNet AI" in resp.data
    assert b"Total URLs Analyzed" in resp.data


def test_scanner_renders(client):
    """Verify dedicated scanner page loads."""
    resp = client.get("/scanner")
    assert resp.status_code == 200
    assert b"Phishing URL Deep Inspection Scanner" in resp.data


def test_threat_intelligence_renders(client):
    """Verify threat intelligence page loads."""
    resp = client.get("/threat-intelligence")
    assert resp.status_code == 200
    assert b"IDN Homograph" in resp.data


def test_about_renders(client):
    """Verify about page loads."""
    resp = client.get("/about")
    assert resp.status_code == 200
    assert b"Dual-Engine Architecture" in resp.data


def test_api_stats_endpoint(client):
    """Verify /api/stats returns valid JSON data."""
    resp = client.get("/api/stats")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "total_scans" in data
    assert "high_risk_count" in data


def test_scan_form_submission(client):
    """Verify submitting URL via POST /scan works and redirects to results."""
    resp = client.post("/scan", data={"url": "https://paypal.com.attacker.xyz/login"})
    assert resp.status_code == 302
    assert "/results/" in resp.headers["Location"]

    # Follow redirect
    follow_resp = client.get(resp.headers["Location"])
    assert follow_resp.status_code == 200
    assert b"High Risk Evaluation" in follow_resp.data
    assert b"Brand Impersonation" in follow_resp.data


def test_scan_json_submission(client):
    """Verify submitting URL via AJAX JSON POST /scan returns structured JSON."""
    resp = client.post("/scan", json={"url": "https://example.org/test"}, headers={"X-Requested-With": "XMLHttpRequest"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    assert "scan_id" in data
    assert data["data"]["risk_level"] == "Low"


def test_scan_invalid_scheme(client):
    """Verify submitting javascript: URL returns bad request error."""
    resp = client.post("/scan", json={"url": "javascript:alert(1)"}, headers={"X-Requested-With": "XMLHttpRequest"})
    assert resp.status_code == 400
    data = resp.get_json()
    assert data["success"] is False
    assert "hazardous URL scheme" in data["error"]


def test_history_and_delete(client):
    """Verify scan appears in history, can be viewed and deleted."""
    # Submit a scan
    client.post("/scan", data={"url": "http://192.0.2.1/login"})

    # Check history
    h_resp = client.get("/history")
    assert h_resp.status_code == 200
    assert b"192.0.2.1" in h_resp.data

    # Search filter
    search_resp = client.get("/history?q=192.0.2.1")
    assert b"192.0.2.1" in search_resp.data

    # Filter with non-matching search
    no_match_resp = client.get("/history?q=nonexistent-host-999")
    assert b"No Scan Records Found" in no_match_resp.data

    # Clear all history
    clear_resp = client.post("/history/clear")
    assert clear_resp.status_code == 302
    after_clear = client.get("/history")
    assert b"Your scan history log is empty" in after_clear.data

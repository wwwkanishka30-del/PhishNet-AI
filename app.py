"""
PhishNet AI - Web Application Backend
Module: app.py

A Flask-based cybersecurity analysis platform for phishing URL detection.
Combines rule-based feature heuristics, machine learning inference,
and an interactive modern dashboard.
"""

import os
import time
from collections import defaultdict
from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)

import database
import detector
import ml_classifier

# Initialize Flask application
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "phishnet-ai-portfolio-secret-key-2026")
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # 16 KB max payload to prevent payload flooding

# Initialize database schema on startup
database.init_db()

# Basic in-memory rate limiter: max 40 scans per minute per client IP
_RATE_LIMIT_STORE = defaultdict(list)
RATE_LIMIT_WINDOW = 60  # seconds
MAX_REQUESTS_PER_WINDOW = 40


def is_rate_limited(client_ip: str) -> bool:
    """Checks whether the client IP has exceeded the allowed scan frequency."""
    now = time.time()
    timestamps = _RATE_LIMIT_STORE[client_ip]
    # Prune expired timestamps
    _RATE_LIMIT_STORE[client_ip] = [t for t in timestamps if now - t < RATE_LIMIT_WINDOW]
    if len(_RATE_LIMIT_STORE[client_ip]) >= MAX_REQUESTS_PER_WINDOW:
        return True
    _RATE_LIMIT_STORE[client_ip].append(now)
    return False


@app.after_request
def set_security_headers(response):
    """Enforces essential HTTP security headers."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# -------------------------------------------------------------
# Routes
# -------------------------------------------------------------

@app.route("/")
def index():
    """Landing route redirects directly to the main dashboard."""
    return redirect(url_for("dashboard"))


@app.route("/dashboard")
def dashboard():
    """Main dashboard displaying live stats, charts, recent scans, and quick scan."""
    stats = database.get_statistics()
    recent_scans = database.get_recent_scans(limit=6)
    return render_template("dashboard.html", stats=stats, recent_scans=recent_scans, active_page="dashboard")


@app.route("/scanner")
def scanner():
    """Dedicated scanner view for deep URL inspection."""
    return render_template("scanner.html", active_page="scanner")


@app.route("/scan", methods=["POST"])
def scan_url():
    """
    Handles URL submission from forms or AJAX requests.
    Validates, extracts features, queries ML model, persists to SQLite,
    and returns either HTML redirect or JSON response.
    """
    client_ip = request.remote_addr or "127.0.0.1"
    if is_rate_limited(client_ip):
        msg = "Scan rate limit reached. Please wait a minute before analyzing more links."
        if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"success": False, "error": msg}), 429
        flash(msg, "warning")
        return redirect(url_for("dashboard"))

    # Extract URL from JSON or form payload
    if request.is_json:
        data = request.get_json() or {}
        raw_url = data.get("url", "").strip()
    else:
        raw_url = request.form.get("url", "").strip()

    if not raw_url:
        msg = "Please enter a valid URL to analyze."
        if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"success": False, "error": msg}), 400
        flash(msg, "danger")
        return redirect(url_for("dashboard"))

    try:
        # Step 1: Run deterministic heuristic feature engine
        analysis = detector.analyze_url(raw_url)

        # Step 2: Run ML Random Forest prediction
        ml_result = ml_classifier.predict_url(analysis["normalized_url"])

        # Step 3: Persist scan record into SQLite
        scan_id = database.save_scan(analysis, ml_result)

        if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({
                "success": True,
                "scan_id": scan_id,
                "redirect_url": url_for("results", scan_id=scan_id),
                "data": {
                    "url": analysis["url"],
                    "risk_score": analysis["risk_score"],
                    "risk_level": analysis["risk_level"],
                    "signals_count": analysis["signals_count"],
                    "ml_prediction": ml_result.get("prediction", "N/A"),
                    "ml_confidence": ml_result.get("confidence", 0.0)
                }
            })

        return redirect(url_for("results", scan_id=scan_id))

    except detector.URLValidationError as ve:
        err_msg = str(ve)
        if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"success": False, "error": err_msg}), 400
        flash(err_msg, "danger")
        return redirect(url_for("dashboard"))
    except Exception as e:
        err_msg = f"Analysis error: {str(e)}"
        if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"success": False, "error": err_msg}), 500
        flash(err_msg, "danger")
        return redirect(url_for("dashboard"))


@app.route("/results/<int:scan_id>")
def results(scan_id: int):
    """Detailed analysis results page for a specific scan."""
    scan = database.get_scan_by_id(scan_id)
    if not scan:
        flash(f"Scan record #{scan_id} not found in database.", "warning")
        return redirect(url_for("dashboard"))

    return render_template("results.html", scan=scan, active_page="results")


@app.route("/history")
def history():
    """Scan history page with search, risk level filtering, and pagination."""
    search = request.args.get("q", "").strip() or None
    risk_filter = request.args.get("risk", "").strip() or None
    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1

    paginated_data = database.get_scans_paginated(
        search=search,
        risk_filter=risk_filter,
        page=page,
        per_page=10
    )

    return render_template(
        "history.html",
        history=paginated_data,
        search=search or "",
        risk_filter=risk_filter or "all",
        active_page="history"
    )


@app.route("/history/delete/<int:scan_id>", methods=["POST"])
def delete_scan_route(scan_id: int):
    """Deletes an individual scan entry."""
    success = database.delete_scan(scan_id)
    if success:
        flash(f"Scan record #{scan_id} successfully deleted.", "info")
    else:
        flash(f"Scan record #{scan_id} could not be deleted.", "danger")
    return redirect(url_for("history"))


@app.route("/history/clear", methods=["POST"])
def clear_history_route():
    """Clears all scan records from the database."""
    database.clear_all_scans()
    flash("All scan records have been cleared from database history.", "info")
    return redirect(url_for("history"))


@app.route("/threat-intelligence")
def threat_intelligence():
    """Educational Threat Intelligence knowledge base and evasion tactic breakdown."""
    return render_template("threat_intelligence.html", active_page="threat_intelligence")


@app.route("/about")
def about():
    """M.Tech CS Project scope, methodology, architecture, and disclaimers."""
    # Check if ML model metadata exists
    metadata_path = os.path.join(os.path.dirname(__file__), "models", "model_metadata.json")
    model_metadata = None
    if os.path.exists(metadata_path):
        import json
        try:
            with open(metadata_path, "r", encoding="utf-8") as f:
                model_metadata = json.load(f)
        except Exception:
            pass

    return render_template("about.html", model_metadata=model_metadata, active_page="about")


@app.route("/api/stats")
def api_stats():
    """Returns current system statistics in JSON for dynamic dashboard charts."""
    stats = database.get_statistics()
    return jsonify(stats)


# -------------------------------------------------------------
# Error Handlers
# -------------------------------------------------------------

@app.errorhandler(404)
def page_not_found(e):
    return render_template("base.html", error_title="404 - Page Not Found",
                           error_message="The requested resource does not exist on PhishNet AI.",
                           active_page="dashboard"), 404


@app.errorhandler(500)
def server_error(e):
    return render_template("base.html", error_title="500 - Server Error",
                           error_message="An internal server error occurred while processing the request.",
                           active_page="dashboard"), 500


if __name__ == "__main__":
    # Built-in Flask development server
    port = int(os.getenv("PORT", 5000))
    debug_mode = os.getenv("FLASK_DEBUG", "True").lower() in ("true", "1")
    print(f"\n=======================================================")
    print(f"  PhishNet AI - Phishing URL Detection Platform")
    print(f"  Running locally at: http://127.0.0.1:{port}")
    print(f"  Environment: Development (Built-in Flask WSGI)")
    print(f"=======================================================\n")
    app.run(host="127.0.0.1", port=port, debug=debug_mode)

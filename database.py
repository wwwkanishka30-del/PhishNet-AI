"""
PhishNet AI - SQLite Database Operations Module
Module: database.py

This module manages all persistent storage operations for URL scans,
risk evaluation histories, and analytical statistics. All queries use
parameterized statements to eliminate SQL injection vulnerabilities.
"""

import json
import os
import sqlite3
from datetime import datetime, timezone

DEFAULT_DB_PATH = os.path.join(os.path.dirname(__file__), "phishnet.db")


def get_db_connection(db_path: str = None) -> sqlite3.Connection:
    """Creates and returns a connection to the SQLite database."""
    target_path = db_path or os.getenv("PHISHNET_DB_PATH", DEFAULT_DB_PATH)
    conn = sqlite3.connect(target_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str = None) -> None:
    """Initializes the database schema if tables do not already exist."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL,
        normalized_url TEXT NOT NULL,
        hostname TEXT NOT NULL,
        risk_score INTEGER NOT NULL,
        risk_level TEXT NOT NULL,
        signals_count INTEGER NOT NULL,
        signals_json TEXT NOT NULL,
        components_json TEXT NOT NULL,
        recommendation TEXT NOT NULL,
        ml_prediction TEXT DEFAULT 'N/A',
        ml_confidence REAL DEFAULT 0.0,
        scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    cursor.execute("""
    CREATE INDEX IF NOT EXISTS idx_scans_scanned_at ON scans(scanned_at DESC);
    """)

    cursor.execute("""
    CREATE INDEX IF NOT EXISTS idx_scans_risk_level ON scans(risk_level);
    """)

    conn.commit()
    conn.close()


def save_scan(scan_data: dict, ml_result: dict = None, db_path: str = None) -> int:
    """
    Persists an analyzed scan record into the database.
    Returns the auto-generated primary key (ID).
    """
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    signals_json = json.dumps(scan_data.get("signals", []))
    components_json = json.dumps(scan_data.get("components", {}))

    ml_prediction = "N/A"
    ml_confidence = 0.0
    if ml_result:
        ml_prediction = ml_result.get("prediction", "N/A")
        ml_confidence = float(ml_result.get("confidence", 0.0))

    cursor.execute("""
        INSERT INTO scans (
            url, normalized_url, hostname, risk_score, risk_level,
            signals_count, signals_json, components_json,
            recommendation, ml_prediction, ml_confidence, scanned_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        scan_data.get("url", ""),
        scan_data.get("normalized_url", ""),
        scan_data.get("hostname", ""),
        int(scan_data.get("risk_score", 0)),
        scan_data.get("risk_level", "Low"),
        int(scan_data.get("signals_count", 0)),
        signals_json,
        components_json,
        scan_data.get("recommendation", ""),
        ml_prediction,
        ml_confidence,
        datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    ))

    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id


def get_scan_by_id(scan_id: int, db_path: str = None) -> dict | None:
    """Fetches a single scan record with parsed JSON data by its unique ID."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    record = dict(row)
    try:
        record["signals"] = json.loads(record.get("signals_json", "[]"))
    except Exception:
        record["signals"] = []

    try:
        record["components"] = json.loads(record.get("components_json", "{}"))
    except Exception:
        record["components"] = {}

    return record


def get_recent_scans(limit: int = 5, db_path: str = None) -> list[dict]:
    """Retrieves the most recent scans for dashboard display."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, url, normalized_url, hostname, risk_score, risk_level,
               signals_count, ml_prediction, scanned_at
        FROM scans
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))

    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_scans_paginated(search: str = None, risk_filter: str = None, page: int = 1, per_page: int = 10, db_path: str = None) -> dict:
    """
    Retrieves filtered and paginated scan history.
    """
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    query_clauses = []
    params = []

    if search:
        query_clauses.append("(url LIKE ? OR hostname LIKE ?)")
        search_pattern = f"%{search.strip()}%"
        params.extend([search_pattern, search_pattern])

    if risk_filter and risk_filter.lower() in ("low", "medium", "high"):
        query_clauses.append("LOWER(risk_level) = LOWER(?)")
        params.append(risk_filter)

    where_sql = f"WHERE {' AND '.join(query_clauses)}" if query_clauses else ""

    # Count total matching rows
    count_sql = f"SELECT COUNT(*) FROM scans {where_sql}"
    cursor.execute(count_sql, params)
    total_count = cursor.fetchone()[0]

    # Calculate offset
    offset = max(0, (page - 1) * per_page)
    total_pages = max(1, (total_count + per_page - 1) // per_page)

    data_sql = f"""
        SELECT id, url, normalized_url, hostname, risk_score, risk_level,
               signals_count, ml_prediction, ml_confidence, scanned_at
        FROM scans
        {where_sql}
        ORDER BY id DESC
        LIMIT ? OFFSET ?
    """
    query_params = list(params) + [per_page, offset]
    cursor.execute(data_sql, query_params)
    rows = cursor.fetchall()
    conn.close()

    return {
        "scans": [dict(r) for r in rows],
        "total_count": total_count,
        "page": page,
        "per_page": per_page,
        "total_pages": total_pages,
        "has_next": page < total_pages,
        "has_prev": page > 1
    }


def get_statistics(db_path: str = None) -> dict:
    """
    Computes real summary metrics across all scans stored in the database.
    Does not fabricate or randomize values.
    """
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM scans")
    total_scans = cursor.fetchone()[0]

    if total_scans == 0:
        conn.close()
        return {
            "total_scans": 0,
            "high_risk_count": 0,
            "medium_risk_count": 0,
            "low_risk_count": 0,
            "avg_risk_score": 0.0,
            "high_risk_pct": 0,
            "medium_risk_pct": 0,
            "low_risk_pct": 0,
            "recent_scores": []
        }

    cursor.execute("SELECT COUNT(*) FROM scans WHERE risk_level = 'High'")
    high_risk_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scans WHERE risk_level = 'Medium'")
    medium_risk_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scans WHERE risk_level = 'Low'")
    low_risk_count = cursor.fetchone()[0]

    cursor.execute("SELECT AVG(risk_score) FROM scans")
    avg_score_row = cursor.fetchone()[0]
    avg_score = round(float(avg_score_row or 0), 1)

    # Get recent scores for timeline display
    cursor.execute("SELECT id, risk_score, scanned_at FROM scans ORDER BY id DESC LIMIT 10")
    recent_scores = [dict(r) for r in cursor.fetchall()]
    recent_scores.reverse()

    conn.close()

    high_pct = round((high_risk_count / total_scans) * 100, 1)
    med_pct = round((medium_risk_count / total_scans) * 100, 1)
    low_pct = round((low_risk_count / total_scans) * 100, 1)

    return {
        "total_scans": total_scans,
        "high_risk_count": high_risk_count,
        "medium_risk_count": medium_risk_count,
        "low_risk_count": low_risk_count,
        "avg_risk_score": avg_score,
        "high_risk_pct": high_pct,
        "medium_risk_pct": med_pct,
        "low_risk_pct": low_pct,
        "recent_scores": recent_scores
    }


def delete_scan(scan_id: int, db_path: str = None) -> bool:
    """Deletes a single scan by ID."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return deleted


def clear_all_scans(db_path: str = None) -> bool:
    """Clears all records from the scans table."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scans")
    conn.commit()
    conn.close()
    return True

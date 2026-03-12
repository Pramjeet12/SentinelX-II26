"""SQLite database models and CRUD operations for Credential Leak Monitor."""

import sqlite3
import hashlib
import time
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
import config


def get_db() -> sqlite3.Connection:
    """Get a database connection with row factory."""
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """Create all tables if they don't exist."""
    conn = get_db()
    conn.executescript("""
        -- Company employees we are monitoring
        CREATE TABLE IF NOT EXISTS employees (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            email           TEXT UNIQUE NOT NULL,
            password_sha1   TEXT NOT NULL,         -- SHA-1 hash (for k-anonymity check)
            password_sha256 TEXT NOT NULL,          -- SHA-256 hash (for exact matching)
            department      TEXT DEFAULT 'General',
            full_name       TEXT DEFAULT '',
            added_at        REAL NOT NULL
        );

        -- Simulated breach database (like a local HIBP / DeHashed)
        -- In production this would be the real HIBP API
        CREATE TABLE IF NOT EXISTS leaked_credentials (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            email           TEXT NOT NULL,
            password_hash   TEXT NOT NULL,          -- SHA-1 hash of leaked password
            breach_name     TEXT NOT NULL,           -- e.g. "LinkedIn2021", "AdobeHack"
            breach_date     TEXT NOT NULL,           -- YYYY-MM-DD
            data_types      TEXT DEFAULT 'email,password',  -- what was leaked
            source          TEXT DEFAULT 'breach_db'         -- breach_db / paste / github
        );

        -- Simulated GitHub code leaks
        CREATE TABLE IF NOT EXISTS github_leaks (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            repo_name       TEXT NOT NULL,
            file_path       TEXT NOT NULL,
            matched_keyword TEXT NOT NULL,           -- password, api_key, token, etc.
            matched_domain  TEXT NOT NULL,           -- the org domain found
            snippet         TEXT NOT NULL,           -- code snippet containing the leak
            found_date      TEXT NOT NULL
        );

        -- Simulated paste site leaks
        CREATE TABLE IF NOT EXISTS paste_leaks (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            paste_url       TEXT NOT NULL,
            paste_title     TEXT DEFAULT '',
            matched_domain  TEXT NOT NULL,
            snippet         TEXT NOT NULL,
            paste_date      TEXT NOT NULL
        );

        -- Scan results history
        CREATE TABLE IF NOT EXISTS scan_results (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id     INTEGER,
            scan_type       TEXT NOT NULL,           -- breach / password / github / paste
            source          TEXT NOT NULL,           -- breach name, repo name, paste URL
            finding         TEXT NOT NULL,           -- description of what was found
            severity        TEXT NOT NULL,           -- CRITICAL / HIGH / MEDIUM / LOW
            scanned_at      REAL NOT NULL,
            FOREIGN KEY (employee_id) REFERENCES employees(id)
        );

        -- Track alerts to prevent duplicate notifications
        CREATE TABLE IF NOT EXISTS alerts_sent (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_result_id  INTEGER UNIQUE NOT NULL,
            alerted_at      REAL NOT NULL,
            FOREIGN KEY (scan_result_id) REFERENCES scan_results(id)
        );
    """)
    conn.commit()
    conn.close()


# ── Employee CRUD ──

def add_employee(email: str, password: str, department: str = "General", full_name: str = ""):
    """Add an employee (stores only hashes, never plaintext)."""
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    sha256 = hashlib.sha256(password.encode()).hexdigest().upper()
    conn = get_db()
    try:
        conn.execute(
            "INSERT OR IGNORE INTO employees (email, password_sha1, password_sha256, department, full_name, added_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (email.lower(), sha1, sha256, department, full_name, time.time()),
        )
        conn.commit()
    finally:
        conn.close()


def get_all_employees() -> list[dict]:
    """Return all employees."""
    conn = get_db()
    rows = conn.execute("SELECT * FROM employees ORDER BY email").fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ── Leaked Credentials CRUD ──

def add_leaked_credential(email: str, password: str, breach_name: str, breach_date: str,
                          data_types: str = "email,password", source: str = "breach_db"):
    """Add a leaked credential to the simulated breach DB."""
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    conn = get_db()
    conn.execute(
        "INSERT INTO leaked_credentials (email, password_hash, breach_name, breach_date, data_types, source) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (email.lower(), sha1, breach_name, breach_date, data_types, source),
    )
    conn.commit()
    conn.close()


def get_leaked_by_email(email: str) -> list[dict]:
    """Find all breaches containing a specific email."""
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM leaked_credentials WHERE email = ?", (email.lower(),)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_leaked_by_domain(domain: str) -> list[dict]:
    """Find all breaches containing emails from a domain."""
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM leaked_credentials WHERE email LIKE ?", (f"%@{domain.lower()}",)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_leaked_by_sha1_prefix(sha1_prefix: str) -> list[dict]:
    """k-Anonymity: return all leaked hashes starting with the given 5-char prefix."""
    conn = get_db()
    rows = conn.execute(
        "SELECT password_hash, breach_name FROM leaked_credentials WHERE password_hash LIKE ?",
        (sha1_prefix.upper() + "%",),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ── GitHub Leaks CRUD ──

def add_github_leak(repo_name: str, file_path: str, keyword: str, domain: str, snippet: str, found_date: str):
    conn = get_db()
    conn.execute(
        "INSERT INTO github_leaks (repo_name, file_path, matched_keyword, matched_domain, snippet, found_date) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (repo_name, file_path, keyword, domain, snippet, found_date),
    )
    conn.commit()
    conn.close()


def get_github_leaks_by_domain(domain: str) -> list[dict]:
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM github_leaks WHERE matched_domain = ?", (domain.lower(),)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ── Paste Leaks CRUD ──

def add_paste_leak(paste_url: str, title: str, domain: str, snippet: str, paste_date: str):
    conn = get_db()
    conn.execute(
        "INSERT INTO paste_leaks (paste_url, paste_title, matched_domain, snippet, paste_date) "
        "VALUES (?, ?, ?, ?, ?)",
        (paste_url, title, domain, snippet, paste_date),
    )
    conn.commit()
    conn.close()


def get_paste_leaks_by_domain(domain: str) -> list[dict]:
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM paste_leaks WHERE matched_domain = ?", (domain.lower(),)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ── Scan Results ──

def add_scan_result(employee_id: int | None, scan_type: str, source: str,
                    finding: str, severity: str) -> int:
    """Record a scan finding. Returns the scan_result ID."""
    conn = get_db()
    cursor = conn.execute(
        "INSERT INTO scan_results (employee_id, scan_type, source, finding, severity, scanned_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (employee_id, scan_type, source, finding, severity, time.time()),
    )
    conn.commit()
    result_id = cursor.lastrowid
    conn.close()
    return result_id


def is_already_alerted(scan_type: str, source: str, finding: str) -> bool:
    """Check if we've already alerted for this exact finding (dedup)."""
    conn = get_db()
    row = conn.execute(
        """SELECT sr.id FROM scan_results sr
           JOIN alerts_sent a ON a.scan_result_id = sr.id
           WHERE sr.scan_type = ? AND sr.source = ? AND sr.finding = ?""",
        (scan_type, source, finding),
    ).fetchone()
    conn.close()
    return row is not None


def mark_alerted(scan_result_id: int):
    """Record that an alert was sent for this scan result."""
    conn = get_db()
    conn.execute(
        "INSERT OR IGNORE INTO alerts_sent (scan_result_id, alerted_at) VALUES (?, ?)",
        (scan_result_id, time.time()),
    )
    conn.commit()
    conn.close()


def get_recent_scan_results(limit: int = 50) -> list[dict]:
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM scan_results ORDER BY scanned_at DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

"""
SQLite database helpers.
Manages:
  - alerts table  (IDS incidents)
  - admin_users table (auth credentials)
"""
import sqlite3
import os
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
DB_PATH  = os.path.join(BASE_DIR, "alerts.db")


# ── Schema init ────────────────────────────────────────────────────────────────

def init_db():
    conn   = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Existing alerts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id     TEXT,
            prompt_snippet TEXT,
            attack_type    TEXT,
            severity       TEXT,
            confidence     REAL,
            timestamp      DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Admin users table  (hashed passwords only — never plain-text)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admin_users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            email         TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role          TEXT DEFAULT "admin",
            created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    conn.commit()
    conn.close()

    # Seed a default admin account (only if none exists)
    _seed_default_admin()


def _seed_default_admin():
    """
    Create the default admin account on first run.
    Credentials:  username=admin   password=admin123
    Change these immediately in production!
    """
    from app.core.security import hash_password

    conn   = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM admin_users WHERE username = ?", ("admin",))
    if cursor.fetchone() is None:
        cursor.execute(
            "INSERT INTO admin_users (username, email, password_hash) VALUES (?, ?, ?)",
            ("admin", "admin@ids.local", hash_password("admin123"))
        )
        conn.commit()
        print("[AUTH] Default admin account seeded — username: admin  password: admin123")
    conn.close()


# ── Admin user helpers ─────────────────────────────────────────────────────────

def get_admin_user(username: str) -> dict | None:
    """Return admin user dict or None if not found."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username, email, password_hash, role FROM admin_users WHERE username = ?",
        (username,)
    )
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_admin_by_email(email: str) -> dict | None:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username, email, password_hash, role FROM admin_users WHERE email = ?",
        (email,)
    )
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


# ── Alert helpers ──────────────────────────────────────────────────────────────

def log_alert(session_id: str, prompt_snippet: str, attack_type: str,
              severity: str, confidence: float):
    conn   = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        '''INSERT INTO alerts
           (session_id, prompt_snippet, attack_type, severity, confidence, timestamp)
           VALUES (?, ?, ?, ?, ?, ?)''',
        (session_id, prompt_snippet, attack_type, severity, confidence,
         datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()


def get_latest_alerts(limit: int = 50) -> list[dict]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
    )
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

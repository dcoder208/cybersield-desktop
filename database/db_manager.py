import sqlite3
from datetime import datetime
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "database", "history.db")


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_type TEXT,
            target TEXT,
            verdict TEXT,
            risk_score INTEGER,
            timestamp TEXT
        )
    """)

    conn.commit()
    conn.close()


def save_scan(scan_type, target, verdict, risk_score):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    c.execute("""
        INSERT INTO scan_history 
        (scan_type, target, verdict, risk_score, timestamp)
        VALUES (?, ?, ?, ?, ?)
    """, (scan_type, target, verdict, risk_score, timestamp))

    conn.commit()
    conn.close()


def get_history(limit=20):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("""
        SELECT scan_type, target, verdict, risk_score, timestamp
        FROM scan_history
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))

    rows = c.fetchall()
    conn.close()

    return rows
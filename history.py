
import sqlite3
from pathlib import Path

import pandas as pd


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "data" / "analysis_history.db"


def initialize_history():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(DB_PATH) as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS analysis_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                normalized_url TEXT,
                status TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                source TEXT,
                analyzed_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)


def save_analysis(result):
    initialize_history()

    with sqlite3.connect(DB_PATH) as connection:
        connection.execute("""
            INSERT INTO analysis_history (
                url,
                normalized_url,
                status,
                risk_score,
                source
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            result.get("url", ""),
            result.get("normalized_url", ""),
            result.get("status", "미확인"),
            result.get("risk_score", 0),
            result.get("source", "")
        ))


def get_history(limit=100):
    initialize_history()

    with sqlite3.connect(DB_PATH) as connection:
        history = pd.read_sql_query("""
            SELECT
                id,
                url,
                normalized_url,
                status,
                risk_score,
                source,
                analyzed_at
            FROM analysis_history
            ORDER BY id DESC
            LIMIT ?
        """, connection, params=(limit,))

    return history


def get_history_summary():
    history = get_history(limit=1000000)

    return {
        "total": len(history),
        "malicious": int((history["status"] == "악성").sum()),
        "suspicious": int((history["status"] == "의심").sum()),
        "normal_candidate": int((history["status"] == "정상 후보").sum()),
        "unknown": int((history["status"] == "미확인").sum())
    }

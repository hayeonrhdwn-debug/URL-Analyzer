import sqlite3
from pathlib import Path

import pandas as pd


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "data" / "analysis_history.db"


def initialize_history():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(DB_PATH, timeout=30) as connection:
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

    with sqlite3.connect(DB_PATH, timeout=30) as connection:
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
    """
    최신 기록부터 반환합니다.
    limit=None이면 전체 기록을 반환합니다.
    """
    initialize_history()

    query = """
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
    """

    params = ()

    if limit is not None:
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise ValueError("limit는 0 이상의 정수 또는 None이어야 합니다.")

        if limit < 0:
            raise ValueError("limit는 0 이상이어야 합니다.")

        query += " LIMIT ?"
        params = (limit,)

    with sqlite3.connect(DB_PATH, timeout=30) as connection:
        return pd.read_sql_query(query, connection, params=params)


def get_history_summary():
    """
    전체 데이터를 메모리에 불러오지 않고 DB에서 직접 집계합니다.
    기존 반환 키를 유지합니다.
    """
    initialize_history()

    with sqlite3.connect(DB_PATH, timeout=30) as connection:
        row = connection.execute("""
            SELECT
                COUNT(*),
                COALESCE(SUM(CASE WHEN status = '악성'
                    THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN status = '의심'
                    THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN status = '정상 후보'
                    THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN status = '미확인'
                    THEN 1 ELSE 0 END), 0)
            FROM analysis_history
        """).fetchone()

    keys = [
        "total",
        "malicious",
        "suspicious",
        "normal_candidate",
        "unknown",
    ]

    return dict(zip(keys, map(int, row)))

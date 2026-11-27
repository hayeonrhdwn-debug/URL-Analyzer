import sqlite3
from contextlib import closing
from pathlib import Path

import pandas as pd


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "data" / "analysis_history.db"


def initialize_history():
    """기존 DB를 유지하면서 필요한 테이블을 생성합니다."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    with closing(sqlite3.connect(DB_PATH, timeout=30)) as connection, connection:
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
    """분석 결과를 저장합니다."""
    initialize_history()

    with closing(sqlite3.connect(DB_PATH, timeout=30)) as connection, connection:
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
    최신 저장 순으로 분석 기록을 반환합니다.

    limit=100: 최근 최대 100건
    limit=None: 전체 기록
    limit=0: 컬럼 구조를 유지한 빈 DataFrame
    음수, 정수가 아닌 값, bool: ValueError
    """
    if limit is not None and (
        isinstance(limit, bool)
        or not isinstance(limit, int)
        or limit < 0
    ):
        raise ValueError("limit는 0 이상의 정수 또는 None이어야 합니다.")

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
        query += " LIMIT ?"
        params = (limit,)

    with closing(sqlite3.connect(DB_PATH, timeout=30)) as connection, connection:
        history = pd.read_sql_query(
            query,
            connection,
            params=params,
        )

    return history


def get_history_summary():
    """
    전체 기록과 판정별 건수를 SQLite에서 직접 집계합니다.
    기존에 사용하던 반환 키를 유지합니다.
    """
    initialize_history()

    with closing(sqlite3.connect(DB_PATH, timeout=30)) as connection, connection:
        row = connection.execute("""
            SELECT
                COUNT(*) AS total,
                COALESCE(SUM(
                    CASE WHEN status = '악성' THEN 1 ELSE 0 END
                ), 0) AS malicious,
                COALESCE(SUM(
                    CASE WHEN status = '의심' THEN 1 ELSE 0 END
                ), 0) AS suspicious,
                COALESCE(SUM(
                    CASE WHEN status = '정상 후보' THEN 1 ELSE 0 END
                ), 0) AS normal_candidate,
                COALESCE(SUM(
                    CASE WHEN status = '미확인' THEN 1 ELSE 0 END
                ), 0) AS unknown
            FROM analysis_history
        """).fetchone()

    return {
        "total": int(row[0]),
        "malicious": int(row[1]),
        "suspicious": int(row[2]),
        "normal_candidate": int(row[3]),
        "unknown": int(row[4]),
    }

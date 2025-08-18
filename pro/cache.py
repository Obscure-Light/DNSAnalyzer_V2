"""Simple persistent cache for DNS query results using SQLite."""

from __future__ import annotations

import json
import sqlite3
from threading import Lock
from typing import List, Optional, Tuple


# Path to the SQLite database. When ``None`` caching is disabled.
DB_PATH: Optional[str] = None

_lock = Lock()


def _ensure_db(path: str) -> sqlite3.Connection:
    """Return a connection to the cache database, creating tables if needed."""

    conn = sqlite3.connect(path)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS cache (
            qname TEXT NOT NULL,
            rtype TEXT NOT NULL,
            ok INTEGER NOT NULL,
            data TEXT NOT NULL,
            error TEXT,
            PRIMARY KEY (qname, rtype)
        )
        """
    )
    return conn


def get_cache(qname: str, rtype: str) -> Optional[Tuple[bool, List[str], str]]:
    """Return cached result for *(qname, rtype)* or ``None``."""

    if not DB_PATH:
        return None

    with _lock:
        conn = _ensure_db(DB_PATH)
        cur = conn.execute(
            "SELECT ok, data, error FROM cache WHERE qname=? AND rtype=?",
            (qname, rtype),
        )
        row = cur.fetchone()
        conn.close()

    if row:
        ok, values_json, error = row
        values = json.loads(values_json)
        return bool(ok), values, error
    return None


def set_cache(qname: str, rtype: str, result: Tuple[bool, List[str], str]) -> None:
    """Store *result* for *(qname, rtype)* in the cache if enabled."""

    if not DB_PATH:
        return

    ok, values, error = result

    with _lock:
        conn = _ensure_db(DB_PATH)
        conn.execute(
            "REPLACE INTO cache (qname, rtype, ok, data, error) VALUES (?,?,?,?,?)",
            (qname, rtype, int(ok), json.dumps(values), error),
        )
        conn.commit()
        conn.close()


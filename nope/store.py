"""SQLite storage shared by the daemon (writer) and the CLI (reader)"""

import sqlite3
import time

from .events import Event

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id      INTEGER PRIMARY KEY,
    ts      REAL NOT NULL,
    ip      TEXT NOT NULL,
    port    INTEGER NOT NULL,
    service TEXT NOT NULL,
    kind    TEXT NOT NULL,
    payload TEXT NOT NULL,
    score   REAL NOT NULL,
    action  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scores (
    ip      TEXT PRIMARY KEY,
    score   REAL NOT NULL,
    updated REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS blocks (
    ip         TEXT PRIMARY KEY,
    blocked_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    reason     TEXT NOT NULL
);
"""


class Store:
    def __init__(self, path="nope.db"):
        self.db = sqlite3.connect(path, timeout=10, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        if path != ":memory:":
            self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(SCHEMA)
        self.db.commit()

    # events
    def add_event(self, event: Event, score: float, action: str):
        self.db.execute(
            "INSERT INTO events (ts, ip, port, service, kind, payload, score, action) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (event.ts, event.ip, event.port, event.service, event.kind,
             event.payload, score, action),
        )
        self.db.commit()

    def recent_events(self, n=15):
        return self.db.execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT ?", (n,)
        ).fetchall()

    # scores
    def get_score(self, ip):
        return self.db.execute(
            "SELECT score, updated FROM scores WHERE ip = ?", (ip,)
        ).fetchone()

    def set_score(self, ip, score, ts):
        self.db.execute(
            "INSERT INTO scores (ip, score, updated) VALUES (?, ?, ?) "
            "ON CONFLICT(ip) DO UPDATE SET score = excluded.score, updated = excluded.updated",
            (ip, score, ts),
        )
        self.db.commit()

    def delete_score(self, ip):
        self.db.execute("DELETE FROM scores WHERE ip = ?", (ip,))
        self.db.commit()

    def list_scores(self, limit=50):
        return self.db.execute(
            "SELECT ip, score, updated FROM scores ORDER BY updated DESC LIMIT ?", (limit,)
        ).fetchall()

    # blocks
    def add_block(self, ip, blocked_at, expires_at, reason):
        self.db.execute(
            "INSERT OR REPLACE INTO blocks (ip, blocked_at, expires_at, reason) "
            "VALUES (?, ?, ?, ?)",
            (ip, blocked_at, expires_at, reason),
        )
        self.db.commit()

    def remove_block(self, ip):
        self.db.execute("DELETE FROM blocks WHERE ip = ?", (ip,))
        self.db.commit()

    def clear_blocks(self):
        self.db.execute("DELETE FROM blocks")
        self.db.commit()

    def active_blocks(self, now=None):
        now = time.time() if now is None else now
        return self.db.execute(
            "SELECT * FROM blocks WHERE expires_at > ? ORDER BY blocked_at DESC", (now,)
        ).fetchall()

    def is_blocked(self, ip, now=None):
        now = time.time() if now is None else now
        row = self.db.execute(
            "SELECT 1 FROM blocks WHERE ip = ? AND expires_at > ?", (ip, now)
        ).fetchone()
        return row is not None

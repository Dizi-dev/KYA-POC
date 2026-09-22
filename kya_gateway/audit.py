"""Append-only audit log in SQLite. Each entry stores the SHA-256 of the previous entry,
so editing or deleting any row breaks the chain and `verify_chain()` reports where."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time

GENESIS = "0" * 64
FIELDS = ["ts", "method", "path", "outcome", "reason", "operator", "keyid", "tag",
          "decision", "rule"]


class AuditLog:
    def __init__(self, path: str = "kya_audit.db"):
        self._lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("""CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL, method TEXT, path TEXT, outcome TEXT, reason TEXT, operator TEXT,
            keyid TEXT, tag TEXT, decision TEXT, rule TEXT, prev_hash TEXT, hash TEXT)""")
        self.db.commit()

    @staticmethod
    def _hash(prev: str, entry: dict) -> str:
        payload = json.dumps({k: entry.get(k) for k in FIELDS}, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256((prev + payload).encode()).hexdigest()

    def append(self, **entry) -> str:
        entry.setdefault("ts", round(time.time(), 3))
        with self._lock:
            row = self.db.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
            prev = row[0] if row else GENESIS
            h = self._hash(prev, entry)
            self.db.execute(
                f"INSERT INTO audit ({','.join(FIELDS)}, prev_hash, hash) VALUES ({','.join('?' * (len(FIELDS) + 2))})",
                [entry.get(k) for k in FIELDS] + [prev, h])
            self.db.commit()
            return h

    def rows(self, limit: int = 200) -> list[dict]:
        cur = self.db.execute(f"SELECT id,{','.join(FIELDS)},prev_hash,hash FROM audit ORDER BY id DESC LIMIT ?", (limit,))
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]

    def verify_chain(self) -> tuple[bool, str]:
        prev = GENESIS
        cur = self.db.execute(f"SELECT id,{','.join(FIELDS)},prev_hash,hash FROM audit ORDER BY id ASC")
        cols = [c[0] for c in cur.description]
        n = 0
        for r in cur:
            e = dict(zip(cols, r))
            if e["prev_hash"] != prev or self._hash(prev, e) != e["hash"]:
                return False, f"chain broken at entry {e['id']}"
            prev, n = e["hash"], n + 1
        return True, f"{n} entries, chain intact"

    def export_json(self) -> str:
        return json.dumps(list(reversed(self.rows(limit=10**9))), indent=2)

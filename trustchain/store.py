"""Local operational store (SQLite): detailed events + a ring of recent telemetry.

Only a SHA-256 of each event goes on-chain; the detail lives here. The integrity checker
compares the two, so editing this database is detectable.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from typing import Any

from .crypto import canonical, sha256_hex

HASHED_FIELDS = ["event_id", "ts", "device_id", "event_type", "severity", "risk_score", "source",
                 "fingerprint", "trust_after", "action"]


def event_hash(rec: dict[str, Any]) -> str:
    return sha256_hex(canonical({k: rec.get(k) for k in HASHED_FIELDS}))


class LocalStore:
    def __init__(self, path: str = ":memory:"):
        if path != ":memory:":
            os.makedirs(os.path.dirname(path), exist_ok=True)
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.RLock()
        self._db.execute(
            """CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY, ts REAL, device_id TEXT, event_type TEXT, severity TEXT,
                risk_score REAL, source TEXT, fingerprint TEXT, trust_after REAL, action TEXT,
                event_hash TEXT, chain_block INTEGER, details TEXT)"""
        )
        self._db.execute("CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v INTEGER)")
        self._db.commit()

    def next_event_id(self, floor: int = 0) -> str:
        """Monotonic event identifiers.

        Never derived from the row count: an intruder (or the tamper demo) deleting a record would make the
        count drop, the next id would collide with an existing one, and every new event would then fail to be
        recorded -- deleting one log entry would blind the IDS. `floor` lets the caller pass the number of events
        already on the ledger so ids also stay unique if this local store was lost or reset.
        """
        with self._lock:
            row = self._db.execute("SELECT v FROM meta WHERE k='event_seq'").fetchone()
            seen = self._db.execute("SELECT COALESCE(MAX(CAST(SUBSTR(event_id, 5) AS INTEGER)), 0) FROM events").fetchone()[0]
            n = max(row[0] if row else 0, int(seen), int(floor)) + 1
            self._db.execute("INSERT OR REPLACE INTO meta (k, v) VALUES ('event_seq', ?)", (n,))
            self._db.commit()
            return f"EVT-{n:06d}"

    def save_event(self, rec: dict[str, Any], details: dict[str, Any]) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (rec["event_id"], rec["ts"], rec["device_id"], rec["event_type"], rec["severity"],
                 rec["risk_score"], rec.get("source"), rec["fingerprint"], rec.get("trust_after"),
                 rec.get("action"), rec["event_hash"], None, json.dumps(details, default=str)),
            )
            self._db.commit()

    def set_chain_block(self, event_id: str, block: int) -> None:
        with self._lock:
            self._db.execute("UPDATE events SET chain_block=? WHERE event_id=?", (block, event_id))
            self._db.commit()

    def _row(self, r) -> dict[str, Any]:
        cols = ["event_id", "ts", "device_id", "event_type", "severity", "risk_score", "source", "fingerprint",
                "trust_after", "action", "event_hash", "chain_block", "details"]
        d = dict(zip(cols, r))
        d["details"] = json.loads(d["details"]) if d["details"] else {}
        return d

    def get_event(self, event_id: str) -> dict[str, Any] | None:
        with self._lock:
            r = self._db.execute("SELECT * FROM events WHERE event_id=?", (event_id,)).fetchone()
        return self._row(r) if r else None

    def list_events(self, limit: int = 100, device_id: str | None = None, severity: str | None = None) -> list[dict[str, Any]]:
        sql, args = "SELECT * FROM events", []
        cond = []
        if device_id:
            cond.append("device_id=?"); args.append(device_id)
        if severity:
            cond.append("severity=?"); args.append(severity)
        if cond:
            sql += " WHERE " + " AND ".join(cond)
        sql += " ORDER BY ts DESC, event_id DESC LIMIT ?"
        args.append(limit)
        with self._lock:
            rows = self._db.execute(sql, args).fetchall()
        return [self._row(r) for r in rows]

    def count(self) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    # ---- used by the tamper simulation (an attacker editing the DB) --------------------
    def raw_update(self, event_id: str, column: str, value: Any) -> bool:
        if column not in {"severity", "risk_score", "event_type", "action", "source", "trust_after"}:
            raise ValueError("column not editable")
        with self._lock:
            cur = self._db.execute(f"UPDATE events SET {column}=? WHERE event_id=?", (value, event_id))
            self._db.commit()
            return cur.rowcount > 0

    def raw_delete(self, event_id: str) -> bool:
        with self._lock:
            cur = self._db.execute("DELETE FROM events WHERE event_id=?", (event_id,))
            self._db.commit()
            return cur.rowcount > 0

    def recompute_hash(self, event_id: str) -> str | None:
        r = self.get_event(event_id)
        return event_hash(r) if r else None

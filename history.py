"""Transactional SQLite incident history with analyst status audit and revision guards."""

from __future__ import annotations
from contextlib import contextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Iterator

STATUSES = ("Open", "Investigating", "Contained", "Resolved", "False Positive")


class IncidentHistory:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        with self.connection() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS incidents (
                  id TEXT PRIMARY KEY, created_at TEXT NOT NULL, status TEXT NOT NULL,
                  report TEXT NOT NULL, revision INTEGER NOT NULL DEFAULT 1);
                CREATE TABLE IF NOT EXISTS audit (
                  id INTEGER PRIMARY KEY, incident_id TEXT NOT NULL, timestamp TEXT NOT NULL,
                  old_status TEXT NOT NULL, new_status TEXT NOT NULL, note TEXT NOT NULL);
            """)
        try:
            self.path.chmod(0o600)
        except OSError:
            pass

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def save(self, report: dict) -> dict:
        """Insert once; duplicate investigations preserve analyst decisions and prior report."""
        with self.connection() as db:
            db.execute(
                "INSERT OR IGNORE INTO incidents (id,created_at,status,report) VALUES (?,?,?,?)",
                (report["incident_id"], report["generated_at"], "Open", json.dumps(report, allow_nan=False)),
            )
        return self.get(report["incident_id"])

    def get(self, incident_id: str) -> dict:
        with self.connection() as db:
            row = db.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        if row is None:
            raise KeyError("Incident does not exist.")
        return {**json.loads(row["report"]), "status": row["status"], "revision": row["revision"]}

    def list(self, limit: int = 1000) -> list[dict]:
        with self.connection() as db:
            rows = db.execute(
                "SELECT id FROM incidents ORDER BY created_at DESC LIMIT ?", (max(1, min(limit, 10000)),)
            ).fetchall()
        return [self.get(row["id"]) for row in rows]

    def update_status(self, incident_id: str, status: str, note: str, expected_revision: int) -> None:
        if status not in STATUSES or not note.strip():
            raise ValueError("Select a valid status and provide an audit note.")
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT status,revision FROM incidents WHERE id=?", (incident_id,)).fetchone()
            if row is None:
                raise KeyError("Incident does not exist.")
            if row["revision"] != expected_revision:
                raise ValueError("Incident changed in another session; refresh before updating.")
            db.execute("UPDATE incidents SET status=?,revision=revision+1 WHERE id=?", (status, incident_id))
            db.execute(
                "INSERT INTO audit (incident_id,timestamp,old_status,new_status,note) VALUES (?,?,?,?,?)",
                (incident_id, datetime.now(timezone.utc).isoformat(), row["status"], status, note[:2000]),
            )

    def audit(self, incident_id: str) -> list[dict]:
        with self.connection() as db:
            return [
                dict(row) for row in db.execute("SELECT * FROM audit WHERE incident_id=? ORDER BY id", (incident_id,))
            ]

"""SQLite-backed scan history and deterministic drift classification."""
import json
import sqlite3
from datetime import datetime, timezone

from .reporting import finding_to_dict


class ScanHistory:
    def __init__(self, path="cloudguard_history.db"):
        self.path = str(path)
        with sqlite3.connect(self.path) as db:
            db.execute("CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY, created_at TEXT NOT NULL, payload TEXT NOT NULL)")

    def record(self, findings, score):
        payload = {"score": score, "findings": [finding_to_dict(f) for f in findings]}
        with sqlite3.connect(self.path) as db:
            cursor = db.execute("INSERT INTO scans(created_at, payload) VALUES (?, ?)",
                                (datetime.now(timezone.utc).isoformat(timespec="seconds"), json.dumps(payload, sort_keys=True)))
            return cursor.lastrowid

    def latest(self):
        with sqlite3.connect(self.path) as db:
            row = db.execute("SELECT id, created_at, payload FROM scans ORDER BY id DESC LIMIT 1").fetchone()
        if not row:
            return None
        return {"id": row[0], "created_at": row[1], **json.loads(row[2])}

    def previous(self):
        with sqlite3.connect(self.path) as db:
            rows = db.execute("SELECT id, created_at, payload FROM scans ORDER BY id DESC LIMIT 2").fetchall()
        if len(rows) < 2:
            return None
        row = rows[1]
        return {"id": row[0], "created_at": row[1], **json.loads(row[2])}

    def diff_latest(self):
        current, previous = self.latest(), self.previous()
        if not current or not previous:
            return {"new": [], "fixed": [], "recurring": [], "changed_to_unknown": []}
        old = {(f["rule_id"], f["resource"]): f for f in previous["findings"]}
        new = {(f["rule_id"], f["resource"]): f for f in current["findings"]}
        return {
            "new": [key for key, finding in new.items() if key not in old and finding["status"] == "FAIL"],
            "fixed": [key for key, finding in new.items() if old.get(key, {}).get("status") == "FAIL" and finding["status"] == "PASS"],
            "recurring": [key for key, finding in new.items() if old.get(key, {}).get("status") == "FAIL" and finding["status"] == "FAIL"],
            "changed_to_unknown": [key for key, finding in new.items() if old.get(key, {}).get("status") != "UNKNOWN" and finding["status"] == "UNKNOWN"],
        }

    def trend(self):
        with sqlite3.connect(self.path) as db:
            rows = db.execute("SELECT created_at, json_extract(payload, '$.score.risk_score') FROM scans ORDER BY id").fetchall()
        return [{"created_at": created_at, "risk_score": risk_score} for created_at, risk_score in rows]

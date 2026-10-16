"""SQLite storage for users, incidents and the audit log."""
import json
import sqlite3
import threading
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('admin', 'security')),
    created_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS incidents (
    id             TEXT PRIMARY KEY,
    camera_id      TEXT NOT NULL,
    timestamp      INTEGER NOT NULL,          -- unix seconds (UTC)
    person_count   INTEGER NOT NULL,
    max_confidence REAL NOT NULL,
    detections     TEXT NOT NULL,             -- JSON list
    zone           TEXT NOT NULL,             -- JSON polygon at time of incident
    evidence_hash  TEXT NOT NULL,             -- SHA-256 of plaintext JPEG
    chain_status   TEXT NOT NULL DEFAULT 'pending',  -- pending | recorded | failed
    chain_tx       TEXT,
    acknowledged_by TEXT,
    acknowledged_at TEXT,
    notified       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_incidents_ts ON incidents(timestamp DESC);
CREATE TABLE IF NOT EXISTS audit_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    at        TEXT NOT NULL,
    username  TEXT,
    action    TEXT NOT NULL,
    detail    TEXT
);
"""


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Database:
    def __init__(self, path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._conn().executescript(SCHEMA)

    def _conn(self):
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path, timeout=10)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn = conn
        return conn

    def execute(self, sql, params=()):
        conn = self._conn()
        with conn:
            return conn.execute(sql, params)

    def query(self, sql, params=()):
        return [dict(r) for r in self._conn().execute(sql, params).fetchall()]

    def one(self, sql, params=()):
        rows = self.query(sql, params)
        return rows[0] if rows else None

    # ---- users ----
    def add_user(self, username, password_hash, role):
        self.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (username, password_hash, role, now_iso()),
        )

    def get_user(self, username):
        return self.one("SELECT * FROM users WHERE username = ?", (username,))

    def list_users(self):
        return self.query("SELECT id, username, role, created_at FROM users ORDER BY id")

    def delete_user(self, username):
        self.execute("DELETE FROM users WHERE username = ?", (username,))

    def count_admins(self):
        return self.one("SELECT COUNT(*) AS n FROM users WHERE role = 'admin'")["n"]

    # ---- incidents ----
    def add_incident(self, inc):
        self.execute(
            """INSERT INTO incidents (id, camera_id, timestamp, person_count, max_confidence,
                   detections, zone, evidence_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (inc["id"], inc["camera_id"], inc["timestamp"], inc["person_count"],
             inc["max_confidence"], json.dumps(inc["detections"]), json.dumps(inc["zone"]),
             inc["evidence_hash"]),
        )

    @staticmethod
    def _decode(row):
        if row:
            row["detections"] = json.loads(row["detections"])
            row["zone"] = json.loads(row["zone"])
        return row

    def get_incident(self, incident_id):
        return self._decode(self.one("SELECT * FROM incidents WHERE id = ?", (incident_id,)))

    def list_incidents(self, limit=100):
        return [self._decode(r) for r in self.query(
            "SELECT * FROM incidents ORDER BY timestamp DESC, rowid DESC LIMIT ?", (limit,))]

    def pending_chain(self):
        return self.query("SELECT * FROM incidents WHERE chain_status != 'recorded' ORDER BY timestamp")

    def set_chain(self, incident_id, status, tx=None):
        self.execute("UPDATE incidents SET chain_status = ?, chain_tx = COALESCE(?, chain_tx) WHERE id = ?",
                     (status, tx, incident_id))

    def set_notified(self, incident_id):
        self.execute("UPDATE incidents SET notified = 1 WHERE id = ?", (incident_id,))

    def acknowledge(self, incident_id, username):
        self.execute(
            "UPDATE incidents SET acknowledged_by = ?, acknowledged_at = ? WHERE id = ? AND acknowledged_by IS NULL",
            (username, now_iso(), incident_id),
        )

    def search_incidents(self, status="", camera="", q="", since=None, until=None, limit=500):
        """Filtered incident list for the incidents page and CSV export."""
        where, params = [], []
        if status == "open":
            where.append("acknowledged_by IS NULL")
        elif status == "acknowledged":
            where.append("acknowledged_by IS NOT NULL")
        if camera:
            where.append("camera_id = ?"); params.append(camera)
        if q:
            where.append("id LIKE ?"); params.append(f"%{q}%")
        if since is not None:
            where.append("timestamp >= ?"); params.append(int(since))
        if until is not None:
            where.append("timestamp < ?"); params.append(int(until))
        sql = "SELECT * FROM incidents"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY timestamp DESC, rowid DESC LIMIT ?"
        params.append(limit)
        return [self._decode(r) for r in self.query(sql, params)]

    def acknowledge_all(self, username):
        cur = self.execute(
            "UPDATE incidents SET acknowledged_by = ?, acknowledged_at = ? WHERE acknowledged_by IS NULL",
            (username, now_iso()))
        return cur.rowcount

    def latest_incident(self):
        return self.one("""SELECT id, camera_id, timestamp, person_count, max_confidence, acknowledged_by
                           FROM incidents ORDER BY timestamp DESC, rowid DESC LIMIT 1""")

    def analytics(self, days=7):
        """Aggregates for the analytics page. Hours/days are in server local time."""
        since = f"-{int(days)} days"
        base = "FROM incidents WHERE timestamp >= strftime('%s','now', ?)"
        hourly = {r["h"]: r["n"] for r in self.query(
            f"SELECT CAST(strftime('%H', timestamp, 'unixepoch', 'localtime') AS INTEGER) AS h, COUNT(*) AS n "
            f"{base} GROUP BY h", (since,))}
        daily = {r["d"]: r["n"] for r in self.query(
            f"SELECT date(timestamp, 'unixepoch', 'localtime') AS d, COUNT(*) AS n {base} GROUP BY d", (since,))}
        weekday = {r["w"]: r["n"] for r in self.query(
            f"SELECT CAST(strftime('%w', timestamp, 'unixepoch', 'localtime') AS INTEGER) AS w, COUNT(*) AS n "
            f"{base} GROUP BY w", (since,))}
        cameras = self.query(f"SELECT camera_id, COUNT(*) AS n {base} GROUP BY camera_id ORDER BY n DESC", (since,))
        conf = self.query(
            f"""SELECT CASE WHEN max_confidence >= 0.8 THEN 'high' WHEN max_confidence >= 0.6 THEN 'medium'
                            ELSE 'low' END AS bucket, COUNT(*) AS n {base} GROUP BY bucket""", (since,))
        summary = self.one(
            f"""SELECT COUNT(*) AS total,
                       COALESCE(SUM(person_count), 0) AS people,
                       COALESCE(AVG(max_confidence), 0) AS avg_conf,
                       SUM(CASE WHEN acknowledged_by IS NOT NULL THEN 1 ELSE 0 END) AS acked,
                       SUM(CASE WHEN chain_status = 'recorded' THEN 1 ELSE 0 END) AS on_chain,
                       AVG(CASE WHEN acknowledged_at IS NOT NULL
                                THEN strftime('%s', acknowledged_at) - timestamp END) AS avg_ack_s
                {base}""", (since,))
        return {"days": days, "hourly": hourly, "daily": daily, "weekday": weekday,
                "cameras": cameras, "confidence": {r["bucket"]: r["n"] for r in conf}, "summary": summary}

    def stats(self):
        return self.one(
            """SELECT COUNT(*) AS total,
                      SUM(CASE WHEN acknowledged_by IS NULL THEN 1 ELSE 0 END) AS open,
                      SUM(CASE WHEN chain_status = 'recorded' THEN 1 ELSE 0 END) AS on_chain,
                      SUM(CASE WHEN timestamp >= strftime('%s','now','-1 day') THEN 1 ELSE 0 END) AS last_24h
               FROM incidents""")

    # ---- audit ----
    def audit(self, username, action, detail=""):
        self.execute("INSERT INTO audit_log (at, username, action, detail) VALUES (?, ?, ?, ?)",
                     (now_iso(), username, action, detail))

    def recent_audit(self, limit=50):
        return self.query("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))

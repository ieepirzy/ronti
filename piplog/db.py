import sqlite3
import os
from pathlib import Path

DB_PATH = Path(os.environ.get("PIPLOG_DB", "/var/lib/piplog/audit.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS installs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT    NOT NULL,
    package     TEXT    NOT NULL,
    version     TEXT    NOT NULL,
    wheel_hash  TEXT,
    installer   TEXT,
    invoked_by  TEXT,
    cwd         TEXT,
    argv        TEXT,
    venv_path   TEXT,
    site_packages TEXT,
    git_remote  TEXT,
    git_branch  TEXT,
    uid         INTEGER,
    username    TEXT
);

CREATE TABLE IF NOT EXISTS deps (
    install_id  INTEGER NOT NULL REFERENCES installs(id),
    dep_name    TEXT    NOT NULL,
    dep_version TEXT,
    dep_extras  TEXT
);

CREATE TABLE IF NOT EXISTS advisories (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    package     TEXT    NOT NULL,
    bad_version TEXT,
    severity    TEXT,
    description TEXT,
    cve         TEXT,
    added_ts    TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_installs_pkg     ON installs(package, version);
CREATE INDEX IF NOT EXISTS idx_installs_ts      ON installs(ts);
CREATE INDEX IF NOT EXISTS idx_deps_install     ON deps(install_id);
CREATE INDEX IF NOT EXISTS idx_advisories_pkg   ON advisories(package, bad_version);
"""

BUILTIN_ADVISORIES = [
    ("litellm",       "1.82.7",  "critical", "TeamPCP credential stealer via Trivy CI compromise",         "CVE-2026-33634"),
    ("litellm",       "1.82.8",  "critical", "TeamPCP credential stealer, .pth persistence variant",       "CVE-2026-33634"),
    ("telnyx",        "4.87.1",  "high",     "TeamPCP backdoor injected via stolen PyPI token",            None),
    ("telnyx",        "4.87.2",  "high",     "TeamPCP backdoor injected via stolen PyPI token",            None),
    ("lightning",     "2.6.2",   "critical", "Mini Shai-Hulud: credential stealer + JS payload on import", None),
    ("lightning",     "2.6.3",   "critical", "Mini Shai-Hulud: credential stealer + JS payload on import", None),
    ("mistralai",     "2.4.6",   "critical", "Shai-Hulud: imports transformers.pyz, exfils to 83.142.209.194", None),
    ("guardrails-ai", None,      "high",     "Shai-Hulud wave: verify version against advisories",         None),
    ("dydx-v4-client",None,      "high",     "Wallet stealer + RAT, verify installed version",             None),
]


def get_conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    with get_conn() as conn:
        conn.executescript(SCHEMA)
        _seed_advisories(conn)


def _seed_advisories(conn: sqlite3.Connection) -> None:
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    for pkg, ver, sev, desc, cve in BUILTIN_ADVISORIES:
        existing = conn.execute(
            "SELECT id FROM advisories WHERE package=? AND (bad_version=? OR (bad_version IS NULL AND ?  IS NULL))",
            (pkg, ver, ver)
        ).fetchone()
        if not existing:
            conn.execute(
                "INSERT INTO advisories (package, bad_version, severity, description, cve, added_ts) VALUES (?,?,?,?,?,?)",
                (pkg, ver, sev, desc, cve, now)
            )
    conn.commit()
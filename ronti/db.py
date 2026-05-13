import sqlite3
import os
from pathlib import Path

DB_PATH = Path(os.environ.get("RONTI_DB", "/var/lib/ronti/audit.db"))

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
    dep_extras  TEXT,
    PRIMARY KEY (install_id, dep_name)
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

CREATE TABLE IF NOT EXISTS osv_cache (
    package    TEXT NOT NULL,
    version    TEXT NOT NULL,
    checked_ts TEXT NOT NULL,
    vuln_ids   TEXT NOT NULL,
    PRIMARY KEY (package, version)
);

CREATE TABLE IF NOT EXISTS osv_vulns (
    id         TEXT PRIMARY KEY,
    fetched_ts TEXT NOT NULL,
    vuln_json  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_installs_pkg    ON installs(package, version);
CREATE INDEX IF NOT EXISTS idx_installs_ts     ON installs(ts);
CREATE INDEX IF NOT EXISTS idx_deps_install    ON deps(install_id);
CREATE INDEX IF NOT EXISTS idx_advisories_pkg  ON advisories(package, bad_version);
CREATE UNIQUE INDEX IF NOT EXISTS idx_advisories_unique
    ON advisories(package, COALESCE(bad_version, ''));
"""


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

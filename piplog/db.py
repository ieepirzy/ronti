import sqlite3
import os
from pathlib import Path
from typing import NamedTuple

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

CREATE INDEX IF NOT EXISTS idx_installs_pkg     ON installs(package, version);
CREATE INDEX IF NOT EXISTS idx_installs_ts      ON installs(ts);
CREATE INDEX IF NOT EXISTS idx_deps_install     ON deps(install_id);
CREATE INDEX IF NOT EXISTS idx_advisories_pkg   ON advisories(package, bad_version);
CREATE UNIQUE INDEX IF NOT EXISTS idx_advisories_unique
    ON advisories(package, COALESCE(bad_version, ''));
"""


class Advisory(NamedTuple):
    package:     str
    bad_version: str | None
    severity:    str
    description: str
    cve:         str | None


BUILTIN_ADVISORIES: list[Advisory] = [
    Advisory("litellm",        "1.82.7",  "critical", "TeamPCP credential stealer via Trivy CI compromise",            "CVE-2026-33634"),
    Advisory("litellm",        "1.82.8",  "critical", "TeamPCP credential stealer, .pth persistence variant",          "CVE-2026-33634"),
    Advisory("telnyx",         "4.87.1",  "high",     "TeamPCP backdoor injected via stolen PyPI token",               None),
    Advisory("telnyx",         "4.87.2",  "high",     "TeamPCP backdoor injected via stolen PyPI token",               None),
    Advisory("lightning",      "2.6.2",   "critical", "Mini Shai-Hulud: credential stealer + JS payload on import",   None),
    Advisory("lightning",      "2.6.3",   "critical", "Mini Shai-Hulud: credential stealer + JS payload on import",   None),
    Advisory("mistralai",      "2.4.6",   "critical", "Shai-Hulud: imports transformers.pyz, exfils to 83.142.209.194", None),
    Advisory("guardrails-ai",  None,      "high",     "Shai-Hulud wave: verify version against advisories",            None),
    Advisory("dydx-v4-client", None,      "high",     "Wallet stealer + RAT, verify installed version",                None),
]


def get_conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    # Drop osv_cache if it still has the old vulns_json column
    cols = {row[1] for row in conn.execute("PRAGMA table_info(osv_cache)")}
    if "vulns_json" in cols:
        conn.execute("DROP TABLE IF EXISTS osv_cache")
        conn.commit()

    # Remove duplicate deps rows before the PRIMARY KEY constraint lands
    try:
        conn.execute("""
            DELETE FROM deps WHERE rowid NOT IN (
                SELECT MIN(rowid) FROM deps GROUP BY install_id, dep_name
            )
        """)
        conn.commit()
    except Exception:
        pass

    # Remove duplicate advisories before the UNIQUE index lands
    try:
        conn.execute("""
            DELETE FROM advisories WHERE id NOT IN (
                SELECT MIN(id) FROM advisories
                GROUP BY package, COALESCE(bad_version, '')
            )
        """)
        conn.commit()
    except Exception:
        pass


def init_db() -> None:
    with get_conn() as conn:
        _migrate(conn)
        conn.executescript(SCHEMA)
        _seed_advisories(conn)


def _seed_advisories(conn: sqlite3.Connection) -> None:
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    for adv in BUILTIN_ADVISORIES:
        conn.execute(
            "INSERT OR IGNORE INTO advisories"
            " (package, bad_version, severity, description, cve, added_ts)"
            " VALUES (?,?,?,?,?,?)",
            (adv.package, adv.bad_version, adv.severity, adv.description, adv.cve, now),
        )
    conn.commit()
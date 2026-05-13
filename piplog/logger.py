import json
import os
import pwd
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .db import get_conn, init_db


def _git_info(cwd: str) -> tuple[Optional[str], Optional[str]]:
    try:
        remote = subprocess.check_output(
            ["git", "remote", "get-url", "origin"],
            cwd=cwd, stderr=subprocess.DEVNULL, timeout=3
        ).decode().strip()
        branch = subprocess.check_output(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=cwd, stderr=subprocess.DEVNULL, timeout=3
        ).decode().strip()
        return remote, branch
    except Exception:
        return None, None


def _dep_tree(package: str) -> list[dict]:
    try:
        out = subprocess.check_output(
            [sys.executable, "-m", "pip", "show", package],
            stderr=subprocess.DEVNULL, timeout=10
        ).decode()
        deps = []
        for line in out.splitlines():
            if line.startswith("Requires:"):
                raw = line.split(":", 1)[1].strip()
                if raw:
                    for dep in raw.split(","):
                        dep = dep.strip()
                        if dep:
                            deps.append({"name": dep.lower(), "version": None, "extras": None})
        return deps
    except Exception:
        return []


def _wheel_hash(package: str, version: str) -> Optional[str]:
    try:
        import importlib.metadata as meta
        dist = meta.distribution(package)
        record = dist.read_text("RECORD")
        if record:
            import hashlib
            h = hashlib.sha256(record.encode()).hexdigest()[:16]
            return f"sha256-record:{h}"
        return None
    except Exception:
        return None


def _venv_info() -> tuple[Optional[str], Optional[str]]:
    venv = os.environ.get("VIRTUAL_ENV")
    if venv:
        py_ver = f"python{sys.version_info.major}.{sys.version_info.minor}"
        site = str(Path(venv) / "lib" / py_ver / "site-packages")
        return venv, site
    return None, str(Path(sys.prefix) / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages")


def log_install(package: str, version: str) -> int:
    init_db()

    ts      = datetime.now(timezone.utc).isoformat()
    cwd     = os.getcwd()
    uid     = os.getuid()
    argv    = json.dumps(sys.argv)
    venv, site = _venv_info()
    git_remote, git_branch = _git_info(cwd)
    wheel_hash = _wheel_hash(package, version)
    deps    = _dep_tree(package)

    try:
        username = pwd.getpwuid(uid).pw_name
    except Exception:
        username = str(uid)

    try:
        installer = subprocess.check_output(
            ["which", "pip"], stderr=subprocess.DEVNULL
        ).decode().strip()
    except Exception:
        installer = sys.executable

    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO installs
               (ts, package, version, wheel_hash, installer, invoked_by,
                cwd, argv, venv_path, site_packages, git_remote, git_branch, uid, username)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (ts, package.lower(), version, wheel_hash, installer, sys.executable,
             cwd, argv, venv, site, git_remote, git_branch, uid, username)
        )
        install_id = cur.lastrowid
        for dep in deps:
            conn.execute(
                "INSERT INTO deps (install_id, dep_name, dep_version, dep_extras) VALUES (?,?,?,?)",
                (install_id, dep["name"], dep.get("version"), dep.get("extras"))
            )
        conn.commit()

    return install_id
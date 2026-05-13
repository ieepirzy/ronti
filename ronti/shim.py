#!/usr/bin/env python3
"""
rönti pip shim — installed at /usr/local/bin/pip (and pip3).
Passes all args through to the real pip, then logs any installs.
Must be fast and non-blocking on non-install commands.
"""
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

PIPLOG_ENABLED = (
    os.environ.get("RONTI_DISABLE", "").lower() not in ("1", "true", "yes")
    and not os.environ.get("RONTI_SHIM_ACTIVE")
)


def _find_real_pip() -> str:
    # Venv install: shim lives in .venv/bin/pip, backup is .venv/bin/.pip-real
    sibling = Path(__file__).parent / ".pip-real"
    if sibling.exists():
        return str(sibling)

    real = shutil.which("pip3") or shutil.which("pip")
    if not real:
        print("[rönti] cannot find pip3 or pip on PATH", file=sys.stderr)
        sys.exit(1)
    if Path(real).resolve() == Path(__file__).resolve():
        backup = Path("/usr/local/bin/.pip-real")
        if backup.exists():
            return str(backup)
        print("[rönti] shim loop detected and no .pip-real backup found", file=sys.stderr)
        sys.exit(1)
    return real


def _pkg_name(spec: str) -> str:
    """Extract bare package name from a pip spec string."""
    return re.split(r"[><=!~\[@; ]", spec)[0].strip().lower()


def _parse_installs(args: list[str]) -> list[str]:
    """Extract package specs from install args (rough but sufficient)."""
    if not args or args[0] != "install":
        return []
    packages = []
    skip_next = False
    flags_with_args = {
        "-r", "--requirement", "-c", "--constraint",
        "-t", "--target", "--root", "--prefix",
        "-i", "--index-url", "--extra-index-url",
        "--trusted-host", "--python-version",
        "-e", "--editable",
        "-f", "--find-links",
        "--cache-dir", "--log",
        "--progress-bar", "--timeout", "--retries",
        "--proxy", "--cert", "--client-cert",
        "--hash", "-C", "--config-settings",
        "--global-option", "--install-option",
        "--platform", "--abi", "--implementation",
        "--only-binary", "--no-binary",
    }
    for arg in args[1:]:
        if skip_next:
            skip_next = False
            continue
        if arg in flags_with_args:
            skip_next = True
            continue
        if arg.startswith("-"):
            continue
        packages.append(arg)
    return packages


def main() -> None:
    real_pip = _find_real_pip()
    pkg_specs = _parse_installs(sys.argv[1:]) if PIPLOG_ENABLED else []

    # Pre-install: check explicitly pinned packages against OSV before pip runs
    if pkg_specs:
        _pre_check_osv(pkg_specs)

    result = subprocess.run([real_pip] + sys.argv[1:], env={**os.environ, "RONTI_SHIM_ACTIVE": "1"})

    # Post-install: log and check full dep tree (versions now resolved)
    if result.returncode == 0 and pkg_specs:
        _log_installed(pkg_specs)

    sys.exit(result.returncode)


def _pre_check_osv(pkg_specs: list[str]) -> None:
    """Query OSV for explicitly pinned packages before pip runs."""
    try:
        from ronti.db import get_conn, init_db
        from ronti.osv import query_packages

        packages = []
        for spec in pkg_specs:
            if "==" in spec:
                name, _, version = spec.partition("==")
                name = name.strip().lower()
                version = version.strip()
                if name and version and not name.startswith((".", "/")):
                    packages.append((name, version))

        if not packages:
            return

        init_db()
        with get_conn() as conn:
            hits = query_packages(packages, conn)

        if not hits:
            return

        print(f"\n{'='*60}", file=sys.stderr)
        print(f"[rönti] \033[1;31m⚠  OSV: vulnerable version pinned\033[0m", file=sys.stderr)
        for (pkg, ver), vulns in sorted(hits.items()):
            for v in vulns:
                sev = v["severity"].upper()
                fix = f"upgrade to {v['fixed']}" if v["fixed"] else "no fix available"
                print(f"  [{sev}] {pkg}=={ver}: {v['summary']}", file=sys.stderr)
                ref = v["cve"] or v["id"]
                print(f"          {ref}  ({fix})", file=sys.stderr)
        print(f"{'='*60}\n", file=sys.stderr)
        sys.stderr.write("  Proceed with install? [y/N] ")
        sys.stderr.flush()
        try:
            answer = sys.stdin.readline().strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = "n"
        if answer not in ("y", "yes"):
            print("[rönti] install aborted.", file=sys.stderr)
            sys.exit(1)
    except Exception as e:
        if os.environ.get("RONTI_DEBUG"):
            print(f"[rönti] pre-install OSV check failed: {e}", file=sys.stderr)


def _log_installed(pkg_specs: list[str]) -> None:
    try:
        import importlib.metadata as meta
        from ronti.logger import log_install

        for spec in pkg_specs:
            name = _pkg_name(spec)
            if not name or name.startswith(".") or name.startswith("/"):
                continue
            try:
                version = meta.version(name)
                install_id = log_install(name, version)
                _check_advisory(name, version, install_id)
            except meta.PackageNotFoundError:
                pass
            except Exception as e:
                if os.environ.get("RONTI_DEBUG"):
                    print(f"[rönti] warning: could not log {name}: {e}", file=sys.stderr)

        _check_osv_batch(pkg_specs)
    except Exception as e:
        if os.environ.get("RONTI_DEBUG"):
            print(f"[rönti] logger unavailable: {e}", file=sys.stderr)


def _check_advisory(name: str, version: str, install_id: int) -> None:
    try:
        from ronti.db import get_conn
        with get_conn() as conn:
            hits = conn.execute(
                """SELECT severity, description, cve FROM advisories
                   WHERE package=? AND (bad_version=? OR bad_version IS NULL)""",
                (name.lower(), version)
            ).fetchall()
        if hits:
            print(f"\n{'='*60}", file=sys.stderr)
            print(f"[rönti] \033[1;31m⚠  ADVISORY MATCH\033[0m  {name}=={version}", file=sys.stderr)
            for h in hits:
                sev = h["severity"].upper()
                print(f"  [{sev}] {h['description']}", file=sys.stderr)
                if h["cve"]:
                    print(f"          {h['cve']}", file=sys.stderr)
            print(f"  install_id={install_id} — run: ronti scan", file=sys.stderr)
            print(f"{'='*60}\n", file=sys.stderr)
    except Exception:
        pass


def _check_osv_batch(pkg_specs: list[str]) -> None:
    """Batch-query OSV for installed packages and all their transitive deps."""
    try:
        import importlib.metadata as meta
        import re
        from ronti.osv import query_packages
        from ronti.db import get_conn

        packages: list[tuple[str, str]] = []
        seen: set[str] = set()

        def _add(name: str) -> None:
            name = name.lower()
            if name in seen:
                return
            seen.add(name)
            try:
                ver = meta.version(name)
                packages.append((name, ver))
                dist = meta.distribution(name)
                for req in (dist.requires or []):
                    # Skip environment markers (extras, python_version, etc.)
                    if ";" in req:
                        marker = req.split(";", 1)[1]
                        if "extra ==" in marker:
                            continue
                    dep = re.split(r"[><=!~\[; ]", req)[0].strip().lower()
                    if dep:
                        _add(dep)
            except meta.PackageNotFoundError:
                pass

        for spec in pkg_specs:
            name = _pkg_name(spec)
            if name and not name.startswith((".", "/")):
                _add(name)

        if not packages:
            return

        with get_conn() as conn:
            hits = query_packages(packages, conn)

        if not hits:
            return

        print(f"\n{'='*60}", file=sys.stderr)
        print(f"[rönti] \033[1;31m⚠  OSV VULNERABILITY\033[0m", file=sys.stderr)
        for (pkg, ver), vulns in sorted(hits.items()):
            for v in vulns:
                sev = v["severity"].upper()
                fix = f"fix: {v['fixed']}" if v["fixed"] else "no fix available"
                print(f"  [{sev}] {pkg}=={ver}  {v['id']}", file=sys.stderr)
                print(f"    {v['summary']}", file=sys.stderr)
                if v["cve"]:
                    print(f"    {v['cve']}  ({fix})", file=sys.stderr)
                else:
                    print(f"    ({fix})", file=sys.stderr)
        print(f"  run: ronti osv-scan", file=sys.stderr)
        print(f"{'='*60}\n", file=sys.stderr)
    except Exception as e:
        if os.environ.get("RONTI_DEBUG"):
            print(f"[rönti] OSV check failed: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from .db import get_conn, init_db, DB_PATH


# ── formatting helpers ────────────────────────────────────────────────────────

RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[1;31m"
YELLOW = "\033[1;33m"
GREEN  = "\033[1;32m"
CYAN   = "\033[1;36m"
GRAY   = "\033[90m"
BLUE   = "\033[1;34m"

SEV_COLOR = {"critical": RED, "high": YELLOW, "medium": YELLOW, "low": GRAY}


def _sev(s: str) -> str:
    return f"{SEV_COLOR.get(s.lower(), RESET)}[{s.upper()}]{RESET}"


def _ts(iso: str) -> str:
    try:
        dt = datetime.fromisoformat(iso)
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return iso


def _col(text, color):
    return f"{color}{text}{RESET}"


def _hr(char="─", width=60):
    return char * width


# ── subcommands ───────────────────────────────────────────────────────────────

def cmd_list(args):
    init_db()
    with get_conn() as conn:
        q = "SELECT * FROM installs"
        params = []
        if args.package:
            q += " WHERE package LIKE ?"
            params.append(f"%{args.package.lower()}%")
        q += " ORDER BY ts DESC LIMIT ?"
        params.append(args.limit)
        rows = conn.execute(q, params).fetchall()

    if not rows:
        print("No installs recorded.")
        return

    print(f"\n{_col('piplog', BOLD)} — {len(rows)} most recent installs\n{_hr()}")
    for r in rows:
        venv = f" {GRAY}[{Path(r['venv_path']).name}]{RESET}" if r["venv_path"] else f" {GRAY}[global]{RESET}"
        user = f"{GRAY}{r['username']}{RESET}" if r["username"] else ""
        git  = f" {CYAN}@{r['git_branch']}{RESET}" if r["git_branch"] else ""
        print(f"  {_col(r['package'], BOLD)}=={r['version']}{venv}{git}  {GRAY}{_ts(r['ts'])}{RESET}  {user}")
    print()


def cmd_scan(args):
    init_db()
    with get_conn() as conn:
        hits = conn.execute("""
            SELECT i.id, i.ts, i.package, i.version, i.venv_path, i.username,
                   i.cwd, i.git_remote,
                   a.severity, a.description, a.cve
            FROM installs i
            JOIN advisories a
              ON i.package = a.package
             AND (a.bad_version = i.version OR a.bad_version IS NULL)
            ORDER BY a.severity DESC, i.ts DESC
        """).fetchall()

    if not hits:
        print(f"\n{_col('✓', GREEN)} No advisory matches found in install history.\n")
        return

    print(f"\n{_col('⚠  ADVISORY MATCHES', RED)}  ({len(hits)} found)\n{_hr()}")
    for h in hits:
        venv = Path(h["venv_path"]).name if h["venv_path"] else "global"
        print(f"  {_sev(h['severity'])}  {_col(h['package'], BOLD)}=={h['version']}")
        print(f"    {h['description']}")
        if h["cve"]:
            print(f"    {_col(h['cve'], CYAN)}")
        print(f"    installed: {_ts(h['ts'])}  user={h['username']}  env={venv}")
        if h["cwd"]:
            print(f"    cwd: {GRAY}{h['cwd']}{RESET}")
        if h["git_remote"]:
            print(f"    repo: {GRAY}{h['git_remote']}{RESET}")
        print(f"    install_id={h['id']}")
        print()

    if args.fail and hits:
        sys.exit(1)

    if getattr(args, "osv", False):
        _cmd_scan_osv(args)


def cmd_tree(args):
    init_db()
    pkg = args.package.lower()
    with get_conn() as conn:
        installs = conn.execute(
            "SELECT * FROM installs WHERE package=? ORDER BY ts DESC LIMIT 1",
            (pkg,)
        ).fetchall()
        if not installs:
            print(f"No install record for '{pkg}'.")
            return
        install = installs[0]
        deps = conn.execute(
            "SELECT * FROM deps WHERE install_id=?",
            (install["id"],)
        ).fetchall()

    print(f"\n{_col(install['package'], BOLD)}=={install['version']}")
    print(f"  installed: {_ts(install['ts'])}  user={install['username']}")
    venv = install["venv_path"] or "global"
    print(f"  env: {venv}")
    if install["git_remote"]:
        print(f"  repo: {install['git_remote']} @ {install['git_branch']}")
    if deps:
        print(f"\n  {_col('dependencies', GRAY)}:")
        for d in deps:
            ver = f"=={d['dep_version']}" if d["dep_version"] else ""
            print(f"    └─ {d['dep_name']}{ver}")
    else:
        print(f"  {GRAY}(no dependencies recorded){RESET}")
    print()


def cmd_diff(args):
    init_db()
    pkg = args.package.lower()
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, ts, version, venv_path, username, cwd FROM installs WHERE package=? ORDER BY ts ASC",
            (pkg,)
        ).fetchall()

    if not rows:
        print(f"No install history for '{pkg}'.")
        return

    print(f"\n{_col('version history', BOLD)} — {pkg}\n{_hr()}")
    prev_ver = None
    for r in rows:
        venv = Path(r["venv_path"]).name if r["venv_path"] else "global"
        change = ""
        if prev_ver and prev_ver != r["version"]:
            change = f"  {YELLOW}← was {prev_ver}{RESET}"
        elif prev_ver == r["version"]:
            change = f"  {GRAY}(reinstall){RESET}"
        print(f"  {_col(r['version'], BOLD)}  {GRAY}{_ts(r['ts'])}{RESET}  [{venv}]  {r['username']}{change}")
        prev_ver = r["version"]
    print()


def cmd_repos(args):
    init_db()
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT git_remote, git_branch, package, version, ts, username
            FROM installs
            WHERE git_remote IS NOT NULL
            ORDER BY git_remote, ts DESC
        """).fetchall()

    if not rows:
        print("No repo-context installs recorded.")
        return

    from itertools import groupby
    print(f"\n{_col('installs by repo', BOLD)}\n{_hr()}")
    for repo, group in groupby(rows, key=lambda r: r["git_remote"]):
        items = list(group)
        print(f"\n  {_col(repo, CYAN)}")
        for r in items:
            print(f"    {r['package']}=={r['version']}  {GRAY}{_ts(r['ts'])}{RESET}  @{r['git_branch']}")
    print()


def cmd_advisory(args):
    init_db()
    if args.action == "list":
        with get_conn() as conn:
            rows = conn.execute("SELECT * FROM advisories ORDER BY severity DESC, package").fetchall()
        print(f"\n{_col('advisory database', BOLD)}  ({len(rows)} entries)\n{_hr()}")
        for r in rows:
            ver = r["bad_version"] or "any version"
            print(f"  {_sev(r['severity'])}  {_col(r['package'], BOLD)}  {ver}")
            print(f"    {r['description']}")
            if r["cve"]:
                print(f"    {_col(r['cve'], CYAN)}")
        print()

    elif args.action == "add":
        now = datetime.now(timezone.utc).isoformat()
        with get_conn() as conn:
            conn.execute(
                "INSERT INTO advisories (package, bad_version, severity, description, cve, added_ts) VALUES (?,?,?,?,?,?)",
                (args.package.lower(), args.version, args.severity, args.description, args.cve, now)
            )
            conn.commit()
        print(f"Added advisory for {args.package}" + (f"=={args.version}" if args.version else ""))


def cmd_inject_venv(args):
    venv = Path(args.venv)
    if not venv.exists():
        print(f"venv not found: {venv}")
        sys.exit(1)
    py = f"python{sys.version_info.major}.{sys.version_info.minor}"
    site = venv / "lib" / py / "site-packages"
    if not site.exists():
        # try without minor version
        candidates = list((venv / "lib").glob("python*/site-packages"))
        if not candidates:
            print(f"Could not find site-packages in {venv}")
            sys.exit(1)
        site = candidates[0]
    dest = site / "sitecustomize.py"
    src  = Path(__file__).parent / "sitecustomize.py"
    shutil.copy(src, dest)
    print(f"Injected piplog hook → {dest}")


def cmd_install_shim(args):
    """Install the pip shim system-wide (requires root)."""
    if os.geteuid() != 0:
        print("install-shim requires root. Run with sudo.")
        sys.exit(1)

    real_pip = shutil.which("pip3") or shutil.which("pip")
    if not real_pip:
        print("Could not find pip3 or pip on PATH.")
        sys.exit(1)

    shim_src = Path(__file__).parent / "shim.py"
    target    = Path("/usr/local/bin/pip")
    real_dest = Path("/usr/local/bin/.pip-real")

    # back up real pip (skip if already backed up to avoid overwriting the shim itself)
    if not real_dest.exists():
        shutil.copy(real_pip, real_dest)
    shutil.copy(shim_src, target)
    target.chmod(0o755)

    # also cover pip3
    target3 = Path("/usr/local/bin/pip3")
    shutil.copy(shim_src, target3)
    target3.chmod(0o755)

    # ensure piplog itself is importable system-wide
    r = subprocess.run([sys.executable, "-m", "pip", "install", "-e",
                        str(Path(__file__).parent.parent), "--quiet"], check=False)
    if r.returncode != 0:
        print("Warning: failed to install piplog system-wide; shim may not be able to import it.", file=sys.stderr)

    print(f"Shim installed: {target} + {target3}")
    print(f"Real pip backed up: {real_dest}")
    print(f"DB will be written to: {DB_PATH}")


def cmd_docker_scan(args):
    """Standalone scan for use in Dockerfiles. Reads requirements file or pip freeze."""
    init_db()

    packages = []
    if args.requirements:
        req_file = Path(args.requirements)
        if not req_file.exists():
            print(f"requirements file not found: {req_file}")
            sys.exit(1)
        for line in req_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and not line.startswith("-"):
                packages.append(line)
    else:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "freeze"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            print(f"pip freeze failed: {result.stderr.strip()}", file=sys.stderr)
            sys.exit(1)
        packages = [l.strip() for l in result.stdout.splitlines() if l.strip()]

    with get_conn() as conn:
        advisories = conn.execute("SELECT package, bad_version, severity, description, cve FROM advisories").fetchall()

    adv_map: dict[str, list] = {}
    for a in advisories:
        adv_map.setdefault(a["package"].lower(), []).append(a)

    hits = []
    for spec in packages:
        name_ver = spec.split("==")
        name = name_ver[0].lower().strip()
        ver  = name_ver[1].strip() if len(name_ver) > 1 else None
        if name in adv_map:
            for adv in adv_map[name]:
                if adv["bad_version"] is None or adv["bad_version"] == ver:
                    hits.append((name, ver, adv))

    if hits:
        print(f"\n{_col('⚠  piplog docker-scan:', RED)} {len(hits)} advisory match(es)\n{_hr()}")
        for name, ver, adv in hits:
            ver_str = f"=={ver}" if ver else ""
            print(f"  {_sev(adv['severity'])}  {_col(name, BOLD)}{ver_str}")
            print(f"    {adv['description']}")
            if adv["cve"]:
                print(f"    {_col(adv['cve'], CYAN)}")
        print()
    else:
        print(f"{_col('✓', GREEN)} piplog docker-scan: no advisory matches ({len(packages)} packages checked).")

    # OSV query — covers transitive deps when using pip freeze
    from .osv import query_packages
    pkg_pairs = []
    for spec in packages:
        name_ver = spec.split("==")
        name = name_ver[0].lower().strip()
        ver  = name_ver[1].strip() if len(name_ver) > 1 else None
        if ver:
            pkg_pairs.append((name, ver))

    osv_hits: dict = {}
    if not getattr(args, "no_osv", False) and pkg_pairs:
        with get_conn() as conn:
            osv_hits = query_packages(pkg_pairs, conn)

    if osv_hits:
        osv_total = sum(len(v) for v in osv_hits.values())
        print(f"\n{_col('⚠  OSV matches:', RED)} {osv_total} vuln(s) across {len(osv_hits)} package version(s)\n{_hr()}")
        for (pkg, ver), vulns in sorted(osv_hits.items()):
            for v in vulns:
                fix = f"fix: {v['fixed']}" if v["fixed"] else "no fix available"
                print(f"  {_sev(v['severity'])}  {_col(pkg, BOLD)}=={ver}  {GRAY}{v['id']}{RESET}")
                print(f"    {v['summary']}")
                ref = _col(v['cve'], CYAN) if v['cve'] else v['id']
                print(f"    {ref}  {GRAY}({fix}){RESET}")
        print()
    elif not getattr(args, "no_osv", False):
        print(f"{_col('✓', GREEN)} OSV: no matches ({len(pkg_pairs)} versioned packages checked).")

    if hits or osv_hits:
        sys.exit(1)


def _cmd_scan_osv(args) -> None:
    """OSV scan portion of `piplog scan --osv` and `piplog osv-scan`."""
    from .osv import query_packages

    with get_conn() as conn:
        rows = conn.execute(
            "SELECT DISTINCT package, version FROM installs"
        ).fetchall()
        packages = [(r["package"], r["version"]) for r in rows]
        osv_hits = query_packages(packages, conn)

    total = sum(len(v) for v in osv_hits.values())
    if not osv_hits:
        print(f"\n{_col('✓', GREEN)} No OSV matches in install history.\n")
        return

    print(f"\n{_col('⚠  OSV MATCHES', RED)}  ({total} vulns across {len(osv_hits)} package versions)\n{_hr()}")
    for (pkg, ver), vulns in sorted(osv_hits.items()):
        for v in vulns:
            fix = f"fix: {v['fixed']}" if v["fixed"] else "no fix available"
            print(f"  {_sev(v['severity'])}  {_col(pkg, BOLD)}=={ver}")
            print(f"    {v['summary']}")
            if v["cve"]:
                print(f"    {_col(v['cve'], CYAN)}  {GRAY}{v['id']}{RESET}")
            else:
                print(f"    {GRAY}{v['id']}{RESET}")
            print(f"    {GRAY}{fix}{RESET}")
            print()

    if getattr(args, "fail", False) and osv_hits:
        sys.exit(1)


def cmd_osv_scan(args) -> None:
    """Query OSV for all packages recorded in the install log."""
    init_db()
    _cmd_scan_osv(args)


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="piplog",
        description="pip install audit logger"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # list
    p_list = sub.add_parser("list", help="list recent installs")
    p_list.add_argument("package", nargs="?", help="filter by package name")
    p_list.add_argument("-n", "--limit", type=int, default=50)

    # scan
    p_scan = sub.add_parser("scan", help="scan install history against advisories")
    p_scan.add_argument("--fail", action="store_true", help="exit 1 if matches found")
    p_scan.add_argument("--osv", action="store_true", help="also query OSV database (requires network)")

    # tree
    p_tree = sub.add_parser("tree", help="show dep tree for a package")
    p_tree.add_argument("package")

    # diff
    p_diff = sub.add_parser("diff", help="version history for a package")
    p_diff.add_argument("package")

    # repos
    sub.add_parser("repos", help="installs grouped by git repo")

    # advisory
    p_adv = sub.add_parser("advisory", help="manage advisory database")
    adv_sub = p_adv.add_subparsers(dest="action", required=True)
    adv_sub.add_parser("list")
    p_adv_add = adv_sub.add_parser("add")
    p_adv_add.add_argument("package")
    p_adv_add.add_argument("--version", default=None)
    p_adv_add.add_argument("--severity", default="high", choices=["critical","high","medium","low"])
    p_adv_add.add_argument("--description", required=True)
    p_adv_add.add_argument("--cve", default=None)

    # inject-venv
    p_iv = sub.add_parser("inject-venv", help="install hook into a specific venv")
    p_iv.add_argument("venv")

    # install-shim
    sub.add_parser("install-shim", help="install system-wide pip shim (run as root)")

    # docker-scan
    p_ds = sub.add_parser("docker-scan", help="scan requirements/freeze for advisories, exit 1 on hit")
    p_ds.add_argument("-r", "--requirements", default=None, help="requirements.txt path")
    p_ds.add_argument("--no-osv", action="store_true", help="skip OSV query (air-gapped builds)")

    # osv-scan
    p_osv = sub.add_parser("osv-scan", help="query OSV database for all recorded installs")
    p_osv.add_argument("--fail", action="store_true", help="exit 1 if matches found")

    args = parser.parse_args()
    dispatch = {
        "list":          cmd_list,
        "scan":          cmd_scan,
        "tree":          cmd_tree,
        "diff":          cmd_diff,
        "repos":         cmd_repos,
        "advisory":      cmd_advisory,
        "inject-venv":   cmd_inject_venv,
        "install-shim":  cmd_install_shim,
        "docker-scan":   cmd_docker_scan,
        "osv-scan":      cmd_osv_scan,
    }
    dispatch[args.cmd](args)


if __name__ == "__main__":
    main()
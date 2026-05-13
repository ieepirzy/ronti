#!/usr/bin/env python3
"""
piplog-docker-scan — standalone advisory scanner for Dockerfiles.
Zero external dependencies. Copy into your image and run after pip install.

Usage in Dockerfile:
    COPY piplog-docker-scan.py /usr/local/bin/piplog-docker-scan
    RUN pip install -r requirements.txt && python /usr/local/bin/piplog-docker-scan -r requirements.txt

Or against the live installed packages:
    RUN pip install -r requirements.txt && python /usr/local/bin/piplog-docker-scan

Exit code 0 = clean, 1 = advisory match found.
Add --warn-only to always exit 0 (log but don't fail the build).
"""
import subprocess
import sys
import json
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_OSV_VULN_URL  = "https://api.osv.dev/v1/vulns/{}"
_OSV_BATCH_SIZE = 1000
_FETCH_WORKERS  = 10


def _osv_query(packages: list[tuple[str, str]]) -> dict[tuple[str, str], list[dict]]:
    """Batch-query OSV then fetch full vuln records in parallel. Returns hits only."""
    pkg_ids: dict[tuple[str, str], list[str]] = {}
    for i in range(0, len(packages), _OSV_BATCH_SIZE):
        chunk = packages[i : i + _OSV_BATCH_SIZE]
        payload = json.dumps({
            "queries": [
                {"package": {"name": n, "ecosystem": "PyPI"}, "version": v}
                for n, v in chunk
            ]
        }).encode()
        req = urllib.request.Request(
            _OSV_BATCH_URL, data=payload,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as e:
            print(f"[piplog-docker-scan] OSV query failed: {e}", file=sys.stderr)
            continue
        api_results = data.get("results", [])
        if len(api_results) != len(chunk):
            print(
                f"[piplog-docker-scan] OSV batch: expected {len(chunk)} results, got {len(api_results)}",
                file=sys.stderr,
            )
        for (name, ver), result in zip(chunk, api_results):
            ids = [v["id"] for v in result.get("vulns", []) if v.get("id")]
            if ids:
                pkg_ids[(name, ver)] = ids

    if not pkg_ids:
        return {}

    # Fetch full vuln records in parallel
    all_ids = {vid for ids in pkg_ids.values() for vid in ids}

    def _fetch_one(vid: str):
        req = urllib.request.Request(_OSV_VULN_URL.format(vid), method="GET")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return vid, json.loads(resp.read())
        except (urllib.error.URLError, OSError, json.JSONDecodeError):
            return vid, None

    details: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=_FETCH_WORKERS) as ex:
        for vid, rec in ex.map(_fetch_one, all_ids):
            if rec:
                details[vid] = rec

    results: dict[tuple[str, str], list[dict]] = {}
    for key, ids in pkg_ids.items():
        parsed = [_parse_osv_vuln(details[vid]) for vid in ids if vid in details]
        if parsed:
            results[key] = parsed
    return results


def _parse_osv_vuln(v: dict) -> dict:
    cve = next((a for a in v.get("aliases", []) if a.startswith("CVE-")), None)
    db_sev = (v.get("database_specific") or {}).get("severity", "")
    severity = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium",
                "MEDIUM": "medium", "LOW": "low"}.get(db_sev.upper(), "")
    if not severity:
        for s in v.get("severity", []):
            vec = s.get("score", "")
            if vec.startswith("CVSS:"):
                highs = vec.count(":H")
                network = "/AV:N" in vec
                no_priv = "/PR:N" in vec
                if highs >= 3 and network:
                    severity = "critical"
                elif highs >= 2 and (network or no_priv):
                    severity = "high"
                elif highs >= 1:
                    severity = "medium"
                else:
                    severity = "low"
                break
    fixed = None
    for affected in v.get("affected", []):
        for r in affected.get("ranges", []):
            if r.get("type") == "ECOSYSTEM":
                for event in r.get("events", []):
                    if "fixed" in event:
                        fixed = event["fixed"]
                        break
    return {"id": v.get("id", ""), "cve": cve, "summary": v.get("summary", ""),
            "severity": severity or "unknown", "fixed": fixed}

RESET  = "\033[0m"
RED    = "\033[1;31m"
YELLOW = "\033[1;33m"
GREEN  = "\033[1;32m"
GRAY   = "\033[90m"
SEV_COLOR = {"critical": RED, "high": YELLOW, "medium": YELLOW}


def sev_str(s):
    return f"{SEV_COLOR.get(s, GRAY)}[{s.upper()}]{RESET}"


def load_packages(req_file=None):
    if req_file:
        path = Path(req_file)
        if not path.exists():
            print(f"requirements file not found: {path}", file=sys.stderr)
            sys.exit(2)
        lines = []
        for line in path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and not line.startswith("-"):
                lines.append(line)
        return lines
    else:
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "freeze"],
                capture_output=True, text=True, timeout=30
            )
        except subprocess.TimeoutExpired:
            print("pip freeze timed out", file=sys.stderr)
            sys.exit(2)
        if result.returncode != 0:
            print(f"pip freeze failed: {result.stderr.strip()}", file=sys.stderr)
            sys.exit(2)
        return [l.strip() for l in result.stdout.splitlines() if l.strip()]


def parse_name_version(spec):
    for sep in ("==", ">=", "<=", "~=", "!="):
        if sep in spec:
            parts = spec.split(sep, 1)
            return parts[0].strip().lower(), parts[1].strip() if sep == "==" else None
    return spec.strip().lower(), None


def main():
    import argparse
    parser = argparse.ArgumentParser(description="piplog standalone OSV scanner")
    parser.add_argument("-r", "--requirements", default=None)
    parser.add_argument("--warn-only", action="store_true", help="log but always exit 0")
    parser.add_argument("--json", dest="as_json", action="store_true")
    parser.add_argument("--no-osv", action="store_true", help="skip OSV query (air-gapped builds)")
    args = parser.parse_args()

    packages = load_packages(args.requirements)

    osv_hits: dict[tuple[str, str], list[dict]] = {}
    if not args.no_osv:
        pkg_pairs = []
        for spec in packages:
            name, ver = parse_name_version(spec)
            if ver:
                pkg_pairs.append((name, ver))
        if pkg_pairs:
            osv_hits = _osv_query(pkg_pairs)

    if args.as_json:
        osv_json = [
            {"package": pkg, "version": ver, **v}
            for (pkg, ver), vulns in osv_hits.items()
            for v in vulns
        ]
        print(json.dumps({"osv_hits": osv_json, "osv_count": len(osv_json)}, indent=2))
    else:
        if osv_hits:
            osv_total = sum(len(v) for v in osv_hits.values())
            print(f"\n{RED}⚠  OSV: {osv_total} vuln(s) across {len(osv_hits)} package version(s){RESET}\n" + "="*56)
            for (pkg, ver), vulns in sorted(osv_hits.items()):
                for v in vulns:
                    fix = f"fix: {v['fixed']}" if v["fixed"] else "no fix available"
                    print(f"  {sev_str(v['severity'])}  {pkg}=={ver}  {GRAY}{v['id']}{RESET}")
                    if v["summary"]:
                        print(f"    {v['summary']}")
                    if v["cve"]:
                        print(f"    {v['cve']}  {GRAY}({fix}){RESET}")
                    else:
                        print(f"    {GRAY}({fix}){RESET}")
            print("="*56 + "\n")
        elif not args.no_osv:
            print(f"{GREEN}✓ OSV: no matches ({len(packages)} packages checked).{RESET}")

    if osv_hits and not args.warn_only:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
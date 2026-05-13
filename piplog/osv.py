"""OSV vulnerability database client with SQLite-backed two-level cache.

Level 1 (osv_cache): (package, version) → [vuln_id, ...]  — 6 h TTL
Level 2 (osv_vulns): vuln_id → full vuln record            — no expiry
                                                              (vuln records are stable)
The batch endpoint only returns stubs; full details are fetched per-ID
in parallel via ThreadPoolExecutor so a cold cache stays fast.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL  = "https://api.osv.dev/v1/vulns/{}"
CACHE_TTL     = timedelta(hours=6)
_BATCH_SIZE   = 1000
_FETCH_WORKERS = 10


def query_packages(
    packages: list[tuple[str, str]],
    conn=None,
) -> dict[tuple[str, str], list[dict]]:
    """Query OSV for (name, version) pairs.

    Returns {(name, version): [vuln, ...]} for packages with known
    unpatched vulnerabilities in the queried version. Clean packages
    are omitted from the result but are still cached.

    conn (sqlite3.Connection) enables two-level caching:
    - osv_cache holds (package, version) → vuln IDs, refreshed every 6 h
    - osv_vulns holds per-ID full records, which are stable and never expire
    """
    if not packages:
        return {}

    to_fetch: list[tuple[str, str]] = []
    pkg_vuln_ids: dict[tuple[str, str], list[str]] = {}

    if conn is not None:
        cutoff = (datetime.now(timezone.utc) - CACHE_TTL).isoformat()
        for name, version in packages:
            key = (name.lower(), version)
            row = conn.execute(
                "SELECT vuln_ids FROM osv_cache"
                " WHERE package=? AND version=? AND checked_ts>?",
                (*key, cutoff),
            ).fetchone()
            if row is not None:
                pkg_vuln_ids[key] = json.loads(row["vuln_ids"])
            else:
                to_fetch.append(key)
    else:
        to_fetch = [(n.lower(), v) for n, v in packages]

    # Batch query for (package, version) pairs not in cache
    batch_results = _fetch_osv_batch(to_fetch)

    if conn is not None and to_fetch:
        now = datetime.now(timezone.utc).isoformat()
        for key in to_fetch:
            conn.execute(
                "INSERT OR REPLACE INTO osv_cache"
                " (package, version, checked_ts, vuln_ids) VALUES (?,?,?,?)",
                (*key, now, json.dumps(batch_results.get(key, []))),
            )
        conn.commit()

    pkg_vuln_ids.update(batch_results)

    # Collect unique vuln IDs that need full records
    all_ids = {vid for ids in pkg_vuln_ids.values() for vid in ids}

    vuln_details: dict[str, dict] = {}
    missing_ids: set[str] = set()

    if conn is not None:
        for vid in all_ids:
            row = conn.execute(
                "SELECT vuln_json FROM osv_vulns WHERE id=?", (vid,)
            ).fetchone()
            if row:
                vuln_details[vid] = json.loads(row["vuln_json"])
            else:
                missing_ids.add(vid)
    else:
        missing_ids = all_ids

    if missing_ids:
        fetched = _fetch_vuln_details(missing_ids)
        vuln_details.update(fetched)
        if conn is not None and fetched:
            now = datetime.now(timezone.utc).isoformat()
            for vid, rec in fetched.items():
                conn.execute(
                    "INSERT OR REPLACE INTO osv_vulns (id, fetched_ts, vuln_json)"
                    " VALUES (?,?,?)",
                    (vid, now, json.dumps(rec)),
                )
            conn.commit()

    # Assemble final results
    results: dict[tuple[str, str], list[dict]] = {}
    for key, ids in pkg_vuln_ids.items():
        parsed = [_parse_vuln(vuln_details[vid]) for vid in ids if vid in vuln_details]
        if parsed:
            results[key] = parsed

    return results


def _fetch_osv_batch(
    packages: list[tuple[str, str]],
) -> dict[tuple[str, str], list[str]]:
    """Batch query OSV → returns {(name, version): [vuln_id, ...]} for hits."""
    results: dict[tuple[str, str], list[str]] = {}
    if not packages:
        return results

    for i in range(0, len(packages), _BATCH_SIZE):
        chunk = packages[i : i + _BATCH_SIZE]
        payload = json.dumps({
            "queries": [
                {"package": {"name": n, "ecosystem": "PyPI"}, "version": v}
                for n, v in chunk
            ]
        }).encode()
        req = urllib.request.Request(
            OSV_BATCH_URL,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())
        except (urllib.error.URLError, OSError, json.JSONDecodeError):
            continue

        api_results = data.get("results", [])
        if len(api_results) != len(chunk) and os.environ.get("PIPLOG_DEBUG"):
            print(
                f"[piplog] OSV batch: expected {len(chunk)} results, got {len(api_results)}",
                file=sys.stderr,
            )
        for (name, version), result in zip(chunk, api_results):
            ids = [v["id"] for v in result.get("vulns", []) if v.get("id")]
            if ids:
                results[(name, version)] = ids

    return results


def _fetch_vuln_details(vuln_ids: set[str]) -> dict[str, dict]:
    """Fetch full vuln records in parallel, one GET per ID."""

    def _fetch_one(vid: str) -> tuple[str, dict | None]:
        req = urllib.request.Request(OSV_VULN_URL.format(vid), method="GET")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return vid, json.loads(resp.read())
        except (urllib.error.URLError, OSError, json.JSONDecodeError):
            return vid, None

    details: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=_FETCH_WORKERS) as ex:
        for vid, rec in ex.map(_fetch_one, vuln_ids):
            if rec:
                details[vid] = rec

    return details


def _parse_vuln(v: dict) -> dict:
    cve = next((a for a in v.get("aliases", []) if a.startswith("CVE-")), None)

    db_sev = (v.get("database_specific") or {}).get("severity", "")
    severity = _normalize_severity(db_sev)

    if not severity:
        for s in v.get("severity", []):
            severity = _severity_from_cvss(s.get("score", ""))
            if severity:
                break

    fixed = None
    for affected in v.get("affected", []):
        for r in affected.get("ranges", []):
            if r.get("type") == "ECOSYSTEM":
                for event in r.get("events", []):
                    if "fixed" in event:
                        fixed = event["fixed"]
                        break

    return {
        "id":       v.get("id", ""),
        "cve":      cve,
        "summary":  v.get("summary", ""),
        "severity": severity or "unknown",
        "fixed":    fixed,
    }


def _first_sentence(text: str, max_len: int = 150) -> str:
    """Trim advisory markdown text to a single displayable sentence.

    pip-audit collapses newlines to double-spaces and leads with markdown
    section headers (## Impact, ### Summary).  Strip those before trimming.
    """
    # Drop leading markdown headers (## Impact, ### Summary, etc.)
    text = re.sub(r"^(#+\s+\S+\s+)+", "", text.strip())
    # pip-audit uses double-space as paragraph separator
    text = text.split("  ")[0].strip()
    # Trim at first sentence boundary within max_len
    for sep in (". ", "! ", "? "):
        pos = text.find(sep)
        if 0 < pos < max_len:
            return text[: pos + 1]
    return text[:max_len].rstrip() + ("…" if len(text) > max_len else "")


def _normalize_severity(s: str) -> str:
    return {
        "CRITICAL": "critical",
        "HIGH":     "high",
        "MODERATE": "medium",
        "MEDIUM":   "medium",
        "LOW":      "low",
    }.get(s.upper(), "")


def _severity_from_cvss(vector: str) -> str:
    """Approximate severity from a CVSS v3/v4 vector string."""
    if not vector.startswith("CVSS:"):
        return ""
    highs   = vector.count(":H")
    network = "/AV:N" in vector
    no_priv = "/PR:N" in vector
    if highs >= 3 and network:
        return "critical"
    if highs >= 2 and (network or no_priv):
        return "high"
    if highs >= 1:
        return "medium"
    return "low"


# ── pip-audit backend ─────────────────────────────────────────────────────────

def _pip_audit_exe() -> str | None:
    """Return the pip-audit executable path, or None if not on PATH."""
    return shutil.which("pip-audit")


def _query_via_pip_audit(
    packages: list[tuple[str, str]],
    conn=None,
) -> dict[tuple[str, str], list[dict]] | None:
    """Run pip-audit for detection, enrich severity from the OSV vuln cache.

    Returns None if pip-audit is unavailable or fails, so the caller can
    fall back to query_packages().
    """
    exe = _pip_audit_exe()
    if not exe:
        return None

    req_fd, req_path = tempfile.mkstemp(suffix=".txt", prefix="piplog-audit-")
    try:
        with os.fdopen(req_fd, "w") as f:
            for name, version in packages:
                f.write(f"{name}=={version}\n")

        try:
            result = subprocess.run(
                [exe, "--format=json", "--no-deps", "-r", req_path],
                capture_output=True, text=True, timeout=120,
            )
        except subprocess.TimeoutExpired:
            return None
    finally:
        os.unlink(req_path)

    # pip-audit exits 1 when vulnerabilities are found — that's not a failure
    if result.returncode not in (0, 1):
        return None

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None

    # Parse — deduplicate by ID (pip-audit can return the same ID from both
    # the PyPA and GHSA sources in the same run)
    raw: dict[tuple[str, str], dict[str, dict]] = {}
    for dep in data.get("dependencies", []):
        key = (dep["name"].lower(), dep["version"])
        seen: set[str] = set()
        for v in dep.get("vulns", []):
            vid = v["id"]
            if vid in seen:
                continue
            seen.add(vid)
            cve  = next((a for a in v.get("aliases", []) if a.startswith("CVE-")), None)
            ghsa = next((a for a in v.get("aliases", []) if a.startswith("GHSA-")), None)
            if cve is None and vid.startswith("CVE-"):
                cve = vid
            fix  = v["fix_versions"][0] if v.get("fix_versions") else None
            raw.setdefault(key, {})[vid] = {
                "id": vid, "cve": cve, "ghsa": ghsa,
                "summary": _first_sentence(v.get("description") or ""),
                "severity": "unknown", "fixed": fix,
            }

    if not raw:
        return {}

    # Enrich severity: look up each GHSA alias in the OSV vuln cache, fetching
    # any that are missing.  This gives us database_specific.severity without
    # re-running the full OSV flow.
    ghsa_ids = {v["ghsa"] for vulns in raw.values() for v in vulns.values() if v["ghsa"]}
    if ghsa_ids:
        details: dict[str, dict] = {}
        missing: set[str] = set()
        if conn is not None:
            for gid in ghsa_ids:
                row = conn.execute(
                    "SELECT vuln_json FROM osv_vulns WHERE id=?", (gid,)
                ).fetchone()
                if row:
                    details[gid] = json.loads(row["vuln_json"])
                else:
                    missing.add(gid)
        else:
            missing = ghsa_ids

        if missing:
            fetched = _fetch_vuln_details(missing)
            details.update(fetched)
            if conn is not None and fetched:
                now = datetime.now(timezone.utc).isoformat()
                for gid, rec in fetched.items():
                    conn.execute(
                        "INSERT OR REPLACE INTO osv_vulns (id, fetched_ts, vuln_json)"
                        " VALUES (?,?,?)",
                        (gid, now, json.dumps(rec)),
                    )
                conn.commit()

        for vulns in raw.values():
            for v in vulns.values():
                if not v["ghsa"] or v["ghsa"] not in details:
                    continue
                rec = details[v["ghsa"]]
                db_sev = (rec.get("database_specific") or {}).get("severity", "")
                sev = _normalize_severity(db_sev)
                if not sev:
                    for s in rec.get("severity", []):
                        sev = _severity_from_cvss(s.get("score", ""))
                        if sev:
                            break
                v["severity"] = sev or "unknown"

    # Deduplicate across IDs by CVE: prefer the GHSA entry (richer metadata)
    # over the PYSEC mirror of the same CVE.
    results: dict[tuple[str, str], list[dict]] = {}
    for key, vulns in raw.items():
        cve_seen: dict[str, dict] = {}
        unique: list[dict] = []
        for v in vulns.values():
            if v["cve"]:
                if v["cve"] not in cve_seen:
                    cve_seen[v["cve"]] = v
                    unique.append(v)
                elif v["ghsa"] and not cve_seen[v["cve"]]["ghsa"]:
                    # Replace PYSEC duplicate with richer GHSA entry
                    unique = [x for x in unique if x.get("cve") != v["cve"]]
                    unique.append(v)
                    cve_seen[v["cve"]] = v
            else:
                unique.append(v)
        if unique:
            results[key] = [
                {"id": v["id"], "cve": v["cve"], "summary": v["summary"],
                 "severity": v["severity"], "fixed": v["fixed"]}
                for v in unique
            ]

    return results


def query_preferred(
    packages: list[tuple[str, str]],
    conn=None,
) -> dict[tuple[str, str], list[dict]]:
    """Query with pip-audit when available, falling back to our OSV client.

    pip-audit is preferred for CLI scan commands because it handles PURL
    normalisation and advisory source merging more robustly than our client.
    The shim and docker-scan use query_packages() directly so they stay
    dependency-free.
    """
    result = _query_via_pip_audit(packages, conn)
    if result is not None:
        return result
    return query_packages(packages, conn)

"""OSV vulnerability database client with SQLite-backed cache.

Queries https://api.osv.dev/v1/querybatch for PyPI packages.
Results are cached per (package, version) for 24 hours so repeated
scans (shim, piplog scan --osv, docker-scan) stay cheap.
"""
import json
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
CACHE_TTL = timedelta(hours=6)
_BATCH_SIZE = 1000  # OSV API limit per request


def query_packages(
    packages: list[tuple[str, str]],
    conn=None,
) -> dict[tuple[str, str], list[dict]]:
    """Query OSV for (name, version) pairs.

    Returns {(name, version): [vuln, ...]} for packages with known
    unpatched vulnerabilities. Packages with no hits are omitted.

    If conn (sqlite3.Connection) is provided, results are cached in the
    osv_cache table and stale entries are re-fetched automatically.
    """
    if not packages:
        return {}

    to_fetch: list[tuple[str, str]] = []
    results: dict[tuple[str, str], list[dict]] = {}

    if conn is not None:
        cutoff = (datetime.now(timezone.utc) - CACHE_TTL).isoformat()
        for name, version in packages:
            key = (name.lower(), version)
            row = conn.execute(
                "SELECT vulns_json FROM osv_cache"
                " WHERE package=? AND version=? AND checked_ts>?",
                (*key, cutoff),
            ).fetchone()
            if row is not None:
                vulns = json.loads(row["vulns_json"])
                if vulns:
                    results[key] = vulns
            else:
                to_fetch.append(key)
    else:
        to_fetch = [(n.lower(), v) for n, v in packages]

    fetched = _fetch_osv_batch(to_fetch)

    if conn is not None and to_fetch:
        now = datetime.now(timezone.utc).isoformat()
        for key in to_fetch:
            conn.execute(
                "INSERT OR REPLACE INTO osv_cache"
                " (package, version, checked_ts, vulns_json) VALUES (?,?,?,?)",
                (*key, now, json.dumps(fetched.get(key, []))),
            )
        conn.commit()

    results.update(fetched)
    return results


def _fetch_osv_batch(
    packages: list[tuple[str, str]],
) -> dict[tuple[str, str], list[dict]]:
    results: dict[tuple[str, str], list[dict]] = {}
    if not packages:
        return results

    for i in range(0, len(packages), _BATCH_SIZE):
        chunk = packages[i : i + _BATCH_SIZE]
        payload = json.dumps({
            "queries": [
                {"package": {"name": name, "ecosystem": "PyPI"}, "version": version}
                for name, version in chunk
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

        for (name, version), result in zip(chunk, data.get("results", [])):
            vulns = [_parse_vuln(v) for v in result.get("vulns", [])]
            if vulns:
                results[(name, version)] = vulns

    return results


def _parse_vuln(v: dict) -> dict:
    cve = next((a for a in v.get("aliases", []) if a.startswith("CVE-")), None)

    # PyPA/GHSA advisories often carry a plain severity string here
    db_sev = (v.get("database_specific") or {}).get("severity", "")
    severity = _normalize_severity(db_sev)

    # Fall back to approximating from the CVSS vector
    if not severity:
        for s in v.get("severity", []):
            severity = _severity_from_cvss(s.get("score", ""))
            if severity:
                break

    # Earliest fix version across all affected ranges
    fixed = None
    for affected in v.get("affected", []):
        for r in affected.get("ranges", []):
            if r.get("type") == "ECOSYSTEM":
                for event in r.get("events", []):
                    if "fixed" in event:
                        fixed = event["fixed"]
                        break

    return {
        "id": v.get("id", ""),
        "cve": cve,
        "summary": v.get("summary", ""),
        "severity": severity or "unknown",
        "fixed": fixed,
    }


def _normalize_severity(s: str) -> str:
    return {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MODERATE": "medium",
        "MEDIUM": "medium",
        "LOW": "low",
    }.get(s.upper(), "")


def _severity_from_cvss(vector: str) -> str:
    """Approximate severity from a CVSS v3/v4 vector string.

    Full CVSS calculation requires a library; this heuristic covers the
    common high-severity patterns well enough for a warning display.
    """
    if not vector.startswith("CVSS:"):
        return ""
    highs = vector.count(":H")
    network = "/AV:N" in vector
    no_priv = "/PR:N" in vector
    if highs >= 3 and network:
        return "critical"
    if highs >= 2 and (network or no_priv):
        return "high"
    if highs >= 1:
        return "medium"
    return "low"

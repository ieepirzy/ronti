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
from pathlib import Path

# ── embedded advisory list ────────────────────────────────────────────────────
# Keep this in sync with piplog/db.py BUILTIN_ADVISORIES.
# Format: (package, bad_version_or_None, severity, description, cve_or_None)
ADVISORIES = [
    ("litellm",        "1.82.7",  "critical", "TeamPCP credential stealer via Trivy CI compromise",          "CVE-2026-33634"),
    ("litellm",        "1.82.8",  "critical", "TeamPCP credential stealer, .pth persistence variant",        "CVE-2026-33634"),
    ("telnyx",         "4.87.1",  "high",     "TeamPCP backdoor injected via stolen PyPI token",             None),
    ("telnyx",         "4.87.2",  "high",     "TeamPCP backdoor injected via stolen PyPI token",             None),
    ("lightning",      "2.6.2",   "critical", "Mini Shai-Hulud: credential stealer + JS payload on import",  None),
    ("lightning",      "2.6.3",   "critical", "Mini Shai-Hulud: credential stealer + JS payload on import",  None),
    ("mistralai",      "2.4.6",   "critical", "Shai-Hulud: imports transformers.pyz from 83.142.209.194",    None),
    ("guardrails-ai",  None,      "high",     "Shai-Hulud wave: verify version against current advisories",  None),
    ("dydx-v4-client", None,      "high",     "Wallet stealer + RAT, verify installed version",              None),
]

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
        result = subprocess.run(
            [sys.executable, "-m", "pip", "freeze"],
            capture_output=True, text=True
        )
        return [l.strip() for l in result.stdout.splitlines() if l.strip()]


def parse_name_version(spec):
    for sep in ("==", ">=", "<=", "~=", "!="):
        if sep in spec:
            parts = spec.split(sep, 1)
            return parts[0].strip().lower(), parts[1].strip() if sep == "==" else None
    return spec.strip().lower(), None


def main():
    import argparse
    parser = argparse.ArgumentParser(description="piplog standalone advisory scanner")
    parser.add_argument("-r", "--requirements", default=None)
    parser.add_argument("--warn-only", action="store_true", help="log but always exit 0")
    parser.add_argument("--json", dest="as_json", action="store_true")
    args = parser.parse_args()

    packages = load_packages(args.requirements)
    adv_index = {}
    for pkg, ver, sev, desc, cve in ADVISORIES:
        adv_index.setdefault(pkg.lower(), []).append((ver, sev, desc, cve))

    hits = []
    for spec in packages:
        name, installed_ver = parse_name_version(spec)
        if name in adv_index:
            for bad_ver, sev, desc, cve in adv_index[name]:
                if bad_ver is None or bad_ver == installed_ver:
                    hits.append({
                        "package": name,
                        "version": installed_ver or "unknown",
                        "severity": sev,
                        "description": desc,
                        "cve": cve,
                    })

    if args.as_json:
        print(json.dumps({"hits": hits, "count": len(hits)}, indent=2))
    elif not hits:
        print(f"{GREEN}✓ piplog-docker-scan: no advisory matches ({len(packages)} packages checked).{RESET}")
    else:
        print(f"\n{RED}⚠  piplog-docker-scan: {len(hits)} advisory match(es){RESET}\n" + "="*56)
        for h in hits:
            ver_str = f"=={h['version']}" if h["version"] != "unknown" else ""
            print(f"  {sev_str(h['severity'])}  {h['package']}{ver_str}")
            print(f"    {h['description']}")
            if h["cve"]:
                print(f"    {h['cve']}")
        print("="*56 + "\n")

    if hits and not args.warn_only:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
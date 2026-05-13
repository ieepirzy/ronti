# piplog

System-wide pip install audit logger with advisory scanning. Catches installs
across all users, all venvs, and flags known-malicious packages at install time.

## Install (as root)

```bash
sudo bash install.sh
```

This:
- Installs piplog system-wide
- Creates `/var/lib/piplog/audit.db` (sticky 1777 — all users write, no clobber)
- Replaces `/usr/local/bin/pip` and `/usr/local/bin/pip3` with the logging shim
- Backs up the real pip to `/usr/local/bin/.pip-real`
- Seeds the advisory database with current known-bad packages
- Sets `PIPLOG_DB` in `/etc/environment`

## Usage

```bash
# list recent installs (all users)
piplog list
piplog list litellm

# scan install history against advisory database
piplog scan
piplog scan --fail          # exit 1 if hits found (for CI)

# show dependency tree for a package (at install time)
piplog tree litellm

# version history for a package
piplog diff requests

# installs grouped by git repo context
piplog repos

# advisory database
piplog advisory list
piplog advisory add <package> --version 1.2.3 --severity critical --description "..."

# inject hook into a specific venv
piplog inject-venv /path/to/.venv
```

## Docker

Copy `piplog-docker-scan.py` into your image and run after `pip install`:

```dockerfile
COPY piplog-docker-scan.py /usr/local/bin/piplog-docker-scan
RUN pip install -r requirements.txt && \
    python /usr/local/bin/piplog-docker-scan -r requirements.txt
```

Exit 0 = clean. Exit 1 = advisory match (fails the build).
Use `--warn-only` to log without failing.
Use `--json` for machine-readable output.

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `PIPLOG_DB` | `/var/lib/piplog/audit.db` | Path to SQLite database |
| `PIPLOG_DISABLE` | unset | Set to `1` to bypass logging |
| `PIPLOG_REAL_PIP` | `/usr/local/bin/.pip-real` | Path to real pip binary |
| `PIPLOG_DEBUG` | unset | Set to `1` for shim debug output |

## Schema

```
installs  — one row per pip install invocation
  id, ts, package, version, wheel_hash,
  installer, invoked_by, cwd, argv,
  venv_path, site_packages,
  git_remote, git_branch,
  uid, username

deps      — dependency tree at install time
  install_id → installs.id
  dep_name, dep_version, dep_extras

advisories — known-bad packages
  package, bad_version (NULL = any), severity,
  description, cve, added_ts
```

## Current advisory list (13.05.2026)

| Package | Bad versions | Severity | Campaign |
|---|---|---|---|
| litellm | 1.82.7, 1.82.8 | critical | TeamPCP / Trivy CI compromise |
| telnyx | 4.87.1, 4.87.2 | high | TeamPCP |
| lightning | 2.6.2, 2.6.3 | critical | Mini Shai-Hulud |
| mistralai | 2.4.6 | critical | Shai-Hulud: Here We Go Again |
| guardrails-ai | any | high | Shai-Hulud wave |
| dydx-v4-client | any | high | Wallet stealer + RAT |
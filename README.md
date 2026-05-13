# rönti

System-wide pip install audit logger with OSV vulnerability scanning. Intercepts
every `pip install`, logs it to a local SQLite database, and alerts on known
vulnerabilities at install time.

## Install

rönti must be installed **system-wide** (into `/usr/local/bin`) so that `sudo`
can find it and the pip shim is on everyone's PATH:

```bash
sudo pip install ronti --break-system-packages
sudo ronti setup
```

`setup` is interactive — it will ask before touching your group membership and
offer to switch your session immediately. It is safe to re-run; all steps are
idempotent.

**Non-interactive / CI / Docker:**

```bash
sudo pip install ronti --break-system-packages
sudo ronti setup --non-interactive
```

`--non-interactive` is also activated automatically when there is no TTY (piped
install, CI pipeline, Docker build).

### What setup does

| Step | Detail |
| --- | --- |
| Creates `ronti` group | Shared write access to the audit DB |
| Creates `/var/lib/ronti/` | `root:ronti 2775` — new files inherit group |
| Initialises `audit.db` | `root:ronti 660` — only group members read/write |
| Installs pip shim | Backs up real pip to `.pip-real`, drops shim at `/usr/local/bin/pip` and `pip3` |
| Sets `RONTI_DB` | Appended to `/etc/environment` for all users |
| Adds you to `ronti` group | Optional — prompted interactively |

### Source install

```bash
git clone https://github.com/you/ronti
sudo bash ronti/ronti/setup.sh
```

### Per-venv hook

The pip shim only covers the system pip. To also log installs inside a specific
venv:

```bash
ronti inject-venv /path/to/.venv
```

## How it works

Once the shim is active, every `pip install` is intercepted automatically — no
need to run `ronti scan` for new packages. The shim:

1. **Pre-install:** queries OSV for any pinned (`==`) packages before pip runs,
   warning if a vulnerable version is about to be installed.
2. **Runs pip** as normal.
3. **Post-install:** logs the install (package, version, user, cwd, git context,
   dep tree) to the SQLite database, then batch-queries OSV for the full
   transitive dependency tree.

`ronti scan` and `ronti osv-scan` are for **retrospective** checks of the
install history database.

## Usage

```bash
# List recent installs (all users)
ronti list
ronti list requests            # filter by package name

# Scan history against your local advisory database
ronti scan
ronti scan --osv               # also query OSV (requires network)
ronti scan --fail              # exit 1 if any hits (CI gate)

# OSV scan of all recorded installs
ronti osv-scan
ronti osv-scan --fail

# Dependency tree recorded at install time
ronti tree requests

# Version history for a package
ronti diff requests

# Installs grouped by git repo
ronti repos

# Advisory database (user-managed, in addition to live OSV)
ronti advisory list
ronti advisory add <package> --version 1.2.3 --severity critical --description "..."

# Inject hook into a specific venv
ronti inject-venv /path/to/.venv
```

## Docker

Use the CLI `docker-scan` subcommand in your `Dockerfile`:

```dockerfile
RUN pip install ronti --break-system-packages
RUN pip install -r requirements.txt && ronti docker-scan -r requirements.txt
```

Or copy the zero-dependency standalone script (`ronti/docker_scan.py`) if you
do not want rönti in the image at all:

```dockerfile
COPY ronti/docker_scan.py /usr/local/bin/ronti-docker-scan
RUN pip install -r requirements.txt && \
    python /usr/local/bin/ronti-docker-scan -r requirements.txt
```

Exit 0 = clean. Exit 1 = vulnerability found (fails the build).
Use `--warn-only` to log without failing the build.
Use `--json` for machine-readable output.
Use `--no-osv` for air-gapped builds.

## Environment variables

| Variable | Default | Description |
| --- | --- | --- |
| `RONTI_DB` | `/var/lib/ronti/audit.db` | Path to SQLite database |
| `RONTI_DISABLE` | unset | Set to `1` to bypass the shim entirely |
| `RONTI_DEBUG` | unset | Set to `1` for verbose shim/OSV output |

## Schema

```text
installs  — one row per pip install invocation
  id, ts, package, version, wheel_hash,
  installer, invoked_by, cwd, argv,
  venv_path, site_packages,
  git_remote, git_branch,
  uid, username

deps      — dependency tree recorded at install time
  install_id → installs.id
  dep_name, dep_version, dep_extras

advisories — user-managed known-bad packages (OSV is the primary source)
  package, bad_version (NULL = any version), severity,
  description, cve, added_ts

osv_cache  — (package, version) → vuln IDs, 6 h TTL
osv_vulns  — vuln ID → full record, no expiry
```

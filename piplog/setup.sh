#!/usr/bin/env bash
set -euo pipefail

# piplog install script
# Run as root: sudo bash install.sh

if [[ $EUID -ne 0 ]]; then
    echo "Run as root: sudo bash piplog/setup.sh"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_DIR="/var/lib/piplog"
INSTALL_DIR="/usr/local/lib/piplog"

echo "==> Installing piplog..."

# 1. Install Python package system-wide
python3 -m pip install -e "$SCRIPT_DIR" --quiet --break-system-packages

# 2. Create DB directory and dedicated group for shared access
groupadd -f piplog
mkdir -p "$DB_DIR"
chown root:piplog "$DB_DIR"
chmod 2775 "$DB_DIR"          # setgid: new files inherit piplog group
echo "    DB dir: $DB_DIR (root:piplog 2775)"

# 3. Initialize the DB as root so schema + advisories are seeded
python3 -c "from piplog.db import init_db; init_db()"
chown root:piplog "$DB_DIR/audit.db"
chmod 660 "$DB_DIR/audit.db"  # only root and piplog group members can read/write
echo "    DB initialized: $DB_DIR/audit.db (root:piplog 660)"
echo ""
echo "    IMPORTANT: add each user to the piplog group so their installs are logged:"
echo "    sudo usermod -aG piplog <username>  (user must re-login)"

# 4. Install pip shim
python3 -m piplog install-shim
echo "    pip shim installed"

# 5. Set PIPLOG_DB for all users via /etc/environment
if ! grep -q "PIPLOG_DB" /etc/environment 2>/dev/null; then
    echo "PIPLOG_DB=/var/lib/piplog/audit.db" >> /etc/environment
    echo "    Added PIPLOG_DB to /etc/environment"
fi

echo ""
echo "==> Done. piplog is active for all users."
echo "    Test: pip install requests  (then: piplog scan)"
echo "    Advisory list: piplog advisory list"
echo "    Inject into a venv: piplog inject-venv /path/to/.venv"
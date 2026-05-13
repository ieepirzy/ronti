#!/usr/bin/env bash
set -euo pipefail

# rönti install script — for source installs only.
# PyPI users: pip install ronti --break-system-packages && sudo ronti setup

if [[ $EUID -ne 0 ]]; then
    echo "Run as root: sudo bash ronti/setup.sh"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> Installing rönti from source..."
python3 -m pip install -e "$SCRIPT_DIR/.." --quiet --break-system-packages

echo "==> Running system setup..."
ronti setup "$@"

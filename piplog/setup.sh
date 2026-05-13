#!/usr/bin/env bash
set -euo pipefail

# piplog install script — for source installs only.
# PyPI users: pip install piplog --break-system-packages && sudo piplog setup

if [[ $EUID -ne 0 ]]; then
    echo "Run as root: sudo bash piplog/setup.sh"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> Installing piplog from source..."
python3 -m pip install -e "$SCRIPT_DIR/.." --quiet --break-system-packages

echo "==> Running system setup..."
piplog setup "$@"

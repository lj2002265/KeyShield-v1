#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
export PYTHONPATH=""
if [ ! -x .venv/bin/python ]; then
  python3 -c 'import sys; assert sys.version_info >= (3,10)'
  python3 -m venv .venv
fi
.venv/bin/python -m pip install -r requirements-lock.txt
exec .venv/bin/python desktop_launcher.py --serve

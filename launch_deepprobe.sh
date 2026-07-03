#!/usr/bin/env sh
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR"

if command -v python3 >/dev/null 2>&1; then
  exec python3 ./network_mapper.py
fi

if command -v python >/dev/null 2>&1; then
  exec python ./network_mapper.py
fi

echo "DeepProbe could not start. Install Python 3 with tkinter support, then run ./launch_deepprobe.sh." >&2
exit 1

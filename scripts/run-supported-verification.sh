#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PYTHON_BIN=${PYTHON_BIN:-python3}
SCRATCH_ROOT=${TMPDIR:-/tmp}
WORKSPACE=$(mktemp -d "$SCRATCH_ROOT/easter-supported-verification.XXXXXX")

cleanup() {
    rm -rf "$WORKSPACE"
}
trap cleanup EXIT HUP INT TERM

command -v git >/dev/null 2>&1 || {
    echo "ERROR: git is required" >&2
    exit 2
}
command -v sqlite3 >/dev/null 2>&1 || {
    echo "ERROR: sqlite3 CLI is required" >&2
    exit 2
}
command -v "$PYTHON_BIN" >/dev/null 2>&1 || {
    echo "ERROR: Python executable not found: $PYTHON_BIN" >&2
    exit 2
}

"$PYTHON_BIN" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 14) else 1)' || {
    echo "ERROR: the supported verification environment requires CPython 3.14" >&2
    echo "Set PYTHON_BIN to a CPython 3.14 executable." >&2
    exit 2
}

mkdir -p "$WORKSPACE/repo"
git -C "$ROOT" archive HEAD | tar -x -C "$WORKSPACE/repo"

"$PYTHON_BIN" -m venv "$WORKSPACE/venv"
"$WORKSPACE/venv/bin/python" -m pip install \
    --disable-pip-version-check \
    -r "$WORKSPACE/repo/requirements-mcp.txt"

"$WORKSPACE/venv/bin/python" \
    "$WORKSPACE/repo/scripts/run_supported_suite.py"

"""The supported-suite runner must never execute tests with asserts disabled."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent

environment = os.environ.copy()
environment["PYTHONOPTIMIZE"] = "1"
result = subprocess.run(
    [sys.executable, str(REPO / "scripts" / "run_supported_suite.py")],
    cwd=REPO,
    env=environment,
    text=True,
    capture_output=True,
    timeout=30,
)

assert result.returncode == 2, result
assert "optimized Python disables assertion-based checks" in result.stderr, result.stderr
assert "PASS" not in result.stdout, result.stdout

print("harness_0_1_pythonoptimize: OK")

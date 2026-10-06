"""GATEWAY-2: the Enterprise token-verification hook in gateway.py must
be importable and runnable with zero dependency on the (private, paid)
EASTER Enterprise broker package, and must fail clearly -- not with a
bare ``ModuleNotFoundError`` -- if ``--issuance-db`` is passed without
that package installed.

This supersedes an earlier, now-abandoned approach (a Dockerfile
``COPY broker/`` + unconditional module-level import of
``broker.tokens``/``broker.reader``) that briefly lived on the
now-superseded ``feature/enterprise-token-broker`` PR. Codex's cold
review of that PR (independently verified by Pax) found the
unconditional import meant the *usage* of the Ed25519 token path was
optional via ``--issuance-db``, but the *import* was not -- the
containerized public gateway would die at startup with
``ModuleNotFoundError: No module named 'broker'`` even when the
Enterprise path was never configured. Rather than ship the Enterprise
broker package inside the public image (which would mean paid product
code living in an open-source repo), the fix made the import lazy:
``gateway.py``'s ``make_app`` only imports ``broker.tokens``/
``broker.reader`` inside the branch gated on ``issuance_db is not
None``. This test proves that fix two ways:

1. ``import gateway`` succeeds from this repository alone -- there is
   no ``broker/`` directory anywhere in this checkout, so if the
   import were still unconditional this would already fail.
2. Running ``gateway.py serve --issuance-db <path> ...`` in a
   subprocess (still with no ``broker/`` present) exits nonzero with a
   message naming the EASTER Enterprise package as the missing
   requirement, not a raw traceback.

Not part of the counted supported suite (not wired into
``scripts/run_supported_suite.py``'s ``SUPPORTED_TESTS``): like
``tests/gateway_0_1_skeleton.py``, this is a real, run but
separately-reported structural check rather than an artifact-boundary
script with isolated per-run fixtures. See ``docs/verification.md``'s
"Historical and non-suite boundary" section.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent


def main() -> None:
    assert not (HERE / "broker").exists(), (
        "this test's premise is that no broker/ package exists in this "
        "checkout -- if that ever changes, this test is no longer "
        "proving what it claims to prove"
    )

    import_result = subprocess.run(
        [sys.executable, "-c", "import gateway"],
        cwd=str(HERE),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert import_result.returncode == 0, (
        "gateway.py must import with zero broker/ package present -- the "
        f"Enterprise hook's import must be lazy.\nstdout:\n{import_result.stdout}"
        f"\nstderr:\n{import_result.stderr}"
    )

    # --cert/--key are only checked for existence (not validity) before
    # --issuance-db's branch runs, and MCPBackend's constructor does no
    # I/O -- so empty placeholder files are enough to reach make_app()
    # and trigger the lazy import's failure, well before uvicorn.run()
    # would ever try to bind a port.
    with tempfile.NamedTemporaryFile(suffix=".pem") as cert, \
            tempfile.NamedTemporaryFile(suffix=".pem") as key:
        serve_result = subprocess.run(
            [
                sys.executable,
                "gateway.py",
                "serve",
                "--cert",
                cert.name,
                "--key",
                key.name,
                "--kernel-db",
                "/tmp/does-not-matter-kernel.db",
                "--issuance-db",
                "/tmp/does-not-matter-issuance.db",
            ],
            cwd=str(HERE),
            capture_output=True,
            text=True,
            timeout=30,
        )

    assert serve_result.returncode != 0, (
        "--issuance-db without the Enterprise package installed must fail, "
        f"not silently start.\nstdout:\n{serve_result.stdout}\nstderr:\n{serve_result.stderr}"
    )
    assert "ModuleNotFoundError" not in serve_result.stderr, (
        "a missing Enterprise package must surface as a clear, named "
        "SystemExit message, not a bare traceback -- this is exactly the "
        f"containerized-startup failure Codex's review flagged.\n{serve_result.stderr}"
    )
    assert "EASTER Enterprise" in serve_result.stderr, (
        "the failure message must name the Enterprise package as the "
        f"requirement.\nstderr:\n{serve_result.stderr}"
    )

    print("gateway_2_enterprise_hook_lazy_import: OK")


if __name__ == "__main__":
    main()

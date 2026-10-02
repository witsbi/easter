#!/usr/bin/env python3
"""Run the supported EASTER verification scripts against isolated fixtures."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
EXPECTED_PASS_COUNT = 32
TEST_TIMEOUT_SECONDS = 180

# Each script receives a newly initialized database. "authority" additionally
# creates the stable identity/Authority prerequisites those two focused tests
# require; no generated identifier is shared between scripts.
SUPPORTED_TESTS = (
    ("tests/harness_0_1_pythonoptimize.py", "base"),
    ("tests/initialize_test.py", "base"),
    ("tests/authority_2_ordering_and_scope.py", "authority"),
    ("tests/authority_3_root_model.py", "authority"),
    ("tests/receipt_2_minimality.py", "base"),
    ("tests/receipt_3_operation_id_uniqueness.py", "base"),
    ("tests/state_1_invariants.py", "base"),
    ("tests/evidence_1_lifecycle.py", "base"),
    ("tests/exception_1_attacks.py", "base"),
    ("tests/whole_kernel_concurrency.py", "base"),
    ("tests/whole_kernel_long_history.py", "base"),
    ("tests/whole_kernel_part_c.py", "base"),
    ("tests/mcp_0_1_vertical_slice.py", "base"),
    ("tests/mcp_0_2_authority_boundary.py", "base"),
    ("tests/mcp_0_3_no_direct_sqlite.py", "base"),
    ("tests/mcp_0_4_v0_2_observability.py", "base"),
    ("tests/api_0_1_http_adapter.py", "base"),
    ("tests/api_0_2_csrf_origin_protection.py", "base"),
    ("tests/api_0_3_no_direct_kernel_access.py", "base"),
    ("tests/api_0_4_pagination_cursor_roundtrip.py", "base"),
    ("tests/api_0_5_openapi_contract.py", "base"),
    ("tests/api_0_6_loopback_launch_contract.py", "base"),
    ("tests/api_0_7_revoke_grant_id_single_representation.py", "base"),
    ("tests/console_0_1_genesis_and_inspection.py", "base"),
    ("tests/console_0_2_grant_lifecycle.py", "base"),
    ("tests/console_0_3_confirmation_gate.py", "base"),
    ("tests/console_0_4_no_direct_kernel_access.py", "base"),
    ("tests/console_0_5_csrf_origin_protection.py", "base"),
    ("tests/console_0_6_malformed_json_payload.py", "base"),
    ("tests/console_0_7_v0_2_observability.py", "base"),
    ("tests/console_0_8_human_participant_records.py", "base"),
    ("tests/v0_2_observability_1_focused.py", "base"),
)

AUTHORITY_FIXTURE = """\
from kernel import Kernel

kernel = Kernel()
kernel.transition(
    requester_identity_id="identity:nathan",
    from_state_id="state:genesis",
    authority_grant_id="grant:genesis-root",
    new_state_payload={"fixture": "supported-verification"},
    new_identities=[{
        "identity_id": "identity:clawde",
        "payload": {"role": "verification-fixture"},
    }],
)
kernel.define_authority(
    requester_identity_id="identity:nathan",
    authority_grant_id="grant:genesis-root",
    authority_id="authority:clawde-scope-alpha",
    payload={"fixture": "supported-verification"},
)
"""


def run_checked(command: list[str], *, capture: bool = True) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment.pop("PYTHONOPTIMIZE", None)
    environment["PYTHONPATH"] = str(REPO)
    return subprocess.run(
        command,
        cwd=REPO,
        env=environment,
        text=True,
        capture_output=capture,
        timeout=TEST_TIMEOUT_SECONDS,
        check=True,
    )


def reset_fixture(profile: str) -> None:
    data = REPO / "data"
    if data.exists():
        shutil.rmtree(data)
    data.mkdir()
    run_checked(
        [sys.executable, "initialize.py", "data/kernel.db", "identity:nathan"]
    )
    if profile == "authority":
        run_checked([sys.executable, "-c", AUTHORITY_FIXTURE])


def main() -> int:
    if sys.flags.optimize:
        print(
            "HARNESS ERROR: optimized Python disables assertion-based checks; "
            "rerun without -O/-OO or PYTHONOPTIMIZE",
            file=sys.stderr,
        )
        return 2

    if len(SUPPORTED_TESTS) != EXPECTED_PASS_COUNT:
        print(
            "HARNESS ERROR: declared expected count "
            f"{EXPECTED_PASS_COUNT} != configured count {len(SUPPORTED_TESTS)}",
            file=sys.stderr,
        )
        return 2

    print(f"EASTER supported verification: {EXPECTED_PASS_COUNT} scripts")
    print(f"Python: {sys.version.split()[0]}")

    for index, (script, fixture) in enumerate(SUPPORTED_TESTS, start=1):
        label = f"[{index:02d}/{EXPECTED_PASS_COUNT}]"
        try:
            reset_fixture(fixture)
            result = run_checked([sys.executable, script])
        except subprocess.TimeoutExpired:
            print(f"{label} FAIL {script} (timeout after {TEST_TIMEOUT_SECONDS}s)")
            return 1
        except subprocess.CalledProcessError as exc:
            print(f"{label} FAIL {script}")
            if exc.stdout:
                print("--- stdout ---")
                print(exc.stdout, end="" if exc.stdout.endswith("\n") else "\n")
            if exc.stderr:
                print("--- stderr ---", file=sys.stderr)
                print(
                    exc.stderr,
                    end="" if exc.stderr.endswith("\n") else "\n",
                    file=sys.stderr,
                )
            return 1
        else:
            print(f"{label} PASS {script}")
            del result

    print(f"RESULT: PASS ({EXPECTED_PASS_COUNT}/{EXPECTED_PASS_COUNT} scripts)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

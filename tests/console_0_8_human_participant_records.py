"""EASTER-CONSOLE-0 verification: first-party human participant records.

Nathan-as-participant (not root-as-governor) records Evidence, records a
human decision, and proposes a Transition through the Console's real HTML
forms -- the same forms Nathan himself would submit in a browser.

Proves:
  1. record_evidence works through the Console with a NON-ROOT grant
     held by identity:nathan (participant role, not root role).
  2. The kernel-authored receipt attributes the record to
     identity:nathan (caused_by_identity_id) -- first-party
     provenance with no agent intermediary in the loop.
  3. The decision form projects to record_evidence with the
     human_decision payload convention; the kernel stores opaque JSON
     (no normative vote/approval semantics below the Console).
  4. transition works through the Console with the same non-root
     grant, including evidence association; receipt attributes nathan.
  5. Authority is still enforced through these forms: a grant the
     requester does not hold, and a grant that does not exist, are
     both rejected by the Kernel (no Console bypass).
  6. Malformed JSON is rejected by the Console before MCP is contacted.
  7. Cross-origin POSTs to the new endpoints are rejected by the
     Console before MCP is contacted.

All Console actions go through the real HTML forms (POST,
url-encoded, exactly what a browser would send). Attribution is
verified through an independent MCP client reading kernel-authored
receipts -- the Console's word is not taken for who caused what.
"""

from __future__ import annotations

import asyncio
import html
import http.client
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path
from typing import Any

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

HERE = Path(__file__).resolve().parent.parent
ROOT = "grant:genesis-root"
NATHAN = "identity:nathan"
GENESIS = "state:genesis"
OTHER = "identity:console-0-8-other"

PRE_BLOCK_RE = re.compile(r"<pre>(.*?)</pre>", re.DOTALL)
EVIL_ORIGIN = "https://evil.example"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for_console(port: int, timeout: float = 15.0) -> None:
    deadline = time.time() + timeout
    last_exc: Exception | None = None
    while time.time() < deadline:
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
            conn.request("GET", "/")
            resp = conn.getresponse()
            resp.read()
            conn.close()
            if resp.status == 200:
                return
        except OSError as exc:
            last_exc = exc
        time.sleep(0.1)
    raise TimeoutError(f"console did not become ready on port {port}: {last_exc}")


def http_post_form(
    port: int,
    path: str,
    fields: dict[str, str],
    headers: dict[str, str] | None = None,
) -> tuple[int, str]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    body = urllib.parse.urlencode(fields)
    all_headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if headers:
        all_headers.update(headers)
    conn.request("POST", path, body=body, headers=all_headers)
    resp = conn.getresponse()
    text = resp.read().decode()
    conn.close()
    return resp.status, text


def extract_result(page_text: str) -> tuple[bool, object]:
    match = PRE_BLOCK_RE.search(page_text)
    assert match is not None, f"no <pre> result block found in page: {page_text[:300]!r}"
    raw = html.unescape(match.group(1))
    is_error = "MCP tool error" in page_text
    try:
        return is_error, json.loads(raw)
    except json.JSONDecodeError:
        return is_error, raw


def mcp_call(db_path: Path, tool: str, arguments: dict[str, Any]) -> tuple[bool, Any]:
    """An independent MCP client -- not the Console -- for setup and verification."""

    async def _run() -> tuple[bool, Any]:
        params = StdioServerParameters(
            command=sys.executable,
            args=[str(HERE / "mcp_server.py")],
            env={"KERNEL_DB_PATH": str(db_path)},
            cwd=str(HERE),
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(tool, arguments)
                if result.is_error:
                    return True, result.content[0].text
                text = result.content[0].text if result.content else "null"
                try:
                    return False, json.loads(text)
                except json.JSONDecodeError:
                    return False, text

    return asyncio.run(_run())


def main() -> None:
    source = HERE / "data" / "kernel.db"
    assert source.exists(), f"fixture db missing: {source}"
    with tempfile.NamedTemporaryFile(prefix="console-0-8-participant-", suffix=".db") as f:
        f.close()
        db_path = Path(f.name)
        shutil.copy2(source, db_path)

        port = free_port()
        env = dict(os.environ)
        env["KERNEL_DB_PATH"] = str(db_path)
        env["CONSOLE_HOST"] = "127.0.0.1"
        env["CONSOLE_PORT"] = str(port)

        console_proc = subprocess.Popen(
            [sys.executable, str(HERE / "console.py")],
            cwd=str(HERE),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        try:
            wait_for_console(port)

            authority_id = "authority:console-0-8-participant"

            # Root defines a non-root participant Authority through the Console.
            status, body = http_post_form(
                port,
                "/authority/define",
                {
                    "requester_identity_id": NATHAN,
                    "authority_grant_id": ROOT,
                    "authority_id": authority_id,
                    "payload": "{}",
                },
            )
            assert status == 200
            is_error, result = extract_result(body)
            assert not is_error, result

            # Root issues a participant (non-root) grant to Nathan through the Console.
            status, body = http_post_form(
                port,
                "/grant/issue",
                {
                    "requester_identity_id": NATHAN,
                    "authority_grant_id": ROOT,
                    "identity_id": NATHAN,
                    "authority_id": authority_id,
                },
            )
            assert status == 200
            is_error, result = extract_result(body)
            assert not is_error, result
            participant_grant = result["grant_id"]

            # A second identity, holding its own grant -- the "foreign grant"
            # for the negative authority test. Created via MCP directly
            # (test setup only, not through the Console).
            is_error, result = mcp_call(
                db_path,
                "transition",
                {
                    "requester_identity_id": NATHAN,
                    "from_state_id": GENESIS,
                    "authority_grant_id": ROOT,
                    "new_state_payload": {"console-0-8": "setup"},
                    "new_identities": [{"identity_id": OTHER, "payload": {}}],
                },
            )
            assert not is_error, result
            status, body = http_post_form(
                port,
                "/grant/issue",
                {
                    "requester_identity_id": NATHAN,
                    "authority_grant_id": ROOT,
                    "identity_id": OTHER,
                    "authority_id": authority_id,
                },
            )
            assert status == 200
            is_error, result = extract_result(body)
            assert not is_error, result
            foreign_grant = result["grant_id"]
            assert foreign_grant != participant_grant

            # 1. Nathan-as-participant records Evidence through the Console
            #    with a NON-ROOT grant.
            status, body = http_post_form(
                port,
                "/evidence/record",
                {
                    "requester_identity_id": NATHAN,
                    "authority_grant_id": participant_grant,
                    "payload": json.dumps({"note": "first-party participant evidence"}),
                },
            )
            assert status == 200
            is_error, result = extract_result(body)
            assert not is_error, result
            evidence_id = result["evidence_id"]
            evidence_receipt_id = result["receipt_id"]

            # 2. The kernel-authored receipt attributes the record to Nathan
            #    himself -- no agent intermediary.
            is_error, receipt = mcp_call(
                db_path, "get_receipt", {"receipt_id": evidence_receipt_id}
            )
            assert not is_error, receipt
            assert receipt["outcome"] == "ACCEPTED", receipt
            assert (
                receipt["payload"]["caused_by_identity_id"] == NATHAN
            ), receipt["payload"]
            assert receipt["payload"]["action"] == "RECORD_EVIDENCE"

            is_error, evidence = mcp_call(
                db_path, "get_evidence", {"evidence_id": evidence_id}
            )
            assert not is_error, evidence
            assert evidence["payload"] == {"note": "first-party participant evidence"}

            # 3. The decision form projects to record_evidence with the
            #    human_decision convention; the kernel sees opaque JSON.
            status, body = http_post_form(
                port,
                "/evidence/decision",
                {
                    "requester_identity_id": NATHAN,
                    "authority_grant_id": participant_grant,
                    "subject": "paper outline scope",
                    "decision": "include PANOPTICON-0 as a case study",
                    "rationale": "it stress-tested the kernel/userland boundary",
                },
            )
            assert status == 200
            is_error, result = extract_result(body)
            assert not is_error, result
            decision_evidence_id = result["evidence_id"]
            decision_receipt_id = result["receipt_id"]

            is_error, devidence = mcp_call(
                db_path, "get_evidence", {"evidence_id": decision_evidence_id}
            )
            assert not is_error, devidence
            assert devidence["payload"]["kind"] == "human_decision"
            assert devidence["payload"]["subject"] == "paper outline scope"
            assert devidence["payload"]["decision"] == "include PANOPTICON-0 as a case study"
            assert (
                devidence["payload"]["rationale"]
                == "it stress-tested the kernel/userland boundary"
            )

            is_error, receipt = mcp_call(
                db_path, "get_receipt", {"receipt_id": decision_receipt_id}
            )
            assert not is_error, receipt
            assert receipt["payload"]["caused_by_identity_id"] == NATHAN

            # 4. Nathan-as-participant proposes a Transition through the
            #    Console, citing the evidence above.
            status, body = http_post_form(
                port,
                "/transition/propose",
                {
                    "requester_identity_id": NATHAN,
                    "from_state_id": GENESIS,
                    "authority_grant_id": participant_grant,
                    "new_state_payload": json.dumps(
                        {"project": "paper", "step": "outline", "by": "nathan"}
                    ),
                    "transition_payload": json.dumps({"via": "console-participant-form"}),
                    "evidence_ids": evidence_id,
                },
            )
            assert status == 200
            is_error, result = extract_result(body)
            assert not is_error, result
            transition_id = result["transition_id"]
            transition_receipt_id = result["receipt_id"]

            is_error, receipt = mcp_call(
                db_path, "get_receipt", {"receipt_id": transition_receipt_id}
            )
            assert not is_error, receipt
            assert receipt["outcome"] == "ACCEPTED", receipt
            assert receipt["transition_id"] == transition_id, receipt
            assert receipt["payload"]["authority_grant_id"] == participant_grant

            # First-party attribution, kernel-authored: the transition row
            # carries both the grant-holder identity and the requester
            # identity, stamped by the kernel inside its write
            # transaction -- not by the Console and not by any agent.
            is_error, transition = mcp_call(
                db_path, "get_transition", {"transition_id": transition_id}
            )
            assert not is_error, transition
            assert transition["payload"]["requester_identity_id"] == NATHAN
            assert transition["payload"]["identity_id"] == NATHAN
            assert transition["payload"]["via"] == "console-participant-form"

            # 5a. Authority still enforced: a grant Nathan does not hold is
            #     rejected by the Kernel through the same form.
            status, body = http_post_form(
                port,
                "/evidence/record",
                {
                    "requester_identity_id": NATHAN,
                    "authority_grant_id": foreign_grant,
                    "payload": json.dumps({"note": "should be rejected"}),
                },
            )
            assert status == 200
            is_error, result = extract_result(body)
            assert is_error, "foreign grant must be rejected by the Kernel"
            assert "does not hold" in str(result) and foreign_grant in str(
                result
            ), result

            # 5b. A grant that does not exist is likewise rejected.
            status, body = http_post_form(
                port,
                "/evidence/record",
                {
                    "requester_identity_id": NATHAN,
                    "authority_grant_id": "grant:does-not-exist",
                    "payload": json.dumps({"note": "should be rejected"}),
                },
            )
            assert status == 200
            is_error, result = extract_result(body)
            assert is_error, "nonexistent grant must be rejected by the Kernel"
            assert "does not exist" in str(result), result

            # 6. Malformed JSON is rejected by the Console before MCP.
            status, body = http_post_form(
                port,
                "/evidence/record",
                {
                    "requester_identity_id": NATHAN,
                    "authority_grant_id": participant_grant,
                    "payload": "{not json",
                },
            )
            assert status == 400, body[:200]
            assert "Invalid JSON" in body

            # 7. Cross-origin POSTs to the new endpoints are rejected
            #    before MCP is contacted: evidence table must not grow.
            is_error, before = mcp_call(
                db_path, "list_records", {"record_type": "evidence", "limit": 1000}
            )
            assert not is_error, before
            n_before = len(before["items"])

            for path in ("/evidence/record", "/evidence/decision", "/transition/propose"):
                status, body = http_post_form(
                    port,
                    path,
                    {
                        "requester_identity_id": NATHAN,
                        "authority_grant_id": participant_grant,
                        "payload": "{}",
                        "subject": "x",
                        "decision": "y",
                        "from_state_id": GENESIS,
                        "new_state_payload": "{}",
                    },
                    headers={"Origin": EVIL_ORIGIN},
                )
                assert status == 403, (path, status)
                assert "cross-origin" in body, body[:200]

            is_error, after = mcp_call(
                db_path, "list_records", {"record_type": "evidence", "limit": 1000}
            )
            assert not is_error, after
            assert len(after["items"]) == n_before, "cross-origin write reached the Kernel"

        finally:
            console_proc.terminate()
            try:
                console_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                console_proc.kill()

    print("console_0_8_human_participant_records: OK")
    print(f"  participant_grant={participant_grant} (non-root, held by {NATHAN})")
    print(f"  evidence_id={evidence_id} receipt={evidence_receipt_id} caused_by={NATHAN}")
    print(f"  decision evidence_id={decision_evidence_id} kind=human_decision")
    print(f"  transition_id={transition_id} receipt={transition_receipt_id} caused_by={NATHAN}")
    print("  foreign/nonexistent grants rejected; malformed JSON 400; cross-origin 403")


if __name__ == "__main__":
    main()

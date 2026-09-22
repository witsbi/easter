"""EASTER-CONSOLE-0 verification 7: Console source contains no direct
SQLite/private-Kernel access.

Same AST-level technique as mcp_0_3_no_direct_sqlite.py, applied to
console.py: a runtime probe only shows what one test run happened to
do, so this checks the source itself. console.py must never import
sqlite3 or kernel.py (Kernel/KernelError/AuthorityError/StateError are
not needed here at all -- the Console never touches the Kernel class,
only MCP), never call .execute(/.cursor(/.connect(, and never
reference a .db file by string literal.
"""

from __future__ import annotations

import ast
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
SOURCE_PATH = HERE / "console.py"
FORBIDDEN_SQLITE_CALL_NAMES = {"execute", "executemany", "executescript", "cursor"}


def main() -> None:
    source = SOURCE_PATH.read_text()
    tree = ast.parse(source, filename=str(SOURCE_PATH))

    imported_names: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported_names.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            imported_names.add(module.split(".")[0])

    assert "sqlite3" not in imported_names, (
        "console.py must not import sqlite3 -- all persistence must "
        "go through MCP-0 tool calls"
    )
    assert "kernel" not in imported_names, (
        "console.py must not import kernel.py at all -- it is a pure "
        "MCP client, it holds no Kernel object of its own"
    )

    forbidden_call_hits: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in FORBIDDEN_SQLITE_CALL_NAMES:
                forbidden_call_hits.append(node.func.attr)
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if node.value.endswith(".db"):
                forbidden_call_hits.append(f"string literal referencing a .db file: {node.value!r}")

    assert not forbidden_call_hits, (
        f"console.py appears to touch a database directly: {forbidden_call_hits}"
    )

    # The only way this module reaches the Kernel is by spawning
    # mcp_server.py as a subprocess and speaking MCP to it.
    mcp_server_references = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and "mcp_server.py" in node.value
    ]
    assert mcp_server_references, (
        "expected console.py to reference mcp_server.py as the subprocess it spawns"
    )

    print("console_0_4_no_direct_kernel_access: OK")
    print(f"  top-level imports: {sorted(imported_names)}")


if __name__ == "__main__":
    main()

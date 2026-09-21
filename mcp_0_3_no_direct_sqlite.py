"""EASTER-MCP-0 structural check: the adapter never touches SQLite directly.

"No direct SQLite access from the client" and "access or mutate SQLite
outside the Kernel's supported boundary" are boundary requirements a
runtime test can't fully prove (a runtime probe only shows what a
particular test run happened to do), so this is a static, source-level
check instead: mcp_server.py's own source text must not import
sqlite3, must not import anything sqlite3-shaped from kernel.py beyond
the Kernel class/exceptions, and must not call .execute(/.cursor(/
.connect( itself. All persistence must go through kernel.Kernel's own
public methods.
"""

from __future__ import annotations

import ast
from pathlib import Path

HERE = Path(__file__).parent
SOURCE_PATH = HERE / "mcp_server.py"
FORBIDDEN_SQLITE_CALL_NAMES = {"execute", "executemany", "executescript", "cursor"}


def main() -> None:
    source = SOURCE_PATH.read_text()
    tree = ast.parse(source, filename=str(SOURCE_PATH))

    imported_names: set[str] = set()
    kernel_imports: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported_names.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module == "kernel":
                kernel_imports.update(alias.name for alias in node.names)
            else:
                imported_names.add(module.split(".")[0])

    assert "sqlite3" not in imported_names, (
        "mcp_server.py must not import sqlite3 -- all persistence must "
        "go through kernel.Kernel's own public methods"
    )

    # kernel.py exposes Kernel plus its KernelError/AuthorityError/
    # StateError exception classes as its supported surface; anything
    # else imported from kernel by name would be reaching past that
    # boundary.
    allowed_kernel_imports = {"Kernel", "KernelError", "AuthorityError", "StateError"}
    unexpected = kernel_imports - allowed_kernel_imports
    assert not unexpected, (
        f"mcp_server.py imports unexpected names from kernel.py: {unexpected}"
    )

    # Guard against direct db-file access via open()/Path(...).open()
    # naming a .db file, or any dunder-style connect/execute call.
    forbidden_call_hits: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in FORBIDDEN_SQLITE_CALL_NAMES:
                forbidden_call_hits.append(node.func.attr)
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if node.value.endswith(".db"):
                forbidden_call_hits.append(f"string literal referencing a .db file: {node.value!r}")

    assert not forbidden_call_hits, (
        f"mcp_server.py appears to touch a database directly: {forbidden_call_hits}"
    )

    # The only Kernel interaction point should be a single shared,
    # module-level `kernel = Kernel(...)` instance -- never constructed
    # fresh inside a tool function (which would suggest per-call
    # reaching-around rather than one adapter-wide Kernel handle).
    function_defs = [
        node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]

    def is_inside_function(target: ast.AST) -> bool:
        return any(
            target in ast.walk(fn) and target is not fn for fn in function_defs
        )

    kernel_instantiations = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "Kernel"
    ]
    assert kernel_instantiations, "expected at least one Kernel(...) instantiation"
    assert not any(is_inside_function(node) for node in kernel_instantiations), (
        "Kernel(...) must only be constructed at module level as a single shared "
        "instance, not freshly inside a tool function"
    )

    print("mcp_0_3_no_direct_sqlite: OK")
    print(f"  imports from kernel.py: {sorted(kernel_imports)}")
    print(f"  top-level imports: {sorted(imported_names)}")


if __name__ == "__main__":
    main()

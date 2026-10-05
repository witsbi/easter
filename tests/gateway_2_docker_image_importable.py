"""GATEWAY-2: the Dockerfile's COPY set must actually be enough for
``gateway.py`` to import inside the built image.

Codex's cold review of PR #35 (independently verified by Pax) found
that ``gateway.py`` gained unconditional module-level imports of
``broker.tokens``/``broker.reader`` (its Ed25519 token-verification
path), but ``deploy/docker/Dockerfile`` still only copied
``kernel.py mcp_server.py gateway.py initialize.py schema.sql`` -- never
``broker/`` -- and the import is not optional even when the Ed25519
path itself is disabled via ``--issuance-db``. The containerized
gateway would die at startup with
``ModuleNotFoundError: No module named 'broker'``.

This does not require Docker (the supported suite deliberately does
not need it -- see ``docs/verification.md``). Instead it parses the
*real* Dockerfile's own ``COPY`` instructions, stages exactly the
files/directories those instructions would place under the image's
``/app``, and then runs ``python -c "import gateway"`` with that
staging directory as the *only* thing on the path -- no access to the
rest of the real checkout. If the Dockerfile's COPY set is ever
missing something ``gateway.py`` needs, this fails with the same
``ModuleNotFoundError`` the container would hit, for the same reason:
it reads the Dockerfile, it does not hand-duplicate a copy of what the
Dockerfile is supposed to say.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
DOCKERFILE = HERE / "deploy" / "docker" / "Dockerfile"

# Matches a single `COPY <src...> <dest>` instruction line. This
# Dockerfile has no multi-line (backslash-continued) COPY and no
# --from=/--chown= flags, so a plain line-oriented regex is sufficient
# -- a more general Dockerfile parser would be solving a problem this
# repository's one Dockerfile does not have.
COPY_RE = re.compile(r"^COPY\s+(.+?)\s+(\S+)\s*$")


def parse_app_copies(dockerfile_text: str) -> list[tuple[list[str], str]]:
    """Return (sources, dest) for every COPY instruction whose
    destination lands under the image's WORKDIR (/app) -- i.e.
    destinations starting with "./". Excludes COPY instructions that
    place a file elsewhere (e.g. entrypoint.sh under /usr/local/bin),
    which cannot affect gateway.py's import path."""
    copies = []
    for line in dockerfile_text.splitlines():
        match = COPY_RE.match(line.strip())
        if not match:
            continue
        sources, dest = match.groups()
        if not dest.startswith("./"):
            continue
        copies.append((sources.split(), dest))
    return copies


def main() -> None:
    dockerfile_text = DOCKERFILE.read_text()
    app_copies = parse_app_copies(dockerfile_text)
    assert app_copies, "expected at least one COPY instruction targeting /app"

    staging = Path(tempfile.mkdtemp(prefix="docker-image-stage-"))
    try:
        for sources, dest in app_copies:
            dest_rel = dest[len("./") :]
            for source in sources:
                src_path = HERE / source
                assert src_path.exists(), (
                    f"Dockerfile COPY references {source!r}, which does not "
                    f"exist in the repository at {src_path}"
                )
                if len(sources) == 1 and dest_rel:
                    # Single source, single destination: dest names the
                    # staged path directly (covers both a plain file
                    # and a directory copy like `COPY broker ./broker`).
                    target = staging / dest_rel
                else:
                    # Multiple sources: dest must be a directory: each
                    # source lands inside it under its own basename.
                    target = staging / dest_rel / Path(source).name
                target.parent.mkdir(parents=True, exist_ok=True)
                if src_path.is_dir():
                    shutil.copytree(src_path, target)
                else:
                    shutil.copy2(src_path, target)

        staged_gateway = staging / "gateway.py"
        assert staged_gateway.exists(), (
            "the Dockerfile's own COPY instructions never place gateway.py "
            "under /app -- parsed instructions: " + repr(app_copies)
        )

        # cwd = staging dir, so `-c` scripts see only the staged files
        # on sys.path[0] (empty-string/cwd), never the real checkout.
        result = subprocess.run(
            [sys.executable, "-c", "import gateway"],
            cwd=str(staging),
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, (
            "gateway.py must import cleanly from exactly the files the "
            "Dockerfile's own COPY instructions place in the image -- this "
            "is precisely the containerized-startup failure Codex's review "
            f"flagged.\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
        assert "ModuleNotFoundError" not in result.stderr

    finally:
        shutil.rmtree(staging)

    print("gateway_2_docker_image_importable: OK")


if __name__ == "__main__":
    main()

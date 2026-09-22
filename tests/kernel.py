"""Direct-script import bridge to the repository-root kernel module."""

import importlib.util
import sys
from pathlib import Path

ROOT_KERNEL = Path(__file__).resolve().parent.parent / "kernel.py"
spec = importlib.util.spec_from_file_location("kernel", ROOT_KERNEL)
if spec is None or spec.loader is None:
    raise ImportError(f"cannot load root kernel module from {ROOT_KERNEL}")
module = importlib.util.module_from_spec(spec)
sys.modules[__name__] = module
spec.loader.exec_module(module)

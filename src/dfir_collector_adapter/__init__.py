"""
agentic-dfir-collector-adapter
==============================

Convert Velociraptor IR collector output into the evidence_root layout
expected by Agentic-DFIR (https://github.com/Juwon1405/agentic-dfir).

Public surface
--------------
- adapt(velociraptor_zip, output_evidence_root, case_id=None)
- write_manifest(evidence_root, case_id=None)
- compute_sha256(path)

Stdlib-only by design.
"""
from importlib.metadata import PackageNotFoundError, version as _pkg_version

from .adapter import adapt
from .manifest import write_manifest
from .hash_indexer import compute_sha256

try:
    __version__ = _pkg_version("agentic-dfir-collector-adapter")
except PackageNotFoundError:
    __version__ = "0.0.0+unknown"

__all__ = ["adapt", "write_manifest", "compute_sha256", "__version__"]

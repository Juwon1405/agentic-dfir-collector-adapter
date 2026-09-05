"""
manifest.json writer.

The manifest is the chain-of-custody seed for Agentic-DFIR:
- adapter_version identifies which adapter produced the layout
- file_count / total_bytes catch silent truncation
- sha256_index lets downstream tools verify integrity without re-reading the ZIP
- source.sha256 anchors the input ZIP's identity so the chain survives rename
- skipped records what the adapter refused, with the reason
- source_members maps each output file back to its original ZIP member path
"""
from __future__ import annotations

import json
import platform
from datetime import datetime, timezone
from pathlib import Path

from .hash_indexer import compute_sha256_tree

MANIFEST_NAME = "manifest.json"
MANIFEST_VERSION = "1.2"


def write_manifest(
    evidence_root: str | Path,
    *,
    case_id: str,
    source_zip: str,
    files_copied: int,
    bytes_copied: int,
    categories: dict[str, int],
    skipped_count: int,
    include_sha256_index: bool = True,
    source_sha256: str | None = None,
    sha256_index: dict[str, str] | None = None,
    source_members: dict[str, str] | None = None,
    skipped_paths: list[str] | None = None,
    adapter_version: str | None = None,
) -> Path:
    """
    Write manifest.json under evidence_root and return its path.

    Parameters
    ----------
    sha256_index : pre-computed { relative_path: hex_digest }. If None and
        include_sha256_index is True, the output tree is walked.
    source_sha256 : SHA-256 of the input collector ZIP (chain-of-custody anchor).
    skipped_paths : list of "<member>  (<reason>)" strings recorded by the adapter.
    source_members : {output_relative_path: original_zip_member_name}. This preserves
        provenance when flat layout collision handling renames an output file.
    adapter_version : injected to avoid an import-time cycle.
    """
    root = Path(evidence_root).resolve()
    root.mkdir(parents=True, exist_ok=True)

    if adapter_version is None:
        from . import __version__ as adapter_version  # local import: avoid cycle at module load

    manifest: dict = {
        "manifest_version": MANIFEST_VERSION,
        "case_id": case_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": {
            "zip": source_zip,
            "type": "velociraptor_offline_collector",
        },
        "host": {
            "os": platform.system(),
            "release": platform.release(),
            "python": platform.python_version(),
        },
        "adapter": {
            "name": "agentic-dfir-collector-adapter",
            "version": adapter_version,
        },
        "counters": {
            "files_copied": files_copied,
            "bytes_copied": bytes_copied,
            "files_skipped": skipped_count,
        },
        "categories": categories,
    }

    if source_sha256:
        manifest["source"]["sha256"] = source_sha256

    if skipped_paths:
        manifest["skipped"] = list(skipped_paths)

    if source_members is not None:
        manifest["source_members"] = dict(sorted(source_members.items()))

    if include_sha256_index:
        index = sha256_index
        if index is None:
            index = {
                k: v for k, v in compute_sha256_tree(root).items()
                if k != MANIFEST_NAME
            }
        manifest["sha256_index"] = index

    target = root / MANIFEST_NAME
    target.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    return target

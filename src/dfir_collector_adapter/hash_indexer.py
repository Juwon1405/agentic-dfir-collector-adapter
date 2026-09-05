"""
SHA-256 file hashing helpers.

Used both to:
- pre-compute file hashes for downstream Agentic-DFIR audit chain entries, and
- support manifest.json integrity verification.

Symlinks are never followed: a forensic adapter must hash the artefact bytes
it actually wrote, not whatever the host filesystem links to.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

_BUF_SIZE = 1024 * 1024  # 1 MiB


def compute_sha256(path: str | Path) -> str:
    """
    Compute the SHA-256 of the file at `path` and return the lowercase hex digest.
    Streams the file in 1 MiB chunks (no full-file load).
    Refuses symlinks.
    """
    p = Path(path)
    if p.is_symlink():
        raise ValueError(f"refusing to hash a symlink: {p}")
    if not p.is_file():
        raise FileNotFoundError(f"file not found: {p}")
    h = hashlib.sha256()
    with open(p, "rb") as f:
        while True:
            chunk = f.read(_BUF_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def compute_sha256_tree(root: str | Path) -> dict[str, str]:
    """
    Recursively SHA-256 every regular file under `root`.
    Returns { relative_path_str: hex_digest }.

    Symlinks (both files and directories) are skipped — never followed.
    """
    root_path = Path(root).resolve()
    if not root_path.is_dir():
        raise NotADirectoryError(f"not a directory: {root_path}")

    out: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(root_path, followlinks=False):
        # prune symlinked subdirectories
        dirnames[:] = [d for d in dirnames if not Path(dirpath, d).is_symlink()]
        for name in sorted(filenames):
            p = Path(dirpath) / name
            if p.is_symlink() or not p.is_file():
                continue
            rel = p.relative_to(root_path).as_posix()
            out[rel] = compute_sha256(p)
    return dict(sorted(out.items()))

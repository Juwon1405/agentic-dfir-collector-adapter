"""
Main adapter — turns a Velociraptor offline-collector ZIP into the
evidence_root layout used by Agentic-DFIR.

Velociraptor offline collector outputs (typical layout):
    archive.zip
    +-- results/
    |   +-- Windows.KapeFiles.Targets/All file metadata.json
    |   +-- Windows.KapeFiles.Targets/All file metadata.zip
    |   +-- Windows.Forensics.Lnkfiles/All file metadata.json
    |   +-- ...
    +-- uploads/
    |   +-- auto/C:/Windows/Prefetch/SVCHOST.EXE-...pf
    |   +-- auto/C:/Windows/AppCompat/Programs/Amcache.hve
    |   +-- ...

Target evidence_root layout (what Agentic-DFIR expects):
    evidence_root/
    +-- manifest.json
    +-- Prefetch/
    |   +-- SVCHOST.EXE-XYZ.pf
    +-- Amcache/
    |   +-- Amcache.hve
    +-- EventLogs/
    |   +-- Security.evtx
    +-- Registry/
    |   +-- SOFTWARE
    |   +-- SYSTEM
    +-- WebLogs/
    |   +-- access.log
    +-- Browser/
    +-- ...
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import time
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .hash_indexer import compute_sha256
from .manifest import MANIFEST_NAME, write_manifest
from .layout import EVIDENCE_LAYOUT, classify_artifact

# Per-file safety guard. Files larger than this are skipped by default.
DEFAULT_MAX_BYTES_PER_FILE = 10 * 1024 * 1024 * 1024  # 10 GiB
# Backwards-compatible alias kept for callers that imported the old name.
DEFAULT_MAX_BYTES = DEFAULT_MAX_BYTES_PER_FILE

# Cumulative cap across the whole ZIP. Defends against many-small-files zip bombs.
DEFAULT_MAX_TOTAL_BYTES = 50 * 1024 * 1024 * 1024  # 50 GiB

_COPY_CHUNK = 1024 * 1024  # 1 MiB

# Reject any ZIP member whose name contains control bytes.
_UNSAFE_NAME_RE = re.compile(r"[\x00-\x1f\x7f]")


@dataclass
class AdapterResult:
    """What adapt() returns."""
    output_root: Path
    case_id: str
    files_copied: int = 0
    files_skipped: int = 0
    bytes_copied: int = 0
    categories: dict[str, int] = field(default_factory=dict)
    skipped_paths: list[str] = field(default_factory=list)
    source_members: dict[str, str] = field(default_factory=dict)
    source_sha256: str | None = None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def adapt(
    velociraptor_zip: str | Path,
    output_evidence_root: str | Path,
    *,
    case_id: str | None = None,
    max_bytes_per_file: int = DEFAULT_MAX_BYTES_PER_FILE,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    overwrite: bool = False,
    include_sha256_index: bool = True,
) -> AdapterResult:
    """
    Extract Velociraptor offline-collector ZIP into Agentic-DFIR
    evidence_root layout.

    Parameters
    ----------
    velociraptor_zip : path to the Velociraptor collector ZIP.
    output_evidence_root : target directory. Created if it does not exist.
    case_id : optional case identifier written into manifest.json. Defaults
        to the ZIP basename.
    max_bytes_per_file : per-file safety guard. Files larger than this are
        skipped. Enforced both via the ZIP header and during streaming
        (the header field is untrusted).
    max_total_bytes : cumulative cap across all members. Defends against
        many-small-files zip-bomb shapes.
    overwrite : if False and output already contains a non-empty manifest,
        raises FileExistsError. If True, the known layout subdirectories
        and the previous manifest are removed before extraction.
    include_sha256_index : write per-file SHA-256 index into manifest.json.

    Returns
    -------
    AdapterResult with counters and a list of skipped paths.

    Raises
    ------
    FileNotFoundError : ZIP does not exist.
    zipfile.BadZipFile : ZIP is malformed.
    FileExistsError : evidence_root has a manifest and overwrite=False.
    """
    src = Path(velociraptor_zip).resolve()
    if not src.is_file():
        raise FileNotFoundError(f"ZIP not found: {src}")

    dst = Path(output_evidence_root).resolve()
    dst.mkdir(parents=True, exist_ok=True)

    manifest_path = dst / MANIFEST_NAME
    if manifest_path.exists():
        if not overwrite:
            raise FileExistsError(
                f"manifest.json already exists in {dst}; pass overwrite=True to replace"
            )
        # Only remove paths we recognise — never wipe unrelated user data.
        for layout_dir in EVIDENCE_LAYOUT.values():
            d = dst / layout_dir
            if d.is_dir() and not d.is_symlink():
                shutil.rmtree(d)
        manifest_path.unlink()

    cid = case_id or src.stem
    # Source hash is the chain-of-custody anchor for the input artefact.
    source_sha256 = compute_sha256(src)
    result = AdapterResult(output_root=dst, case_id=cid, source_sha256=source_sha256)
    sha256_index: dict[str, str] = {}

    with zipfile.ZipFile(src, "r") as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            if _is_symlink_member(info):
                _skip(result, info.filename, "symlink member")
                continue
            if info.file_size > max_bytes_per_file:
                _skip(result, info.filename, f"too large: {info.file_size} bytes")
                continue
            if _UNSAFE_NAME_RE.search(info.filename):
                _skip(result, info.filename, "unsafe characters")
                continue

            target = _safe_target_path(dst, info.filename)
            if target is None:
                _skip(result, info.filename, "would escape evidence_root")
                continue
            target = _avoid_target_collision(target, dst, info.filename)

            target.parent.mkdir(parents=True, exist_ok=True)
            remaining_total = max_total_bytes - result.bytes_copied
            try:
                with zf.open(info, "r") as fsrc, open(target, "wb") as fdst:
                    outcome = _stream_copy_with_hash(
                        fsrc, fdst,
                        per_file_cap=max_bytes_per_file,
                        remaining_total_cap=remaining_total,
                    )
            except Exception:
                # Avoid leaving a half-written file masquerading as evidence.
                target.unlink(missing_ok=True)
                raise

            if outcome is None:
                target.unlink(missing_ok=True)
                _skip(result, info.filename, "stream exceeded size cap")
                # A bomb-shaped ZIP would keep producing skips; abort total if hit.
                if result.bytes_copied >= max_total_bytes:
                    break
                continue

            written, sha = outcome
            _apply_member_mtime(target, info)

            rel = target.relative_to(dst).as_posix()
            sha256_index[rel] = sha
            result.source_members[rel] = info.filename

            result.files_copied += 1
            result.bytes_copied += written
            category = classify_artifact(info.filename)
            result.categories[category] = result.categories.get(category, 0) + 1

    # Manifest written last so that incomplete runs do not look successful.
    write_manifest(
        evidence_root=dst,
        case_id=cid,
        source_zip=str(src),
        source_sha256=source_sha256,
        files_copied=result.files_copied,
        bytes_copied=result.bytes_copied,
        categories=result.categories,
        skipped_count=result.files_skipped,
        skipped_paths=result.skipped_paths,
        include_sha256_index=include_sha256_index,
        sha256_index=dict(sorted(sha256_index.items())) if include_sha256_index else None,
        source_members=dict(sorted(result.source_members.items())),
    )

    return result


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _skip(result: AdapterResult, member: str, reason: str) -> None:
    result.files_skipped += 1
    result.skipped_paths.append(f"{member}  ({reason})")


def _is_symlink_member(info: zipfile.ZipInfo) -> bool:
    """
    Detect Unix symlink members. ZIP stores POSIX mode bits in the high 16
    bits of external_attr; S_IFLNK is 0o120000.
    """
    mode = (info.external_attr >> 16) & 0o170000
    return mode == stat.S_IFLNK


def _stream_copy_with_hash(
    fsrc, fdst, *, per_file_cap: int, remaining_total_cap: int,
) -> tuple[int, str] | None:
    """
    Copy fsrc -> fdst while updating SHA-256 in the same pass, and bail
    if either cap is exceeded (returns None). Caps are checked against
    bytes actually read, never the untrusted ZIP header.
    """
    hasher = hashlib.sha256()
    written = 0
    while True:
        chunk = fsrc.read(_COPY_CHUNK)
        if not chunk:
            break
        written += len(chunk)
        if written > per_file_cap or written > remaining_total_cap:
            return None
        hasher.update(chunk)
        fdst.write(chunk)
    return written, hasher.hexdigest()


def _apply_member_mtime(target: Path, info: zipfile.ZipInfo) -> None:
    """
    Preserve the ZIP member's recorded modification time on the output file.
    DFIR consumers downstream rely on artefact mtimes; the default os.open
    would otherwise stamp "now". Silently ignore obviously-invalid timestamps.
    """
    dt = info.date_time
    if not dt or len(dt) != 6 or dt[0] < 1980:
        return
    try:
        ts = time.mktime(datetime(*dt).timetuple())
        os.utime(target, (ts, ts))
    except (OverflowError, OSError, ValueError):
        pass


def _avoid_target_collision(target: Path, evidence_root: Path, member_name: str) -> Path:
    """
    Keep the public evidence_root layout flat, but never let two source
    members silently overwrite each other. Common forensic filenames such as
    History, SYSTEM, access.log, and ConsoleHost_history.txt can appear once
    per user/profile/host in a Velociraptor ZIP.
    """
    if not target.exists():
        return target

    digest = hashlib.sha256(member_name.encode("utf-8", errors="surrogatepass")).hexdigest()[:12]
    stem = target.stem or target.name
    suffix = target.suffix
    parent = target.parent
    candidate = parent / f"{stem}-{digest}{suffix}"
    counter = 2
    while candidate.exists():
        candidate = parent / f"{stem}-{digest}-{counter}{suffix}"
        counter += 1

    root_resolved = evidence_root.resolve()
    try:
        candidate.resolve().relative_to(root_resolved)
    except ValueError as e:
        raise RuntimeError(f"collision target escaped evidence_root: {candidate}") from e
    return candidate


def _safe_target_path(evidence_root: Path, member_name: str) -> Path | None:
    """
    Map a Velociraptor ZIP member name to a path under evidence_root using
    the layout categories, refusing anything that looks like a traversal
    or path-injection attempt.

    Defenses, in order:
    1. Refuse empty / dot-only names.
    2. Normalise slashes; refuse any ".." segment.
    3. Reduce to basename — Velociraptor uses absolute-looking paths inside
       its ZIP, but only the file name is meaningful for our layout.
    4. After category lookup + basename extraction, the resolved candidate
       must live inside evidence_root (defends against parent-symlink tricks).
    """
    if not member_name or member_name in (".", ".."):
        return None

    norm = member_name.replace("\\", "/")
    segments = [s for s in norm.split("/") if s]
    if any(s == ".." for s in segments):
        return None
    if not segments:
        return None

    base_name = segments[-1]
    if not base_name or base_name in (".", ".."):
        return None

    category = classify_artifact(member_name)
    layout_dir = EVIDENCE_LAYOUT[category]

    root_resolved = evidence_root.resolve()
    candidate = (root_resolved / layout_dir / base_name).resolve()
    try:
        candidate.relative_to(root_resolved)
    except ValueError:
        return None
    return candidate

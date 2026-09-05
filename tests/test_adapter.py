"""End-to-end adapter tests using a synthetic Velociraptor-shaped ZIP."""
import json
import zipfile
from pathlib import Path

import pytest

from dfir_collector_adapter import adapt
from dfir_collector_adapter.adapter import _safe_target_path


@pytest.fixture()
def velo_zip(tmp_path: Path) -> Path:
    """Build a tiny ZIP that mimics a Velociraptor offline-collector output."""
    z = tmp_path / "case_synthetic.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("uploads/auto/C:/Windows/Prefetch/SVCHOST.EXE-ABC.pf", b"PF\x00\x00fake")
        zf.writestr("uploads/auto/C:/Windows/AppCompat/Programs/Amcache.hve", b"AMCACHE")
        zf.writestr("uploads/auto/C:/Windows/System32/config/SECURITY", b"REGF" + b"\x00" * 12)
        zf.writestr("uploads/auto/C:/Windows/System32/winevt/Logs/Security.evtx", b"ElfFile\x00")
        zf.writestr("uploads/auto/var/log/auth.log", b"auth\n")
        zf.writestr("uploads/auto/var/log/nginx/access_2024.log", b"200 GET /\n")
        zf.writestr("uploads/auto/random/unknown.bin", b"???")
    return z


def test_adapt_produces_expected_layout(velo_zip: Path, tmp_path: Path):
    out = tmp_path / "evidence_root"
    result = adapt(velo_zip, out, case_id="case-test")

    assert result.files_copied == 7
    assert result.files_skipped == 0
    assert (out / "manifest.json").is_file()

    # Each artifact landed in the correct subdir
    assert (out / "Prefetch" / "SVCHOST.EXE-ABC.pf").is_file()
    assert (out / "Amcache" / "Amcache.hve").is_file()
    assert (out / "Registry" / "SECURITY").is_file()
    assert (out / "EventLogs" / "Security.evtx").is_file()
    assert (out / "AuthLogs" / "auth.log").is_file()
    assert (out / "WebLogs" / "access_2024.log").is_file()
    assert (out / "Other" / "unknown.bin").is_file()


def test_manifest_has_required_fields(velo_zip: Path, tmp_path: Path):
    out = tmp_path / "evidence_root"
    result = adapt(velo_zip, out, case_id="case-manifest")
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))

    for k in ("manifest_version", "case_id", "generated_at",
              "source", "host", "adapter", "counters",
              "categories", "sha256_index", "source_members"):
        assert k in manifest, f"missing manifest field: {k}"

    assert manifest["case_id"] == "case-manifest"
    assert manifest["counters"]["files_copied"] == 7
    assert manifest["categories"]["prefetch"] == 1
    assert manifest["categories"]["amcache"] == 1
    # SHA-256 index covers every output file
    assert "Prefetch/SVCHOST.EXE-ABC.pf" in manifest["sha256_index"]
    assert manifest["source_members"]["Prefetch/SVCHOST.EXE-ABC.pf"].endswith(
        "SVCHOST.EXE-ABC.pf"
    )
    assert result.source_members["Prefetch/SVCHOST.EXE-ABC.pf"].endswith(
        "SVCHOST.EXE-ABC.pf"
    )


def test_adapt_refuses_overwrite_by_default(velo_zip: Path, tmp_path: Path):
    out = tmp_path / "evidence_root"
    adapt(velo_zip, out, case_id="case-1")
    with pytest.raises(FileExistsError):
        adapt(velo_zip, out, case_id="case-2")


def test_adapt_overwrites_when_requested(velo_zip: Path, tmp_path: Path):
    out = tmp_path / "evidence_root"
    adapt(velo_zip, out, case_id="case-1")
    # No exception when overwrite=True
    result = adapt(velo_zip, out, case_id="case-2", overwrite=True)
    assert result.case_id == "case-2"


def test_adapt_missing_zip_raises(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        adapt(tmp_path / "nope.zip", tmp_path / "out")


def test_safe_target_path_rejects_traversal(tmp_path: Path):
    # The adapter's _safe_target_path is the single line of defence against
    # malicious ZIP member names. Test it directly.
    assert _safe_target_path(tmp_path, "../../etc/passwd") is None
    assert _safe_target_path(tmp_path, "") is None
    assert _safe_target_path(tmp_path, ".") is None
    assert _safe_target_path(tmp_path, "..") is None


def test_unsafe_names_skipped(tmp_path: Path):
    z = tmp_path / "bad.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("ok.txt", b"fine")
        zf.writestr("bad\x01name.txt", b"control-byte")
    out = tmp_path / "out"
    result = adapt(z, out, case_id="case-unsafe")
    assert result.files_copied == 1
    assert result.files_skipped == 1
    assert any("unsafe characters" in s for s in result.skipped_paths)


# ---------------------------------------------------------------------------
# v0.1.2 — integrity & security additions
# ---------------------------------------------------------------------------

def test_manifest_contains_source_sha256(velo_zip: Path, tmp_path: Path):
    out = tmp_path / "evidence_root"
    result = adapt(velo_zip, out, case_id="case-anchor")
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert result.source_sha256 is not None
    assert manifest["source"]["sha256"] == result.source_sha256


def test_manifest_records_skipped_with_reason(tmp_path: Path):
    z = tmp_path / "bad.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("ok.txt", b"fine")
        zf.writestr("bad\x01name.txt", b"control-byte")
    out = tmp_path / "out"
    adapt(z, out, case_id="case-skipped")
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert "skipped" in manifest
    assert any("unsafe characters" in s for s in manifest["skipped"])


def test_overwrite_clears_stale_files(velo_zip: Path, tmp_path: Path):
    out = tmp_path / "evidence_root"
    adapt(velo_zip, out, case_id="case-1")
    # An older artifact lingers from a previous run.
    assert (out / "Prefetch" / "SVCHOST.EXE-ABC.pf").is_file()

    # New ZIP contains only one Prefetch file with a different name.
    z2 = tmp_path / "second.zip"
    with zipfile.ZipFile(z2, "w") as zf:
        zf.writestr("uploads/auto/C:/Windows/Prefetch/NOTEPAD.EXE-NEW.pf", b"PF\x00\x00new")
    adapt(z2, out, case_id="case-2", overwrite=True)

    assert not (out / "Prefetch" / "SVCHOST.EXE-ABC.pf").exists()
    assert (out / "Prefetch" / "NOTEPAD.EXE-NEW.pf").is_file()

    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    # counters and sha256_index must agree after overwrite.
    assert manifest["counters"]["files_copied"] == len(manifest["sha256_index"])
    assert "Prefetch/NOTEPAD.EXE-NEW.pf" in manifest["sha256_index"]
    assert "Prefetch/SVCHOST.EXE-ABC.pf" not in manifest["sha256_index"]


def test_duplicate_basenames_are_not_silently_overwritten(tmp_path: Path):
    z = tmp_path / "duplicate-history.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr(
            "uploads/auto/C:/Users/alice/AppData/Local/Google/Chrome/User Data/Default/History",
            b"alice",
        )
        zf.writestr(
            "uploads/auto/C:/Users/bob/AppData/Local/Google/Chrome/User Data/Default/History",
            b"bob",
        )

    out = tmp_path / "out"
    result = adapt(z, out, case_id="case-dup")
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    browser_files = sorted(p.name for p in (out / "Browser").iterdir())

    assert result.files_copied == 2
    assert len(browser_files) == 2
    assert "History" in browser_files
    assert (out / "Browser" / "History").read_bytes() == b"alice"
    assert any(name.startswith("History-") for name in browser_files)
    assert len(result.source_members) == 2
    assert len(manifest["sha256_index"]) == 2
    assert len(manifest["source_members"]) == 2
    assert any("Users/bob" in member for member in manifest["source_members"].values())


def test_symlink_member_is_skipped(tmp_path: Path):
    """A ZIP member with the POSIX S_IFLNK mode bits is refused."""
    import stat as _stat
    z = tmp_path / "with_symlink.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("ok.txt", b"hi")
        info = zipfile.ZipInfo("evil-link")
        # S_IFLNK | 0o777 in the high 16 bits of external_attr.
        info.external_attr = (_stat.S_IFLNK | 0o777) << 16
        zf.writestr(info, b"/etc/passwd")
    out = tmp_path / "out"
    result = adapt(z, out, case_id="case-sym")
    assert result.files_copied == 1
    assert result.files_skipped == 1
    assert any("symlink" in s for s in result.skipped_paths)


def test_total_byte_cap_aborts(tmp_path: Path):
    """Cumulative cap protects against many-small-files zip-bomb shapes."""
    z = tmp_path / "many.zip"
    with zipfile.ZipFile(z, "w") as zf:
        for i in range(20):
            zf.writestr(f"uploads/auto/file_{i}.bin", b"A" * 1024)
    out = tmp_path / "out"
    # Allow only ~5 KiB total.
    result = adapt(z, out, case_id="case-total", max_total_bytes=5 * 1024)
    assert result.bytes_copied <= 5 * 1024
    assert result.files_skipped > 0


def test_per_file_byte_cap_enforced_during_stream(tmp_path: Path):
    """Per-file cap is enforced against bytes actually read (not the header)."""
    z = tmp_path / "fat.zip"
    payload = b"B" * (2 * 1024 * 1024)  # 2 MiB actual stream
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("uploads/auto/big.bin", payload)
    out = tmp_path / "out"
    result = adapt(z, out, case_id="case-cap", max_bytes_per_file=512 * 1024)
    assert result.files_copied == 0
    assert result.files_skipped == 1
    # The half-written file must not be left behind on disk.
    assert not (out / "Other" / "big.bin").exists()


def test_no_hash_index_omits_sha256_index(velo_zip: Path, tmp_path: Path):
    out = tmp_path / "evidence_root"
    adapt(velo_zip, out, case_id="case-no-idx", include_sha256_index=False)
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert "sha256_index" not in manifest


def test_member_mtime_is_preserved(tmp_path: Path):
    z = tmp_path / "mt.zip"
    info = zipfile.ZipInfo("uploads/auto/C:/Windows/Prefetch/X.pf")
    info.date_time = (2024, 3, 14, 9, 26, 53)
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr(info, b"PF")
    out = tmp_path / "out"
    adapt(z, out, case_id="case-mtime")
    p = out / "Prefetch" / "X.pf"
    assert p.is_file()
    import datetime as _dt
    mtime = _dt.datetime.fromtimestamp(p.stat().st_mtime)
    assert (mtime.year, mtime.month, mtime.day, mtime.hour) == (2024, 3, 14, 9)


def test_empty_layout_dirs_not_created_when_no_member_lands(tmp_path: Path):
    """Only categories that received at least one file should appear on disk."""
    z = tmp_path / "small.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("uploads/auto/C:/Windows/Prefetch/ONE.pf", b"PF")
    out = tmp_path / "out"
    adapt(z, out, case_id="case-lazy")
    assert (out / "Prefetch").is_dir()
    # Categories with no contributing member should NOT be pre-created.
    for empty in ("Amcache", "Registry", "EventLogs", "MFT", "USNJournal",
                  "JumpLists", "Memory", "PowerShell"):
        assert not (out / empty).exists(), f"{empty} should not be pre-created"

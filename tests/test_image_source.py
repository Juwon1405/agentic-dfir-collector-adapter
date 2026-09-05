"""Tests for the --source image pipeline (Velociraptor dead-disk handoff).

Velociraptor itself is never executed here: the single subprocess boundary
(``image_source._run_velociraptor``) is mocked so we can verify the
image -> collection.zip -> manifest.json handoff deterministically and
offline.
"""
import json
import subprocess
import zipfile
from pathlib import Path

import pytest

from dfir_collector_adapter import cli, image_source
from dfir_collector_adapter.image_source import (
    ImageExtractionError,
    VelociraptorNotFoundError,
    build_velociraptor_command,
    resolve_velociraptor_bin,
)


def _fake_image(path: Path) -> Path:
    path.write_bytes(b"\x00" * 4096)  # stand-in for a .dd/.E01 image
    return path


def _collection_zip_bytes() -> bytes:
    import io
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("uploads/auto/C:/Windows/Prefetch/X.pf", b"PF\x00\x00")
        zf.writestr("uploads/auto/C:/Windows/System32/config/SYSTEM", b"REGF")
    return buf.getvalue()


def _make_fake_velociraptor(monkeypatch, *, returncode=0, write_zip=True, on_path=True):
    """Patch binary resolution + the subprocess boundary."""
    if on_path:
        monkeypatch.setattr(image_source, "resolve_velociraptor_bin",
                            lambda explicit=None: "/usr/bin/velociraptor")

    def fake_run(cmd, *, timeout=3600):
        # cmd[-1] is the --output zip target; honour it like the real tool.
        out_idx = cmd.index("--output") + 1
        out_zip = Path(cmd[out_idx])
        if write_zip and returncode == 0:
            out_zip.write_bytes(_collection_zip_bytes())
        return subprocess.CompletedProcess(cmd, returncode, stdout="ok", stderr="boom")

    monkeypatch.setattr(image_source, "_run_velociraptor", fake_run)


# --------------------------------------------------------------------------- #
# parsing / help
# --------------------------------------------------------------------------- #

def test_source_image_parses():
    args = cli.build_parser().parse_args(
        ["--source", "image", "--input", "disk.E01", "--output", "out"]
    )
    assert args.source == "image"
    assert args.input == "disk.E01"


def test_source_defaults_to_zip():
    args = cli.build_parser().parse_args(["--input", "x.zip", "--output", "out"])
    assert args.source == "zip"


# --------------------------------------------------------------------------- #
# binary resolution order
# --------------------------------------------------------------------------- #

def test_resolution_prefers_explicit(tmp_path, monkeypatch):
    binpath = tmp_path / "velociraptor"
    binpath.write_text("#!/bin/sh\n")
    binpath.chmod(0o755)
    assert resolve_velociraptor_bin(str(binpath)) == str(binpath.resolve())


def test_resolution_uses_env(tmp_path, monkeypatch):
    binpath = tmp_path / "velociraptor"
    binpath.write_text("#!/bin/sh\n")
    binpath.chmod(0o755)
    monkeypatch.setenv("DFIR_VELOCIRAPTOR_BIN", str(binpath))
    assert resolve_velociraptor_bin() == str(binpath.resolve())


def test_resolution_missing_raises_actionable(monkeypatch):
    monkeypatch.delenv("DFIR_VELOCIRAPTOR_BIN", raising=False)
    monkeypatch.setattr(image_source.shutil, "which", lambda name: None)
    monkeypatch.setattr(image_source, "_staged_bin_dir",
                        lambda: Path("/nonexistent/bin"))
    with pytest.raises(VelociraptorNotFoundError) as exc:
        resolve_velociraptor_bin()
    msg = str(exc.value)
    assert "DFIR_VELOCIRAPTOR_BIN" in msg and "--velociraptor-bin" in msg


# --------------------------------------------------------------------------- #
# command construction
# --------------------------------------------------------------------------- #

def test_build_command_shape(tmp_path):
    cmd = build_velociraptor_command(
        "/usr/bin/velociraptor",
        tmp_path / "disk.dd",
        tmp_path / "remap.yaml",
        tmp_path / "out.zip",
        artifact="Windows.Triage.Targets",
    )
    assert cmd[0] == "/usr/bin/velociraptor"
    assert "artifacts" in cmd and "collect" in cmd
    assert cmd[cmd.index("--output") + 1] == str(tmp_path / "out.zip")
    assert "Windows.Triage.Targets" in cmd


# --------------------------------------------------------------------------- #
# full mocked handoff: image -> collection.zip -> manifest.json
# --------------------------------------------------------------------------- #

def test_mocked_image_run_produces_manifest(tmp_path, monkeypatch):
    img = _fake_image(tmp_path / "disk.E01")
    out = tmp_path / "evidence_root"
    _make_fake_velociraptor(monkeypatch)

    rc = cli.main(["--source", "image", "--input", str(img),
                   "--output", str(out), "--case-id", "img-case", "--quiet"])
    assert rc == 0
    manifest = out / "manifest.json"
    assert manifest.is_file()
    data = json.loads(manifest.read_text())
    assert data["case_id"] == "img-case"


def test_mocked_image_cleans_temp(tmp_path, monkeypatch):
    img = _fake_image(tmp_path / "disk.dd")
    out = tmp_path / "evidence_root"

    captured = {}
    real = image_source.extract_image_to_zip

    def spy(*a, **k):
        res = real(*a, **k)
        captured["temp_dir"] = res.temp_dir
        return res

    _make_fake_velociraptor(monkeypatch)
    monkeypatch.setattr(image_source, "extract_image_to_zip", spy)
    monkeypatch.setattr(cli, "extract_image_to_zip", spy)

    assert cli.main(["--source", "image", "--input", str(img),
                     "--output", str(out), "--quiet"]) == 0
    # temp dir removed after the run (keep_temp not set).
    assert not captured["temp_dir"].exists()


def test_image_missing_binary_returns_5(tmp_path, monkeypatch):
    img = _fake_image(tmp_path / "disk.dd")
    monkeypatch.delenv("DFIR_VELOCIRAPTOR_BIN", raising=False)
    monkeypatch.setattr(image_source.shutil, "which", lambda name: None)
    monkeypatch.setattr(image_source, "_staged_bin_dir",
                        lambda: Path("/nonexistent/bin"))
    rc = cli.main(["--source", "image", "--input", str(img),
                   "--output", str(tmp_path / "out"), "--quiet"])
    assert rc == 5


def test_image_collection_failure_returns_6(tmp_path, monkeypatch):
    img = _fake_image(tmp_path / "disk.dd")
    _make_fake_velociraptor(monkeypatch, returncode=1, write_zip=False)
    rc = cli.main(["--source", "image", "--input", str(img),
                   "--output", str(tmp_path / "out"), "--quiet"])
    assert rc == 6


def test_image_missing_file_returns_2(tmp_path, monkeypatch):
    _make_fake_velociraptor(monkeypatch)
    rc = cli.main(["--source", "image", "--input", str(tmp_path / "nope.dd"),
                   "--output", str(tmp_path / "out"), "--quiet"])
    assert rc == 2

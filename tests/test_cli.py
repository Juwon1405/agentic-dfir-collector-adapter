"""Smoke tests for the CLI entrypoint."""
import json
import sys
import zipfile
from pathlib import Path

import pytest

from dfir_collector_adapter.cli import build_parser, main


def _build_demo_zip(path: Path) -> None:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("uploads/auto/C:/Windows/Prefetch/X.pf", b"PF\x00\x00")
        zf.writestr("uploads/auto/C:/Windows/System32/config/SYSTEM", b"REGF")


def test_parser_requires_input_and_output():
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([])


def test_help_exits_zero(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0


def test_missing_input_returns_2(tmp_path: Path):
    rc = main(["--input", str(tmp_path / "nope.zip"),
               "--output", str(tmp_path / "out")])
    assert rc == 2


def test_overwrite_conflict_returns_3(tmp_path: Path):
    z = tmp_path / "demo.zip"
    _build_demo_zip(z)
    out = tmp_path / "out"
    assert main(["--input", str(z), "--output", str(out), "--quiet"]) == 0
    # Second run without --overwrite must fail with exit code 3.
    assert main(["--input", str(z), "--output", str(out), "--quiet"]) == 3


def test_bad_zip_returns_4(tmp_path: Path):
    z = tmp_path / "broken.zip"
    z.write_bytes(b"not a zip file at all")
    rc = main(["--input", str(z), "--output", str(tmp_path / "out"), "--quiet"])
    assert rc == 4


def test_end_to_end_json_summary(tmp_path: Path, capsys):
    z = tmp_path / "demo.zip"
    _build_demo_zip(z)
    out = tmp_path / "out"
    rc = main(["--input", str(z), "--output", str(out), "--case-id", "cli-case"])
    assert rc == 0
    captured = capsys.readouterr()
    summary = json.loads(captured.out)
    assert summary["case_id"] == "cli-case"
    assert summary["files_copied"] == 2
    assert summary["source_sha256"]


def test_no_hash_index_flag_is_wired(tmp_path: Path):
    z = tmp_path / "demo.zip"
    _build_demo_zip(z)
    out = tmp_path / "out"
    assert main(["--input", str(z), "--output", str(out),
                 "--no-hash-index", "--quiet"]) == 0
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert "sha256_index" not in manifest

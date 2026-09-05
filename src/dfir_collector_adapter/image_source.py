"""
Disk-image source pipeline.

The adapter's primary contract is the Velociraptor *offline-collector ZIP*
(see ``adapter.adapt``). This module adds a second supported source: a raw
forensic disk image (``.dd``/``.raw``) or an EnCase image (``.E01``).

Design constraints (kept deliberately honest):

* Velociraptor does not ingest a raw image directly. The documented mechanism
  for "dead disk" analysis is a *remapping* configuration that exposes the
  image to Velociraptor's NTFS accessor, after which an ordinary
  ``artifacts collect`` run produces a standard collection ZIP. That ZIP then
  flows into the existing ``adapt()`` pipeline unchanged.
* The exact artifact name and accessor flags vary across Velociraptor
  releases. We therefore *build* the command from documented building blocks
  and route execution through a single, mockable boundary
  (``_run_velociraptor``). Callers can override the artifact/extra args.
* If no Velociraptor binary can be resolved, we fail fast with an actionable
  message instead of pretending the image was processed.

Binary resolution order (first hit wins):
    1. explicit ``velociraptor_bin`` argument (e.g. ``--velociraptor-bin``)
    2. ``DFIR_VELOCIRAPTOR_BIN`` environment variable
    3. ``<adapter package parent>/bin/`` staged binary
    4. ``velociraptor`` on ``PATH``
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

# Image extensions we recognise as a "dead disk" source.
IMAGE_SUFFIXES = (".dd", ".raw", ".img", ".e01", ".001")

# Default Velociraptor artifact used to triage a remapped dead disk. This is a
# stock artifact present in modern Velociraptor releases; override via
# ``extra_args`` / ``artifact`` if your release names it differently.
DEFAULT_ARTIFACT = "Windows.Triage.Targets"

# Candidate binary names searched on PATH / in the staged bin dir.
_BINARY_NAMES = ("velociraptor", "velociraptor.exe")


class VelociraptorNotFoundError(RuntimeError):
    """Raised when no Velociraptor binary can be resolved."""


class ImageExtractionError(RuntimeError):
    """Raised when the Velociraptor collection step fails or yields no ZIP."""


@dataclass
class ImageExtractionResult:
    collection_zip: Path
    temp_dir: Path
    command: list[str]
    keep_temp: bool = False
    extra: dict = field(default_factory=dict)

    def cleanup(self) -> None:
        """Remove the temp dir unless the caller asked to keep it."""
        if self.keep_temp:
            return
        shutil.rmtree(self.temp_dir, ignore_errors=True)


def _staged_bin_dir() -> Path:
    # ``.../src/dfir_collector_adapter/image_source.py`` -> repo root ``bin/``.
    return Path(__file__).resolve().parents[2] / "bin"


def resolve_velociraptor_bin(explicit: str | None = None) -> str:
    """Resolve the Velociraptor binary using the documented fallback order.

    Raises ``VelociraptorNotFoundError`` with an actionable message when no
    binary is found, listing every location that was checked.
    """
    checked: list[str] = []

    if explicit:
        p = Path(explicit).expanduser()
        if p.is_file() and os.access(p, os.X_OK):
            return str(p.resolve())
        checked.append(f"--velociraptor-bin {explicit}")

    env = os.environ.get("DFIR_VELOCIRAPTOR_BIN")
    if env:
        p = Path(env).expanduser()
        if p.is_file() and os.access(p, os.X_OK):
            return str(p.resolve())
        checked.append(f"DFIR_VELOCIRAPTOR_BIN={env}")

    bin_dir = _staged_bin_dir()
    # 1) exact stable names ('velociraptor', 'velociraptor.exe')
    for name in _BINARY_NAMES:
        p = bin_dir / name
        if p.is_file() and os.access(p, os.X_OK):
            return str(p.resolve())
    # 2) versioned release asset left by the installer
    #    (e.g. 'velociraptor-v0.76.6-linux-amd64'). The installer also tries to
    #    drop a stable 'velociraptor' symlink, but if that step was skipped or
    #    the binary was staged by hand, match the versioned name directly so a
    #    present-but-versioned binary is never reported as missing.
    if bin_dir.is_dir():
        versioned = sorted(
            (p for p in bin_dir.glob("velociraptor-v*")
             if p.is_file() and os.access(p, os.X_OK)),
            reverse=True,  # highest version string first
        )
        if versioned:
            return str(versioned[0].resolve())
    checked.append(f"staged dir {bin_dir}/")

    for name in _BINARY_NAMES:
        found = shutil.which(name)
        if found:
            return found
    checked.append("PATH (velociraptor)")

    raise VelociraptorNotFoundError(
        "Velociraptor binary not found. Checked: "
        + "; ".join(checked)
        + ". Stage it with `bash scripts/install.sh` (which downloads and "
        "verifies the Velociraptor release binary into ./bin/), set "
        "DFIR_VELOCIRAPTOR_BIN=/path/to/velociraptor, or pass "
        "--velociraptor-bin /path/to/velociraptor."
    )


def build_remapping_config(image_path: Path, config_path: Path) -> Path:
    """Write a Velociraptor remapping config that maps ``image_path`` to the
    NTFS accessor so a normal collection can run against a dead disk.

    This follows Velociraptor's documented dead-disk remapping pattern. The
    exact schema can differ by release; treat this file as a starting point
    and verify against ``velociraptor config show`` for your version.
    """
    yaml = (
        "# Auto-generated by dfir_collector_adapter for dead-disk analysis.\n"
        "# Maps the supplied image to the NTFS accessor (Velociraptor\n"
        "# remapping pattern). Verify against your Velociraptor release.\n"
        "remappings:\n"
        "  - type: permissions\n"
        "    permissions:\n"
        "      - COLLECT_CLIENT\n"
        "      - FILESYSTEM_READ\n"
        "  - type: impersonation\n"
        "    os: windows\n"
        "  - type: mount\n"
        "    description: dead disk image\n"
        "    from:\n"
        "      accessor: raw_ntfs\n"
        f"      prefix: '{image_path}'\n"
        "    'on':\n"
        "      accessor: ntfs\n"
        "      prefix: '\\\\.\\C:'\n"
    )
    config_path.write_text(yaml, encoding="utf-8")
    return config_path


def build_velociraptor_command(
    binary: str,
    image_path: Path,
    config_path: Path,
    output_zip: Path,
    *,
    artifact: str = DEFAULT_ARTIFACT,
    extra_args: list[str] | None = None,
) -> list[str]:
    """Construct the documented dead-disk collection command.

    Equivalent to::

        velociraptor --config <remap.yaml> artifacts collect <ARTIFACT> \\
            --output <collection.zip>

    Kept as a pure function so tests can assert on the argv without running
    anything.
    """
    cmd = [
        binary,
        "--config",
        str(config_path),
        "artifacts",
        "collect",
        artifact,
        "--output",
        str(output_zip),
    ]
    if extra_args:
        cmd.extend(extra_args)
    return cmd


def _run_velociraptor(cmd: list[str], *, timeout: int = 3600) -> subprocess.CompletedProcess:
    """Single mockable execution boundary. Tests patch this symbol."""
    return subprocess.run(
        cmd,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def extract_image_to_zip(
    image_path: str | Path,
    *,
    velociraptor_bin: str | None = None,
    artifact: str = DEFAULT_ARTIFACT,
    extra_args: list[str] | None = None,
    keep_temp: bool = False,
    temp_root: str | Path | None = None,
) -> ImageExtractionResult:
    """Run Velociraptor against a dead-disk image and return the collection ZIP.

    The returned ZIP is suitable as ``adapt(velociraptor_zip=...)`` input, so
    the image source reuses the entire existing layout/manifest architecture.

    Raises:
        FileNotFoundError          - image does not exist
        VelociraptorNotFoundError  - no binary resolved
        ImageExtractionError       - collection failed or produced no ZIP
    """
    img = Path(image_path).expanduser().resolve()
    if not img.is_file():
        raise FileNotFoundError(f"disk image not found: {img}")

    binary = resolve_velociraptor_bin(velociraptor_bin)

    temp_dir = Path(
        tempfile.mkdtemp(prefix="dfir-image-", dir=str(temp_root) if temp_root else None)
    )
    config_path = temp_dir / "remap.config.yaml"
    output_zip = temp_dir / "collection.zip"

    build_remapping_config(img, config_path)
    cmd = build_velociraptor_command(
        binary, img, config_path, output_zip,
        artifact=artifact, extra_args=extra_args,
    )

    result = ImageExtractionResult(
        collection_zip=output_zip, temp_dir=temp_dir, command=cmd, keep_temp=keep_temp,
    )

    try:
        proc = _run_velociraptor(cmd)
    except FileNotFoundError as e:  # binary vanished between resolve and exec
        result.cleanup()
        raise VelociraptorNotFoundError(str(e)) from e
    except Exception:
        result.cleanup()
        raise

    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        result.cleanup()
        raise ImageExtractionError(
            f"Velociraptor collection failed (exit {proc.returncode}). "
            f"Command: {' '.join(cmd)}. "
            f"stderr: {stderr[-800:] or '<empty>'}. "
            "Dead-disk remapping syntax is release-specific; verify the "
            "artifact name and accessor against your Velociraptor version, "
            "or pass a prepared collection ZIP via --source zip instead."
        )

    if not output_zip.is_file():
        result.cleanup()
        raise ImageExtractionError(
            "Velociraptor exited 0 but produced no collection ZIP at "
            f"{output_zip}. Verify the artifact emits a --output archive on "
            "your release."
        )

    result.extra = {"stdout_tail": (proc.stdout or "")[-400:]}
    return result

"""
Command-line entrypoint:

    # offline-collector ZIP (default, original behaviour)
    python3 -m dfir_collector_adapter --source zip \
        --input collector.zip --output evidence_root --case-id case-001

    # raw forensic disk image (.dd/.raw/.E01) via Velociraptor dead-disk
    python3 -m dfir_collector_adapter --source image \
        --input disk.E01 --output evidence_root --case-id case-001

Both sources converge on the same layout.py / manifest.py architecture and
write ``evidence_root/manifest.json``. Exits non-zero on any error so that
pipelines can chain it.
"""
from __future__ import annotations

import argparse
import json
import sys
import zipfile

from . import __version__
from .adapter import adapt
from .image_source import (
    ImageExtractionError,
    VelociraptorNotFoundError,
    extract_image_to_zip,
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dfir-collector-adapter",
        description=(
            "Convert a Velociraptor offline-collector ZIP, or a raw forensic "
            "disk image, into the Agentic-DFIR evidence_root layout (writes "
            "manifest.json with a SHA-256 index)."
        ),
    )
    p.add_argument("--source", choices=("zip", "image"), default="zip",
                   help="Input kind: 'zip' = Velociraptor offline-collector "
                        "ZIP (default); 'image' = raw disk image (.dd/.raw/"
                        ".E01) processed via Velociraptor dead-disk remapping.")
    p.add_argument("--input", "-i", required=True,
                   help="Path to the source ZIP (--source zip) or disk image "
                        "(--source image).")
    p.add_argument("--output", "-o", required=True,
                   help="Target evidence_root directory (created if missing).")
    p.add_argument("--case-id", default=None,
                   help="Case identifier written into manifest.json. "
                        "Defaults to the input basename.")
    p.add_argument("--overwrite", action="store_true",
                   help="Replace an existing manifest.json instead of failing.")
    p.add_argument("--no-hash-index", action="store_true",
                   help="Skip the sha256_index field in manifest.json (faster, less safe).")
    p.add_argument("--quiet", "-q", action="store_true",
                   help="Suppress progress output.")

    img = p.add_argument_group("image source (--source image)")
    img.add_argument("--velociraptor-bin", default=None,
                     help="Path to the Velociraptor binary. Resolution order: "
                          "this flag -> DFIR_VELOCIRAPTOR_BIN -> ./bin/ -> PATH.")
    img.add_argument("--artifact", default=None,
                     help="Velociraptor artifact to collect from the remapped "
                          "image (release-specific; overrides the default).")
    img.add_argument("--keep-temp", action="store_true",
                     help="Keep the temp directory holding the intermediate "
                          "collection ZIP instead of deleting it.")

    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _adapt_zip(zip_path: str, args: argparse.Namespace):
    return adapt(
        velociraptor_zip=zip_path,
        output_evidence_root=args.output,
        case_id=args.case_id,
        overwrite=args.overwrite,
        include_sha256_index=not args.no_hash_index,
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    extraction = None
    try:
        if args.source == "image":
            kwargs = {}
            if args.artifact:
                kwargs["artifact"] = args.artifact
            extraction = extract_image_to_zip(
                args.input,
                velociraptor_bin=args.velociraptor_bin,
                keep_temp=args.keep_temp,
                **kwargs,
            )
            if not args.quiet:
                print(f"[image] Velociraptor collection -> {extraction.collection_zip}",
                      file=sys.stderr)
            result = _adapt_zip(str(extraction.collection_zip), args)
        else:
            result = _adapt_zip(args.input, args)
    except VelociraptorNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 5
    except ImageExtractionError as e:
        print(f"error: {e}", file=sys.stderr)
        return 6
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except FileExistsError as e:
        print(f"error: {e}", file=sys.stderr)
        return 3
    except zipfile.BadZipFile as e:
        print(f"error: malformed ZIP: {e}", file=sys.stderr)
        return 4
    except Exception as e:
        print(f"error: {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    finally:
        if extraction is not None:
            extraction.cleanup()

    if not args.quiet:
        summary = {
            "output_root": str(result.output_root),
            "case_id": result.case_id,
            "files_copied": result.files_copied,
            "files_skipped": result.files_skipped,
            "bytes_copied": result.bytes_copied,
            "categories": result.categories,
            "source_sha256": result.source_sha256,
        }
        print(json.dumps(summary, indent=2, sort_keys=True))
        if result.skipped_paths:
            print(f"\n[note] {len(result.skipped_paths)} entries skipped",
                  file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

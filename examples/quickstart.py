#!/usr/bin/env python3
"""
examples/quickstart.py
======================

Build a tiny synthetic Velociraptor-shaped ZIP and run the adapter against
it. Useful for verifying your install without an actual incident host.

    python examples/quickstart.py /tmp/demo_out
"""
import json
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path

from dfir_collector_adapter import adapt


def build_demo_zip(zip_path: Path) -> None:
    """Synthesize a tiny ZIP that looks like Velociraptor offline-collector output."""
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("uploads/auto/C:/Windows/Prefetch/SVCHOST.EXE-ABC.pf",
                    b"PF\x00\x00synthetic-prefetch-content")
        zf.writestr("uploads/auto/C:/Windows/AppCompat/Programs/Amcache.hve",
                    b"AMCACHE-synthetic")
        zf.writestr("uploads/auto/C:/Windows/System32/config/SECURITY",
                    b"REGF" + b"\x00" * 28)
        zf.writestr("uploads/auto/C:/Windows/System32/winevt/Logs/Security.evtx",
                    b"ElfFile\x00synthetic")
        zf.writestr("uploads/auto/C:/Users/x/AppData/Local/Google/Chrome/User Data/Default/History",
                    b"SQLite format 3\x00")
        zf.writestr("uploads/auto/var/log/auth.log",
                    b"May 13 10:00:00 host sshd[1234]: Accepted publickey for x\n")
        zf.writestr("uploads/auto/inetpub/logs/LogFiles/W3SVC1/u_ex240513.log",
                    b"#Software: Microsoft Internet Information Services 10.0\n")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {Path(__file__).name} <output_evidence_root>", file=sys.stderr)
        return 2

    out_root = Path(argv[1]).resolve()
    if out_root.exists():
        shutil.rmtree(out_root)

    with tempfile.TemporaryDirectory() as tmp:
        zip_path = Path(tmp) / "demo_collector.zip"
        build_demo_zip(zip_path)
        print(f"[+] synthetic ZIP built: {zip_path}  ({zip_path.stat().st_size} bytes)")

        result = adapt(zip_path, out_root, case_id="demo-case")
        print(f"[+] adapter ran  ->  {out_root}")
        print(f"    files_copied : {result.files_copied}")
        print(f"    bytes_copied : {result.bytes_copied}")
        print(f"    categories   : {result.categories}")

    print("\n[+] evidence_root contents:")
    for p in sorted(out_root.rglob("*")):
        if p.is_file():
            rel = p.relative_to(out_root)
            print(f"      {rel}  ({p.stat().st_size} bytes)")

    print("\n[+] manifest.json head:")
    manifest = json.loads((out_root / "manifest.json").read_text(encoding="utf-8"))
    preview = {k: manifest[k] for k in ("case_id", "adapter", "counters", "categories")}
    print(json.dumps(preview, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

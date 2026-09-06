# Changelog

All notable changes to **agentic-dfir-collector-adapter** are documented here.
The adapter follows the [Agentic-DFIR](https://github.com/Juwon1405/agentic-dfir)
release line.

## [Unreleased]

### Changed
- README links to the core project's rollout roadmap follow it to
  `docs/roadmap.md` (the core README is now a landing page).

## [2.0.0] — 2026-09-05 — Renamed to agentic-dfir-collector-adapter

### Changed
- Renamed alongside the Agentic-DFIR core project. The Python package is now
  `dfir_collector_adapter`, the console script `dfir-collector-adapter`, and the
  Velociraptor override variable `DFIR_VELOCIRAPTOR_BIN` (previously
  `dart_collector_adapter` / `dart-collector-adapter` / `DART_VELOCIRAPTOR_BIN`).
  Update imports, shell aliases, and environment files accordingly.
- Version bumped to `2.0.0` because the import path and CLI name changed.
  No functional change: layout classification, `manifest.json` schema `1.2`,
  exit codes, and the `--source {zip,image}` behaviour are identical to `1.0.1`.
- Roadmap phases renumbered onto the v2.x line (`v2.1`–`v2.3`); their scope is
  unchanged.

### Fixed
- `README.md` hand-off section names the core runner `analyze.py` (the file was
  renamed from `run_eval.py` in June).
- `scripts/fetch-responder-binaries.sh` installs the adapter from the
  repository root (it pointed `pip install -e` at `scripts/`, which has no
  `pyproject.toml`) and stages the binaries under `./bin/velociraptor/` as the
  README documents, instead of `scripts/bin/`. Its usage text names itself.

## [1.0.1] — 2026-06-10 — Collision-safe manifest provenance

### Added
- Module entrypoint `python3 -m dfir_collector_adapter` (`__main__.py`).
- `--source {zip,image}` contract. `zip` keeps the original offline-collector
  behaviour; `image` accepts a raw forensic disk image (`.dd`/`.raw`/`.E01`)
  and runs a documented Velociraptor dead-disk remapping → collection ZIP →
  the existing `layout.py`/`manifest.py` extraction, producing the same
  `evidence_root/manifest.json`.
- Velociraptor binary resolution order for `--source image`:
  `--velociraptor-bin` → `DFIR_VELOCIRAPTOR_BIN` → staged `./bin/` → `PATH`,
  with a fail-fast actionable error when none resolves.
- `--keep-temp` and `--artifact` flags for the image path; intermediate files
  are otherwise removed after each run.
- Mocked end-to-end tests for the image path (image → collection ZIP →
  `manifest.json`), binary-resolution order, and failure exit codes. The image
  path has not been exercised against a live Velociraptor binary in CI.

### Fixed
- Prevented flat-layout filename collisions from silently overwriting earlier
  output files when multiple Velociraptor ZIP members share a basename such as
  `History`, `SYSTEM`, or `access.log`.
- Added deterministic digest suffixing for colliding output paths while keeping
  the public `evidence_root/<Category>/<basename>` layout.

### Changed
- Bumped `manifest.json` schema to `1.2` with `source_members`, a map from each
  output-relative path back to the original ZIP member path.
- Updated package metadata to the stable classifier and version `1.0.1`.
- Regenerated README and roadmap diagrams around manifest `1.2`.

## [1.0.0] — 2026-06-05 — First stable release

First stable release, aligned with Agentic-DFIR v1.0.0. The adapter's core job —
translating Velociraptor offline-collector output into the `evidence_root`
layout that Agentic-DFIR reads — is complete, hardened, and fully tested.

### Added
- This CHANGELOG.

### Changed
- Roadmap renumbered onto a v1.x line. `v1.0` (current, stable) consolidates the
  former `v0.1` (foundation) and `v0.2` (hardened integrity) milestones; sidecar
  generation, `results/*.json` ingest, and cross-platform artifact parity become
  `v1.1`–`v1.3`. The README roadmap table and the generated
  `docs/img/roadmap.png` were regenerated to match.

### Stable at release
- Velociraptor offline-collector ZIP -> `evidence_root` layout translation.
- `manifest.json` schema `1.1` — input-ZIP `source.sha256` anchor + `skipped`
  audit trail alongside the per-file SHA-256 index.
- Hardened integrity: ZIP-bomb + symlink defenses, single-pass hashing, mtime
  preservation, overwrite-safe writes.
- `install.sh` verifies the downloaded Velociraptor binary against the upstream
  SHA-256 manifest before use.
- 45 tests passing on Linux + macOS x py3.10/11/12. Zero runtime dependencies
  (standard library only).

## [0.2.0] — 2026-05-17 — Hardened integrity + manifest 1.1

- Manifest schema bumped to `1.1` (`source.sha256` input-ZIP anchor, `skipped`
  audit trail).
- ZIP-bomb + symlink defenses, single-pass hashing, mtime preservation,
  overwrite-safe writes.
- Hardened `install.sh` with install-time binary checksum verification.
- Single-source version.

## [0.1.1] — 2026-05-14 — Initial adapter

- Velociraptor offline-collector ZIP -> `evidence_root` with SHA-256 manifest.
- Full test suite passing on Linux + macOS x py3.10/11/12.

# Contributing

Thank you for considering a contribution.

This adapter is deliberately small. The goal is to keep it small. Please read this guide before opening a PR — it will save us both time.

## Scope

This repo is **only** the layout-normalization layer between Velociraptor offline-collector ZIPs and the [Agentic-DFIR](https://github.com/Juwon1405/agentic-dfir) `evidence_root/` layout.

Things that **belong** here:
- New artifact patterns in `src/dfir_collector_adapter/layout.py`
- Improvements to `manifest.json` integrity (extra fields, stronger hashing)
- Bug fixes in path-safety, ZIP traversal handling, large-file streaming
- Sidecar parser invocation (e.g., calling `EvtxECmd` when available) — planned for v1.1
- New tests

Things that **do not belong** here:
- Velociraptor agent code, VQL artifacts, or anything that would normally live upstream
- The forensic analysis itself (that goes in Agentic-DFIR)
- A web UI, a database, a service daemon

## Development

```bash
git clone https://github.com/Juwon1405/agentic-dfir-collector-adapter
cd agentic-dfir-collector-adapter
pip install -e ".[dev]"
pytest -q
```

CI runs on Linux + macOS × Python 3.10/3.11/3.12. Please add tests for any new behavior; the bar is **every new branch covered**.

## Pull requests

- Keep the diff focused. One concern per PR.
- New artifact patterns: add at least one positive test and one negative test in `tests/test_layout.py`.
- New CLI flag: update `README.md` Usage section.
- No new runtime dependencies. Stdlib only.

## Security issues

If you find a path-traversal or ZIP-bomb mitigation gap, please **do not** open a public issue. Email `juwon1405.jp@gmail.com` instead.

## Code style

- `ruff` / `black` welcome but not enforced yet.
- Type hints on every public function.
- Docstrings on every public function, please.

Thanks again.

#!/usr/bin/env bash
# install.sh — bootstrap script for agentic-dfir-collector-adapter
#
# What this script does:
#   1. Detects the host OS/arch.
#   2. Downloads the matching Velociraptor binary from the upstream
#      GitHub release.
#   3. Downloads the upstream `sha256sums` manifest and verifies the
#      downloaded binary's SHA-256 against it. A mismatch results in
#      the binary being deleted, the script exiting non-zero, and an
#      error message naming the expected vs. actual hash.
#   4. (Optional) Installs the Python package via `pip install -e .`
#      so the `dfir-collector-adapter` console script is on PATH.
#
# Flags:
#   --skip-checksum       Skip SHA-256 verification of the
#                         Velociraptor binary. NOT RECOMMENDED.
#                         You are explicitly trusting the download
#                         channel when you pass this.
#   --no-velociraptor     Install only the Python package; do not
#                         download Velociraptor.
#   --install-dir <path>  Where to place the Velociraptor binary
#                         (default: ./bin).
#   --version <X.Y.Z>     Velociraptor version to install
#                         (default: latest release).
#   --help                Print this help and exit.
#
# Exit codes:
#   0  success
#   1  generic failure (missing dep, network error, etc.)
#   2  SHA-256 mismatch on Velociraptor binary
#   3  unknown flag
set -euo pipefail

# ─── Defaults ────────────────────────────────────────────────────────
SKIP_CHECKSUM=false
NO_VELOCIRAPTOR=false
INSTALL_DIR="./bin"
VELOCIRAPTOR_VERSION=""   # empty = look up latest

# ─── Helpers ─────────────────────────────────────────────────────────
log()  { printf "\033[1;34m[install]\033[0m %s\n" "$*"; }
ok()   { printf "\033[1;32m[ ok ]\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m[warn]\033[0m %s\n" "$*" >&2; }
err()  { printf "\033[1;31m[err ]\033[0m %s\n" "$*" >&2; }

usage() {
  sed -n '2,/^set -euo pipefail$/p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
}

# ─── Parse args ──────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-checksum)     SKIP_CHECKSUM=true; shift ;;
    --no-velociraptor)   NO_VELOCIRAPTOR=true; shift ;;
    --install-dir)       INSTALL_DIR="$2"; shift 2 ;;
    --version)           VELOCIRAPTOR_VERSION="$2"; shift 2 ;;
    --help|-h)           usage ;;
    *)
      err "Unknown flag: $1"
      err "Run with --help for usage."
      exit 3
      ;;
  esac
done

# ─── 1. Python package ───────────────────────────────────────────────
log "Installing Python package (editable)"
python3 -m pip install --upgrade pip wheel >/dev/null
python3 -m pip install -e . >/dev/null
ok "dfir-collector-adapter installed (console script: dfir-collector-adapter)"

# ─── 2. Velociraptor (optional) ──────────────────────────────────────
if [[ "$NO_VELOCIRAPTOR" == "true" ]]; then
  ok "Skipping Velociraptor download (--no-velociraptor)"
  log "Done."
  exit 0
fi

# Detect OS/arch
UNAME_S="$(uname -s)"
UNAME_M="$(uname -m)"
case "$UNAME_S/$UNAME_M" in
  Linux/x86_64)   VR_ASSET_PATTERN="velociraptor-v.*-linux-amd64"; VR_PLATFORM="linux" ;;
  Linux/aarch64)  VR_ASSET_PATTERN="velociraptor-v.*-linux-arm64"; VR_PLATFORM="linux" ;;
  Darwin/x86_64)  VR_ASSET_PATTERN="velociraptor-v.*-darwin-amd64"; VR_PLATFORM="darwin" ;;
  Darwin/arm64)   VR_ASSET_PATTERN="velociraptor-v.*-darwin-arm64"; VR_PLATFORM="darwin" ;;
  *)
    err "Unsupported platform: $UNAME_S/$UNAME_M"
    err "Run with --no-velociraptor to install Python package only."
    exit 1
    ;;
esac

# Resolve version (latest if unspecified)
if [[ -z "$VELOCIRAPTOR_VERSION" ]]; then
  log "Looking up latest Velociraptor release..."
  VELOCIRAPTOR_VERSION="$(curl -sL https://api.github.com/repos/Velocidex/velociraptor/releases/latest \
    | grep -oE '"tag_name":\s*"v[0-9.]+' \
    | head -1 \
    | grep -oE 'v[0-9.]+' \
    | sed 's/^v//')"
  if [[ -z "$VELOCIRAPTOR_VERSION" ]]; then
    err "Could not resolve latest Velociraptor version (network issue?)."
    exit 1
  fi
fi
log "Velociraptor version: $VELOCIRAPTOR_VERSION ($UNAME_S/$UNAME_M)"

mkdir -p "$INSTALL_DIR"
RELEASE_URL="https://github.com/Velocidex/velociraptor/releases/download/v${VELOCIRAPTOR_VERSION}"

# Find the asset filename for this platform
log "Resolving asset filename..."
ASSET_LIST="$(curl -sL "https://api.github.com/repos/Velocidex/velociraptor/releases/tags/v${VELOCIRAPTOR_VERSION}" \
  | grep -oE '"name":\s*"velociraptor-v[^"]+"' \
  | sed -E 's/.*"name":\s*"([^"]+)".*/\1/')"
ASSET="$(echo "$ASSET_LIST" | grep -E "$VR_ASSET_PATTERN" | grep -v '\.sig$' | head -1)"
if [[ -z "$ASSET" ]]; then
  err "No matching asset found for pattern: $VR_ASSET_PATTERN"
  err "Available assets:"
  echo "$ASSET_LIST" | sed 's/^/  /' >&2
  exit 1
fi
log "Asset: $ASSET"

# Download binary
BINARY_PATH="$INSTALL_DIR/$ASSET"
log "Downloading $ASSET..."
curl -sL --fail "$RELEASE_URL/$ASSET" -o "$BINARY_PATH" || {
  err "Download failed: $RELEASE_URL/$ASSET"
  exit 1
}
ok "Downloaded to $BINARY_PATH"

# Verify SHA-256
if [[ "$SKIP_CHECKSUM" == "true" ]]; then
  warn "Skipping SHA-256 verification (--skip-checksum). You are trusting the download channel."
else
  log "Verifying SHA-256 (trying upstream sha256sums first, then GitHub API)..."
  SUMS_PATH="$INSTALL_DIR/.sha256sums"
  EXPECTED=""

  # Strategy 1: legacy sha256sums manifest (pre-2026 releases shipped this).
  if curl -sL --fail "$RELEASE_URL/sha256sums" -o "$SUMS_PATH" 2>/dev/null \
     || curl -sL --fail "$RELEASE_URL/sha256sums.txt" -o "$SUMS_PATH" 2>/dev/null; then
    EXPECTED="$(grep -E "[[:space:]]+\*?${ASSET}\$" "$SUMS_PATH" | awk '{print $1}' | head -1)"
    [[ -n "$EXPECTED" ]] && log "  source: upstream sha256sums manifest"
  fi

  # Strategy 2: GitHub API asset digest (modern Velociraptor releases stopped
  # shipping sha256sums and only sign with GPG .sig files; GitHub still records
  # each asset's SHA-256 as the digest field in the release API. This is the
  # authoritative source as long as you trust GitHub's TLS / their release
  # storage, which is the same trust boundary as the download itself).
  if [[ -z "$EXPECTED" ]]; then
    log "  upstream sha256sums not found; falling back to GitHub API asset digest"
    EXPECTED="$(curl -sL --fail \
      "https://api.github.com/repos/Velocidex/velociraptor/releases/tags/v${VELOCIRAPTOR_VERSION}" \
      2>/dev/null \
      | python3 -c "
import json, sys, re
try:
    d = json.load(sys.stdin)
    for a in d.get('assets', []):
        if a.get('name') == '${ASSET}':
            m = re.match(r'sha256:([a-f0-9]{64})\$', a.get('digest', ''))
            if m:
                print(m.group(1))
            break
except Exception:
    pass
" 2>/dev/null)"
    [[ -n "$EXPECTED" ]] && log "  source: GitHub API release asset digest"
  fi

  if [[ -z "$EXPECTED" ]]; then
    err "Could not obtain SHA-256 for $ASSET from any source."
    err "Tried: sha256sums manifest at $RELEASE_URL, GitHub API release digest."
    err "If you must proceed without checksum verification, re-run with --skip-checksum."
    rm -f "$BINARY_PATH"
    exit 2
  fi

  if command -v sha256sum >/dev/null; then
    ACTUAL="$(sha256sum "$BINARY_PATH" | awk '{print $1}')"
  elif command -v shasum >/dev/null; then
    ACTUAL="$(shasum -a 256 "$BINARY_PATH" | awk '{print $1}')"
  else
    err "Neither sha256sum nor shasum available. Cannot verify."
    rm -f "$BINARY_PATH"
    exit 1
  fi

  if [[ "$EXPECTED" != "$ACTUAL" ]]; then
    err "SHA-256 mismatch!"
    err "  expected: $EXPECTED"
    err "  actual:   $ACTUAL"
    err "  asset:    $ASSET"
    err "Refusing to keep a tampered binary. Deleting."
    rm -f "$BINARY_PATH"
    rm -f "$SUMS_PATH"
    exit 2
  fi
  ok "SHA-256 verified: $EXPECTED"
  rm -f "$SUMS_PATH"
fi

chmod +x "$BINARY_PATH"
ok "Velociraptor ready: $BINARY_PATH"

# Create a version-agnostic 'velociraptor' name next to the versioned binary.
# The downloaded asset is named e.g. velociraptor-v0.76.6-linux-amd64, but the
# adapter's resolver (image_source.py: _BINARY_NAMES) looks for a plain
# 'velociraptor' in the staged bin dir. Without this link, the binary is
# present but invisible to --source image, which is exactly the failure mode
# this whole installer exists to prevent. Prefer a symlink; fall back to a
# copy on filesystems that do not support symlinks.
STABLE_BIN="$INSTALL_DIR/velociraptor"
if [[ "$(realpath "$BINARY_PATH")" != "$(realpath "$STABLE_BIN" 2>/dev/null || echo /nonexistent)" ]]; then
  rm -f "$STABLE_BIN"
  if ln -s "$(basename "$BINARY_PATH")" "$STABLE_BIN" 2>/dev/null; then
    ok "Linked $STABLE_BIN -> $(basename "$BINARY_PATH")"
  elif cp "$BINARY_PATH" "$STABLE_BIN" 2>/dev/null; then
    chmod +x "$STABLE_BIN"
    ok "Copied $BINARY_PATH -> $STABLE_BIN (symlink unsupported here)"
  else
    warn "Could not create a plain 'velociraptor' name at $STABLE_BIN;"
    warn "--source image may not find the binary. Set DFIR_VELOCIRAPTOR_BIN=$BINARY_PATH"
  fi
fi

log "Add to PATH (suggested):"
echo "  export PATH=\"\$(realpath $INSTALL_DIR):\$PATH\""
log "Done."

#!/usr/bin/env bash
# ===========================================================================
# fetch-responder-binaries.sh
#
# Downloads Velociraptor agent binaries for EVERY common (OS, arch) combo
# into ./bin/velociraptor/ so that responders can ship the right binary to
# each incident host without leaving the analysis server.
#
# This is the MULTI-PLATFORM fetcher, distinct from scripts/install.sh:
#   - scripts/install.sh             installs the adapter + ONE Velociraptor
#                                    binary matching the current host (for
#                                    the analyst's own machine).
#   - scripts/fetch-responder-binaries.sh (this file) pulls binaries for ALL
#                                    platforms so responders can push the
#                                    correct one to Windows/Linux/macOS
#                                    incident hosts.
#
# Run this on the analysis server (Linux or macOS). It does NOT install
# anything on incident hosts; it only stages binaries for distribution.
#
# Usage:
#   ./install.sh                       # full setup
#   VELO_VERSION=0.74.0 ./install.sh   # pin a specific Velociraptor version
#   ./install.sh --no-velociraptor     # adapter only (skip binaries)
#   ./install.sh --skip-checksum       # skip SHA-256 verification (NOT recommended)
# ===========================================================================
set -euo pipefail

# Default version; override via env var to bump.
VELO_VERSION="${VELO_VERSION:-0.73.4}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="${SCRIPT_DIR}/bin/velociraptor"
SKIP_VELO=0
SKIP_CHECKSUM=0
for arg in "$@"; do
    case "${arg}" in
        --no-velociraptor) SKIP_VELO=1 ;;
        --skip-checksum)   SKIP_CHECKSUM=1 ;;
        -h|--help)
            sed -n '2,18p' "${BASH_SOURCE[0]}"
            exit 0
            ;;
        *)
            echo "error: unknown argument: ${arg}" >&2
            echo "run with --help for usage." >&2
            exit 1
            ;;
    esac
done

# Velociraptor release matrix that responders typically need.
# Format: "os-arch:release-asset-suffix"
VELO_TARGETS=(
    "windows-amd64:windows-amd64.exe"
    "windows-arm64:windows-arm64.exe"
    "linux-amd64:linux-amd64"
    "linux-arm64:linux-arm64"
    "darwin-amd64:darwin-amd64"
    "darwin-arm64:darwin-arm64"
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
fetch() {
    # fetch <url> <dest>  — returns 0 on success.
    local url="$1" dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fSL -o "${dest}" "${url}"
    elif command -v wget >/dev/null 2>&1; then
        wget -O "${dest}" "${url}"
    else
        echo "error: neither curl nor wget is available" >&2
        return 1
    fi
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        echo "error: neither sha256sum nor shasum found" >&2
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Step 1 — adapter (Python, OS-agnostic)
# ---------------------------------------------------------------------------
echo "==> Step 1/2: installing dfir-collector-adapter (Python)"
PYTHON_BIN="$(command -v python3 || command -v python || true)"
if [[ -z "${PYTHON_BIN}" ]]; then
    echo "error: python3 not found on PATH" >&2
    exit 1
fi
"${PYTHON_BIN}" -m pip install --upgrade --user -e "${SCRIPT_DIR}" >/dev/null
echo "    adapter installed: $(command -v dfir-collector-adapter 2>/dev/null || echo '(use python -m dfir_collector_adapter.cli)')"

# ---------------------------------------------------------------------------
# Step 2 — Velociraptor binaries for every (OS, arch) combo
# ---------------------------------------------------------------------------
if [[ "${SKIP_VELO}" -eq 1 ]]; then
    echo "==> Step 2/2: skipped (--no-velociraptor)"
    exit 0
fi

echo "==> Step 2/2: downloading Velociraptor v${VELO_VERSION} binaries"
mkdir -p "${BIN_DIR}"

# Pull the upstream checksum manifest once. Velocidex publishes a sha256sum
# file alongside every release; we use it to detect tampered downloads.
# (This does NOT defeat an attacker who controls the GitHub account itself
#  — for that you need GPG signature verification. Documented in README.)
CHECKSUM_URL="https://github.com/Velocidex/velociraptor/releases/download/v${VELO_VERSION}/sha256sums"
CHECKSUM_FILE="${BIN_DIR}/.sha256sums"
CHECKSUM_AVAILABLE=0
if [[ "${SKIP_CHECKSUM}" -eq 1 ]]; then
    echo "    [warn] --skip-checksum: integrity verification disabled"
elif fetch "${CHECKSUM_URL}" "${CHECKSUM_FILE}" >/dev/null 2>&1; then
    CHECKSUM_AVAILABLE=1
    echo "    [ok]   checksum manifest pulled"
else
    rm -f "${CHECKSUM_FILE}"
    echo "    [warn] checksum manifest not available for v${VELO_VERSION}"
    echo "           (verify each binary manually or pass --skip-checksum)"
fi

for target in "${VELO_TARGETS[@]}"; do
    os_arch="${target%%:*}"
    suffix="${target##*:}"
    asset="velociraptor-v${VELO_VERSION}-${suffix}"
    url="https://github.com/Velocidex/velociraptor/releases/download/v${VELO_VERSION}/${asset}"
    dst="${BIN_DIR}/velociraptor-${os_arch}"

    if [[ -f "${dst}" ]]; then
        echo "    [skip] ${os_arch}  (already present)"
        continue
    fi

    echo "    [fetch] ${os_arch}"
    if ! fetch "${url}" "${dst}"; then
        echo "    [warn] failed to download ${os_arch}, continuing"
        rm -f "${dst}"
        continue
    fi

    if [[ "${CHECKSUM_AVAILABLE}" -eq 1 ]]; then
        expected="$(awk -v a="${asset}" '$2 == a || $2 == "*"a {print $1}' "${CHECKSUM_FILE}" | head -n1)"
        if [[ -z "${expected}" ]]; then
            echo "    [warn] ${os_arch}: no entry in checksum manifest, leaving file in place"
        else
            actual="$(sha256_of "${dst}")"
            if [[ "${expected}" != "${actual}" ]]; then
                echo "    [FAIL] ${os_arch}: checksum mismatch — removing"
                echo "           expected ${expected}"
                echo "           actual   ${actual}"
                rm -f "${dst}"
                continue
            fi
            echo "    [ok]   ${os_arch}: SHA-256 verified"
        fi
    fi

    chmod +x "${dst}" 2>/dev/null || true
done

echo ""
echo "Done."
echo "  Adapter:               dfir-collector-adapter --help"
echo "  Velociraptor binaries: ${BIN_DIR}"
echo ""
echo "Ship the matching binary to each incident host. For example:"
echo "  scp ${BIN_DIR}/velociraptor-windows-amd64  responder@incident-host:C:/temp/"

#!/usr/bin/env bash
# dep-scan installer
# Usage: curl -fsSL https://raw.githubusercontent.com/tkdtaylor/dep-scan/main/install.sh | bash
#
# Options:
#   --dry-run     Print what would be done without downloading
#   INSTALL_DIR   Override install directory (default: ~/.local/bin)
#
# Examples:
#   curl -fsSL .../install.sh | bash
#   curl -fsSL .../install.sh | INSTALL_DIR=/usr/local/bin sudo bash
#   curl -fsSL .../install.sh | bash -s -- --dry-run

set -euo pipefail

REPO="tkdtaylor/dep-scan"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
DRY_RUN=false

# Temp directory at script scope so the EXIT trap survives `main` returning.
# Declared and initialized before `main` runs so `set -u` is happy.
TMPDIR=""
cleanup() {
  if [ -n "$TMPDIR" ]; then
    rm -rf "$TMPDIR"
  fi
  return 0
}
trap cleanup EXIT

NO_VERIFY=false
PIN_VERSION=""
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=true ;;
    --no-verify) NO_VERIFY=true ;;
    --version=*) PIN_VERSION="${arg#--version=}" ;;
  esac
done

# Detect OS
detect_os() {
  case "$(uname -s)" in
    Linux*)  echo "linux" ;;
    Darwin*) echo "macos" ;;
    MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
    *) echo "unknown" ;;
  esac
}

# Detect architecture
detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64)  echo "x86_64" ;;
    arm64|aarch64)  echo "aarch64" ;;
    *) echo "unknown" ;;
  esac
}

# Map OS + arch to release target triple
get_target() {
  local os="$1" arch="$2"
  case "${os}-${arch}" in
    linux-x86_64)   echo "x86_64-unknown-linux-gnu" ;;
    linux-aarch64)  echo "aarch64-unknown-linux-gnu" ;;
    macos-x86_64)   echo "x86_64-apple-darwin" ;;
    macos-aarch64)  echo "aarch64-apple-darwin" ;;
    windows-x86_64) echo "x86_64-pc-windows-msvc" ;;
    *) echo "" ;;
  esac
}

# Get latest release tag from GitHub API
get_latest_version() {
  curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' \
    | head -1 \
    | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/'
}

main() {
  local os arch target version ext

  os="$(detect_os)"
  arch="$(detect_arch)"
  target="$(get_target "$os" "$arch")"

  if [ -z "$target" ]; then
    echo "Error: unsupported platform ${os}/${arch}" >&2
    exit 1
  fi

  echo "Detected platform: ${os}/${arch} (${target})"

  if [ -n "$PIN_VERSION" ]; then
    version="$PIN_VERSION"
    echo "Pinned version: ${version}"
  else
    version="$(get_latest_version)"
    if [ -z "$version" ]; then
      echo "Error: could not determine latest version" >&2
      exit 1
    fi
    echo "Latest version: ${version}"
  fi

  if [ "$os" = "windows" ]; then
    ext="zip"
  else
    ext="tar.gz"
  fi

  local filename="dep-scan-${version}-${target}.${ext}"
  local url="https://github.com/${REPO}/releases/download/${version}/${filename}"
  local checksums_url="https://github.com/${REPO}/releases/download/${version}/sha256sums.txt"

  echo "Binary: ${filename}"
  echo "Install directory: ${INSTALL_DIR}"

  if [ "$DRY_RUN" = true ]; then
    echo ""
    echo "[dry-run] Would download: ${url}"
    echo "[dry-run] Would verify checksum from: ${checksums_url}"
    echo "[dry-run] Would install to: ${INSTALL_DIR}/dep-scan"
    exit 0
  fi

  # Create temp directory (assigned to script-scope TMPDIR so the trap can clean it up)
  TMPDIR="$(mktemp -d)"

  echo ""
  echo "Downloading ${filename}..."
  curl -fsSL "$url" -o "${TMPDIR}/${filename}"

  # Verify checksum
  echo "Verifying checksum..."
  curl -fsSL "$checksums_url" -o "${TMPDIR}/sha256sums.txt"
  cd "$TMPDIR"
  if command -v sha256sum >/dev/null 2>&1; then
    grep "$filename" sha256sums.txt | sha256sum -c --quiet
  elif command -v shasum >/dev/null 2>&1; then
    grep "$filename" sha256sums.txt | shasum -a 256 -c --quiet
  elif [ "$NO_VERIFY" = true ]; then
    echo "Warning: checksum verification SKIPPED (--no-verify; no sha256sum/shasum found)"
  else
    echo "Error: cannot verify the download — neither sha256sum nor shasum is installed." >&2
    echo "Install one of them, or re-run with --no-verify to accept an unverified binary." >&2
    exit 1
  fi
  cd - >/dev/null

  # Extract
  echo "Extracting..."
  if [ "$ext" = "tar.gz" ]; then
    tar xzf "${TMPDIR}/${filename}" -C "$TMPDIR"
  else
    unzip -q "${TMPDIR}/${filename}" -d "$TMPDIR"
  fi

  # Install
  mkdir -p "$INSTALL_DIR"
  mv "${TMPDIR}/dep-scan" "${INSTALL_DIR}/dep-scan"
  chmod +x "${INSTALL_DIR}/dep-scan"

  echo ""
  echo "dep-scan ${version} installed to ${INSTALL_DIR}/dep-scan"

  # Check if INSTALL_DIR is in PATH
  if ! echo "$PATH" | tr ':' '\n' | grep -qF "$INSTALL_DIR"; then
    echo ""
    echo "Note: ${INSTALL_DIR} is not in your PATH. Add it with:"
    echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
    echo ""
    echo "To make permanent, add that line to your ~/.bashrc or ~/.zshrc"
  fi

  echo ""
  echo "Get started:"
  echo "  dep-scan check lodash express --registry npm"
  echo "  dep-scan check requests flask --registry pypi"
  echo "  dep-scan --help"
}

main "$@"

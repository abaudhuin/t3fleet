#!/usr/bin/env sh
# Install t3fleet (and optionally t3fleet-server) from GitHub Releases.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/abaudhuin/t3fleet/main/install.sh | sh
#   curl -fsSL https://raw.githubusercontent.com/abaudhuin/t3fleet/main/install.sh | sh -s -- --server
#
# Environment:
#   T3FLEET_VERSION      Release tag to install (default: latest)
#   T3FLEET_INSTALL_DIR  Destination directory (default: ~/.local/bin)
#   T3FLEET_REPO         GitHub repo (default: abaudhuin/t3fleet)
set -eu

REPO="${T3FLEET_REPO:-abaudhuin/t3fleet}"
INSTALL_DIR="${T3FLEET_INSTALL_DIR:-$HOME/.local/bin}"
VERSION="${T3FLEET_VERSION:-latest}"
INCLUDE_SERVER=0

for arg in "$@"; do
  case "$arg" in
    --server) INCLUDE_SERVER=1 ;;
    --help|-h)
      echo "Usage: install.sh [--server]"
      exit 0
      ;;
    *)
      echo "Unknown option: $arg" >&2
      exit 1
      ;;
  esac
done

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux)  OS_TAG="unknown-linux-gnu" ;;
  Darwin) OS_TAG="apple-darwin" ;;
  *)
    echo "Unsupported OS: $OS (use install.ps1 on Windows)" >&2
    exit 1
    ;;
esac

case "$ARCH" in
  x86_64|amd64)  ARCH_TAG="x86_64" ;;
  aarch64|arm64) ARCH_TAG="aarch64" ;;
  *)
    echo "Unsupported architecture: $ARCH" >&2
    exit 1
    ;;
esac

TARGET="${ARCH_TAG}-${OS_TAG}"

if [ "$VERSION" = "latest" ]; then
  BASE_URL="https://github.com/${REPO}/releases/latest/download"
else
  BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
fi

ARCHIVE="t3fleet-${TARGET}.tar.gz"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

echo "Downloading ${ARCHIVE} from ${REPO} (${VERSION})..."
curl -fsSL "${BASE_URL}/${ARCHIVE}" -o "${TMPDIR}/${ARCHIVE}"
curl -fsSL "${BASE_URL}/SHA256SUMS.txt" -o "${TMPDIR}/SHA256SUMS.txt"

EXPECTED="$(awk -v f="$ARCHIVE" '$2 == f || $2 == ("*" f) { print $1; exit }' "${TMPDIR}/SHA256SUMS.txt")"
if [ -z "$EXPECTED" ]; then
  echo "Checksum entry for ${ARCHIVE} not found in SHA256SUMS.txt" >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL="$(sha256sum "${TMPDIR}/${ARCHIVE}" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  ACTUAL="$(shasum -a 256 "${TMPDIR}/${ARCHIVE}" | awk '{print $1}')"
else
  echo "Neither sha256sum nor shasum found; cannot verify download." >&2
  exit 1
fi

if [ "$EXPECTED" != "$ACTUAL" ]; then
  echo "Checksum mismatch for ${ARCHIVE}!" >&2
  echo "  expected: $EXPECTED" >&2
  echo "  actual:   $ACTUAL" >&2
  exit 1
fi

tar -xzf "${TMPDIR}/${ARCHIVE}" -C "${TMPDIR}"
mkdir -p "${INSTALL_DIR}"

install -m 0755 "${TMPDIR}/t3fleet" "${INSTALL_DIR}/t3fleet"
echo "Installed t3fleet to ${INSTALL_DIR}/t3fleet"

if [ "$INCLUDE_SERVER" -eq 1 ]; then
  if [ -f "${TMPDIR}/t3fleet-server" ]; then
    install -m 0755 "${TMPDIR}/t3fleet-server" "${INSTALL_DIR}/t3fleet-server"
    echo "Installed t3fleet-server to ${INSTALL_DIR}/t3fleet-server"
  else
    echo "Warning: t3fleet-server binary not included in ${ARCHIVE}" >&2
  fi
fi

case ":${PATH}:" in
  *":${INSTALL_DIR}:"*) ;;
  *)
    echo ""
    echo "Add ${INSTALL_DIR} to your PATH:"
    echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
    ;;
esac

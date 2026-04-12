#!/bin/sh
# piilex installer — downloads the latest release binary
# Usage: curl -sSfL https://raw.githubusercontent.com/piilex/piilex/main/install.sh | sh

set -e

REPO="piilex/piilex"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

# Detect platform
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$OS" in
  linux)   OS_TARGET="unknown-linux-gnu"  ;;
  darwin)  OS_TARGET="apple-darwin"       ;;
  *)       echo "Error: unsupported OS: $OS"; exit 1 ;;
esac

case "$ARCH" in
  x86_64|amd64)   ARCH_TARGET="x86_64"  ;;
  aarch64|arm64)   ARCH_TARGET="aarch64" ;;
  *)               echo "Error: unsupported architecture: $ARCH"; exit 1 ;;
esac

TARGET="${ARCH_TARGET}-${OS_TARGET}"

# Get latest version
if [ -n "$PIILEX_VERSION" ]; then
  VERSION="$PIILEX_VERSION"
else
  VERSION=$(curl -sSf "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' | head -1 | cut -d '"' -f 4)
fi

if [ -z "$VERSION" ]; then
  echo "Error: could not determine latest version"
  exit 1
fi

URL="https://github.com/${REPO}/releases/download/${VERSION}/piilex-${VERSION}-${TARGET}.tar.gz"

echo "Installing piilex ${VERSION} for ${TARGET}..."
echo "  Download: ${URL}"
echo "  Install:  ${INSTALL_DIR}/piilex"

# Download and extract
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

curl -sSfL "$URL" | tar xz -C "$TMPDIR"

# Install
if [ -w "$INSTALL_DIR" ]; then
  mv "$TMPDIR/piilex" "$INSTALL_DIR/piilex"
else
  echo "  (requires sudo for ${INSTALL_DIR})"
  sudo mv "$TMPDIR/piilex" "$INSTALL_DIR/piilex"
fi

chmod +x "$INSTALL_DIR/piilex"

echo ""
echo "✓ piilex ${VERSION} installed to ${INSTALL_DIR}/piilex"
echo ""
echo "Get started:"
echo "  piilex init --framework gdpr"
echo "  piilex scan ./src"

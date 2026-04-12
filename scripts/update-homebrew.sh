#!/usr/bin/env bash
#
# Update the Homebrew formula in the piilex/homebrew-piilex tap.
#
# Usage:
#   ./scripts/update-homebrew.sh <version>
#
# Environment:
#   GITHUB_TOKEN   - Token with push access to piilex/homebrew-piilex
#   GITHUB_REPO    - Main repo (default: piilex/piilex)
#   TAP_REPO       - Tap repo (default: piilex/homebrew-piilex)
#
# This script:
#   1. Downloads release assets to compute SHA256 checksums
#   2. Generates a new Formula/piilex.rb with correct URLs and checksums
#   3. Commits and pushes to the tap repository

set -euo pipefail

VERSION="${1:?Usage: update-homebrew.sh <version>}"
VERSION_BARE="${VERSION#v}"  # strip leading 'v'

GITHUB_REPO="${GITHUB_REPO:-piilex/piilex}"
TAP_REPO="${TAP_REPO:-piilex/homebrew-piilex}"
BASE_URL="https://github.com/${GITHUB_REPO}/releases/download/v${VERSION_BARE}"

echo "Updating Homebrew formula for piilex v${VERSION_BARE}"
echo "  Release URL base: ${BASE_URL}"

# ── Compute SHA256 for each platform ──────────────────────────

compute_sha() {
  local target="$1"
  local url="${BASE_URL}/piilex-v${VERSION_BARE}-${target}.tar.gz"
  echo "  Downloading ${target}..." >&2
  curl -sSfL "$url" | sha256sum | cut -d' ' -f1
}

echo "Computing checksums..."
SHA_LINUX_X64=$(compute_sha "x86_64-unknown-linux-gnu")
SHA_LINUX_ARM=$(compute_sha "aarch64-unknown-linux-gnu")
SHA_MACOS_X64=$(compute_sha "x86_64-apple-darwin")
SHA_MACOS_ARM=$(compute_sha "aarch64-apple-darwin")

echo "  linux-x64:  ${SHA_LINUX_X64}"
echo "  linux-arm:  ${SHA_LINUX_ARM}"
echo "  macos-x64:  ${SHA_MACOS_X64}"
echo "  macos-arm:  ${SHA_MACOS_ARM}"

# ── Generate formula ──────────────────────────────────────────

FORMULA='# typed: false
# frozen_string_literal: true

# Formula automatically updated by release workflow.
# Manual edits will be overwritten on next release.
class Piilex < Formula
  desc "PII Lexical Analyzer -- Detect PII in source code and map to regulatory frameworks"
  homepage "https://github.com/'"${GITHUB_REPO}"'"
  version "'"${VERSION_BARE}"'"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "'"${BASE_URL}"'/piilex-v'"${VERSION_BARE}"'-aarch64-apple-darwin.tar.gz"
      sha256 "'"${SHA_MACOS_ARM}"'"
    else
      url "'"${BASE_URL}"'/piilex-v'"${VERSION_BARE}"'-x86_64-apple-darwin.tar.gz"
      sha256 "'"${SHA_MACOS_X64}"'"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "'"${BASE_URL}"'/piilex-v'"${VERSION_BARE}"'-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "'"${SHA_LINUX_ARM}"'"
    else
      url "'"${BASE_URL}"'/piilex-v'"${VERSION_BARE}"'-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "'"${SHA_LINUX_X64}"'"
    end
  end

  def install
    bin.install "piilex"
  end

  test do
    assert_match "piilex #{version}", shell_output("#{bin}/piilex --version")

    (testpath/"test.ts").write <<~EOS
      const email = "user@example.com";
      const count = 42;
    EOS
    output = shell_output("#{bin}/piilex scan #{testpath}/test.ts -o json")
    assert_match %q("pii_type"), output

    (testpath/"clean.ts").write <<~EOS
      const total = 100;
      function add(a: number, b: number) { return a + b; }
    EOS
    clean_output = shell_output("#{bin}/piilex scan #{testpath}/clean.ts -o json")
    assert_match %q("findings": []), clean_output

    system "#{bin}/piilex", "init"
    assert_predicate testpath/".piilex.yml", :exist?
  end
end'

echo ""
echo "Generated formula:"
echo "${FORMULA}" | head -5
echo "  ..."

# ── Clone and update tap ─────────────────────────────────────

TMPDIR=$(mktemp -d)
trap "rm -rf ${TMPDIR}" EXIT

echo ""
echo "Cloning tap repository..."
git clone --depth=1 "https://x-access-token:${GITHUB_TOKEN}@github.com/${TAP_REPO}.git" "${TMPDIR}/tap"

echo "${FORMULA}" > "${TMPDIR}/tap/Formula/piilex.rb"

cd "${TMPDIR}/tap"
git config user.name "piilex-bot"
git config user.email "bot@piilex.dev"

if git diff --quiet; then
  echo "No changes to formula. Skipping."
  exit 0
fi

git add Formula/piilex.rb
git commit -m "piilex ${VERSION_BARE}

Updated by release automation."
git push origin main

echo ""
echo "Homebrew formula updated to v${VERSION_BARE}"

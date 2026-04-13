#!/bin/bash
# Publish piilex VS Code extension to Marketplace.
#
# Prerequisites:
#   1. Create publisher at https://marketplace.visualstudio.com/manage
#      Publisher ID: piilex
#
#   2. Create Personal Access Token at https://dev.azure.com
#      Organization: All accessible organizations
#      Scopes: Marketplace > Manage
#
#   3. Set environment variable:
#      export VSCE_PAT="your-personal-access-token"
#
# Usage:
#   cd editors/vscode
#   bash scripts/publish.sh

set -euo pipefail

cd "$(dirname "$0")/.."

echo "Building VSIX..."
npx @vscode/vsce package --no-git-tag-version

VERSION=$(node -e "console.log(require('./package.json').version)")
VSIX="piilex-${VERSION}.vsix"

if [ ! -f "$VSIX" ]; then
  echo "Error: VSIX file not found: $VSIX"
  exit 1
fi

echo "Package: $VSIX ($(du -h "$VSIX" | cut -f1))"

if [ -z "${VSCE_PAT:-}" ]; then
  echo ""
  echo "VSCE_PAT not set. To publish:"
  echo "  export VSCE_PAT='your-token'"
  echo "  npx @vscode/vsce publish"
  echo ""
  echo "Or publish the VSIX manually:"
  echo "  https://marketplace.visualstudio.com/manage"
  exit 0
fi

echo "Publishing to Marketplace..."
npx @vscode/vsce publish

echo ""
echo "Published piilex v${VERSION}"
echo "View at: https://marketplace.visualstudio.com/items?itemName=piilex.piilex"

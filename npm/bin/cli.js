#!/usr/bin/env node
"use strict";

/**
 * piilex npm CLI wrapper
 *
 * Thin shim that locates the platform-specific piilex binary and
 * forwards all arguments to it. The binary is downloaded during
 * `npm install` via the postinstall script.
 */

const { execFileSync } = require("child_process");
const path = require("path");
const fs = require("fs");

const BINARY_NAME = process.platform === "win32" ? "piilex.exe" : "piilex";

/**
 * Resolve the path to the piilex binary.
 * Search order:
 *   1. Bundled in this package (downloaded by postinstall)
 *   2. Globally installed (in PATH)
 */
function findBinary() {
  // 1. Bundled binary next to this script
  const bundled = path.join(__dirname, BINARY_NAME);
  if (fs.existsSync(bundled)) {
    return bundled;
  }

  // 2. In the package root
  const pkgRoot = path.join(__dirname, "..", "bin", BINARY_NAME);
  if (fs.existsSync(pkgRoot)) {
    return pkgRoot;
  }

  // 3. Look in PATH
  const pathDirs = (process.env.PATH || "").split(path.delimiter);
  for (const dir of pathDirs) {
    const candidate = path.join(dir, BINARY_NAME);
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }

  return null;
}

const binary = findBinary();

if (!binary) {
  console.error(
    "Error: piilex binary not found.\n\n" +
    "The binary should have been downloaded during `npm install`.\n" +
    "Try reinstalling: npm install -g piilex\n\n" +
    "Or install directly:\n" +
    "  curl -sSfL https://raw.githubusercontent.com/piilex/piilex/main/install.sh | sh\n"
  );
  process.exit(1);
}

// Forward all arguments to the native binary
const args = process.argv.slice(2);

try {
  execFileSync(binary, args, {
    stdio: "inherit",
    env: process.env,
  });
} catch (err) {
  // execFileSync throws if the child exits with non-zero.
  // The child's stderr/stdout are already inherited, so just propagate the code.
  process.exit(err.status || 1);
}

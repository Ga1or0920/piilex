#!/usr/bin/env node
"use strict";

/**
 * piilex postinstall script
 *
 * Downloads the platform-specific piilex binary from GitHub Releases
 * and places it in the package's bin/ directory.
 *
 * Supports: linux-x64, linux-arm64, darwin-x64, darwin-arm64, win32-x64
 */

const https = require("https");
const http = require("http");
const fs = require("fs");
const path = require("path");
const zlib = require("zlib");
const { execSync } = require("child_process");

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const PACKAGE = require("../package.json");
const VERSION = PACKAGE.version;
const GITHUB_REPO = "piilex/piilex";
const BIN_DIR = path.join(__dirname, "..", "bin");

const PLATFORM_MAP = {
  "darwin-x64":   { target: "x86_64-apple-darwin",          ext: "tar.gz" },
  "darwin-arm64": { target: "aarch64-apple-darwin",          ext: "tar.gz" },
  "linux-x64":   { target: "x86_64-unknown-linux-gnu",      ext: "tar.gz" },
  "linux-arm64":  { target: "aarch64-unknown-linux-gnu",     ext: "tar.gz" },
  "win32-x64":   { target: "x86_64-pc-windows-msvc",        ext: "zip"    },
};

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  const platformKey = `${process.platform}-${process.arch}`;
  const platformInfo = PLATFORM_MAP[platformKey];

  if (!platformInfo) {
    console.error(
      `piilex: unsupported platform ${platformKey}\n` +
      `Supported: ${Object.keys(PLATFORM_MAP).join(", ")}\n` +
      `Install manually: https://github.com/${GITHUB_REPO}/releases`
    );
    // Don't fail the install -- user might have the binary elsewhere
    process.exit(0);
  }

  const { target, ext } = platformInfo;
  const binaryName = process.platform === "win32" ? "piilex.exe" : "piilex";
  const destPath = path.join(BIN_DIR, binaryName);

  // Skip if binary already exists and is the right version
  if (fs.existsSync(destPath)) {
    try {
      const versionOutput = execSync(`"${destPath}" --version`, {
        encoding: "utf-8",
        timeout: 5000,
      }).trim();
      if (versionOutput.includes(VERSION)) {
        console.log(`piilex v${VERSION} already installed.`);
        return;
      }
    } catch {
      // Binary exists but is broken -- re-download
    }
  }

  const fileName = `piilex-v${VERSION}-${target}.${ext}`;
  const url = `https://github.com/${GITHUB_REPO}/releases/download/v${VERSION}/${fileName}`;

  console.log(`piilex: downloading v${VERSION} for ${platformKey}...`);
  console.log(`  ${url}`);

  fs.mkdirSync(BIN_DIR, { recursive: true });

  try {
    if (ext === "tar.gz") {
      await downloadAndExtractTarGz(url, BIN_DIR, binaryName);
    } else {
      await downloadAndExtractZip(url, BIN_DIR, binaryName);
    }

    // Ensure executable permission on Unix
    if (process.platform !== "win32") {
      fs.chmodSync(destPath, 0o755);
    }

    // Verify
    const check = execSync(`"${destPath}" --version`, {
      encoding: "utf-8",
      timeout: 5000,
    }).trim();
    console.log(`piilex: installed ${check}`);
  } catch (err) {
    console.error(
      `piilex: failed to download binary.\n` +
      `  Error: ${err.message}\n\n` +
      `This is not fatal -- you can install piilex manually:\n` +
      `  curl -sSfL https://raw.githubusercontent.com/${GITHUB_REPO}/main/install.sh | sh\n`
    );
    // Exit 0 so npm install doesn't fail
    process.exit(0);
  }
}

// ---------------------------------------------------------------------------
// Download helpers
// ---------------------------------------------------------------------------

/**
 * Follow redirects (GitHub releases redirect to S3/CDN).
 * Returns a readable stream.
 */
function fetchWithRedirects(url, maxRedirects = 5) {
  return new Promise((resolve, reject) => {
    if (maxRedirects <= 0) {
      return reject(new Error("Too many redirects"));
    }

    const client = url.startsWith("https") ? https : http;

    client.get(url, { headers: { "User-Agent": "piilex-npm-installer" } }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        // Follow redirect
        fetchWithRedirects(res.headers.location, maxRedirects - 1)
          .then(resolve)
          .catch(reject);
        res.resume(); // Consume response to free memory
        return;
      }

      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode} for ${url}`));
      }

      resolve(res);
    }).on("error", reject);
  });
}

/**
 * Download a .tar.gz, extract the binary, and write to destDir.
 */
async function downloadAndExtractTarGz(url, destDir, binaryName) {
  const res = await fetchWithRedirects(url);
  const destPath = path.join(destDir, binaryName);

  return new Promise((resolve, reject) => {
    const gunzip = zlib.createGunzip();
    const chunks = [];

    res.pipe(gunzip);

    gunzip.on("data", (chunk) => chunks.push(chunk));
    gunzip.on("end", () => {
      try {
        const tarData = Buffer.concat(chunks);
        const extracted = extractFileFromTar(tarData, binaryName);
        if (!extracted) {
          throw new Error(`'${binaryName}' not found in tar archive`);
        }
        fs.writeFileSync(destPath, extracted);
        resolve();
      } catch (err) {
        reject(err);
      }
    });
    gunzip.on("error", reject);
  });
}

/**
 * Minimal tar parser -- extract a single file from an uncompressed tar buffer.
 * Supports basic POSIX tar (ustar) format, which is what `tar czf` produces.
 */
function extractFileFromTar(buffer, targetName) {
  let offset = 0;
  while (offset < buffer.length - 512) {
    // Read header
    const header = buffer.subarray(offset, offset + 512);

    // Check for end-of-archive (two zero blocks)
    if (header.every((b) => b === 0)) break;

    // File name: bytes 0-99 (null-terminated)
    const nameRaw = header.subarray(0, 100).toString("utf-8").replace(/\0/g, "");
    // Also check prefix field (bytes 345-500) for long names
    const prefix = header.subarray(345, 500).toString("utf-8").replace(/\0/g, "");
    const fullName = prefix ? `${prefix}/${nameRaw}` : nameRaw;

    // File size: bytes 124-135 (octal, null-terminated)
    const sizeStr = header.subarray(124, 136).toString("utf-8").replace(/\0/g, "").trim();
    const fileSize = parseInt(sizeStr, 8) || 0;

    offset += 512; // Past header

    // Check if this is the file we want
    const baseName = path.basename(fullName);
    if (baseName === targetName) {
      return buffer.subarray(offset, offset + fileSize);
    }

    // Skip to next header (file data is padded to 512-byte blocks)
    offset += Math.ceil(fileSize / 512) * 512;
  }

  return null;
}

/**
 * Download a .zip and extract the binary.
 * Uses PowerShell on Windows (always available).
 */
async function downloadAndExtractZip(url, destDir, binaryName) {
  const res = await fetchWithRedirects(url);
  const zipPath = path.join(destDir, "piilex-download.zip");

  return new Promise((resolve, reject) => {
    const ws = fs.createWriteStream(zipPath);
    res.pipe(ws);

    ws.on("finish", () => {
      try {
        // Use PowerShell to extract (available on all modern Windows)
        execSync(
          `powershell -Command "Expand-Archive -Force -Path '${zipPath}' -DestinationPath '${destDir}'"`,
          { timeout: 30000 }
        );
        fs.unlinkSync(zipPath);
        resolve();
      } catch (err) {
        // Cleanup
        try { fs.unlinkSync(zipPath); } catch {}
        reject(err);
      }
    });

    ws.on("error", reject);
  });
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

main().catch((err) => {
  console.error(`piilex postinstall error: ${err.message}`);
  process.exit(0); // Don't break npm install
});

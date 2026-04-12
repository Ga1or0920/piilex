# piilex

**PII Lexical Analyzer** -- Detect personally identifiable information in source code and map to regulatory frameworks.

## Install

```bash
npm install -g piilex
```

Or run without installing:

```bash
npx piilex scan ./src
```

## Usage

```bash
# Scan for PII
piilex scan ./src

# With GDPR mapping (Pro)
piilex scan ./src --framework gdpr

# JSON output for CI
piilex scan -o json --fail-on high

# SARIF for GitHub Code Scanning
piilex scan -o sarif > results.sarif
```

## What it detects

- **20+ PII types**: email, phone, SSN, credit card, password, health data, and more
- **Data flow tracing**: tracks PII from input to logs, databases, APIs
- **Cross-file analysis**: follows import/export chains across modules
- **Regulatory mapping**: maps findings to GDPR articles and CCPA sections

## Supported languages

- TypeScript (`.ts`, `.tsx`)
- JavaScript (`.js`, `.jsx`)
- Python (`.py`)

## How it works

This npm package is a thin wrapper around the native piilex binary.
On `npm install`, the correct binary for your platform is automatically
downloaded from GitHub Releases. No compilation required.

Supported platforms:
- macOS (x64, ARM64)
- Linux (x64, ARM64)
- Windows (x64)

## Full documentation

See the [GitHub repository](https://github.com/piilex/piilex) for complete documentation,
configuration options, and CI/CD integration guides.

## License

Apache-2.0

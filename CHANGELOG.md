# Changelog

All notable changes to piilex will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-04-12

Initial release.

### Added

#### Core detection engine
- 20 PII types: email, phone, national ID, passport, IP address, full name,
  date of birth, gender, address, credit card, bank account, salary, password,
  auth token, API key, health data, medical record, user agent, device ID, cookie
- Variable name pattern matching (regex-based dictionary with confidence levels)
- String literal scanning (email, IPv4, credit card patterns)
- tree-sitter AST parsing for TypeScript, JavaScript, and Python
- Accurate identifier extraction: variable declarations, parameters, properties,
  destructuring, member access, class fields, interface fields
- Comment-aware analysis (comments are excluded via AST, not heuristics)

#### Data flow analysis
- Intra-file source-to-sink tracing (user input, log output, database,
  third-party API, HTTP response, file system)
- Cross-file analysis via import/export dependency graph
- Module resolution for relative imports (TS/JS/Python)
- Sink classification: console.log, logger, db.query, fetch, axios,
  requests.post, res.json, and 30+ patterns

#### Regulatory framework mapping
- GDPR: Art.5(1f), Art.13, Art.25, Art.30, Art.32, Art.44
- CCPA: SS1798.100(b), SS1798.100(d), SS1798.150
- Article-level risk descriptions and recommendations
- Multi-framework support (`--framework gdpr,ccpa`)

#### Compliance reports
- Markdown report with executive summary and article-by-article assessment
- HTML report (styled, auditor-ready)
- JSON structured output
- Data flow summary table

#### Fix suggestions
- Log masking suggestions with example masking functions
- Response redaction guidance
- Per-PII-type mask implementations (email, phone, credit card, IP)
- Free tier: 3 suggestions/day; Pro: unlimited

#### Baseline diff scanning
- Content-based fingerprinting (file + PII type + code snippet + sink kind)
- Change classification: added, removed, modified, unchanged
- Whitespace-normalized and path-normalized fingerprints
- Diff table output and JSON diff format
- `--save-baseline` and `--baseline` flags

#### CLI
- `piilex scan` with table, JSON, and SARIF output
- `piilex report` for compliance report generation
- `piilex suggest` for fix suggestions
- `piilex init` for project configuration
- `piilex license` (activate, deactivate, status)
- `--fail-on` exit code for CI/CD gating
- `--severity` filter, `--exclude` glob patterns, `--no-flow` fast mode
- `--quiet` summary-only mode
- Detailed `--help` with examples for every subcommand

#### License system
- RS256 JWT token verification (public key embedded in binary)
- License resolution: explicit key > PIILEX_LICENSE_KEY env > ~/.piilex/license.key
- Feature gating: Free tier for basic detection, Pro for frameworks/reports/baseline
- Daily usage tracking for Free tier suggest limit

#### CI/CD
- GitHub Actions composite action (`uses: piilex/scan@v1`)
- SARIF output with automatic GitHub Code Scanning upload
- CI workflow: lint (fmt + clippy), test (Linux/macOS/Windows), build (5 targets)
- Release workflow: multi-platform build, GitHub Release, Homebrew tap update
- Install script (`curl | sh`)

#### Build
- Release profile: LTO fat, codegen-units 1, strip, panic abort, opt-level z
- Binary size: 4.6 MB (down from 62 MB debug)
- Cross-platform: x86_64/aarch64 Linux, x86_64/aarch64 macOS, x86_64 Windows

#### Quality
- 123 tests (75 unit + 35 CLI E2E + 13 license)
- clippy clean with `-D warnings`
- rustfmt enforced

[Unreleased]: https://github.com/piilex/piilex/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/piilex/piilex/releases/tag/v0.1.0

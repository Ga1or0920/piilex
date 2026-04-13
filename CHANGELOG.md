# Changelog

All notable changes to piilex will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-04-13

Major expansion: 6 languages, 56 PII types, 5 regulatory frameworks, IDE plugins,
SaaS dashboard, parallel scanning, and pre-commit hooks.

### Added

#### Language support (N1, N11)
- Go language support (`.go`): struct fields, short var declarations, selectors,
  keyed elements, parameter declarations, import specs
- Java language support (`.java`): field/variable declarations, formal parameters,
  field access, getter-to-field inference (`getEmail` -> `email`), import declarations
- C# language support (`.cs`): variable/field declarations, parameters,
  member access expressions, using directives
- Feature flags for language selection: `lang-web` (TS/JS/Py, 5.1 MB),
  `lang-all` (6 languages, 12 MB)
- Slim binary variant in release workflow

#### PII dictionary expansion (N8, N13)
- Expanded from 20 to 56 built-in PII types
- Regional identifiers: My Number (JP), IBAN (EU), BSN (NL), NHS (UK)
- Personal attributes: first name, last name, nationality, ethnicity
- Government IDs: drivers license, tax ID, voter ID
- Financial: bank routing number, SWIFT code, crypto wallet, insurance ID,
  card token, merchant ID, payment account (CVV/expiry)
- Auth credentials: private key, secret key
- Health/HIPAA: patient ID, insurance claim ID, lab result
- Biometric: biometric data, face image, fingerprint
- Digital: MAC address, session ID, GPS coordinates
- Education/employment: student ID, employee ID, social media handle
- Custom PII types definable in `.piilex.yml`
- Literal patterns: My Number (12-digit), IBAN regex

#### Regulatory frameworks (N12, N13)
- APPI (Japan Act on Protection of Personal Information): 9 rules including
  Art.17 (utilization purpose), Art.20 (security control), Art.23 (third-party),
  Art.24 (cross-border), Art.2(3) (special care-required), My Number Act Art.9/12
- HIPAA: 7 sections including 164.502(a) (PHI uses), 164.312(a) (access control),
  164.312(a)(2)(iv) (encryption), 164.312(b) (audit), 164.312(e) (transmission),
  164.514(a) (de-identification), 164.530(c) (training)
- PCI-DSS: 6 requirements including Req 3.2 (auth data), Req 3.3 (mask PAN),
  Req 3.4 (render unreadable), Req 3.5 (protect keys), Req 4.1 (transit encryption),
  Req 6.5 (coding vulnerabilities)
- New trigger types: HealthPii, PaymentPii, CredentialPii, BiometricPii, JapanSpecificPii
- `--framework hipaa` and `--framework pci-dss` flags

#### Fix suggestions overhaul (N9)
- Replaced template-based suggestions with real unified diff patches
- Source file reading for accurate line-level replacement
- Sink-specific strategies: log masking, response redaction, DB encryption, API masking
- PII variable extraction via regex (member access, standalone vars)
- `--auto-fix` flag with per-finding confirmation prompt
- `--yes` flag for non-interactive batch application
- Stale detection: rejects patches if source line has changed since scan
- `SuggestContext` with project root resolution

#### IDE integration (N5, N17)
- VS Code extension: LSP client, status bar, enable/disable commands,
  configurable severity threshold, VSIX packaging (12 KB)
- IntelliJ plugin: LSP server support provider (built-in API), settings UI,
  status action, Gradle build, supports all JetBrains IDEs 2024.1+
- LSP server (`piilex lsp`): initialize, textDocument/didOpen, didChange, didSave,
  didClose, publishDiagnostics, codeAction (quick fixes)

#### Pre-commit hooks (N14)
- `piilex scan --staged` flag: scans only git-staged files
- `piilex hook install` / `uninstall` / `status` subcommands
- Auto-generated `.git/hooks/pre-commit` with configurable `--fail-on` threshold
- Example configs for husky, lefthook, and pre-commit framework

#### SaaS dashboard (N10, N15, N16)
- Web dashboard: signup/login, team management, scan history, API key management
- `piilex scan --upload` flag with `--project`, `--api-url`, `--api-key` options
- Trend charts: daily scan count, findings over time, PII type distribution
- Stripe integration: Checkout Session, Billing Portal, Webhook processing
  (subscription created/updated/deleted, payment failed, checkout completed)
- License JWT generation from dashboard (RS256 signed, 365-day expiry)
- HMAC-SHA256 webhook signature verification with replay protection
- Email notifications: new findings alert, payment failure, weekly summary report
- PostgreSQL migration: JSONB columns, TIMESTAMPTZ, partial indexes, PgBouncer guide

#### Telemetry (N10)
- Anonymous opt-in usage telemetry
- First-run consent prompt (skipped in CI)
- Bucketed metrics: scan count, PII type distribution, language distribution, duration
- `piilex telemetry on/off/status` subcommands
- `PIILEX_TELEMETRY=0` environment variable override
- Local event buffer with batch upload

#### Custom rules (N11)
- `custom_sinks`: regex-based callee patterns mapped to sink types, with `allowed` flag
- `allow_identifiers`: suppress findings for specific identifier names
- `deny_identifiers`: force-flag identifiers with custom PII type and severity
- `exceptions`: path-based rules with `skip`, `reduce_severity`, and `suppress_low` actions
- `pii_types.ignore`: suppress specific PII types globally
- `pii_types.custom`: define new PII types with regex patterns and severity

### Changed

#### Performance (N1, N12)
- Parallel file parsing via rayon (12K+ files/sec on 2K file benchmark)
- Memory usage tracking (`memory_usage_bytes()` for Windows/Linux)
- Binary size: feature flags reduce full 12 MB to 5.1 MB for web-only

#### Detection accuracy (N9)
- Fixed false positive: `WriteLine` matching `phone_number` medium pattern
  (phone regex changed from substring to word-boundary match)
- Safe identifier list: `WriteLine`, `readline`, `pipeline`, `count`, `total`,
  `index`, and 30+ common programming terms excluded from detection
- Test file context: low-confidence findings suppressed in test/spec/fixture files
- Example data context: findings in `example.com`, `// dummy`, `// mock` lines excluded
- `confidence=Low` findings filtered by default in CLI output

#### UX improvements (N3)
- Expanded `--help` for all subcommands with examples and value descriptions
- Parse warnings with heuristic hints (mismatched braces, parentheses, brackets)
- indicatif progress bar for 20+ file scans (auto-disabled in CI/non-terminal)
- Syntax error limit: max 5 per file to reduce noise

### Security

#### Audit and hardening (N4)
- Replaced `serde_yml` (unsound, RUSTSEC-2025-0067/0068) with `serde_yaml_ng`
- Input validation on signup (email format, password length 8+, name length limits)
- Input validation on team invite (email, role whitelist)
- All 35 SQL queries verified as parameterized (zero string interpolation)
- No hardcoded secrets in codebase (verified by static scan)

### Infrastructure

#### CI/CD (N2)
- 158 main tests + 20 SaaS API tests = 178 total
- CI: fmt + clippy + test (debug + release) + build (5 targets) + size check (<15 MB)
- Release workflow: 6 distribution jobs (GitHub Release, Homebrew, npm, VS Code, IntelliJ)
- Binary size assertion in CI (blocks build if over threshold)

#### Distribution (N5, N6, N7, N8)
- VS Code Marketplace packaging (VSIX)
- IntelliJ Marketplace packaging (Gradle)
- npm wrapper package with postinstall binary downloader (5 platforms)
- Homebrew tap with multi-arch formula (4 platform SHA256 checksums)
- Landing page with SEO, OG tags, JSON-LD structured data, Cloudflare Pages workflow
- Community templates: bug report, feature request, false positive (GitHub Issues)
- Discussion templates: Q&A, Ideas (GitHub Discussions)
- PR template, CONTRIBUTING.md, CODE_OF_CONDUCT.md

---

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

[Unreleased]: https://github.com/piilex/piilex/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/piilex/piilex/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/piilex/piilex/releases/tag/v0.1.0

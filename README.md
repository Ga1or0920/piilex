# piilex

**PII Lexical Analyzer** -- Detect personally identifiable information in source code, trace data flows, and map findings to regulatory frameworks.

piilex statically analyzes TypeScript, JavaScript, Python, Go, Java, and C# code to find PII such as emails, passwords, credit card numbers, and national IDs. It traces how that data flows through your application -- from user input to logs, databases, and third-party APIs -- and maps each finding to specific GDPR, CCPA, APPI, HIPAA, and PCI-DSS articles.

## Features

- **56 PII types** -- email, phone, SSN, credit card, My Number (JP), IBAN (EU), biometric data, and more
- **6 languages** -- TypeScript, JavaScript, Python, Go, Java, C#
- **Data flow tracing** -- tracks PII from source to sink (logs, DB, APIs, HTTP responses)
- **Cross-file analysis** -- follows import/export chains across modules
- **5 regulatory frameworks** -- GDPR, CCPA, APPI, HIPAA, PCI-DSS
- **Baseline diff** -- compare scans to show only new, removed, or changed findings
- **Fix suggestions** -- unified diff patches with `--auto-fix` support
- **Multiple outputs** -- table, JSON, SARIF (GitHub Code Scanning)
- **CI/CD ready** -- `--fail-on` exit codes, SARIF upload, GitHub Action, pre-commit hooks
- **IDE integration** -- VS Code extension, IntelliJ plugin (LSP-based)
- **Web dashboard** -- team management, scan history, trend charts
- **Fast** -- rayon parallel parsing, 12K+ files/sec, single binary (5-12 MB)

## Quick start

### Install

**macOS / Linux:**

```bash
curl -sSfL https://raw.githubusercontent.com/piilex/piilex/main/install.sh | sh
```

**Homebrew:**

```bash
brew install piilex/tap/piilex
```

**npm:**

```bash
npm install -g piilex
```

**Windows:**

Download the latest `.zip` from [Releases](https://github.com/piilex/piilex/releases) and add to your PATH.

**From source:**

```bash
cargo install --git https://github.com/piilex/piilex piilex-cli
```

### Initialize

```bash
cd your-project
piilex init --framework gdpr
```

This creates `.piilex.yml` with default settings for your project.

### Scan

```bash
piilex scan ./src
```

```
  PII Scan Results -- 15 finding(s) in 8 file(s) (0.3s)

  SEVERITY   TYPE             FILE                          LINE   DATA FLOW
  -----------------------------------------------------------------
  critical   password         src/auth/login.ts             9      --
  critical   credit_card      src/billing/charge.ts         10     --
  critical   national_id      src/models/user.ts            34     -- [Art.25, MyNumber Act Art.9]
  high       email            src/api/handler.ts            13     user_input -> log_output [Art.5(1f)]
  high       full_name        src/api/handler.ts            18     user_input -> database [Art.30]
  medium     ip_address       src/middleware/logger.ts       5      --
  ...

  Summary:
    critical: 3  high: 9  medium: 3  low: 0
    Frameworks: GDPR
```

## Usage

### Basic scan

```bash
# Scan current directory
piilex scan

# Scan a specific path
piilex scan ./src/api

# Show only high and critical
piilex scan --severity high

# Quiet mode (summary only)
piilex scan -q

# Scan only git-staged files (for pre-commit hooks)
piilex scan --staged
```

### Output formats

```bash
# JSON (for scripting and CI)
piilex scan -o json > results.json

# SARIF (for GitHub Code Scanning)
piilex scan -o sarif > results.sarif

# Table (default, human-readable)
piilex scan -o table
```

### CI/CD integration

```bash
# Exit with code 1 if any high+ findings
piilex scan --fail-on high

# SARIF output for GitHub
piilex scan -o sarif --fail-on high > results.sarif
```

### GitHub Action

```yaml
- uses: piilex/scan@v1
  with:
    path: src/
    framework: gdpr
    fail-on: high
    output: sarif
```

See [examples/github-actions/](examples/github-actions/) for more workflow examples including baseline diff and full pipeline.

### Pre-commit hooks

```bash
# Install native hook
piilex hook install --fail-on high

# Or use with husky
npx husky add .husky/pre-commit 'piilex scan --staged --fail-on high'

# Or lefthook (see examples/hooks/lefthook.yml)
```

See [examples/hooks/](examples/hooks/) for husky, lefthook, and pre-commit framework configs.

### Regulatory mapping (Pro)

```bash
# Single framework
piilex scan ./src --framework gdpr

# Multiple frameworks
piilex scan ./src --framework gdpr,ccpa,appi,hipaa,pci-dss
```

Findings are annotated with specific regulatory articles:

```
  critical   password    src/auth.ts    9    -- [Art.25, Req 3.2]
  high       email       src/api.ts     13   user_input -> log_output [Art.5(1f), 164.312(b)]
  high       full_name   src/api.ts     18   user_input -> third_party_api [Art.13, Art.23]
```

### Compliance reports (Pro)

```bash
piilex scan ./src --framework gdpr -o json > scan.json

# Markdown report
piilex report -i scan.json -f gdpr

# HTML report to file
piilex report -i scan.json -f gdpr -o html --out-file report.html
```

### Fix suggestions

```bash
piilex scan ./src -o json > scan.json

# Show unified diff patches
piilex suggest -i scan.json

# Auto-apply with confirmation
piilex suggest -i scan.json --auto-fix

# Apply all without prompting
piilex suggest -i scan.json --auto-fix --yes
```

Generates real unified diffs based on source file analysis:

```diff
--- a/src/api/handler.ts
+++ b/src/api/handler.ts
@@ -13,1 +13,1 @@
-logger.info(`User logged in from ${user.ipAddress}`);
+logger.info(`User logged in from ${maskIpAddress(user.ipAddress)}`);
```

Free tier: 3 suggestions per day. Pro: unlimited.

### Baseline diff (Pro)

```bash
# Save a baseline
piilex scan ./src --save-baseline baseline.json

# Later, compare against baseline
piilex scan ./src --baseline baseline.json
```

```
  Diff Scan Results (baseline: 15 -> current: 17)

  CHANGE   SEVERITY   TYPE           FILE             LINE   DETAILS
  -----------------------------------------------------------------------
  +ADD     critical   bank_account   src/billing.ts   37     new finding
  +ADD     critical   health_data    src/patient.ts   38     new finding
  ~MOD     high       email          src/api.ts       28     line: 17 -> 28

  Diff Summary:
    +added: 2  -removed: 0  ~modified: 1  =unchanged: 13
```

### Upload to dashboard

```bash
# Upload scan results to piilex SaaS dashboard
piilex scan ./src --upload --api-key plx_xxx --project my-app
```

### Exclude patterns and custom rules

```bash
# Exclude test files
piilex scan --exclude '**/*.test.ts' --exclude '**/*.spec.ts'

# Skip cross-file analysis (faster)
piilex scan --no-flow
```

## Configuration

Create `.piilex.yml` with `piilex init`:

```yaml
version: "1"

scan:
  languages: [typescript, javascript, python, go, java, csharp]
  exclude:
    - "node_modules/**"
    - "**/*.test.ts"
    - "dist/**"
    - ".git/**"

frameworks:
  - gdpr
  # - ccpa
  # - appi
  # - hipaa
  # - pci-dss

severity:
  fail_on: high
  min_display: low

rules:
  allow_log: []
  ignore_findings: []

  # Custom sink patterns
  # custom_sinks:
  #   - pattern: "analyticsClient\\.track"
  #     kind: third_party_api
  #   - pattern: "auditLog\\.write"
  #     kind: log_output
  #     allowed: true

  # Identifiers that should never be flagged
  # allow_identifiers:
  #   - "email_count"
  #   - "phone_validator"

  # Force-flag identifiers as PII
  # deny_identifiers:
  #   - pattern: "(?i)^customer[-_]?ref$"
  #     pii_type: national_id
  #     severity: critical

  # Path-based exceptions
  # exceptions:
  #   - paths: ["generated/**", "proto/**"]
  #     action: skip
  #   - paths: ["**/test/**"]
  #     action: reduce_severity
  #     max_severity: medium

# pii_types:
#   custom:
#     - name: loyalty_card
#       patterns:
#         - "(?i)^loyalty[-_]?(card|id|number)$"
#       severity: high
#   ignore: []
```

## IDE integration

### VS Code

Install from the [VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=piilex.piilex) or search for "piilex" in the Extensions panel.

Real-time PII detection with inline diagnostics and quick-fix code actions.

### IntelliJ / JetBrains IDEs

Install from the [JetBrains Marketplace](https://plugins.jetbrains.com/plugin/piilex) or search for "piilex" in Settings > Plugins.

Works with IntelliJ IDEA, WebStorm, PyCharm, GoLand, Rider, and all JetBrains IDEs 2024.1+.

### Other editors

Any editor with LSP support can use piilex:

```bash
piilex lsp   # Starts LSP server on stdin/stdout
```

## License management

```bash
# Check status
piilex license status

# Activate Pro
piilex license activate <JWT_TOKEN>

# Deactivate
piilex license deactivate
```

For CI/CD, set the `PIILEX_LICENSE_KEY` environment variable.

### Free vs Pro

| Feature | Free | Pro |
|---------|------|-----|
| PII detection (56 types) | Yes | Yes |
| 6 languages (TS, JS, Py, Go, Java, C#) | Yes | Yes |
| Data flow tracing | Yes | Yes |
| Cross-file analysis | Yes | Yes |
| JSON / SARIF output | Yes | Yes |
| `--fail-on` CI gate | Yes | Yes |
| Pre-commit hooks (`--staged`) | Yes | Yes |
| `--framework` regulatory mapping | -- | Yes |
| `report` compliance reports | -- | Yes |
| `suggest` (unlimited) | 3/day | Yes |
| `--baseline` diff scanning | -- | Yes |
| Web dashboard | -- | Yes |

## Supported languages

| Language | Extensions | Analysis |
|----------|-----------|----------|
| TypeScript | `.ts`, `.tsx`, `.mts` | AST + data flow + imports |
| JavaScript | `.js`, `.jsx`, `.mjs` | AST + data flow + imports |
| Python | `.py` | AST + data flow + imports |
| Go | `.go` | AST + data flow + imports |
| Java | `.java` | AST + data flow + imports |
| C# | `.cs` | AST + data flow + imports |

Language support is modular via feature flags. Build a slim binary with only web languages:

```bash
cargo build --release --no-default-features --features lang-web  # 5.1 MB
```

## Regulatory frameworks

| Framework | Articles/Rules | Target |
|-----------|---------------|--------|
| **GDPR** | 6 articles | EU data protection |
| **CCPA** | 3 sections | California consumer privacy |
| **APPI** | 9 rules | Japan personal information + My Number Act |
| **HIPAA** | 7 sections | US healthcare (PHI) |
| **PCI-DSS** | 6 requirements | Payment card industry |

## PII types detected (56)

**Contact (5):** email, phone, address, postal code, fax

**Personal (7):** full name, first name, last name, date of birth, gender, nationality, ethnicity

**Government IDs (9):** national ID/SSN, passport, drivers license, tax ID, voter ID, My Number (JP), IBAN (EU), BSN (NL), NHS (UK)

**Financial (10):** credit card, bank account, salary, routing number, SWIFT code, crypto wallet, insurance ID, card token, merchant ID, payment account (CVV/expiry)

**Auth (5):** password, auth token, API key, private key, secret key

**Health (7):** health data, medical record, diagnosis, prescription, patient ID, insurance claim ID, lab result

**Biometric (3):** biometric data, face image, fingerprint

**Digital (7):** IP address, MAC address, user agent, device ID, cookie, session ID, GPS coordinates

**Education/Employment (3):** student ID, employee ID, social media handle

**Custom:** define your own types in `.piilex.yml`

## Architecture

piilex is built in Rust for speed and single-binary distribution:

- **tree-sitter** for language-agnostic AST parsing (6 grammars)
- **rayon** parallel file processing (12K+ files/sec)
- **4-layer detection pipeline:** identifier matching, literal scanning, data flow tracing, regulatory mapping
- **Cross-file module graph** for import/export tracking
- **RS256 JWT** for license verification (public key embedded in binary)
- **LSP server** for real-time IDE integration
- **Feature flags** for language selection (`lang-web` = 5.1 MB, `lang-all` = 12 MB)

## Web dashboard

The SaaS dashboard provides team management, scan history, and trend visualization:

- **Scan history** -- track all scans with findings, severity, and duration
- **Trend charts** -- visualize findings over time
- **PII distribution** -- see which PII types are most common
- **Team management** -- invite members, assign roles
- **API keys** -- manage CLI authentication tokens
- **Billing** -- Stripe-powered Pro subscriptions

## Development

```bash
# Build
cargo build

# Test (178 tests)
cargo test --all
cd saas/api && cargo test   # SaaS API tests

# Lint
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings

# Release build
cargo build --release       # 12 MB (all languages)

# Slim build (TS/JS/Py only)
cargo build --release --no-default-features --features lang-web  # 5.1 MB

# Benchmark
bash scripts/benchmark.sh 1000
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, PR guidelines, and how to add new PII types or languages.

## License

Licensed under [Apache License 2.0](LICENSE).

---

Built with Rust. 178 tests. Tested on Windows, macOS, and Linux.

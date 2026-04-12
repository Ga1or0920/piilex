# piilex

**PII Lexical Analyzer** -- Detect personally identifiable information in source code, trace data flows, and map findings to regulatory frameworks.

piilex statically analyzes TypeScript, JavaScript, and Python code to find PII such as emails, passwords, credit card numbers, and national IDs. It traces how that data flows through your application -- from user input to logs, databases, and third-party APIs -- and maps each finding to specific GDPR and CCPA articles.

## Features

- **20+ PII types** -- email, phone, SSN, credit card, password, health data, and more
- **Data flow tracing** -- tracks PII from source to sink (logs, DB, APIs, HTTP responses)
- **Cross-file analysis** -- follows import/export chains across modules
- **Regulatory mapping** -- maps findings to GDPR articles and CCPA sections
- **Baseline diff** -- compare scans to show only new, removed, or changed findings
- **Multiple outputs** -- table, JSON, SARIF (GitHub Code Scanning)
- **CI/CD ready** -- `--fail-on` exit codes, SARIF upload, GitHub Action
- **Fast** -- tree-sitter AST parsing, single binary under 5 MB

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
  high       email            src/models/user.ts            2      --
  high       email            src/api/handler.ts            13     user_input -> log_output
  high       full_name        src/api/handler.ts            18     user_input -> database
  medium     ip_address       src/middleware/logger.ts       5      --
  ...

  Summary:
    critical: 2  high: 6  medium: 3  low: 0
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

See [examples/github-actions/](examples/github-actions/) for more workflow examples.

### Regulatory mapping (Pro)

```bash
# GDPR article mapping
piilex scan ./src --framework gdpr

# Multiple frameworks
piilex scan ./src --framework gdpr,ccpa
```

Findings are annotated with specific regulatory articles:

```
  critical   password    src/auth.ts    9    -- [Art.25]
  high       email       src/api.ts     13   user_input -> log_output [Art.5(1f), Art.32]
  high       full_name   src/api.ts     18   user_input -> third_party_api [Art.13, Art.44]
```

### Compliance reports (Pro)

```bash
# Generate scan results first
piilex scan ./src --framework gdpr -o json > scan.json

# Markdown report
piilex report -i scan.json -f gdpr

# HTML report to file
piilex report -i scan.json -f gdpr -o html --out-file report.html
```

### Fix suggestions

```bash
piilex scan ./src -o json > scan.json
piilex suggest -i scan.json
```

Shows concrete masking and redaction suggestions for each finding.

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

### Exclude patterns

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
  languages: [typescript, javascript, python]
  exclude:
    - "node_modules/**"
    - "**/*.test.ts"
    - "dist/**"
    - ".git/**"

frameworks:
  - gdpr

severity:
  fail_on: high
  min_display: low

rules:
  allow_log: []
  ignore_findings: []
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

For CI/CD, set the `PIILEX_LICENSE_KEY` environment variable instead.

### Free vs Pro

| Feature | Free | Pro |
|---------|------|-----|
| Basic PII detection (20+ types) | Yes | Yes |
| Data flow tracing | Yes | Yes |
| Cross-file analysis | Yes | Yes |
| JSON / SARIF output | Yes | Yes |
| `--fail-on` CI gate | Yes | Yes |
| `--framework` regulatory mapping | -- | Yes |
| `report` compliance reports | -- | Yes |
| `suggest` (unlimited) | 3/day | Yes |
| `--baseline` diff scanning | -- | Yes |

## Supported languages

| Language | Extensions | Analysis |
|----------|-----------|----------|
| TypeScript | `.ts`, `.tsx`, `.mts` | AST + data flow + imports |
| JavaScript | `.js`, `.jsx`, `.mjs` | AST + data flow + imports |
| Python | `.py` | AST + data flow + imports |

## PII types detected

**Identifiers:** email, phone, SSN/national ID, passport number

**Personal:** full name, date of birth, gender, address

**Financial:** credit card, bank account, salary

**Auth:** password, auth token, API key

**Health:** health data, medical record

**Browser/Device:** user agent, device ID, cookie

**Network:** IP address

## Architecture

piilex is built in Rust for speed and single-binary distribution:

- **tree-sitter** for language-agnostic AST parsing
- **4-layer detection pipeline:** identifier matching, literal scanning, data flow tracing, regulatory mapping
- **Cross-file module graph** for import/export tracking
- **RS256 JWT** for license verification (public key embedded in binary)

## Development

```bash
# Build
cargo build

# Test
cargo test --all

# Lint
cargo fmt --all --check
cargo clippy --all-targets

# Release build (4.6 MB optimized binary)
cargo build --release
```

## License

Licensed under [Apache License 2.0](LICENSE).

---

Built with Rust. Tested on Windows, macOS, and Linux.

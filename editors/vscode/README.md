# piilex - PII Scanner for VS Code

Detect personally identifiable information (PII) in your source code in real-time as you type. Maps findings to GDPR, CCPA, and APPI regulatory articles.

![piilex diagnostics](https://raw.githubusercontent.com/piilex/piilex/main/editors/vscode/assets/screenshot-diagnostics.png)

## Features

### Real-time PII detection
piilex scans your code as you type and highlights PII with inline diagnostics:

- **Critical** (red squiggly) -- passwords, SSN, credit cards, national IDs
- **High** (yellow squiggly) -- email, phone, full name, address
- **Medium** (blue) -- IP address, date of birth, device ID
- **Low** (gray hint) -- user agent, cookies

### 50+ PII types
Detects email, phone, SSN, credit card, passport, My Number (Japan), IBAN (EU), BSN (Netherlands), NHS (UK), biometric data, health records, API keys, passwords, and 35+ more types.

### 6 languages
TypeScript, JavaScript, Python, Go, Java, C#

### Data flow tracing
Alerts when PII flows to dangerous sinks:
- `user.email` passed to `console.log()` -- **PII leaked to logs**
- `user.ssn` passed to `fetch()` -- **PII sent to third-party API**
- `user.phone` passed to `db.save()` -- **PII stored without encryption**

### Quick fixes
Click the lightbulb (or press Ctrl+.) on a diagnostic to see fix suggestions:
- **Mask before logging**: `maskEmail(user.email)`
- **Encrypt before storage**: `encrypt(user.ssn)`
- **Redact from response**: Replace with `"[REDACTED]"`

### Regulatory mapping (Pro)
With a Pro license, diagnostics include regulatory article references:
- `[Art.5(1f)]` -- GDPR: Integrity and Confidentiality
- `[Art.23]` -- APPI: Restriction on Third-Party Provision

## Requirements

The **piilex binary** must be installed and available in your PATH.

**macOS / Linux:**
```bash
brew install piilex/tap/piilex
```

**npm:**
```bash
npm install -g piilex
```

**Manual:** Download from [GitHub Releases](https://github.com/piilex/piilex/releases)

Verify installation:
```bash
piilex --version
```

## Extension Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `piilex.path` | `"piilex"` | Path to the piilex binary |
| `piilex.enable` | `true` | Enable or disable scanning |
| `piilex.severity` | `"low"` | Minimum severity to display |

## Commands

| Command | Description |
|---------|-------------|
| `piilex: Show Status` | Show whether the scanner is active |
| `piilex: Scan Workspace` | Re-scan all open documents |
| `piilex: Enable` | Enable the PII scanner |
| `piilex: Disable` | Disable the PII scanner |

## How It Works

The extension launches `piilex lsp` as a [Language Server Protocol](https://microsoft.github.io/language-server-protocol/) server. When you open or edit a file, piilex parses it using tree-sitter AST analysis, matches identifiers against a PII dictionary, traces data flows, and publishes diagnostics.

The LSP server runs locally -- **no code is sent to any external service**.

## Troubleshooting

**"Failed to start LSP server"**: Ensure `piilex` is installed and in PATH. Run `piilex --version` in your terminal to verify.

**No diagnostics appearing**: Check that `piilex.enable` is `true` and `piilex.severity` is set to `low`.

**Too many false positives**: Increase `piilex.severity` to `medium` or `high` to filter out low-confidence findings.

## Links

- [GitHub Repository](https://github.com/piilex/piilex)
- [Documentation](https://github.com/piilex/piilex#readme)
- [Issue Tracker](https://github.com/piilex/piilex/issues)
- [Pricing](https://piilex.dev/pricing)

## License

Apache-2.0

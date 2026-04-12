# piilex for VS Code

Detect personally identifiable information (PII) in your source code with real-time highlighting and quick fix suggestions.

## Features

- **Real-time PII detection** -- highlights PII as you type
- **6 languages** -- TypeScript, JavaScript, Python, Go, Java, C#
- **50+ PII types** -- email, phone, SSN, credit card, My Number, IBAN, and more
- **Data flow warnings** -- alerts when PII flows to logs, databases, or APIs
- **Quick fixes** -- click the lightbulb to apply masking/redaction suggestions
- **Severity levels** -- Critical (red), High (yellow), Medium (blue), Low (gray)

## Requirements

- **piilex binary** must be installed and available in PATH
- Install: `brew install piilex/tap/piilex` or `npm install -g piilex`

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `piilex.path` | `"piilex"` | Path to the piilex binary |
| `piilex.enable` | `true` | Enable/disable scanning |
| `piilex.severity` | `"low"` | Minimum severity to display |

## How It Works

The extension launches `piilex lsp` as a Language Server Protocol server.
When you open or edit a file, piilex analyzes it and publishes diagnostics
(warnings/errors) for each PII finding. Quick fix code actions are available
for findings with known remediation patterns.

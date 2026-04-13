# piilex for JetBrains IDEs

Detect PII in source code in real-time with IntelliJ IDEA, WebStorm, PyCharm, GoLand, and other JetBrains IDEs.

## Features

- **Real-time PII detection** via Language Server Protocol
- **50+ PII types**: email, phone, SSN, credit card, My Number, IBAN, and more
- **6 languages**: TypeScript, JavaScript, Python, Go, Java, C#
- **Data flow warnings**: alerts when PII flows to logs, databases, or APIs
- **Quick fixes**: Alt+Enter to apply masking/redaction suggestions
- **Configurable severity threshold**: low, medium, high, critical

## Requirements

- **JetBrains IDE 2024.1+** (IntelliJ IDEA, WebStorm, PyCharm, GoLand, etc.)
- **piilex binary** in PATH
  - Install: `brew install piilex/tap/piilex` or `npm install -g piilex`

## Installation

1. Install the piilex binary (see above)
2. In your IDE: Settings > Plugins > Marketplace > Search "piilex"
3. Install and restart

## Configuration

Settings > Tools > piilex

| Setting | Default | Description |
|---------|---------|-------------|
| Enable | `true` | Enable/disable scanning |
| Binary path | `piilex` | Path to the piilex binary |
| Minimum severity | `low` | Minimum severity to display |

## How It Works

The plugin launches `piilex lsp` as a Language Server. When you open or edit
a supported file, piilex analyzes it and publishes diagnostics (warnings/errors)
for each PII finding. Quick fix code actions are available via Alt+Enter.

## Development

```bash
cd editors/intellij
./gradlew buildPlugin    # Build the plugin
./gradlew runIde         # Test in a sandbox IDE
./gradlew publishPlugin  # Publish to Marketplace
```

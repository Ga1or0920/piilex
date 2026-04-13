# Contributing to piilex

Thanks for your interest in contributing! Here's how to get started.

## Ways to contribute

- **Report bugs** -- Use the [Bug Report](https://github.com/piilex/piilex/issues/new?template=bug_report.yml) template
- **Report false positives** -- Use the [False Positive](https://github.com/piilex/piilex/issues/new?template=false_positive.yml) template
- **Request features** -- Use the [Feature Request](https://github.com/piilex/piilex/issues/new?template=feature_request.yml) template
- **Ask questions** -- Use [GitHub Discussions](https://github.com/piilex/piilex/discussions)
- **Submit PRs** -- See development setup below

## Development setup

```bash
# Clone
git clone https://github.com/piilex/piilex.git
cd piilex

# Build
cargo build

# Test
cargo test --all

# Lint
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings

# Run
cargo run -- scan ./tests/fixtures/typescript/simple_pii.ts
```

## Pull request guidelines

1. **Fork and branch** -- Create a feature branch from `main`
2. **Small PRs** -- One feature or fix per PR
3. **Tests** -- Add tests for new functionality
4. **Lint** -- Ensure `cargo fmt` and `cargo clippy` pass
5. **Description** -- Explain what and why, not just how

## Adding a new PII type

1. Add the variant to `PiiType` enum in `finding.rs`
2. Add identifier patterns in `pii/dictionary.rs`
3. Add literal regex in `pii/patterns.rs` (if applicable)
4. Add tests
5. Update README if the type is notable

## Adding a new language

1. Add `tree-sitter-{lang}` to workspace dependencies
2. Add feature flag in `piilex-core/Cargo.toml`
3. Add `Language` variant in `discovery.rs`
4. Implement identifier/call/import walkers in `parser/ast.rs` and `parser/imports.rs`
5. Add `#[cfg(feature)]` gates
6. Add test fixtures

## License

By contributing, you agree that your contributions will be licensed under Apache-2.0.

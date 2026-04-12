pub mod ast;
pub mod imports;

use crate::discovery::Language;
use std::path::{Path, PathBuf};
use tree_sitter::Parser;

pub use imports::{ExportDecl, ExportKind, ImportDecl, ImportSpecifier};

pub struct ParsedFile {
    pub path: PathBuf,
    pub language: Language,
    pub source: String,
    pub identifiers: Vec<Identifier>,
    pub string_literals: Vec<StringLiteral>,
    pub call_expressions: Vec<CallExpression>,
    pub imports: Vec<ImportDecl>,
    pub exports: Vec<ExportDecl>,
    pub warnings: Vec<ParseWarning>,
}

#[derive(Debug, Clone)]
pub struct Identifier {
    pub name: String,
    pub line: usize,
    pub column: usize,
    pub context: IdentifierContext,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentifierContext {
    VariableDecl,
    Parameter,
    PropertyDef,
    PropertyAccess,
    TypeField,
    Destructure,
    Other,
}

#[derive(Debug, Clone)]
pub struct StringLiteral {
    pub value: String,
    pub line: usize,
    pub column: usize,
}

#[derive(Debug, Clone)]
pub struct CallExpression {
    pub callee: String,
    pub line: usize,
    pub column: usize,
    pub argument_identifiers: Vec<String>,
}

/// A non-fatal warning emitted during parsing.
#[derive(Debug, Clone)]
pub struct ParseWarning {
    pub file: PathBuf,
    pub line: Option<usize>,
    pub message: String,
    pub hint: String,
}

impl std::fmt::Display for ParseWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.file.display())?;
        if let Some(line) = self.line {
            write!(f, ":{}", line)?;
        }
        write!(f, " - {}", self.message)?;
        if !self.hint.is_empty() {
            write!(f, "\n  Hint: {}", self.hint)?;
        }
        Ok(())
    }
}

/// Create a tree-sitter Parser configured for the given language.
fn create_parser(language: Language) -> Option<Parser> {
    let mut parser = Parser::new();
    let ts_language = match language {
        #[cfg(feature = "lang-typescript")]
        Language::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        #[cfg(feature = "lang-javascript")]
        Language::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        #[cfg(feature = "lang-python")]
        Language::Python => tree_sitter_python::LANGUAGE.into(),
        #[cfg(feature = "lang-go")]
        Language::Go => tree_sitter_go::LANGUAGE.into(),
        #[cfg(feature = "lang-java")]
        Language::Java => tree_sitter_java::LANGUAGE.into(),
        #[cfg(feature = "lang-csharp")]
        Language::CSharp => tree_sitter_c_sharp::LANGUAGE.into(),
    };
    parser.set_language(&ts_language).ok()?;
    Some(parser)
}

fn empty_parsed(path: &Path, source: &str, language: Language) -> ParsedFile {
    ParsedFile {
        path: path.to_path_buf(),
        language,
        source: source.to_string(),
        identifiers: Vec::new(),
        string_literals: Vec::new(),
        call_expressions: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        warnings: Vec::new(),
    }
}

/// Parse a source file using tree-sitter AST analysis.
pub fn parse_file(path: &Path, source: &str, language: Language) -> ParsedFile {
    let mut warnings = Vec::new();

    let mut parser = match create_parser(language) {
        Some(p) => p,
        None => {
            let mut result = empty_parsed(path, source, language);
            result.warnings.push(ParseWarning {
                file: path.to_path_buf(),
                line: None,
                message: format!("failed to initialize {} parser", language.as_str()),
                hint: format!(
                    "This may indicate a tree-sitter ABI mismatch. \
                     Ensure piilex was built with compatible tree-sitter-{} grammar.",
                    language.as_str()
                ),
            });
            return result;
        }
    };

    let tree = match parser.parse(source.as_bytes(), None) {
        Some(t) => t,
        None => {
            let mut result = empty_parsed(path, source, language);
            result.warnings.push(ParseWarning {
                file: path.to_path_buf(),
                line: None,
                message: "tree-sitter returned no parse tree (file may be empty or binary)".into(),
                hint: "Verify the file contains valid source code and is not a binary file.".into(),
            });
            return result;
        }
    };

    let src_bytes = source.as_bytes();
    let root = tree.root_node();

    // Detect parse errors in the AST
    collect_syntax_errors(root, src_bytes, path, &mut warnings);

    let identifiers = ast::extract_identifiers(root, src_bytes, language);
    let string_literals = ast::extract_string_literals(root, src_bytes, language);
    let call_expressions = ast::extract_call_expressions(root, src_bytes, language);
    let import_decls = imports::extract_imports(root, src_bytes, language);
    let export_decls = match language {
        #[cfg(any(feature = "lang-typescript", feature = "lang-javascript"))]
        Language::TypeScript | Language::JavaScript => {
            imports::extract_exports(root, src_bytes, language)
        }
        #[cfg(feature = "lang-python")]
        Language::Python => imports::extract_py_public_names(root, src_bytes),
        #[cfg(any(feature = "lang-go", feature = "lang-java", feature = "lang-csharp"))]
        Language::Go | Language::Java | Language::CSharp => {
            imports::extract_exports(root, src_bytes, language)
        }
    };

    ParsedFile {
        path: path.to_path_buf(),
        language,
        source: source.to_string(),
        identifiers,
        string_literals,
        call_expressions,
        imports: import_decls,
        exports: export_decls,
        warnings,
    }
}

/// Walk the AST and collect ERROR / MISSING nodes as warnings with hints.
fn collect_syntax_errors(
    node: tree_sitter::Node,
    src: &[u8],
    path: &Path,
    warnings: &mut Vec<ParseWarning>,
) {
    if warnings.len() >= 5 {
        // Cap at 5 syntax errors per file to avoid noise
        return;
    }

    if node.is_error() {
        let line = node.start_position().row + 1;
        let col = node.start_position().column + 1;
        let snippet = extract_error_context(src, node.start_byte(), node.end_byte());
        let hint = guess_syntax_hint(src, node);

        warnings.push(ParseWarning {
            file: path.to_path_buf(),
            line: Some(line),
            message: format!("syntax error at line {}:{} near `{}`", line, col, snippet),
            hint,
        });
    } else if node.is_missing() {
        let line = node.start_position().row + 1;
        let expected = node.kind();
        warnings.push(ParseWarning {
            file: path.to_path_buf(),
            line: Some(line),
            message: format!("missing expected `{}` at line {}", expected, line),
            hint: format!(
                "The parser expected a `{}` token here. Check for unclosed \
                 brackets, missing semicolons, or incomplete statements.",
                expected
            ),
        });
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_syntax_errors(child, src, path, warnings);
    }
}

/// Extract a short snippet around the error location.
fn extract_error_context(src: &[u8], start: usize, end: usize) -> String {
    let snippet_end = end.min(start + 40).min(src.len());
    let raw = std::str::from_utf8(&src[start..snippet_end]).unwrap_or("???");
    let single_line = raw.lines().next().unwrap_or(raw);
    if single_line.len() > 30 {
        format!("{}...", &single_line[..30])
    } else {
        single_line.to_string()
    }
}

/// Try to guess what went wrong based on surrounding context.
fn guess_syntax_hint(src: &[u8], error_node: tree_sitter::Node) -> String {
    let line_start = src[..error_node.start_byte()]
        .iter()
        .rposition(|&b| b == b'\n')
        .map(|p| p + 1)
        .unwrap_or(0);
    let line_end = src[error_node.start_byte()..]
        .iter()
        .position(|&b| b == b'\n')
        .map(|p| error_node.start_byte() + p)
        .unwrap_or(src.len());
    let line_text = std::str::from_utf8(&src[line_start..line_end]).unwrap_or("");

    // Heuristic hints based on common patterns
    if line_text.contains("=>") && !line_text.contains("(") {
        return "Arrow function may be missing parentheses around parameters.".into();
    }
    if line_text.matches('{').count() != line_text.matches('}').count() {
        return "Mismatched braces `{}` detected on this line. Check for unclosed blocks.".into();
    }
    if line_text.matches('(').count() != line_text.matches(')').count() {
        return "Mismatched parentheses `()` detected. Check for unclosed function calls.".into();
    }
    if line_text.matches('[').count() != line_text.matches(']').count() {
        return "Mismatched brackets `[]` detected. Check for unclosed array literals.".into();
    }
    if line_text.trim_end().ends_with(',') {
        return "Trailing comma may not be allowed in this context.".into();
    }

    // Generic hint
    "Check for typos, missing punctuation, or unsupported syntax in this area.".into()
}

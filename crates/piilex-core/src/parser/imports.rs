use crate::discovery::Language;
use tree_sitter::Node;

/// An import declaration extracted from source code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportDecl {
    /// The module path (e.g., "./userService", "express", "os")
    pub source: String,
    /// Individual import specifiers
    pub specifiers: Vec<ImportSpecifier>,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportSpecifier {
    /// import { foo } from "mod"  /  from mod import foo
    Named { local: String, imported: String },
    /// import foo from "mod"  /  import mod
    Default { local: String },
    /// import * as foo from "mod"  /  from mod import *
    Namespace { local: String },
}

/// An export declaration extracted from source code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportDecl {
    /// The exported symbol name
    pub name: String,
    /// What kind of export
    pub kind: ExportKind,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportKind {
    /// export function foo / export const foo / export class Foo
    Named,
    /// export default ...
    Default,
    /// export { foo } from "./mod"  (re-export)
    ReExport { source: String },
}

fn node_text<'a>(node: Node, src: &'a [u8]) -> &'a str {
    std::str::from_utf8(&src[node.start_byte()..node.end_byte()]).unwrap_or("")
}

fn line_of(node: Node) -> usize {
    node.start_position().row + 1
}

/// Strip surrounding quotes from a module path string.
fn strip_quotes(s: &str) -> &str {
    s.trim_matches(|c| c == '"' || c == '\'' || c == '`')
}

// ─── Public API ─────────────────────────────────────────────────────

pub fn extract_imports(root: Node, src: &[u8], language: Language) -> Vec<ImportDecl> {
    let mut out = Vec::new();
    match language {
        #[cfg(any(feature = "lang-typescript", feature = "lang-javascript"))]
        Language::TypeScript | Language::JavaScript => walk_ts_imports(root, src, &mut out),
        #[cfg(feature = "lang-python")]
        Language::Python => walk_py_imports(root, src, &mut out),
        #[cfg(feature = "lang-go")]
        Language::Go => walk_go_imports(root, src, &mut out),
        #[cfg(any(feature = "lang-java", feature = "lang-csharp"))]
        Language::Java | Language::CSharp => walk_java_imports(root, src, &mut out),
    }
    out
}

pub fn extract_exports(root: Node, src: &[u8], language: Language) -> Vec<ExportDecl> {
    let mut out = Vec::new();
    match language {
        #[cfg(any(feature = "lang-typescript", feature = "lang-javascript"))]
        Language::TypeScript | Language::JavaScript => walk_ts_exports(root, src, &mut out),
        #[cfg(feature = "lang-python")]
        Language::Python => {}
        #[cfg(any(feature = "lang-go", feature = "lang-java", feature = "lang-csharp"))]
        Language::Go | Language::Java | Language::CSharp => {
            walk_public_declarations(root, src, &mut out);
        }
    }
    out
}

/// For Python, all top-level assignments and function/class defs are implicitly exported.
pub fn extract_py_public_names(root: Node, src: &[u8]) -> Vec<ExportDecl> {
    let mut out = Vec::new();
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        match child.kind() {
            "function_definition" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let name = node_text(name_node, src);
                    if !name.starts_with('_') {
                        out.push(ExportDecl {
                            name: name.to_string(),
                            kind: ExportKind::Named,
                            line: line_of(child),
                        });
                    }
                }
            }
            "class_definition" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    out.push(ExportDecl {
                        name: node_text(name_node, src).to_string(),
                        kind: ExportKind::Named,
                        line: line_of(child),
                    });
                }
            }
            "expression_statement" => {
                if let Some(assign) = child.named_child(0) {
                    if assign.kind() == "assignment" {
                        if let Some(left) = assign.child_by_field_name("left") {
                            if left.kind() == "identifier" {
                                let name = node_text(left, src);
                                if !name.starts_with('_') {
                                    out.push(ExportDecl {
                                        name: name.to_string(),
                                        kind: ExportKind::Named,
                                        line: line_of(child),
                                    });
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    out
}

// ─── TypeScript / JavaScript ────────────────────────────────────────

fn walk_ts_imports(node: Node, src: &[u8], out: &mut Vec<ImportDecl>) {
    if node.kind() == "import_statement" {
        if let Some(decl) = parse_ts_import(node, src) {
            out.push(decl);
        }
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_ts_imports(child, src, out);
    }
}

fn parse_ts_import(node: Node, src: &[u8]) -> Option<ImportDecl> {
    // Find the source string: import ... from "source"
    let source_node = node.child_by_field_name("source")?;
    let source = strip_quotes(node_text(source_node, src)).to_string();

    let mut specifiers = Vec::new();

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            // import foo from "mod"
            "identifier" => {
                specifiers.push(ImportSpecifier::Default {
                    local: node_text(child, src).to_string(),
                });
            }
            // import { a, b as c } from "mod"
            "import_clause" => {
                collect_ts_import_clause(child, src, &mut specifiers);
            }
            // Handle named_imports directly under import_statement
            "named_imports" => {
                collect_ts_named_imports(child, src, &mut specifiers);
            }
            _ => {}
        }
    }

    Some(ImportDecl {
        source,
        specifiers,
        line: line_of(node),
    })
}

fn collect_ts_import_clause(node: Node, src: &[u8], out: &mut Vec<ImportSpecifier>) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "identifier" => {
                out.push(ImportSpecifier::Default {
                    local: node_text(child, src).to_string(),
                });
            }
            "named_imports" => {
                collect_ts_named_imports(child, src, out);
            }
            "namespace_import" => {
                // import * as foo
                if let Some(name) = child.named_child(0) {
                    out.push(ImportSpecifier::Namespace {
                        local: node_text(name, src).to_string(),
                    });
                }
            }
            _ => {}
        }
    }
}

fn collect_ts_named_imports(node: Node, src: &[u8], out: &mut Vec<ImportSpecifier>) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "import_specifier" {
            let name_node = child.child_by_field_name("name");
            let alias_node = child.child_by_field_name("alias");

            if let Some(name) = name_node {
                let imported = node_text(name, src).to_string();
                let local = alias_node
                    .map(|a| node_text(a, src).to_string())
                    .unwrap_or_else(|| imported.clone());
                out.push(ImportSpecifier::Named { local, imported });
            }
        }
    }
}

fn walk_ts_exports(node: Node, src: &[u8], out: &mut Vec<ExportDecl>) {
    if node.kind() == "export_statement" {
        parse_ts_export(node, src, out);
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_ts_exports(child, src, out);
    }
}

fn parse_ts_export(node: Node, src: &[u8], out: &mut Vec<ExportDecl>) {
    // Check for re-export: export { ... } from "source"
    let re_export_source = node
        .child_by_field_name("source")
        .map(|s| strip_quotes(node_text(s, src)).to_string());

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            // export function foo / export class Foo
            "function_declaration" | "class_declaration" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    out.push(ExportDecl {
                        name: node_text(name_node, src).to_string(),
                        kind: ExportKind::Named,
                        line: line_of(node),
                    });
                }
            }
            // export const foo = ...
            "lexical_declaration" => {
                let mut inner = child.walk();
                for decl in child.named_children(&mut inner) {
                    if decl.kind() == "variable_declarator" {
                        if let Some(name_node) = decl.child_by_field_name("name") {
                            out.push(ExportDecl {
                                name: node_text(name_node, src).to_string(),
                                kind: ExportKind::Named,
                                line: line_of(node),
                            });
                        }
                    }
                }
            }
            // export { foo, bar }  or  export { foo } from "./mod"
            "export_clause" => {
                let mut inner = child.walk();
                for spec in child.named_children(&mut inner) {
                    if spec.kind() == "export_specifier" {
                        if let Some(name) = spec.child_by_field_name("name") {
                            let kind = if let Some(ref src) = re_export_source {
                                ExportKind::ReExport {
                                    source: src.clone(),
                                }
                            } else {
                                ExportKind::Named
                            };
                            out.push(ExportDecl {
                                name: node_text(name, src).to_string(),
                                kind,
                                line: line_of(node),
                            });
                        }
                    }
                }
            }
            _ => {
                // export default expression
                // Check if "default" keyword is present
                let full = node_text(node, src);
                if full.contains("export default") {
                    out.push(ExportDecl {
                        name: "default".to_string(),
                        kind: ExportKind::Default,
                        line: line_of(node),
                    });
                }
            }
        }
    }
}

// ─── Python ─────────────────────────────────────────────────────────

fn walk_py_imports(node: Node, src: &[u8], out: &mut Vec<ImportDecl>) {
    match node.kind() {
        // from X import Y, Z
        "import_from_statement" => {
            if let Some(decl) = parse_py_import_from(node, src) {
                out.push(decl);
            }
        }
        // import X, import X as Y
        "import_statement" => {
            parse_py_import(node, src, out);
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_py_imports(child, src, out);
    }
}

fn parse_py_import_from(node: Node, src: &[u8]) -> Option<ImportDecl> {
    let module_node = node.child_by_field_name("module_name")?;
    let source = node_text(module_node, src).to_string();

    let mut specifiers = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "dotted_name" if child != module_node => {
                let name = node_text(child, src).to_string();
                specifiers.push(ImportSpecifier::Named {
                    local: name.clone(),
                    imported: name,
                });
            }
            "aliased_import" => {
                let name_node = child.child_by_field_name("name");
                let alias_node = child.child_by_field_name("alias");
                if let Some(name) = name_node {
                    let imported = node_text(name, src).to_string();
                    let local = alias_node
                        .map(|a| node_text(a, src).to_string())
                        .unwrap_or_else(|| imported.clone());
                    specifiers.push(ImportSpecifier::Named { local, imported });
                }
            }
            "wildcard_import" => {
                specifiers.push(ImportSpecifier::Namespace {
                    local: "*".to_string(),
                });
            }
            _ => {}
        }
    }

    Some(ImportDecl {
        source,
        specifiers,
        line: line_of(node),
    })
}

fn parse_py_import(node: Node, src: &[u8], out: &mut Vec<ImportDecl>) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "dotted_name" => {
                let name = node_text(child, src).to_string();
                out.push(ImportDecl {
                    source: name.clone(),
                    specifiers: vec![ImportSpecifier::Default { local: name }],
                    line: line_of(node),
                });
            }
            "aliased_import" => {
                if let Some(name) = child.child_by_field_name("name") {
                    let imported = node_text(name, src).to_string();
                    let local = child
                        .child_by_field_name("alias")
                        .map(|a| node_text(a, src).to_string())
                        .unwrap_or_else(|| imported.clone());
                    out.push(ImportDecl {
                        source: imported,
                        specifiers: vec![ImportSpecifier::Default { local }],
                        line: line_of(node),
                    });
                }
            }
            _ => {}
        }
    }
}

// ─── Go ─────────────────────────────────────────────────────────────

#[cfg(feature = "lang-go")]
fn walk_go_imports(node: Node, src: &[u8], out: &mut Vec<ImportDecl>) {
    if node.kind() == "import_declaration" {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            match child.kind() {
                "import_spec" => {
                    if let Some(path_node) = child.child_by_field_name("path") {
                        let source = strip_quotes(node_text(path_node, src)).to_string();
                        let alias = child
                            .child_by_field_name("name")
                            .map(|n| node_text(n, src).to_string());
                        let local = alias.unwrap_or_else(|| {
                            source.rsplit('/').next().unwrap_or(&source).to_string()
                        });
                        out.push(ImportDecl {
                            source,
                            specifiers: vec![ImportSpecifier::Default { local }],
                            line: line_of(child),
                        });
                    }
                }
                "import_spec_list" => {
                    let mut inner = child.walk();
                    for spec in child.named_children(&mut inner) {
                        if spec.kind() == "import_spec" {
                            if let Some(path_node) = spec.child_by_field_name("path") {
                                let source = strip_quotes(node_text(path_node, src)).to_string();
                                let alias = spec
                                    .child_by_field_name("name")
                                    .map(|n| node_text(n, src).to_string());
                                let local = alias.unwrap_or_else(|| {
                                    source.rsplit('/').next().unwrap_or(&source).to_string()
                                });
                                out.push(ImportDecl {
                                    source,
                                    specifiers: vec![ImportSpecifier::Default { local }],
                                    line: line_of(spec),
                                });
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_go_imports(child, src, out);
    }
}

// ─── Java / C# ──────────────────────────────────────────────────────

#[cfg(any(feature = "lang-java", feature = "lang-csharp"))]
fn walk_java_imports(node: Node, src: &[u8], out: &mut Vec<ImportDecl>) {
    match node.kind() {
        // Java: import com.example.UserService;
        "import_declaration" => {
            let full = node_text(node, src);
            // Extract the path between "import" and ";"
            let path = full
                .trim()
                .strip_prefix("import")
                .unwrap_or(full)
                .trim()
                .strip_prefix("static")
                .unwrap_or(full.trim().strip_prefix("import").unwrap_or(full))
                .trim()
                .strip_suffix(';')
                .unwrap_or("")
                .trim();
            if !path.is_empty() {
                let local = path.rsplit('.').next().unwrap_or(path).to_string();
                out.push(ImportDecl {
                    source: path.to_string(),
                    specifiers: vec![ImportSpecifier::Named {
                        local: local.clone(),
                        imported: local,
                    }],
                    line: line_of(node),
                });
            }
        }
        // C#: using System.Collections.Generic;
        "using_directive" => {
            let full = node_text(node, src);
            let path = full
                .trim()
                .strip_prefix("using")
                .unwrap_or(full)
                .trim()
                .strip_suffix(';')
                .unwrap_or("")
                .trim();
            if !path.is_empty() {
                let local = path.rsplit('.').next().unwrap_or(path).to_string();
                out.push(ImportDecl {
                    source: path.to_string(),
                    specifiers: vec![ImportSpecifier::Namespace { local }],
                    line: line_of(node),
                });
            }
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_java_imports(child, src, out);
    }
}

/// Extract public declarations from Go/Java/C# for export tracking.
#[cfg(any(feature = "lang-go", feature = "lang-java", feature = "lang-csharp"))]
fn walk_public_declarations(node: Node, src: &[u8], out: &mut Vec<ExportDecl>) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            // Go: func GetUser() / Java: public void getUser() / C#: public void GetUser()
            "function_declaration" | "method_declaration" => {
                if let Some(name) = child.child_by_field_name("name") {
                    let text = node_text(name, src);
                    // Go: exported if starts with uppercase
                    // Java/C#: check for public modifier
                    let is_public = text.starts_with(|c: char| c.is_uppercase())
                        || node_text(child, src).contains("public");
                    if is_public {
                        out.push(ExportDecl {
                            name: text.to_string(),
                            kind: ExportKind::Named,
                            line: line_of(child),
                        });
                    }
                }
            }
            // Go: type User struct / Java: public class User
            "type_declaration" | "class_declaration" | "struct_declaration" => {
                if let Some(name) = child
                    .child_by_field_name("name")
                    .or_else(|| child.child_by_field_name("type"))
                {
                    let text = node_text(name, src);
                    if text.starts_with(|c: char| c.is_uppercase())
                        || node_text(child, src).contains("public")
                    {
                        out.push(ExportDecl {
                            name: text.to_string(),
                            kind: ExportKind::Named,
                            line: line_of(child),
                        });
                    }
                }
            }
            _ => {}
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::Parser;

    fn parse_ts(source: &str) -> (tree_sitter::Tree, Vec<u8>) {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .unwrap();
        let src = source.as_bytes().to_vec();
        let tree = parser.parse(&src, None).unwrap();
        (tree, src)
    }

    fn parse_py(source: &str) -> (tree_sitter::Tree, Vec<u8>) {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .unwrap();
        let src = source.as_bytes().to_vec();
        let tree = parser.parse(&src, None).unwrap();
        (tree, src)
    }

    // ── TS imports ──

    #[test]
    fn ts_named_import() {
        let (tree, src) = parse_ts("import { UserService, logger } from './services/user';");
        let imports = extract_imports(tree.root_node(), &src, Language::TypeScript);
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].source, "./services/user");
        assert_eq!(imports[0].specifiers.len(), 2);
        assert!(matches!(&imports[0].specifiers[0],
            ImportSpecifier::Named { local, imported } if local == "UserService" && imported == "UserService"));
    }

    #[test]
    fn ts_default_import() {
        let (tree, src) = parse_ts("import express from 'express';");
        let imports = extract_imports(tree.root_node(), &src, Language::TypeScript);
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].source, "express");
        assert!(
            matches!(&imports[0].specifiers[0], ImportSpecifier::Default { local } if local == "express")
        );
    }

    #[test]
    fn ts_aliased_import() {
        let (tree, src) = parse_ts("import { sendEmail as mailer } from './email';");
        let imports = extract_imports(tree.root_node(), &src, Language::TypeScript);
        assert_eq!(imports.len(), 1);
        assert!(matches!(&imports[0].specifiers[0],
            ImportSpecifier::Named { local, imported } if local == "mailer" && imported == "sendEmail"));
    }

    #[test]
    fn ts_namespace_import() {
        let (tree, src) = parse_ts("import * as utils from './utils';");
        let imports = extract_imports(tree.root_node(), &src, Language::TypeScript);
        assert_eq!(imports.len(), 1);
        assert!(
            matches!(&imports[0].specifiers[0], ImportSpecifier::Namespace { local } if local == "utils")
        );
    }

    // ── TS exports ──

    #[test]
    fn ts_export_function() {
        let (tree, src) = parse_ts("export function processUser(user: User) { }");
        let exports = extract_exports(tree.root_node(), &src, Language::TypeScript);
        assert!(
            exports
                .iter()
                .any(|e| e.name == "processUser" && e.kind == ExportKind::Named),
            "got: {:?}",
            exports
        );
    }

    #[test]
    fn ts_export_const() {
        let (tree, src) = parse_ts("export const API_KEY = 'xxx';");
        let exports = extract_exports(tree.root_node(), &src, Language::TypeScript);
        assert!(
            exports.iter().any(|e| e.name == "API_KEY"),
            "got: {:?}",
            exports
        );
    }

    #[test]
    fn ts_export_clause() {
        let (tree, src) = parse_ts("export { getEmail, getPhone };");
        let exports = extract_exports(tree.root_node(), &src, Language::TypeScript);
        assert!(
            exports.iter().any(|e| e.name == "getEmail"),
            "got: {:?}",
            exports
        );
        assert!(
            exports.iter().any(|e| e.name == "getPhone"),
            "got: {:?}",
            exports
        );
    }

    #[test]
    fn ts_re_export() {
        let (tree, src) = parse_ts("export { UserService } from './services/user';");
        let exports = extract_exports(tree.root_node(), &src, Language::TypeScript);
        assert!(exports.iter().any(|e| e.name == "UserService"
            && matches!(&e.kind, ExportKind::ReExport { source } if source == "./services/user")),
            "got: {:?}", exports);
    }

    // ── Python imports ──

    #[test]
    fn py_import_from() {
        let (tree, src) = parse_py("from services.user import UserService, get_email");
        let imports = extract_imports(tree.root_node(), &src, Language::Python);
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].source, "services.user");
        assert_eq!(imports[0].specifiers.len(), 2);
    }

    #[test]
    fn py_import_module() {
        let (tree, src) = parse_py("import os");
        let imports = extract_imports(tree.root_node(), &src, Language::Python);
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].source, "os");
    }

    #[test]
    fn py_import_alias() {
        let (tree, src) = parse_py("import numpy as np");
        let imports = extract_imports(tree.root_node(), &src, Language::Python);
        assert_eq!(imports.len(), 1);
        assert!(
            matches!(&imports[0].specifiers[0], ImportSpecifier::Default { local } if local == "np")
        );
    }

    #[test]
    fn py_relative_import() {
        let (tree, src) = parse_py("from .models import User");
        let imports = extract_imports(tree.root_node(), &src, Language::Python);
        assert_eq!(imports.len(), 1);
    }

    // ── Python exports (public names) ──

    #[test]
    fn py_public_names() {
        let src =
            "def get_email():\n    pass\n\nclass User:\n    pass\n\napi_key = 'xxx'\n_private = 1";
        let (tree, src_bytes) = parse_py(src);
        let exports = extract_py_public_names(tree.root_node(), &src_bytes);
        assert!(
            exports.iter().any(|e| e.name == "get_email"),
            "got: {:?}",
            exports
        );
        assert!(
            exports.iter().any(|e| e.name == "User"),
            "got: {:?}",
            exports
        );
        assert!(
            exports.iter().any(|e| e.name == "api_key"),
            "got: {:?}",
            exports
        );
        assert!(
            !exports.iter().any(|e| e.name == "_private"),
            "should exclude _private: {:?}",
            exports
        );
    }
}

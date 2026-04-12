use super::{CallExpression, Identifier, IdentifierContext, StringLiteral};
use crate::discovery::Language;
use tree_sitter::Node;

// ─── Utility ────────────────────────────────────────────────────────

fn node_text<'a>(node: Node, src: &'a [u8]) -> &'a str {
    std::str::from_utf8(&src[node.start_byte()..node.end_byte()]).unwrap_or("")
}

/// tree-sitter uses 0-based rows; we expose 1-based line numbers.
fn line_of(node: Node) -> usize {
    node.start_position().row + 1
}

fn col_of(node: Node) -> usize {
    node.start_position().column + 1
}

// ─── Identifier extraction ──────────────────────────────────────────

pub fn extract_identifiers(root: Node, src: &[u8], language: Language) -> Vec<Identifier> {
    let mut out = Vec::new();
    match language {
        #[cfg(any(feature = "lang-typescript", feature = "lang-javascript"))]
        Language::TypeScript | Language::JavaScript => walk_ts_identifiers(root, src, &mut out),
        #[cfg(feature = "lang-python")]
        Language::Python => walk_py_identifiers(root, src, &mut out),
        #[cfg(feature = "lang-go")]
        Language::Go => walk_go_identifiers(root, src, &mut out),
        #[cfg(any(feature = "lang-java", feature = "lang-csharp"))]
        Language::Java | Language::CSharp => walk_java_identifiers(root, src, &mut out),
    }
    out
}

// ─── TypeScript / JavaScript ────────────────────────────────────────

fn walk_ts_identifiers(node: Node, src: &[u8], out: &mut Vec<Identifier>) {
    match node.kind() {
        // ── variable declarator: const email = ... ──
        "variable_declarator" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                push_ident(name_node, src, IdentifierContext::VariableDecl, out);
            }
        }

        // ── interface / type alias fields: email: string ──
        "property_signature" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                push_ident(name_node, src, IdentifierContext::TypeField, out);
            }
        }

        // ── class property: private email: string ──
        "public_field_definition" | "property_definition" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                push_ident(name_node, src, IdentifierContext::TypeField, out);
            }
        }

        // ── function / method parameters ──
        "required_parameter" | "optional_parameter" => {
            if let Some(pat) = node.child_by_field_name("pattern") {
                push_ident(pat, src, IdentifierContext::Parameter, out);
            }
        }
        // Plain JS parameter (identifier directly inside formal_parameters)
        "identifier" if is_inside_formal_parameters(node) => {
            push_ident(node, src, IdentifierContext::Parameter, out);
        }

        // ── destructuring pattern: const { email, phone } = ... ──
        "shorthand_property_identifier_pattern" | "shorthand_property_identifier" => {
            push_ident(node, src, IdentifierContext::Destructure, out);
        }

        // ── object literal property key: { email: value } ──
        "pair" => {
            if let Some(key) = node.child_by_field_name("key") {
                push_ident(key, src, IdentifierContext::PropertyDef, out);
            }
        }

        // ── member expression: user.email ──
        "member_expression" => {
            if let Some(prop) = node.child_by_field_name("property") {
                push_ident(prop, src, IdentifierContext::PropertyAccess, out);
            }
        }

        _ => {}
    }

    // Recurse into children
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_ts_identifiers(child, src, out);
    }
}

fn is_inside_formal_parameters(node: Node) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.kind() == "formal_parameters" {
            return true;
        }
        current = parent;
    }
    false
}

// ─── Python ─────────────────────────────────────────────────────────

fn walk_py_identifiers(node: Node, src: &[u8], out: &mut Vec<Identifier>) {
    match node.kind() {
        // ── assignment: email = ... ──
        "assignment" | "augmented_assignment" => {
            if let Some(left) = node.child_by_field_name("left") {
                match left.kind() {
                    "identifier" => {
                        push_ident(left, src, IdentifierContext::VariableDecl, out);
                    }
                    // self.email = ...
                    "attribute" => {
                        if let Some(attr) = left.child_by_field_name("attribute") {
                            push_ident(attr, src, IdentifierContext::PropertyDef, out);
                        }
                    }
                    _ => {}
                }
            }
        }

        // ── typed parameter: def func(email: str, ...) ──
        "typed_parameter" => {
            // First named child is the parameter name
            if let Some(child) = node.named_child(0) {
                if child.kind() == "identifier" {
                    let text = node_text(child, src);
                    if text != "self" && text != "cls" {
                        push_ident(child, src, IdentifierContext::Parameter, out);
                    }
                }
            }
        }

        // ── plain parameter identifier inside parameters() ──
        "identifier" if is_inside_py_parameters(node) => {
            let text = node_text(node, src);
            if text != "self" && text != "cls" {
                push_ident(node, src, IdentifierContext::Parameter, out);
            }
        }

        // ── default_parameter: def func(email="default") ──
        "default_parameter" => {
            if let Some(name) = node.child_by_field_name("name") {
                let text = node_text(name, src);
                if text != "self" && text != "cls" {
                    push_ident(name, src, IdentifierContext::Parameter, out);
                }
            }
        }

        // ── attribute access: user.email ──
        "attribute" => {
            if let Some(attr) = node.child_by_field_name("attribute") {
                let text = node_text(attr, src);
                // Filter out common method names
                if !is_python_builtin_method(text) {
                    push_ident(attr, src, IdentifierContext::PropertyAccess, out);
                }
            }
        }

        // ── dict pair key: {"email": value} ──
        "pair" => {
            if let Some(key) = node.child_by_field_name("key") {
                if key.kind() == "string" {
                    let raw = node_text(key, src);
                    let stripped = raw.trim_matches(|c| c == '"' || c == '\'');
                    if !stripped.is_empty()
                        && stripped.chars().all(|c| c.is_alphanumeric() || c == '_')
                    {
                        out.push(Identifier {
                            name: stripped.to_string(),
                            line: line_of(key),
                            column: col_of(key),
                            context: IdentifierContext::PropertyDef,
                        });
                    }
                }
            }
        }

        _ => {}
    }

    // Recurse into children
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_py_identifiers(child, src, out);
    }
}

fn is_inside_py_parameters(node: Node) -> bool {
    if let Some(parent) = node.parent() {
        return parent.kind() == "parameters";
    }
    false
}

fn is_python_builtin_method(name: &str) -> bool {
    matches!(
        name,
        "append"
            | "extend"
            | "items"
            | "keys"
            | "values"
            | "get"
            | "set"
            | "join"
            | "split"
            | "strip"
            | "format"
            | "encode"
            | "decode"
            | "lower"
            | "upper"
            | "replace"
            | "startswith"
            | "endswith"
            | "find"
            | "index"
            | "count"
            | "sort"
            | "pop"
            | "remove"
            | "insert"
            | "copy"
            | "update"
            | "clear"
            | "close"
            | "read"
            | "write"
            | "readline"
            | "readlines"
            | "flush"
            | "seek"
            | "tell"
    )
}

// ─── String literal extraction ──────────────────────────────────────

pub fn extract_string_literals(root: Node, src: &[u8], _language: Language) -> Vec<StringLiteral> {
    let mut out = Vec::new();
    walk_string_literals(root, src, &mut out);
    out
}

fn walk_string_literals(node: Node, src: &[u8], out: &mut Vec<StringLiteral>) {
    match node.kind() {
        "string" | "string_fragment" | "template_string" => {
            let raw = node_text(node, src);
            let value = strip_string_delimiters(raw);
            if value.len() >= 5 {
                out.push(StringLiteral {
                    value: value.to_string(),
                    line: line_of(node),
                    column: col_of(node),
                });
            }
            return; // Don't recurse into string children
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_string_literals(child, src, out);
    }
}

fn strip_string_delimiters(raw: &str) -> &str {
    let s = raw
        .strip_prefix('"')
        .or_else(|| raw.strip_prefix('\''))
        .or_else(|| raw.strip_prefix('`'))
        .or_else(|| raw.strip_prefix("f\"").or_else(|| raw.strip_prefix("f'")))
        .unwrap_or(raw);
    let s = s
        .strip_suffix('"')
        .or_else(|| s.strip_suffix('\''))
        .or_else(|| s.strip_suffix('`'))
        .unwrap_or(s);
    s
}

// ─── Call expression extraction ─────────────────────────────────────

pub fn extract_call_expressions(root: Node, src: &[u8], language: Language) -> Vec<CallExpression> {
    let mut out = Vec::new();
    walk_call_expressions(root, src, language, &mut out);
    out
}

fn walk_call_expressions(
    node: Node,
    src: &[u8],
    language: Language,
    out: &mut Vec<CallExpression>,
) {
    let call_kind = match language {
        #[cfg(any(feature = "lang-typescript", feature = "lang-javascript"))]
        Language::TypeScript | Language::JavaScript => "call_expression",
        #[cfg(feature = "lang-python")]
        Language::Python => "call",
        #[cfg(feature = "lang-go")]
        Language::Go => "call_expression",
        #[cfg(any(feature = "lang-java", feature = "lang-csharp"))]
        Language::Java | Language::CSharp => "method_invocation",
    };

    if node.kind() == call_kind {
        if let Some(func_node) = node.child_by_field_name("function") {
            let callee = node_text(func_node, src).to_string();

            let args_node = node.child_by_field_name("arguments");
            let argument_identifiers = args_node
                .map(|args| collect_argument_identifiers(args, src))
                .unwrap_or_default();

            out.push(CallExpression {
                callee,
                line: line_of(node),
                column: col_of(node),
                argument_identifiers,
            });
        }
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_call_expressions(child, src, language, out);
    }
}

/// Collect identifiers used in call arguments (for data-flow analysis).
fn collect_argument_identifiers(args_node: Node, src: &[u8]) -> Vec<String> {
    let mut idents = Vec::new();
    walk_argument_idents(args_node, src, &mut idents);
    idents
}

fn walk_argument_idents(node: Node, src: &[u8], out: &mut Vec<String>) {
    match node.kind() {
        "identifier" => {
            let text = node_text(node, src);
            if !is_keyword(text) {
                out.push(text.to_string());
            }
        }
        "member_expression" | "attribute" => {
            // Capture the full dotted expression (e.g., "user.email")
            let full = node_text(node, src);
            out.push(full.to_string());
            // Also capture individual property
            if let Some(prop) = node
                .child_by_field_name("property")
                .or_else(|| node.child_by_field_name("attribute"))
            {
                out.push(node_text(prop, src).to_string());
            }
        }
        _ => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                walk_argument_idents(child, src, out);
            }
        }
    }
}

fn is_keyword(text: &str) -> bool {
    matches!(
        text,
        "true"
            | "false"
            | "null"
            | "undefined"
            | "None"
            | "True"
            | "False"
            | "self"
            | "cls"
            | "this"
            | "new"
            | "typeof"
            | "instanceof"
    )
}

// ─── Helper ─────────────────────────────────────────────────────────

fn push_ident(node: Node, src: &[u8], context: IdentifierContext, out: &mut Vec<Identifier>) {
    let text = node_text(node, src);
    if text.is_empty() || is_keyword(text) {
        return;
    }
    out.push(Identifier {
        name: text.to_string(),
        line: line_of(node),
        column: col_of(node),
        context,
    });
}

// ─── Go ─────────────────────────────────────────────────────────────

#[cfg(feature = "lang-go")]
fn walk_go_identifiers(node: Node, src: &[u8], out: &mut Vec<Identifier>) {
    match node.kind() {
        // var email string / email := ...
        "short_var_declaration" | "var_declaration" => {
            walk_go_var_names(node, src, out);
        }
        // Struct field: Email string `json:"email"`
        "field_declaration" => {
            if let Some(name) = node.named_child(0) {
                if name.kind() == "field_identifier" {
                    push_ident(name, src, IdentifierContext::TypeField, out);
                }
            }
        }
        // Function parameters
        "parameter_declaration" => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if child.kind() == "identifier" {
                    push_ident(child, src, IdentifierContext::Parameter, out);
                }
            }
        }
        // Selector: user.Email
        "selector_expression" => {
            if let Some(field) = node.child_by_field_name("field") {
                push_ident(field, src, IdentifierContext::PropertyAccess, out);
            }
        }
        // Composite literal key: Email: "test"
        "keyed_element" => {
            if let Some(key) = node.named_child(0) {
                if key.kind() == "field_identifier" || key.kind() == "identifier" {
                    push_ident(key, src, IdentifierContext::PropertyDef, out);
                }
            }
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_go_identifiers(child, src, out);
    }
}

#[cfg(feature = "lang-go")]
fn walk_go_var_names(node: Node, src: &[u8], out: &mut Vec<Identifier>) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "identifier" | "expression_list" => {
                let mut inner = child.walk();
                if child.kind() == "expression_list" {
                    for id in child.named_children(&mut inner) {
                        if id.kind() == "identifier" {
                            push_ident(id, src, IdentifierContext::VariableDecl, out);
                        }
                    }
                } else {
                    push_ident(child, src, IdentifierContext::VariableDecl, out);
                }
            }
            "var_spec" => {
                if let Some(name) = child.child_by_field_name("name") {
                    push_ident(name, src, IdentifierContext::VariableDecl, out);
                }
                // Also check for multiple names in a var spec
                let mut inner = child.walk();
                for sub in child.named_children(&mut inner) {
                    if sub.kind() == "identifier" {
                        push_ident(sub, src, IdentifierContext::VariableDecl, out);
                    }
                }
            }
            _ => {}
        }
    }
}

// ─── Java / C# ──────────────────────────────────────────────────────

#[cfg(any(feature = "lang-java", feature = "lang-csharp"))]
fn walk_java_identifiers(node: Node, src: &[u8], out: &mut Vec<Identifier>) {
    match node.kind() {
        // Variable declaration: String email = ...
        "local_variable_declaration" | "variable_declaration" => {
            walk_java_var_declarators(node, src, out);
        }
        // Field declaration: private String email;
        "field_declaration" => {
            walk_java_var_declarators(node, src, out);
        }
        // Method/constructor parameter: String email
        "formal_parameter" | "parameter" => {
            if let Some(name) = node.child_by_field_name("name") {
                push_ident(name, src, IdentifierContext::Parameter, out);
            }
        }
        // Member access: user.getEmail() / user.email
        "field_access" | "member_access_expression" => {
            if let Some(field) = node.child_by_field_name("field") {
                push_ident(field, src, IdentifierContext::PropertyAccess, out);
            }
            if let Some(name) = node.child_by_field_name("name") {
                push_ident(name, src, IdentifierContext::PropertyAccess, out);
            }
        }
        // Method invocation name: logger.info(email)
        "method_invocation" | "invocation_expression" => {
            if let Some(name) = node.child_by_field_name("name") {
                let text = node_text(name, src);
                // Check if getter method reveals PII: getEmail -> email
                if text.starts_with("get") && text.len() > 3 {
                    let field = &text[3..];
                    let lower = format!("{}{}", field[..1].to_lowercase(), &field[1..]);
                    out.push(Identifier {
                        name: lower,
                        line: line_of(name),
                        column: col_of(name),
                        context: IdentifierContext::PropertyAccess,
                    });
                }
            }
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_java_identifiers(child, src, out);
    }
}

#[cfg(any(feature = "lang-java", feature = "lang-csharp"))]
fn walk_java_var_declarators(node: Node, src: &[u8], out: &mut Vec<Identifier>) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "variable_declarator" {
            if let Some(name) = child.child_by_field_name("name") {
                push_ident(name, src, IdentifierContext::VariableDecl, out);
            }
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

    fn parse_js(source: &str) -> (tree_sitter::Tree, Vec<u8>) {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_javascript::LANGUAGE.into())
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

    // ── TypeScript identifiers ──

    #[test]
    fn ts_variable_decl() {
        let (tree, src) = parse_ts("const email = getUserEmail();");
        let ids = extract_identifiers(tree.root_node(), &src, Language::TypeScript);
        assert!(
            ids.iter()
                .any(|i| i.name == "email" && i.context == IdentifierContext::VariableDecl),
            "Expected VariableDecl 'email', got: {:?}",
            ids
        );
    }

    #[test]
    fn ts_interface_field() {
        let (tree, src) = parse_ts("interface User { email: string; }");
        let ids = extract_identifiers(tree.root_node(), &src, Language::TypeScript);
        assert!(
            ids.iter()
                .any(|i| i.name == "email" && i.context == IdentifierContext::TypeField),
            "Expected TypeField 'email', got: {:?}",
            ids
        );
    }

    #[test]
    fn ts_member_access() {
        let (tree, src) = parse_ts("console.log(user.email);");
        let ids = extract_identifiers(tree.root_node(), &src, Language::TypeScript);
        assert!(
            ids.iter()
                .any(|i| i.name == "email" && i.context == IdentifierContext::PropertyAccess),
            "Expected PropertyAccess 'email', got: {:?}",
            ids
        );
    }

    #[test]
    fn ts_destructure() {
        let (tree, src) = parse_ts("const { email, phone } = user;");
        let ids = extract_identifiers(tree.root_node(), &src, Language::TypeScript);
        assert!(
            ids.iter()
                .any(|i| i.name == "email" && i.context == IdentifierContext::Destructure),
            "Expected Destructure 'email', got: {:?}",
            ids
        );
        assert!(
            ids.iter()
                .any(|i| i.name == "phone" && i.context == IdentifierContext::Destructure),
            "Expected Destructure 'phone', got: {:?}",
            ids
        );
    }

    #[test]
    fn ts_function_params() {
        let (tree, src) = parse_ts("function login(email: string, password: string) {}");
        let ids = extract_identifiers(tree.root_node(), &src, Language::TypeScript);
        assert!(
            ids.iter()
                .any(|i| i.name == "email" && i.context == IdentifierContext::Parameter),
            "Expected Parameter 'email', got: {:?}",
            ids
        );
        assert!(
            ids.iter()
                .any(|i| i.name == "password" && i.context == IdentifierContext::Parameter),
            "Expected Parameter 'password', got: {:?}",
            ids
        );
    }

    #[test]
    fn ts_class_field() {
        let (tree, src) = parse_ts("class User { private email: string; }");
        let ids = extract_identifiers(tree.root_node(), &src, Language::TypeScript);
        assert!(
            ids.iter()
                .any(|i| i.name == "email" && i.context == IdentifierContext::TypeField),
            "Expected TypeField 'email', got: {:?}",
            ids
        );
    }

    #[test]
    fn ts_object_property() {
        let (tree, src) = parse_ts("const obj = { email: 'test@example.com', count: 5 };");
        let ids = extract_identifiers(tree.root_node(), &src, Language::TypeScript);
        assert!(
            ids.iter()
                .any(|i| i.name == "email" && i.context == IdentifierContext::PropertyDef),
            "Expected PropertyDef 'email', got: {:?}",
            ids
        );
    }

    #[test]
    fn ts_arrow_function_params() {
        let (tree, src) = parse_ts("const fn = (email: string) => email;");
        let ids = extract_identifiers(tree.root_node(), &src, Language::TypeScript);
        assert!(
            ids.iter()
                .any(|i| i.name == "email" && i.context == IdentifierContext::Parameter),
            "Expected Parameter 'email', got: {:?}",
            ids
        );
    }

    #[test]
    fn ts_nested_member_access() {
        let (tree, src) = parse_ts("const x = request.body.email;");
        let ids = extract_identifiers(tree.root_node(), &src, Language::TypeScript);
        assert!(
            ids.iter()
                .any(|i| i.name == "email" && i.context == IdentifierContext::PropertyAccess),
            "Expected PropertyAccess 'email', got: {:?}",
            ids
        );
    }

    // ── JavaScript identifiers ──

    #[test]
    fn js_function_params() {
        let (tree, src) = parse_js("function login(email, password) {}");
        let ids = extract_identifiers(tree.root_node(), &src, Language::JavaScript);
        assert!(
            ids.iter()
                .any(|i| i.name == "email" && i.context == IdentifierContext::Parameter),
            "Expected Parameter 'email', got: {:?}",
            ids
        );
    }

    // ── Python identifiers ──

    #[test]
    fn py_assignment() {
        let (tree, src) = parse_py("email = get_email()");
        let ids = extract_identifiers(tree.root_node(), &src, Language::Python);
        assert!(
            ids.iter()
                .any(|i| i.name == "email" && i.context == IdentifierContext::VariableDecl),
            "Expected VariableDecl 'email', got: {:?}",
            ids
        );
    }

    #[test]
    fn py_function_param() {
        let (tree, src) = parse_py("def process(email, phone_number):\n    pass");
        let ids = extract_identifiers(tree.root_node(), &src, Language::Python);
        assert!(
            ids.iter()
                .any(|i| i.name == "email" && i.context == IdentifierContext::Parameter),
            "Expected Parameter 'email', got: {:?}",
            ids
        );
        assert!(
            ids.iter()
                .any(|i| i.name == "phone_number" && i.context == IdentifierContext::Parameter),
            "Expected Parameter 'phone_number', got: {:?}",
            ids
        );
    }

    #[test]
    fn py_typed_param() {
        let (tree, src) = parse_py("def process(email: str, age: int):\n    pass");
        let ids = extract_identifiers(tree.root_node(), &src, Language::Python);
        assert!(
            ids.iter()
                .any(|i| i.name == "email" && i.context == IdentifierContext::Parameter),
            "Expected Parameter 'email', got: {:?}",
            ids
        );
    }

    #[test]
    fn py_self_attribute() {
        let src = "class User:\n    def __init__(self):\n        self.email = ''";
        let (tree, src_bytes) = parse_py(src);
        let ids = extract_identifiers(tree.root_node(), &src_bytes, Language::Python);
        assert!(
            ids.iter()
                .any(|i| i.name == "email" && i.context == IdentifierContext::PropertyDef),
            "Expected PropertyDef 'email', got: {:?}",
            ids
        );
    }

    #[test]
    fn py_attribute_access() {
        let (tree, src) = parse_py("x = user.email");
        let ids = extract_identifiers(tree.root_node(), &src, Language::Python);
        assert!(
            ids.iter()
                .any(|i| i.name == "email" && i.context == IdentifierContext::PropertyAccess),
            "Expected PropertyAccess 'email', got: {:?}",
            ids
        );
    }

    #[test]
    fn py_dict_key() {
        let (tree, src) = parse_py("data = {\"email\": \"test@example.com\"}");
        let ids = extract_identifiers(tree.root_node(), &src, Language::Python);
        assert!(
            ids.iter()
                .any(|i| i.name == "email" && i.context == IdentifierContext::PropertyDef),
            "Expected PropertyDef 'email', got: {:?}",
            ids
        );
    }

    #[test]
    fn py_skip_self_param() {
        let (tree, src) = parse_py("def method(self, email):\n    pass");
        let ids = extract_identifiers(tree.root_node(), &src, Language::Python);
        assert!(
            !ids.iter().any(|i| i.name == "self"),
            "Should not include 'self', got: {:?}",
            ids
        );
        assert!(
            ids.iter().any(|i| i.name == "email"),
            "Should include 'email', got: {:?}",
            ids
        );
    }

    // ── Comments properly ignored via AST ──

    #[test]
    fn ts_skip_comments() {
        let (tree, src) = parse_ts("// const email = 'test';");
        let ids = extract_identifiers(tree.root_node(), &src, Language::TypeScript);
        assert!(
            !ids.iter()
                .any(|i| i.name == "email" && i.context == IdentifierContext::VariableDecl),
            "Should not find email in comment, got: {:?}",
            ids
        );
    }

    #[test]
    fn py_skip_comments() {
        let (tree, src) = parse_py("# email = 'test'");
        let ids = extract_identifiers(tree.root_node(), &src, Language::Python);
        assert!(
            !ids.iter()
                .any(|i| i.name == "email" && i.context == IdentifierContext::VariableDecl),
            "Should not find email in comment, got: {:?}",
            ids
        );
    }

    // ── String literals ──

    #[test]
    fn ts_string_literal() {
        let (tree, src) = parse_ts(r#"const msg = "user@example.com";"#);
        let lits = extract_string_literals(tree.root_node(), &src, Language::TypeScript);
        assert!(
            lits.iter().any(|l| l.value == "user@example.com"),
            "Expected string 'user@example.com', got: {:?}",
            lits
        );
    }

    #[test]
    fn py_string_literal() {
        let (tree, src) = parse_py(r#"msg = "user@example.com""#);
        let lits = extract_string_literals(tree.root_node(), &src, Language::Python);
        assert!(
            lits.iter().any(|l| l.value == "user@example.com"),
            "Expected string 'user@example.com', got: {:?}",
            lits
        );
    }

    #[test]
    fn ts_template_string() {
        let (tree, src) = parse_ts("const url = `https://api.example.com/users`;");
        let lits = extract_string_literals(tree.root_node(), &src, Language::TypeScript);
        assert!(
            lits.iter().any(|l| l.value.contains("api.example.com")),
            "Expected template string content, got: {:?}",
            lits
        );
    }

    // ── Call expressions ──

    #[test]
    fn ts_call_expression() {
        let (tree, src) = parse_ts("console.log(user.email);");
        let calls = extract_call_expressions(tree.root_node(), &src, Language::TypeScript);
        assert!(
            calls.iter().any(|c| c.callee == "console.log"),
            "Expected call 'console.log', got: {:?}",
            calls
        );
    }

    #[test]
    fn ts_call_with_args() {
        let (tree, src) = parse_ts("fetch(url, { body: data });");
        let calls = extract_call_expressions(tree.root_node(), &src, Language::TypeScript);
        assert!(
            calls.iter().any(|c| c.callee == "fetch"),
            "Expected call 'fetch', got: {:?}",
            calls
        );
    }

    #[test]
    fn py_call_expression() {
        let (tree, src) = parse_py("logging.info(user.email)");
        let calls = extract_call_expressions(tree.root_node(), &src, Language::Python);
        assert!(
            calls.iter().any(|c| c.callee == "logging.info"),
            "Expected call 'logging.info', got: {:?}",
            calls
        );
    }

    #[test]
    fn ts_nested_call() {
        let (tree, src) = parse_ts("db.query(sql, [user.email, user.phone]);");
        let calls = extract_call_expressions(tree.root_node(), &src, Language::TypeScript);
        assert!(
            calls.iter().any(|c| c.callee == "db.query"),
            "Expected call 'db.query', got: {:?}",
            calls
        );
        let db_call = calls.iter().find(|c| c.callee == "db.query").unwrap();
        assert!(
            db_call
                .argument_identifiers
                .iter()
                .any(|a| a.contains("email")),
            "Expected 'email' in args, got: {:?}",
            db_call.argument_identifiers
        );
    }

    // ── Multi-line / complex structures ──

    #[test]
    fn ts_multiline_interface() {
        let src = "interface User {\n  email: string;\n  fullName: string;\n  age: number;\n}";
        let (tree, src_bytes) = parse_ts(src);
        let ids = extract_identifiers(tree.root_node(), &src_bytes, Language::TypeScript);
        assert!(ids
            .iter()
            .any(|i| i.name == "email" && i.context == IdentifierContext::TypeField));
        assert!(ids
            .iter()
            .any(|i| i.name == "fullName" && i.context == IdentifierContext::TypeField));
        assert!(ids
            .iter()
            .any(|i| i.name == "age" && i.context == IdentifierContext::TypeField));
    }

    #[test]
    fn py_class_with_init() {
        let src = "class User:\n    def __init__(self, email, phone):\n        self.email = email\n        self.phone = phone";
        let (tree, src_bytes) = parse_py(src);
        let ids = extract_identifiers(tree.root_node(), &src_bytes, Language::Python);
        assert!(
            ids.iter()
                .any(|i| i.name == "email" && i.context == IdentifierContext::Parameter),
            "Expected param 'email', got: {:?}",
            ids
        );
        assert!(
            ids.iter()
                .any(|i| i.name == "email" && i.context == IdentifierContext::PropertyDef),
            "Expected field 'email', got: {:?}",
            ids
        );
    }
}

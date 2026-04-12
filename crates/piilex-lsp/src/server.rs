use lsp_server::{Connection, Message, Notification, Request, RequestId, Response};
use lsp_types::{
    notification::{
        DidChangeTextDocument, DidOpenTextDocument, DidSaveTextDocument, Notification as _,
    },
    request::{CodeActionRequest, Request as _},
    CodeActionParams, CodeActionResponse, DidChangeTextDocumentParams, DidOpenTextDocumentParams,
    DidSaveTextDocumentParams, InitializeParams, PublishDiagnosticsParams, ServerCapabilities,
    TextDocumentSyncCapability, TextDocumentSyncKind, Uri,
};
use std::collections::HashMap;

use crate::diagnostics;

/// Run the LSP server on stdin/stdout.
pub fn run_server() -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("piilex LSP server starting...");

    let (connection, io_threads) = Connection::stdio();

    let capabilities = ServerCapabilities {
        text_document_sync: Some(TextDocumentSyncCapability::Kind(TextDocumentSyncKind::FULL)),
        code_action_provider: Some(lsp_types::CodeActionProviderCapability::Simple(true)),
        ..Default::default()
    };

    let server_capabilities = serde_json::to_value(capabilities)?;
    let init_params = connection.initialize(server_capabilities)?;
    let _params: InitializeParams = serde_json::from_value(init_params)?;

    eprintln!("piilex LSP initialized");
    main_loop(&connection)?;
    io_threads.join()?;
    eprintln!("piilex LSP server shut down");

    Ok(())
}

struct DocumentState {
    documents: HashMap<Uri, String>,
}

impl DocumentState {
    fn new() -> Self {
        Self {
            documents: HashMap::new(),
        }
    }

    fn open(&mut self, uri: Uri, text: String) {
        self.documents.insert(uri, text);
    }

    fn update(&mut self, uri: &Uri, text: String) {
        self.documents.insert(uri.clone(), text);
    }

    fn get(&self, uri: &Uri) -> Option<&String> {
        self.documents.get(uri)
    }

    fn close(&mut self, uri: &Uri) {
        self.documents.remove(uri);
    }
}

fn main_loop(connection: &Connection) -> Result<(), Box<dyn std::error::Error>> {
    let mut state = DocumentState::new();

    for msg in &connection.receiver {
        match msg {
            Message::Request(req) => {
                if connection.handle_shutdown(&req)? {
                    return Ok(());
                }
                handle_request(connection, &state, req)?;
            }
            Message::Notification(notif) => {
                handle_notification(connection, &mut state, notif)?;
            }
            Message::Response(_) => {}
        }
    }

    Ok(())
}

fn handle_request(
    connection: &Connection,
    state: &DocumentState,
    req: Request,
) -> Result<(), Box<dyn std::error::Error>> {
    if req.method == CodeActionRequest::METHOD {
        let (id, params): (RequestId, CodeActionParams) = req.extract(CodeActionRequest::METHOD)?;

        let uri = &params.text_document.uri;
        let text = state.get(uri).cloned().unwrap_or_default();

        let actions =
            diagnostics::code_actions_for_diagnostics(uri, &text, &params.context.diagnostics);

        let response: CodeActionResponse = actions
            .into_iter()
            .map(lsp_types::CodeActionOrCommand::CodeAction)
            .collect();
        let result = serde_json::to_value(response)?;

        connection.sender.send(Message::Response(Response {
            id,
            result: Some(result),
            error: None,
        }))?;
    }

    Ok(())
}

fn handle_notification(
    connection: &Connection,
    state: &mut DocumentState,
    notif: Notification,
) -> Result<(), Box<dyn std::error::Error>> {
    match notif.method.as_str() {
        DidOpenTextDocument::METHOD => {
            let params: DidOpenTextDocumentParams = serde_json::from_value(notif.params)?;
            let uri = params.text_document.uri.clone();
            let text = params.text_document.text.clone();
            state.open(uri.clone(), text.clone());
            publish_diagnostics(connection, &uri, &text)?;
        }
        DidChangeTextDocument::METHOD => {
            let params: DidChangeTextDocumentParams = serde_json::from_value(notif.params)?;
            let uri = params.text_document.uri.clone();
            if let Some(change) = params.content_changes.into_iter().last() {
                state.update(&uri, change.text.clone());
                publish_diagnostics(connection, &uri, &change.text)?;
            }
        }
        DidSaveTextDocument::METHOD => {
            let params: DidSaveTextDocumentParams = serde_json::from_value(notif.params)?;
            let uri = params.text_document.uri;
            if let Some(text) = params.text.or_else(|| state.get(&uri).cloned()) {
                state.update(&uri, text.clone());
                publish_diagnostics(connection, &uri, &text)?;
            }
        }
        "textDocument/didClose" => {
            if let Ok(params) =
                serde_json::from_value::<lsp_types::DidCloseTextDocumentParams>(notif.params)
            {
                state.close(&params.text_document.uri);
                let clear = PublishDiagnosticsParams {
                    uri: params.text_document.uri,
                    diagnostics: vec![],
                    version: None,
                };
                connection.sender.send(Message::Notification(Notification {
                    method: "textDocument/publishDiagnostics".to_string(),
                    params: serde_json::to_value(clear)?,
                }))?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn publish_diagnostics(
    connection: &Connection,
    uri: &Uri,
    text: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let diagnostics = diagnostics::diagnose_document(uri, text);

    let params = PublishDiagnosticsParams {
        uri: uri.clone(),
        diagnostics,
        version: None,
    };

    connection.sender.send(Message::Notification(Notification {
        method: "textDocument/publishDiagnostics".to_string(),
        params: serde_json::to_value(params)?,
    }))?;

    Ok(())
}

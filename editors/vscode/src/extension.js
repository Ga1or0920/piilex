const vscode = require("vscode");
const { LanguageClient, TransportKind } = require("vscode-languageclient/node");

let client;
let statusBar;

async function activate(context) {
  const config = vscode.workspace.getConfiguration("piilex");
  const enabled = config.get("enable", true);

  // Status bar
  statusBar = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Right,
    100
  );
  statusBar.command = "piilex.showStatus";
  context.subscriptions.push(statusBar);

  // Commands
  context.subscriptions.push(
    vscode.commands.registerCommand("piilex.showStatus", showStatus),
    vscode.commands.registerCommand("piilex.scanWorkspace", scanWorkspace),
    vscode.commands.registerCommand("piilex.enable", () => toggleEnable(true)),
    vscode.commands.registerCommand("piilex.disable", () => toggleEnable(false))
  );

  if (enabled) {
    await startClient(context);
  } else {
    updateStatusBar(false);
  }
}

async function startClient(context) {
  const config = vscode.workspace.getConfiguration("piilex");
  const binaryPath = config.get("path", "piilex");

  const serverOptions = {
    run: { command: binaryPath, args: ["lsp"], transport: TransportKind.stdio },
    debug: { command: binaryPath, args: ["lsp"], transport: TransportKind.stdio },
  };

  const clientOptions = {
    documentSelector: [
      { scheme: "file", language: "typescript" },
      { scheme: "file", language: "typescriptreact" },
      { scheme: "file", language: "javascript" },
      { scheme: "file", language: "javascriptreact" },
      { scheme: "file", language: "python" },
      { scheme: "file", language: "go" },
      { scheme: "file", language: "java" },
      { scheme: "file", language: "csharp" },
    ],
    synchronize: {
      fileEvents: vscode.workspace.createFileSystemWatcher("**/.piilex.yml"),
    },
  };

  client = new LanguageClient("piilex", "piilex PII Scanner", serverOptions, clientOptions);

  try {
    await client.start();
    updateStatusBar(true);
  } catch (err) {
    updateStatusBar(false);
    const action = await vscode.window.showErrorMessage(
      `piilex: Failed to start LSP server. Is 'piilex' installed and in PATH?\n${err.message}`,
      "Install Instructions"
    );
    if (action === "Install Instructions") {
      vscode.env.openExternal(vscode.Uri.parse("https://github.com/piilex/piilex#install"));
    }
  }
}

async function stopClient() {
  if (client) {
    await client.stop();
    client = undefined;
  }
  updateStatusBar(false);
}

function updateStatusBar(active) {
  if (!statusBar) return;
  if (active) {
    statusBar.text = "$(shield) piilex";
    statusBar.tooltip = "piilex PII Scanner - active";
    statusBar.backgroundColor = undefined;
  } else {
    statusBar.text = "$(shield) piilex (off)";
    statusBar.tooltip = "piilex PII Scanner - disabled";
    statusBar.backgroundColor = new vscode.ThemeColor("statusBarItem.warningBackground");
  }
  statusBar.show();
}

function showStatus() {
  const active = client && client.isRunning();
  const msg = active
    ? "piilex PII Scanner is active. PII findings appear as diagnostics in your editor."
    : "piilex PII Scanner is not running. Run 'piilex: Enable' to start.";
  vscode.window.showInformationMessage(msg);
}

async function scanWorkspace() {
  if (!client || !client.isRunning()) {
    vscode.window.showWarningMessage("piilex is not running. Enable it first.");
    return;
  }
  vscode.window.showInformationMessage("piilex: Re-scanning open documents...");
  // Trigger re-diagnosis by touching all open text documents
  for (const doc of vscode.workspace.textDocuments) {
    if (doc.uri.scheme === "file") {
      // The LSP server will re-diagnose when the document is "changed"
      const edit = new vscode.WorkspaceEdit();
      // No-op edit to trigger didChange
      edit.insert(doc.uri, new vscode.Position(0, 0), "");
      edit.delete(doc.uri, new vscode.Range(new vscode.Position(0, 0), new vscode.Position(0, 0)));
    }
  }
}

async function toggleEnable(enable) {
  const config = vscode.workspace.getConfiguration("piilex");
  await config.update("enable", enable, vscode.ConfigurationTarget.Global);

  if (enable) {
    await startClient();
    vscode.window.showInformationMessage("piilex PII Scanner enabled.");
  } else {
    await stopClient();
    vscode.window.showInformationMessage("piilex PII Scanner disabled.");
  }
}

function deactivate() {
  return stopClient();
}

module.exports = { activate, deactivate };

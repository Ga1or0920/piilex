const vscode = require("vscode");
const path = require("path");
const { LanguageClient, TransportKind } = require("vscode-languageclient/node");

let client;

function activate(context) {
  const config = vscode.workspace.getConfiguration("piilex");
  const enabled = config.get("enable", true);

  if (!enabled) {
    return;
  }

  const binaryPath = config.get("path", "piilex");

  // Resolve the binary: check if it's an absolute path or search in PATH
  const serverCommand = binaryPath;

  const serverOptions = {
    run: {
      command: serverCommand,
      args: ["lsp"],
      transport: TransportKind.stdio,
    },
    debug: {
      command: serverCommand,
      args: ["lsp"],
      transport: TransportKind.stdio,
    },
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

  client = new LanguageClient(
    "piilex",
    "piilex PII Scanner",
    serverOptions,
    clientOptions
  );

  client.start();

  // Register status bar item
  const statusBar = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Right,
    100
  );
  statusBar.text = "$(shield) piilex";
  statusBar.tooltip = "piilex PII Scanner active";
  statusBar.command = "piilex.showStatus";
  statusBar.show();

  context.subscriptions.push(statusBar);

  // Register commands
  context.subscriptions.push(
    vscode.commands.registerCommand("piilex.showStatus", () => {
      vscode.window.showInformationMessage(
        "piilex PII Scanner is active. PII findings appear as diagnostics."
      );
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("piilex.scanWorkspace", async () => {
      if (client) {
        vscode.window.showInformationMessage("piilex: scanning workspace...");
      }
    })
  );
}

function deactivate() {
  if (client) {
    return client.stop();
  }
}

module.exports = { activate, deactivate };

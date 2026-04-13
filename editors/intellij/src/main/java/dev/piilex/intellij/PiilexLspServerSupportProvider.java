package dev.piilex.intellij;

import com.intellij.execution.configurations.GeneralCommandLine;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.vfs.VirtualFile;
import com.intellij.platform.lsp.api.LspServerSupportProvider;
import com.intellij.platform.lsp.api.ProjectWideLspServerDescriptor;
import org.jetbrains.annotations.NotNull;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Provides piilex LSP server support for JetBrains IDEs.
 * Launches `piilex lsp` as a Language Server and connects via stdio.
 */
public class PiilexLspServerSupportProvider implements LspServerSupportProvider {

    private static final Set<String> SUPPORTED_EXTENSIONS = new HashSet<>(Arrays.asList(
        "ts", "tsx", "mts", "js", "jsx", "mjs",
        "py", "go", "java", "cs"
    ));

    @Override
    public void fileOpened(
        @NotNull Project project,
        @NotNull VirtualFile file,
        @NotNull LspServerStarter serverStarter
    ) {
        String ext = file.getExtension();
        if (ext != null && SUPPORTED_EXTENSIONS.contains(ext.toLowerCase())) {
            PiilexSettings settings = PiilexSettings.getInstance();
            if (settings.isEnabled()) {
                serverStarter.ensureServerStarted(new PiilexLspServerDescriptor(project));
            }
        }
    }

    /**
     * LSP server descriptor that launches `piilex lsp`.
     */
    private static class PiilexLspServerDescriptor extends ProjectWideLspServerDescriptor {

        PiilexLspServerDescriptor(@NotNull Project project) {
            super(project, "piilex");
        }

        @NotNull
        @Override
        public GeneralCommandLine createCommandLine() {
            PiilexSettings settings = PiilexSettings.getInstance();
            String binaryPath = settings.getBinaryPath();

            GeneralCommandLine cmd = new GeneralCommandLine(binaryPath, "lsp");
            cmd.setWorkDirectory(getProject().getBasePath());
            return cmd;
        }

        @Override
        public boolean isSupportedFile(@NotNull VirtualFile file) {
            String ext = file.getExtension();
            return ext != null && SUPPORTED_EXTENSIONS.contains(ext.toLowerCase());
        }
    }
}

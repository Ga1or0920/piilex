package dev.piilex.intellij;

import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.components.PersistentStateComponent;
import com.intellij.openapi.components.State;
import com.intellij.openapi.components.Storage;
import com.intellij.util.xmlb.XmlSerializerUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/**
 * Persistent settings for piilex plugin.
 */
@State(
    name = "dev.piilex.intellij.PiilexSettings",
    storages = @Storage("piilex.xml")
)
public class PiilexSettings implements PersistentStateComponent<PiilexSettings> {

    private boolean enabled = true;
    private String binaryPath = "piilex";
    private String severity = "low";

    public static PiilexSettings getInstance() {
        return ApplicationManager.getApplication().getService(PiilexSettings.class);
    }

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    public String getBinaryPath() { return binaryPath; }
    public void setBinaryPath(String path) { this.binaryPath = path; }

    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }

    @Nullable
    @Override
    public PiilexSettings getState() {
        return this;
    }

    @Override
    public void loadState(@NotNull PiilexSettings state) {
        XmlSerializerUtil.copyBean(state, this);
    }
}

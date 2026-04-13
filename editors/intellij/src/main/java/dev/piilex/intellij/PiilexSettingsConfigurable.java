package dev.piilex.intellij;

import com.intellij.openapi.options.Configurable;
import org.jetbrains.annotations.Nls;
import org.jetbrains.annotations.Nullable;

import javax.swing.*;
import java.awt.*;

/**
 * Settings UI for piilex plugin (Settings > Tools > piilex).
 */
public class PiilexSettingsConfigurable implements Configurable {

    private JCheckBox enabledCheckbox;
    private JTextField binaryPathField;
    private JComboBox<String> severityCombo;

    @Nls(capitalization = Nls.Capitalization.Title)
    @Override
    public String getDisplayName() {
        return "piilex";
    }

    @Nullable
    @Override
    public JComponent createComponent() {
        PiilexSettings settings = PiilexSettings.getInstance();

        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 4, 4, 4);
        gbc.anchor = GridBagConstraints.WEST;

        // Enable checkbox
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 2;
        enabledCheckbox = new JCheckBox("Enable piilex PII scanning", settings.isEnabled());
        panel.add(enabledCheckbox, gbc);

        // Binary path
        gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 1;
        panel.add(new JLabel("Binary path:"), gbc);

        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        binaryPathField = new JTextField(settings.getBinaryPath(), 30);
        panel.add(binaryPathField, gbc);

        // Severity
        gbc.gridx = 0; gbc.gridy = 2; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        panel.add(new JLabel("Minimum severity:"), gbc);

        gbc.gridx = 1;
        severityCombo = new JComboBox<>(new String[]{"low", "medium", "high", "critical"});
        severityCombo.setSelectedItem(settings.getSeverity());
        panel.add(severityCombo, gbc);

        // Help text
        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 2;
        JLabel help = new JLabel("<html><br><i>Requires piilex binary in PATH. " +
            "Install: brew install piilex/tap/piilex</i></html>");
        help.setForeground(Color.GRAY);
        panel.add(help, gbc);

        return panel;
    }

    @Override
    public boolean isModified() {
        PiilexSettings settings = PiilexSettings.getInstance();
        return enabledCheckbox.isSelected() != settings.isEnabled()
            || !binaryPathField.getText().equals(settings.getBinaryPath())
            || !severityCombo.getSelectedItem().equals(settings.getSeverity());
    }

    @Override
    public void apply() {
        PiilexSettings settings = PiilexSettings.getInstance();
        settings.setEnabled(enabledCheckbox.isSelected());
        settings.setBinaryPath(binaryPathField.getText());
        settings.setSeverity((String) severityCombo.getSelectedItem());
    }

    @Override
    public void reset() {
        PiilexSettings settings = PiilexSettings.getInstance();
        enabledCheckbox.setSelected(settings.isEnabled());
        binaryPathField.setText(settings.getBinaryPath());
        severityCombo.setSelectedItem(settings.getSeverity());
    }
}

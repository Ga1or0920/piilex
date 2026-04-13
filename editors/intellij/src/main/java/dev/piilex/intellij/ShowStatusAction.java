package dev.piilex.intellij;

import com.intellij.notification.NotificationGroupManager;
import com.intellij.notification.NotificationType;
import com.intellij.openapi.actionSystem.AnAction;
import com.intellij.openapi.actionSystem.AnActionEvent;
import org.jetbrains.annotations.NotNull;

/**
 * Action to show piilex scanner status.
 */
public class ShowStatusAction extends AnAction {

    @Override
    public void actionPerformed(@NotNull AnActionEvent e) {
        PiilexSettings settings = PiilexSettings.getInstance();
        String status = settings.isEnabled() ? "active" : "disabled";
        String message = String.format(
            "piilex PII Scanner: %s\nBinary: %s\nSeverity: %s",
            status, settings.getBinaryPath(), settings.getSeverity()
        );

        NotificationGroupManager.getInstance()
            .getNotificationGroup("piilex")
            .createNotification(message, NotificationType.INFORMATION)
            .notify(e.getProject());
    }
}

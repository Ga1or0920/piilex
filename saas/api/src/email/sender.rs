use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

/// Email configuration from environment variables.
#[derive(Clone)]
pub struct EmailConfig {
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_user: String,
    pub smtp_password: String,
    pub from_address: String,
    pub from_name: String,
    pub enabled: bool,
}

impl EmailConfig {
    pub fn from_env() -> Self {
        let enabled = std::env::var("SMTP_HOST").is_ok();
        Self {
            smtp_host: std::env::var("SMTP_HOST").unwrap_or_default(),
            smtp_port: std::env::var("SMTP_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(587),
            smtp_user: std::env::var("SMTP_USER").unwrap_or_default(),
            smtp_password: std::env::var("SMTP_PASSWORD").unwrap_or_default(),
            from_address: std::env::var("SMTP_FROM")
                .unwrap_or_else(|_| "noreply@piilex.dev".into()),
            from_name: "piilex".to_string(),
            enabled,
        }
    }
}

/// Send an HTML email.
pub async fn send_email(
    config: &EmailConfig,
    to: &str,
    subject: &str,
    html_body: &str,
) -> Result<(), String> {
    if !config.enabled {
        eprintln!(
            "Email not sent (SMTP not configured): to={} subject={}",
            to, subject
        );
        return Ok(());
    }

    let from = format!("{} <{}>", config.from_name, config.from_address);

    let message = Message::builder()
        .from(from.parse().map_err(|e| format!("invalid from: {}", e))?)
        .to(to.parse().map_err(|e| format!("invalid to: {}", e))?)
        .subject(subject)
        .header(ContentType::TEXT_HTML)
        .body(html_body.to_string())
        .map_err(|e| format!("message build error: {}", e))?;

    let creds = Credentials::new(config.smtp_user.clone(), config.smtp_password.clone());

    let mailer = AsyncSmtpTransport::<Tokio1Executor>::relay(&config.smtp_host)
        .map_err(|e| format!("SMTP relay error: {}", e))?
        .port(config.smtp_port)
        .credentials(creds)
        .build();

    mailer
        .send(message)
        .await
        .map_err(|e| format!("SMTP send error: {}", e))?;

    Ok(())
}

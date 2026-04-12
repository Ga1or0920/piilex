use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const STRIPE_API: &str = "https://api.stripe.com/v1";

/// Price IDs (configured in Stripe Dashboard).
pub const PRICE_PRO_MONTHLY: &str = "price_pro_monthly";
pub const PRICE_PRO_YEARLY: &str = "price_pro_yearly";

// ---------------------------------------------------------------------------
// API client
// ---------------------------------------------------------------------------

pub struct StripeClient {
    secret_key: String,
    http: reqwest::Client,
}

impl StripeClient {
    pub fn new(secret_key: &str) -> Self {
        Self {
            secret_key: secret_key.to_string(),
            http: reqwest::Client::new(),
        }
    }

    /// Create a Stripe Customer.
    pub async fn create_customer(
        &self,
        email: &str,
        name: &str,
        team_id: &str,
    ) -> Result<String, String> {
        let resp = self
            .http
            .post(format!("{}/customers", STRIPE_API))
            .basic_auth(&self.secret_key, None::<&str>)
            .form(&[
                ("email", email),
                ("name", name),
                ("metadata[team_id]", team_id),
            ])
            .send()
            .await
            .map_err(|e| e.to_string())?;

        let json: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
        json["id"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| format!("Stripe error: {:?}", json))
    }

    /// Create a Checkout Session for subscription.
    pub async fn create_checkout_session(
        &self,
        customer_id: &str,
        price_id: &str,
        success_url: &str,
        cancel_url: &str,
    ) -> Result<String, String> {
        let resp = self
            .http
            .post(format!("{}/checkout/sessions", STRIPE_API))
            .basic_auth(&self.secret_key, None::<&str>)
            .form(&[
                ("customer", customer_id),
                ("mode", "subscription"),
                ("line_items[0][price]", price_id),
                ("line_items[0][quantity]", "1"),
                ("success_url", success_url),
                ("cancel_url", cancel_url),
            ])
            .send()
            .await
            .map_err(|e| e.to_string())?;

        let json: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
        json["url"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| format!("Stripe error: {:?}", json))
    }

    /// Create a Billing Portal session.
    pub async fn create_portal_session(
        &self,
        customer_id: &str,
        return_url: &str,
    ) -> Result<String, String> {
        let resp = self
            .http
            .post(format!("{}/billing_portal/sessions", STRIPE_API))
            .basic_auth(&self.secret_key, None::<&str>)
            .form(&[("customer", customer_id), ("return_url", return_url)])
            .send()
            .await
            .map_err(|e| e.to_string())?;

        let json: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
        json["url"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| format!("Stripe error: {:?}", json))
    }
}

// ---------------------------------------------------------------------------
// Webhook signature verification
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct StripeEvent {
    pub id: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub data: StripeEventData,
}

#[derive(Debug, Deserialize)]
pub struct StripeEventData {
    pub object: serde_json::Value,
}

/// Verify Stripe webhook signature (Stripe-Signature header).
pub fn verify_webhook_signature(
    payload: &str,
    sig_header: &str,
    webhook_secret: &str,
) -> Result<(), String> {
    // Parse "t=TIMESTAMP,v1=SIGNATURE" from header
    let mut timestamp = "";
    let mut signature = "";

    for part in sig_header.split(',') {
        if let Some(t) = part.strip_prefix("t=") {
            timestamp = t;
        } else if let Some(v) = part.strip_prefix("v1=") {
            signature = v;
        }
    }

    if timestamp.is_empty() || signature.is_empty() {
        return Err("missing timestamp or signature".to_string());
    }

    // Compute expected signature: HMAC-SHA256(secret, "TIMESTAMP.PAYLOAD")
    let signed_payload = format!("{}.{}", timestamp, payload);
    let mut mac =
        HmacSha256::new_from_slice(webhook_secret.as_bytes()).map_err(|e| e.to_string())?;
    mac.update(signed_payload.as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());

    if expected != signature {
        return Err("signature mismatch".to_string());
    }

    // Check timestamp is recent (within 5 minutes)
    if let Ok(ts) = timestamp.parse::<i64>() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        if (now - ts).abs() > 300 {
            return Err("timestamp too old".to_string());
        }
    }

    Ok(())
}

/// Map Stripe subscription status to our plan names.
pub fn status_to_plan(status: &str) -> &'static str {
    match status {
        "active" | "trialing" => "pro",
        _ => "free",
    }
}

// ---------------------------------------------------------------------------
// License JWT generation
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct LicenseClaims {
    sub: String,
    tier: String,
    team_id: String,
    iat: u64,
    exp: u64,
    jti: String,
}

/// Generate a piilex Pro license JWT signed with the RS256 private key.
pub fn generate_license_jwt(
    email: &str,
    team_id: &str,
    private_key_pem: &str,
    valid_days: u64,
) -> Result<String, String> {
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let claims = LicenseClaims {
        sub: email.to_string(),
        tier: "pro".to_string(),
        team_id: team_id.to_string(),
        iat: now,
        exp: now + valid_days * 86400,
        jti: format!("plx-{}-{}", team_id.get(..8).unwrap_or(team_id), now),
    };

    let key =
        EncodingKey::from_rsa_pem(private_key_pem.as_bytes()).map_err(|e| e.to_string())?;

    encode(&Header::new(Algorithm::RS256), &claims, &key).map_err(|e| e.to_string())
}

use sha2::{Digest, Sha256};
use sqlx::SqlitePool;

pub fn hash_key(key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn generate_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

pub fn generate_api_key() -> String {
    format!("plx_{}", uuid::Uuid::new_v4().to_string().replace('-', ""))
}

/// Verify an API key and return (user_id, team_id) if valid.
pub async fn verify_api_key(pool: &SqlitePool, key: &str) -> Option<(String, String)> {
    let key_hash = hash_key(key);
    let row = sqlx::query_as::<_, (String, String)>(
        "SELECT user_id, team_id FROM api_keys WHERE key_hash = ?",
    )
    .bind(&key_hash)
    .fetch_optional(pool)
    .await
    .ok()??;

    // Update last_used
    let _ = sqlx::query("UPDATE api_keys SET last_used = CURRENT_TIMESTAMP WHERE key_hash = ?")
        .bind(&key_hash)
        .execute(pool)
        .await;

    Some(row)
}

use crate::{db, middleware, models::*, AppState};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use std::sync::Arc;

pub async fn list_keys(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<ApiKey>>, StatusCode> {
    let claims = middleware::auth(&headers, &state.jwt_secret)?;

    let keys = sqlx::query_as::<_, ApiKey>(
        "SELECT * FROM api_keys WHERE team_id = ? AND name != '__password__' ORDER BY created_at DESC",
    )
    .bind(&claims.team_id)
    .fetch_all(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(keys))
}

pub async fn create_key(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateKeyRequest>,
) -> Result<(StatusCode, Json<CreateKeyResponse>), StatusCode> {
    let claims = middleware::auth(&headers, &state.jwt_secret)?;

    let key_id = db::generate_id();
    let raw_key = db::generate_api_key();
    let key_hash = db::hash_key(&raw_key);

    sqlx::query("INSERT INTO api_keys (id, user_id, team_id, key_hash, name) VALUES (?, ?, ?, ?, ?)")
        .bind(&key_id)
        .bind(&claims.sub)
        .bind(&claims.team_id)
        .bind(&key_hash)
        .bind(&body.name)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok((
        StatusCode::CREATED,
        Json(CreateKeyResponse {
            id: key_id,
            key: raw_key,
            name: body.name,
        }),
    ))
}

pub async fn delete_key(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let claims = middleware::auth(&headers, &state.jwt_secret)?;

    let result = sqlx::query("DELETE FROM api_keys WHERE id = ? AND team_id = ? AND name != '__password__'")
        .bind(&id)
        .bind(&claims.team_id)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(StatusCode::NO_CONTENT)
}

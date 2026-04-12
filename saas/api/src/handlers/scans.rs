use crate::{db, middleware, models::*, AppState};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Deserialize)]
pub struct ListParams {
    limit: Option<i64>,
    offset: Option<i64>,
}

pub async fn list_scans(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<ListParams>,
) -> Result<Json<Vec<Scan>>, StatusCode> {
    let claims = middleware::auth(&headers, &state.jwt_secret)?;
    let limit = params.limit.unwrap_or(50).min(100);
    let offset = params.offset.unwrap_or(0);

    let scans = sqlx::query_as::<_, Scan>(
        "SELECT * FROM scans WHERE team_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
    )
    .bind(&claims.team_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(scans))
}

pub async fn create_scan(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateScanRequest>,
) -> Result<(StatusCode, Json<Scan>), StatusCode> {
    let claims = middleware::auth(&headers, &state.jwt_secret)?;
    let scan_id = db::generate_id();

    let frameworks_json = body
        .frameworks
        .as_ref()
        .map(|f| serde_json::to_string(f).unwrap_or_default());
    let pii_json = body
        .pii_type_summary
        .as_ref()
        .map(|v| v.to_string());
    let lang_json = body
        .language_summary
        .as_ref()
        .map(|v| v.to_string());

    sqlx::query(
        "INSERT INTO scans (id, team_id, user_id, project_name, files_scanned, findings_count, \
         critical_count, high_count, medium_count, low_count, frameworks, duration_ms, \
         pii_type_summary, language_summary) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&scan_id)
    .bind(&claims.team_id)
    .bind(&claims.sub)
    .bind(&body.project_name)
    .bind(body.files_scanned)
    .bind(body.findings_count)
    .bind(body.critical_count)
    .bind(body.high_count)
    .bind(body.medium_count)
    .bind(body.low_count)
    .bind(&frameworks_json)
    .bind(body.duration_ms)
    .bind(&pii_json)
    .bind(&lang_json)
    .execute(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Insert findings if provided
    if let Some(findings) = &body.findings {
        for f in findings {
            let finding_id = db::generate_id();
            let df_json = f.data_flow.as_ref().map(|v| v.to_string());
            let fm_json = f.framework_mappings.as_ref().map(|v| v.to_string());

            let _ = sqlx::query(
                "INSERT INTO scan_findings (id, scan_id, pii_type, severity, file_path, line, \
                 code_snippet, data_flow, framework_mappings) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&finding_id)
            .bind(&scan_id)
            .bind(&f.pii_type)
            .bind(&f.severity)
            .bind(&f.file_path)
            .bind(f.line)
            .bind(&f.code_snippet)
            .bind(&df_json)
            .bind(&fm_json)
            .execute(&state.db)
            .await;
        }
    }

    let scan = sqlx::query_as::<_, Scan>("SELECT * FROM scans WHERE id = ?")
        .bind(&scan_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok((StatusCode::CREATED, Json(scan)))
}

pub async fn get_scan(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Scan>, StatusCode> {
    let claims = middleware::auth(&headers, &state.jwt_secret)?;

    let scan = sqlx::query_as::<_, Scan>("SELECT * FROM scans WHERE id = ? AND team_id = ?")
        .bind(&id)
        .bind(&claims.team_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(scan))
}

pub async fn get_findings(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Vec<ScanFinding>>, StatusCode> {
    let claims = middleware::auth(&headers, &state.jwt_secret)?;

    // Verify scan belongs to team
    let _ = sqlx::query_scalar::<_, String>(
        "SELECT id FROM scans WHERE id = ? AND team_id = ?",
    )
    .bind(&id)
    .bind(&claims.team_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .ok_or(StatusCode::NOT_FOUND)?;

    let findings = sqlx::query_as::<_, ScanFinding>(
        "SELECT * FROM scan_findings WHERE scan_id = ? ORDER BY severity DESC, line ASC",
    )
    .bind(&id)
    .fetch_all(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(findings))
}

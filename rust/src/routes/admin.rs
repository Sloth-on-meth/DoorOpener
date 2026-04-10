use crate::config::save as save_config;
use crate::logging::{AuditEntry, filter_test_entries, parse_log_file};
use crate::routes::index::{gen_nonce, html_response_with_security_headers};
use crate::state::AppState;
use axum::{
    Json,
    extract::{Multipart, Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde_json::{Value, json};
use tower_sessions::Session;

// ---------------------------------------------------------------------------
// Admin page (GET /admin)
// ---------------------------------------------------------------------------

pub async fn admin_page(
    State(state): State<AppState>,
    session: Session,
) -> impl IntoResponse {
    let cfg = &state.inner.cfg;
    let is_authenticated = session
        .get::<bool>("admin_authenticated")
        .await
        .unwrap_or(None)
        .unwrap_or(false);
    let mutable = state.inner.mutable.read().await;

    let nonce = gen_nonce();
    let mut ctx = tera::Context::new();
    ctx.insert("csp_nonce", &nonce);
    ctx.insert("oidc_enabled", &cfg.oidc_enabled);
    ctx.insert("app_version", &cfg.app_version);
    ctx.insert("is_authenticated", &is_authenticated);
    ctx.insert("test_mode", &mutable.test_mode);

    match state.inner.tera.render("admin.html", &ctx) {
        Ok(html) => html_response_with_security_headers(html, &nonce),
        Err(e) => {
            tracing::error!("Admin template error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Template error").into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Admin auth (POST /admin/auth)
// ---------------------------------------------------------------------------

pub async fn admin_auth(
    State(state): State<AppState>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    session: Session,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let primary_ip = addr.ip().to_string();
    let cfg = &state.inner.cfg;

    let password = body
        .get("password")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let remember_me = body
        .get("remember_me")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let session_id: String = get_or_create_session_id(&session).await;
    let identifier = primary_ip.clone();

    // Check if blocked
    {
        let rl = state.inner.rate_limit.read().await;
        if let Some(_until) = rl.is_session_blocked(&session_id) {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({ "status": "error", "message": "Too many failed attempts. Please try later." })),
            )
                .into_response();
        }
        if let Some(_until) = rl.is_ip_blocked(&identifier) {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({ "status": "error", "message": "Too many failed attempts. Please try later." })),
            )
                .into_response();
        }
    }

    if constant_time_eq(&password, &cfg.admin_password) {
        {
            let mut rl = state.inner.rate_limit.write().await;
            rl.record_success(&session_id, &identifier);
        }
        let now = chrono::Utc::now().to_rfc3339();
        let csrf = gen_random_hex(32);
        let _ = session.insert("admin_authenticated", true).await;
        let _ = session.insert("admin_login_time", now).await;
        let _ = session.insert("admin_csrf_token", csrf).await;
        if remember_me {
            // tower-sessions handles expiry via cookie max-age configured at startup
        }

        let entry = AuditEntry::new(&primary_ip, &session_id, "ADMIN", "ADMIN_SUCCESS", "Admin login");
        state.inner.audit_logger.log(&entry);

        Json(json!({ "status": "success" })).into_response()
    } else {
        let outcome = {
            let mut rl = state.inner.rate_limit.write().await;
            rl.record_failure(
                &session_id,
                &identifier,
                cfg.session_max_attempts,
                cfg.session_max_attempts,
                cfg.block_time_minutes as i64,
            )
        };

        let details = match &outcome {
            crate::rate_limit::FailureOutcome::SessionBlocked { minutes, .. } => {
                format!("Invalid admin password. Session blocked for {} minutes", minutes)
            }
            crate::rate_limit::FailureOutcome::IpBlocked { minutes, .. } => {
                format!("Invalid admin password. IP blocked for {} minutes", minutes)
            }
            crate::rate_limit::FailureOutcome::Counted => "Invalid admin password".to_string(),
        };

        let entry = AuditEntry::new(&primary_ip, &session_id, "ADMIN", "ADMIN_FAILURE", &details);
        state.inner.audit_logger.log(&entry);

        (
            StatusCode::FORBIDDEN,
            Json(json!({ "status": "error", "message": "Invalid admin password" })),
        )
            .into_response()
    }
}

// ---------------------------------------------------------------------------
// GET /admin/check-auth
// ---------------------------------------------------------------------------

pub async fn admin_check_auth(session: Session) -> impl IntoResponse {
    let authenticated = session
        .get::<bool>("admin_authenticated")
        .await
        .unwrap_or(None)
        .unwrap_or(false);
    if authenticated {
        let login_time = session
            .get::<String>("admin_login_time")
            .await
            .unwrap_or(None);
        let csrf = session
            .get::<String>("admin_csrf_token")
            .await
            .unwrap_or(None);
        Json(json!({
            "authenticated": true,
            "login_time": login_time,
            "csrf_token": csrf,
        }))
        .into_response()
    } else {
        Json(json!({ "authenticated": false })).into_response()
    }
}

// ---------------------------------------------------------------------------
// POST /admin/logout
// ---------------------------------------------------------------------------

pub async fn admin_logout(
    State(_state): State<AppState>,
    session: Session,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !check_csrf(&session, &headers).await {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Invalid CSRF token" }))).into_response();
    }
    let _ = session.remove::<bool>("admin_authenticated").await;
    let _ = session.remove::<String>("admin_login_time").await;
    let _ = session.remove::<String>("admin_csrf_token").await;
    Json(json!({ "status": "success", "message": "Logged out successfully" })).into_response()
}

// ---------------------------------------------------------------------------
// Notice
// ---------------------------------------------------------------------------

pub async fn admin_notice_get(State(state): State<AppState>) -> impl IntoResponse {
    let mutable = state.inner.mutable.read().await;
    Json(json!({ "notice": mutable.notice }))
}

pub async fn admin_notice_set(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    if !require_admin(&session).await {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "Unauthorized" }))).into_response();
    }
    if !check_csrf(&session, &headers).await {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Invalid CSRF token" }))).into_response();
    }

    let notice = body
        .get("notice")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();

    {
        let mut mutable = state.inner.mutable.write().await;
        mutable.notice = notice.clone();
        if let Err(e) = save_config(&state.inner.cfg.config_path, &mutable, &state.inner.cfg) {
            tracing::error!("Failed to save config: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "Could not save config" }))).into_response();
        }
    }

    Json(json!({ "status": "ok", "notice": notice })).into_response()
}

// ---------------------------------------------------------------------------
// Test mode
// ---------------------------------------------------------------------------

pub async fn admin_test_mode_get(
    State(state): State<AppState>,
    session: Session,
) -> impl IntoResponse {
    if !require_admin(&session).await {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "Unauthorized" }))).into_response();
    }
    let mutable = state.inner.mutable.read().await;
    Json(json!({ "test_mode": mutable.test_mode })).into_response()
}

pub async fn admin_test_mode_set(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    if !require_admin(&session).await {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "Unauthorized" }))).into_response();
    }
    if !check_csrf(&session, &headers).await {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Invalid CSRF token" }))).into_response();
    }

    let enabled = match body.get("enabled").and_then(|v| v.as_bool()) {
        Some(b) => b,
        None => {
            return (StatusCode::BAD_REQUEST, Json(json!({ "error": "Missing 'enabled' field" }))).into_response()
        }
    };

    {
        let mut mutable = state.inner.mutable.write().await;
        mutable.test_mode = enabled;
        if let Err(e) = save_config(&state.inner.cfg.config_path, &mutable, &state.inner.cfg) {
            tracing::error!("Failed to save config: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "Could not save config" }))).into_response();
        }
    }

    if enabled {
        tracing::warn!("TEST MODE ENABLED via admin panel — the door will NOT open.");
    } else {
        tracing::info!("Test mode disabled via admin panel.");
    }

    Json(json!({ "status": "ok", "test_mode": enabled })).into_response()
}

// ---------------------------------------------------------------------------
// Background image
// ---------------------------------------------------------------------------

pub async fn admin_background_get(
    State(state): State<AppState>,
    session: Session,
) -> impl IntoResponse {
    if !require_admin(&session).await {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "Unauthorized" }))).into_response();
    }
    let bg_path = state.inner.cfg.static_dir.join("background.jpg");
    let default_path = state.inner.cfg.static_dir.join("background_default.jpg");
    let has_custom = default_path.exists() && !backgrounds_identical(&bg_path, &default_path);
    Json(json!({ "custom": has_custom })).into_response()
}

pub async fn admin_background_upload(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> impl IntoResponse {
    if !require_admin(&session).await {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "Unauthorized" }))).into_response();
    }
    if !check_csrf(&session, &headers).await {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Invalid CSRF token" }))).into_response();
    }

    const MAX_SIZE: usize = 10 * 1024 * 1024;
    let allowed_types = ["jpg", "jpeg", "png", "gif", "webp"];

    let mut data: Option<Vec<u8>> = None;
    while let Ok(Some(field)) = multipart.next_field().await {
        if field.name() == Some("file") {
            let bytes = match field.bytes().await {
                Ok(b) => b,
                Err(e) => {
                    return (StatusCode::BAD_REQUEST, Json(json!({ "error": format!("Upload error: {}", e) }))).into_response()
                }
            };
            if bytes.len() > MAX_SIZE {
                return (StatusCode::PAYLOAD_TOO_LARGE, Json(json!({ "error": "File too large (max 10 MB)" }))).into_response();
            }
            data = Some(bytes.to_vec());
            break;
        }
    }

    let data = match data {
        Some(d) => d,
        None => return (StatusCode::BAD_REQUEST, Json(json!({ "error": "No file provided" }))).into_response(),
    };

    // Validate magic bytes
    let kind = infer::get(&data);
    let ext = kind.map(|k| k.extension()).unwrap_or("");
    if !allowed_types.contains(&ext) {
        return (StatusCode::UNSUPPORTED_MEDIA_TYPE, Json(json!({ "error": "Invalid image type. Allowed: JPEG, PNG, GIF, WebP" }))).into_response();
    }

    let static_dir = &state.inner.cfg.static_dir;
    let bg_path = static_dir.join("background.jpg");
    let default_path = static_dir.join("background_default.jpg");

    // Preserve default on first run
    if bg_path.exists() && !default_path.exists() {
        let _ = std::fs::copy(&bg_path, &default_path);
    }

    // Atomic write
    let tmp_path = static_dir.join("background.tmp");
    if let Err(e) = std::fs::write(&tmp_path, &data) {
        tracing::error!("Failed to write background tmp: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "Could not save background" }))).into_response();
    }
    if let Err(e) = std::fs::rename(&tmp_path, &bg_path) {
        tracing::error!("Failed to rename background: {}", e);
        let _ = std::fs::remove_file(&tmp_path);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "Could not save background" }))).into_response();
    }

    tracing::info!("Background image updated by admin ({} bytes, ext={})", data.len(), ext);
    Json(json!({ "status": "ok" })).into_response()
}

pub async fn admin_background_reset(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !require_admin(&session).await {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "Unauthorized" }))).into_response();
    }
    if !check_csrf(&session, &headers).await {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Invalid CSRF token" }))).into_response();
    }

    let bg_path = state.inner.cfg.static_dir.join("background.jpg");
    let default_path = state.inner.cfg.static_dir.join("background_default.jpg");

    if !default_path.exists() {
        return (StatusCode::NOT_FOUND, Json(json!({ "error": "No default background to restore" }))).into_response();
    }

    if let Err(e) = std::fs::copy(&default_path, &bg_path) {
        tracing::error!("Failed to restore default background: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "Could not restore default" }))).into_response();
    }

    tracing::info!("Background image reset to default by admin");
    Json(json!({ "status": "ok" })).into_response()
}

// ---------------------------------------------------------------------------
// Logs
// ---------------------------------------------------------------------------

pub async fn admin_logs(
    State(state): State<AppState>,
    session: Session,
) -> impl IntoResponse {
    if !require_admin(&session).await {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "Authentication required" }))).into_response();
    }

    let log_path = state.inner.cfg.log_dir.join("log.txt");
    let logs = parse_log_file(&log_path);
    Json(json!({ "logs": logs })).into_response()
}

pub async fn admin_logs_clear(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    if !require_admin(&session).await {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "Authentication required" }))).into_response();
    }
    if !check_csrf(&session, &headers).await {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Invalid CSRF token" }))).into_response();
    }

    let mode = body
        .get("mode")
        .and_then(|v| v.as_str())
        .unwrap_or("all")
        .to_lowercase();
    let log_path = state.inner.cfg.log_dir.join("log.txt");

    match mode.as_str() {
        "all" => {
            if let Err(e) = std::fs::write(&log_path, b"") {
                tracing::error!("Failed to clear log: {}", e);
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "Failed to clear logs" }))).into_response();
            }
            Json(json!({ "status": "ok", "mode": "all", "removed": 0, "kept": 0 })).into_response()
        }
        "test_only" => {
            match filter_test_entries(&log_path) {
                Ok((removed, kept)) => {
                    Json(json!({ "status": "ok", "mode": "test_only", "removed": removed, "kept": kept })).into_response()
                }
                Err(e) => {
                    tracing::error!("Failed to filter test log entries: {}", e);
                    (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "Failed to filter logs" }))).into_response()
                }
            }
        }
        _ => (StatusCode::BAD_REQUEST, Json(json!({ "error": "Invalid mode" }))).into_response(),
    }
}

// ---------------------------------------------------------------------------
// User management
// ---------------------------------------------------------------------------

pub async fn admin_users_list(
    State(state): State<AppState>,
    session: Session,
) -> impl IntoResponse {
    if !require_admin(&session).await {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "Authentication required" }))).into_response();
    }

    let mutable = state.inner.mutable.read().await;
    let mut store_users = {
        let mut users = state.inner.users.write().await;
        users.list_users(false)
    };

    let store_names: std::collections::HashSet<String> = store_users
        .iter()
        .filter_map(|u| u.get("username").and_then(|v| v.as_str()).map(str::to_string))
        .collect();

    // Add source/can_edit flags to store users
    for u in &mut store_users {
        u["source"] = json!("store");
        u["can_edit"] = json!(true);
    }

    // Config-only users (not yet migrated to JSON store)
    let mut config_only: Vec<Value> = mutable
        .user_pins
        .keys()
        .filter(|name| !store_names.contains(*name))
        .map(|name| {
            json!({
                "username": name,
                "active": true,
                "created_at": null,
                "updated_at": null,
                "last_used_at": null,
                "source": "config",
                "can_edit": false,
            })
        })
        .collect();

    config_only.sort_by_key(|u| u["username"].as_str().unwrap_or("").to_string());
    let all_users: Vec<Value> = store_users.into_iter().chain(config_only).collect();

    Json(json!({ "users": all_users })).into_response()
}

pub async fn admin_users_create(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    if !require_admin(&session).await {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "Authentication required" }))).into_response();
    }
    if !check_csrf(&session, &headers).await {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Invalid CSRF token" }))).into_response();
    }

    let username = match body.get("username").and_then(|v| v.as_str()) {
        Some(u) => u.to_string(),
        None => return (StatusCode::BAD_REQUEST, Json(json!({ "error": "username and pin are required" }))).into_response(),
    };
    let pin = match body.get("pin").and_then(|v| v.as_str()) {
        Some(p) => p.to_string(),
        None => return (StatusCode::BAD_REQUEST, Json(json!({ "error": "username and pin are required" }))).into_response(),
    };
    let active = body.get("active").and_then(|v| v.as_bool()).unwrap_or(true);

    {
        let mutable = state.inner.mutable.read().await;
        if mutable.user_pins.contains_key(&username) {
            return (StatusCode::CONFLICT, Json(json!({ "error": "User exists in config and cannot be edited via UI" }))).into_response();
        }
    }

    let result = {
        let mut users = state.inner.users.write().await;
        users.create_user(&username, &pin, active)
    };

    match result {
        Ok(_) => {
            let ip = addr.ip().to_string();
            let entry = AuditEntry::new(&ip, "admin", "ADMIN", "ADMIN_USER_CREATE", &format!("username={}", username));
            state.inner.audit_logger.log(&entry);
            (StatusCode::CREATED, Json(json!({ "status": "created" }))).into_response()
        }
        Err(e) if e.to_string().contains("already exists") => {
            (StatusCode::CONFLICT, Json(json!({ "error": "User already exists" }))).into_response()
        }
        Err(e) => {
            tracing::warn!("Error creating user: {}", e);
            (StatusCode::BAD_REQUEST, Json(json!({ "error": "Invalid input" }))).into_response()
        }
    }
}

pub async fn admin_users_update(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    Path(username): Path<String>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    if !require_admin(&session).await {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "Authentication required" }))).into_response();
    }
    if !check_csrf(&session, &headers).await {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Invalid CSRF token" }))).into_response();
    }
    {
        let mutable = state.inner.mutable.read().await;
        if mutable.user_pins.contains_key(&username) {
            return (StatusCode::CONFLICT, Json(json!({ "error": "Config-defined users cannot be edited via UI" }))).into_response();
        }
    }

    let pin = body.get("pin").and_then(|v| v.as_str());
    let active = body.get("active").and_then(|v| v.as_bool());

    let result = {
        let mut users = state.inner.users.write().await;
        users.update_user(&username, pin, active)
    };

    match result {
        Ok(_) => {
            let ip = addr.ip().to_string();
            let entry = AuditEntry::new(&ip, "admin", "ADMIN", "ADMIN_USER_UPDATE", &format!("username={}", username));
            state.inner.audit_logger.log(&entry);
            Json(json!({ "status": "updated" })).into_response()
        }
        Err(e) if e.to_string().contains("not found") => {
            (StatusCode::NOT_FOUND, Json(json!({ "error": "User not found" }))).into_response()
        }
        Err(e) => {
            tracing::warn!("Error updating user {}: {}", username, e);
            (StatusCode::BAD_REQUEST, Json(json!({ "error": "Invalid input" }))).into_response()
        }
    }
}

pub async fn admin_users_delete(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    Path(username): Path<String>,
) -> impl IntoResponse {
    if !require_admin(&session).await {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "Authentication required" }))).into_response();
    }
    if !check_csrf(&session, &headers).await {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Invalid CSRF token" }))).into_response();
    }
    {
        let mutable = state.inner.mutable.read().await;
        if mutable.user_pins.contains_key(&username) {
            return (StatusCode::CONFLICT, Json(json!({ "error": "Config-defined users cannot be deleted via UI" }))).into_response();
        }
    }

    let result = {
        let mut users = state.inner.users.write().await;
        users.delete_user(&username)
    };

    match result {
        Ok(_) => {
            let ip = addr.ip().to_string();
            let entry = AuditEntry::new(&ip, "admin", "ADMIN", "ADMIN_USER_DELETE", &format!("username={}", username));
            state.inner.audit_logger.log(&entry);
            Json(json!({ "status": "deleted" })).into_response()
        }
        Err(_) => (StatusCode::NOT_FOUND, Json(json!({ "error": "User not found" }))).into_response(),
    }
}

pub async fn admin_users_migrate(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    Path(username): Path<String>,
    body: Option<Json<Value>>,
) -> impl IntoResponse {
    if !require_admin(&session).await {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "Authentication required" }))).into_response();
    }
    if !check_csrf(&session, &headers).await {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Invalid CSRF token" }))).into_response();
    }

    let existing_pin = {
        let mutable = state.inner.mutable.read().await;
        mutable.user_pins.get(&username).cloned()
    };

    let existing_pin = match existing_pin {
        Some(p) => p,
        None => return (StatusCode::NOT_FOUND, Json(json!({ "error": "User not found in config" }))).into_response(),
    };

    let pin_to_use = if let Some(Json(b)) = &body {
        if let Some(new_pin) = b.get("pin").and_then(|v| v.as_str()) {
            if !new_pin.chars().all(|c| c.is_ascii_digit()) || new_pin.len() < 4 || new_pin.len() > 8 {
                return (StatusCode::BAD_REQUEST, Json(json!({ "error": "PIN must be 4-8 digits" }))).into_response();
            }
            new_pin.to_string()
        } else {
            existing_pin.clone()
        }
    } else {
        existing_pin.clone()
    };

    let result = {
        let mut users = state.inner.users.write().await;
        users.create_user(&username, &pin_to_use, true)
    };

    if let Err(e) = result {
        tracing::error!("Error migrating user {}: {}", username, e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "Failed to migrate user" }))).into_response();
    }

    // Remove from config.ini
    {
        let mut mutable = state.inner.mutable.write().await;
        mutable.user_pins.remove(&username);
        let _ = save_config(&state.inner.cfg.config_path, &mutable, &state.inner.cfg);
    }

    let ip = addr.ip().to_string();
    let entry = AuditEntry::new(&ip, "admin", "ADMIN", "ADMIN_USER_MIGRATE", &format!("username={}", username));
    state.inner.audit_logger.log(&entry);

    Json(json!({ "status": "migrated" })).into_response()
}

pub async fn admin_users_migrate_all(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
) -> impl IntoResponse {
    if !require_admin(&session).await {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "Authentication required" }))).into_response();
    }
    if !check_csrf(&session, &headers).await {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Invalid CSRF token" }))).into_response();
    }

    let candidates: Vec<(String, String)> = {
        let mutable = state.inner.mutable.read().await;
        mutable.user_pins.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    };

    if candidates.is_empty() {
        return Json(json!({ "migrated": 0, "failed": [] })).into_response();
    }

    let mut migrated = 0usize;
    let mut failed: Vec<Value> = vec![];
    let ip = addr.ip().to_string();

    for (username, pin) in &candidates {
        // Validate format
        if !pin.chars().all(|c| c.is_ascii_digit()) || pin.len() < 4 || pin.len() > 8 {
            failed.push(json!({ "username": username, "error": "invalid_format" }));
            continue;
        }

        // Skip if already in JSON store
        let exists = {
            let mut users = state.inner.users.write().await;
            users.user_exists(username)
        };
        if exists {
            continue;
        }

        let result = {
            let mut users = state.inner.users.write().await;
            users.create_user(username, pin, true)
        };

        match result {
            Ok(_) => {
                {
                    let mut mutable = state.inner.mutable.write().await;
                    mutable.user_pins.remove(username);
                    let _ = save_config(&state.inner.cfg.config_path, &mutable, &state.inner.cfg);
                }
                let entry = AuditEntry::new(&ip, "admin", "ADMIN", "ADMIN_USER_MIGRATE", &format!("username={}", username));
                state.inner.audit_logger.log(&entry);
                migrated += 1;
            }
            Err(e) => {
                tracing::error!("Failed to migrate user {}: {}", username, e);
                failed.push(json!({ "username": username, "error": "store_write_failed", "detail": "internal_error" }));
            }
        }
    }

    let status = if failed.is_empty() { StatusCode::OK } else { StatusCode::MULTI_STATUS };
    (status, Json(json!({ "migrated": migrated, "failed": failed }))).into_response()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn require_admin(session: &Session) -> bool {
    session
        .get::<bool>("admin_authenticated")
        .await
        .unwrap_or(None)
        .unwrap_or(false)
}

async fn check_csrf(session: &Session, headers: &HeaderMap) -> bool {
    let token = headers
        .get("X-CSRF-Token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let stored = session
        .get::<String>("admin_csrf_token")
        .await
        .unwrap_or(None)
        .unwrap_or_default();
    if token.is_empty() || stored.is_empty() {
        return false;
    }
    constant_time_eq(token, &stored)
}

async fn get_or_create_session_id(session: &Session) -> String {
    if let Ok(Some(id)) = session.get::<String>("_session_id").await {
        return id;
    }
    let id = gen_random_hex(16);
    let _ = session.insert("_session_id", id.clone()).await;
    id
}

fn gen_random_hex(n_bytes: usize) -> String {
    use rand::RngCore;
    let mut bytes = vec![0u8; n_bytes];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn backgrounds_identical(a: &std::path::Path, b: &std::path::Path) -> bool {
    match (std::fs::read(a), std::fs::read(b)) {
        (Ok(av), Ok(bv)) => av == bv,
        _ => false,
    }
}

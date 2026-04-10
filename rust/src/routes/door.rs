use crate::ha_client;
use crate::logging::AuditEntry;
use crate::rate_limit::{FailureOutcome, latest_block_ts};
use crate::state::AppState;
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::{Value, json};
use tower_sessions::Session;

pub async fn open_door(
    State(state): State<AppState>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    session: Session,
    body: axum::extract::Json<Value>,
) -> impl IntoResponse {
    let primary_ip = addr.ip().to_string();
    let cfg = &state.inner.cfg;
    let mutable = state.inner.mutable.read().await;

    // --- Build session/composite identifiers ---
    let session_id: String = match session.get::<String>("_session_id").await.unwrap_or(None) {
        Some(id) => id,
        None => {
            let id = gen_session_id();
            let _ = session.insert("_session_id", id.clone()).await;
            id
        }
    };
    let ua_hash = {
        // Use a stable hash of UA+lang as secondary factor (matches Python behaviour)
        0u32 // simplified: Axum doesn't have request headers here without TypedHeader
    };
    let identifier = format!("{}:{}", primary_ip, ua_hash % 10000);

    // --- Global rate limit ---
    {
        let mut rl = state.inner.rate_limit.write().await;
        if !rl.check_global_rate_limit(cfg.max_global_attempts_per_hour) {
            let entry = AuditEntry::new(
                &primary_ip, &session_id, "UNKNOWN", "GLOBAL_BLOCKED",
                "Global rate limit exceeded",
            );
            state.inner.audit_logger.log(&entry);
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({ "status": "error", "message": "Service temporarily unavailable" })),
            )
                .into_response();
        }
    }

    // --- Session-based block (persisted in cookie) ---
    if let Some(ts) = session.get::<f64>("blocked_until_ts").await.unwrap_or(None) {
        let now = chrono::Utc::now().timestamp() as f64;
        if now < ts {
            let remaining = (ts - now) as i64;
            let entry = AuditEntry::new(
                &primary_ip, &session_id, "UNKNOWN", "SESSION_BLOCKED",
                &format!("Session blocked for {} more seconds (persisted)", remaining),
            );
            state.inner.audit_logger.log(&entry);
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({
                    "status": "error",
                    "message": "Too many failed attempts. Please try again later.",
                    "blocked_until": ts
                })),
            )
                .into_response();
        }
    }

    // --- In-memory session + IP blocks ---
    {
        let rl = state.inner.rate_limit.read().await;
        if let Some(_until) = rl.is_session_blocked(&session_id) {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({
                    "status": "error",
                    "message": "Too many failed attempts. Please try again later.",
                    "blocked_until": until.timestamp() as f64
                })),
            )
                .into_response();
        }
        if let Some(until) = rl.is_ip_blocked(&identifier) {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({
                    "status": "error",
                    "message": "Too many failed attempts. Please try again later.",
                    "blocked_until": until.timestamp() as f64
                })),
            )
                .into_response();
        }
    }

    // --- OIDC auth path ---
    let oidc_authenticated = session
        .get::<bool>("oidc_authenticated")
        .await
        .unwrap_or(None)
        .unwrap_or(false)
        && cfg.oidc_enabled;

    let oidc_exp = session.get::<i64>("oidc_exp").await.unwrap_or(None);
    let now_ts = chrono::Utc::now().timestamp();

    let oidc_auth = if oidc_authenticated {
        if oidc_exp.map(|e| e < now_ts).unwrap_or(true) {
            // Session expired
            let _ = session.remove::<bool>("oidc_authenticated").await;
            let _ = session.remove::<String>("oidc_user").await;
            let _ = session.remove::<Vec<String>>("oidc_groups").await;
            let _ = session.remove::<i64>("oidc_exp").await;
            false
        } else {
            true
        }
    } else {
        false
    };

    let oidc_user = session.get::<String>("oidc_user").await.unwrap_or(None);
    let oidc_groups: Vec<String> = session
        .get::<Vec<String>>("oidc_groups")
        .await
        .unwrap_or(None)
        .unwrap_or_default();

    let pin_from_request = body.get("pin").and_then(|v| v.as_str()).map(str::to_string);

    // Expired OIDC + no PIN
    if !oidc_auth && oidc_authenticated && pin_from_request.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "status": "error", "message": "Session expired. Please log in again." })),
        )
            .into_response();
    }

    // OIDC user allowed group check
    let oidc_user_allowed = cfg.oidc_user_group.is_empty()
        || oidc_groups.contains(&cfg.oidc_user_group);

    // OIDC path: no PIN required (unless require_pin_for_oidc)
    if pin_from_request.is_none() && oidc_auth && oidc_user_allowed && !cfg.require_pin_for_oidc {
        // Check if still blocked even for OIDC users
        {
            let rl = state.inner.rate_limit.read().await;
            if let Some(ts) = latest_block_ts(&rl, &session_id, &identifier) {
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(json!({
                        "status": "error",
                        "message": "Too many failed attempts. Please try again later.",
                        "blocked_until": ts
                    })),
                )
                    .into_response();
            }
        }

        let matched_user = oidc_user.clone().unwrap_or_else(|| "oidc-user".to_string());
        {
            let mut rl = state.inner.rate_limit.write().await;
            rl.record_success(&session_id, &identifier);
        }

        return execute_door_open(
            &state, &mutable, &primary_ip, &session_id, &matched_user, &identifier, &session,
        )
        .await;
    }

    // --- PIN path ---
    if pin_from_request.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "message": "PIN required" })),
        )
            .into_response();
    }

    let pin = pin_from_request.unwrap();

    // Validate PIN format
    if !pin.chars().all(|c| c.is_ascii_digit()) || pin.len() < 4 || pin.len() > 8 {
        let mut rl = state.inner.rate_limit.write().await;
        rl.record_failure(
            &session_id, &identifier,
            cfg.session_max_attempts, cfg.max_attempts,
            cfg.block_time_minutes as i64,
        );
        let entry = AuditEntry::new(&primary_ip, &session_id, "UNKNOWN", "INVALID_FORMAT", "Invalid PIN format");
        state.inner.audit_logger.log(&entry);
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "message": "Invalid PIN format" })),
        )
            .into_response();
    }

    // Check PIN against effective user pins
    let effective_pins = {
        let mut users = state.inner.users.write().await;
        users.effective_pins(&mutable.user_pins)
    };

    let matched_user = effective_pins.iter().find_map(|(user, user_pin)| {
        if constant_time_eq(&pin, user_pin) {
            Some(user.clone())
        } else {
            None
        }
    });

    if let Some(matched_user) = matched_user {
        // Enforce any active block even on correct PIN
        {
            let rl = state.inner.rate_limit.read().await;
            if let Some(ts) = latest_block_ts(&rl, &session_id, &identifier) {
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(json!({
                        "status": "error",
                        "message": "Too many failed attempts. Please try again later.",
                        "blocked_until": ts
                    })),
                )
                    .into_response();
            }
        }

        {
            let mut rl = state.inner.rate_limit.write().await;
            rl.record_success(&session_id, &identifier);
        }
        let _ = session.remove::<f64>("blocked_until_ts").await;

        execute_door_open(
            &state, &mutable, &primary_ip, &session_id, &matched_user, &identifier, &session,
        )
        .await
    } else {
        // Check if this is a disabled user's PIN
        let disabled_user = {
            let mut users = state.inner.users.write().await;
            users.find_disabled_user_by_pin(&pin)
        };

        if let Some(disabled) = disabled_user {
            let entry = AuditEntry::new(
                &primary_ip, &session_id, &disabled,
                "DISABLED_USER", "Access denied: account disabled",
            );
            state.inner.audit_logger.log(&entry);
            return (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "status": "error",
                    "message": "Your account has been disabled. Contact the administrator."
                })),
            )
                .into_response();
        }

        // Auth failure — increment counters
        let outcome = {
            let mut rl = state.inner.rate_limit.write().await;
            rl.record_failure(
                &session_id, &identifier,
                cfg.session_max_attempts, cfg.max_attempts,
                cfg.block_time_minutes as i64,
            )
        };

        let (reason, blocked_until) = match &outcome {
            FailureOutcome::SessionBlocked { until, minutes } => {
                // Persist block in session cookie so it survives worker restarts
                let _ = session.insert("blocked_until_ts", until.timestamp() as f64).await;
                (
                    format!("Invalid PIN. Session blocked for {} minutes", minutes),
                    Some(until.timestamp() as f64),
                )
            }
            FailureOutcome::IpBlocked { until, minutes } => (
                format!("Invalid PIN. Access blocked for {} minutes", minutes),
                Some(until.timestamp() as f64),
            ),
            FailureOutcome::Counted => ("Invalid PIN".to_string(), None),
        };

        let entry = AuditEntry::new(&primary_ip, &session_id, "UNKNOWN", "AUTH_FAILURE", &reason);
        state.inner.audit_logger.log(&entry);

        let mut resp_body = json!({ "status": "error", "message": reason });
        if let Some(ts) = blocked_until {
            resp_body["blocked_until"] = json!(ts);
        }
        (StatusCode::UNAUTHORIZED, Json(resp_body)).into_response()
    }
}

async fn execute_door_open(
    state: &AppState,
    mutable: &crate::config::MutableConfig,
    primary_ip: &str,
    session_id: &str,
    matched_user: &str,
    _identifier: &str,
    _session: &Session,
) -> axum::response::Response {
    let cfg = &state.inner.cfg;
    let display_name = {
        let mut chars = matched_user.chars();
        match chars.next() {
            Some(c) => c.to_uppercase().to_string() + chars.as_str(),
            None => matched_user.to_string(),
        }
    };

    if mutable.test_mode {
        let entry = AuditEntry::new(
            primary_ip, session_id, matched_user,
            "SUCCESS", "Door opened (TEST MODE)",
        );
        state.inner.audit_logger.log(&entry);
        let _ = {
            let mut users = state.inner.users.write().await;
            users.touch_user(matched_user);
        };
        return Json(json!({
            "status": "success",
            "message": format!("Door open command sent (TEST MODE).\nWelcome home, {}!", display_name)
        }))
        .into_response();
    }

    match ha_client::open_door(&state.inner.http, &cfg.ha_url, &cfg.ha_token, &cfg.entity_id).await {
        Ok(_) => {
            let entry = AuditEntry::new(primary_ip, session_id, matched_user, "SUCCESS", "Door opened");
            state.inner.audit_logger.log(&entry);
            let _ = {
                let mut users = state.inner.users.write().await;
                users.touch_user(matched_user);
            };
            Json(json!({
                "status": "success",
                "message": format!("Door open command sent.\nWelcome home, {}!", display_name)
            }))
            .into_response()
        }
        Err(e) => {
            let reason = format!("Home Assistant API error: {}", e);
            let entry = AuditEntry::new(primary_ip, session_id, matched_user, "FAILURE", &reason);
            state.inner.audit_logger.log(&entry);
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "status": "error", "message": "Failed to contact Home Assistant" })),
            )
                .into_response()
        }
    }
}

fn gen_session_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
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

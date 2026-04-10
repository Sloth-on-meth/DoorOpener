use crate::ha_client;
use crate::state::AppState;
use axum::{
    Json,
    body::Body,
    extract::State,
    http::{HeaderValue, Response, StatusCode, header},
    response::{Html, IntoResponse},
};
use serde_json::{Value, json};
use tower_sessions::Session;

pub async fn index(State(state): State<AppState>, _session: Session) -> impl IntoResponse {
    let cfg = &state.inner.cfg;
    let mutable = state.inner.mutable.read().await;

    let nonce = gen_nonce();
    let mut ctx = tera::Context::new();
    ctx.insert("csp_nonce", &nonce);
    ctx.insert("oidc_enabled", &cfg.oidc_enabled);
    ctx.insert("require_pin_for_oidc", &cfg.require_pin_for_oidc);
    ctx.insert("easter_egg_enabled", &cfg.easter_egg_enabled);
    ctx.insert("app_version", &cfg.app_version);
    ctx.insert("page_title", &cfg.page_title);
    ctx.insert("notice", &mutable.notice);
    ctx.insert("test_mode", &mutable.test_mode);
    ctx.insert("pushbullet_enabled", &cfg.pushbullet_token.is_some());

    match state.inner.tera.render("index.html", &ctx) {
        Ok(html) => html_response_with_security_headers(html, &nonce),
        Err(e) => {
            tracing::error!("Template error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Template error").into_response()
        }
    }
}

pub async fn health() -> impl IntoResponse {
    Json(json!({ "status": "ok" }))
}

pub async fn battery(State(state): State<AppState>) -> impl IntoResponse {
    let cfg = &state.inner.cfg;
    match ha_client::get_battery_level(
        &state.inner.http,
        &cfg.ha_url,
        &cfg.ha_token,
        &cfg.battery_entity,
    )
    .await
    {
        Some(level) => Json(json!({ "level": level })).into_response(),
        None => Json(json!({ "level": Value::Null })).into_response(),
    }
}

pub async fn service_worker(State(state): State<AppState>) -> impl IntoResponse {
    let path = state.inner.cfg.static_dir.join("service-worker.js");
    serve_file_with_mime(&path, "application/javascript").await
}

pub async fn manifest_file(State(state): State<AppState>) -> impl IntoResponse {
    let path = state.inner.cfg.static_dir.join("manifest.webmanifest");
    serve_file_with_mime(&path, "application/manifest+json").await
}

async fn serve_file_with_mime(path: &std::path::Path, mime: &str) -> impl IntoResponse {
    match tokio::fs::read(path).await {
        Ok(bytes) => Response::builder()
            .header(header::CONTENT_TYPE, mime)
            .body(Body::from(bytes))
            .unwrap()
            .into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

pub async fn report_problem(
    State(state): State<AppState>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let pushbullet_token = match &state.inner.cfg.pushbullet_token {
        Some(t) => t.clone(),
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": "Notifications not configured" })),
            )
                .into_response()
        }
    };

    let message = body
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();

    if message.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Message is required" })),
        )
            .into_response();
    }
    if message.len() > 500 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Message too long (max 500 characters)" })),
        )
            .into_response();
    }

    let ip = addr.ip().to_string();
    let allowed = {
        let mut rl = state.inner.rate_limit.write().await;
        rl.check_report_limit(&ip, 3, chrono::Duration::hours(1))
    };

    if !allowed {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({ "error": "Too many reports — please wait before sending another" })),
        )
            .into_response();
    }

    match ha_client::send_pushbullet(
        &state.inner.http,
        &pushbullet_token,
        "DoorOpener: Problem Report",
        &message,
    )
    .await
    {
        Ok(_) => {
            tracing::info!("Problem report sent from {}: {}", ip, &message[..message.len().min(80)]);
            Json(json!({ "status": "ok" })).into_response()
        }
        Err(e) => {
            tracing::error!("Pushbullet report failed: {}", e);
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "error": "Failed to send notification" })),
            )
                .into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub fn gen_nonce() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Wrap an HTML string in a Response with full security headers.
pub fn html_response_with_security_headers(html: String, nonce: &str) -> axum::response::Response {
    let csp = format!(
        "default-src 'self'; \
         script-src 'self' 'nonce-{nonce}'; \
         style-src 'self' 'nonce-{nonce}'; \
         img-src 'self' data:; \
         font-src 'self'; \
         connect-src 'self' https://api.github.com; \
         object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    );

    let mut resp = Html(html).into_response();
    let headers = resp.headers_mut();
    headers.insert("X-Content-Type-Options", HeaderValue::from_static("nosniff"));
    headers.insert("X-Frame-Options", HeaderValue::from_static("DENY"));
    headers.insert("Referrer-Policy", HeaderValue::from_static("strict-origin-when-cross-origin"));
    headers.insert(
        "Permissions-Policy",
        HeaderValue::from_static(
            "geolocation=(), microphone=(), camera=(), payment=(), usb=(), \
             magnetometer=(), gyroscope=(), fullscreen=(self), \
             browsing-topics=(), run-ad-auction=(), join-ad-interest-group=()",
        ),
    );
    headers.insert("X-Permitted-Cross-Domain-Policies", HeaderValue::from_static("none"));
    headers.insert("Cross-Origin-Opener-Policy", HeaderValue::from_static("same-origin"));
    headers.insert(
        "Content-Security-Policy",
        HeaderValue::from_str(&csp).unwrap_or(HeaderValue::from_static("default-src 'self'")),
    );
    headers.insert("Cache-Control", HeaderValue::from_static("no-store, no-cache, must-revalidate, max-age=0"));
    headers.insert("Pragma", HeaderValue::from_static("no-cache"));
    resp
}

/// Add security headers to any JSON/generic response.
pub fn add_security_headers(mut resp: axum::response::Response) -> axum::response::Response {
    let headers = resp.headers_mut();
    headers.insert("X-Content-Type-Options", HeaderValue::from_static("nosniff"));
    headers.insert("X-Frame-Options", HeaderValue::from_static("DENY"));
    headers.insert("Referrer-Policy", HeaderValue::from_static("strict-origin-when-cross-origin"));
    headers.insert("Cache-Control", HeaderValue::from_static("no-store, no-cache, must-revalidate, max-age=0"));
    headers.insert("Pragma", HeaderValue::from_static("no-cache"));
    resp
}

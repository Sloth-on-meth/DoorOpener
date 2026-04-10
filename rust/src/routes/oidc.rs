use crate::ha_client;
use crate::state::AppState;
use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use tower_sessions::Session;

// ---------------------------------------------------------------------------
// /auth/status
// ---------------------------------------------------------------------------

pub async fn auth_status(
    State(state): State<AppState>,
    session: Session,
) -> impl IntoResponse {
    let cfg = &state.inner.cfg;
    let enabled = cfg.oidc_enabled;

    let authenticated = enabled
        && session
            .get::<bool>("oidc_authenticated")
            .await
            .unwrap_or(None)
            .unwrap_or(false);

    let user = if authenticated {
        session.get::<String>("oidc_user").await.unwrap_or(None)
    } else {
        None
    };

    let groups: Vec<String> = if authenticated {
        session
            .get::<Vec<String>>("oidc_groups")
            .await
            .unwrap_or(None)
            .unwrap_or_default()
    } else {
        vec![]
    };

    Json(json!({
        "oidc_enabled": enabled,
        "oidc_authenticated": authenticated,
        "user": user,
        "groups": groups,
        "require_pin_for_oidc": cfg.require_pin_for_oidc,
    }))
}

// ---------------------------------------------------------------------------
// /login
// ---------------------------------------------------------------------------

pub async fn login_redirect(
    State(state): State<AppState>,
    session: Session,
) -> impl IntoResponse {
    let cfg = &state.inner.cfg;

    if !cfg.oidc_enabled {
        return Redirect::to("/admin").into_response();
    }

    let (issuer, client_id) = match (&cfg.oidc_issuer, &cfg.oidc_client_id) {
        (Some(i), Some(c)) => (i.clone(), c.clone()),
        _ => return Redirect::to("/admin").into_response(),
    };

    // Fetch discovery document to get authorization_endpoint
    let discovery = match ha_client::fetch_oidc_discovery(&state.inner.http, &issuer).await {
        Ok(d) => d,
        Err(e) => {
            tracing::error!("OIDC discovery failed: {}", e);
            return (StatusCode::BAD_GATEWAY, "OIDC discovery failed").into_response();
        }
    };

    let auth_endpoint = match discovery.get("authorization_endpoint").and_then(|v| v.as_str()) {
        Some(e) => e.to_string(),
        None => {
            tracing::error!("No authorization_endpoint in OIDC discovery");
            return (StatusCode::BAD_GATEWAY, "OIDC misconfigured").into_response();
        }
    };

    // Generate state, nonce, PKCE
    let oidc_state = gen_random_hex(16);
    let oidc_nonce = gen_random_hex(16);
    let code_verifier = gen_random_base64url(64);
    let code_challenge = pkce_challenge(&code_verifier);

    let _ = session.insert("oidc_state", oidc_state.clone()).await;
    let _ = session.insert("oidc_nonce", oidc_nonce.clone()).await;
    let _ = session.insert("oidc_code_verifier", code_verifier.clone()).await;

    let redirect_uri = cfg
        .oidc_redirect_uri
        .clone()
        .unwrap_or_else(|| "/oidc/callback".to_string());

    let auth_url = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope=openid%20email%20profile%20groups\
         &state={}&nonce={}&code_challenge={}&code_challenge_method=S256",
        auth_endpoint,
        url_encode(&client_id),
        url_encode(&redirect_uri),
        url_encode(&oidc_state),
        url_encode(&oidc_nonce),
        url_encode(&code_challenge),
    );

    Redirect::to(&auth_url).into_response()
}

// ---------------------------------------------------------------------------
// /oidc/callback
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct CallbackParams {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

pub async fn oidc_callback(
    State(state): State<AppState>,
    session: Session,
    Query(params): Query<CallbackParams>,
) -> impl IntoResponse {
    let cfg = &state.inner.cfg;

    if !cfg.oidc_enabled {
        return Redirect::to("/admin").into_response();
    }

    if let Some(err) = &params.error {
        tracing::error!("OIDC provider returned error: {}", err);
        return (StatusCode::UNAUTHORIZED, "OIDC authentication failed").into_response();
    }

    // Validate state (CSRF)
    let saved_state = session
        .remove::<String>("oidc_state")
        .await
        .unwrap_or(None);
    if params.state.as_deref() != saved_state.as_deref() {
        return (StatusCode::UNAUTHORIZED, "Invalid state").into_response();
    }

    let code = match &params.code {
        Some(c) => c.clone(),
        None => return (StatusCode::BAD_REQUEST, "Missing code").into_response(),
    };

    let code_verifier = session
        .remove::<String>("oidc_code_verifier")
        .await
        .unwrap_or(None)
        .unwrap_or_default();

    let saved_nonce = session
        .remove::<String>("oidc_nonce")
        .await
        .unwrap_or(None);

    // Fetch discovery document to get token_endpoint
    let issuer = cfg.oidc_issuer.clone().unwrap();
    let client_id = cfg.oidc_client_id.clone().unwrap();
    let client_secret = cfg.oidc_client_secret.clone().unwrap();
    let redirect_uri = cfg
        .oidc_redirect_uri
        .clone()
        .unwrap_or_else(|| "/oidc/callback".to_string());

    let discovery = match ha_client::fetch_oidc_discovery(&state.inner.http, &issuer).await {
        Ok(d) => d,
        Err(e) => {
            tracing::error!("OIDC discovery failed: {}", e);
            return (StatusCode::BAD_GATEWAY, "OIDC discovery failed").into_response();
        }
    };

    let token_endpoint = match discovery
        .get("token_endpoint")
        .and_then(|v| v.as_str())
    {
        Some(e) => e.to_string(),
        None => {
            tracing::error!("No token_endpoint in OIDC discovery");
            return (StatusCode::BAD_GATEWAY, "OIDC misconfigured").into_response();
        }
    };

    // Exchange code for tokens
    let tokens = match ha_client::exchange_code(
        &state.inner.http,
        &token_endpoint,
        &client_id,
        &client_secret,
        &code,
        &redirect_uri,
        &code_verifier,
    )
    .await
    {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("Token exchange failed: {}", e);
            return (StatusCode::UNAUTHORIZED, "Token exchange failed").into_response();
        }
    };

    // Extract and validate claims
    // Prefer userinfo; fall back to decoding id_token without signature check
    let claims = extract_claims(&tokens);

    // Validate nonce
    if claims.get("nonce").and_then(|v| v.as_str()) != saved_nonce.as_deref() {
        return (StatusCode::UNAUTHORIZED, "Invalid nonce").into_response();
    }

    // Validate audience
    let aud_valid = match claims.get("aud") {
        Some(Value::Array(arr)) => arr.iter().any(|v| v.as_str() == Some(&client_id)),
        Some(Value::String(s)) => s == &client_id,
        _ => false,
    };
    if !aud_valid {
        tracing::error!("Invalid OIDC audience");
        return (StatusCode::UNAUTHORIZED, "Invalid audience").into_response();
    }

    // Validate issuer
    if let Some(iss) = claims.get("iss").and_then(|v| v.as_str()) {
        let cfg_issuer = issuer.trim_end_matches('/');
        if iss.trim_end_matches('/') != cfg_issuer {
            tracing::error!("Invalid OIDC issuer: {}", iss);
            return (StatusCode::UNAUTHORIZED, "Invalid issuer").into_response();
        }
    }

    // Validate expiration
    let now_ts = chrono::Utc::now().timestamp();
    let leeway = 60i64;
    if let Some(exp) = claims.get("exp").and_then(|v| v.as_i64()) {
        if exp + leeway < now_ts {
            return (StatusCode::UNAUTHORIZED, "Token has expired").into_response();
        }
    }
    if let Some(nbf) = claims.get("nbf").and_then(|v| v.as_i64()) {
        if nbf - leeway > now_ts {
            return (StatusCode::UNAUTHORIZED, "Token not yet valid").into_response();
        }
    }

    // Extract user info
    let user = claims
        .get("email")
        .or_else(|| claims.get("preferred_username"))
        .or_else(|| claims.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("oidc-user")
        .to_string();

    let groups: Vec<String> = match claims
        .get("groups")
        .or_else(|| claims.get("roles"))
    {
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        Some(Value::String(s)) => s
            .split(',')
            .map(|g| g.trim().to_string())
            .filter(|g| !g.is_empty())
            .collect(),
        _ => vec![],
    };

    // Group access control
    let (is_admin, _is_user_allowed) = if !cfg.oidc_admin_group.is_empty() || !cfg.oidc_user_group.is_empty() {
        if groups.is_empty() {
            tracing::error!("No groups found in OIDC token for user {}", user);
            return (StatusCode::FORBIDDEN, "Access denied: No groups found").into_response();
        }
        let admin = !cfg.oidc_admin_group.is_empty() && groups.contains(&cfg.oidc_admin_group);
        let allowed = cfg.oidc_user_group.is_empty() || groups.contains(&cfg.oidc_user_group);
        if !allowed {
            tracing::error!("User {} is not in allowed OIDC group", user);
            return (StatusCode::FORBIDDEN, "Access denied: User not in allowed group").into_response();
        }
        (admin, allowed)
    } else {
        (false, true)
    };

    // Reset session to prevent fixation
    session.clear().await;

    let exp = claims.get("exp").and_then(|v| v.as_i64());

    let _ = session.insert("oidc_authenticated", true).await;
    let _ = session.insert("oidc_user", user.clone()).await;
    let _ = session.insert("oidc_groups", groups.clone()).await;
    if let Some(e) = exp {
        let _ = session.insert("oidc_exp", e).await;
    }

    if is_admin {
        let _ = session.insert("admin_authenticated", true).await;
        let _ = session.insert("admin_login_time", chrono::Utc::now().to_rfc3339()).await;
        let _ = session.insert("admin_user", user.clone()).await;
        let _ = session.insert("admin_csrf_token", gen_random_hex(32)).await;
    }

    Redirect::to("/").into_response()
}

// ---------------------------------------------------------------------------
// /oidc/logout
// ---------------------------------------------------------------------------

pub async fn oidc_logout(
    State(state): State<AppState>,
    session: Session,
) -> impl IntoResponse {
    let cfg = &state.inner.cfg;

    session.clear().await;

    if cfg.oidc_enabled {
        if let Some(issuer) = &cfg.oidc_issuer {
            if let Some(end_session_url) =
                ha_client::fetch_oidc_end_session_endpoint(&state.inner.http, issuer).await
            {
                let logout_url = format!("{end_session_url}?redirect_uri=/");
                return Redirect::to(&logout_url).into_response();
            }
        }
    }

    Redirect::to("/").into_response()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn gen_random_hex(n_bytes: usize) -> String {
    use rand::RngCore;
    let mut bytes = vec![0u8; n_bytes];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn gen_random_base64url(n_bytes: usize) -> String {
    use rand::RngCore;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let mut bytes = vec![0u8; n_bytes];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(&bytes)
}

fn pkce_challenge(verifier: &str) -> String {
    use sha2::{Digest, Sha256};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let hash = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hash)
}

fn url_encode(s: &str) -> String {
    // Simple percent-encoding for URL query parameter values
    let mut result = String::new();
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
            }
            _ => {
                result.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    result
}

/// Try to extract claims from a token response.
/// Prefers the `userinfo` object if present; otherwise base64-decodes the id_token payload.
fn extract_claims(tokens: &HashMap<String, Value>) -> HashMap<String, Value> {
    // Prefer already-parsed userinfo
    if let Some(Value::Object(ui)) = tokens.get("userinfo") {
        return ui.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    }

    // Fall back: decode the id_token JWT payload (no signature verification here —
    // matches the Python behaviour where sig check only happens if public_key is set)
    if let Some(id_token) = tokens.get("id_token").and_then(|v| v.as_str()) {
        let parts: Vec<&str> = id_token.split('.').collect();
        if parts.len() >= 2 {
            use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
            if let Ok(payload_bytes) = URL_SAFE_NO_PAD.decode(parts[1]) {
                if let Ok(claims) =
                    serde_json::from_slice::<HashMap<String, Value>>(&payload_bytes)
                {
                    return claims;
                }
            }
        }
    }

    HashMap::new()
}

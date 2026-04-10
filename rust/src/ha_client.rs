use anyhow::{bail, Result};
use reqwest::Client;
use serde_json::{json, Value};
use std::collections::HashMap;

/// Open the door/lock/switch via the Home Assistant REST API.
pub async fn open_door(
    client: &Client,
    ha_url: &str,
    ha_token: &str,
    entity_id: &str,
) -> Result<()> {
    let url = if entity_id.starts_with("lock.") {
        format!("{}/api/services/lock/unlock", ha_url)
    } else if entity_id.starts_with("input_boolean.") {
        format!("{}/api/services/input_boolean/turn_on", ha_url)
    } else {
        format!("{}/api/services/switch/turn_on", ha_url)
    };

    let payload = json!({ "entity_id": entity_id });

    let resp = client
        .post(&url)
        .bearer_auth(ha_token)
        .header("Content-Type", "application/json")
        .json(&payload)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await?;

    if !resp.status().is_success() {
        bail!("Home Assistant API error: {}", resp.status());
    }
    Ok(())
}

/// Fetch the battery level from a Home Assistant sensor entity.
/// Returns None if the value is unavailable or out of range.
pub async fn get_battery_level(
    client: &Client,
    ha_url: &str,
    ha_token: &str,
    battery_entity: &str,
) -> Option<i64> {
    let url = format!("{}/api/states/{}", ha_url, battery_entity);

    let resp = client
        .get(&url)
        .bearer_auth(ha_token)
        .header("Content-Type", "application/json")
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .ok()?;

    if !resp.status().is_success() {
        return None;
    }

    let body: Value = resp.json().await.ok()?;
    let level_str = body.get("state")?.as_str()?;
    let level: f64 = level_str.parse().ok()?;

    if (0.0..=100.0).contains(&level) {
        Some(level as i64)
    } else {
        None
    }
}

/// Fetch OIDC discovery document and return the `end_session_endpoint`, if present.
pub async fn fetch_oidc_end_session_endpoint(
    client: &Client,
    issuer: &str,
) -> Option<String> {
    let url = format!("{}/.well-known/openid-configuration", issuer);
    let resp = client
        .get(&url)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .ok()?;
    let doc: HashMap<String, Value> = resp.json().await.ok()?;
    doc.get("end_session_endpoint")?.as_str().map(str::to_string)
}

/// Fetch OIDC discovery document and return the full JSON object.
pub async fn fetch_oidc_discovery(
    client: &Client,
    issuer: &str,
) -> Result<HashMap<String, Value>> {
    let url = format!("{}/.well-known/openid-configuration", issuer);
    let resp = client
        .get(&url)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await?;
    Ok(resp.json().await?)
}

/// Exchange an authorization code for tokens at the token endpoint.
pub async fn exchange_code(
    client: &Client,
    token_endpoint: &str,
    client_id: &str,
    client_secret: &str,
    code: &str,
    redirect_uri: &str,
    code_verifier: &str,
) -> Result<HashMap<String, Value>> {
    let params = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("code_verifier", code_verifier),
    ];

    let resp = client
        .post(token_endpoint)
        .form(&params)
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("Token endpoint returned {}: {}", status, body);
    }

    Ok(resp.json().await?)
}

/// Send a Pushbullet notification.
pub async fn send_pushbullet(
    client: &Client,
    api_token: &str,
    title: &str,
    body: &str,
) -> Result<()> {
    let payload = json!({
        "type": "note",
        "title": title,
        "body": body,
    });

    let resp = client
        .post("https://api.pushbullet.com/v2/pushes")
        .header("Access-Token", api_token)
        .header("Content-Type", "application/json")
        .json(&payload)
        .timeout(std::time::Duration::from_secs(8))
        .send()
        .await?;

    if !resp.status().is_success() {
        bail!("Pushbullet API error: {}", resp.status());
    }
    Ok(())
}

use anyhow::{bail, Context, Result};
use configparser::ini::Ini;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Fully resolved configuration for the application.
/// Fields that can be mutated at runtime (test_mode, notice, user_pins) are
/// kept in AppState behind an RwLock rather than here.
#[derive(Debug, Clone)]
pub struct Config {
    // paths
    pub config_path: PathBuf,
    pub log_dir: PathBuf,
    pub users_store_path: PathBuf,
    pub static_dir: PathBuf,

    // server
    pub port: u16,
    pub secret_key: String,
    pub random_secret_warning: bool,

    // session
    pub session_cookie_secure: bool,

    // home assistant
    pub ha_url: String,
    pub ha_token: String,
    pub entity_id: String,
    pub battery_entity: String,
    pub ha_ca_bundle: Option<String>,

    // admin
    pub admin_password: String,

    // runtime-mutable (cloned into RwLock<MutableConfig>)
    pub test_mode: bool,
    pub notice: String,

    // pins from config.ini [pins] section (read-only; overridable by users.json)
    pub user_pins: HashMap<String, String>,

    // oidc
    pub oidc_enabled: bool,
    pub oidc_issuer: Option<String>,
    pub oidc_client_id: Option<String>,
    pub oidc_client_secret: Option<String>,
    pub oidc_redirect_uri: Option<String>,
    pub oidc_admin_group: String,
    pub oidc_user_group: String,
    pub require_pin_for_oidc: bool,
    pub oidc_public_key: Option<String>,

    // pushbullet
    pub pushbullet_token: Option<String>,

    // security
    pub max_attempts: u32,
    pub block_time_minutes: u32,
    pub max_global_attempts_per_hour: u32,
    pub session_max_attempts: u32,

    // misc
    pub page_title: String,
    pub easter_egg_enabled: bool,
    pub app_version: String,
}

/// Fields that can be toggled at runtime by the admin panel.
#[derive(Debug, Clone)]
pub struct MutableConfig {
    pub test_mode: bool,
    pub notice: String,
    /// Pins from config.ini — mutable because migrate endpoints remove entries.
    pub user_pins: HashMap<String, String>,
}

/// Load and validate configuration from config.ini and environment variables.
pub fn load(config_path: &Path) -> Result<Config> {
    let mut ini = Ini::new();

    // It's OK if the file doesn't exist yet; we'll fail on missing mandatory values below.
    let _ = ini.load(config_path);

    let get = |section: &str, key: &str| -> Option<String> {
        ini.get(section, key).filter(|s| !s.is_empty())
    };
    let get_bool = |section: &str, key: &str, default: bool| -> bool {
        match ini.get(section, key).as_deref() {
            Some("true") | Some("1") | Some("yes") => true,
            Some("false") | Some("0") | Some("no") => false,
            _ => default,
        }
    };
    let get_u32 = |section: &str, key: &str, default: u32| -> u32 {
        ini.get(section, key)
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    };

    // --- Mandatory values ---
    let admin_password = get("admin", "admin_password")
        .context("Missing [admin] admin_password in config.ini")?;

    let ha_token = get("homeassistant", "token")
        .context("Missing [HomeAssistant] token in config.ini")?;

    let entity_id = get("homeassistant", "switch_entity")
        .context("Missing [HomeAssistant] switch_entity in config.ini")?;

    // --- Derived values ---
    let device_name = entity_id
        .split('.')
        .nth(1)
        .unwrap_or(&entity_id)
        .to_string();

    let battery_entity = get("homeassistant", "battery_entity")
        .unwrap_or_else(|| format!("sensor.{}_battery", device_name));

    let ha_url = get("homeassistant", "url")
        .unwrap_or_else(|| "http://homeassistant.local:8123".to_string());

    let ha_ca_bundle = get("homeassistant", "ca_bundle").and_then(|p| {
        if Path::new(&p).exists() {
            Some(p)
        } else {
            tracing::warn!("Configured HomeAssistant ca_bundle not found: {}. Falling back to system trust store.", p);
            None
        }
    });

    // --- Secret key ---
    let (secret_key, random_secret_warning) = if let Ok(k) = std::env::var("FLASK_SECRET_KEY") {
        (k, false)
    } else if let Some(k) = get("server", "secret_key") {
        (k, false)
    } else {
        let k = generate_secret_key();
        tracing::warn!(
            "SECRET_KEY not set and no [server] secret_key in config.ini; \
             sessions will be invalidated on restart."
        );
        (k, true)
    };

    // --- Port ---
    let port = std::env::var("DOOROPENER_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| get_u32("server", "port", 6532) as u16);

    // --- Session cookie secure ---
    let session_cookie_secure = std::env::var("SESSION_COOKIE_SECURE")
        .map(|v| v.to_lowercase() != "false" && v != "0")
        .unwrap_or(true);

    // --- Paths ---
    let app_dir = config_path.parent().unwrap_or(Path::new(".")).to_path_buf();
    let log_dir = std::env::var("DOOROPENER_LOG_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| app_dir.join("logs"));
    let users_store_path = std::env::var("USERS_STORE_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| app_dir.join("users.json"));
    let static_dir = app_dir.join("static");

    // --- Pins ---
    let user_pins: HashMap<String, String> = ini
        .get_map()
        .unwrap_or_default()
        .get("pins")
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(k, v)| v.map(|pin| (k, pin)))
        .collect();

    // --- OIDC ---
    let oidc_enabled = get_bool("oidc", "enabled", false);
    let oidc_issuer = get("oidc", "issuer");
    let oidc_client_id = get("oidc", "client_id");
    let oidc_client_secret = get("oidc", "client_secret");
    let oidc_redirect_uri = get("oidc", "redirect_uri");
    let oidc_admin_group = get("oidc", "admin_group").unwrap_or_default();
    let oidc_user_group = get("oidc", "user_group").unwrap_or_default();
    let require_pin_for_oidc = get_bool("oidc", "require_pin_for_oidc", false);
    let oidc_public_key = get("oidc", "public_key");

    let oidc_ready = oidc_enabled
        && oidc_issuer.is_some()
        && oidc_client_id.is_some()
        && oidc_client_secret.is_some();

    if oidc_enabled && !oidc_ready {
        tracing::warn!("OIDC is enabled but missing issuer, client_id, or client_secret — OIDC will be disabled.");
    }

    // --- Security ---
    let max_attempts = get_u32("security", "max_attempts", 5);
    let block_time_minutes = get_u32("security", "block_time_minutes", 5);
    let max_global_attempts_per_hour = get_u32("security", "max_global_attempts_per_hour", 50);
    let session_max_attempts = get_u32("security", "session_max_attempts", 3);

    // --- Misc ---
    let test_mode = get_bool("server", "test_mode", false);
    let notice = get("server", "notice").unwrap_or_default();
    let page_title = get("server", "page_title").unwrap_or_default();
    let easter_egg_enabled = get_bool("server", "67mode", false);
    let pushbullet_token = get("pushbullet", "api_token");

    if test_mode {
        tracing::warn!(
            "TEST MODE ENABLED — the door will NOT open. \
             Disable [server] test_mode in config.ini before deploying to production."
        );
    }

    Ok(Config {
        config_path: config_path.to_path_buf(),
        log_dir,
        users_store_path,
        static_dir,
        port,
        secret_key,
        random_secret_warning,
        session_cookie_secure,
        ha_url,
        ha_token,
        entity_id,
        battery_entity,
        ha_ca_bundle,
        admin_password,
        test_mode,
        notice,
        user_pins,
        oidc_enabled: oidc_ready,
        oidc_issuer,
        oidc_client_id,
        oidc_client_secret,
        oidc_redirect_uri,
        oidc_admin_group,
        oidc_user_group,
        require_pin_for_oidc,
        oidc_public_key,
        pushbullet_token,
        max_attempts,
        block_time_minutes,
        max_global_attempts_per_hour,
        session_max_attempts,
        page_title,
        easter_egg_enabled,
        app_version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

/// Persist the mutable config fields back to config.ini.
pub fn save(config_path: &Path, mutable: &MutableConfig, base_config: &Config) -> Result<()> {
    let mut ini = Ini::new();
    // Load existing file first to preserve all sections/keys we don't manage
    let _ = ini.load(config_path);

    // server section
    ini.set("server", "test_mode", Some(if mutable.test_mode { "true" } else { "false" }.to_string()));
    if mutable.notice.is_empty() {
        ini.remove_key("server", "notice");
    } else {
        ini.set("server", "notice", Some(mutable.notice.clone()));
    }

    // pins section — write remaining pins
    // First clear the section, then re-add
    for (username, pin) in &mutable.user_pins {
        ini.set("pins", username, Some(pin.clone()));
    }
    // Remove pins that were in base_config but are no longer in mutable
    for username in base_config.user_pins.keys() {
        if !mutable.user_pins.contains_key(username) {
            ini.remove_key("pins", username);
        }
    }

    ini.write(config_path)
        .context("Failed to write config.ini")?;
    Ok(())
}

fn generate_secret_key() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

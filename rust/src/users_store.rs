use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::io::Write;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserMeta {
    pub pin: String,
    pub active: bool,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub last_used_at: Option<String>,
    #[serde(default)]
    pub times_used: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct StoreData {
    users: HashMap<String, UserMeta>,
}

/// JSON-backed user store with atomic writes and merge-over-config behaviour.
///
/// This is a direct port of Python's `UsersStore`. Callers must hold the outer
/// `RwLock<UsersStore>` when accessing any method.
#[derive(Debug, Clone)]
pub struct UsersStore {
    path: PathBuf,
    data: StoreData,
}

impl UsersStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            data: StoreData::default(),
        }
    }

    fn load(&mut self) {
        if self.path.exists() {
            match std::fs::read_to_string(&self.path) {
                Ok(contents) => {
                    self.data = serde_json::from_str(&contents).unwrap_or_default();
                }
                Err(_) => {
                    self.data = StoreData::default();
                }
            }
        } else {
            if let Some(parent) = self.path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            self.data = StoreData::default();
        }
    }

    fn save_atomic(&self) -> Result<()> {
        let dir = self.path.parent().unwrap_or(Path::new("."));
        std::fs::create_dir_all(dir)?;

        // Try to place the temp file on the same filesystem for atomic rename.
        let tmp_path = self.path.with_extension("tmp");
        let json = serde_json::to_string_pretty(&self.data)?;

        let mut file = std::fs::File::create(&tmp_path)
            .context("Failed to create temp file for users store")?;
        file.write_all(json.as_bytes())?;
        file.flush()?;
        drop(file);

        std::fs::rename(&tmp_path, &self.path).context("Failed to atomically replace users.json")?;
        Ok(())
    }

    /// Merge base_pins (from config.ini [pins]) with the JSON store.
    /// JSON store entries take precedence; inactive users are excluded.
    pub fn effective_pins(&mut self, base_pins: &HashMap<String, String>) -> HashMap<String, String> {
        self.load();
        let mut effective: HashMap<String, String> = base_pins.clone();
        for (username, meta) in &self.data.users {
            if !meta.active {
                effective.remove(username);
                continue;
            }
            if is_valid_pin(&meta.pin) {
                effective.insert(username.clone(), meta.pin.clone());
            }
        }
        effective
    }

    pub fn list_users(&mut self, include_pins: bool) -> Vec<serde_json::Value> {
        self.load();
        self.data
            .users
            .iter()
            .map(|(username, meta)| {
                let mut item = serde_json::json!({
                    "username": username,
                    "active": meta.active,
                    "created_at": meta.created_at,
                    "updated_at": meta.updated_at,
                    "last_used_at": meta.last_used_at,
                    "times_used": meta.times_used,
                });
                if include_pins {
                    item["pin"] = serde_json::Value::String(meta.pin.clone());
                }
                item
            })
            .collect()
    }

    pub fn create_user(&mut self, username: &str, pin: &str, active: bool) -> Result<()> {
        self.load();
        validate_username(username)?;
        validate_pin(pin)?;
        if self.data.users.contains_key(username) {
            bail!("User already exists");
        }
        let now = now_iso();
        self.data.users.insert(
            username.to_string(),
            UserMeta {
                pin: pin.to_string(),
                active,
                created_at: Some(now.clone()),
                updated_at: Some(now),
                last_used_at: None,
                times_used: 0,
            },
        );
        self.save_atomic()
    }

    pub fn update_user(&mut self, username: &str, pin: Option<&str>, active: Option<bool>) -> Result<()> {
        self.load();
        let meta = self
            .data
            .users
            .get_mut(username)
            .ok_or_else(|| anyhow::anyhow!("User not found"))?;

        if let Some(p) = pin {
            validate_pin(p)?;
            meta.pin = p.to_string();
        }
        if let Some(a) = active {
            meta.active = a;
        }
        meta.updated_at = Some(now_iso());
        self.save_atomic()
    }

    pub fn delete_user(&mut self, username: &str) -> Result<()> {
        self.load();
        if self.data.users.remove(username).is_none() {
            bail!("User not found");
        }
        self.save_atomic()
    }

    pub fn touch_user(&mut self, username: &str) {
        self.load();
        if let Some(meta) = self.data.users.get_mut(username) {
            meta.last_used_at = Some(now_iso());
            meta.times_used += 1;
            let _ = self.save_atomic();
        }
    }

    pub fn user_exists(&mut self, username: &str) -> bool {
        self.load();
        self.data.users.contains_key(username)
    }

    /// Return the username of an inactive user whose PIN matches, or None.
    pub fn find_disabled_user_by_pin(&mut self, pin: &str) -> Option<String> {
        self.load();
        for (username, meta) in &self.data.users {
            if !meta.active && constant_time_eq(pin, &meta.pin) {
                return Some(username.clone());
            }
        }
        None
    }
}

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn is_valid_pin(pin: &str) -> bool {
    pin.chars().all(|c| c.is_ascii_digit()) && pin.len() >= 4 && pin.len() <= 8
}

fn validate_pin(pin: &str) -> Result<()> {
    if !is_valid_pin(pin) {
        bail!("Invalid pin: must be 4-8 digits");
    }
    Ok(())
}

fn validate_username(username: &str) -> Result<()> {
    if username.is_empty() || username.len() > 32 {
        bail!("Invalid username: must be 1-32 characters");
    }
    if !username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        bail!("Invalid username: only alphanumeric, _, -, . allowed");
    }
    Ok(())
}

/// Constant-time string equality to prevent timing attacks on PIN comparison.
fn constant_time_eq(a: &str, b: &str) -> bool {
    // Manual byte-by-byte compare that doesn't short-circuit (constant-time).
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

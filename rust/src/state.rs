use crate::config::{Config, MutableConfig};
use crate::logging::AuditLogger;
use crate::rate_limit::RateLimitState;
use crate::users_store::UsersStore;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Shared application state threaded through every Axum handler via `axum::extract::State`.
#[derive(Clone)]
pub struct AppState {
    pub inner: Arc<Inner>,
}

pub struct Inner {
    /// Static (startup-time) configuration.
    pub cfg: Config,
    /// Runtime-mutable configuration (test_mode, notice, user_pins).
    pub mutable: RwLock<MutableConfig>,
    /// In-memory rate-limiting / brute-force state.
    pub rate_limit: RwLock<RateLimitState>,
    /// JSON-backed user store.
    pub users: RwLock<UsersStore>,
    /// Shared async HTTP client (reqwest).
    pub http: reqwest::Client,
    /// Tera template engine (read-only after startup).
    pub tera: tera::Tera,
    /// Rotating audit log writer.
    pub audit_logger: AuditLogger,
}

impl AppState {
    pub fn new(cfg: Config, tera: tera::Tera, http: reqwest::Client) -> Self {
        let mutable = MutableConfig {
            test_mode: cfg.test_mode,
            notice: cfg.notice.clone(),
            user_pins: cfg.user_pins.clone(),
        };
        let users = UsersStore::new(cfg.users_store_path.clone());

        // Ensure the log directory exists
        let _ = std::fs::create_dir_all(&cfg.log_dir);
        let audit_logger = AuditLogger::new(&cfg.log_dir, "log.txt", 1_000_000, 5);

        AppState {
            inner: Arc::new(Inner {
                mutable: RwLock::new(mutable),
                rate_limit: RwLock::new(RateLimitState::new()),
                users: RwLock::new(users),
                http,
                tera,
                audit_logger,
                cfg,
            }),
        }
    }
}

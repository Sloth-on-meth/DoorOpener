mod config;
mod ha_client;
mod logging;
mod rate_limit;
mod routes;
mod state;
mod users_store;

use anyhow::{Context, Result};
use state::AppState;
use std::net::SocketAddr;
use std::path::PathBuf;
use tower_sessions::{MemoryStore, SessionManagerLayer};
use tower_sessions::cookie::SameSite;
use time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    // --- Logging ---
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // --- Config ---
    let config_path = std::env::var("DOOROPENER_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            // Default: config.ini next to this binary, or in the current dir
            PathBuf::from("config.ini")
        });

    let cfg = config::load(&config_path)
        .with_context(|| format!("Failed to load config from {:?}", config_path))?;

    let port = cfg.port;
    let secret_key = cfg.secret_key.clone();
    let session_cookie_secure = cfg.session_cookie_secure;
    let static_dir = cfg.static_dir.clone();

    // --- HTTP client ---
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent(format!("DoorOpener/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .context("Failed to build reqwest client")?;

    // --- Templates ---
    // Templates live in a `templates/` directory next to config.ini
    let templates_glob = config_path
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .join("templates/**/*.html")
        .to_string_lossy()
        .into_owned();

    let mut tera = tera::Tera::new(&templates_glob)
        .with_context(|| format!("Failed to load Tera templates from {}", templates_glob))?;
    tera.autoescape_on(vec!["html"]);

    // --- App state ---
    let state = AppState::new(cfg, tera, http);

    // --- Session layer ---
    // MemoryStore is fine for single-process deployments (Docker).
    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(session_cookie_secure)
        .with_same_site(SameSite::Lax)
        .with_http_only(true)
        .with_max_age(Duration::days(30));

    // --- Router ---
    let app = routes::build_router(state, static_dir)
        .layer(session_layer);

    // --- Serve ---
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("DoorOpener listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("Failed to bind to {}", addr))?;

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .context("Server error")?;

    Ok(())
}

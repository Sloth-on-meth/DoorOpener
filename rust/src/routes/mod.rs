pub mod admin;
pub mod door;
pub mod index;
pub mod oidc;

use crate::state::AppState;
use axum::{
    Router,
    routing::{get, post, put},
};
use tower_http::services::ServeDir;

pub fn build_router(state: AppState, static_dir: std::path::PathBuf) -> Router {
    Router::new()
        // Static files
        .nest_service("/static", ServeDir::new(&static_dir))
        // PWA helpers
        .route("/service-worker.js", get(index::service_worker))
        .route("/manifest.webmanifest", get(index::manifest_file))
        // Main pages
        .route("/", get(index::index))
        .route("/health", get(index::health))
        .route("/battery", get(index::battery))
        // Door opening
        .route("/open-door", post(door::open_door))
        // Auth status
        .route("/auth/status", get(oidc::auth_status))
        // OIDC
        .route("/login", get(oidc::login_redirect))
        .route("/oidc/callback", get(oidc::oidc_callback))
        .route("/oidc/logout", get(oidc::oidc_logout))
        // Admin panel
        .route("/admin", get(admin::admin_page))
        .route("/admin/auth", post(admin::admin_auth))
        .route("/admin/check-auth", get(admin::admin_check_auth))
        .route("/admin/logout", post(admin::admin_logout))
        // Admin config
        .route("/admin/notice", get(admin::admin_notice_get).post(admin::admin_notice_set))
        .route("/admin/test-mode", get(admin::admin_test_mode_get).post(admin::admin_test_mode_set))
        // Admin background image
        .route(
            "/admin/background",
            get(admin::admin_background_get)
                .post(admin::admin_background_upload)
                .delete(admin::admin_background_reset),
        )
        // Admin logs
        .route("/admin/logs", get(admin::admin_logs))
        .route("/admin/logs/clear", post(admin::admin_logs_clear))
        // Admin users
        .route(
            "/admin/users",
            get(admin::admin_users_list).post(admin::admin_users_create),
        )
        .route(
            "/admin/users/{username}",
            put(admin::admin_users_update).delete(admin::admin_users_delete),
        )
        .route("/admin/users/{username}/migrate", post(admin::admin_users_migrate))
        .route("/admin/users/migrate-all", post(admin::admin_users_migrate_all))
        // Problem report
        .route("/report-problem", post(index::report_problem))
        .with_state(state)
}

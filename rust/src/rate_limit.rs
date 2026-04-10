use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;

/// All in-memory rate-limiting and brute-force-protection state.
/// Lives behind an `RwLock<RateLimitState>` in `AppState`.
#[derive(Debug, Default)]
pub struct RateLimitState {
    pub ip_failed_attempts: HashMap<String, u32>,
    pub ip_blocked_until: HashMap<String, DateTime<Utc>>,
    pub session_failed_attempts: HashMap<String, u32>,
    pub session_blocked_until: HashMap<String, DateTime<Utc>>,
    pub global_failed_attempts: u32,
    pub global_last_reset: Option<DateTime<Utc>>,
    /// Rate limiting for Pushbullet problem reports: IP → list of submission timestamps.
    pub report_timestamps: HashMap<String, Vec<DateTime<Utc>>>,
}

impl RateLimitState {
    pub fn new() -> Self {
        Self {
            global_last_reset: Some(Utc::now()),
            ..Default::default()
        }
    }

    /// True if the global failure budget has not been exhausted for this hour.
    pub fn check_global_rate_limit(&mut self, max_per_hour: u32) -> bool {
        let now = Utc::now();
        let last_reset = self.global_last_reset.unwrap_or(now);
        if now - last_reset > Duration::hours(1) {
            self.global_failed_attempts = 0;
            self.global_last_reset = Some(now);
        }
        self.global_failed_attempts < max_per_hour
    }

    /// True if `session_id` is currently blocked.
    pub fn is_session_blocked(&self, session_id: &str) -> Option<DateTime<Utc>> {
        let now = Utc::now();
        self.session_blocked_until
            .get(session_id)
            .copied()
            .filter(|&t| now < t)
    }

    /// True if `identifier` (composite IP:hash) is currently blocked.
    pub fn is_ip_blocked(&self, identifier: &str) -> Option<DateTime<Utc>> {
        let now = Utc::now();
        self.ip_blocked_until
            .get(identifier)
            .copied()
            .filter(|&t| now < t)
    }

    /// Record a failure for this session + IP combo. Returns any new block end time.
    pub fn record_failure(
        &mut self,
        session_id: &str,
        identifier: &str,
        session_max: u32,
        ip_max: u32,
        block_minutes: i64,
    ) -> FailureOutcome {
        let now = Utc::now();
        let block_duration = Duration::minutes(block_minutes);

        *self.session_failed_attempts.entry(session_id.to_string()).or_insert(0) += 1;
        *self.ip_failed_attempts.entry(identifier.to_string()).or_insert(0) += 1;
        self.global_failed_attempts += 1;

        let sess_count = self.session_failed_attempts[session_id];
        let ip_count = self.ip_failed_attempts[identifier];

        if sess_count >= session_max {
            let until = now + block_duration;
            self.session_blocked_until.insert(session_id.to_string(), until);
            FailureOutcome::SessionBlocked { until, minutes: block_minutes }
        } else if ip_count >= ip_max {
            let until = now + block_duration;
            self.ip_blocked_until.insert(identifier.to_string(), until);
            FailureOutcome::IpBlocked { until, minutes: block_minutes }
        } else {
            FailureOutcome::Counted
        }
    }

    /// Clear all failure counters for this session + IP on successful auth.
    pub fn record_success(&mut self, session_id: &str, identifier: &str) {
        self.session_failed_attempts.remove(session_id);
        self.session_blocked_until.remove(session_id);
        self.ip_failed_attempts.remove(identifier);
        self.ip_blocked_until.remove(identifier);
    }

    /// True if the IP is within the report rate limit window.
    /// Prunes old timestamps and returns false when the limit is exceeded.
    pub fn check_report_limit(&mut self, ip: &str, limit: usize, window: Duration) -> bool {
        let now = Utc::now();
        let cutoff = now - window;
        let timestamps = self.report_timestamps.entry(ip.to_string()).or_default();
        timestamps.retain(|&t| t > cutoff);
        if timestamps.len() >= limit {
            return false;
        }
        timestamps.push(now);
        true
    }
}

#[derive(Debug, Clone)]
pub enum FailureOutcome {
    /// No block triggered — just counted.
    Counted,
    /// Session is now blocked until the given time.
    SessionBlocked { until: DateTime<Utc>, minutes: i64 },
    /// IP identifier is now blocked until the given time.
    IpBlocked { until: DateTime<Utc>, minutes: i64 },
}

/// Returns the latest block-end timestamp across session and IP blocks, if any.
pub fn latest_block_ts(
    state: &RateLimitState,
    session_id: &str,
    identifier: &str,
) -> Option<f64> {
    let now = Utc::now();
    let sess = state
        .session_blocked_until
        .get(session_id)
        .copied()
        .filter(|&t| now < t);
    let ip = state
        .ip_blocked_until
        .get(identifier)
        .copied()
        .filter(|&t| now < t);
    match (sess, ip) {
        (Some(a), Some(b)) => Some(a.max(b).timestamp() as f64),
        (Some(a), None) | (None, Some(a)) => Some(a.timestamp() as f64),
        (None, None) => None,
    }
}

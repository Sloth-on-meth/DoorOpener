use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

/// Structured audit log entry — mirrors the Python JSON format.
#[derive(Debug, Serialize)]
pub struct AuditEntry {
    pub timestamp: String,
    pub ip: String,
    pub session: String,
    pub user: String,
    pub status: String,
    pub details: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exception: Option<String>,
}

impl AuditEntry {
    pub fn new(
        ip: &str,
        session_id: &str,
        user: &str,
        status: &str,
        details: &str,
    ) -> Self {
        AuditEntry {
            timestamp: Utc::now().to_rfc3339(),
            ip: ip.to_string(),
            session: session_id.chars().take(8).collect(),
            user: user.to_string(),
            status: status.to_string(),
            details: details.to_string(),
            exception: None,
        }
    }

    pub fn with_exception(mut self, exc: impl ToString) -> Self {
        self.exception = Some(exc.to_string());
        self
    }
}

/// A simple rotating-file audit logger.
/// Thread-safe via an inner Mutex.
pub struct AuditLogger {
    inner: Mutex<AuditLoggerInner>,
}

struct AuditLoggerInner {
    path: std::path::PathBuf,
    max_bytes: u64,
    backup_count: usize,
}

impl AuditLogger {
    pub fn new(log_dir: &Path, filename: &str, max_bytes: u64, backup_count: usize) -> Self {
        let path = log_dir.join(filename);
        AuditLogger {
            inner: Mutex::new(AuditLoggerInner {
                path,
                max_bytes,
                backup_count,
            }),
        }
    }

    pub fn log(&self, entry: &AuditEntry) {
        let json = match serde_json::to_string(entry) {
            Ok(j) => j,
            Err(e) => {
                tracing::error!("Failed to serialize audit entry: {}", e);
                return;
            }
        };

        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(e) => {
                tracing::error!("Audit logger lock poisoned: {}", e);
                return;
            }
        };

        inner.rotate_if_needed();

        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&inner.path)
        {
            Ok(mut f) => {
                let _ = writeln!(f, "{}", json);
            }
            Err(e) => {
                tracing::error!("Failed to write audit log: {}", e);
            }
        }
    }
}

impl AuditLoggerInner {
    fn rotate_if_needed(&self) {
        let size = std::fs::metadata(&self.path)
            .map(|m| m.len())
            .unwrap_or(0);
        if size < self.max_bytes {
            return;
        }
        // Rotate: backup_count.log → /dev/null, 1.log → 2.log, log → 1.log
        for i in (1..self.backup_count).rev() {
            let from = self.path.with_extension(format!("log.{}", i));
            let to = self.path.with_extension(format!("log.{}", i + 1));
            let _ = std::fs::rename(&from, &to);
        }
        let backup = self.path.with_extension("log.1");
        let _ = std::fs::rename(&self.path, &backup);
    }
}

/// Parse the access log file and return structured entries for the admin dashboard.
pub fn parse_log_file(path: &Path) -> Vec<HashMap<String, Value>> {
    let contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    let mut entries = Vec::new();

    for line in contents.lines() {
        // Log lines may have a leading timestamp prefix from the logging module;
        // find the first `{` and treat everything from there as JSON.
        let json_start = match line.find('{') {
            Some(i) => i,
            None => continue,
        };
        let json_part = &line[json_start..];

        if let Ok(obj) = serde_json::from_str::<HashMap<String, Value>>(json_part) {
            let user = obj.get("user").and_then(|v| v.as_str());
            let entry = {
                let mut e: HashMap<String, Value> = HashMap::new();
                e.insert("timestamp".into(), obj.get("timestamp").cloned().unwrap_or(Value::Null));
                e.insert("ip".into(), obj.get("ip").cloned().unwrap_or(Value::Null));
                e.insert(
                    "user".into(),
                    if user == Some("UNKNOWN") {
                        Value::Null
                    } else {
                        obj.get("user").cloned().unwrap_or(Value::Null)
                    },
                );
                e.insert("status".into(), obj.get("status").cloned().unwrap_or(Value::Null));
                e.insert("details".into(), obj.get("details").cloned().unwrap_or(Value::Null));
                e
            };
            entries.push(entry);
        }
    }
    entries
}

/// Rewrite the log file keeping only lines that do NOT contain "TEST MODE" in their details.
pub fn filter_test_entries(path: &Path) -> std::io::Result<(usize, usize)> {
    let contents = std::fs::read_to_string(path).unwrap_or_default();
    let mut kept = Vec::new();
    let mut removed = 0usize;

    for line in contents.lines() {
        let json_start = line.find('{');
        let is_test = json_start
            .and_then(|i| serde_json::from_str::<HashMap<String, Value>>(&line[i..]).ok())
            .and_then(|obj| obj.get("details")?.as_str().map(|d| d.contains("TEST MODE")))
            .unwrap_or(false);

        if is_test {
            removed += 1;
        } else {
            kept.push(line);
        }
    }

    let kept_count = kept.len();
    // Atomic write
    let tmp = path.with_extension("log.tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        for line in &kept {
            writeln!(f, "{}", line)?;
        }
    }
    std::fs::rename(&tmp, path)?;
    Ok((removed, kept_count))
}

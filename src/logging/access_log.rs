use std::path::PathBuf;
use tokio::sync::mpsc;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use chrono::Local;
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub timestamp: chrono::DateTime<Local>,
    pub ip: IpAddr,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub user_agent: Option<String>,
    pub referer: Option<String>,
    pub response_time_ms: u64,
}

pub struct AccessLogger {
    tx: mpsc::UnboundedSender<LogEntry>,
}

impl AccessLogger {
    pub fn new(log_path: PathBuf, format: LogFormat) -> Self {
        let (tx, mut rx) = mpsc::unbounded_channel::<LogEntry>();

        // Spawn background task to write logs
        tokio::spawn(async move {
            // Open log file in append mode
            let mut file = match OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)
                .await
            {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("❌ Failed to open log file {:?}: {}", log_path, e);
                    return;
                }
            };

            println!("📝 Logging to: {:?}", log_path);

            while let Some(entry) = rx.recv().await {
                let log_line = match format {
                    LogFormat::Combined => Self::format_combined(&entry),
                    LogFormat::Common => Self::format_common(&entry),
                    LogFormat::Json => Self::format_json(&entry),
                };

                if let Err(e) = file.write_all(log_line.as_bytes()).await {
                    eprintln!("❌ Failed to write to log: {}", e);
                }
            }
        });

        Self { tx }
    }

    /// Log an access entry
    pub fn log(&self, entry: LogEntry) {
        // Also print to stdout if desired
        if cfg!(debug_assertions) {
            println!("{} {} {} {}", entry.ip, entry.method, entry.path, entry.status);
        }

        if let Err(e) = self.tx.send(entry) {
            eprintln!("Failed to send log entry: {}", e);
        }
    }

    /// Apache Combined Log Format
    /// 127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.0" 200 2326 "http://example.com/" "Mozilla/5.0"
    fn format_combined(entry: &LogEntry) -> String {
        format!(
            "{} - - [{}] \"{} {} HTTP/1.1\" {} - \"{}\" \"{}\"\n",
            entry.ip,
            entry.timestamp.format("%d/%b/%Y:%H:%M:%S %z"),
            entry.method,
            entry.path,
            entry.status,
            entry.referer.as_deref().unwrap_or("-"),
            entry.user_agent.as_deref().unwrap_or("-"),
        )
    }

    /// Apache Common Log Format
    /// 127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.0" 200 2326
    fn format_common(entry: &LogEntry) -> String {
        format!(
            "{} - - [{}] \"{} {} HTTP/1.1\" {} -\n",
            entry.ip,
            entry.timestamp.format("%d/%b/%Y:%H:%M:%S %z"),
            entry.method,
            entry.path,
            entry.status,
        )
    }

    /// JSON Format (one line per request)
    fn format_json(entry: &LogEntry) -> String {
        format!(
            r#"{{"timestamp":"{}","ip":"{}","method":"{}","path":"{}","status":{},"user_agent":"{}","referer":"{}","response_time_ms":{}}}"#,
            entry.timestamp.to_rfc3339(),
            entry.ip,
            entry.method,
            entry.path,
            entry.status,
            entry.user_agent.as_deref().unwrap_or(""),
            entry.referer.as_deref().unwrap_or(""),
            entry.response_time_ms,
        ) + "\n"
    }
}

#[derive(Debug, Clone, Copy)]
pub enum LogFormat {
    Combined,  // Apache combined format
    Common,    // Apache common format
    Json,      // JSON lines
}

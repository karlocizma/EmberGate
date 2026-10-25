//! Optional access log in nginx "combined" format, so CrowdSec's nginx parsers
//! and HTTP scenarios can read EmberGate traffic unchanged. A background
//! thread writes and rotates the file; the proxy never blocks on it.
use crate::state::{AccessLog, Shared};
use axum::{extract::State, http::StatusCode, routing::get, Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    fs::{File, OpenOptions},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{sync_channel, Receiver, SyncSender, TrySendError},
    },
    time::Duration,
};

const SECRET: &str = "access_log_enabled";
const FILE_NAME: &str = "access.log";
const ROTATE_BYTES: u64 = 50 * 1024 * 1024;
const KEEP: usize = 3;

pub struct AccessLogFile {
    enabled: AtomicBool,
    dropped: AtomicU64,
    directory: PathBuf,
    sender: SyncSender<String>,
}

impl AccessLogFile {
    pub fn start(directory: PathBuf, enabled: bool) -> std::io::Result<Self> {
        // CrowdSec only follows files that exist when its agent starts, so
        // create the file up front even while logging is off.
        if let Err(error) = open(&directory) {
            log::warn!(
                "Access log directory {} is not writable: {error}",
                directory.display()
            );
        }
        let (sender, receiver) = sync_channel(8192);
        let writer_directory = directory.clone();
        std::thread::Builder::new()
            .name("gateway-access-log".into())
            .spawn(move || worker(&writer_directory, receiver))?;
        Ok(Self {
            enabled: AtomicBool::new(enabled),
            dropped: AtomicU64::new(0),
            directory,
            sender,
        })
    }

    pub fn path(&self) -> PathBuf {
        self.directory.join(FILE_NAME)
    }

    /// Queues one request. Lines are dropped and counted, never blocking
    /// traffic, when the writer falls behind.
    pub fn write(
        &self,
        entry: &AccessLog,
        user_agent: Option<&str>,
        referer: Option<&str>,
        bytes: usize,
    ) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }
        match self
            .sender
            .try_send(line(entry, user_agent, referer, bytes))
        {
            Ok(()) => {}
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

fn worker(directory: &Path, receiver: Receiver<String>) {
    let mut file: Option<(BufWriter<File>, u64)> = None;
    while let Ok(first) = receiver.recv() {
        // Write everything queued, then flush once so CrowdSec sees lines promptly.
        let mut next = Some(first);
        while let Some(line) = next.take() {
            if file.is_none() {
                match open(directory) {
                    Ok(opened) => file = Some(opened),
                    Err(error) => {
                        log::error!("Access log unavailable at {}: {error}", directory.display());
                        std::thread::sleep(Duration::from_secs(5));
                        break;
                    }
                }
            }
            let (writer, size) = file.as_mut().expect("open access log");
            if writer.write_all(line.as_bytes()).is_err() {
                file = None;
            } else {
                *size += line.len() as u64;
                if *size >= ROTATE_BYTES {
                    let _ = writer.flush();
                    file = None;
                    if let Err(error) = rotate(directory) {
                        log::error!("Access log rotation failed: {error}");
                    }
                }
            }
            next = receiver.try_recv().ok();
        }
        if let Some((writer, _)) = file.as_mut() {
            let _ = writer.flush();
        }
    }
}

fn open(directory: &Path) -> std::io::Result<(BufWriter<File>, u64)> {
    std::fs::create_dir_all(directory)?;
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    // Readable by a CrowdSec agent sharing the volume; it holds no secrets or query strings.
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o644);
    let file = options.open(directory.join(FILE_NAME))?;
    let size = file.metadata()?.len();
    Ok((BufWriter::new(file), size))
}

/// Shifts access.log → access.log.1 → … keeping `KEEP` old files.
fn rotate(directory: &Path) -> std::io::Result<()> {
    let name = |n: usize| directory.join(format!("{FILE_NAME}.{n}"));
    let _ = std::fs::remove_file(name(KEEP));
    for n in (1..KEEP).rev() {
        if name(n).exists() {
            std::fs::rename(name(n), name(n + 1))?;
        }
    }
    std::fs::rename(directory.join(FILE_NAME), name(1))
}

/// Escapes like nginx: quotes, backslashes, and non-printable bytes as \xHH.
fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes().take(1024) {
        match byte {
            b'"' | b'\\' | 0..=0x1f | 0x7f..=0xff => out.push_str(&format!("\\x{byte:02X}")),
            _ => out.push(byte as char),
        }
    }
    out
}

fn field(value: Option<&str>) -> String {
    value
        .filter(|v| !v.is_empty())
        .map_or_else(|| "-".into(), escape)
}

/// `25/Oct/2026:14:01:35 +0000` from a Unix timestamp, in UTC.
fn time_local(timestamp: u64) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = (timestamp / 86400) as i64;
    let seconds = timestamp % 86400;
    // Howard Hinnant's civil-from-days algorithm.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{day:02}/{}/{year}:{:02}:{:02}:{:02} +0000",
        MONTHS[(month - 1) as usize],
        seconds / 3600,
        seconds % 3600 / 60,
        seconds % 60
    )
}

pub fn line(
    entry: &AccessLog,
    user_agent: Option<&str>,
    referer: Option<&str>,
    bytes: usize,
) -> String {
    let address = entry
        .client_ip
        .as_deref()
        .or(entry.peer_ip.as_deref())
        .unwrap_or("-");
    // Referers can carry another site's secrets in their query; keep the path only.
    let referer = referer.map(|r| r.split(['?', '#']).next().unwrap_or_default());
    format!(
        "{address} - - [{}] \"{} {} HTTP/1.1\" {} {bytes} \"{}\" \"{}\"\n",
        time_local(entry.timestamp),
        escape(&entry.method),
        escape(&entry.path),
        entry.status,
        field(referer),
        field(user_agent),
    )
}

pub fn initially_enabled(control: &crate::management::Control) -> Result<bool, String> {
    Ok(control.secret(SECRET)?.as_deref() == Some("true"))
}

pub fn validate_backup(value: &str) -> Result<(), String> {
    (value == "true")
        .then_some(())
        .ok_or_else(|| "Invalid access log setting.".into())
}

pub fn status_json(state: &Shared) -> Value {
    let log = &state.access_log;
    json!({
        "enabled": log.enabled.load(Ordering::Relaxed),
        "path": log.path().display().to_string(),
        "dropped": log.dropped.load(Ordering::Relaxed),
        "size_bytes": std::fs::metadata(log.path()).map(|m| m.len()).ok(),
        "rotate_bytes": ROTATE_BYTES,
        "keep": KEEP,
    })
}

async fn status(State(state): State<Shared>) -> Json<Value> {
    Json(status_json(&state))
}

#[derive(Deserialize)]
struct Settings {
    enabled: bool,
}

async fn save(
    State(state): State<Shared>,
    Json(input): Json<Settings>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    state
        .control
        .set_secret(SECRET.into(), input.enabled.then(|| "true".to_owned()))
        .await
        .map_err(|e| (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error":e}))))?;
    state
        .access_log
        .enabled
        .store(input.enabled, Ordering::Relaxed);
    Ok(Json(status_json(&state)))
}

pub fn routes() -> Router<Shared> {
    Router::new().route("/api/integrations/access-log", get(status).put(save))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> AccessLog {
        serde_json::from_value(json!({
            "timestamp": 1_792_850_495u64, "route_id": null, "client_ip": "203.0.113.9", "peer_ip": "10.0.0.2",
            "identity_source": "peer", "access_denied": false, "method": "GET", "host": "app.test",
            "path": "/wp-login.php", "route": null, "upstream": null, "rate_limited": false,
            "status": 404, "latency_ms": 1.0
        }))
        .unwrap()
    }

    #[test]
    fn lines_match_nginx_combined_format() {
        assert_eq!(
            line(&entry(), Some("Mozilla/5.0 \"evil\"\n"), Some("https://other.test/page?token=secret"), 153),
            "203.0.113.9 - - [24/Oct/2026:14:01:35 +0000] \"GET /wp-login.php HTTP/1.1\" 404 153 \"https://other.test/page\" \"Mozilla/5.0 \\x22evil\\x22\\x0A\"\n"
        );
        let mut anonymous = entry();
        anonymous.client_ip = None;
        assert!(line(&anonymous, None, Some(""), 0).starts_with("10.0.0.2 - - "));
        assert!(line(&anonymous, None, None, 0).ends_with(" 0 \"-\" \"-\"\n"));
    }

    #[test]
    fn dates_convert_across_leap_years() {
        assert_eq!(time_local(0), "01/Jan/1970:00:00:00 +0000");
        assert_eq!(time_local(951_782_400), "29/Feb/2000:00:00:00 +0000");
        assert_eq!(time_local(4_133_980_799), "31/Dec/2100:23:59:59 +0000");
    }

    #[test]
    fn writes_only_when_enabled_and_rotates() {
        let directory =
            std::env::temp_dir().join(format!("embergate-access-{}", uuid::Uuid::new_v4()));
        let log = AccessLogFile::start(directory.clone(), false).unwrap();
        log.write(&entry(), None, None, 1);
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(
            std::fs::read(log.path()).unwrap(),
            b"",
            "disabled logs write nothing"
        );
        log.enabled.store(true, Ordering::Relaxed);
        log.write(&entry(), Some("curl/8"), None, 1);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::fs::read_to_string(log.path())
            .unwrap_or_default()
            .is_empty()
        {
            assert!(std::time::Instant::now() < deadline, "line was not flushed");
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(std::fs::read_to_string(log.path())
            .unwrap()
            .contains("\"curl/8\""));
        for n in 1..=4 {
            std::fs::write(directory.join(format!("{FILE_NAME}.{n}")), n.to_string()).unwrap();
        }
        rotate(&directory).unwrap();
        assert!(!log.path().exists());
        assert!(std::fs::read_to_string(directory.join("access.log.1"))
            .unwrap()
            .contains("curl/8"));
        assert_eq!(
            std::fs::read_to_string(directory.join("access.log.3")).unwrap(),
            "2"
        );
        std::fs::remove_dir_all(directory).unwrap();
    }
}

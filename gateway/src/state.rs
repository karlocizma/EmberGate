use crate::config::Config;
use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AccessLog {
    pub timestamp: u64,
    pub route_id: Option<String>,
    pub client_ip: Option<String>,
    pub peer_ip: Option<String>,
    pub identity_source: String,
    pub access_denied: bool,
    #[serde(default)]
    pub crowdsec_blocked: bool,
    pub method: String,
    pub host: String,
    pub path: String,
    pub route: Option<String>,
    pub upstream: Option<String>,
    #[serde(default)]
    pub attempted_upstreams: Vec<String>,
    #[serde(default)]
    pub maintenance: bool,
    pub rate_limited: bool,
    #[serde(default)]
    pub cache_status: String,
    pub status: u16,
    pub latency_ms: f64,
}

#[derive(Clone, Serialize)]
pub struct Bucket {
    pub timestamp: u64,
    pub requests: u64,
    pub errors: u64,
}

#[derive(Default)]
pub struct Metrics {
    pub prometheus: crate::prometheus::Counters,
    pub requests: u64,
    pub errors: u64,
    pub rate_limited: u64,
    pub latency_total_ms: f64,
    pub buckets: VecDeque<Bucket>,
}
impl Metrics {
    pub fn record(&mut self, entry: &AccessLog) {
        self.prometheus.record(entry);
        self.requests += 1;
        self.errors += u64::from(entry.status >= 500);
        self.rate_limited += u64::from(entry.rate_limited);
        self.latency_total_ms += entry.latency_ms;
        let minute = entry.timestamp / 60 * 60;
        if self.buckets.back().map(|b| b.timestamp) != Some(minute) {
            self.buckets.push_back(Bucket {
                timestamp: minute,
                requests: 0,
                errors: 0,
            });
        }
        let bucket = self.buckets.back_mut().unwrap();
        bucket.requests += 1;
        bucket.errors += u64::from(entry.status >= 500);
        while self
            .buckets
            .front()
            .is_some_and(|b| b.timestamp + 3600 <= minute)
        {
            self.buckets.pop_front();
        }
    }
}

pub struct AppState {
    pub backups: crate::backup::Manager,
    pub http_cache: &'static crate::cache::ResponseCache,
    pub analytics: crate::analytics::Analytics,
    pub rate_limits: crate::rate_limit::RateLimits,
    pub crowdsec: crate::crowdsec::Bouncer,
    pub upstreams: crate::upstreams::Upstreams,
    pub acme: crate::acme::Acme,
    pub config: ArcSwap<Config>,
    pub certificates: ArcSwap<crate::certificates::CertificateStore>,
    pub certificates_path: PathBuf,
    pub write_lock: tokio::sync::Mutex<()>,
    pub metrics: Mutex<Metrics>,
    pub sessions: Mutex<HashMap<String, crate::accounts::Session>>,
    pub control: crate::management::Control,
    pub account_write_lock: tokio::sync::Mutex<()>,
    pub login_attempts: Mutex<HashMap<String, VecDeque<Instant>>>,
    pub password_hash: Option<String>,
    pub dummy_password_hash: String,
    pub setup_token: Option<String>,
    pub config_path: PathBuf,
    pub proxy_addr: String,
    pub admin_addr: String,
    pub https_addr: Option<String>,
    pub secure_cookie: bool,
    pub started: Instant,
}
pub type Shared = Arc<AppState>;

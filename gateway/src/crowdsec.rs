//! CrowdSec Local API decision-stream bouncer.
use crate::{management::Control, state::Shared};
use ipnet::IpNet;
use serde::Deserialize;
use std::{
    net::IpAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, RwLock,
    },
    time::Duration,
};
use tokio::time::MissedTickBehavior;

/// What a CrowdSec decision asks EmberGate to do with a visitor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Remedy {
    Ban,
    Captcha,
}
impl Remedy {
    fn parse(kind: &str) -> Option<Self> {
        match kind {
            "ban" => Some(Self::Ban),
            "captcha" => Some(Self::Captcha),
            _ => None,
        }
    }
}

#[derive(Clone)]
pub struct Bouncer {
    decisions: Arc<RwLock<Vec<(IpNet, Remedy)>>>,
    /// Decision types EmberGate does not enforce, with how often each arrived.
    unknown: Arc<RwLock<std::collections::BTreeMap<String, u64>>>,
    pub remediation: Arc<arc_swap::ArcSwap<crate::captcha::Remediation>>,
    status: Arc<RwLock<Status>>,
    startup: Arc<AtomicBool>,
}
impl Default for Bouncer {
    fn default() -> Self {
        Self {
            decisions: Arc::default(),
            unknown: Arc::default(),
            remediation: Arc::default(),
            status: Arc::default(),
            startup: Arc::new(AtomicBool::new(true)),
        }
    }
}
#[derive(Clone, Default, serde::Serialize)]
pub struct Status {
    pub configured: bool,
    pub connected: bool,
    pub decisions: usize,
    pub bans: usize,
    pub captchas: usize,
    pub unknown_types: std::collections::BTreeMap<String, u64>,
    pub last_sync: Option<u64>,
    pub error: Option<String>,
}
#[derive(Deserialize)]
struct Stream {
    // The Local API sends `null` rather than `[]` when a list is empty.
    #[serde(default, deserialize_with = "nullable")]
    new: Vec<Decision>,
    #[serde(default, deserialize_with = "nullable")]
    deleted: Vec<Decision>,
}
fn nullable<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Vec<Decision>, D::Error> {
    Ok(Option::<Vec<Decision>>::deserialize(deserializer)?.unwrap_or_default())
}
#[derive(Clone, Deserialize)]
struct Decision {
    #[serde(default)]
    scope: String,
    #[serde(default)]
    value: String,
    #[serde(rename = "type", default)]
    kind: String,
}

impl Bouncer {
    /// The strongest decision covering `ip`: a ban outranks a captcha.
    pub fn remedy(&self, ip: IpAddr) -> Option<Remedy> {
        let decisions = self.decisions.read().ok()?;
        let mut matching = decisions
            .iter()
            .filter(|(n, _)| n.contains(&ip))
            .map(|(_, r)| *r);
        let first = matching.next()?;
        Some(
            if first == Remedy::Ban || matching.any(|r| r == Remedy::Ban) {
                Remedy::Ban
            } else {
                Remedy::Captcha
            },
        )
    }
    #[cfg(test)]
    pub fn blocks(&self, ip: IpAddr) -> bool {
        self.remedy(ip).is_some()
    }
    pub fn status(&self) -> Status {
        let mut status = self.status.read().map(|s| s.clone()).unwrap_or_default();
        status.unknown_types = self.unknown.read().map(|u| u.clone()).unwrap_or_default();
        status
    }
    pub async fn configure(
        &self,
        control: &Control,
        url: String,
        key: String,
    ) -> Result<(), String> {
        let url = url.trim().trim_end_matches('/').to_owned();
        let parsed = url::Url::parse(&url).map_err(|_| "Enter a valid CrowdSec Local API URL.")?;
        if !matches!(parsed.scheme(), "http" | "https")
            || parsed.host_str().is_none()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err("CrowdSec URL must be an HTTP(S) origin or API base path.".into());
        }
        if key.trim().is_empty() || key.len() > 4096 {
            return Err("Enter a valid bouncer API key.".into());
        }
        control.set_secret("crowdsec_url".into(), Some(url)).await?;
        control
            .set_secret("crowdsec_bouncer_key".into(), Some(key.trim().into()))
            .await?;
        self.startup.store(true, Ordering::SeqCst);
        *self
            .status
            .write()
            .map_err(|_| "CrowdSec status unavailable.")? = Status {
            configured: true,
            ..Status::default()
        };
        *self
            .decisions
            .write()
            .map_err(|_| "CrowdSec cache unavailable.")? = Vec::new();
        self.unknown
            .write()
            .map_err(|_| "CrowdSec cache unavailable.")?
            .clear();
        Ok(())
    }
    pub async fn remove(&self, control: &Control) -> Result<(), String> {
        control.set_secret("crowdsec_url".into(), None).await?;
        control
            .set_secret("crowdsec_bouncer_key".into(), None)
            .await?;
        self.startup.store(true, Ordering::SeqCst);
        *self
            .decisions
            .write()
            .map_err(|_| "CrowdSec cache unavailable.")? = Vec::new();
        self.unknown
            .write()
            .map_err(|_| "CrowdSec cache unavailable.")?
            .clear();
        *self
            .status
            .write()
            .map_err(|_| "CrowdSec status unavailable.")? = Status::default();
        Ok(())
    }
    pub async fn sync_once(&self, url: &str, key: &str, startup: bool) -> Result<(), String> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| "Could not initialize CrowdSec client.")?;
        let response = client
            .get(format!(
                "{}/v1/decisions/stream?startup={}",
                url.trim_end_matches('/'),
                startup
            ))
            .header("X-Api-Key", key)
            .send()
            .await
            .map_err(|_| "Could not connect to CrowdSec Local API.")?;
        if !response.status().is_success() {
            return Err(format!(
                "CrowdSec Local API returned HTTP {}.",
                response.status().as_u16()
            ));
        }
        let stream: Stream = response
            .json()
            .await
            .map_err(|_| "CrowdSec returned an invalid decision stream.")?;
        let mut cache = self
            .decisions
            .write()
            .map_err(|_| "CrowdSec cache unavailable.")?;
        // Startup streams are complete snapshots, which also prune bans that expired while the
        // Local API was unreachable. Incremental streams only apply deltas.
        if startup {
            cache.clear();
        }
        let network = |d: &Decision| {
            d.value
                .parse::<IpNet>()
                .or_else(|_| d.value.parse::<IpAddr>().map(IpNet::from))
                .ok()
        };
        for d in &stream.deleted {
            if let Some(n) = network(d) {
                let remedy = Remedy::parse(&d.kind);
                cache.retain(|(v, r)| !(*v == n && remedy.is_none_or(|remedy| remedy == *r)));
            }
        }
        let mut unknown = self
            .unknown
            .write()
            .map_err(|_| "CrowdSec cache unavailable.")?;
        for d in &stream.new {
            if !matches!(d.scope.as_str(), "Ip" | "Range") {
                continue;
            }
            let Some(remedy) = Remedy::parse(&d.kind) else {
                let count = unknown
                    .entry(d.kind.chars().take(64).collect())
                    .or_default();
                if *count == 0 {
                    log::warn!("CrowdSec decision type {:?} is not enforced by EmberGate; these visitors are allowed.", d.kind);
                }
                *count += 1;
                continue;
            };
            if let Some(n) = network(d) {
                if !cache.contains(&(n, remedy)) {
                    cache.push((n, remedy));
                }
            }
        }
        drop(unknown);
        let count = cache.len();
        let bans = cache.iter().filter(|(_, r)| *r == Remedy::Ban).count();
        drop(cache);
        *self
            .status
            .write()
            .map_err(|_| "CrowdSec status unavailable.")? = Status {
            configured: true,
            connected: true,
            decisions: count,
            bans,
            captchas: count - bans,
            unknown_types: Default::default(),
            last_sync: Some(crate::state::now()),
            error: None,
        };
        Ok(())
    }
}
pub struct Synchronizer(pub Shared);
#[async_trait::async_trait]
impl pingora::services::background::BackgroundService for Synchronizer {
    async fn start(&self, mut shutdown: pingora::server::ShutdownWatch) {
        let mut ticker = tokio::time::interval(Duration::from_secs(10));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tokio::select! { _=shutdown.changed()=>break, _=ticker.tick()=>{
             let url=self.0.control.secret("crowdsec_url").ok().flatten(); let key=self.0.control.secret("crowdsec_bouncer_key").ok().flatten();
             if let (Some(url),Some(key))=(url,key){ let startup=self.0.crowdsec.startup.swap(false,Ordering::SeqCst); if let Err(e)=self.0.crowdsec.sync_once(&url,&key,startup).await { self.0.crowdsec.startup.store(true,Ordering::SeqCst); if let Ok(mut s)=self.0.crowdsec.status.write(){s.configured=true;s.connected=false;s.error=Some(e);} } }
            }}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn blocks_ipv4_and_ipv6_networks_without_blocking_neighbors() {
        let bouncer = Bouncer::default();
        *bouncer.decisions.write().unwrap() = vec![
            ("192.0.2.0/24".parse().unwrap(), Remedy::Ban),
            ("2001:db8::/48".parse().unwrap(), Remedy::Ban),
        ];
        assert!(bouncer.blocks("192.0.2.42".parse().unwrap()));
        assert!(!bouncer.blocks("192.0.3.42".parse().unwrap()));
        assert!(bouncer.blocks("2001:db8::5".parse().unwrap()));
        assert!(!bouncer.blocks("2001:db9::5".parse().unwrap()));
    }

    /// Serves each body once, in order, as a Local API decision stream.
    fn lapi(bodies: Vec<&'static str>) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for body in bodies {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0u8; 2048];
                let _ = std::io::Read::read(&mut stream, &mut request);
                let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                std::io::Write::write_all(&mut stream, response.as_bytes()).unwrap();
            }
        });
        format!("http://{address}")
    }

    #[tokio::test]
    async fn decision_streams_keep_types_and_tolerate_null_lists() {
        let url = lapi(vec![
            r#"{"new":null,"deleted":null}"#,
            r#"{"new":[{"scope":"Ip","value":"203.0.113.7","type":"captcha"},{"scope":"Ip","value":"203.0.113.8","type":"captcha"},{"scope":"Range","value":"198.51.100.0/24","type":"ban"},{"scope":"Ip","value":"198.51.100.9","type":"captcha"},{"scope":"Ip","value":"192.0.2.1","type":"throttle"},{"scope":"Ip","value":"192.0.2.2","type":"throttle"},{"scope":"Country","value":"XX","type":"ban"}],"deleted":null}"#,
            r#"{"new":null,"deleted":[{"scope":"Ip","value":"203.0.113.8","type":"ban"},{"scope":"Ip","value":"203.0.113.7","type":"captcha"}]}"#,
        ]);
        let bouncer = Bouncer::default();
        bouncer.sync_once(&url, "key", true).await.unwrap();
        assert_eq!(bouncer.status().decisions, 0, "null lists are empty lists");
        bouncer.sync_once(&url, "key", false).await.unwrap();
        assert_eq!(
            bouncer.remedy("203.0.113.7".parse().unwrap()),
            Some(Remedy::Captcha)
        );
        assert_eq!(
            bouncer.remedy("198.51.100.9".parse().unwrap()),
            Some(Remedy::Ban),
            "a ban outranks a captcha"
        );
        assert_eq!(
            bouncer.remedy("192.0.2.1".parse().unwrap()),
            None,
            "unknown types are not enforced"
        );
        let status = bouncer.status();
        assert_eq!((status.decisions, status.bans, status.captchas), (4, 1, 3));
        assert_eq!(status.unknown_types.get("throttle"), Some(&2));
        bouncer.sync_once(&url, "key", false).await.unwrap();
        assert_eq!(
            bouncer.remedy("203.0.113.7".parse().unwrap()),
            None,
            "deleted by type"
        );
        assert_eq!(
            bouncer.remedy("203.0.113.8".parse().unwrap()),
            Some(Remedy::Captcha),
            "a ban deletion keeps the captcha"
        );
    }
}

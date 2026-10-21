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

#[derive(Clone)]
pub struct Bouncer {
    decisions: Arc<RwLock<Vec<IpNet>>>,
    status: Arc<RwLock<Status>>,
    startup: Arc<AtomicBool>,
}
impl Default for Bouncer {
    fn default() -> Self {
        Self {
            decisions: Arc::default(),
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
    pub last_sync: Option<u64>,
    pub error: Option<String>,
}
#[derive(Deserialize)]
struct Stream {
    #[serde(default)]
    new: Vec<Decision>,
    #[serde(default)]
    deleted: Vec<Decision>,
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
    pub fn blocks(&self, ip: IpAddr) -> bool {
        self.decisions
            .read()
            .map(|items| items.iter().any(|n| n.contains(&ip)))
            .unwrap_or(false)
    }
    pub fn status(&self) -> Status {
        self.status.read().map(|s| s.clone()).unwrap_or_default()
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
        for d in stream.deleted {
            if let Ok(n) = d.value.parse::<IpNet>() {
                cache.retain(|v| *v != n);
            } else if let Ok(ip) = d.value.parse::<IpAddr>() {
                cache.retain(|v| !(*v == IpNet::from(ip)));
            }
        }
        for d in stream.new {
            if d.kind == "ban" && matches!(d.scope.as_str(), "Ip" | "Range") {
                if let Ok(n) = d
                    .value
                    .parse::<IpNet>()
                    .or_else(|_| d.value.parse::<IpAddr>().map(IpNet::from))
                {
                    if !cache.contains(&n) {
                        cache.push(n);
                    }
                }
            }
        }
        let count = cache.len();
        drop(cache);
        *self
            .status
            .write()
            .map_err(|_| "CrowdSec status unavailable.")? = Status {
            configured: true,
            connected: true,
            decisions: count,
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
            "192.0.2.0/24".parse().unwrap(),
            "2001:db8::/48".parse().unwrap(),
        ];
        assert!(bouncer.blocks("192.0.2.42".parse().unwrap()));
        assert!(!bouncer.blocks("192.0.3.42".parse().unwrap()));
        assert!(bouncer.blocks("2001:db8::5".parse().unwrap()));
        assert!(!bouncer.blocks("2001:db9::5".parse().unwrap()));
    }
}

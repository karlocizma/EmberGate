//! Live origin selection and bounded, asynchronous HTTP health probes.
use crate::{
    config::{Config, HealthCheck, Route, Strategy},
    state::{now, Shared},
};
use async_trait::async_trait;
use pingora::{server::ShutdownWatch, services::background::BackgroundService};
use serde::Serialize;
use std::{
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, Weak,
    },
    time::{Duration, Instant},
};

#[derive(Clone, Serialize)]
pub struct BackendStatus {
    pub upstream: String,
    pub status: &'static str,
    pub checked_at: Option<u64>,
    pub latency_ms: Option<f64>,
    pub detail: Option<String>,
    pub weight: u16,
    pub draining: bool,
    pub active_requests: usize,
    #[serde(skip)]
    active: Arc<AtomicUsize>,
    #[serde(skip)]
    healthy: bool,
    #[serde(skip)]
    successes: u32,
    #[serde(skip)]
    failures: u32,
    #[serde(skip)]
    due: Option<Instant>,
    #[serde(skip)]
    in_flight: bool,
}
struct Pool {
    backends: Vec<BackendStatus>,
    cursor: usize,
    current_weights: Vec<i64>,
    weights: Vec<u16>,
}
#[derive(Default)]
pub struct Upstreams {
    pools: Mutex<HashMap<String, Pool>>,
    activity: Mutex<HashMap<(String, String), Weak<AtomicUsize>>>,
}
pub struct Lease {
    pub origin: String,
    active: Arc<AtomicUsize>,
}
impl Drop for Lease {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
    }
}

// A changed origin, hostname, or probe policy must never inherit old probe results.
fn key(route: &Route) -> String {
    serde_json::to_string(&(
        &route.id,
        &route.upstream,
        &route.additional_upstreams,
        &route.health_check,
        &route.host,
        route.preserve_host,
        route.enabled,
    ))
    .unwrap()
}
fn pool(route: &Route, activity: &mut HashMap<(String, String), Weak<AtomicUsize>>) -> Pool {
    Pool {
        cursor: 0,
        current_weights: vec![0; route.origins().count()],
        weights: vec![],
        backends: route
            .origins()
            .map(|origin| BackendStatus {
                upstream: origin.clone(),
                status: if route.health_check.is_some() {
                    "pending"
                } else {
                    "unchecked"
                },
                checked_at: None,
                latency_ms: None,
                detail: None,
                weight: 1,
                draining: false,
                active_requests: 0,
                active: {
                    let key = (route.id.clone(), origin.clone());
                    let active = activity
                        .get(&key)
                        .and_then(Weak::upgrade)
                        .unwrap_or_else(|| Arc::new(AtomicUsize::new(0)));
                    activity.insert(key, Arc::downgrade(&active));
                    active
                },
                healthy: route.health_check.is_none(),
                successes: 0,
                failures: 0,
                due: route.health_check.as_ref().map(|_| Instant::now()),
                in_flight: false,
            })
            .collect(),
    }
}
impl Upstreams {
    fn new_pool(&self, route: &Route) -> Pool {
        let mut activity = self.activity.lock().unwrap();
        activity.retain(|_, value| value.strong_count() > 0);
        pool(route, &mut activity)
    }
    #[cfg(test)]
    pub fn select(&self, route: &Route) -> Option<String> {
        self.select_request(route, None, &[])
            .map(|lease| lease.origin.clone())
    }
    pub fn select_request(
        &self,
        route: &Route,
        client: Option<std::net::IpAddr>,
        excluded: &[String],
    ) -> Option<Lease> {
        if !route.enabled {
            return None;
        }
        let mut pools = self.pools.lock().unwrap();
        let pool = pools
            .entry(key(route))
            .or_insert_with(|| self.new_pool(route));
        let policy = route.balancing.clone().unwrap_or_default();
        let weights = if policy.weights.is_empty() {
            vec![1; pool.backends.len()]
        } else {
            policy.weights
        };
        if pool.weights != weights {
            pool.weights = weights.clone();
            pool.current_weights.fill(0);
        }
        let eligible: Vec<_> = (0..pool.backends.len())
            .filter(|&i| {
                pool.backends[i].healthy
                    && !policy.draining.contains(&pool.backends[i].upstream)
                    && !excluded.contains(&pool.backends[i].upstream)
            })
            .collect();
        if eligible.is_empty() {
            return None;
        }
        let cyclic: Vec<_> = (0..pool.backends.len())
            .map(|offset| (pool.cursor + offset) % pool.backends.len())
            .filter(|i| eligible.contains(i))
            .collect();
        let index = match policy.strategy {
            Strategy::WeightedRoundRobin => {
                let mut best = cyclic[0];
                let mut total = 0;
                for i in 0..pool.backends.len() {
                    if !eligible.contains(&i) {
                        pool.current_weights[i] = 0;
                        continue;
                    }
                    let weight = i64::from(weights[i]);
                    pool.current_weights[i] += weight;
                    total += weight;
                }
                for &i in &cyclic {
                    if pool.current_weights[i] > pool.current_weights[best] {
                        best = i
                    }
                }
                pool.current_weights[best] -= total;
                best
            }
            Strategy::LeastConnections => {
                let mut best = cyclic[0];
                for &i in &cyclic {
                    let left = pool.backends[i].active.load(Ordering::Relaxed) as u128
                        * u128::from(weights[best]);
                    let right = pool.backends[best].active.load(Ordering::Relaxed) as u128
                        * u128::from(weights[i]);
                    if left < right {
                        best = i
                    }
                }
                best
            }
            Strategy::ClientIpHash if client.is_some() => {
                let client = client.unwrap().to_string();
                let mut best = cyclic[0];
                let mut score = f64::INFINITY;
                for &i in &eligible {
                    let bytes = openssl::sha::sha256(
                        format!("{client}|{}", pool.backends[i].upstream).as_bytes(),
                    );
                    let hash = u64::from_be_bytes(bytes[..8].try_into().unwrap());
                    let uniform = (hash as f64 + 1.) / (u64::MAX as f64 + 2.);
                    let candidate = -uniform.ln() / f64::from(weights[i]);
                    if candidate < score {
                        best = i;
                        score = candidate;
                    }
                }
                best
            }
            _ => cyclic[0],
        };
        pool.cursor = (index + 1) % pool.backends.len();
        let backend = &pool.backends[index];
        backend.active.fetch_add(1, Ordering::Relaxed);
        Some(Lease {
            origin: backend.upstream.clone(),
            active: backend.active.clone(),
        })
    }
    pub fn snapshot(&self, config: &Config) -> HashMap<String, Vec<BackendStatus>> {
        let mut pools = self.pools.lock().unwrap();
        config
            .routes
            .iter()
            .map(|route| {
                let pool = pools
                    .entry(key(route))
                    .or_insert_with(|| self.new_pool(route));
                let mut statuses = pool.backends.clone();
                for (index, status) in statuses.iter_mut().enumerate() {
                    status.active_requests = status.active.load(Ordering::Relaxed);
                    status.weight = route
                        .balancing
                        .as_ref()
                        .and_then(|p| p.weights.get(index))
                        .copied()
                        .unwrap_or(1);
                    status.draining = route
                        .balancing
                        .as_ref()
                        .is_some_and(|p| p.draining.contains(&status.upstream));
                    if status.draining {
                        status.status = "draining";
                    }
                }
                if !route.enabled {
                    for status in &mut statuses {
                        status.status = "paused";
                    }
                }
                (route.id.clone(), statuses)
            })
            .collect()
    }
    fn jobs(&self, config: &Config, limit: usize) -> Vec<Probe> {
        let mut pools = self.pools.lock().unwrap();
        let keys: HashSet<_> = config.routes.iter().map(key).collect();
        pools.retain(|key, _| keys.contains(key));
        let mut due = vec![];
        for route in config.routes.iter().filter(|route| route.enabled) {
            let Some(check) = &route.health_check else {
                continue;
            };
            let key = key(route);
            let pool = pools
                .entry(key.clone())
                .or_insert_with(|| self.new_pool(route));
            for (index, backend) in pool.backends.iter().enumerate() {
                if !backend.in_flight && backend.due.is_some_and(|due| due <= Instant::now()) {
                    due.push((
                        backend.due.unwrap(),
                        Probe {
                            key: key.clone(),
                            index,
                            origin: backend.upstream.clone(),
                            check: check.clone(),
                            host: (route.preserve_host && route.host != "*")
                                .then(|| route.host.clone()),
                        },
                    ));
                }
            }
        }
        due.sort_by_key(|(due, _)| *due);
        due.into_iter()
            .take(limit)
            .map(|(_, probe)| {
                pools.get_mut(&probe.key).unwrap().backends[probe.index].in_flight = true;
                probe
            })
            .collect()
    }
    fn complete(&self, probe: &Probe, result: Result<(), String>, latency_ms: f64) {
        let mut pools = self.pools.lock().unwrap();
        let Some(pool) = pools.get_mut(&probe.key) else {
            return;
        };
        let backend = &mut pool.backends[probe.index];
        backend.in_flight = false;
        backend.checked_at = Some(now());
        backend.latency_ms = Some(latency_ms);
        backend.due = Some(Instant::now() + Duration::from_secs(probe.check.interval_seconds));
        backend.detail = result.as_ref().err().cloned();
        if result.is_ok() {
            backend.failures = 0;
            backend.successes = backend.successes.saturating_add(1);
            if backend.successes >= probe.check.recovery_threshold {
                backend.healthy = true;
            }
        } else {
            backend.successes = 0;
            backend.failures = backend.failures.saturating_add(1);
            if backend.failures >= probe.check.failure_threshold {
                backend.healthy = false;
            }
        }
        backend.status = if backend.healthy {
            "healthy"
        } else if backend.failures > 0 {
            "unhealthy"
        } else {
            "pending"
        };
    }
}
struct Probe {
    key: String,
    index: usize,
    origin: String,
    check: HealthCheck,
    host: Option<String>,
}
impl Probe {
    async fn run(&self, client: &reqwest::Client) -> Result<(), String> {
        // Concatenate a validated absolute path, keeping the configured origin fixed.
        let mut request = client
            .get(format!("{}{}", self.origin, self.check.path))
            .timeout(Duration::from_secs(self.check.timeout_seconds));
        if let Some(host) = &self.host {
            request = request.header("Host", host);
        }
        match request.send().await {
            Ok(response) if response.status().is_success() => Ok(()),
            Ok(response) => Err(format!("HTTP {}", response.status().as_u16())),
            Err(error) if error.is_timeout() => Err("Probe timed out".into()),
            Err(_) => Err("Connection or TLS verification failed".into()),
        }
    }
}

pub struct HealthMonitor(pub Shared);
#[async_trait]
impl BackgroundService for HealthMonitor {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let client = match reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("EmberGate-Health/1.0")
            .build()
        {
            Ok(client) => client,
            Err(error) => {
                log::error!("Health monitor could not start: {error}");
                return;
            }
        };
        let mut tasks = tokio::task::JoinSet::new();
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            if *shutdown.borrow() {
                break;
            }
            tokio::select! {
                _ = shutdown.changed() => break,
                _ = interval.tick() => {
                    for probe in self.0.upstreams.jobs(&self.0.config.load(), 32usize.saturating_sub(tasks.len())) {
                        let client = client.clone();
                        tasks.spawn(async move {
                            let started = Instant::now();
                            let result = probe.run(&client).await;
                            (probe, result, started.elapsed().as_secs_f64() * 1000.0)
                        });
                    }
                }
                Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                    if let Ok((probe, result, latency)) = result {
                        self.0.upstreams.complete(&probe, result, latency);
                    }
                }
            }
        }
        tasks.abort_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn route() -> Route {
        serde_json::from_value(serde_json::json!({
            "id":uuid::Uuid::new_v4().to_string(), "name":"Pool", "host":"app.test",
            "path_prefix":"/", "upstream":"http://127.0.0.1:9000",
            "additional_upstreams":["http://127.0.0.1:9001"], "enabled":true, "preserve_host":false,
            "health_check":{"path":"/health","interval_seconds":5,"timeout_seconds":1,
                "failure_threshold":2,"recovery_threshold":2}
        }))
        .unwrap()
    }
    #[test]
    fn thresholds_gate_startup_failures_and_recovery_without_replaying_requests() {
        let route = route();
        let config = Config {
            trusted_proxies: vec![],
            version: 0,
            routes: vec![route.clone()],
        };
        let upstreams = Upstreams::default();
        assert!(upstreams.select(&route).is_none());
        let probes = upstreams.jobs(&config, 32);
        assert_eq!(probes.len(), 2);
        upstreams.complete(&probes[0], Ok(()), 1.0);
        assert!(upstreams.select(&route).is_none());
        upstreams.complete(&probes[0], Ok(()), 1.0);
        assert_eq!(upstreams.select(&route), Some(route.upstream.clone()));
        upstreams.complete(&probes[0], Err("HTTP 500".into()), 1.0);
        assert!(upstreams.select(&route).is_some());
        upstreams.complete(&probes[0], Err("HTTP 500".into()), 1.0);
        assert!(upstreams.select(&route).is_none());
        upstreams.complete(&probes[0], Ok(()), 1.0);
        assert!(upstreams.select(&route).is_none());
        upstreams.complete(&probes[0], Ok(()), 1.0);
        upstreams.complete(&probes[1], Ok(()), 1.0);
        upstreams.complete(&probes[1], Ok(()), 1.0);
        let selected: Vec<_> = (0..4).map(|_| upstreams.select(&route).unwrap()).collect();
        assert_eq!(
            selected,
            vec![
                route.additional_upstreams[0].clone(),
                route.upstream.clone(),
                route.additional_upstreams[0].clone(),
                route.upstream.clone()
            ]
        );
    }
    #[test]
    fn live_policy_changes_cannot_inherit_old_probe_results() {
        let mut route = route();
        let config = Config {
            trusted_proxies: vec![],
            version: 0,
            routes: vec![route.clone()],
        };
        let upstreams = Upstreams::default();
        let probes = upstreams.jobs(&config, 32);
        route.health_check.as_mut().unwrap().path = "/ready".into();
        upstreams.jobs(
            &Config {
                trusted_proxies: vec![],
                version: 1,
                routes: vec![route.clone()],
            },
            32,
        );
        upstreams.complete(&probes[0], Ok(()), 1.0);
        upstreams.complete(&probes[0], Ok(()), 1.0);
        assert!(upstreams.select(&route).is_none());
        route.health_check = None;
        assert_eq!(upstreams.select(&route), Some(route.upstream.clone()));
        assert_eq!(
            upstreams.select(&route),
            Some(route.additional_upstreams[0].clone())
        );
        upstreams.jobs(&Config::default(), 32);
        assert!(upstreams.pools.lock().unwrap().is_empty());
    }
    #[test]
    fn weighted_distribution_affinity_draining_and_least_active_accounting() {
        let mut route = route();
        route.health_check = None;
        route.balancing = Some(crate::config::Balancing {
            strategy: Strategy::WeightedRoundRobin,
            weights: vec![3, 1],
            draining: vec![],
        });
        let upstreams = Upstreams::default();
        let primary = (0..80)
            .filter(|_| upstreams.select(&route).unwrap() == route.upstream)
            .count();
        assert_eq!(primary, 60);
        route.balancing.as_mut().unwrap().strategy = Strategy::LeastConnections;
        route.balancing.as_mut().unwrap().weights = vec![1, 1];
        let first = upstreams.select_request(&route, None, &[]).unwrap();
        let second = upstreams.select_request(&route, None, &[]).unwrap();
        assert_ne!(first.origin, second.origin);
        let config = Config {
            version: 0,
            routes: vec![route.clone()],
            trusted_proxies: vec![],
        };
        assert_eq!(
            upstreams.snapshot(&config)[&route.id]
                .iter()
                .map(|s| s.active_requests)
                .sum::<usize>(),
            2
        );
        drop(first);
        let next = upstreams.select_request(&route, None, &[]).unwrap();
        assert_ne!(next.origin, second.origin);
        drop(next);
        drop(second);
        route.balancing.as_mut().unwrap().strategy = Strategy::ClientIpHash;
        let client = Some("203.0.113.5".parse().unwrap());
        let selected = upstreams.select_request(&route, client, &[]).unwrap();
        for _ in 0..10 {
            let same = upstreams.select_request(&route, client, &[]).unwrap();
            assert_eq!(selected.origin, same.origin);
        }
        route.balancing.as_mut().unwrap().draining = vec![selected.origin.clone()];
        let other = upstreams.select_request(&route, client, &[]).unwrap();
        assert_ne!(other.origin, selected.origin);
        let config = Config {
            version: 1,
            routes: vec![route.clone()],
            trusted_proxies: vec![],
        };
        let snapshot = upstreams.snapshot(&config);
        let drained = snapshot[&route.id]
            .iter()
            .find(|s| s.upstream == selected.origin)
            .unwrap();
        assert!(drained.draining);
        assert_eq!(drained.active_requests, 1);
        route.balancing.as_mut().unwrap().draining = route.origins().cloned().collect();
        assert!(upstreams.select_request(&route, client, &[]).is_none());
        drop(other);
        drop(selected);
        assert_eq!(
            upstreams.snapshot(&Config {
                version: 2,
                routes: vec![route.clone()],
                trusted_proxies: vec![]
            })[&route.id]
                .iter()
                .map(|s| s.active_requests)
                .sum::<usize>(),
            0
        );
    }
    #[test]
    fn retries_exclude_previous_origins_and_activity_survives_probe_changes() {
        let mut route = route();
        route.health_check = None;
        let upstreams = Upstreams::default();
        let first = upstreams.select_request(&route, None, &[]).unwrap();
        let second = upstreams
            .select_request(&route, None, &[first.origin.clone()])
            .unwrap();
        assert_ne!(first.origin, second.origin);
        assert!(upstreams
            .select_request(&route, None, &[first.origin.clone(), second.origin.clone()])
            .is_none());
        route.health_check = Some(HealthCheck {
            path: "/health".into(),
            interval_seconds: 5,
            timeout_seconds: 1,
            failure_threshold: 1,
            recovery_threshold: 1,
        });
        let config = Config {
            version: 1,
            routes: vec![route.clone()],
            trusted_proxies: vec![],
        };
        assert_eq!(
            upstreams.snapshot(&config)[&route.id]
                .iter()
                .map(|s| s.active_requests)
                .sum::<usize>(),
            2
        );
        drop(first);
        drop(second);
        assert_eq!(
            upstreams.snapshot(&config)[&route.id]
                .iter()
                .map(|s| s.active_requests)
                .sum::<usize>(),
            0
        );
    }
}

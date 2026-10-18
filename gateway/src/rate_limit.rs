//! Exact per-route/client token buckets. State is bounded and shared by all proxy workers.
use crate::config::{Config, RateLimit, Route};
use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::Mutex,
    time::Instant,
};

const MAX_BUCKETS: usize = 100_000;
#[derive(Clone, PartialEq, Eq, Hash)]
struct Policy {
    route_id: String,
    limit: RateLimit,
}
#[derive(PartialEq, Eq, Hash)]
struct Key {
    policy: Policy,
    client: Option<IpAddr>,
}
struct Bucket {
    tokens: f64,
    updated: Instant,
}
#[derive(Default)]
struct State {
    buckets: HashMap<Key, Bucket>,
    last_cleanup: Option<Instant>,
}
#[derive(Default)]
pub struct RateLimits(Mutex<State>);

fn policy(route: &Route) -> Option<Policy> {
    route.rate_limit.as_ref().map(|limit| Policy {
        route_id: route.id.clone(),
        limit: limit.clone(),
    })
}
fn refill(limit: &RateLimit) -> f64 {
    limit.requests as f64 / limit.window_seconds as f64
}
fn normalized_ip(client: Option<IpAddr>) -> Option<IpAddr> {
    client.map(|ip| match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        ip => ip,
    })
}
impl RateLimits {
    /// None admits a request; Some(seconds) rejects it with an estimated retry delay.
    pub fn check(&self, route: &Route, client: Option<IpAddr>) -> Option<u64> {
        self.check_at(route, client, Instant::now(), MAX_BUCKETS)
    }
    fn check_at(
        &self,
        route: &Route,
        client: Option<IpAddr>,
        now: Instant,
        capacity: usize,
    ) -> Option<u64> {
        let policy = policy(route)?;
        let key = Key {
            policy,
            client: normalized_ip(client),
        };
        let mut state = self.0.lock().unwrap();
        // Reclaim only fully replenished buckets. Evicting active buckets would reset budgets.
        let cleanup_after = if state.buckets.len() >= capacity {
            1.0
        } else {
            30.0
        };
        if state
            .last_cleanup
            .is_none_or(|last| now.duration_since(last).as_secs_f64() >= cleanup_after)
        {
            state.buckets.retain(|key, bucket| {
                bucket.tokens
                    + now.duration_since(bucket.updated).as_secs_f64() * refill(&key.policy.limit)
                    < key.policy.limit.burst as f64
            });
            state.last_cleanup = Some(now);
        }
        if !state.buckets.contains_key(&key) && state.buckets.len() >= capacity {
            // Never admit unlimited new identities when the table is full.
            return Some(1);
        }
        let limit = &key.policy.limit;
        let rate = refill(limit);
        let burst = limit.burst as f64;
        let bucket = state.buckets.entry(key).or_insert(Bucket {
            tokens: burst,
            updated: now,
        });
        // Requests can capture their timestamps before waiting for another worker's lock.
        let now = now.max(bucket.updated);
        bucket.tokens =
            (bucket.tokens + now.duration_since(bucket.updated).as_secs_f64() * rate).min(burst);
        bucket.updated = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            None
        } else {
            Some(((1.0 - bucket.tokens) / rate).ceil().max(1.0) as u64)
        }
    }
    pub fn retain_config(&self, config: &Config) {
        let policies: HashSet<_> = config
            .routes
            .iter()
            .filter(|route| route.enabled)
            .filter_map(policy)
            .collect();
        self.0
            .lock()
            .unwrap()
            .buckets
            .retain(|key, _| policies.contains(&key.policy));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::Arc, time::Duration};
    fn route() -> Route {
        serde_json::from_value(serde_json::json!({"id":uuid::Uuid::new_v4().to_string(),
            "name":"Limited", "host":"app.test", "path_prefix":"/", "upstream":"http://127.0.0.1:9000",
            "enabled":true,"preserve_host":false,"rate_limit":{"requests":2,"window_seconds":10,"burst":2}})).unwrap()
    }
    #[test]
    fn burst_refill_retry_delay_and_client_route_isolation() {
        let limiter = RateLimits::default();
        let mut route = route();
        let ip = Some("127.0.0.1".parse().unwrap());
        let start = Instant::now();
        assert_eq!(limiter.check_at(&route, ip, start, 100), None);
        assert_eq!(limiter.check_at(&route, ip, start, 100), None);
        assert_eq!(limiter.check_at(&route, ip, start, 100), Some(5));
        assert_eq!(
            limiter.check_at(&route, ip, start + Duration::from_secs(4), 100),
            Some(1)
        );
        assert_eq!(
            limiter.check_at(&route, ip, start + Duration::from_secs(5), 100),
            None
        );
        assert_eq!(
            limiter.check_at(&route, ip, start + Duration::from_secs(5), 100),
            Some(5)
        );
        assert_eq!(
            limiter.check_at(
                &route,
                Some("127.0.0.2".parse().unwrap()),
                start + Duration::from_secs(5),
                100
            ),
            None
        );
        route.id = uuid::Uuid::new_v4().to_string();
        assert_eq!(
            limiter.check_at(&route, ip, start + Duration::from_secs(5), 100),
            None
        );
    }
    #[test]
    fn capacity_does_not_evict_active_buckets_and_mapped_ips_share_budget() {
        let limiter = RateLimits::default();
        let route = route();
        let start = Instant::now();
        let ip = Some("127.0.0.1".parse().unwrap());
        assert_eq!(limiter.check_at(&route, ip, start, 1), None);
        assert_eq!(
            limiter.check_at(&route, Some("::ffff:127.0.0.1".parse().unwrap()), start, 1),
            None
        );
        assert!(limiter.check_at(&route, ip, start, 1).is_some());
        assert!(limiter
            .check_at(&route, Some("127.0.0.2".parse().unwrap()), start, 1)
            .is_some());
        assert_eq!(
            limiter.check_at(
                &route,
                Some("127.0.0.2".parse().unwrap()),
                start + Duration::from_secs(10),
                1
            ),
            None
        );
        assert_eq!(limiter.0.lock().unwrap().buckets.len(), 1);
    }
    #[test]
    fn policy_updates_reset_budgets_but_unrelated_saves_do_not() {
        let limiter = RateLimits::default();
        let mut route = route();
        let start = Instant::now();
        for _ in 0..2 {
            assert_eq!(limiter.check_at(&route, None, start, 100), None);
        }
        limiter.retain_config(&Config {
            trusted_proxies: vec![],
            version: 1,
            routes: vec![route.clone()],
        });
        assert!(limiter.check_at(&route, None, start, 100).is_some());
        route.rate_limit.as_mut().unwrap().requests = 3;
        limiter.retain_config(&Config {
            trusted_proxies: vec![],
            version: 2,
            routes: vec![route.clone()],
        });
        assert_eq!(limiter.check_at(&route, None, start, 100), None);
        route.rate_limit = None;
        limiter.retain_config(&Config {
            trusted_proxies: vec![],
            version: 3,
            routes: vec![route.clone()],
        });
        assert!(limiter.0.lock().unwrap().buckets.is_empty());
        assert_eq!(limiter.check_at(&route, None, start, 0), None);
    }
    #[test]
    fn concurrent_requests_share_one_atomic_budget() {
        let limiter = Arc::new(RateLimits::default());
        let route = route();
        let now = Instant::now();
        let threads: Vec<_> = (0..32)
            .map(|_| {
                let limiter = limiter.clone();
                let route = route.clone();
                std::thread::spawn(move || limiter.check_at(&route, None, now, 100).is_none())
            })
            .collect();
        let allowed = threads
            .into_iter()
            .filter_map(|thread| thread.join().ok())
            .filter(|allowed| *allowed)
            .count();
        assert_eq!(allowed, 2);
    }
}

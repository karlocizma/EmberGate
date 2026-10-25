use serde::{Deserialize, Serialize};
use std::{collections::HashSet, path::Path};
use url::Url;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    #[serde(default, skip_serializing_if = "UpstreamProtocol::is_http1")]
    pub upstream_protocol: UpstreamProtocol,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forward_auth: Option<crate::forward_auth::ForwardAuth>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc: Option<crate::oidc::HostPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compression: Option<crate::compression::CompressionPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pages: Option<crate::pages::PagePolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routing: Option<crate::routing::RoutingPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reliability: Option<Reliability>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub balancing: Option<Balancing>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache: Option<crate::cache::CachePolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access: Option<crate::policy::AccessPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<crate::policy::ResponsePolicy>,
    pub id: String,
    pub name: String,
    pub host: String,
    pub path_prefix: String,
    pub upstream: String,
    pub enabled: bool,
    pub preserve_host: bool,
    /// Whether HTTPS origins must present a trusted certificate matching their hostname.
    /// Disabled only for explicitly configured private/self-signed HTTPS origins.
    #[serde(
        default = "default_verify_upstream_tls",
        skip_serializing_if = "verify_upstream_tls_default"
    )]
    pub verify_upstream_tls: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub additional_upstreams: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_check: Option<HealthCheck>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimit>,
    /// Holds concurrent requests sharing a Cookie header behind a per-session
    /// lock until the upstream response headers arrive, so they reach the
    /// upstream in order. Fixes upstreams whose own session handling races
    /// itself under concurrent requests. It does not fix login loops caused by
    /// lost cookies or forwarded headers. Requests without cookies are never
    /// serialized, waits time out with 503, and upgraded or streaming bodies do
    /// not hold the lock.
    /// Off by default.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub serialize_by_session: bool,
}

fn default_verify_upstream_tls() -> bool {
    true
}
fn verify_upstream_tls_default(value: &bool) -> bool {
    *value
}

/// Upstream wire protocol; Auto keeps ordinary HTTP/WebSockets on H1 and uses H2 for native gRPC.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamProtocol {
    #[default]
    Http1,
    Auto,
    Http2,
}
impl UpstreamProtocol {
    pub fn is_http1(&self) -> bool {
        *self == Self::Http1
    }
    pub fn requires_h2(self, grpc: bool) -> bool {
        self == Self::Http2 || (self == Self::Auto && grpc)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(deny_unknown_fields)]
pub struct RateLimit {
    pub requests: u32,
    pub window_seconds: u64,
    pub burst: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthCheck {
    pub path: String,
    pub interval_seconds: u64,
    pub timeout_seconds: u64,
    pub failure_threshold: u32,
    pub recovery_threshold: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Reliability {
    pub connect_timeout_seconds: u64,
    pub read_timeout_seconds: u64,
    pub write_timeout_seconds: u64,
    pub retries: u32,
}
impl Default for Reliability {
    fn default() -> Self {
        Self {
            connect_timeout_seconds: 5,
            read_timeout_seconds: 60,
            write_timeout_seconds: 60,
            retries: 0,
        }
    }
}
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Strategy {
    #[default]
    RoundRobin,
    WeightedRoundRobin,
    LeastConnections,
    ClientIpHash,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Balancing {
    pub strategy: Strategy,
    pub weights: Vec<u16>,
    pub draining: Vec<String>,
}
impl Route {
    pub fn origins(&self) -> impl Iterator<Item = &String> {
        std::iter::once(&self.upstream).chain(self.additional_upstreams.iter())
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_proxies: Vec<crate::policy::TrustedProxy>,
    pub version: u64,
    pub routes: Vec<Route>,
}

pub fn normalized_host(host: &str) -> Option<String> {
    // http::uri::Authority handles host:port and bracketed IPv6 authorities.
    let authority = host.parse::<axum::http::uri::Authority>().ok()?;
    Some(authority.host().trim_end_matches('.').to_ascii_lowercase())
}

impl Config {
    pub fn validate(&mut self) -> Result<(), String> {
        if self.routes.len() > 500 {
            return Err("A maximum of 500 routes is supported.".into());
        }
        crate::policy::validate_trusted(&mut self.trusted_proxies)?;
        let mut ids = HashSet::new();
        let mut matches = HashSet::new();
        let mut monitored = 0;
        for route in &mut self.routes {
            if let Some(policy) = &mut route.forward_auth {
                policy.validate()?;
            }
            if let Some(policy) = &mut route.oidc {
                if route.forward_auth.is_some() {
                    return Err(
                        "Choose either external login or single sign-on for a host, not both."
                            .into(),
                    );
                }
                policy.validate()?;
            }
            if let Some(policy) = &route.compression {
                policy.validate()?;
            }
            if let Some(policy) = &route.reliability {
                if !(1..=120).contains(&policy.connect_timeout_seconds)
                    || !(1..=3600).contains(&policy.read_timeout_seconds)
                    || !(1..=3600).contains(&policy.write_timeout_seconds)
                    || policy.retries > 3
                {
                    return Err("Use a 1–120 second connect timeout, 1–3600 second read/write timeouts, and 0–3 failover retries.".into());
                }
            }
            if let Some(cache) = &route.cache {
                cache.validate()?;
            }
            if let Some(access) = &mut route.access {
                access.validate()?;
            }
            if let Some(response) = &mut route.response {
                response.validate()?;
            }
            if let Some(limit) = &route.rate_limit {
                if !(1..=1_000_000).contains(&limit.requests)
                    || !(1..=3600).contains(&limit.window_seconds)
                    || !(1..=100_000).contains(&limit.burst)
                    || limit.burst > limit.requests
                {
                    return Err("Rate limits require 1–1,000,000 requests per 1–3,600 seconds and a burst of 1–100,000, no greater than the request allowance.".into());
                }
            }
            if uuid::Uuid::parse_str(&route.id).is_err() || !ids.insert(route.id.clone()) {
                return Err("Each route must have a unique UUID.".into());
            }
            route.name = route.name.trim().to_owned();
            if route.name.is_empty() || route.name.len() > 80 {
                return Err("Route names must contain 1–80 characters.".into());
            }
            route.host = route.host.trim().trim_end_matches('.').to_ascii_lowercase();
            if route.host != "*" {
                let authority = route
                    .host
                    .parse::<axum::http::uri::Authority>()
                    .map_err(|_| "Enter a hostname without a scheme, port, or path.".to_owned())?;
                if authority.port().is_some()
                    || authority.host() != route.host
                    || route.host.contains('@')
                {
                    return Err("Enter a hostname without a scheme, port, or path.".into());
                }
                Url::parse(&format!("http://{}/", route.host))
                    .map_err(|_| "Invalid route hostname.".to_owned())?;
            }
            if !route.path_prefix.starts_with('/')
                || route.path_prefix.len() > 1024
                || route.path_prefix.contains(['?', '#'])
                || route
                    .path_prefix
                    .chars()
                    .any(|c| c.is_control() || c.is_whitespace())
            {
                return Err(
                    "Path prefixes must start with / and contain no query or fragment.".into(),
                );
            }
            if let Some(policy) = &mut route.pages {
                policy.validate()?;
            }
            if let Some(policy) = &mut route.routing {
                policy.validate()?;
            }
            if !matches.insert((route.host.clone(), route.path_prefix.clone())) {
                return Err("Two routes cannot have the same hostname and path prefix.".into());
            }
            if route.additional_upstreams.len() > 15 {
                return Err("A host supports up to 16 upstream origins.".into());
            }
            let mut origins = HashSet::new();
            for origin in
                std::iter::once(&mut route.upstream).chain(route.additional_upstreams.iter_mut())
            {
                let upstream = Url::parse(origin.trim())
                    .map_err(|_| "Enter a valid upstream URL.".to_owned())?;
                if !["http", "https"].contains(&upstream.scheme())
                    || upstream.host_str().is_none()
                    || !upstream.username().is_empty()
                    || upstream.password().is_some()
                    || upstream.path() != "/"
                    || upstream.query().is_some()
                    || upstream.fragment().is_some()
                {
                    return Err(
                    "Upstreams must be HTTP or HTTPS origins, for example http://127.0.0.1:9000."
                        .into(),
                );
                }
                *origin = upstream.as_str().trim_end_matches('/').to_owned();
                if !origins.insert(origin.clone()) {
                    return Err("Upstream origins in a host must be unique.".into());
                }
            }
            let configured_origins: Vec<_> = route.origins().cloned().collect();
            if let Some(policy) = &mut route.balancing {
                if !policy.weights.is_empty()
                    && (policy.weights.len() != configured_origins.len()
                        || policy.weights.iter().any(|w| !(1..=100).contains(w)))
                {
                    return Err("Specify one weight of 1–100 for each upstream, or omit weights to use equal weights.".into());
                }
                let mut seen = HashSet::new();
                for origin in &mut policy.draining {
                    let parsed = Url::parse(origin.trim())
                        .map_err(|_| "Invalid draining upstream origin.".to_owned())?;
                    *origin = parsed.as_str().trim_end_matches('/').to_owned();
                    if !configured_origins.contains(origin) || !seen.insert(origin.clone()) {
                        return Err(
                            "Draining origins must be unique members of this host's upstream pool."
                                .into(),
                        );
                    }
                }
            }
            if route.upstream_protocol == UpstreamProtocol::Http2 && route.health_check.is_some() {
                return Err("HTTP/2-only routes cannot use HTTP/1.1 health checks; disable health checks or use Auto".into());
            }
            if let Some(check) = &route.health_check {
                if !check.path.starts_with('/')
                    || check.path.starts_with("//")
                    || check.path.len() > 1024
                    || check.path.contains(['?', '#', '\\'])
                    || check
                        .path
                        .chars()
                        .any(|c| c.is_control() || c.is_whitespace())
                {
                    return Err("Health check paths must start with / and contain no query, fragment, or whitespace.".into());
                }
                if !(5..=300).contains(&check.interval_seconds)
                    || !(1..=10).contains(&check.timeout_seconds)
                    || !(1..=10).contains(&check.failure_threshold)
                    || !(1..=10).contains(&check.recovery_threshold)
                {
                    return Err("Health checks require a 5–300 second interval, 1–10 second timeout, and thresholds of 1–10 checks.".into());
                }
                monitored += route.origins().count();
            }
        }
        if monitored > 256 {
            return Err("A maximum of 256 health-checked upstreams is supported.".into());
        }
        Ok(())
    }

    pub fn find_route(&self, host: &str, path: &str) -> Option<Route> {
        self.routes
            .iter()
            .filter(|r| {
                r.enabled && (r.host == host || r.host == "*") && path.starts_with(&r.path_prefix)
            })
            .max_by_key(|r| (r.host != "*", r.path_prefix.len()))
            .cloned()
    }

    pub fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        match std::fs::read(path) {
            Ok(bytes) => {
                let mut config: Self = serde_json::from_slice(&bytes)?;
                config.validate().map_err(std::io::Error::other)?;
                Ok(config)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn route(host: &str, prefix: &str) -> Route {
        Route {
            upstream_protocol: UpstreamProtocol::default(),
            forward_auth: None,
            oidc: None,
            compression: None,
            pages: None,
            routing: None,
            reliability: None,
            balancing: None,
            cache: None,
            access: None,
            response: None,
            id: uuid::Uuid::new_v4().to_string(),
            name: "Test".into(),
            host: host.into(),
            path_prefix: prefix.into(),
            upstream: "http://localhost:9000".into(),
            enabled: true,
            preserve_host: false,
            verify_upstream_tls: true,
            additional_upstreams: vec![],
            health_check: None,
            rate_limit: None,
            serialize_by_session: false,
        }
    }
    #[test]
    fn specific_hosts_then_longest_prefix_win() {
        let config = Config {
            trusted_proxies: vec![],
            version: 0,
            routes: vec![
                route("*", "/api/v1"),
                route("app.test", "/"),
                route("app.test", "/api"),
            ],
        };
        assert_eq!(
            config
                .find_route("app.test", "/api/v1/users")
                .unwrap()
                .path_prefix,
            "/api"
        );
        assert_eq!(
            config.find_route("other.test", "/api/v1").unwrap().host,
            "*"
        );
        assert!(config.find_route("other.test", "/").is_none());
    }
    #[test]
    fn rejects_duplicates_credentials_and_upstream_paths() {
        let a = route("app.test", "/");
        let mut config = Config {
            trusted_proxies: vec![],
            version: 0,
            routes: vec![a.clone(), route("app.test", "/")],
        };
        assert!(config.validate().is_err());
        for upstream in [
            "ftp://app.test",
            "http://user:pass@app.test",
            "http://app.test/path",
        ] {
            let mut r = a.clone();
            r.upstream = upstream.into();
            assert!(Config {
                trusted_proxies: vec![],
                version: 0,
                routes: vec![r]
            }
            .validate()
            .is_err());
        }
    }
    #[test]
    fn normalizes_and_ignores_disabled_routes() {
        assert_eq!(normalized_host("APP.TEST:8080"), Some("app.test".into()));
        let mut r = route("APP.TEST.", "/");
        r.enabled = false;
        let mut config = Config {
            trusted_proxies: vec![],
            version: 0,
            routes: vec![r],
        };
        config.validate().unwrap();
        assert_eq!(config.routes[0].host, "app.test");
        assert!(config.find_route("app.test", "/").is_none());
    }

    #[test]
    fn pools_reject_duplicate_origins_and_invalid_health_policies() {
        let legacy = serde_json::json!({"id":uuid::Uuid::new_v4().to_string(),"name":"Legacy",
            "host":"app.test","path_prefix":"/","upstream":"http://localhost:9000",
            "enabled":true,"preserve_host":false});
        let original: Route = serde_json::from_value(legacy.clone()).unwrap();
        assert!(original.additional_upstreams.is_empty() && original.health_check.is_none());
        assert_eq!(serde_json::to_value(&original).unwrap(), legacy);
        let mut r = original.clone();
        r.additional_upstreams = vec!["http://LOCALHOST:9000/".into()];
        assert!(Config {
            trusted_proxies: vec![],
            version: 0,
            routes: vec![r]
        }
        .validate()
        .is_err());
        for path in [
            "https://other.test",
            "//other.test",
            "/health?key=1",
            "/health#fragment",
            "/bad path",
            "/\\other.test",
        ] {
            let mut r = original.clone();
            r.health_check = Some(HealthCheck {
                path: path.into(),
                interval_seconds: 5,
                timeout_seconds: 1,
                failure_threshold: 1,
                recovery_threshold: 1,
            });
            assert!(
                Config {
                    trusted_proxies: vec![],
                    version: 0,
                    routes: vec![r]
                }
                .validate()
                .is_err(),
                "{path}"
            );
        }
        let mut r = original;
        r.health_check = Some(HealthCheck {
            path: "/health".into(),
            interval_seconds: 0,
            timeout_seconds: 1,
            failure_threshold: 1,
            recovery_threshold: 1,
        });
        assert!(Config {
            trusted_proxies: vec![],
            version: 0,
            routes: vec![r]
        }
        .validate()
        .is_err());
    }

    #[test]
    fn rate_policy_bounds_are_validated_and_legacy_routes_remain_unlimited() {
        let original = route("app.test", "/");
        assert!(original.rate_limit.is_none());
        assert!(serde_json::to_value(&original)
            .unwrap()
            .get("rate_limit")
            .is_none());
        for limit in [
            RateLimit {
                requests: 0,
                window_seconds: 60,
                burst: 1,
            },
            RateLimit {
                requests: 60,
                window_seconds: 0,
                burst: 1,
            },
            RateLimit {
                requests: 60,
                window_seconds: 3601,
                burst: 1,
            },
            RateLimit {
                requests: 60,
                window_seconds: 60,
                burst: 61,
            },
            RateLimit {
                requests: 60,
                window_seconds: 60,
                burst: 0,
            },
        ] {
            let mut route = original.clone();
            route.rate_limit = Some(limit);
            assert!(Config {
                trusted_proxies: vec![],
                version: 0,
                routes: vec![route]
            }
            .validate()
            .is_err());
        }
        let mut route = original;
        route.rate_limit = Some(RateLimit {
            requests: 60,
            window_seconds: 60,
            burst: 20,
        });
        assert!(Config {
            trusted_proxies: vec![],
            version: 0,
            routes: vec![route]
        }
        .validate()
        .is_ok());
    }
    #[test]
    fn reliability_and_balancing_policies_validate_and_old_routes_keep_defaults() {
        let mut config = Config {
            version: 0,
            routes: vec![route("app.test", "/")],
            trusted_proxies: vec![],
        };
        assert!(config.validate().is_ok());
        assert!(config.routes[0].reliability.is_none());
        assert!(config.routes[0].balancing.is_none());
        assert!(config.routes[0].verify_upstream_tls);
        config.routes[0].reliability = Some(Reliability {
            retries: 4,
            ..Default::default()
        });
        assert!(config.validate().is_err());
        config.routes[0].reliability = Some(Reliability {
            connect_timeout_seconds: 0,
            ..Default::default()
        });
        assert!(config.validate().is_err());
        config.routes[0].reliability = Some(Reliability::default());
        config.routes[0].balancing = Some(Balancing {
            weights: vec![101],
            ..Default::default()
        });
        assert!(config.validate().is_err());
        config.routes[0].balancing = Some(Balancing {
            weights: vec![1, 2],
            ..Default::default()
        });
        assert!(config.validate().is_err());
        config.routes[0].balancing = Some(Balancing {
            draining: vec!["http://another.test".into()],
            ..Default::default()
        });
        assert!(config.validate().is_err());
        config.routes[0].balancing = Some(Balancing {
            weights: vec![2],
            draining: vec!["http://localhost:9000/".into()],
            ..Default::default()
        });
        assert!(config.validate().is_ok());
        assert_eq!(
            config.routes[0].balancing.as_ref().unwrap().draining,
            vec!["http://localhost:9000"]
        );
    }
}

//! Bounded process metrics and separately authorized machine scrapes.
use crate::{
    config::Config,
    state::{AccessLog, Shared},
};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use rusqlite::{params, OptionalExtension};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    fmt::Write,
};
const SECRET: &str = "prometheus_token_sha256";
pub const BOUNDS: [f64; 11] = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1., 2.5, 5., 10.];
#[derive(Default)]
pub struct Traffic {
    pub requests: u64,
    pub errors: u64,
    pub sum: f64,
    pub buckets: [u64; 11],
}
impl Traffic {
    fn record(&mut self, e: &AccessLog) {
        self.requests += 1;
        self.errors += u64::from(e.status >= 500);
        let seconds = e.latency_ms / 1000.;
        self.sum += seconds;
        for (i, bound) in BOUNDS.iter().enumerate() {
            if seconds <= *bound {
                self.buckets[i] += 1;
            }
        }
    }
}
#[derive(Default)]
pub struct Counters {
    pub global: Traffic,
    pub routes: HashMap<String, Traffic>,
    active: HashSet<String>,
    pub responses: HashMap<(&'static str, &'static str), u64>,
    pub access_denied: u64,
    pub maintenance: u64,
    pub attempts: u64,
    pub failovers: u64,
}
impl Counters {
    pub fn configure(&mut self, config: &Config) {
        self.active = config.routes.iter().map(|r| r.id.clone()).collect();
        self.routes.retain(|id, _| self.active.contains(id));
    }
    pub fn record(&mut self, e: &AccessLog) {
        self.global.record(e);
        if let Some(id) = e.route_id.as_ref().filter(|id| self.active.contains(*id)) {
            self.routes.entry(id.clone()).or_default().record(e);
        }
        let method = match e.method.as_str() {
            "GET" => "GET",
            "HEAD" => "HEAD",
            "POST" => "POST",
            "PUT" => "PUT",
            "PATCH" => "PATCH",
            "DELETE" => "DELETE",
            "OPTIONS" => "OPTIONS",
            _ => "OTHER",
        };
        let class = match e.status / 100 {
            1 => "1xx",
            2 => "2xx",
            3 => "3xx",
            4 => "4xx",
            5 => "5xx",
            _ => "other",
        };
        *self.responses.entry((method, class)).or_default() += 1;
        self.access_denied += u64::from(e.access_denied);
        self.maintenance += u64::from(e.maintenance);
        self.attempts += e.attempted_upstreams.len() as u64;
        self.failovers += e.attempted_upstreams.len().saturating_sub(1) as u64;
    }
}
fn family(out: &mut String, name: &str, kind: &str, help: &str) {
    writeln!(out, "# HELP {name} {help}\n# TYPE {name} {kind}").unwrap();
}
fn sample(out: &mut String, name: &str, labels: &str, value: impl std::fmt::Display) {
    writeln!(out, "{name}{labels} {value}").unwrap();
}
fn histogram(out: &mut String, name: &str, traffic: &Traffic, route: Option<&str>) {
    for (i, bound) in BOUNDS.iter().enumerate() {
        let labels = route.map_or_else(
            || format!("{{le=\"{bound}\"}}"),
            |id| format!("{{route_id=\"{id}\",le=\"{bound}\"}}"),
        );
        sample(out, &format!("{name}_bucket"), &labels, traffic.buckets[i]);
    }
    let labels = route.map_or_else(
        || "{le=\"+Inf\"}".into(),
        |id| format!("{{route_id=\"{id}\",le=\"+Inf\"}}"),
    );
    sample(out, &format!("{name}_bucket"), &labels, traffic.requests);
    let labels = route.map_or_else(String::new, |id| format!("{{route_id=\"{id}\"}}"));
    sample(out, &format!("{name}_sum"), &labels, traffic.sum);
    sample(out, &format!("{name}_count"), &labels, traffic.requests);
}
async fn exposition(state: &Shared) -> Result<String, String> {
    let config = state.config.load_full();
    let mut out = String::with_capacity(32768);
    {
        let metrics = state.metrics.lock().map_err(|_| "Metrics unavailable.")?;
        let counters = &metrics.prometheus;
        for (name, help, value) in [
            (
                "embergate_requests_total",
                "Completed proxy requests since process start.",
                metrics.requests,
            ),
            (
                "embergate_errors_total",
                "Completed responses with status 500 or above.",
                metrics.errors,
            ),
            (
                "embergate_rate_limited_requests_total",
                "Requests blocked by gateway rate limits.",
                metrics.rate_limited,
            ),
            (
                "embergate_access_denied_requests_total",
                "Requests blocked by IP access rules.",
                counters.access_denied,
            ),
            (
                "embergate_maintenance_requests_total",
                "Maintenance responses, including holding pages.",
                counters.maintenance,
            ),
            (
                "embergate_upstream_attempts_total",
                "Upstream connection attempts.",
                counters.attempts,
            ),
            (
                "embergate_failovers_total",
                "Additional distinct-backend attempts after the first.",
                counters.failovers,
            ),
        ] {
            family(&mut out, name, "counter", help);
            sample(&mut out, name, "", value);
        }
        family(
            &mut out,
            "embergate_http_responses_total",
            "counter",
            "Completed proxy requests grouped by bounded method and status class.",
        );
        let mut responses: Vec<_> = counters.responses.iter().collect();
        responses.sort_by_key(|(key, _)| **key);
        for ((method, class), value) in responses {
            sample(
                &mut out,
                "embergate_http_responses_total",
                &format!("{{method=\"{method}\",status_class=\"{class}\"}}"),
                value,
            );
        }
        family(
            &mut out,
            "embergate_request_duration_seconds",
            "histogram",
            "End-to-end duration of completed proxy requests.",
        );
        histogram(
            &mut out,
            "embergate_request_duration_seconds",
            &counters.global,
            None,
        );
        for (name, help) in [
            (
                "embergate_route_requests_total",
                "Completed requests for each configured route.",
            ),
            (
                "embergate_route_errors_total",
                "Completed 5xx responses for each configured route.",
            ),
        ] {
            family(&mut out, name, "counter", help);
            for route in &config.routes {
                let value = counters.routes.get(&route.id).map_or(0, |t| {
                    if name.ends_with("errors_total") {
                        t.errors
                    } else {
                        t.requests
                    }
                });
                sample(
                    &mut out,
                    name,
                    &format!("{{route_id=\"{}\"}}", route.id),
                    value,
                );
            }
        }
        family(
            &mut out,
            "embergate_route_request_duration_seconds",
            "histogram",
            "End-to-end request duration for configured routes.",
        );
        let empty = Traffic::default();
        for route in &config.routes {
            histogram(
                &mut out,
                "embergate_route_request_duration_seconds",
                counters.routes.get(&route.id).unwrap_or(&empty),
                Some(&route.id),
            );
        }
    }
    for (name, help, value) in [
        (
            "embergate_uptime_seconds",
            "Seconds since process start.",
            state.started.elapsed().as_secs_f64(),
        ),
        (
            "embergate_config_revision",
            "Current route configuration revision.",
            config.version as f64,
        ),
        (
            "embergate_routes",
            "Number of configured routes.",
            config.routes.len() as f64,
        ),
    ] {
        family(&mut out, name, "gauge", help);
        sample(&mut out, name, "", value);
    }
    for (name, help) in [
        ("embergate_route_enabled", "Whether the route is enabled."),
        (
            "embergate_route_maintenance",
            "Whether an enabled route is in maintenance.",
        ),
    ] {
        family(&mut out, name, "gauge", help);
        for route in &config.routes {
            sample(
                &mut out,
                name,
                &format!("{{route_id=\"{}\"}}", route.id),
                u8::from(
                    route.enabled
                        && (name.ends_with("enabled")
                            || route.pages.as_ref().is_some_and(|p| p.maintenance)),
                ),
            );
        }
    }
    let backends = state.upstreams.snapshot(&config);
    for (name, help) in [
        (
            "embergate_backend_available",
            "Whether new proxy traffic can select this backend.",
        ),
        (
            "embergate_backend_active_requests",
            "Active proxy requests on this backend.",
        ),
        (
            "embergate_backend_draining",
            "Whether this backend is draining.",
        ),
        ("embergate_backend_weight", "Configured backend weight."),
    ] {
        family(&mut out, name, "gauge", help);
        for route in &config.routes {
            for (index, backend) in backends.get(&route.id).into_iter().flatten().enumerate() {
                let value = match name {
                    "embergate_backend_active_requests" => backend.active_requests as u64,
                    "embergate_backend_draining" => u64::from(backend.draining),
                    "embergate_backend_weight" => u64::from(backend.weight),
                    _ => u64::from(
                        route.enabled
                            && !route.pages.as_ref().is_some_and(|p| p.maintenance)
                            && !backend.draining
                            && (route.health_check.is_none() || backend.status == "healthy"),
                    ),
                };
                sample(
                    &mut out,
                    name,
                    &format!("{{route_id=\"{}\",backend=\"{index}\"}}", route.id),
                    value,
                );
            }
        }
    }
    let cache = state.http_cache.summary(&config);
    for (name, key, help) in [
        (
            "embergate_cache_used_bytes",
            "used_bytes",
            "Committed shared-cache storage bytes.",
        ),
        (
            "embergate_cache_capacity_bytes",
            "capacity_bytes",
            "Shared-cache storage budget.",
        ),
        (
            "embergate_cache_entries",
            "entries",
            "Shared-cache object count.",
        ),
    ] {
        family(&mut out, name, "gauge", help);
        sample(&mut out, name, "", cache[key].as_u64().unwrap_or(0));
    }
    for (name, key, kind) in [
        ("embergate_cache_hits_total", "hits", "counter"),
        ("embergate_cache_misses_total", "misses", "counter"),
        ("embergate_cache_bypasses_total", "bypasses", "counter"),
        ("embergate_cache_purges_total", "purges", "counter"),
        ("embergate_route_cache_bytes", "bytes", "gauge"),
    ] {
        family(
            &mut out,
            name,
            kind,
            "Per-route shared-cache activity or storage.",
        );
        for row in cache["routes"].as_array().into_iter().flatten() {
            if let Some(id) = row["route_id"].as_str() {
                sample(
                    &mut out,
                    name,
                    &format!("{{route_id=\"{id}\"}}"),
                    row[key].as_u64().unwrap_or(0),
                );
            }
        }
    }
    family(
        &mut out,
        "embergate_certificate_days_remaining",
        "gauge",
        "Whole days until installed certificate expiry, negative when expired.",
    );
    for cert in state.certificates.load().summaries() {
        sample(
            &mut out,
            "embergate_certificate_days_remaining",
            &format!("{{certificate_id=\"{}\"}}", cert.id),
            cert.days_remaining,
        );
    }
    let delivery = state
        .control
        .run(|db| {
            let active: u64 = db
                .query_row(
                    "SELECT COUNT(*) FROM alerts WHERE resolved_at IS NULL",
                    [],
                    |r| r.get(0),
                )
                .map_err(crate::management::storage)?;
            let mut stmt = db
                .prepare("SELECT state,COUNT(*) FROM outbox GROUP BY state")
                .map_err(crate::management::storage)?;
            let rows = stmt
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, u64>(1)?)))
                .map_err(crate::management::storage)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(crate::management::storage)?;
            Ok((active, rows))
        })
        .await?;
    family(
        &mut out,
        "embergate_active_alerts",
        "gauge",
        "Unresolved dashboard alerts.",
    );
    sample(&mut out, "embergate_active_alerts", "", delivery.0);
    family(
        &mut out,
        "embergate_notification_queue",
        "gauge",
        "Retained notification outbox rows grouped by state.",
    );
    for state in ["pending", "delivered", "failed", "cancelled"] {
        sample(
            &mut out,
            "embergate_notification_queue",
            &format!("{{state=\"{state}\"}}"),
            delivery
                .1
                .iter()
                .find(|(s, _)| s == state)
                .map_or(0, |(_, n)| *n),
        );
    }
    Ok(out)
}
async fn hash(state: &Shared) -> Result<Option<String>, String> {
    state
        .control
        .run(|db| {
            db.query_row(
                "SELECT value FROM secrets WHERE key=?1",
                params![SECRET],
                |r| r.get(0),
            )
            .optional()
            .map_err(crate::management::storage)
        })
        .await
}
pub async fn status(State(state): State<Shared>) -> Result<Json<Value>, StatusCode> {
    Ok(Json(
        json!({"configured":hash(&state).await.map_err(|_|StatusCode::SERVICE_UNAVAILABLE)?.is_some(),"path":"/metrics"}),
    ))
}
pub async fn rotate(State(state): State<Shared>) -> Result<Json<Value>, StatusCode> {
    let mut bytes = [0u8; 32];
    openssl::rand::rand_bytes(&mut bytes).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let token: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let digest: String = openssl::sha::sha256(token.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    state
        .control
        .set_secret(SECRET.into(), Some(digest))
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(Json(
        json!({"token":token,"configured":true,"path":"/metrics"}),
    ))
}
pub async fn disable(State(state): State<Shared>) -> Result<Json<Value>, StatusCode> {
    state
        .control
        .set_secret(SECRET.into(), None)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(Json(json!({"configured":false,"path":"/metrics"})))
}
pub async fn scrape(State(state): State<Shared>, headers: HeaderMap) -> Response {
    let Ok(Some(expected)) = hash(&state).await else {
        return (StatusCode::UNAUTHORIZED, "Metrics token required.\n").into_response();
    };
    if headers.get_all("authorization").iter().count() != 1 {
        return (StatusCode::UNAUTHORIZED, "Metrics token required.\n").into_response();
    }
    let supplied = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let valid = supplied
        .filter(|v| v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()))
        .is_some_and(|value| {
            let digest: String = openssl::sha::sha256(value.as_bytes())
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            expected.len() == digest.len()
                && openssl::memcmp::eq(expected.as_bytes(), digest.as_bytes())
        });
    if !valid {
        return (StatusCode::UNAUTHORIZED, "Metrics token required.\n").into_response();
    }
    authenticated(State(state)).await
}
pub async fn authenticated(State(state): State<Shared>) -> Response {
    match exposition(&state).await {
        Ok(body) => (
            [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
            body,
        )
            .into_response(),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "Metrics unavailable.\n").into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn counters_bound_labels_histograms_and_removed_routes() {
        let id = uuid::Uuid::new_v4().to_string();
        let config:Config=serde_json::from_value(json!({"version":0,"routes":[{"id":id,"name":"Host","host":"*","path_prefix":"/","upstream":"http://localhost:9000","enabled":true,"preserve_host":false}]})).unwrap();
        let mut counters = Counters::default();
        counters.configure(&config);
        let mut e:AccessLog=serde_json::from_value(json!({"timestamp":1,"route_id":id,"client_ip":null,"peer_ip":null,"identity_source":"connection","access_denied":false,"method":"GET","host":"private","path":"/secret?token=never-label","route":"Host","upstream":null,"attempted_upstreams":["A","B"],"rate_limited":false,"maintenance":true,"cache_status":"OFF","status":503,"latency_ms":100.0})).unwrap();
        counters.record(&e);
        assert_eq!(counters.global.requests, 1);
        assert_eq!(counters.global.errors, 1);
        assert_eq!(counters.global.buckets[3], 0);
        assert_eq!(counters.global.buckets[4], 1);
        assert_eq!(counters.failovers, 1);
        for i in 0..1000 {
            e.method = format!("CUSTOM-{i}");
            counters.record(&e);
        }
        assert_eq!(counters.responses.len(), 2);
        assert_eq!(counters.routes.len(), 1);
        let mut rendered = String::new();
        histogram(&mut rendered, "duration", &counters.global, None);
        assert!(rendered.contains("duration_bucket{le=\"+Inf\"} 1001"));
        assert!(!rendered.contains("private"));
        counters.configure(&Config {
            version: 1,
            routes: vec![],
            trusted_proxies: vec![],
        });
        counters.record(&e);
        assert!(counters.routes.is_empty());
        assert_eq!(counters.global.requests, 1002);
    }
}

use crate::{
    certificates::{Certificate, CertificateInput, CertificateStore, StoredCertificate},
    config::Config,
    state::{now, Shared},
};

use async_trait::async_trait;
use axum::{
    extract::{DefaultBodyLimit, Path, Query, Request, State},
    http::{header, HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post},
    Extension, Json, Router,
};
use pingora::{server::ShutdownWatch, services::background::BackgroundService};
use serde::Deserialize;
use serde_json::json;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

type ApiError = (StatusCode, Json<serde_json::Value>);
fn failure(status: StatusCode, message: impl ToString) -> ApiError {
    (status, Json(json!({"error": message.to_string()})))
}
fn token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|part| part.trim().strip_prefix("gateway_session="))
}

async fn protect(State(state): State<Shared>, mut request: Request, next: Next) -> Response {
    let session = token(request.headers()).and_then(|token| {
        let mut sessions = state.sessions.lock().unwrap();
        sessions.retain(|_, session| session.expires > Instant::now());
        sessions.get(token).cloned()
    });
    let Some(mut session) = session else {
        return failure(StatusCode::UNAUTHORIZED, "Please sign in.").into_response();
    };
    let path = request.uri().path().to_owned();
    let method = request.method().to_string();
    let mutating = method != "GET" && method != "HEAD";
    let verified = !mutating
        || request
            .headers()
            .get("x-gateway-request")
            .and_then(|h| h.to_str().ok())
            == Some("1");
    let persistent_write = mutating && path != "/api/diagnostics";
    let _mutation = if persistent_write {
        Some(state.backups.mutations.lock().await)
    } else {
        None
    };
    // A waiting write must use the current session and policy after preceding mutations finish.
    if mutating {
        let fresh = token(request.headers()).and_then(|token| {
            state
                .sessions
                .lock()
                .unwrap()
                .get(token)
                .filter(|s| s.expires > Instant::now())
                .cloned()
        });
        let Some(fresh) = fresh else {
            return failure(StatusCode::UNAUTHORIZED, "Please sign in.").into_response();
        };
        session = fresh;
    }
    let mfa_enabled = match crate::mfa::enabled(&state, &session.user.id).await {
        Ok(value) => value,
        Err(error) => return failure(StatusCode::SERVICE_UNAVAILABLE, error).into_response(),
    };
    if mfa_enabled && !session.mfa_verified {
        return failure(
            StatusCode::UNAUTHORIZED,
            "Two-factor authentication changed. Please sign in again.",
        )
        .into_response();
    }
    let enforcement = match crate::mfa::policy(&state) {
        Ok(value) => value,
        Err(error) => return failure(StatusCode::SERVICE_UNAVAILABLE, error).into_response(),
    };
    let enrollment_required = session.user.role.admin() && enforcement && !mfa_enabled;
    let allowed = session.user.role.admin()
        || (!mutating
            && !matches!(path.as_str(), "/api/users" | "/api/audit")
            && !path.starts_with("/api/backups/")
            && !path.starts_with("/api/config/history")
            && !path.starts_with("/api/host-templates")
            && !path.starts_with("/api/cluster"))
        || (method == "POST" && matches!(path.as_str(), "/api/logout" | "/api/password"))
        || (method == "DELETE" && path.starts_with("/api/sessions/"))
        || (path.starts_with("/api/passkeys/") && path != "/api/passkeys/config")
        || matches!(
            (method.as_str(), path.as_str()),
            (
                "POST",
                "/api/mfa/setup" | "/api/mfa/confirm" | "/api/mfa/recovery"
            ) | ("DELETE", "/api/mfa")
        );
    if mutating && crate::cluster::follower(&state) && crate::cluster::shared_write(&path) {
        return failure(StatusCode::CONFLICT, "This node follows a primary. Change shared routes, certificates, and policies on the primary.").into_response();
    }
    if persistent_write
        && state
            .backups
            .pending
            .load(std::sync::atomic::Ordering::SeqCst)
        && !matches!(
            path.as_str(),
            "/api/backups/cancel" | "/api/backups/export" | "/api/logout"
        )
    {
        return failure(StatusCode::CONFLICT,"A restore is queued. Restart EmberGate to apply it, or cancel it before making changes.").into_response();
    }
    let before = state.config.load().version;
    let audit = if mutating {
        match state
            .control
            .begin_audit(
                session.actor(),
                method.clone(),
                path.clone(),
                json!({"configuration_version":before}),
            )
            .await
        {
            Ok(id) => Some(id),
            Err(_) if path == "/api/logout" => None,
            Err(error) => return failure(StatusCode::SERVICE_UNAVAILABLE, error).into_response(),
        }
    } else {
        None
    };
    request.extensions_mut().insert(session);
    let mut response = if !verified {
        failure(
            StatusCode::FORBIDDEN,
            "Missing request verification header.",
        )
        .into_response()
    } else if enrollment_required
        && !matches!(
            (method.as_str(), path.as_str()),
            ("GET", "/api/session" | "/api/mfa")
                | (
                    "POST",
                    "/api/mfa/setup" | "/api/mfa/confirm" | "/api/logout"
                )
        )
    {
        (StatusCode::FORBIDDEN, Json(json!({"error":"Set up two-factor authentication before continuing.","mfa_enrollment_required":true}))).into_response()
    } else if !allowed {
        failure(StatusCode::FORBIDDEN, "Administrator access required.").into_response()
    } else {
        next.run(request).await
    };
    if persistent_write && response.status().is_success() && !path.starts_with("/api/backups/") {
        state
            .backups
            .revision
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
    if let Some(id) = audit {
        let target = response
            .extensions()
            .get::<crate::management::AuditExtra>()
            .map(|extra| extra.0.clone())
            .or_else(|| {
                path.split('/')
                    .find(|part| uuid::Uuid::parse_str(part).is_ok())
                    .map(str::to_owned)
            });
        let details = response
            .extensions()
            .get::<crate::management::AuditDetails>()
            .map(|extra| extra.0.clone())
            .unwrap_or_else(|| json!({}));
        if let Err(error) = state
            .control
            .finish_audit(id, response.status().as_u16(), target, details, None)
            .await
        {
            log::error!("Audit completion pending: {error}");
            response
                .headers_mut()
                .insert("x-gateway-audit-pending", "1".parse().unwrap());
        }
    }
    response
}

async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    headers.insert("x-content-type-options", "nosniff".parse().unwrap());
    headers.insert("referrer-policy", "no-referrer".parse().unwrap());
    headers.insert("content-security-policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'".parse().unwrap());
    response
}

async fn logout(State(state): State<Shared>, headers: HeaderMap) -> impl IntoResponse {
    if let Some(t) = token(&headers) {
        state.sessions.lock().unwrap().remove(t);
    }
    (
        [(
            header::SET_COOKIE,
            "gateway_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
        )],
        Json(json!({"ok": true})),
    )
}

async fn get_config(State(state): State<Shared>) -> Json<Config> {
    Json((**state.config.load()).clone())
}

pub(crate) async fn save_config(
    State(state): State<Shared>,
    Extension(session): Extension<crate::accounts::Session>,
    Json(mut config): Json<Config>,
) -> Result<Response, ApiError> {
    config
        .validate()
        .map_err(|e| failure(StatusCode::UNPROCESSABLE_ENTITY, e))?;
    let _guard = state.write_lock.lock().await;
    let old = state.config.load_full();
    if old.version != config.version {
        return Err(failure(
            StatusCode::CONFLICT,
            "Configuration changed in another session. Refresh and try again.",
        ));
    }
    config.version = old.version.checked_add(1).ok_or_else(|| {
        failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Configuration version exhausted.",
        )
    })?;
    let bytes = serde_json::to_vec_pretty(&config)
        .map_err(|e| failure(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let previous = serde_json::to_vec_pretty(old.as_ref())
        .map_err(|e| failure(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let path = state.config_path.clone();
    let archived = old.as_ref().clone();
    let actor = session.user.username;
    tokio::task::spawn_blocking(move || -> Result<(), String> {
        crate::history::archive(path.parent().unwrap(), archived, actor)?;
        crate::history::write_atomic(&path.with_extension("previous.json"), &previous)
            .map_err(|e| e.to_string())?;
        crate::history::write_atomic(&path, &bytes).map_err(|e| e.to_string())?;
        Ok(())
    })
    .await
    .map_err(|e| failure(StatusCode::INTERNAL_SERVER_ERROR, e))?
    .map_err(|e| {
        log::error!("Configuration save failed: {e}");
        failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Could not save configuration. The active routes were retained.",
        )
    })?;
    state.metrics.lock().unwrap().prometheus.configure(&config);
    state.config.store(Arc::new(config.clone()));
    state.rate_limits.retain_config(&config);
    state.http_cache.sync_config(&config);
    let changed_routes: Vec<_> = config
        .routes
        .iter()
        .filter(|route| {
            old.routes
                .iter()
                .find(|previous| previous.id == route.id)
                .is_none_or(|previous| {
                    serde_json::to_value(previous).ok() != serde_json::to_value(route).ok()
                })
        })
        .map(|r| r.id.clone())
        .chain(
            old.routes
                .iter()
                .filter(|previous| !config.routes.iter().any(|r| r.id == previous.id))
                .map(|r| r.id.clone()),
        )
        .take(25)
        .collect();
    let details = json!({"configuration_version_before":old.version,"configuration_version_after":config.version,"changed_route_ids":changed_routes});
    let mut response = Json(config).into_response();
    response
        .extensions_mut()
        .insert(crate::management::AuditDetails(details));
    Ok(response)
}

async fn stats(State(state): State<Shared>) -> Json<serde_json::Value> {
    let metrics = state.metrics.lock().unwrap();
    let minute = now() / 60 * 60;
    let buckets: Vec<_> = (0..60).rev().map(|offset| {
        let timestamp = minute - offset * 60;
        let existing = metrics.buckets.iter().find(|b| b.timestamp == timestamp);
        json!({"timestamp": timestamp, "requests": existing.map_or(0, |b| b.requests), "errors": existing.map_or(0, |b| b.errors)})
    }).collect();
    Json(
        json!({"requests": metrics.requests, "errors": metrics.errors, "rate_limited": metrics.rate_limited,
        "avg_latency_ms": if metrics.requests == 0 { 0.0 } else { metrics.latency_total_ms / metrics.requests as f64 },
        "uptime_seconds": state.started.elapsed().as_secs(), "buckets": buckets,
        "proxy_addr": state.proxy_addr, "admin_addr": state.admin_addr,
        "https_addr": state.https_addr,
        "cluster_role": crate::cluster::role(&state), "cluster_ready": crate::cluster::ready(&state),
        "version": env!("CARGO_PKG_VERSION")}),
    )
}
async fn logs(State(state): State<Shared>) -> Result<Json<serde_json::Value>, ApiError> {
    state
        .analytics
        .query(24, None, true)
        .await
        .map(Json)
        .map_err(|e| failure(StatusCode::SERVICE_UNAVAILABLE, e))
}
#[derive(Deserialize)]
struct AnalyticsQuery {
    hours: Option<u64>,
    route_id: Option<String>,
}
async fn analytics(
    State(state): State<Shared>,
    Query(query): Query<AnalyticsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let hours = query.hours.unwrap_or(24);
    if ![24, 168, 720].contains(&hours)
        || query
            .route_id
            .as_ref()
            .is_some_and(|id| id != "unmatched" && uuid::Uuid::parse_str(id).is_err())
    {
        return Err(failure(
            StatusCode::BAD_REQUEST,
            "Choose 24, 168, or 720 hours and a valid route ID.",
        ));
    }
    state
        .analytics
        .query(hours, query.route_id, false)
        .await
        .map(Json)
        .map_err(|e| failure(StatusCode::SERVICE_UNAVAILABLE, e))
}
async fn cloudflare_networks() -> Result<Json<serde_json::Value>, ApiError> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| {
            failure(
                StatusCode::BAD_GATEWAY,
                "Could not initialize Cloudflare lookup.",
            )
        })?;
    let response = client
        .get("https://api.cloudflare.com/client/v4/ips")
        .send()
        .await
        .map_err(|_| {
            failure(
                StatusCode::BAD_GATEWAY,
                "Could not retrieve Cloudflare networks.",
            )
        })?;
    if !response.status().is_success() {
        return Err(failure(
            StatusCode::BAD_GATEWAY,
            "Cloudflare network lookup failed.",
        ));
    }
    let value: serde_json::Value = response
        .json()
        .await
        .map_err(|_| failure(StatusCode::BAD_GATEWAY, "Invalid Cloudflare network list."))?;
    let mut networks = vec![];
    for field in ["ipv4_cidrs", "ipv6_cidrs"] {
        let entries = value["result"][field]
            .as_array()
            .ok_or_else(|| failure(StatusCode::BAD_GATEWAY, "Invalid Cloudflare network list."))?;
        for entry in entries {
            let text = entry
                .as_str()
                .ok_or_else(|| failure(StatusCode::BAD_GATEWAY, "Invalid network."))?;
            let net = crate::policy::network(text)
                .map_err(|_| failure(StatusCode::BAD_GATEWAY, "Invalid network."))?;
            networks.push(net.to_string());
        }
    }
    if networks.is_empty() || networks.len() > 64 {
        return Err(failure(
            StatusCode::BAD_GATEWAY,
            "Unexpected Cloudflare network list.",
        ));
    }
    Ok(Json(json!({"networks":networks})))
}

async fn upstream_status(State(state): State<Shared>) -> Json<serde_json::Value> {
    let config = state.config.load();
    Json(json!({"version": config.version, "routes": state.upstreams.snapshot(&config)}))
}

async fn cache_status(State(state): State<Shared>) -> Json<serde_json::Value> {
    Json(state.http_cache.summary(&state.config.load()))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CachePurge {
    route_id: Option<String>,
    url: Option<String>,
}
async fn cache_purge(
    State(state): State<Shared>,
    Json(input): Json<CachePurge>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let _guard = state.write_lock.lock().await;
    if input
        .route_id
        .as_ref()
        .is_some_and(|id| !state.config.load().routes.iter().any(|r| &r.id == id))
    {
        return Err(failure(StatusCode::NOT_FOUND, "Route not found."));
    }
    let removed = state
        .http_cache
        .purge_route(input.route_id.as_deref(), input.url.as_deref())
        .map_err(|e| failure(StatusCode::UNPROCESSABLE_ENTITY, e))?;
    Ok(Json(json!({"removed":removed})))
}

async fn list_certificates(State(state): State<Shared>) -> Json<serde_json::Value> {
    Json(
        json!({"certificates": state.certificates.load().summaries(), "https_addr": state.https_addr}),
    )
}

async fn write_certificate(
    state: Shared,
    id: String,
    input: Option<CertificateInput>,
    replace: bool,
) -> Result<Json<serde_json::Value>, ApiError> {
    if state.acme.manages(&id).await {
        return Err(failure(StatusCode::CONFLICT, "This certificate is managed automatically. Stop automatic management before uploading a replacement or deleting it."));
    }
    let _guard = state.write_lock.lock().await;
    let mut records = state.certificates.load().records();
    if replace && !records.iter().any(|record| record.id == id) {
        return Err(failure(StatusCode::NOT_FOUND, "Certificate not found."));
    }
    let reserved_domains = state.acme.reserved_domains().await;
    let path = state.certificates_path.clone();
    let store = tokio::task::spawn_blocking(move || -> Result<CertificateStore, ApiError> {
        records.retain(|record| record.id != id);
        if let Some(input) = input {
            let cert = Certificate::parse(StoredCertificate { id, input }, true)
                .map_err(|error| failure(StatusCode::UNPROCESSABLE_ENTITY, error))?;
            if cert.domains.iter().any(|domain| reserved_domains.contains(domain)) {
                return Err(failure(StatusCode::CONFLICT, "An ACME request already manages one of these DNS names. Stop its automatic management before uploading a certificate."));
            }
            records.push(cert.stored);
        }
        let store = CertificateStore::parse(records)
            .map_err(|error| failure(StatusCode::UNPROCESSABLE_ENTITY, error))?;
        store.persist(&path).map_err(|error| {
            log::error!("Could not save certificates: {error}");
            failure(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not save certificates. The active certificates were retained.",
            )
        })?;
        Ok(store)
    })
    .await
    .map_err(|_| {
        failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Could not process certificate.",
        )
    })??;
    let summaries = store.summaries();
    state.certificates.store(Arc::new(store));
    Ok(Json(
        json!({"certificates": summaries, "https_addr": state.https_addr}),
    ))
}

async fn upload_certificate(
    State(state): State<Shared>,
    Json(input): Json<CertificateInput>,
) -> Result<Json<serde_json::Value>, ApiError> {
    write_certificate(state, uuid::Uuid::new_v4().to_string(), Some(input), false).await
}
async fn replace_certificate(
    State(state): State<Shared>,
    Path(id): Path<String>,
    Json(input): Json<CertificateInput>,
) -> Result<Json<serde_json::Value>, ApiError> {
    write_certificate(state, id, Some(input), true).await
}
async fn delete_certificate(
    State(state): State<Shared>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    write_certificate(state, id, None, true).await
}

async fn acme_status(State(state): State<Shared>) -> Json<serde_json::Value> {
    Json(state.acme.status().await)
}
async fn request_managed_certificate(
    State(state): State<Shared>,
    Json(input): Json<crate::acme::CertificateRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let order = state
        .acme
        .request(input, &state)
        .await
        .map_err(|error| failure(StatusCode::UNPROCESSABLE_ENTITY, error))?;
    Ok((StatusCode::ACCEPTED, Json(order)))
}
async fn renew_managed_certificate(
    State(state): State<Shared>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    state
        .acme
        .renew(&id)
        .await
        .map_err(|error| failure(StatusCode::CONFLICT, error))?;
    Ok((StatusCode::ACCEPTED, Json(json!({"ok":true}))))
}
async fn stop_managing_certificate(
    State(state): State<Shared>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state
        .acme
        .remove(&id)
        .await
        .map_err(|error| failure(StatusCode::CONFLICT, error))?;
    Ok(Json(json!({"ok":true})))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AcmeConsent {
    agree_to_terms: bool,
}
async fn production_certificate(
    State(state): State<Shared>,
    Path(id): Path<String>,
    Json(input): Json<AcmeConsent>,
) -> Result<impl IntoResponse, ApiError> {
    state
        .acme
        .production(&id, input.agree_to_terms)
        .await
        .map_err(|error| failure(StatusCode::CONFLICT, error))?;
    Ok((StatusCode::ACCEPTED, Json(json!({"ok":true}))))
}

async fn credentials_status(State(state): State<Shared>) -> Json<serde_json::Value> {
    Json(
        json!({"cloudflare":state.acme.credential_status(),"admin_password":{"source":if state.password_hash.is_some(){"environment"}else{"database"},"editable":state.password_hash.is_none()}}),
    )
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CloudflareToken {
    token: String,
}
async fn save_cloudflare_token(
    State(state): State<Shared>,
    Json(input): Json<CloudflareToken>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state
        .acme
        .save_token(&state.control, Some(input.token))
        .await
        .map_err(|e| failure(StatusCode::CONFLICT, e))?;
    Ok(Json(state.acme.credential_status()))
}
async fn remove_cloudflare_token(
    State(state): State<Shared>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state
        .acme
        .save_token(&state.control, None)
        .await
        .map_err(|e| failure(StatusCode::CONFLICT, e))?;
    Ok(Json(state.acme.credential_status()))
}
pub fn router(state: Shared) -> Router {
    let protected = Router::new()
        .merge(crate::accounts::routes())
        .merge(crate::mfa::routes())
        .merge(crate::passkeys::routes())
        .merge(crate::cluster::routes())
        .route("/api/diagnostics", post(crate::diagnostics::run))
        .route("/api/documentation", get(crate::documentation::get))
        .merge(crate::alerts::routes())
        .merge(crate::backup::routes())
        .merge(crate::scheduled::routes())
        .merge(crate::history::routes())
        .merge(crate::templates::routes())
        .route("/api/metrics", get(crate::prometheus::authenticated))
        .route(
            "/api/integrations/prometheus",
            get(crate::prometheus::status)
                .post(crate::prometheus::rotate)
                .delete(crate::prometheus::disable),
        )
        .route("/api/credentials", get(credentials_status))
        .route(
            "/api/credentials/cloudflare",
            axum::routing::put(save_cloudflare_token).delete(remove_cloudflare_token),
        )
        .route("/api/logout", post(logout))
        .route("/api/config", get(get_config).put(save_config))
        .route("/api/stats", get(stats))
        .route("/api/logs", get(logs))
        .route("/api/cache", get(cache_status))
        .route("/api/cache/purge", post(cache_purge))
        .route("/api/analytics", get(analytics))
        .route("/api/cloudflare/networks", get(cloudflare_networks))
        .route("/api/upstreams", get(upstream_status))
        .route("/api/acme", get(acme_status))
        .route("/api/acme/orders", post(request_managed_certificate))
        .route(
            "/api/acme/orders/{id}/renew",
            post(renew_managed_certificate),
        )
        .route(
            "/api/acme/orders/{id}/production",
            post(production_certificate),
        )
        .route("/api/acme/orders/{id}", delete(stop_managing_certificate))
        .route(
            "/api/certificates",
            get(list_certificates).post(upload_certificate),
        )
        .route(
            "/api/certificates/{id}",
            delete(delete_certificate).put(replace_certificate),
        )
        .route_layer(middleware::from_fn_with_state(state.clone(), protect));
    Router::new()
        .merge(protected)
        .route("/metrics", get(crate::prometheus::scrape))
        .route("/healthz/ready", get(crate::cluster::health))
        .route("/api/cluster/snapshot", get(crate::cluster::snapshot))
        .route("/api/login", post(crate::accounts::login))
        .route(
            "/api/passkeys/login/start",
            post(crate::passkeys::login_start),
        )
        .route(
            "/api/passkeys/login/finish",
            post(crate::passkeys::login_finish),
        )
        .route(
            "/api/setup",
            get(crate::accounts::setup_status).post(crate::accounts::setup),
        )
        .route(
            "/",
            get(|| async { Html(include_str!("../web/index.html")) }),
        )
        .route(
            "/app.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    include_str!("../web/app.js"),
                )
            }),
        )
        .route(
            "/style.css",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
                    include_str!("../web/style.css"),
                )
            }),
        )
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

pub struct Management {
    pub state: Shared,
    // Bind before starting Pingora so an unavailable admin port fails startup.
    pub listener: std::sync::Mutex<Option<std::net::TcpListener>>,
}
#[async_trait]
impl BackgroundService for Management {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let listener = self
            .listener
            .lock()
            .unwrap()
            .take()
            .expect("Management service started twice");
        let listener =
            tokio::net::TcpListener::from_std(listener).expect("Cannot adopt admin listener");
        if let Err(error) = axum::serve(
            listener,
            router(self.state.clone())
                .into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = shutdown.changed().await;
        })
        .await
        {
            log::error!("Management server stopped: {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use std::collections::HashMap;
    use tower::ServiceExt;

    fn state() -> Shared {
        let path = std::env::temp_dir().join(format!("gateway-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&path).unwrap();
        let salt = SaltString::encode_b64(b"test-salt-for-gateway").unwrap();
        Arc::new(crate::state::AppState {
            backups: crate::backup::Manager::default(),
            http_cache: Box::leak(Box::new(crate::cache::ResponseCache::default())),
            analytics: crate::analytics::Analytics::open(&path.join("analytics.sqlite3")).unwrap(),
            rate_limits: crate::rate_limit::RateLimits::default(),
            upstreams: crate::upstreams::Upstreams::default(),
            acme: crate::acme::Acme::disabled(&path),
            config: arc_swap::ArcSwap::from_pointee(Config::default()),
            certificates: arc_swap::ArcSwap::from_pointee(CertificateStore::default()),
            certificates_path: path.join("certificates.json"),
            write_lock: tokio::sync::Mutex::new(()),
            metrics: std::sync::Mutex::new(Default::default()),
            sessions: std::sync::Mutex::new(HashMap::new()),
            login_attempts: std::sync::Mutex::new(HashMap::new()),
            control: crate::management::Control::open(&path.join("management.sqlite3")).unwrap(),
            account_write_lock: tokio::sync::Mutex::new(()),
            password_hash: Some(
                Argon2::default()
                    .hash_password(b"test-password-123", &salt)
                    .unwrap()
                    .to_string(),
            ),
            dummy_password_hash: Argon2::default()
                .hash_password(b"dummy-password-123", &salt)
                .unwrap()
                .to_string(),
            setup_token: None,
            config_path: path.join("routes.json"),
            proxy_addr: "127.0.0.1:8080".into(),
            admin_addr: "127.0.0.1:9090".into(),
            https_addr: None,
            secure_cookie: false,
            started: Instant::now(),
        })
    }
    fn request(
        method: &str,
        path: &str,
        cookie: &str,
        body: serde_json::Value,
        verified: bool,
    ) -> Request<Body> {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::COOKIE, cookie);
        if verified {
            request = request.header("x-gateway-request", "1");
        }
        request.body(Body::from(body.to_string())).unwrap()
    }
    #[tokio::test]
    async fn documentation_requires_login_and_is_available_to_both_roles() {
        let state = state();
        let app = router(state.clone());
        let response = app
            .clone()
            .oneshot(request("GET", "/api/documentation", "", json!(null), false))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        for (token, role) in [
            ("docs-admin", crate::management::Role::Administrator),
            ("docs-reader", crate::management::Role::ReadOnly),
        ] {
            let mut user = crate::management::bootstrap();
            user.role = role;
            state.sessions.lock().unwrap().insert(
                token.into(),
                crate::accounts::Session::new(user, "local".into()),
            );
            let response = app
                .clone()
                .oneshot(request(
                    "GET",
                    "/api/documentation",
                    &format!("gateway_session={token}"),
                    json!(null),
                    false,
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
            let data: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(data["version"], env!("CARGO_PKG_VERSION"));
            assert_eq!(data["guides"].as_array().unwrap().len(), 8);
        }
        std::fs::remove_dir_all(state.config_path.parent().unwrap()).unwrap();
    }
    #[tokio::test]
    async fn login_protects_api_and_logout_revokes_session() {
        let state = state();
        let app = router(state.clone());
        let response = app
            .clone()
            .oneshot(request("GET", "/api/config", "", json!(null), false))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let response = app
            .clone()
            .oneshot(request(
                "POST",
                "/api/login",
                "",
                json!({"password":"wrong"}),
                true,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let response = app
            .clone()
            .oneshot(request(
                "POST",
                "/api/login",
                "",
                json!({"password":"test-password-123"}),
                true,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let cookie = response.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        assert!(response.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .contains("HttpOnly; SameSite=Strict"));
        let response = app
            .clone()
            .oneshot(request("GET", "/api/config", &cookie, json!(null), false))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response = app
            .clone()
            .oneshot(request("POST", "/api/logout", &cookie, json!(null), false))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let response = app
            .clone()
            .oneshot(request("POST", "/api/logout", &cookie, json!(null), true))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response = app
            .oneshot(request("GET", "/api/config", &cookie, json!(null), false))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        std::fs::remove_dir_all(state.config_path.parent().unwrap()).unwrap();
    }
    #[tokio::test]
    async fn waiting_writes_recheck_revoked_sessions_and_mfa_policy() {
        let state = state();
        let app = router(state.clone());
        for policy in [false, true] {
            state.sessions.lock().unwrap().insert(
                "waiting".into(),
                crate::accounts::Session::new(crate::management::bootstrap(), "local".into()),
            );
            let guard = state.backups.mutations.lock().await;
            let mut response = Box::pin(app.clone().oneshot(request(
                "PUT",
                "/api/config",
                "gateway_session=waiting",
                json!({"version":0,"routes":[]}),
                true,
            )));
            assert!(
                tokio::time::timeout(Duration::from_millis(10), &mut response)
                    .await
                    .is_err()
            );
            if policy {
                state
                    .control
                    .set_secret("mfa_policy".into(), Some("true".into()))
                    .await
                    .unwrap();
            } else {
                state.sessions.lock().unwrap().clear();
            }
            drop(guard);
            assert_eq!(
                response.await.unwrap().status(),
                if policy {
                    StatusCode::FORBIDDEN
                } else {
                    StatusCode::UNAUTHORIZED
                }
            );
            assert_eq!(state.config.load().version, 0);
        }
        let audit = state.control.audit().await.unwrap();
        assert!(audit["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["path"] == "/api/config" && e["status"] == 403));
        std::fs::remove_dir_all(state.config_path.parent().unwrap()).unwrap();
    }
    #[tokio::test]
    async fn config_saves_persists_and_rejects_stale_or_invalid_changes() {
        let state = state();
        state.sessions.lock().unwrap().insert(
            "test".into(),
            crate::accounts::Session::new(crate::management::bootstrap(), "local".into()),
        );
        let app = router(state.clone());
        let cookie = "gateway_session=test";
        let route = json!({"id":uuid::Uuid::new_v4().to_string(), "name":"Site", "host":"APP.TEST", "path_prefix":"/", "upstream":"http://127.0.0.1:9000", "enabled":true,"preserve_host":false});
        let response = app
            .clone()
            .oneshot(request(
                "PUT",
                "/api/config",
                cookie,
                json!({"version":0,"routes":[route.clone()]}),
                true,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let result: Config = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(result.version, 1);
        assert_eq!(result.routes[0].host, "app.test");
        assert_eq!(Config::load(&state.config_path).unwrap().version, 1);
        assert_eq!(
            Config::load(&state.config_path.with_extension("previous.json"))
                .unwrap()
                .version,
            0
        );
        let response = app
            .clone()
            .oneshot(request(
                "PUT",
                "/api/config",
                cookie,
                json!({"version":0,"routes":[]}),
                true,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let response = app
            .oneshot(request(
                "PUT",
                "/api/config",
                cookie,
                json!({"version":1,"routes":[route.clone(),route]}),
                true,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(state.config.load().routes.len(), 1);
        std::fs::remove_dir_all(state.config_path.parent().unwrap()).unwrap();
    }
    #[tokio::test]
    async fn readonly_permissions_and_unavailable_audit_prevent_writes() {
        let state = state();
        let mut reader = crate::management::bootstrap();
        reader.id = "reader".into();
        reader.username = "reader".into();
        reader.role = crate::management::Role::ReadOnly;
        state.sessions.lock().unwrap().insert(
            "reader".into(),
            crate::accounts::Session::new(reader, "local".into()),
        );
        state.sessions.lock().unwrap().insert(
            "owner".into(),
            crate::accounts::Session::new(crate::management::bootstrap(), "local".into()),
        );
        let app = router(state.clone());
        for (method, path, status) in [
            ("GET", "/api/config", StatusCode::OK),
            ("GET", "/api/users", StatusCode::FORBIDDEN),
            ("GET", "/api/audit", StatusCode::FORBIDDEN),
            ("PUT", "/api/config", StatusCode::FORBIDDEN),
            ("POST", "/api/cache/purge", StatusCode::FORBIDDEN),
            ("PUT", "/api/alerts/settings", StatusCode::FORBIDDEN),
        ] {
            let response = app
                .clone()
                .oneshot(request(
                    method,
                    path,
                    "gateway_session=reader",
                    json!({}),
                    true,
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), status);
        }
        assert!(state.control.audit().await.unwrap()["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["status"] == 403));
        state
            .control
            .run(|db| {
                db.execute_batch("DROP TABLE audit")
                    .map_err(crate::management::storage)
            })
            .await
            .unwrap();
        let response = app
            .oneshot(request(
                "PUT",
                "/api/config",
                "gateway_session=owner",
                json!({"version":0,"routes":[]}),
                true,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(state.config.load().version, 0);
        assert!(!state.config_path.exists());
        std::fs::remove_dir_all(state.config_path.parent().unwrap()).unwrap();
    }
}

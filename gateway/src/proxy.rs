use crate::{
    config::{normalized_host, Route},
    state::{now, AccessLog, Shared},
};
use async_trait::async_trait;
use pingora::{prelude::*, ErrorType};
use std::time::{Duration, Instant};

pub struct Gateway(pub Shared);
pub struct Context {
    route: Option<Route>,
    auth_headers: Vec<(reqwest::header::HeaderName, reqwest::header::HeaderValue)>,
    oidc_identity: Option<crate::oidc::Identity>,
    upstream: Option<String>,
    lease: Option<crate::upstreams::Lease>,
    attempted: Vec<String>,
    retry_eligible: bool,
    response_started: bool,
    header_latency_ms: std::sync::OnceLock<f64>,
    long_lived: bool,
    maintenance: bool,
    rate_limited: bool,
    access_denied: bool,
    crowdsec_blocked: bool,
    identity: crate::policy::Identity,
    started: Instant,
    received: std::time::SystemTime,
    config_version: u64,
    cache_key: Option<pingora::cache::CacheKey>,
    cache_status: &'static str,
    // Held from request start until upstream response headers arrive (or the
    // request ends), so upgraded and streaming connections never keep it.
    session_lock: Option<tokio::sync::OwnedMutexGuard<()>>,
}

impl Gateway {
    fn selection_route(&self, ctx: &Context) -> Option<(u64, Route)> {
        let original = ctx.route.as_ref()?;
        let config = self.0.config.load();
        let current = config
            .routes
            .iter()
            .find(|route| route.id == original.id && route.enabled)?;
        // Do not retry into an origin pool that changed during this request.
        if current.upstream != original.upstream
            || current.additional_upstreams != original.additional_upstreams
        {
            return None;
        }
        Some((config.version, current.clone()))
    }
    fn select_lease(&self, ctx: &Context) -> Option<crate::upstreams::Lease> {
        for _ in 0..3 {
            let (version, route) = self.selection_route(ctx)?;
            let lease =
                self.0
                    .upstreams
                    .select_request(&route, ctx.identity.client, &ctx.attempted);
            // Reserve/count the request before checking the revision. A published drain either
            // sees this as an existing request, or makes us discard the reservation and reselect.
            if self.0.config.load().version == version {
                return lease;
            }
        }
        None
    }
    fn retry_error(
        &self,
        session: &mut Session,
        ctx: &mut Context,
        mut error: Box<Error>,
    ) -> Box<Error> {
        let retries = ctx
            .route
            .as_ref()
            .and_then(|r| r.reliability.as_ref())
            .map_or(0, |policy| policy.retries);
        let network = matches!(
            error.etype(),
            ErrorType::ConnectTimedout
                | ErrorType::ConnectRefused
                | ErrorType::ConnectNoRoute
                | ErrorType::ConnectError
                | ErrorType::SocketError
                | ErrorType::ReadError
                | ErrorType::WriteError
                | ErrorType::ReadTimedout
                | ErrorType::WriteTimedout
                | ErrorType::ConnectionClosed
                | ErrorType::TLSHandshakeTimedout
        );
        let allowed = ctx.retry_eligible
            && !ctx.response_started
            && session.response_written().is_none()
            && !session.retry_buffer_truncated()
            && *error.esource() == pingora::ErrorSource::Upstream
            && network
            && ctx.attempted.len() <= retries as usize;
        error.set_retry(false);
        if allowed {
            ctx.lease.take();
            if let Some(lease) = self.select_lease(ctx) {
                ctx.upstream = Some(lease.origin.clone());
                ctx.lease = Some(lease);
                error.set_retry(true);
            }
        }
        error
    }
}

#[async_trait]
impl ProxyHttp for Gateway {
    type CTX = Context;
    fn init_downstream_modules(&self, modules: &mut pingora::modules::http::HttpModules) {
        crate::compression::register(modules);
    }
    fn new_ctx(&self) -> Context {
        Context {
            route: None,
            auth_headers: vec![],
            oidc_identity: None,
            upstream: None,
            lease: None,
            attempted: vec![],
            retry_eligible: false,
            response_started: false,
            header_latency_ms: std::sync::OnceLock::new(),
            long_lived: false,
            maintenance: false,
            rate_limited: false,
            access_denied: false,
            crowdsec_blocked: false,
            identity: crate::policy::Identity {
                client: None,
                peer: None,
                https: false,
                source: "connection",
            },
            started: Instant::now(),
            received: std::time::SystemTime::now(),
            config_version: 0,
            cache_key: None,
            cache_status: "OFF",
            session_lock: None,
        }
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Context) -> Result<bool> {
        if !crate::cluster::ready(&self.0) {
            local_response(
                session,
                ctx,
                503,
                "This follower is waiting for a fresh primary snapshot.\n",
                &[],
            )
            .await?;
            return Ok(true);
        }
        ctx.retry_eligible = matches!(session.req_header().method.as_str(), "GET" | "HEAD")
            && session.is_body_empty()
            && !session.req_header().headers.contains_key("upgrade")
            && !session
                .req_header()
                .headers
                .contains_key("transfer-encoding")
            && session
                .req_header()
                .headers
                .get_all("content-length")
                .iter()
                .all(|value| {
                    value
                        .to_str()
                        .ok()
                        .and_then(|v| v.trim().parse::<u64>().ok())
                        == Some(0)
                });
        let host = session
            .req_header()
            .headers
            .get("host")
            .and_then(|h| h.to_str().ok())
            .or_else(|| session.req_header().uri.authority().map(|a| a.as_str()))
            .and_then(normalized_host)
            .unwrap_or_default();
        let config = self.0.config.load_full();
        ctx.config_version = config.version;
        let peer = match session.client_addr() {
            Some(pingora::protocols::l4::socket::SocketAddr::Inet(addr)) => Some(addr.ip()),
            _ => None,
        };
        let tls = session
            .digest()
            .is_some_and(|digest| digest.ssl_digest.is_some());
        ctx.identity = crate::policy::identity(
            peer,
            tls,
            &session.req_header().headers,
            &config.trusted_proxies,
        );
        ctx.route = config.find_route(&host, session.req_header().uri.path());
        if ctx.route.is_none() {
            local_response(
                session,
                ctx,
                404,
                "No proxy host matches this request.\n",
                &[],
            )
            .await?;
            return Ok(true);
        }
        if let Some(ip) = ctx.identity.client {
            if let Some(remedy) = self.0.crowdsec.remedy(ip) {
                let remediation = self.0.crowdsec.remediation.load_full();
                if remedy == crate::crowdsec::Remedy::Captcha && remediation.challenges() {
                    if !captcha(session, ctx, &remediation, ip).await? {
                        return Ok(true);
                    }
                } else {
                    // Captcha decisions without a configured provider are handled as bans.
                    ctx.access_denied = true;
                    ctx.crowdsec_blocked = true;
                    local_response(
                        session,
                        ctx,
                        403,
                        &format!("{}\n", remediation.settings.ban_message),
                        &[],
                    )
                    .await?;
                    return Ok(true);
                }
            }
        }
        let route = ctx.route.as_ref().unwrap();
        if route
            .access
            .as_ref()
            .is_some_and(|access| !access.permits(ctx.identity.client))
        {
            ctx.access_denied = true;
            local_response(session, ctx, 403, "Access denied.\n", &[]).await?;
            return Ok(true);
        }
        let grpc = crate::grpc::is_grpc(session.req_header());
        if grpc {
            ctx.retry_eligible = false;
            if session.req_header().version != axum::http::Version::HTTP_2
                || route.upstream_protocol.is_http1()
            {
                local_response(
                    session,
                    ctx,
                    426,
                    "Native gRPC requires an HTTP/2 client and an Auto or HTTP/2 upstream policy.",
                    &[],
                )
                .await?;
                return Ok(true);
            }
        }
        if route.upstream_protocol == crate::config::UpstreamProtocol::Http2
            && session.req_header().headers.contains_key("upgrade")
        {
            local_response(
                session,
                ctx,
                400,
                "Use Auto or HTTP/1.1 upstream transport for WebSocket upgrades.",
                &[],
            )
            .await?;
            return Ok(true);
        }
        if let Some(response) = &route.response {
            if response.redirect_https && !ctx.identity.https {
                let authority = if route.host == "*" {
                    host.as_str()
                } else {
                    route.host.as_str()
                };
                if authority.is_empty() {
                    local_response(session, ctx, 400, "Invalid request authority.\n", &[]).await?;
                    return Ok(true);
                }
                let port = if response.https_port == 443 {
                    String::new()
                } else {
                    format!(":{}", response.https_port)
                };
                let path = session
                    .req_header()
                    .uri
                    .path_and_query()
                    .map(|p| p.as_str())
                    .unwrap_or("/");
                let location = format!("https://{authority}{port}{path}");
                local_response(
                    session,
                    ctx,
                    308,
                    "Use HTTPS for this resource.\n",
                    &[("Location", location)],
                )
                .await?;
                return Ok(true);
            }
        }
        if let Some(retry_after) = self
            .0
            .rate_limits
            .check(ctx.route.as_ref().unwrap(), ctx.identity.client)
        {
            ctx.rate_limited = true;
            local_response(
                session,
                ctx,
                429,
                "Too many requests. Please try again later.\n",
                &[("Retry-After", retry_after.to_string())],
            )
            .await?;
            return Ok(true);
        }
        if let Some(pages) = ctx
            .route
            .as_ref()
            .and_then(|r| r.pages.as_ref())
            .filter(|p| p.maintenance)
        {
            ctx.maintenance = true;
            local_response(
                session,
                ctx,
                pages.status,
                &pages.message,
                &[("Retry-After", pages.retry_after_seconds.to_string())],
            )
            .await?;
            return Ok(true);
        }
        if let Some(policy) = ctx.route.as_ref().and_then(|r| r.oidc.clone()) {
            if !host_sign_in(&self.0, session, ctx, &policy).await? {
                return Ok(true);
            }
        }
        if let Some(policy) = ctx.route.as_ref().and_then(|r| r.forward_auth.clone()) {
            match crate::forward_auth::check(
                &policy,
                session.req_header(),
                &ctx.identity,
                &self.0.trust,
            )
            .await
            {
                crate::forward_auth::Decision::Allow(headers) => ctx.auth_headers = headers,
                crate::forward_auth::Decision::Deny(status, location) => {
                    ctx.access_denied = true;
                    let headers = location
                        .map(|value| vec![("Location", value)])
                        .unwrap_or_default();
                    local_response(
                        session,
                        ctx,
                        status,
                        "Application sign-in is required or access was denied.\n",
                        &headers,
                    )
                    .await?;
                    return Ok(true);
                }
                crate::forward_auth::Decision::Unavailable => {
                    local_response(
                        session,
                        ctx,
                        503,
                        "Application authentication is unavailable.\n",
                        &[],
                    )
                    .await?;
                    return Ok(true);
                }
            }
        }
        if ctx.route.as_ref().is_some_and(|r| r.serialize_by_session) {
            let route_id = ctx.route.as_ref().unwrap().id.clone();
            if let Some(key) = crate::serialize::session_key(session.req_header()) {
                match self.0.session_locks.acquire_timeout(&route_id, key).await {
                    Some(guard) => ctx.session_lock = Some(guard),
                    None => {
                        local_response(
                            session,
                            ctx,
                            503,
                            "Timed out waiting for an earlier request in this session.\n",
                            &[("retry-after", "1".to_string())],
                        )
                        .await?;
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }

    fn request_cache_filter(&self, session: &mut Session, ctx: &mut Context) -> Result<()> {
        let Some(route) = &ctx.route else {
            return Ok(());
        };
        let Some(policy) = &route.cache else {
            return Ok(());
        };
        ctx.cache_status = "BYPASS";
        if route.forward_auth.is_some()
            || route.oidc.is_some()
            || crate::grpc::is_grpc(session.req_header())
        {
            return Ok(());
        }
        if !session.as_mut().is_body_empty()
            || crate::cache::request_eligible(session.req_header(), policy).is_err()
        {
            return Ok(());
        }
        ctx.cache_key = self.0.http_cache.key(
            route,
            session.req_header(),
            ctx.identity.https,
            ctx.config_version,
        );
        if ctx.cache_key.is_none() {
            return Ok(());
        }
        session.cache.enable(
            self.0.http_cache,
            None,
            None,
            Some(&self.0.http_cache.lock),
            None,
        );
        session
            .cache
            .set_max_file_size_bytes(policy.max_object_bytes);
        ctx.cache_status = "MISS";
        Ok(())
    }
    fn cache_key_callback(
        &self,
        _: &Session,
        ctx: &mut Context,
    ) -> Result<pingora::cache::CacheKey> {
        ctx.cache_key
            .clone()
            .ok_or_else(|| Error::new(ErrorType::InternalError))
    }
    async fn cache_hit_filter(
        &self,
        _: &mut Session,
        _: &pingora::cache::CacheMeta,
        _: &mut pingora::cache::storage::HitHandler,
        is_fresh: bool,
        ctx: &mut Context,
    ) -> Result<Option<pingora::cache::ForcedFreshness>> {
        if is_fresh {
            ctx.cache_status = "HIT";
        }
        Ok(None)
    }
    fn response_cache_filter(
        &self,
        session: &Session,
        response: &ResponseHeader,
        ctx: &mut Context,
    ) -> Result<pingora::cache::RespCacheable> {
        let Some(policy) = ctx.route.as_ref().and_then(|r| r.cache.as_ref()) else {
            return Ok(pingora::cache::RespCacheable::Uncacheable(
                pingora::cache::NoCacheReason::NeverEnabled,
            ));
        };
        let meta =
            crate::cache::response_meta(session.req_header(), response, policy, ctx.received);
        if matches!(&meta, pingora::cache::RespCacheable::Uncacheable(_)) {
            ctx.cache_status = "BYPASS";
        }
        Ok(meta)
    }
    async fn proxy_upstream_filter(
        &self,
        session: &mut Session,
        ctx: &mut Context,
    ) -> Result<bool> {
        if crate::cache::only_if_cached(&session.req_header().headers) {
            local_response(
                session,
                ctx,
                504,
                "No usable cached response is available.\n",
                &[],
            )
            .await?;
            return Ok(false);
        }
        ctx.lease = self.select_lease(ctx);
        ctx.upstream = ctx.lease.as_ref().map(|lease| lease.origin.clone());
        if ctx.upstream.is_none() {
            local_response(
                session,
                ctx,
                503,
                "No healthy upstream is available.\n",
                &[],
            )
            .await?;
            return Ok(false);
        }
        Ok(true)
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Context,
    ) -> Result<Box<HttpPeer>> {
        let upstream = ctx
            .upstream
            .clone()
            .ok_or_else(|| Error::new_up(ErrorType::ConnectError))?;
        ctx.attempted.push(upstream.clone());
        let policy = ctx
            .route
            .as_ref()
            .and_then(|r| r.reliability.clone())
            .unwrap_or_default();
        let started = Instant::now();
        let result = async {
            let url =
                url::Url::parse(&upstream).map_err(|_| Error::new_up(ErrorType::ConnectError))?;
            let hostname = url
                .host_str()
                .unwrap()
                .trim_start_matches('[')
                .trim_end_matches(']');
            let addresses = tokio::time::timeout(
                Duration::from_secs(policy.connect_timeout_seconds),
                tokio::net::lookup_host((hostname, url.port_or_known_default().unwrap())),
            )
            .await
            .map_err(|_| Error::new_up(ErrorType::ConnectTimedout))?
            .map_err(|_| Error::new_up(ErrorType::ConnectError))?;
            let address = addresses
                .into_iter()
                .next()
                .ok_or_else(|| Error::new_up(ErrorType::ConnectError))?;
            let remaining = Duration::from_secs(policy.connect_timeout_seconds)
                .saturating_sub(started.elapsed());
            if remaining.is_zero() {
                return Err(Error::new_up(ErrorType::ConnectTimedout));
            }
            let mut peer = HttpPeer::new(address, url.scheme() == "https", hostname.to_owned());
            let h2 = ctx.route.as_ref().is_some_and(|route| {
                route
                    .upstream_protocol
                    .requires_h2(crate::grpc::is_grpc(session.req_header()))
            });
            peer.options
                .set_http_version(if h2 { 2 } else { 1 }, if h2 { 2 } else { 1 });
            // Pingora's peer hash excludes ALPN. Keep H1 and H2 connection pools separate.
            peer.group_key = if h2 { 2 } else { 1 };
            peer.options.connection_timeout = Some(remaining);
            peer.options.total_connection_timeout = Some(remaining);
            peer.options.read_timeout = Some(Duration::from_secs(policy.read_timeout_seconds));
            peer.options.write_timeout = Some(Duration::from_secs(policy.write_timeout_seconds));
            let verify = ctx
                .route
                .as_ref()
                .is_none_or(|route| route.verify_upstream_tls);
            peer.options.verify_cert = verify;
            peer.options.verify_hostname = verify;
            Ok(Box::new(peer))
        }
        .await;
        result.map_err(|error| self.retry_error(session, ctx, error))
    }

    fn fail_to_connect(
        &self,
        session: &mut Session,
        _peer: &HttpPeer,
        ctx: &mut Context,
        error: Box<Error>,
    ) -> Box<Error> {
        self.retry_error(session, ctx, error)
    }
    fn error_while_proxy(
        &self,
        _peer: &HttpPeer,
        session: &mut Session,
        error: Box<Error>,
        ctx: &mut Context,
        _client_reused: bool,
    ) -> Box<Error> {
        self.retry_error(session, ctx, error)
    }
    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        error: &Error,
        ctx: &mut Context,
    ) -> pingora::proxy::FailToProxy {
        if session.response_written().is_some() {
            return pingora::proxy::FailToProxy {
                error_code: 0,
                can_reuse_downstream: false,
            };
        }
        let code = match error.etype() {
            ErrorType::HTTPStatus(code) => *code,
            ErrorType::ConnectTimedout
            | ErrorType::TLSHandshakeTimedout
            | ErrorType::ReadTimedout
            | ErrorType::WriteTimedout
                if *error.esource() == pingora::ErrorSource::Upstream =>
            {
                504
            }
            _ => match error.esource() {
                pingora::ErrorSource::Upstream => 502,
                pingora::ErrorSource::Downstream => match error.etype() {
                    ErrorType::ReadError | ErrorType::WriteError | ErrorType::ConnectionClosed => 0,
                    _ => 400,
                },
                _ => 500,
            },
        };
        if code > 0 {
            let message = if code == 504 {
                "Upstream timed out.\n"
            } else {
                "Unable to complete the request.\n"
            };
            if let Err(error) = local_response(session, ctx, code, message, &[]).await {
                log::debug!("Could not send proxy error: {error}");
            }
        }
        pingora::proxy::FailToProxy {
            error_code: code,
            can_reuse_downstream: false,
        }
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        request: &mut RequestHeader,
        ctx: &mut Context,
    ) -> Result<()> {
        // HTTP/2 clients may split cookies across several fields; HTTP/1.1
        // upstreams (Apache, nginx, PHP, Django) need a single Cookie line.
        if request.headers.get_all("cookie").iter().nth(1).is_some() {
            if let Some(cookie) = crate::serialize::merged_cookie(request) {
                request.insert_header("Cookie", cookie)?;
            }
        }
        if let Some(route) = &ctx.route {
            if let Some(policy) = &route.routing {
                policy.apply(request, &session.req_header().uri, &route.path_prefix)?;
            }
            if !route.preserve_host {
                let url = url::Url::parse(ctx.upstream.as_ref().unwrap()).unwrap();
                let authority = &url[url::Position::BeforeHost..url::Position::AfterPort];
                request.insert_header("Host", authority)?;
            } else if let Some(authority) = crate::cache::request_authority(session.req_header()) {
                request.insert_header("Host", authority)?;
            }
        }
        if let Some(policy) = ctx.route.as_ref().and_then(|r| r.forward_auth.as_ref()) {
            crate::forward_auth::apply(policy, &ctx.auth_headers, request)?;
        }
        // Sign-in and captcha cookies are scoped to the whole host, so every
        // route strips them, not only the routes that use them.
        strip_gateway_cookies(request)?;
        if ctx.route.as_ref().is_some_and(|r| r.oidc.is_some()) {
            apply_sign_in(ctx.oidc_identity.as_ref(), request)?;
        }
        // Replace forwarding headers from untrusted clients with connection facts.
        for header in [
            "forwarded",
            "x-forwarded-for",
            "x-forwarded-host",
            "x-forwarded-proto",
            "cf-connecting-ip",
            "cf-connecting-ipv6",
            "true-client-ip",
            "x-real-ip",
        ] {
            request.remove_header(header);
        }
        let scheme = if ctx.identity.https { "https" } else { "http" };
        request.insert_header("X-Forwarded-Proto", scheme)?;
        if let Some(host) = crate::cache::request_authority(session.req_header()) {
            request.insert_header("X-Forwarded-Host", host)?;
        }
        if let Some(ip) = ctx.identity.client {
            request.insert_header("X-Forwarded-For", ip.to_string())?;
            request.insert_header("X-Real-IP", ip.to_string())?;
        }
        Ok(())
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        response: &mut ResponseHeader,
        ctx: &mut Context,
    ) -> Result<()> {
        ctx.response_started = true;
        ctx.session_lock = None;
        if response.status.as_u16() >= 200 || response.status.as_u16() == 101 {
            if ctx.header_latency_ms.get().is_none() {
                let _ = ctx
                    .header_latency_ms
                    .set(ctx.started.elapsed().as_secs_f64() * 1000.);
            }
            ctx.long_lived = response.status.as_u16() == 101
                || session
                    .req_header()
                    .uri
                    .path()
                    .eq_ignore_ascii_case("/Microsoft-Server-ActiveSync")
                || crate::grpc::is_grpc(session.req_header())
                || response
                    .headers
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|v| {
                        v.split(';')
                            .next()
                            .unwrap_or("")
                            .trim()
                            .eq_ignore_ascii_case("text/event-stream")
                    });
        }
        if !["GET", "HEAD", "OPTIONS", "TRACE"].contains(&session.req_header().method.as_str())
            && (200..400).contains(&response.status.as_u16())
        {
            if let Some(route) = ctx.route.as_ref().filter(|route| route.cache.is_some()) {
                let _ = self.0.http_cache.purge_route(Some(&route.id), None);
            }
        }
        if let Some(policy) = ctx.route.as_ref().and_then(|route| route.response.as_ref()) {
            policy.apply(response, ctx.identity.https)?;
        }
        if let Some(policy) = ctx
            .route
            .as_ref()
            .filter(|route| {
                route.forward_auth.is_none()
                    && route.oidc.is_none()
                    && !crate::grpc::is_grpc(session.req_header())
            })
            .and_then(|route| route.compression.as_ref())
        {
            let request = session.req_header().clone();
            if let Some(module) = session
                .downstream_modules_ctx
                .get_mut::<crate::compression::Downstream>()
            {
                module.prepare(&request, response, policy)?;
            }
        }
        response.insert_header("X-EmberGate-Cache", ctx.cache_status)?;
        response.insert_header("X-Current-Cache", ctx.cache_status)?;
        Ok(())
    }

    fn request_summary(&self, session: &Session, ctx: &Context) -> String {
        format!(
            "{} {} route={} attempts={}",
            session.req_header().method,
            session
                .req_header()
                .uri
                .path()
                .chars()
                .take(1024)
                .collect::<String>(),
            ctx.route
                .as_ref()
                .map(|r| r.id.as_str())
                .unwrap_or("unmatched"),
            ctx.attempted.len()
        )
    }
    async fn logging(&self, session: &mut Session, error: Option<&Error>, ctx: &mut Context) {
        ctx.lease.take();
        let status = session
            .response_written()
            .map(|r| r.status.as_u16())
            .unwrap_or(if error.is_some() { 502 } else { 499 });
        let entry = AccessLog {
            timestamp: now(),
            route_id: ctx.route.as_ref().map(|r| r.id.clone()),
            client_ip: ctx.identity.client.map(|ip| ip.to_string()),
            peer_ip: ctx.identity.peer.map(|ip| ip.to_string()),
            identity_source: ctx.identity.source.to_owned(),
            access_denied: ctx.access_denied,
            crowdsec_blocked: ctx.crowdsec_blocked,
            method: session.req_header().method.to_string(),
            host: crate::cache::request_authority(session.req_header())
                .unwrap_or_default()
                .chars()
                .take(255)
                .collect(),
            // Query strings may contain secrets; never retain them.
            path: session.req_header().uri.path().chars().take(1024).collect(),
            route: ctx.route.as_ref().map(|r| r.name.clone()),
            upstream: ctx.upstream.clone(),
            attempted_upstreams: ctx.attempted.clone(),
            maintenance: ctx.maintenance,
            rate_limited: ctx.rate_limited,
            cache_status: ctx.cache_status.to_owned(),
            status,
            latency_ms: ctx.started.elapsed().as_secs_f64() * 1000.0,
            header_latency_ms: ctx.header_latency_ms.get().copied(),
            client_cancelled: error
                .is_some_and(|error| *error.esource() == pingora::ErrorSource::Downstream),
            long_lived: ctx.long_lived,
        };
        if let Some(route) = &ctx.route {
            self.0.http_cache.record(&route.id, ctx.cache_status);
        }
        self.0.metrics.lock().unwrap().record(&entry);
        let header = |name| {
            session
                .req_header()
                .headers
                .get(name)
                .and_then(|v| v.to_str().ok())
        };
        self.0.access_log.write(
            &entry,
            header(axum::http::header::USER_AGENT),
            header(axum::http::header::REFERER),
            session.body_bytes_sent(),
        );
        self.0.analytics.record(entry).await;
    }
}

/// Removes EmberGate's own sign-in and captcha cookies before a request
/// reaches any application.
fn strip_gateway_cookies(request: &mut RequestHeader) -> Result<()> {
    let ours = |part: &str| {
        part.starts_with(crate::oidc::HOST_COOKIE) || part.starts_with(crate::captcha::COOKIE)
    };
    let parts: Vec<String> = request
        .headers
        .get_all("cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect();
    if !parts.iter().any(|part| ours(part)) {
        return Ok(());
    }
    let kept: Vec<&str> = parts
        .iter()
        .map(String::as_str)
        .filter(|p| !ours(p))
        .collect();
    request.remove_header("cookie");
    if !kept.is_empty() {
        request.insert_header("Cookie", kept.join("; "))?;
    }
    Ok(())
}

/// Sends identity headers to the application and removes identity headers a
/// visitor could forge.
fn apply_sign_in(
    identity: Option<&crate::oidc::Identity>,
    request: &mut RequestHeader,
) -> Result<()> {
    for name in crate::oidc::IDENTITY_HEADERS {
        request.remove_header(name);
    }
    let Some(identity) = identity else {
        return Ok(());
    };
    let safe = |value: &str| {
        value
            .chars()
            .filter(|c| !c.is_control())
            .collect::<String>()
    };
    request.insert_header("X-Auth-Request-User", safe(&identity.subject))?;
    if let Some(email) = identity.verified_email() {
        request.insert_header("X-Auth-Request-Email", safe(email))?;
    }
    if let Some(name) = &identity.preferred_username {
        request.insert_header("X-Auth-Request-Preferred-Username", safe(name))?;
    }
    if !identity.groups.is_empty() {
        request.insert_header("X-Auth-Request-Groups", safe(&identity.groups.join(",")))?;
    }
    Ok(())
}

/// Enforces a host's single sign-on policy. Returns true when the request may
/// continue to the application; otherwise a response was already sent.
async fn host_sign_in(
    state: &crate::state::Shared,
    session: &mut Session,
    ctx: &mut Context,
    policy: &crate::oidc::HostPolicy,
) -> Result<bool> {
    let route_id = ctx.route.as_ref().map(|r| r.id.clone()).unwrap_or_default();
    // Callbacks live under the route's prefix so the same route receives them,
    // and each route keeps its own cookie when several share a hostname.
    let prefix = ctx
        .route
        .as_ref()
        .map_or("", |r| r.path_prefix.trim_end_matches('/'))
        .to_owned();
    let (callback, logout) = (
        format!("{prefix}{}", crate::oidc::CALLBACK),
        format!("{prefix}{}", crate::oidc::LOGOUT),
    );
    let host_cookie_name = crate::oidc::host_cookie_name(&route_id);
    let authority = crate::cache::request_authority(session.req_header())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let secure = ctx.identity.https;
    let base = format!("{}://{authority}", if secure { "https" } else { "http" });
    let redirect_uri = format!("{base}{callback}");
    let flag = if secure { "; Secure" } else { "" };
    let header = session.req_header();
    let path = header.uri.path().to_owned();
    let target = header
        .uri
        .path_and_query()
        .map_or("/", |p| p.as_str())
        .to_owned();
    let method = header.method.clone();
    let cookie = |name: &str| crate::oidc::cookie(&header.headers, name).map(str::to_owned);
    let (host_cookie, state_cookie) =
        (cookie(&host_cookie_name), cookie(crate::oidc::STATE_COOKIE));
    let wants_html = crate::pages::wants_html(&header.headers);
    let redirect = |location: &str, cookies: Vec<String>| -> Result<Box<ResponseHeader>> {
        let mut response = ResponseHeader::build(303, Some(6))?;
        response.insert_header("Location", location)?;
        for cookie in cookies {
            response.append_header("Set-Cookie", cookie)?;
        }
        response.insert_header("Cache-Control", "no-store")?;
        response.insert_header("Content-Length", "0")?;
        Ok(Box::new(response))
    };
    if state.oidc.settings().is_none() {
        local_response(
            session,
            ctx,
            503,
            "Single sign-on is not configured for this site.\n",
            &[],
        )
        .await?;
        return Ok(false);
    }
    if path == logout {
        let clear = format!("{host_cookie_name}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0{flag}");
        let location = state
            .oidc
            .end_session_url(&state.trust)
            .await
            .unwrap_or_else(|| "/".into());
        session
            .write_response_header(redirect(&location, vec![clear])?, true)
            .await?;
        return Ok(false);
    }
    if path == callback {
        ctx.access_denied = true;
        let query: std::collections::HashMap<String, String> =
            url::form_urlencoded::parse(header.uri.query().unwrap_or_default().as_bytes())
                .into_owned()
                .collect();
        let clear_state = format!(
            "{}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0{flag}",
            crate::oidc::STATE_COOKIE
        );
        let result = if query.contains_key("error") {
            Err("Sign-in was cancelled at the identity provider.".to_owned())
        } else {
            state
                .oidc
                .finish(
                    &state.trust,
                    query.get("state").map_or("", String::as_str),
                    query.get("code").map_or("", String::as_str),
                    state_cookie.as_deref(),
                    &redirect_uri,
                )
                .await
        };
        let (identity, pending) = match result {
            Ok((identity, pending))
                if pending.target
                    == (crate::oidc::Target::Host {
                        route_id: route_id.clone(),
                        host: authority.clone(),
                    }) =>
            {
                (identity, pending)
            }
            Ok(_) => {
                return local_response(
                    session,
                    ctx,
                    400,
                    "This sign-in belongs to another site. Start again.\n",
                    &[("Set-Cookie", clear_state)],
                )
                .await
                .map(|_| false)
            }
            Err(error) => {
                log::info!("Host sign-in for {authority} failed: {error}");
                return local_response(
                    session,
                    ctx,
                    403,
                    &format!("{error}\n"),
                    &[("Set-Cookie", clear_state)],
                )
                .await
                .map(|_| false);
            }
        };
        if !policy.admits(&identity) {
            return local_response(
                session,
                ctx,
                403,
                "Your account is not allowed to use this site. Ask the site owner for access.\n",
                &[("Set-Cookie", clear_state)],
            )
            .await
            .map(|_| false);
        }
        let sealed = format!(
            "{host_cookie_name}={}; HttpOnly; SameSite=Lax; Path=/; Max-Age={}{flag}",
            state
                .oidc
                .seal(&route_id, &authority, &identity, policy.session_hours),
            u64::from(policy.session_hours) * 3600
        );
        session
            .write_response_header(
                redirect(
                    &crate::oidc::return_path(&pending.return_to),
                    vec![sealed, clear_state],
                )?,
                true,
            )
            .await?;
        return Ok(false);
    }
    if let Some(identity) = host_cookie
        .and_then(|c| state.oidc.open(&c, &route_id, &authority))
        .filter(|i| policy.admits(i))
    {
        ctx.oidc_identity = Some(identity);
        return Ok(true);
    }
    ctx.access_denied = true;
    if !(method == "GET" || method == "HEAD") || !wants_html {
        local_response(session, ctx, 401, "Sign in to use this site.\n", &[]).await?;
        return Ok(false);
    }
    match state
        .oidc
        .begin(
            &state.trust,
            crate::oidc::Target::Host {
                route_id,
                host: authority,
            },
            redirect_uri,
            crate::oidc::return_path(&target),
        )
        .await
    {
        Ok((location, flow)) => {
            let cookie = format!(
                "{}={flow}; HttpOnly; SameSite=Lax; Path=/; Max-Age=600{flag}",
                crate::oidc::STATE_COOKIE
            );
            session
                .write_response_header(redirect(&location, vec![cookie])?, true)
                .await?;
        }
        Err(error) => {
            log::warn!("Host sign-in could not start: {error}");
            local_response(
                session,
                ctx,
                503,
                "Sign-in is temporarily unavailable.\n",
                &[],
            )
            .await?;
        }
    }
    Ok(false)
}

/// Handles a visitor under a CrowdSec captcha decision. Returns true when the
/// request may continue: the visitor holds a valid pass cookie.
async fn captcha(
    session: &mut Session,
    ctx: &mut Context,
    remediation: &crate::captcha::Remediation,
    ip: std::net::IpAddr,
) -> Result<bool> {
    let ip = ip.to_string();
    let header = session.req_header();
    let cookie = header
        .headers
        .get_all("cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|part| {
            part.trim()
                .strip_prefix(crate::captcha::COOKIE)
                .and_then(|v| v.strip_prefix('='))
        })
        .map(str::to_owned);
    if remediation.passes(cookie.as_deref(), &ip, now()) {
        return Ok(true);
    }
    ctx.access_denied = true;
    ctx.crowdsec_blocked = true;
    let target = header
        .uri
        .path_and_query()
        .map_or("/", |p| p.as_str())
        .to_owned();
    let on_path = header.uri.path() == crate::captcha::PATH;
    let posted = on_path && header.method == "POST";
    let mut failed = false;
    if posted {
        let mut body = Vec::new();
        while let Some(chunk) = session.read_request_body().await? {
            body.extend_from_slice(&chunk);
            if body.len() > 16 * 1024 {
                break;
            }
        }
        let form: std::collections::HashMap<String, String> =
            url::form_urlencoded::parse(&body).into_owned().collect();
        let token = form.get("cf-turnstile-response").map_or("", String::as_str);
        if body.len() <= 16 * 1024 && remediation.verify(token, &ip).await {
            let destination =
                crate::captcha::destination(form.get("rd").map_or("/", String::as_str));
            let mut response = ResponseHeader::build(303, Some(4))?;
            response.insert_header("Location", destination)?;
            response.insert_header(
                "Set-Cookie",
                format!(
                    "{}={}; HttpOnly; SameSite=Lax; Path=/; Max-Age=3600{}",
                    crate::captcha::COOKIE,
                    remediation.pass(&ip, now()),
                    if ctx.identity.https { "; Secure" } else { "" }
                ),
            )?;
            response.insert_header("Cache-Control", "no-store")?;
            response.insert_header("Content-Length", "0")?;
            session
                .write_response_header(Box::new(response), true)
                .await?;
            return Ok(false);
        }
        failed = true;
    }
    let target = if on_path { "/".to_owned() } else { target };
    let page = crate::captcha::page(&remediation.settings.site_key, &target, failed);
    let mut response = ResponseHeader::build(403, Some(8))?;
    response.insert_header("Content-Type", "text/html; charset=utf-8")?;
    response.insert_header("Content-Length", page.len().to_string())?;
    response.insert_header("Content-Security-Policy", "default-src 'none'; script-src https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; connect-src https://challenges.cloudflare.com; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")?;
    response.insert_header("X-Content-Type-Options", "nosniff")?;
    response.insert_header("Referrer-Policy", "no-referrer")?;
    response.insert_header("Cache-Control", "no-store")?;
    let head = session.req_header().method == "HEAD";
    session
        .write_response_header(Box::new(response), head)
        .await?;
    if !head {
        session.write_response_body(Some(page.into()), true).await?;
    }
    Ok(false)
}

async fn local_response(
    session: &mut Session,
    ctx: &Context,
    status: u16,
    body: &str,
    extra: &[(&'static str, String)],
) -> Result<()> {
    if ctx.header_latency_ms.get().is_none() {
        let _ = ctx
            .header_latency_ms
            .set(ctx.started.elapsed().as_secs_f64() * 1000.);
    }
    if status >= 400 && crate::grpc::is_grpc(session.req_header()) {
        let mut response = ResponseHeader::build(200, Some(5))?;
        response.insert_header("Content-Type", "application/grpc")?;
        response.insert_header("grpc-status", crate::grpc::status_for_http(status))?;
        response.insert_header("grpc-message", crate::grpc::message(body.trim()))?;
        response.insert_header("Cache-Control", "no-store")?;
        return session
            .write_response_header(Box::new(response), true)
            .await;
    }
    let pages = ctx.route.as_ref().and_then(|r| r.pages.as_ref());
    let maintenance = pages.filter(|p| ctx.maintenance && p.status == status);
    let html = crate::pages::wants_html(&session.req_header().headers)
        && (maintenance.is_some() || (status >= 400 && pages.is_none_or(|p| p.branded_errors)));
    let rendered = if html {
        let title =
            maintenance.map_or_else(|| crate::pages::error_title(status), |p| p.title.as_str());
        crate::pages::html(status, title, body.trim(), maintenance.is_some())
    } else {
        body.to_owned()
    };
    let mut response = ResponseHeader::build(status, Some(12))?;
    if let Some(policy) = ctx.route.as_ref().and_then(|route| route.response.as_ref()) {
        policy.apply(&mut response, ctx.identity.https)?;
    }

    response.insert_header(
        "Content-Type",
        if html {
            "text/html; charset=utf-8"
        } else {
            "text/plain; charset=utf-8"
        },
    )?;
    response.insert_header("Content-Length", rendered.len().to_string())?;
    if html {
        response.insert_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")?;
        response.insert_header("X-Content-Type-Options", "nosniff")?;
        response.insert_header("Referrer-Policy", "no-referrer")?;
    }
    response.insert_header("Vary", "Accept")?;
    response.insert_header("Cache-Control", "no-store")?;
    response.insert_header("X-EmberGate-Cache", ctx.cache_status)?;
    response.insert_header("X-Current-Cache", ctx.cache_status)?;
    for (name, value) in extra {
        response.insert_header(*name, value.as_str())?;
    }
    let head = session.req_header().method == "HEAD";
    session
        .write_response_header(Box::new(response), head)
        .await?;
    if !head {
        session
            .write_response_body(Some(rendered.into()), true)
            .await?;
    }
    Ok(())
}

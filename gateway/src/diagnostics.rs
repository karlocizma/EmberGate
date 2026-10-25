//! Explicit, bounded diagnostics of saved routes. Probes never change health or traffic counters.
use crate::{
    config::Route,
    state::{now, Shared},
};
use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode, Uri},
    Json,
};
use openssl::{
    asn1::Asn1Time,
    hash::MessageDigest,
    ssl::{SslConnector, SslMethod},
    x509::X509VerifyResult,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    net::SocketAddr,
    pin::Pin,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::Semaphore,
    task::JoinSet,
    time::timeout,
};

static REPORTS: Semaphore = Semaphore::const_new(2);
static CONNECTIONS: Semaphore = Semaphore::const_new(4);
fn tls_connector(verify: bool, trust: &crate::trust::Bundle) -> Result<SslConnector, String> {
    let mut builder = SslConnector::builder(SslMethod::tls_client())
        .map_err(|_| "TLS diagnostics unavailable.".to_owned())?;
    // A predictable HTTP/1.1 probe; the traffic proxy has its own protocol negotiation.
    builder
        .set_alpn_protos(b"\x08http/1.1")
        .map_err(|_| "TLS diagnostics unavailable.".to_owned())?;
    if verify {
        trust.add_to_openssl(&mut builder);
    } else {
        builder.set_verify(openssl::ssl::SslVerifyMode::NONE);
    }
    Ok(builder.build())
}
const REPORT_SECONDS: u64 = 30;
const DNS_SECONDS: u64 = 3;
const CONNECT_SECONDS: u64 = 5;
const HTTP_SECONDS: u64 = 5;
const HEADER_LIMIT: usize = 16384;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    host: String,
    path: String,
    #[serde(default)]
    probe: bool,
}
fn validate(input: &Input) -> Result<(String, Uri), String> {
    if input.host.is_empty()
        || input.host.len() > 512
        || !input.host.is_ascii()
        || input.host.contains(['@', '/', '\\', '?', '#'])
        || input
            .host
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        || input.host == "*"
    {
        return Err(
            "Enter a visitor hostname, optionally with a port, without a scheme or credentials."
                .into(),
        );
    }
    let host = crate::config::normalized_host(&input.host)
        .filter(|h| !h.is_empty())
        .ok_or("Invalid visitor hostname.")?;
    if input.path.len() > 8192
        || !input.path.starts_with('/')
        || !input.path.is_ascii()
        || input.path.contains(['#', '\\'])
        || input
            .path
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return Err("Use a URL path starting with /, up to 8192 ASCII bytes; percent-encode spaces and Unicode.".into());
    }
    let uri: Uri = input.path.parse().map_err(|_| "Invalid URL path.")?;
    if uri.scheme().is_some() || uri.authority().is_some() {
        return Err("Use a path, not a full URL.".into());
    }
    Ok((host, uri))
}
#[derive(Clone, Serialize)]
struct Stage {
    status: &'static str,
    detail: String,
    elapsed_ms: Option<f64>,
}
impl Stage {
    fn skipped(detail: &str) -> Self {
        Self {
            status: "skipped",
            detail: detail.into(),
            elapsed_ms: None,
        }
    }
    fn finish(success: bool, detail: impl Into<String>, start: Instant) -> Self {
        Self {
            status: if success { "passed" } else { "failed" },
            detail: detail.into(),
            elapsed_ms: Some(ms(start)),
        }
    }
}
fn ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}
#[derive(Serialize)]
struct Backend {
    origin: String,
    host_header: String,
    draining: bool,
    monitored_status: String,
    addresses: Vec<String>,
    connected_address: Option<String>,
    dns: Stage,
    tcp: Stage,
    tls: Stage,
    http: Stage,
    http_status: Option<u16>,
    certificate: Option<Value>,
    total_ms: f64,
}
fn request(
    route: &Route,
    origin: &str,
    host: &str,
    uri: &Uri,
) -> Result<(Vec<u8>, String), String> {
    let url = url::Url::parse(origin).map_err(|_| "Invalid saved origin.")?;
    let host_header = if route.preserve_host {
        host.to_owned()
    } else {
        url[url::Position::BeforeHost..url::Position::AfterPort].to_owned()
    };
    // Only configured non-sensitive header overrides are sent. Browser headers/cookies are not copied.
    let mut headers = HeaderMap::new();
    headers.insert(
        header::HOST,
        host_header.parse().map_err(|_| "Invalid Host header.")?,
    );
    headers.insert(
        header::USER_AGENT,
        "EmberGate-Diagnostics/1".parse().unwrap(),
    );
    headers.insert(header::ACCEPT, "*/*".parse().unwrap());
    if let Some(policy) = &route.routing {
        for name in &policy.remove_headers {
            headers.remove(name);
        }
        for rule in &policy.set_headers {
            headers.insert(
                rule.name
                    .parse::<header::HeaderName>()
                    .map_err(|_| "Invalid saved header.")?,
                rule.value.parse().map_err(|_| "Invalid saved header.")?,
            );
        }
    }
    headers.insert(header::CONNECTION, "close".parse().unwrap());
    let mut bytes = format!(
        "HEAD {} HTTP/1.1\r\n",
        uri.path_and_query().map_or("/", |p| p.as_str())
    )
    .into_bytes();
    for (name, value) in &headers {
        bytes.extend_from_slice(name.as_str().as_bytes());
        bytes.extend_from_slice(b": ");
        bytes.extend_from_slice(value.as_bytes());
        bytes.extend_from_slice(b"\r\n");
    }
    bytes.extend_from_slice(b"\r\n");
    Ok((bytes, host_header))
}
// Read headers only, with a cumulative cap and an outer deadline even for drip-fed responses.
async fn head<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    request: &[u8],
) -> Result<u16, &'static str> {
    stream
        .write_all(request)
        .await
        .map_err(|_| "Could not send the HEAD request.")?;
    let mut bytes = Vec::new();
    let mut consumed = 0;
    let mut informational = 0;
    loop {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut parsed = httparse::Response::new(&mut headers);
        match parsed.parse(&bytes) {
            Ok(httparse::Status::Complete(size)) => {
                let status = parsed.code.ok_or("Missing HTTP status.")?;
                if !(100..=599).contains(&status) || status == 101 {
                    return Err("Unsupported HTTP response.");
                }
                if status >= 200 {
                    return Ok(status);
                }
                informational += 1;
                if informational > 4 {
                    return Err("Too many informational responses.");
                }
                bytes.drain(..size);
                consumed += size;
            }
            Ok(httparse::Status::Partial) => {
                let remaining = HEADER_LIMIT.saturating_sub(consumed + bytes.len());
                if remaining == 0 {
                    return Err("Response headers exceeded 16 KiB.");
                }
                let mut chunk = [0u8; 1024];
                let count = stream
                    .read(&mut chunk[..remaining.min(1024)])
                    .await
                    .map_err(|_| "Could not read HTTP response headers.")?;
                if count == 0 {
                    return Err("Backend closed before complete HTTP headers.");
                }
                bytes.extend_from_slice(&chunk[..count]);
            }
            Err(_) => return Err("Invalid HTTP response headers."),
        }
    }
}
async fn probe(
    route: Route,
    origin: String,
    host: String,
    uri: Uri,
    monitored_status: String,
    trust: std::sync::Arc<crate::trust::Bundle>,
) -> Backend {
    let _permit = CONNECTIONS
        .acquire()
        .await
        .expect("diagnostic semaphore stays open");
    let start = Instant::now();
    let prepared = request(&route, &origin, &host, &uri);
    let mut result = Backend {
        origin: origin.clone(),
        host_header: prepared.as_ref().map(|p| p.1.clone()).unwrap_or_default(),
        draining: route
            .balancing
            .as_ref()
            .is_some_and(|b| b.draining.contains(&origin)),
        monitored_status,
        addresses: vec![],
        connected_address: None,
        dns: Stage::skipped("Not checked"),
        tcp: Stage::skipped("DNS did not succeed"),
        tls: Stage::skipped("TCP did not succeed"),
        http: Stage::skipped("Connection did not succeed"),
        http_status: None,
        certificate: None,
        total_ms: 0.0,
    };
    let Ok((bytes, _)) = prepared else {
        result.http = Stage::finish(false, "Invalid saved request configuration", start);
        return result;
    };
    let url = url::Url::parse(&origin).expect("validated saved origin");
    let hostname = url
        .host_str()
        .unwrap()
        .trim_start_matches('[')
        .trim_end_matches(']');
    let port = url.port_or_known_default().unwrap();
    let dns_start = Instant::now();
    let addresses = match timeout(
        Duration::from_secs(DNS_SECONDS),
        tokio::net::lookup_host((hostname, port)),
    )
    .await
    {
        Ok(Ok(addresses)) => addresses.take(16).collect::<Vec<SocketAddr>>(),
        Ok(Err(_)) => {
            result.dns = Stage::finish(false, "DNS resolution failed", dns_start);
            result.total_ms = ms(start);
            return result;
        }
        Err(_) => {
            result.dns = Stage::finish(false, "DNS resolution timed out", dns_start);
            result.total_ms = ms(start);
            return result;
        }
    };
    result.addresses = addresses.iter().map(ToString::to_string).collect();
    let Some(address) = addresses.first() else {
        result.dns = Stage::finish(false, "DNS returned no addresses", dns_start);
        result.total_ms = ms(start);
        return result;
    };
    result.dns = Stage::finish(
        true,
        format!("{} address(es) resolved", addresses.len()),
        dns_start,
    );
    // Match the proxy's first-resolved-address selection; no diagnostic failover hides a bad backend.
    let tcp_start = Instant::now();
    let mut stream = match timeout(
        Duration::from_secs(CONNECT_SECONDS),
        TcpStream::connect(address),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            result.tcp = Stage::finish(
                false,
                if e.kind() == std::io::ErrorKind::ConnectionRefused {
                    "Connection refused"
                } else {
                    "TCP connection failed"
                },
                tcp_start,
            );
            result.total_ms = ms(start);
            return result;
        }
        Err(_) => {
            result.tcp = Stage::finish(false, "TCP connection timed out", tcp_start);
            result.total_ms = ms(start);
            return result;
        }
    };
    result.connected_address = Some(address.to_string());
    result.tcp = Stage::finish(true, "Connected", tcp_start);
    if route.upstream_protocol == crate::config::UpstreamProtocol::Http2 {
        result.http = Stage::skipped(
            "HTTP/2-only origin: HEAD diagnostics cannot verify native gRPC; use a gRPC client",
        );
        result.tls = Stage::skipped("Use a gRPC client to verify HTTP/2 and TLS");
        result.total_ms = ms(start);
        return result;
    }
    let http_start;
    let response;
    if url.scheme() == "https" {
        let tls_start = Instant::now();
        let connector = tls_connector(route.verify_upstream_tls, &trust);
        let ssl = connector
            .as_ref()
            .map_err(|_| ())
            .and_then(|connector| connector.configure().map_err(|_| ()))
            .and_then(|config| config.into_ssl(hostname).map_err(|_| ()));
        let tls = ssl.and_then(|ssl| tokio_openssl::SslStream::new(ssl, stream).map_err(|_| ()));
        let Ok(mut tls) = tls else {
            result.tls = Stage::finish(false, "TLS diagnostics unavailable", tls_start);
            result.total_ms = ms(start);
            return result;
        };
        match timeout(
            Duration::from_secs(CONNECT_SECONDS),
            Pin::new(&mut tls).connect(),
        )
        .await
        {
            Ok(Ok(())) => {
                result.tls = Stage::finish(
                    true,
                    if route.verify_upstream_tls {
                        format!("{} · verified chain and hostname", tls.ssl().version_str())
                    } else {
                        format!(
                            "{} · certificate verification disabled",
                            tls.ssl().version_str()
                        )
                    },
                    tls_start,
                );
                result.certificate=tls.ssl().peer_certificate().map(|cert|json!({"expires_at":cert.not_after().to_string(),"days_remaining":Asn1Time::days_from_now(0).ok().and_then(|now|now.diff(cert.not_after()).ok()).map(|d|d.days),"fingerprint":cert.digest(MessageDigest::sha256()).ok().map(|d|d.iter().map(|b|format!("{b:02X}")).collect::<Vec<_>>().join(":")),"protocol":tls.ssl().version_str()}));
            }
            Ok(Err(_)) => {
                let verification = tls.ssl().verify_result();
                result.tls = Stage::finish(
                    false,
                    if verification != X509VerifyResult::OK {
                        format!("Certificate verification failed: {verification}")
                    } else {
                        "TLS handshake failed".into()
                    },
                    tls_start,
                );
                result.total_ms = ms(start);
                return result;
            }
            Err(_) => {
                result.tls = Stage::finish(false, "TLS handshake timed out", tls_start);
                result.total_ms = ms(start);
                return result;
            }
        }
        http_start = Instant::now();
        response = timeout(Duration::from_secs(HTTP_SECONDS), head(&mut tls, &bytes)).await;
    } else {
        result.tls = Stage::skipped("HTTP origin · TLS is not used");
        http_start = Instant::now();
        response = timeout(Duration::from_secs(HTTP_SECONDS), head(&mut stream, &bytes)).await;
    }
    match response {
        Ok(Ok(status)) => {
            result.http_status = Some(status);
            result.http = Stage::finish(
                true,
                format!("HTTP {status} · HEAD response headers received"),
                http_start,
            );
        }
        Ok(Err(message)) => result.http = Stage::finish(false, message, http_start),
        Err(_) => result.http = Stage::finish(false, "HTTP response timed out", http_start),
    }
    result.total_ms = ms(start);
    result
}
pub async fn run(
    State(state): State<Shared>,
    Json(input): Json<Input>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let fail = |status, message: String| (status, Json(json!({"error":message})));
    let (host, uri) = validate(&input).map_err(|e| fail(StatusCode::UNPROCESSABLE_ENTITY, e))?;
    let config = state.config.load_full();
    let route = config.find_route(&host, uri.path());
    let paused = config
        .routes
        .iter()
        .filter(|r| {
            !r.enabled
                && (r.host == host || r.host == "*")
                && uri.path().starts_with(&r.path_prefix)
        })
        .take(10)
        .map(|r| json!({"id":r.id,"name":r.name,"host":r.host,"path_prefix":r.path_prefix}))
        .collect::<Vec<_>>();
    let public_certificate = state.certificates.load().select(&host).map(|c| c.summary());
    let mut notes = vec![];
    let target = route
        .as_ref()
        .map(|r| {
            r.routing
                .clone()
                .unwrap_or_default()
                .target(&uri, &r.path_prefix)
        })
        .transpose()
        .map_err(|_| {
            fail(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Could not build the upstream path.".into(),
            )
        })?;
    let mut backends = vec![];
    let mut probe_incomplete = false;
    if let Some(route) = &route {
        if route.pages.as_ref().is_some_and(|p| p.maintenance) {
            notes.push("Maintenance is enabled. Visitors may receive the maintenance page before any backend is contacted.");
        }
        if route.response.as_ref().is_some_and(|p| p.redirect_https) {
            notes.push("HTTPS redirection is enabled for HTTP visitors.");
        }
        if route.access.is_some() {
            notes.push(
                "IP access rules may block visitors. These probes do not simulate a visitor IP.",
            );
        }
        if route.rate_limit.is_some() {
            notes.push("Visitor rate limits are not applied to these direct backend probes.");
        }
        if route.cache.is_some() {
            notes.push("Probes bypass response caching; a cached visitor response may still work when a backend is unavailable.");
        }
        if input.probe {
            let _report = REPORTS.try_acquire().map_err(|_| {
                fail(
                    StatusCode::TOO_MANY_REQUESTS,
                    "Two diagnostic reports are already running. Try again shortly.".into(),
                )
            })?;
            let statuses = state
                .upstreams
                .snapshot(&config)
                .remove(&route.id)
                .unwrap_or_default();
            let mut tasks = JoinSet::new();
            for (index, origin) in route.origins().enumerate() {
                let route = route.clone();
                let origin = origin.clone();
                let host = input.host.clone();
                let uri = target.clone().unwrap();
                let monitored = statuses
                    .iter()
                    .find(|s| s.upstream == origin)
                    .map_or("unchecked", |s| s.status)
                    .to_owned();
                let trust = state.trust.current();
                tasks.spawn(async move {
                    (
                        index,
                        probe(route, origin, host, uri, monitored, trust).await,
                    )
                });
            }
            let deadline = Instant::now() + Duration::from_secs(REPORT_SECONDS);
            loop {
                match timeout(
                    deadline.saturating_duration_since(Instant::now()),
                    tasks.join_next(),
                )
                .await
                {
                    Ok(Some(result)) => backends.push(result.map_err(|_| {
                        fail(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "A diagnostic task could not complete.".into(),
                        )
                    })?),
                    Ok(None) => break,
                    Err(_) => {
                        probe_incomplete = true;
                        tasks.abort_all();
                        notes.push("The 30-second report deadline was reached. Some backends were not fully checked; run another report to retry.");
                        break;
                    }
                }
            }
            backends.sort_by_key(|b| b.0);
        }
    }
    let stale = state.config.load().version != config.version;
    Ok(Json(
        json!({"checked_at":now(),"configuration_version":config.version,"configuration_changed":stale,"host":host,"path":input.path,"probe":input.probe,"probe_incomplete":probe_incomplete,"route":route.as_ref().map(|r|json!({"id":r.id,"name":r.name,"host":r.host,"path_prefix":r.path_prefix,"upstream_path":target.as_ref().unwrap().to_string(),"upstreams":r.origins().collect::<Vec<_>>(),"preserve_host":r.preserve_host,"reliability":r.reliability.clone().unwrap_or_default()})),"paused_matches":paused,"https_listener_configured":state.https_addr.is_some(),"public_certificate":public_certificate,"notes":notes,"backends":backends.into_iter().map(|b|b.1).collect::<Vec<_>>(),"limits":{"report_seconds":REPORT_SECONDS,"dns_seconds":DNS_SECONDS,"connect_seconds":CONNECT_SECONDS,"tls_seconds":CONNECT_SECONDS,"http_seconds":HTTP_SECONDS,"parallel_backends":4,"response_header_bytes":HEADER_LIMIT}}),
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_untrusted_authorities_and_targets() {
        for host in [
            "",
            "*",
            "user@example.com",
            "https://example.com",
            "host\r\nHeader: bad",
            "host/path",
        ] {
            assert!(
                validate(&Input {
                    host: host.into(),
                    path: "/".into(),
                    probe: false
                })
                .is_err(),
                "{host}"
            );
        }
        for path in [
            "https://example.com/",
            "/x\r\nHeader: bad",
            "/a b",
            "/x#frag",
            "/x\\y",
            "/é",
        ] {
            assert!(
                validate(&Input {
                    host: "example.com".into(),
                    path: path.into(),
                    probe: false
                })
                .is_err(),
                "{path}"
            );
        }
        let (host, uri) = validate(&Input {
            host: "EXAMPLE.com.:443".into(),
            path: "/api%2Ftest?x=%2f&x=2".into(),
            probe: false,
        })
        .unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(uri.to_string(), "/api%2Ftest?x=%2f&x=2");
    }
    #[tokio::test]
    async fn bounded_headers_and_informational_responses() {
        for (response,expected) in [(b"HTTP/1.1 103 Early Hints\r\nLink: </x>\r\n\r\nHTTP/1.1 405 Nope\r\nContent-Length: 900000\r\n\r\n".to_vec(),Some(405)),(b"HTTP/1.1 101 Switching Protocols\r\n\r\n".to_vec(),None),(b"bad response\r\n\r\n".to_vec(),None),(format!("HTTP/1.1 200 OK\r\nX-Large: {}\r\n\r\n","x".repeat(HEADER_LIMIT)).into_bytes(),None)] {
            let (mut client,mut server)=tokio::io::duplex(65536);
            let task=tokio::spawn(async move{let mut bytes=[0u8;32];let _=server.read(&mut bytes).await;server.write_all(&response).await.unwrap();});
            assert_eq!(head(&mut client,b"HEAD / HTTP/1.1\r\n\r\n").await.ok(),expected);task.await.unwrap();
        }
    }
}

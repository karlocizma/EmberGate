//! Read-only Docker Engine client used to list containers EmberGate could expose.
//!
//! Only `GET /containers/json` is ever sent. Requests use HTTP/1.0 so the engine
//! (or a socket proxy) answers with a plain body that ends at connection close,
//! which keeps this client free of chunked decoding.
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, net::IpAddr, path::Path, time::Duration};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const API_VERSION: &str = "v1.41";
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_SOCKET: &str = "/var/run/docker.sock";

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "address", rename_all = "lowercase")]
pub enum Endpoint {
    Unix(String),
    Tcp(String),
}

impl Endpoint {
    /// Resolves `DOCKER_HOST`, falling back to the default socket when it exists.
    /// Returns `Ok(None)` when Docker is not configured on this gateway.
    pub fn from_env() -> Result<Option<Self>, String> {
        match std::env::var("DOCKER_HOST") {
            Ok(value) if !value.trim().is_empty() => Self::parse(value.trim()).map(Some),
            _ if Path::new(DEFAULT_SOCKET).exists() => {
                Ok(Some(Self::Unix(DEFAULT_SOCKET.to_string())))
            }
            _ => Ok(None),
        }
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        if let Some(path) = value.strip_prefix("unix://") {
            if !path.starts_with('/') {
                return Err("DOCKER_HOST unix:// paths must be absolute.".into());
            }
            return Ok(Self::Unix(path.to_string()));
        }
        if let Some(authority) = value.strip_prefix("tcp://") {
            let authority = authority.trim_end_matches('/');
            let valid = authority
                .parse::<axum::http::uri::Authority>()
                .ok()
                .filter(|a| a.port_u16().is_some() && a.as_str() == authority);
            return match valid {
                Some(_) => Ok(Self::Tcp(authority.to_string())),
                None => Err("DOCKER_HOST tcp:// addresses need a host and port.".into()),
            };
        }
        Err("DOCKER_HOST must start with unix:// or tcp://. TLS endpoints are not supported; use a local socket proxy.".into())
    }
}

/// Docker and compatible engines (such as Podman) send `null` for empty lists and maps.
fn nullable<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawContainer {
    id: String,
    #[serde(default, deserialize_with = "nullable")]
    names: Vec<String>,
    #[serde(default, deserialize_with = "nullable")]
    image: String,
    #[serde(default, deserialize_with = "nullable")]
    state: String,
    #[serde(default, deserialize_with = "nullable")]
    status: String,
    #[serde(default, deserialize_with = "nullable")]
    ports: Vec<RawPort>,
    #[serde(default, deserialize_with = "nullable")]
    network_settings: Option<RawNetworkSettings>,
    #[serde(default, deserialize_with = "nullable")]
    labels: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawPort {
    private_port: u16,
    #[serde(default, deserialize_with = "nullable")]
    public_port: Option<u16>,
    #[serde(default, rename = "Type", deserialize_with = "nullable")]
    protocol: String,
    #[serde(default, rename = "IP", deserialize_with = "nullable")]
    ip: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawNetworkSettings {
    #[serde(default, deserialize_with = "nullable")]
    networks: BTreeMap<String, RawNetwork>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawNetwork {
    #[serde(default, rename = "IPAddress", deserialize_with = "nullable")]
    ip_address: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Port {
    pub private: u16,
    pub public: Option<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Container {
    pub id: String,
    pub name: String,
    pub image: String,
    pub state: String,
    pub status: String,
    /// TCP ports only; UDP cannot be proxied.
    pub ports: Vec<Port>,
    pub networks: Vec<String>,
    /// Whether EmberGate shares a network with this container and can use its name.
    pub reachable: bool,
    /// Ready-to-use application addresses, one per TCP port, when reachable.
    /// Otherwise, when EmberGate runs on the host itself, its published ports.
    pub suggested_upstreams: Vec<String>,
    /// Whether `suggested_upstreams` use published host ports instead of the name.
    pub via_host: bool,
    /// Public host name from the `embergate.host` label, when it is a valid name.
    pub suggested_host: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Inventory {
    /// Networks of the EmberGate container, or empty when it does not run in Docker.
    pub gateway_networks: Vec<String>,
    pub containers: Vec<Container>,
}

fn scheme_for(port: u16) -> &'static str {
    if matches!(port, 443 | 8443 | 9443) {
        "https"
    } else {
        "http"
    }
}

/// Docker Engine API ports. Never suggested as application addresses.
const DOCKER_API_PORTS: [u16; 2] = [2375, 2376];

/// Turns the engine's container list into what the dashboard needs. `own_id` is
/// the gateway's container ID or a prefix of it (Docker's default hostname).
/// Containers holding one of `api_addresses` serve the Docker API this gateway
/// uses, such as a socket proxy, and are left out so they cannot be exposed.
fn summarize(raw: Vec<RawContainer>, own_id: Option<&str>, api_addresses: &[IpAddr]) -> Inventory {
    let own_id = own_id.filter(|id| id.len() >= 12);
    let serves_api = |c: &RawContainer| {
        c.network_settings.as_ref().is_some_and(|n| {
            n.networks
                .values()
                .filter_map(|net| net.ip_address.parse::<IpAddr>().ok())
                .any(|ip| api_addresses.contains(&ip))
        })
    };
    let gateway_networks: Vec<String> = raw
        .iter()
        .find(|c| own_id.is_some_and(|id| c.id.starts_with(id)))
        .and_then(|c| c.network_settings.as_ref())
        .map(|n| n.networks.keys().cloned().collect())
        .unwrap_or_default();
    // Outside Docker, or with host networking, published ports are on this host.
    let on_host = gateway_networks.iter().all(|n| n == "host");
    let mut containers: Vec<Container> = raw
        .into_iter()
        .filter(|c| !own_id.is_some_and(|id| c.id.starts_with(id)) && !serves_api(c))
        .map(|c| {
            let name = c
                .names
                .first()
                .map(|n| n.trim_start_matches('/').to_string())
                .unwrap_or_else(|| c.id.chars().take(12).collect());
            let networks: Vec<String> = c
                .network_settings
                .map(|n| {
                    n.networks
                        .into_iter()
                        .filter(|(_, net)| !net.ip_address.is_empty())
                        .map(|(network, _)| network)
                        .collect()
                })
                .unwrap_or_default();
            let tcp: Vec<RawPort> = c
                .ports
                .into_iter()
                .filter(|p| p.protocol.is_empty() || p.protocol == "tcp")
                .collect();
            let mut published: Vec<(u16, u16, String)> = tcp
                .iter()
                .filter_map(|p| Some((p.public_port?, p.private_port, host_address(&p.ip)?)))
                .collect();
            published.sort();
            // IPv4 first: Docker lists dual-stack bindings once per family.
            published.dedup_by_key(|p| p.0);
            let mut ports: Vec<Port> = tcp
                .iter()
                .map(|p| Port {
                    private: p.private_port,
                    public: p.public_port,
                })
                .collect();
            ports.sort_by_key(|p| (p.private, p.public));
            // Docker lists a port once per published host address (IPv4 and IPv6).
            ports.dedup_by_key(|p| p.private);
            let reachable = networks
                .iter()
                .any(|n| n != "host" && n != "none" && gateway_networks.contains(n));
            let via_host = !reachable && on_host && !published.is_empty();
            let suggested_upstreams = if reachable {
                ports
                    .iter()
                    .filter(|p| !DOCKER_API_PORTS.contains(&p.private))
                    .map(|p| format!("{}://{}:{}", scheme_for(p.private), name, p.private))
                    .collect()
            } else if via_host {
                published
                    .iter()
                    .filter(|p| {
                        !DOCKER_API_PORTS.contains(&p.0) && !DOCKER_API_PORTS.contains(&p.1)
                    })
                    .map(|(public, private, address)| {
                        format!("{}://{}:{}", scheme_for(*private), address, public)
                    })
                    .collect()
            } else {
                Vec::new()
            };
            Container {
                id: c.id,
                name,
                image: c.image,
                state: c.state,
                status: c.status,
                ports,
                networks,
                reachable,
                via_host: via_host && !suggested_upstreams.is_empty(),
                suggested_upstreams,
                suggested_host: label_host(&c.labels),
            }
        })
        .collect();
    containers.sort_by(|a, b| a.name.cmp(&b.name));
    Inventory {
        gateway_networks,
        containers,
    }
}

/// Where a port published on `ip` is reached from the host: wildcard bindings
/// through loopback, specific ones on their own address.
fn host_address(ip: &str) -> Option<String> {
    match ip.parse::<IpAddr>() {
        Err(_) if ip.is_empty() => Some("127.0.0.1".into()),
        Err(_) => None,
        Ok(ip) if ip.is_unspecified() => Some("127.0.0.1".into()),
        Ok(IpAddr::V6(ip)) => Some(format!("[{ip}]")),
        Ok(ip) => Some(ip.to_string()),
    }
}

/// Reads the `embergate.host` label, ignoring values that are not a plain host name.
fn label_host(labels: &BTreeMap<String, String>) -> Option<String> {
    let host = labels.get("embergate.host")?.trim().to_ascii_lowercase();
    let name = host.strip_prefix("*.").unwrap_or(&host);
    let valid = name.len() <= 253
        && name.split('.').all(|part| {
            !part.is_empty()
                && part.len() <= 63
                && !part.starts_with('-')
                && !part.ends_with('-')
                && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    valid.then_some(host)
}

/// The gateway's own container ID prefix: Docker sets the hostname to it by default.
fn own_container_id() -> Option<String> {
    std::env::var("HOSTNAME")
        .ok()
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
        .map(|h| h.trim().to_ascii_lowercase())
        .filter(|h| h.len() >= 12 && h.bytes().all(|b| b.is_ascii_hexdigit()))
}

pub async fn list(endpoint: &Endpoint) -> Result<Inventory, String> {
    let body = tokio::time::timeout(TIMEOUT, fetch(endpoint))
        .await
        .map_err(|_| "Docker did not answer within 5 seconds.".to_string())??;
    let raw: Vec<RawContainer> = serde_json::from_slice(&body)
        .map_err(|e| format!("Docker returned an unexpected container list: {e}"))?;
    let api_addresses = match endpoint {
        Endpoint::Tcp(address) => tokio::time::timeout(TIMEOUT, tokio::net::lookup_host(address))
            .await
            .ok()
            .and_then(Result::ok)
            .map(|addresses| addresses.map(|a| a.ip()).collect())
            .unwrap_or_default(),
        Endpoint::Unix(_) => Vec::new(),
    };
    Ok(summarize(
        raw,
        own_container_id().as_deref(),
        &api_addresses,
    ))
}

async fn fetch(endpoint: &Endpoint) -> Result<Vec<u8>, String> {
    let unreachable = |e: std::io::Error| format!("Could not connect to Docker: {e}");
    match endpoint {
        Endpoint::Unix(path) => {
            let stream = tokio::net::UnixStream::connect(path)
                .await
                .map_err(unreachable)?;
            exchange(stream).await
        }
        Endpoint::Tcp(address) => {
            let stream = tokio::net::TcpStream::connect(address)
                .await
                .map_err(unreachable)?;
            exchange(stream).await
        }
    }
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S) -> Result<Vec<u8>, String> {
    let request = format!("GET /{API_VERSION}/containers/json HTTP/1.0\r\nHost: docker\r\nAccept: application/json\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| format!("Could not send the Docker request: {e}"))?;
    let mut response = Vec::new();
    let read = (&mut stream)
        .take(MAX_RESPONSE_BYTES as u64 + 1)
        .read_to_end(&mut response)
        .await
        .map_err(|e| format!("Could not read the Docker response: {e}"))?;
    if read > MAX_RESPONSE_BYTES {
        return Err("Docker's container list is larger than 8 MiB.".into());
    }
    parse_response(&response)
}

fn parse_response(response: &[u8]) -> Result<Vec<u8>, String> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Response::new(&mut headers);
    let head = match parsed.parse(response) {
        Ok(httparse::Status::Complete(length)) => length,
        _ => return Err("Docker returned an invalid HTTP response.".into()),
    };
    let body = &response[head..];
    let chunked = parsed.headers.iter().any(|h| {
        h.name.eq_ignore_ascii_case("transfer-encoding")
            && !h.value.eq_ignore_ascii_case(b"identity")
    });
    if chunked {
        return Err("Docker answered with a chunked body to an HTTP/1.0 request.".into());
    }
    match parsed.code {
        Some(200) => Ok(body.to_vec()),
        Some(403) => Err("The Docker endpoint refused to list containers. If you use a socket proxy, allow CONTAINERS.".into()),
        Some(code) => Err(format!("Docker answered HTTP {code} when listing containers.")),
        None => Err("Docker returned an invalid HTTP response.".into()),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExposedBy {
    pub id: String,
    pub name: String,
    pub host: String,
}

#[derive(Debug, Serialize)]
pub struct Listing {
    pub configured: bool,
    pub endpoint: Option<Endpoint>,
    pub error: Option<String>,
    pub gateway_networks: Vec<String>,
    pub containers: Vec<ListedContainer>,
}

#[derive(Debug, Serialize)]
pub struct ListedContainer {
    #[serde(flatten)]
    pub container: Container,
    /// Saved hosts whose application addresses use this container's name.
    pub exposed_by: Vec<ExposedBy>,
}

fn listing(
    endpoint: Option<Endpoint>,
    inventory: Result<Inventory, String>,
    routes: &[crate::config::Route],
) -> Listing {
    let (inventory, error) = match inventory {
        Ok(inventory) => (inventory, None),
        Err(error) => (Inventory::default(), Some(error)),
    };
    let containers = inventory
        .containers
        .into_iter()
        .map(|container| {
            let exposed_by = routes
                .iter()
                .filter(|route| {
                    std::iter::once(&route.upstream)
                        .chain(&route.additional_upstreams)
                        .filter_map(|upstream| url::Url::parse(upstream).ok())
                        .any(|url| {
                            url.host_str()
                                .is_some_and(|host| host.eq_ignore_ascii_case(&container.name))
                        })
                })
                .map(|route| ExposedBy {
                    id: route.id.clone(),
                    name: route.name.clone(),
                    host: route.host.clone(),
                })
                .collect();
            ListedContainer {
                container,
                exposed_by,
            }
        })
        .collect();
    Listing {
        configured: true,
        endpoint,
        error,
        gateway_networks: inventory.gateway_networks,
        containers,
    }
}

async fn containers(
    axum::extract::State(state): axum::extract::State<crate::state::Shared>,
) -> axum::Json<Listing> {
    let endpoint = match &state.docker {
        Ok(Some(endpoint)) => endpoint.clone(),
        Ok(None) => {
            return axum::Json(Listing {
                configured: false,
                endpoint: None,
                error: None,
                gateway_networks: Vec::new(),
                containers: Vec::new(),
            })
        }
        Err(error) => {
            return axum::Json(listing(None, Err(error.clone()), &[]));
        }
    };
    let inventory = list(&endpoint).await;
    let config = state.config.load_full();
    axum::Json(listing(Some(endpoint), inventory, &config.routes))
}

pub fn routes() -> axum::Router<crate::state::Shared> {
    axum::Router::new().route("/api/docker/containers", axum::routing::get(containers))
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIST: &str = r#"[
      {"Id":"dddddddddddd4444","Names":["/idle"],"Image":"busybox","State":"running","Status":null,"Ports":null,
       "NetworkSettings":{"Networks":null}},
      {"Id":"aaaaaaaaaaaa1111","Names":["/embergate"],"Image":"embergate","State":"running","Status":"Up 2 hours",
       "Ports":[{"PrivatePort":8080,"PublicPort":80,"Type":"tcp"}],
       "NetworkSettings":{"Networks":{"proxy":{"IPAddress":"172.20.0.2"}}}},
      {"Id":"bbbbbbbbbbbb2222","Names":["/photos"],"Image":"immich","State":"running","Status":"Up 1 hour",
       "Labels":{"embergate.host":" Photos.Example.com "},
       "Ports":[{"PrivatePort":2283,"Type":"tcp"},{"PrivatePort":443,"PublicPort":8443,"IP":"0.0.0.0","Type":"tcp"},{"PrivatePort":443,"PublicPort":8443,"IP":"::","Type":"tcp"},{"PrivatePort":5353,"Type":"udp"}],
       "NetworkSettings":{"Networks":{"proxy":{"IPAddress":"172.20.0.3"},"internal":{"IPAddress":"172.21.0.3"}}}},
      {"Id":"cccccccccccc3333","Names":["/db"],"Image":"postgres","State":"running","Status":"Up 1 hour",
       "Labels":{"embergate.host":"bad host/path"},
       "Ports":[{"PrivatePort":5432,"Type":"tcp"}],
       "NetworkSettings":{"Networks":{"internal":{"IPAddress":"172.21.0.4"}}}}
    ]"#;

    fn inventory(own: Option<&str>) -> Inventory {
        summarize(serde_json::from_str(LIST).unwrap(), own, &[])
    }

    #[test]
    fn shared_networks_make_containers_reachable_by_name() {
        let inventory = inventory(Some("aaaaaaaaaaaa"));
        assert_eq!(inventory.gateway_networks, ["proxy"]);
        let names: Vec<_> = inventory
            .containers
            .iter()
            .map(|c| c.name.as_str())
            .collect();
        assert_eq!(
            names,
            ["db", "idle", "photos"],
            "the gateway lists other containers only"
        );
        let idle = &inventory.containers[1];
        assert!(idle.ports.is_empty() && idle.networks.is_empty() && idle.status.is_empty());
        let photos = &inventory.containers[2];
        assert!(photos.reachable);
        assert_eq!(
            photos.ports,
            [
                Port {
                    private: 443,
                    public: Some(8443)
                },
                Port {
                    private: 2283,
                    public: None
                }
            ],
            "UDP is skipped and dual-stack duplicates collapse"
        );
        assert_eq!(
            photos.suggested_upstreams,
            ["https://photos:443", "http://photos:2283"]
        );
        assert!(!inventory.containers[0].reachable);
        assert!(inventory.containers[0].suggested_upstreams.is_empty());
    }

    #[test]
    fn host_label_suggests_a_valid_public_name() {
        let inventory = inventory(None);
        let host = |name: &str| {
            inventory
                .containers
                .iter()
                .find(|c| c.name == name)
                .unwrap()
                .suggested_host
                .clone()
        };
        assert_eq!(host("photos").as_deref(), Some("photos.example.com"));
        assert_eq!(host("db"), None, "invalid labels are ignored");
        assert_eq!(host("idle"), None);
        let label = |value: &str| BTreeMap::from([("embergate.host".into(), value.into())]);
        assert_eq!(
            label_host(&label("*.apps.example.com")).as_deref(),
            Some("*.apps.example.com")
        );
        for bad in ["", "*.", "-a.example.com", "a..b", "a.example.com:8080"] {
            assert_eq!(label_host(&label(bad)), None, "{bad:?}");
        }
    }

    #[test]
    fn the_docker_api_can_never_be_exposed() {
        let raw = r#"[
          {"Id":"aaaaaaaaaaaa1111","Names":["/embergate"],"NetworkSettings":{"Networks":{"proxy":{"IPAddress":"172.20.0.2"},"docker-api":{"IPAddress":"172.30.0.2"}}}},
          {"Id":"eeeeeeeeeeee5555","Names":["/socket-proxy"],"Ports":[{"PrivatePort":2375,"Type":"tcp"}],"NetworkSettings":{"Networks":{"docker-api":{"IPAddress":"172.30.0.3"}}}},
          {"Id":"ffffffffffff6666","Names":["/dind"],"Ports":[{"PrivatePort":2376,"Type":"tcp"},{"PrivatePort":8080,"Type":"tcp"}],"NetworkSettings":{"Networks":{"proxy":{"IPAddress":"172.20.0.9"}}}}
        ]"#;
        let api: IpAddr = "172.30.0.3".parse().unwrap();
        let inventory = summarize(
            serde_json::from_str(raw).unwrap(),
            Some("aaaaaaaaaaaa"),
            &[api],
        );
        let names: Vec<_> = inventory
            .containers
            .iter()
            .map(|c| c.name.as_str())
            .collect();
        assert_eq!(
            names,
            ["dind"],
            "the container serving DOCKER_HOST is hidden"
        );
        assert_eq!(
            inventory.containers[0].suggested_upstreams,
            ["http://dind:8080"]
        );
    }

    #[test]
    fn a_gateway_outside_docker_reaches_no_container_by_name() {
        let inventory = inventory(None);
        assert!(inventory.gateway_networks.is_empty());
        assert_eq!(inventory.containers.len(), 4);
        assert!(inventory.containers.iter().all(|c| !c.reachable));
        let upstreams = |name: &str| {
            let c = inventory
                .containers
                .iter()
                .find(|c| c.name == name)
                .unwrap();
            (c.via_host, c.suggested_upstreams.clone())
        };
        assert_eq!(
            upstreams("photos"),
            (true, vec!["https://127.0.0.1:8443".to_string()]),
            "published ports are offered once, unpublished ones are not"
        );
        assert_eq!(upstreams("db"), (false, Vec::new()));
        let host = |ip: &str| host_address(ip);
        assert_eq!(host("").as_deref(), Some("127.0.0.1"));
        assert_eq!(host("::").as_deref(), Some("127.0.0.1"));
        assert_eq!(host("192.168.1.5").as_deref(), Some("192.168.1.5"));
        assert_eq!(host("fd00::5").as_deref(), Some("[fd00::5]"));
        assert_eq!(host("bogus"), None);
    }

    #[test]
    fn host_networking_uses_published_ports() {
        let raw = r#"[
          {"Id":"aaaaaaaaaaaa1111","Names":["/embergate"],"NetworkSettings":{"Networks":{"host":{"IPAddress":""}}}},
          {"Id":"bbbbbbbbbbbb2222","Names":["/app"],"Ports":[{"PrivatePort":80,"PublicPort":8081,"IP":"127.0.0.1","Type":"tcp"},{"PrivatePort":2375,"PublicPort":2375,"Type":"tcp"}],
           "NetworkSettings":{"Networks":{"bridge":{"IPAddress":"172.17.0.2"}}}}
        ]"#;
        let inventory = summarize(
            serde_json::from_str(raw).unwrap(),
            Some("aaaaaaaaaaaa"),
            &[],
        );
        let app = &inventory.containers[0];
        assert!(!app.reachable && app.via_host);
        assert_eq!(app.suggested_upstreams, ["http://127.0.0.1:8081"]);
    }

    #[test]
    fn endpoints_accept_only_local_sockets_and_plain_tcp() {
        assert_eq!(
            Endpoint::parse("unix:///run/docker.sock"),
            Ok(Endpoint::Unix("/run/docker.sock".into()))
        );
        assert_eq!(
            Endpoint::parse("tcp://socket-proxy:2375"),
            Ok(Endpoint::Tcp("socket-proxy:2375".into()))
        );
        for bad in [
            "unix://run/docker.sock",
            "tcp://socket-proxy",
            "https://docker:2376",
            "tcp://a:1/x",
        ] {
            assert!(Endpoint::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn responses_must_be_successful_plain_bodies() {
        assert_eq!(
            parse_response(b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n[]").unwrap(),
            b"[]"
        );
        assert!(parse_response(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            .unwrap_err()
            .contains("CONTAINERS"));
        assert!(parse_response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n[]\r\n0\r\n\r\n"
        )
        .is_err());
        assert!(parse_response(b"garbage").is_err());
    }

    #[tokio::test]
    async fn the_client_sends_one_read_only_request() {
        let (client, mut server) = tokio::io::duplex(4096);
        let task = tokio::spawn(exchange(client));
        let mut request = vec![0; 1024];
        let read = server.read(&mut request).await.unwrap();
        let request = String::from_utf8_lossy(&request[..read]).to_string();
        assert!(request.starts_with("GET /v1.41/containers/json HTTP/1.0\r\n"));
        server
            .write_all(b"HTTP/1.0 200 OK\r\n\r\n[]")
            .await
            .unwrap();
        drop(server);
        assert_eq!(task.await.unwrap().unwrap(), b"[]");
    }

    #[test]
    fn listings_show_which_saved_hosts_use_a_container() {
        let routes: Vec<crate::config::Route> = serde_json::from_value(serde_json::json!([
            {"id":"r1","name":"Photos","host":"photos.example.com","path_prefix":"/","upstream":"http://PHOTOS:2283","enabled":true,"preserve_host":false},
            {"id":"r2","name":"Other","host":"other.example.com","path_prefix":"/","upstream":"http://10.0.0.5:80","additional_upstreams":["http://db:5432"],"enabled":true,"preserve_host":false}
        ])).unwrap();
        let listing = listing(None, Ok(inventory(Some("aaaaaaaaaaaa"))), &routes);
        let exposed: Vec<(&str, Vec<&str>)> = listing
            .containers
            .iter()
            .map(|c| {
                (
                    c.container.name.as_str(),
                    c.exposed_by.iter().map(|e| e.id.as_str()).collect(),
                )
            })
            .collect();
        assert_eq!(
            exposed,
            [("db", vec!["r2"]), ("idle", vec![]), ("photos", vec!["r1"])]
        );
        let failed = super::listing(None, Err("Could not connect to Docker".into()), &routes);
        assert!(failed.configured && failed.containers.is_empty());
        assert_eq!(failed.error.as_deref(), Some("Could not connect to Docker"));
    }

    /// Run with `DOCKER_HOST=unix:///path/to/docker.sock cargo test -- --ignored live_engine`.
    #[tokio::test]
    #[ignore]
    async fn live_engine_lists_containers() {
        let endpoint = Endpoint::from_env().unwrap().expect("set DOCKER_HOST");
        let inventory = list(&endpoint).await.unwrap();
        println!("{inventory:#?}");
    }
}

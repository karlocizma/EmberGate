//! Read-only Docker Engine client used to list containers EmberGate could expose.
//!
//! Only `GET /containers/json` is ever sent. Requests use HTTP/1.0 so the engine
//! (or a socket proxy) answers with a plain body that ends at connection close,
//! which keeps this client free of chunked decoding.
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path, time::Duration};
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
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawPort {
    private_port: u16,
    #[serde(default, deserialize_with = "nullable")]
    public_port: Option<u16>,
    #[serde(default, rename = "Type", deserialize_with = "nullable")]
    protocol: String,
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
    pub suggested_upstreams: Vec<String>,
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

/// Turns the engine's container list into what the dashboard needs. `own_id` is
/// the gateway's container ID or a prefix of it (Docker's default hostname).
fn summarize(raw: Vec<RawContainer>, own_id: Option<&str>) -> Inventory {
    let own_id = own_id.filter(|id| id.len() >= 12);
    let gateway_networks: Vec<String> = raw
        .iter()
        .find(|c| own_id.is_some_and(|id| c.id.starts_with(id)))
        .and_then(|c| c.network_settings.as_ref())
        .map(|n| n.networks.keys().cloned().collect())
        .unwrap_or_default();
    let mut containers: Vec<Container> = raw
        .into_iter()
        .filter(|c| !own_id.is_some_and(|id| c.id.starts_with(id)))
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
            let mut ports: Vec<Port> = c
                .ports
                .into_iter()
                .filter(|p| p.protocol.is_empty() || p.protocol == "tcp")
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
            let suggested_upstreams = if reachable {
                ports
                    .iter()
                    .map(|p| format!("{}://{}:{}", scheme_for(p.private), name, p.private))
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
                suggested_upstreams,
            }
        })
        .collect();
    containers.sort_by(|a, b| a.name.cmp(&b.name));
    Inventory {
        gateway_networks,
        containers,
    }
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
    Ok(summarize(raw, own_container_id().as_deref()))
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
       "Ports":[{"PrivatePort":2283,"Type":"tcp"},{"PrivatePort":443,"PublicPort":8443,"IP":"0.0.0.0","Type":"tcp"},{"PrivatePort":443,"PublicPort":8443,"IP":"::","Type":"tcp"},{"PrivatePort":5353,"Type":"udp"}],
       "NetworkSettings":{"Networks":{"proxy":{"IPAddress":"172.20.0.3"},"internal":{"IPAddress":"172.21.0.3"}}}},
      {"Id":"cccccccccccc3333","Names":["/db"],"Image":"postgres","State":"running","Status":"Up 1 hour",
       "Ports":[{"PrivatePort":5432,"Type":"tcp"}],
       "NetworkSettings":{"Networks":{"internal":{"IPAddress":"172.21.0.4"}}}}
    ]"#;

    fn inventory(own: Option<&str>) -> Inventory {
        summarize(serde_json::from_str(LIST).unwrap(), own)
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
    fn a_gateway_outside_docker_reaches_no_container_by_name() {
        let inventory = inventory(None);
        assert!(inventory.gateway_networks.is_empty());
        assert_eq!(inventory.containers.len(), 4);
        assert!(inventory.containers.iter().all(|c| !c.reachable));
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

    /// Run with `DOCKER_HOST=unix:///path/to/docker.sock cargo test -- --ignored live_engine`.
    #[tokio::test]
    #[ignore]
    async fn live_engine_lists_containers() {
        let endpoint = Endpoint::from_env().unwrap().expect("set DOCKER_HOST");
        let inventory = list(&endpoint).await.unwrap();
        println!("{inventory:#?}");
    }
}

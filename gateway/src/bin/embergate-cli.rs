//! Command-line client for the EmberGate management API, authenticated with an
//! API token. Configure it with `EMBERGATE_URL` and `EMBERGATE_TOKEN`.
use serde_json::{json, Value};
use std::{io::Write, process::ExitCode};

const USAGE: &str = "Usage: embergate-cli [--json] <command>

Commands:
  status                              Gateway version, role, uptime, and traffic
  hosts list                          Saved proxy hosts
  hosts show <host>                   One host's full configuration (JSON)
  hosts enable <host>                 Start sending traffic to a paused host
  hosts disable <host>                Pause a host without deleting it
  hosts delete <host> --yes           Delete a host
  hosts apply <file.json>             Create or replace hosts from a route or list of routes
  containers                          Running Docker containers and suggested addresses
  history                             Retained configuration revisions
  cache purge [<host>] [--url <url>]  Purge cached responses for every host, one host, or one URL
  backup export --output <file>       Download an encrypted full backup
                                      (passphrase from EMBERGATE_BACKUP_PASSPHRASE)

<host> is a host ID, name, or hostname.

Environment:
  EMBERGATE_URL    Dashboard address, for example http://127.0.0.1:9090
  EMBERGATE_TOKEN  API token from Settings → API tokens

Exit codes: 0 success, 1 request failed, 2 usage error, 3 not authorized, 4 not found.";

enum Failure {
    Usage(String),
    Request(String),
    Unauthorized(String),
    NotFound(String),
}
use Failure::*;

impl Failure {
    fn code(&self) -> u8 {
        match self {
            Request(_) => 1,
            Usage(_) => 2,
            Unauthorized(_) => 3,
            NotFound(_) => 4,
        }
    }
    fn message(&self) -> &str {
        match self {
            Usage(m) | Request(m) | Unauthorized(m) | NotFound(m) => m,
        }
    }
}

struct Client {
    http: reqwest::Client,
    base: String,
    token: String,
}

impl Client {
    fn from_env() -> Result<Self, Failure> {
        let base = std::env::var("EMBERGATE_URL").map_err(|_| {
            Usage(
                "Set EMBERGATE_URL to the dashboard address, for example http://127.0.0.1:9090."
                    .into(),
            )
        })?;
        let url = url::Url::parse(&base)
            .map_err(|_| Usage("EMBERGATE_URL is not a valid URL.".into()))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(Usage(
                "EMBERGATE_URL must start with http:// or https://.".into(),
            ));
        }
        let token = std::env::var("EMBERGATE_TOKEN").map_err(|_| {
            Usage("Set EMBERGATE_TOKEN to an API token from Settings → API tokens.".into())
        })?;
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(std::time::Duration::from_secs(120))
            .user_agent(concat!("embergate-cli/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| Request(e.to_string()))?;
        Ok(Self {
            http,
            base: base.trim_end_matches('/').to_owned(),
            token: token.trim().to_owned(),
        })
    }

    async fn send(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<reqwest::Response, Failure> {
        let mut request = self
            .http
            .request(method, format!("{}/api/{path}", self.base))
            .bearer_auth(&self.token);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request
            .send()
            .await
            .map_err(|e| Request(format!("Could not reach EmberGate at {}: {e}", self.base)))?;
        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }
        let message = response
            .json::<Value>()
            .await
            .ok()
            .and_then(|v| v["error"].as_str().map(str::to_owned))
            .unwrap_or_else(|| format!("EmberGate answered {status}."));
        Err(match status.as_u16() {
            401 | 403 => Unauthorized(message),
            404 => NotFound(message),
            _ => Request(message),
        })
    }

    async fn json(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value, Failure> {
        self.send(method, path, body)
            .await?
            .json()
            .await
            .map_err(|e| Request(format!("Unexpected response: {e}")))
    }
    async fn get(&self, path: &str) -> Result<Value, Failure> {
        self.json(reqwest::Method::GET, path, None).await
    }
}

/// Prints rows as aligned columns.
fn table(headers: &[&str], rows: Vec<Vec<String>>) -> String {
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for row in &rows {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.chars().count());
        }
    }
    let line = |cells: Vec<String>| {
        let last = cells.len() - 1;
        cells
            .into_iter()
            .enumerate()
            .map(|(i, c)| {
                if i == last {
                    c
                } else {
                    format!("{c:<w$}", w = widths[i])
                }
            })
            .collect::<Vec<_>>()
            .join("  ")
    };
    let mut out = vec![line(headers.iter().map(|h| h.to_uppercase()).collect())];
    out.extend(rows.into_iter().map(line));
    out.join("\n")
}

fn text(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Null => "—".into(),
        other => other.to_string(),
    }
}

/// Finds one route by ID, name, or hostname.
fn find(config: &Value, selector: &str) -> Result<usize, Failure> {
    let routes = config["routes"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default();
    let matches: Vec<usize> = routes
        .iter()
        .enumerate()
        .filter(|(_, r)| {
            [&r["id"], &r["name"], &r["host"]]
                .iter()
                .any(|v| v.as_str() == Some(selector))
        })
        .map(|(i, _)| i)
        .collect();
    match matches.as_slice() {
        [index] => Ok(*index),
        [] => Err(NotFound(format!("No host matches “{selector}”."))),
        _ => Err(Usage(format!(
            "“{selector}” matches several hosts. Use the host ID from `hosts list`."
        ))),
    }
}

async fn save(client: &Client, config: Value) -> Result<Value, Failure> {
    client
        .json(reqwest::Method::PUT, "config", Some(config))
        .await
}

fn duration(seconds: u64) -> String {
    match seconds {
        s if s >= 86400 => format!("{}d {}h", s / 86400, s % 86400 / 3600),
        s if s >= 3600 => format!("{}h {}m", s / 3600, s % 3600 / 60),
        s => format!("{}m {}s", s / 60, s % 60),
    }
}

async fn run(args: Vec<String>) -> Result<String, Failure> {
    let as_json = args.iter().any(|a| a == "--json");
    let args: Vec<&str> = args
        .iter()
        .map(String::as_str)
        .filter(|a| *a != "--json")
        .collect();
    if args.is_empty() || matches!(args[0], "-h" | "--help" | "help") {
        return Ok(USAGE.into());
    }
    if args[0] == "--version" {
        return Ok(concat!("embergate-cli ", env!("CARGO_PKG_VERSION")).into());
    }
    let client = Client::from_env()?;
    let pretty = |value: &Value| serde_json::to_string_pretty(value).expect("JSON output");
    match args.as_slice() {
        ["status"] => {
            let stats = client.get("stats").await?;
            if as_json {
                return Ok(pretty(&stats));
            }
            Ok(format!(
                "EmberGate {}\nRole: {}{}\nUptime: {}\nRequests: {} ({} errors, {} rate limited)\nProxy: {}\nAdmin: {}",
                text(&stats["version"]),
                text(&stats["cluster_role"]),
                if stats["cluster_ready"] == false { " (not ready)" } else { "" },
                duration(stats["uptime_seconds"].as_u64().unwrap_or(0)),
                stats["requests"], stats["errors"], stats["rate_limited"],
                text(&stats["proxy_addr"]),
                text(&stats["admin_addr"]),
            ))
        }
        ["hosts", "list"] | ["hosts"] => {
            let config = client.get("config").await?;
            let routes = config["routes"].as_array().cloned().unwrap_or_default();
            if as_json {
                return Ok(pretty(&Value::Array(routes)));
            }
            if routes.is_empty() {
                return Ok("No hosts yet.".into());
            }
            Ok(table(
                &["id", "name", "host", "upstream", "status"],
                routes
                    .iter()
                    .map(|r| {
                        vec![
                            text(&r["id"]),
                            text(&r["name"]),
                            format!(
                                "{}{}",
                                text(&r["host"]),
                                r["path_prefix"]
                                    .as_str()
                                    .filter(|p| *p != "/")
                                    .unwrap_or("")
                            ),
                            text(&r["upstream"]),
                            if r["enabled"] == true {
                                "active"
                            } else {
                                "paused"
                            }
                            .into(),
                        ]
                    })
                    .collect(),
            ))
        }
        ["hosts", "show", selector] => {
            let config = client.get("config").await?;
            Ok(pretty(&config["routes"][find(&config, selector)?]))
        }
        ["hosts", action @ ("enable" | "disable"), selector] => {
            let mut config = client.get("config").await?;
            let index = find(&config, selector)?;
            let enable = *action == "enable";
            if config["routes"][index]["enabled"] == enable {
                return Ok(format!(
                    "{} is already {}.",
                    text(&config["routes"][index]["name"]),
                    if enable { "active" } else { "paused" }
                ));
            }
            config["routes"][index]["enabled"] = json!(enable);
            let name = text(&config["routes"][index]["name"]);
            save(&client, config).await?;
            Ok(format!(
                "{name} is now {}.",
                if enable { "active" } else { "paused" }
            ))
        }
        ["hosts", "delete", selector, rest @ ..] => {
            if !rest.contains(&"--yes") {
                return Err(Usage(
                    "Deleting a host cannot be undone from the CLI. Add --yes to confirm.".into(),
                ));
            }
            let mut config = client.get("config").await?;
            let index = find(&config, selector)?;
            let removed = config["routes"]
                .as_array_mut()
                .expect("routes")
                .remove(index);
            save(&client, config).await?;
            Ok(format!(
                "Deleted {} ({}).",
                text(&removed["name"]),
                text(&removed["host"])
            ))
        }
        ["hosts", "apply", file] => {
            let input: Value = serde_json::from_slice(
                &std::fs::read(file).map_err(|e| Usage(format!("Could not read {file}: {e}")))?,
            )
            .map_err(|e| Usage(format!("{file} is not valid JSON: {e}")))?;
            let incoming = match input {
                Value::Array(routes) => routes,
                route @ Value::Object(_) => vec![route],
                _ => return Err(Usage("Provide a route object or a list of routes.".into())),
            };
            let mut config = client.get("config").await?;
            let routes = config["routes"]
                .as_array_mut()
                .ok_or_else(|| Request("Unexpected configuration.".into()))?;
            let (mut created, mut replaced) = (0, 0);
            for mut route in incoming {
                if !route.is_object() {
                    return Err(Usage("Every entry must be a route object.".into()));
                }
                if route["id"].as_str().is_none_or(str::is_empty) {
                    route["id"] = json!(uuid::Uuid::new_v4().to_string());
                }
                match routes.iter().position(|r| r["id"] == route["id"]) {
                    Some(index) => {
                        routes[index] = route;
                        replaced += 1;
                    }
                    None => {
                        routes.push(route);
                        created += 1;
                    }
                }
            }
            save(&client, config).await?;
            Ok(format!("Applied: {created} created, {replaced} replaced."))
        }
        ["containers"] => {
            let info = client.get("docker/containers").await?;
            if as_json {
                return Ok(pretty(&info));
            }
            if info["configured"] == false {
                return Ok("Docker is not connected. Set DOCKER_HOST for EmberGate to enable container discovery.".into());
            }
            if let Some(error) = info["error"].as_str() {
                return Err(Request(format!("Could not list containers: {error}")));
            }
            let containers = info["containers"].as_array().cloned().unwrap_or_default();
            if containers.is_empty() {
                return Ok("No running containers.".into());
            }
            Ok(table(
                &["name", "image", "addresses", "used by"],
                containers
                    .iter()
                    .map(|c| {
                        let list = |v: &Value, key: Option<&str>| {
                            let items: Vec<String> = v
                                .as_array()
                                .into_iter()
                                .flatten()
                                .map(|i| text(key.map_or(i, |k| &i[k])))
                                .collect();
                            if items.is_empty() {
                                "—".into()
                            } else {
                                items.join(", ")
                            }
                        };
                        vec![
                            text(&c["name"]),
                            text(&c["image"]),
                            list(&c["suggested_upstreams"], None),
                            list(&c["exposed_by"], Some("host")),
                        ]
                    })
                    .collect(),
            ))
        }
        ["history"] => {
            let history = client.get("config/history").await?;
            if as_json {
                return Ok(pretty(&history));
            }
            let revisions = history["revisions"].as_array().cloned().unwrap_or_default();
            if revisions.is_empty() {
                return Ok(format!(
                    "Current revision {}. No earlier revisions retained.",
                    history["current_version"]
                ));
            }
            Ok(format!(
                "Current revision {}.\n{}",
                history["current_version"],
                table(
                    &["revision", "archived at", "by", "hosts"],
                    revisions
                        .iter()
                        .map(|r| vec![
                            text(&r["version"]),
                            text(&r["archived_at"]),
                            text(&r["archived_by"]),
                            text(&r["hosts"])
                        ])
                        .collect(),
                )
            ))
        }
        ["cache", "purge", rest @ ..] => {
            let mut route_id = None;
            let mut url = None;
            let mut rest = rest.iter();
            while let Some(arg) = rest.next() {
                match *arg {
                    "--url" => {
                        url = Some(
                            rest.next()
                                .ok_or_else(|| Usage("--url needs a value.".into()))?
                                .to_string(),
                        )
                    }
                    selector if route_id.is_none() => {
                        let config = client.get("config").await?;
                        route_id = Some(text(&config["routes"][find(&config, selector)?]["id"]));
                    }
                    other => return Err(Usage(format!("Unexpected argument “{other}”."))),
                }
            }
            let result = client
                .json(
                    reqwest::Method::POST,
                    "cache/purge",
                    Some(json!({"route_id":route_id,"url":url})),
                )
                .await?;
            if as_json {
                return Ok(pretty(&result));
            }
            Ok(format!(
                "Purged {} cached responses.",
                result["removed"].as_u64().unwrap_or(0)
            ))
        }
        ["backup", "export", "--output", path] | ["backup", "export", "-o", path] => {
            let passphrase = std::env::var("EMBERGATE_BACKUP_PASSPHRASE").map_err(|_| {
                Usage(
                    "Set EMBERGATE_BACKUP_PASSPHRASE to the passphrase that encrypts the backup."
                        .into(),
                )
            })?;
            let bytes = client
                .send(
                    reqwest::Method::POST,
                    "backups/export",
                    Some(json!({"passphrase":passphrase})),
                )
                .await?
                .bytes()
                .await
                .map_err(|e| Request(format!("Backup download failed: {e}")))?;
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
            options
                .open(path)
                .and_then(|mut file| file.write_all(&bytes))
                .map_err(|e| Request(format!("Could not write {path}: {e}")))?;
            Ok(format!(
                "Saved encrypted backup to {path} ({} bytes).",
                bytes.len()
            ))
        }
        _ => Err(Usage(format!("Unknown command.\n\n{USAGE}"))),
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match run(std::env::args().skip(1).collect()).await {
        Ok(output) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(failure) => {
            eprintln!("embergate-cli: {}", failure.message());
            ExitCode::from(failure.code())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_are_found_by_id_name_or_hostname() {
        let config = json!({"routes":[
            {"id":"a","name":"Photos","host":"photos.example.com"},
            {"id":"b","name":"Wiki","host":"wiki.example.com"},
            {"id":"c","name":"Wiki","host":"wiki2.example.com"}
        ]});
        assert_eq!(find(&config, "a").ok(), Some(0));
        assert_eq!(find(&config, "photos.example.com").ok(), Some(0));
        assert_eq!(find(&config, "wiki2.example.com").ok(), Some(2));
        assert!(
            matches!(find(&config, "Wiki"), Err(Usage(_))),
            "ambiguous names need an ID"
        );
        assert!(matches!(find(&config, "missing"), Err(NotFound(_))));
    }

    #[test]
    fn tables_align_columns() {
        let out = table(
            &["id", "name"],
            vec![
                vec!["1".into(), "Photos".into()],
                vec!["200".into(), "W".into()],
            ],
        );
        assert_eq!(out, "ID   NAME\n1    Photos\n200  W");
    }
}

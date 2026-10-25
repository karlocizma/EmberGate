//! Token-based DNS provider APIs: Hetzner, deSEC, DigitalOcean, Porkbun, Gandi, IONOS.
use super::{closest_zone, relative, ChallengeRecord, Settings};
use reqwest::{Client, Method, RequestBuilder, StatusCode};
use serde_json::{json, Value};
use std::time::Duration;

/// Challenge TTL in seconds, raised per provider to its minimum.
const TTL: u64 = 60;

pub struct Rest {
    pub settings: Settings,
    client: Client,
    base: String,
}

impl Rest {
    pub fn new(settings: Settings, base: Option<&str>) -> Result<Self, String> {
        let default = match settings.provider.as_str() {
            "hetzner" => "https://api.hetzner.cloud/v1",
            "desec" => "https://desec.io/api/v1",
            "digitalocean" => "https://api.digitalocean.com/v2",
            "porkbun" => "https://api.porkbun.com/api/json/v3",
            "gandi" => "https://api.gandi.net/v5/livedns",
            "ionos" => "https://api.hosting.ionos.com/dns/v1",
            _ => return Err("Choose a supported DNS provider.".into()),
        };
        Ok(Self {
            client: Client::builder()
                .timeout(Duration::from_secs(20))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|_| "Could not initialize DNS client.")?,
            base: base.unwrap_or(default).trim_end_matches('/').to_owned(),
            settings,
        })
    }
    fn provider(&self) -> &str {
        &self.settings.provider
    }
    fn name(&self) -> &'static str {
        super::kind(self.provider()).map_or("DNS", |kind| kind.name)
    }
    fn request(&self, method: Method, path: &str) -> RequestBuilder {
        let request = self.client.request(method, format!("{}{path}", self.base));
        let token = self.settings.get(super::TOKEN);
        match self.provider() {
            "desec" => request.header("Authorization", format!("Token {token}")),
            "ionos" => request.header("X-API-Key", token),
            // Porkbun authenticates in the JSON body.
            "porkbun" => request,
            _ => request.bearer_auth(token),
        }
    }
    /// Sends a request; `Ok(None)` is a 404. Errors never include response
    /// bodies or credentials.
    async fn send(&self, request: RequestBuilder) -> Result<Option<Value>, String> {
        let response = request
            .send()
            .await
            .map_err(|_| format!("Could not reach the {} DNS API.", self.name()))?;
        let status = response.status();
        if status == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|_| format!("{} returned an invalid response.", self.name()))?;
        let body: Value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)
                .map_err(|_| format!("{} returned an invalid response.", self.name()))?
        };
        if !status.is_success() || (self.provider() == "porkbun" && body["status"] != "SUCCESS") {
            return Err(format!(
                "{} DNS API rejected the request (HTTP {}). Check the credentials and their permissions for this zone.",
                self.name(),
                status.as_u16()
            ));
        }
        Ok(Some(body))
    }
    async fn porkbun(&self, path: &str, extra: Value) -> Result<Option<Value>, String> {
        let mut body = json!({"apikey":self.settings.get("api_key"),"secretapikey":self.settings.get("secret_key")});
        if let (Some(body), Value::Object(extra)) = (body.as_object_mut(), extra) {
            body.extend(extra);
        }
        self.send(self.request(Method::POST, path).json(&body))
            .await
    }
    fn missing(&self, domain: &str) -> String {
        format!(
            "No {} zone that this credential can manage was found for {domain}.",
            self.name()
        )
    }
    /// Parent names of a domain, longest first, excluding the top-level label.
    fn candidates(domain: &str) -> Vec<String> {
        let labels: Vec<_> = domain.split('.').collect();
        (0..labels.len().saturating_sub(1))
            .map(|offset| labels[offset..].join("."))
            .collect()
    }
    pub async fn zone_for(&self, domain: &str) -> Result<String, String> {
        let domain = domain.strip_prefix("*.").unwrap_or(domain);
        match self.provider() {
            "desec" => {
                let qname = format!("_acme-challenge.{domain}");
                let body = self
                    .send(
                        self.request(Method::GET, "/domains/")
                            .query(&[("owns_qname", qname.as_str())]),
                    )
                    .await?;
                body.as_ref()
                    .and_then(|body| body[0]["name"].as_str())
                    .map(str::to_owned)
                    .ok_or_else(|| self.missing(domain))
            }
            "ionos" => {
                let body = self
                    .send(self.request(Method::GET, "/zones"))
                    .await?
                    .unwrap_or_default();
                let zones = body.as_array().cloned().unwrap_or_default();
                let names = zones.iter().filter_map(|zone| zone["name"].as_str());
                let name = closest_zone(domain, names).ok_or_else(|| self.missing(domain))?;
                zones
                    .iter()
                    .find(|zone| zone["name"] == name)
                    .and_then(|zone| zone["id"].as_str())
                    .map(str::to_owned)
                    .ok_or_else(|| self.missing(domain))
            }
            provider => {
                for candidate in Self::candidates(domain) {
                    let found = match provider {
                        "hetzner" => self
                            .send(
                                self.request(Method::GET, "/zones")
                                    .query(&[("name", candidate.as_str())]),
                            )
                            .await?
                            .is_some_and(|body| body["zones"][0]["name"] == candidate.as_str()),
                        "digitalocean" => self
                            .send(self.request(Method::GET, &format!("/domains/{candidate}")))
                            .await?
                            .is_some(),
                        "gandi" => self
                            .send(self.request(Method::GET, &format!("/domains/{candidate}")))
                            .await?
                            .is_some(),
                        "porkbun" => {
                            // Unknown or API-disabled domains are refused, not 404.
                            self.porkbun(&format!("/dns/retrieve/{candidate}"), json!({}))
                                .await
                                .is_ok_and(|body| body.is_some())
                        }
                        _ => false,
                    };
                    if found {
                        return Ok(candidate);
                    }
                }
                Err(self.missing(domain))
            }
        }
    }
    /// The challenge name for `rrset` style APIs: relative to the zone, `@` at the apex.
    fn subname(record: &ChallengeRecord) -> &str {
        relative(&record.name, &record.zone).unwrap_or("@")
    }
    fn quoted(value: &str) -> String {
        format!("\"{value}\"")
    }
    fn same(found: &Value, value: &str) -> bool {
        found
            .as_str()
            .is_some_and(|found| found.trim_matches('"') == value)
    }
    /// Current values of the TXT set, quoted as the provider stores them.
    async fn rrset(&self, record: &ChallengeRecord) -> Result<Vec<Value>, String> {
        let name = Self::subname(record);
        let (path, key) = match self.provider() {
            "desec" => (
                format!(
                    "/domains/{}/rrsets/{}/TXT/",
                    record.zone,
                    if name == "@" { "" } else { name }
                ),
                "records",
            ),
            _ => (
                format!("/domains/{}/records/{name}/TXT", record.zone),
                "rrset_values",
            ),
        };
        Ok(self
            .send(self.request(Method::GET, &path))
            .await?
            .and_then(|body| body[key].as_array().cloned())
            .unwrap_or_default())
    }
    async fn write_rrset(
        &self,
        record: &ChallengeRecord,
        values: Vec<Value>,
    ) -> Result<(), String> {
        let name = Self::subname(record);
        match self.provider() {
            "desec" => {
                // An empty record list deletes the set. deSEC's minimum TTL is 3600.
                let subname = if name == "@" { "" } else { name };
                self.send(
                    self.request(Method::PATCH, &format!("/domains/{}/rrsets/", record.zone))
                        .json(
                            &json!([{"subname":subname,"type":"TXT","ttl":3600,"records":values}]),
                        ),
                )
                .await?;
            }
            _ => {
                let path = format!("/domains/{}/records/{name}/TXT", record.zone);
                if values.is_empty() {
                    self.send(self.request(Method::DELETE, &path)).await?;
                } else {
                    // Gandi's minimum TTL is 300.
                    self.send(
                        self.request(Method::PUT, &path)
                            .json(&json!({"rrset_values":values,"rrset_ttl":300})),
                    )
                    .await?;
                }
            }
        }
        Ok(())
    }
    /// Records with IDs, for APIs that manage individual records.
    async fn records(&self, record: &ChallengeRecord) -> Result<Vec<(String, Value)>, String> {
        let (list, id_key, value_key) = match self.provider() {
            "digitalocean" => {
                let body = self
                    .send(
                        self.request(Method::GET, &format!("/domains/{}/records", record.zone))
                            .query(&[
                                ("type", "TXT"),
                                ("name", record.name.as_str()),
                                ("per_page", "200"),
                            ]),
                    )
                    .await?
                    .unwrap_or_default();
                (body["domain_records"].clone(), "id", "data")
            }
            "porkbun" => {
                let path = format!(
                    "/dns/retrieveByNameType/{}/TXT/{}",
                    record.zone,
                    relative(&record.name, &record.zone).unwrap_or("")
                );
                let body = self.porkbun(&path, json!({})).await?.unwrap_or_default();
                (body["records"].clone(), "id", "content")
            }
            _ => {
                let body = self
                    .send(
                        self.request(Method::GET, &format!("/zones/{}", record.zone))
                            .query(&[("recordName", record.name.as_str()), ("recordType", "TXT")]),
                    )
                    .await?
                    .unwrap_or_default();
                (body["records"].clone(), "id", "content")
            }
        };
        let list = list.as_array().cloned().unwrap_or_default();
        if list.len() >= 200 {
            return Err(
                "Too many challenge records to manage safely; remove obsolete records first."
                    .into(),
            );
        }
        Ok(list
            .into_iter()
            .filter_map(|found| {
                let id = match &found[id_key] {
                    Value::String(id) => id.clone(),
                    Value::Number(id) => id.to_string(),
                    _ => return None,
                };
                Some((id, found[value_key].clone()))
            })
            .collect())
    }
    pub async fn present(&self, record: &ChallengeRecord) -> Result<(), String> {
        match self.provider() {
            "hetzner" => {
                self.send(
                    self.request(
                        Method::POST,
                        &format!("/zones/{}/rrsets/{}/TXT/actions/add_records", record.zone, Self::subname(record)),
                    )
                    .json(&json!({"ttl":TTL,"records":[{"value":Self::quoted(&record.value),"comment":record.comment}]})),
                )
                .await?;
            }
            "desec" | "gandi" => {
                let mut values = self.rrset(record).await?;
                if !values.iter().any(|found| Self::same(found, &record.value)) {
                    values.push(Self::quoted(&record.value).into());
                    self.write_rrset(record, values).await?;
                }
            }
            "digitalocean" => {
                self.send(
                    self.request(Method::POST, &format!("/domains/{}/records", record.zone))
                        .json(&json!({"type":"TXT","name":Self::subname(record),"data":record.value,"ttl":TTL})),
                )
                .await?;
            }
            "porkbun" => {
                // Porkbun's minimum TTL is 600.
                self.porkbun(
                    &format!("/dns/create/{}", record.zone),
                    json!({"name":relative(&record.name, &record.zone).unwrap_or(""),"type":"TXT","content":record.value,"ttl":"600"}),
                )
                .await?;
            }
            _ => {
                self.send(
                    self.request(Method::POST, &format!("/zones/{}/records", record.zone))
                        .json(&json!([{"name":record.name,"type":"TXT","content":record.value,"ttl":TTL,"disabled":false}])),
                )
                .await?;
            }
        }
        Ok(())
    }
    /// Removes only the challenge value EmberGate created. Values are unique to
    /// one authorization, so other clients' records under the same name stay.
    pub async fn cleanup(&self, record: &ChallengeRecord) -> Result<(), String> {
        match self.provider() {
            "hetzner" => {
                self.send(
                    self.request(
                        Method::POST,
                        &format!(
                            "/zones/{}/rrsets/{}/TXT/actions/remove_records",
                            record.zone,
                            Self::subname(record)
                        ),
                    )
                    .json(&json!({"records":[{"value":Self::quoted(&record.value)}]})),
                )
                .await?;
            }
            "desec" | "gandi" => {
                let values = self.rrset(record).await?;
                let kept: Vec<_> = values
                    .iter()
                    .filter(|found| !Self::same(found, &record.value))
                    .cloned()
                    .collect();
                if kept.len() != values.len() {
                    self.write_rrset(record, kept).await?;
                }
            }
            provider => {
                for (id, value) in self.records(record).await? {
                    if !Self::same(&value, &record.value) {
                        continue;
                    }
                    match provider {
                        "digitalocean" => {
                            self.send(self.request(
                                Method::DELETE,
                                &format!("/domains/{}/records/{id}", record.zone),
                            ))
                            .await?;
                        }
                        "porkbun" => {
                            self.porkbun(&format!("/dns/delete/{}/{id}", record.zone), json!({}))
                                .await?;
                        }
                        _ => {
                            self.send(self.request(
                                Method::DELETE,
                                &format!("/zones/{}/records/{id}", record.zone),
                            ))
                            .await?;
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Bytes,
        extract::{Path, State},
        http::{HeaderMap, Method as HttpMethod, Uri},
        routing::any,
        Json, Router,
    };
    use std::collections::{BTreeMap, HashMap};
    use std::sync::{Arc, Mutex};

    /// An in-memory fake of one provider's API: TXT values by record name.
    #[derive(Clone, Default)]
    struct Fake {
        provider: &'static str,
        records: Arc<Mutex<BTreeMap<String, Vec<(u64, String)>>>>,
        next: Arc<Mutex<u64>>,
    }
    impl Fake {
        fn add(&self, name: &str, value: &str) {
            let mut next = self.next.lock().unwrap();
            *next += 1;
            self.records
                .lock()
                .unwrap()
                .entry(name.into())
                .or_default()
                .push((*next, value.into()));
        }
        fn values(&self, name: &str) -> Vec<String> {
            self.records
                .lock()
                .unwrap()
                .get(name)
                .map(|set| set.iter().map(|(_, v)| v.clone()).collect())
                .unwrap_or_default()
        }
        fn authorized(&self, headers: &HeaderMap, body: &Value) -> bool {
            let header = |name: &str| {
                headers
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
            };
            match self.provider {
                "desec" => header("authorization") == "Token secret-token",
                "ionos" => header("x-api-key") == "secret-token",
                "porkbun" => body["apikey"] == "pk1_key" && body["secretapikey"] == "sk1_secret",
                _ => header("authorization") == "Bearer secret-token",
            }
        }
    }
    fn fqdn(sub: &str) -> String {
        if sub.is_empty() || sub == "@" {
            "example.com".into()
        } else {
            format!("{sub}.example.com")
        }
    }

    async fn handle(
        State(fake): State<Fake>,
        method: HttpMethod,
        uri: Uri,
        headers: HeaderMap,
        Path(path): Path<String>,
        body: Bytes,
    ) -> (axum::http::StatusCode, Json<Value>) {
        use axum::http::StatusCode as S;
        let body: Value = serde_json::from_slice(&body).unwrap_or_default();
        if !fake.authorized(&headers, &body) {
            return (S::UNAUTHORIZED, Json(json!({"status":"ERROR"})));
        }
        let query: HashMap<String, String> = uri
            .query()
            .map(|q| {
                url::form_urlencoded::parse(q.as_bytes())
                    .into_owned()
                    .collect()
            })
            .unwrap_or_default();
        let parts: Vec<&str> = path.trim_end_matches('/').split('/').collect();
        let ok = |value: Value| (S::OK, Json(value));
        let quoted = |set: Vec<String>| {
            set.into_iter()
                .map(|v| format!("\"{v}\""))
                .collect::<Vec<_>>()
        };
        match (fake.provider, method.as_str(), parts.as_slice()) {
            ("hetzner", "GET", ["zones"]) => ok(
                json!({"zones": if query["name"]=="example.com" {json!([{"id":1,"name":"example.com"}])} else {json!([])}}),
            ),
            (
                "hetzner",
                "POST",
                ["zones", "example.com", "rrsets", sub, "TXT", "actions", action],
            ) => {
                assert_eq!(
                    body["records"][0]["value"]
                        .as_str()
                        .unwrap()
                        .matches('"')
                        .count(),
                    2
                );
                let value = body["records"][0]["value"]
                    .as_str()
                    .unwrap()
                    .trim_matches('"')
                    .to_owned();
                if *action == "add_records" {
                    fake.add(&fqdn(sub), &value);
                } else {
                    fake.records
                        .lock()
                        .unwrap()
                        .entry(fqdn(sub))
                        .or_default()
                        .retain(|(_, v)| *v != value);
                }
                ok(json!({"action":{"id":1}}))
            }
            ("desec", "GET", ["domains"]) => ok(if query["owns_qname"].ends_with("example.com") {
                json!([{"name":"example.com"}])
            } else {
                json!([])
            }),
            ("desec", "GET", ["domains", "example.com", "rrsets", sub, "TXT"]) => {
                let set = fake.values(&fqdn(sub));
                if set.is_empty() {
                    (S::NOT_FOUND, Json(json!({})))
                } else {
                    ok(json!({"records":quoted(set)}))
                }
            }
            ("desec", "PATCH", ["domains", "example.com", "rrsets"]) => {
                let rrset = &body[0];
                assert_eq!(rrset["ttl"], 3600);
                let name = fqdn(rrset["subname"].as_str().unwrap());
                fake.records.lock().unwrap().remove(&name);
                for value in rrset["records"].as_array().unwrap() {
                    fake.add(&name, value.as_str().unwrap().trim_matches('"'));
                }
                ok(json!([]))
            }
            ("gandi", "GET", ["domains", domain])
            | ("digitalocean", "GET", ["domains", domain]) => {
                if *domain == "example.com" {
                    ok(json!({}))
                } else {
                    (S::NOT_FOUND, Json(json!({})))
                }
            }
            ("gandi", "GET", ["domains", "example.com", "records", sub, "TXT"]) => {
                let set = fake.values(&fqdn(sub));
                if set.is_empty() {
                    (S::NOT_FOUND, Json(json!({})))
                } else {
                    ok(json!({"rrset_values":quoted(set)}))
                }
            }
            ("gandi", "PUT", ["domains", "example.com", "records", sub, "TXT"]) => {
                fake.records.lock().unwrap().remove(&fqdn(sub));
                for value in body["rrset_values"].as_array().unwrap() {
                    fake.add(&fqdn(sub), value.as_str().unwrap().trim_matches('"'));
                }
                ok(json!({}))
            }
            ("gandi", "DELETE", ["domains", "example.com", "records", sub, "TXT"]) => {
                fake.records.lock().unwrap().remove(&fqdn(sub));
                ok(json!({}))
            }
            ("digitalocean", "GET", ["domains", "example.com", "records"]) => {
                let records = fake
                    .records
                    .lock()
                    .unwrap()
                    .get(&query["name"])
                    .cloned()
                    .unwrap_or_default();
                ok(
                    json!({"domain_records":records.iter().map(|(id,v)|json!({"id":id,"type":"TXT","data":v})).collect::<Vec<_>>()}),
                )
            }
            ("digitalocean", "POST", ["domains", "example.com", "records"]) => {
                fake.add(
                    &fqdn(body["name"].as_str().unwrap()),
                    body["data"].as_str().unwrap(),
                );
                ok(json!({}))
            }
            ("digitalocean", "DELETE", ["domains", "example.com", "records", id])
            | ("ionos", "DELETE", ["zones", "zone-1", "records", id]) => {
                for set in fake.records.lock().unwrap().values_mut() {
                    set.retain(|(old, _)| old.to_string() != *id);
                }
                (S::NO_CONTENT, Json(Value::Null))
            }
            ("porkbun", "POST", ["dns", "retrieve", domain]) => {
                if *domain == "example.com" {
                    ok(json!({"status":"SUCCESS","records":[]}))
                } else {
                    (S::BAD_REQUEST, Json(json!({"status":"ERROR"})))
                }
            }
            ("porkbun", "POST", ["dns", "retrieveByNameType", "example.com", "TXT", sub]) => {
                let records = fake
                    .records
                    .lock()
                    .unwrap()
                    .get(&fqdn(sub))
                    .cloned()
                    .unwrap_or_default();
                ok(
                    json!({"status":"SUCCESS","records":records.iter().map(|(id,v)|json!({"id":id.to_string(),"content":v})).collect::<Vec<_>>()}),
                )
            }
            ("porkbun", "POST", ["dns", "create", "example.com"]) => {
                fake.add(
                    &fqdn(body["name"].as_str().unwrap()),
                    body["content"].as_str().unwrap(),
                );
                ok(json!({"status":"SUCCESS","id":1}))
            }
            ("porkbun", "POST", ["dns", "delete", "example.com", id]) => {
                for set in fake.records.lock().unwrap().values_mut() {
                    set.retain(|(old, _)| old.to_string() != *id);
                }
                ok(json!({"status":"SUCCESS"}))
            }
            ("ionos", "GET", ["zones"]) => {
                ok(json!([{"id":"zone-0","name":"com"},{"id":"zone-1","name":"example.com"}]))
            }
            ("ionos", "GET", ["zones", "zone-1"]) => {
                let records = fake
                    .records
                    .lock()
                    .unwrap()
                    .get(&query["recordName"])
                    .cloned()
                    .unwrap_or_default();
                ok(
                    json!({"records":records.iter().map(|(id,v)|json!({"id":id.to_string(),"content":format!("\"{v}\"")})).collect::<Vec<_>>()}),
                )
            }
            ("ionos", "POST", ["zones", "zone-1", "records"]) => {
                fake.add(
                    body[0]["name"].as_str().unwrap(),
                    body[0]["content"].as_str().unwrap(),
                );
                ok(json!([]))
            }
            other => panic!("unexpected request {other:?}"),
        }
    }

    #[tokio::test]
    async fn every_rest_provider_adds_and_removes_only_its_own_value() {
        for provider in [
            "hetzner",
            "desec",
            "digitalocean",
            "porkbun",
            "gandi",
            "ionos",
        ] {
            let fake = Fake {
                provider,
                ..Default::default()
            };
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let app = Router::new()
                .route("/{*path}", any(handle))
                .with_state(fake.clone());
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let credentials = if provider == "porkbun" {
                vec![("api_key", "pk1_key"), ("secret_key", "sk1_secret")]
            } else {
                vec![("token", "secret-token")]
            };
            let mut settings = Settings {
                provider: provider.into(),
                credentials: credentials
                    .iter()
                    .map(|(k, v)| ((*k).into(), (*v).into()))
                    .collect(),
            };
            let dns = super::super::Provider::new(&mut settings, Some(&base)).unwrap();
            let zone = dns.zone_for("*.www.example.com").await.unwrap();
            assert!(dns.zone_for("example.org").await.is_err(), "{provider}");
            let name = "_acme-challenge.www.example.com";
            fake.add(name, "another-client");
            let record = ChallengeRecord {
                zone: zone.clone(),
                name: name.into(),
                value: "ours".into(),
                comment: "EmberGate ACME test".into(),
            };
            dns.present(&record).await.unwrap();
            assert_eq!(fake.values(name), ["another-client", "ours"], "{provider}");
            dns.cleanup(&record).await.unwrap();
            assert_eq!(fake.values(name), ["another-client"], "{provider}");
            // Apex challenge names work too.
            let apex = ChallengeRecord {
                zone,
                name: "_acme-challenge.example.com".into(),
                ..record
            };
            dns.present(&apex).await.unwrap();
            assert_eq!(fake.values(&apex.name), ["ours"], "{provider}");
            dns.cleanup(&apex).await.unwrap();
            assert!(fake.values(&apex.name).is_empty(), "{provider}");

            let mut wrong = settings.clone();
            for value in wrong.credentials.values_mut() {
                value.push('x');
            }
            let error = super::super::Provider::new(&mut wrong, Some(&base))
                .unwrap()
                .zone_for("www.example.com")
                .await
                .unwrap_err();
            assert!(
                !error.contains("secret-token") && !error.contains("sk1_"),
                "{provider}: {error}"
            );
            server.abort();
        }
    }
}

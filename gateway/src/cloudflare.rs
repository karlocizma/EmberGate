use reqwest::{Client, Method};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Duration;

pub struct Cloudflare {
    client: Client,
    token: String,
    base: String,
    dns_endpoint: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ChallengeRecord {
    pub zone: String,
    pub name: String,
    pub value: String,
    pub comment: String,
}

impl Cloudflare {
    pub(crate) fn backup_token(&self) -> String {
        self.token.clone()
    }
    pub fn new(token: String, base: String, dns_endpoint: String) -> Result<Self, String> {
        Ok(Self {
            client: Client::builder()
                .timeout(Duration::from_secs(20))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|_| "Could not initialize DNS client.")?,
            token,
            base: base.trim_end_matches('/').to_owned(),
            dns_endpoint,
        })
    }
    async fn call(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, &str)],
        body: Option<Value>,
    ) -> Result<Value, String> {
        let mut request = self
            .client
            .request(method, format!("{}{path}", self.base))
            .bearer_auth(&self.token)
            .query(query);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request
            .send()
            .await
            .map_err(|_| "Could not reach the Cloudflare DNS API.".to_owned())?;
        let status = response.status();
        let body: Value = response
            .json()
            .await
            .map_err(|_| "Cloudflare returned an invalid response.".to_owned())?;
        if !status.is_success() || body["success"] != true {
            // Do not echo response bodies or credentials into logs or API errors.
            let code = body["errors"][0]["code"].as_u64().unwrap_or(0);
            return Err(format!("Cloudflare DNS API rejected the request (HTTP {}, code {code}). Check the token's zone permissions.", status.as_u16()));
        }
        Ok(body["result"].clone())
    }
    pub async fn zone_for(&self, domain: &str) -> Result<String, String> {
        let domain = domain.strip_prefix("*.").unwrap_or(domain);
        let labels: Vec<_> = domain.split('.').collect();
        for offset in 0..labels.len().saturating_sub(1) {
            let candidate = labels[offset..].join(".");
            let result = self
                .call(
                    Method::GET,
                    "/zones",
                    &[
                        ("name", &candidate),
                        ("status", "active"),
                        ("per_page", "1"),
                    ],
                    None,
                )
                .await?;
            if let Some(zone) = result[0]["id"].as_str() {
                return Ok(zone.to_owned());
            }
        }
        Err(format!("No accessible Cloudflare zone was found for {domain}. Grant Zone Read and DNS Edit on its zone."))
    }
    async fn records(&self, zone: &str, name: &str, kind: &str) -> Result<Vec<Value>, String> {
        let result = self
            .call(
                Method::GET,
                &format!("/zones/{zone}/dns_records"),
                &[("name", name), ("type", kind), ("per_page", "100")],
                None,
            )
            .await?;
        let records = result
            .as_array()
            .ok_or("Cloudflare returned an invalid record list.")?;
        if records.len() >= 100 {
            return Err(
                "Too many challenge records to manage safely; remove obsolete records first."
                    .into(),
            );
        }
        Ok(records.clone())
    }
    pub async fn check_delegation(&self, record: &ChallengeRecord) -> Result<(), String> {
        if !self
            .records(&record.zone, &record.name, "CNAME")
            .await?
            .is_empty()
        {
            return Err(format!("{} has a CNAME delegation. This version supports direct Cloudflare DNS challenges only.", record.name));
        }
        Ok(())
    }
    pub async fn present(&self, record: &ChallengeRecord) -> Result<(), String> {
        self.call(Method::POST, &format!("/zones/{}/dns_records", record.zone), &[], Some(json!({
            "type":"TXT", "name":record.name, "content":record.value, "ttl":120, "comment":record.comment
        }))).await?;
        Ok(())
    }
    pub async fn cleanup(&self, record: &ChallengeRecord) -> Result<(), String> {
        // Match our unique ownership comment and exact value. Never erase another
        // ACME client's TXT records, even when it uses the same challenge name.
        for found in self.records(&record.zone, &record.name, "TXT").await? {
            if found["content"].as_str() != Some(record.value.as_str())
                || found["comment"].as_str() != Some(record.comment.as_str())
            {
                continue;
            }
            let id = found["id"]
                .as_str()
                .ok_or("Cloudflare returned a record without an ID.")?;
            self.call(
                Method::DELETE,
                &format!("/zones/{}/dns_records/{id}", record.zone),
                &[],
                None,
            )
            .await?;
        }
        Ok(())
    }
    pub async fn propagated(&self, record: &ChallengeRecord) -> Result<bool, String> {
        // Public recursive DNS must see the TXT value before asking the CA to validate.
        let response = self
            .client
            .get(&self.dns_endpoint)
            .header("Accept", "application/dns-json")
            .query(&[("name", record.name.as_str()), ("type", "TXT")])
            .send()
            .await
            .map_err(|_| "Could not check public DNS propagation.".to_owned())?;
        if !response.status().is_success() {
            return Ok(false);
        }
        let body: Value = response
            .json()
            .await
            .map_err(|_| "Invalid public DNS response.".to_owned())?;
        Ok(body["Status"] == 0
            && body["Answer"].as_array().is_some_and(|answers| {
                answers.iter().any(|answer| {
                    answer["type"] == 16
                        && answer["data"]
                            .as_str()
                            .is_some_and(|value| value.trim_matches('"') == record.value)
                })
            }))
    }
}

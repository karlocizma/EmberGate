//! DNS-01 providers and the provider-independent public propagation check.
use crate::cloudflare::Cloudflare;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;

/// A TXT record EmberGate created for one DNS-01 challenge. `zone` is the
/// provider's identifier for the zone that holds it.
#[derive(Clone, Serialize, Deserialize)]
pub struct ChallengeRecord {
    pub zone: String,
    pub name: String,
    pub value: String,
    pub comment: String,
}

/// A DNS service that can create and remove challenge TXT records.
pub enum Provider {
    Cloudflare(Cloudflare),
}
impl Provider {
    pub fn id(&self) -> &'static str {
        match self {
            Self::Cloudflare(_) => "cloudflare",
        }
    }
    pub fn name(&self) -> &'static str {
        match self {
            Self::Cloudflare(_) => "Cloudflare",
        }
    }
    pub(crate) fn backup_token(&self) -> String {
        match self {
            Self::Cloudflare(provider) => provider.backup_token(),
        }
    }
    /// Finds the provider's zone identifier for a challenge domain.
    pub async fn zone_for(&self, domain: &str) -> Result<String, String> {
        match self {
            Self::Cloudflare(provider) => provider.zone_for(domain).await,
        }
    }
    /// Refuses challenge names delegated elsewhere, where a TXT record would be ignored.
    pub async fn check_delegation(&self, record: &ChallengeRecord) -> Result<(), String> {
        match self {
            Self::Cloudflare(provider) => provider.check_delegation(record).await,
        }
    }
    pub async fn present(&self, record: &ChallengeRecord) -> Result<(), String> {
        match self {
            Self::Cloudflare(provider) => provider.present(record).await,
        }
    }
    /// Removes only the record EmberGate created, never another client's.
    pub async fn cleanup(&self, record: &ChallengeRecord) -> Result<(), String> {
        match self {
            Self::Cloudflare(provider) => provider.cleanup(record).await,
        }
    }
}

/// Asks a public DNS-over-HTTPS resolver whether a challenge value is visible yet.
pub struct Propagation {
    client: Client,
    endpoint: String,
}
impl Propagation {
    pub fn new(endpoint: String) -> Result<Self, String> {
        Ok(Self {
            client: Client::builder()
                .timeout(Duration::from_secs(20))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|_| "Could not initialize DNS client.")?,
            endpoint,
        })
    }
    pub async fn visible(&self, record: &ChallengeRecord) -> Result<bool, String> {
        // Public recursive DNS must see the TXT value before asking the CA to validate.
        let response = self
            .client
            .get(&self.endpoint)
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

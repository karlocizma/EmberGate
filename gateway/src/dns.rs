//! DNS-01 providers and the provider-independent public propagation check.
mod acme_dns;
mod rest;
mod rfc2136;

use crate::cloudflare::Cloudflare;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
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

/// One credential field a provider needs. `secret` fields are never shown again.
struct Field {
    id: &'static str,
    label: &'static str,
    secret: bool,
    optional: bool,
    help: &'static str,
}
const fn field(id: &'static str, label: &'static str, secret: bool, help: &'static str) -> Field {
    Field {
        id,
        label,
        secret,
        optional: false,
        help,
    }
}

struct Kind {
    id: &'static str,
    name: &'static str,
    fields: &'static [Field],
    guide: &'static str,
}

const TOKEN: &str = "token";
const KINDS: &[Kind] = &[
    Kind {
        id: "cloudflare",
        name: "Cloudflare",
        fields: &[field(TOKEN, "API token", true, "Grant Zone Read and DNS Edit on the zones you manage.")],
        guide: "automatic-certificates-with-cloudflare-dns",
    },
    Kind {
        id: "acme-dns",
        name: "acme-dns",
        fields: &[
            field("server", "Server URL", false, "Your acme-dns server, for example https://auth.example.net."),
            field("username", "Username", false, "From the acme-dns registration response."),
            field("password", "Password", true, "From the acme-dns registration response."),
            field("subdomain", "Subdomain", false, "From the registration response; each _acme-challenge name must be a CNAME to <subdomain>.<acme-dns domain>."),
        ],
        guide: "acme-dns",
    },
    Kind {
        id: "rfc2136",
        name: "RFC 2136 (BIND, PowerDNS, Knot, Technitium)",
        fields: &[
            field("server", "Server", false, "Primary name server that accepts updates, as host or host:port (port 53 by default). Updates use TCP."),
            field("zones", "Zones", false, "Zones this key may update, separated by commas, for example example.com,example.org."),
            field("key_name", "TSIG key name", false, "The key name configured on the server."),
            field("algorithm", "TSIG algorithm", false, "hmac-sha256 or hmac-sha512."),
            field("secret", "TSIG secret", true, "Base64 secret of the key."),
        ],
        guide: "rfc-2136-dynamic-updates",
    },
    Kind {
        id: "hetzner",
        name: "Hetzner",
        fields: &[field(TOKEN, "API token", true, "A Hetzner Console project token with read & write access, from the project that holds the zones.")],
        guide: "dns-provider-apis",
    },
    Kind {
        id: "desec",
        name: "deSEC",
        fields: &[field(TOKEN, "API token", true, "A deSEC token; restrict it to the challenge names with a token policy where possible.")],
        guide: "dns-provider-apis",
    },
    Kind {
        id: "digitalocean",
        name: "DigitalOcean",
        fields: &[field(TOKEN, "API token", true, "A personal access token with the domain:read and domain:create/update/delete scopes only.")],
        guide: "dns-provider-apis",
    },
    Kind {
        id: "porkbun",
        name: "Porkbun",
        fields: &[
            field("api_key", "API key", false, "Starts with pk1_. Enable API access on each domain."),
            field("secret_key", "Secret API key", true, "Starts with sk1_."),
        ],
        guide: "dns-provider-apis",
    },
    Kind {
        id: "gandi",
        name: "Gandi",
        fields: &[field(TOKEN, "Personal access token", true, "Grant \"Manage domain name technical configurations\" for the domains you use.")],
        guide: "dns-provider-apis",
    },
    Kind {
        id: "ionos",
        name: "IONOS",
        fields: &[field(TOKEN, "API key", true, "The full key as <public prefix>.<secret>, from the IONOS developer portal.")],
        guide: "dns-provider-apis",
    },
];

fn kind(id: &str) -> Option<&'static Kind> {
    KINDS.iter().find(|kind| kind.id == id)
}

/// Providers and their fields, for the dashboard. Contains no credentials.
pub fn catalog() -> Value {
    Value::Array(
        KINDS
            .iter()
            .map(|kind| {
                json!({"id":kind.id,"name":kind.name,"guide":kind.guide,"fields":kind.fields.iter().map(|f|json!({"id":f.id,"label":f.label,"secret":f.secret,"optional":f.optional,"help":f.help})).collect::<Vec<_>>()})
            })
            .collect(),
    )
}

/// Saved provider settings. Cloudflare keeps its own `cloudflare_token` secret
/// for compatibility; every other provider is stored as this JSON document.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub provider: String,
    pub credentials: BTreeMap<String, String>,
}
impl Settings {
    pub fn cloudflare(token: String) -> Self {
        Self {
            provider: "cloudflare".into(),
            credentials: BTreeMap::from([(TOKEN.to_owned(), token)]),
        }
    }
    /// Checks the provider and its fields, trimming values in place.
    pub fn validate(&mut self) -> Result<(), String> {
        let kind = kind(&self.provider).ok_or("Choose a supported DNS provider.")?;
        if self
            .credentials
            .keys()
            .any(|key| !kind.fields.iter().any(|field| field.id == key))
        {
            return Err(format!("Unexpected credential field for {}.", kind.name));
        }
        for field in kind.fields {
            let value = self
                .credentials
                .get_mut(field.id)
                .map(|value| {
                    *value = value.trim().to_owned();
                    value
                })
                .filter(|value| !value.is_empty());
            match value {
                None if field.optional => {
                    self.credentials.remove(field.id);
                }
                None => return Err(format!("Enter the {}.", field.label.to_lowercase())),
                Some(value)
                    if value.len() > 4096 || !value.bytes().all(|byte| byte.is_ascii_graphic()) =>
                {
                    return Err(format!(
                        "Use a {} without spaces, up to 4096 characters.",
                        field.label.to_lowercase()
                    ))
                }
                Some(_) => {}
            }
        }
        Ok(())
    }
    fn get(&self, id: &str) -> &str {
        self.credentials.get(id).map_or("", String::as_str)
    }
}

/// Checks a `dns_provider` secret in a backup before it is restored.
pub fn validate_backup(value: &str) -> Result<(), String> {
    let mut settings: Settings =
        serde_json::from_str(value).map_err(|_| "Invalid DNS provider credentials.".to_owned())?;
    if settings.provider == "cloudflare" {
        return Err("Invalid DNS provider credentials.".into());
    }
    Provider::new(&mut settings, None).map(drop)
}

/// A DNS service that can create and remove challenge TXT records.
pub enum Provider {
    Cloudflare(Cloudflare),
    AcmeDns(acme_dns::AcmeDns),
    Rfc2136(rfc2136::Rfc2136),
    Rest(rest::Rest),
}
impl Provider {
    /// Builds a provider from validated settings. `base` overrides the API
    /// address for local fixtures.
    pub fn new(settings: &mut Settings, base: Option<&str>) -> Result<Self, String> {
        settings.validate()?;
        let settings = settings.clone();
        Ok(match settings.provider.as_str() {
            "cloudflare" => Self::Cloudflare(Cloudflare::new(
                settings.get(TOKEN).to_owned(),
                base.unwrap_or("https://api.cloudflare.com/client/v4")
                    .to_owned(),
            )?),
            "acme-dns" => Self::AcmeDns(acme_dns::AcmeDns::new(settings)?),
            "rfc2136" => Self::Rfc2136(rfc2136::Rfc2136::new(settings)?),
            _ => Self::Rest(rest::Rest::new(settings, base)?),
        })
    }
    pub fn settings(&self) -> Settings {
        match self {
            Self::Cloudflare(provider) => Settings::cloudflare(provider.backup_token()),
            Self::AcmeDns(provider) => provider.settings.clone(),
            Self::Rfc2136(provider) => provider.settings.clone(),
            Self::Rest(provider) => provider.settings.clone(),
        }
    }
    pub fn id(&self) -> &'static str {
        kind(&self.settings().provider).map_or("", |kind| kind.id)
    }
    pub fn name(&self) -> &'static str {
        match self {
            Self::Rfc2136(_) => "RFC 2136",
            _ => kind(&self.settings().provider).map_or("DNS", |kind| kind.name),
        }
    }
    /// Non-secret fields, so the dashboard can show what is configured.
    pub fn summary(&self) -> Value {
        let settings = self.settings();
        let kind = kind(&settings.provider);
        let mut public = serde_json::Map::new();
        for field in kind.map_or(&[][..], |kind| kind.fields) {
            if !field.secret {
                if let Some(value) = settings.credentials.get(field.id) {
                    public.insert(field.id.into(), value.clone().into());
                }
            }
        }
        Value::Object(public)
    }
    /// The secret row that restores this provider: `(key, value)`.
    pub(crate) fn backup_secret(&self) -> (String, String) {
        match self {
            Self::Cloudflare(provider) => ("cloudflare_token".into(), provider.backup_token()),
            _ => (
                "dns_provider".into(),
                serde_json::to_string(&self.settings()).unwrap_or_default(),
            ),
        }
    }
    /// The most challenge names one order may use; acme-dns keeps only two values.
    pub fn name_limit(&self) -> usize {
        match self {
            Self::AcmeDns(_) => 2,
            _ => usize::MAX,
        }
    }
    /// Finds the provider's zone identifier for a challenge domain.
    pub async fn zone_for(&self, domain: &str) -> Result<String, String> {
        match self {
            Self::Cloudflare(provider) => provider.zone_for(domain).await,
            Self::AcmeDns(provider) => Ok(provider.zone()),
            Self::Rfc2136(provider) => provider.zone_for(domain),
            Self::Rest(provider) => provider.zone_for(domain).await,
        }
    }
    /// Refuses challenge names delegated elsewhere, where a TXT record would be
    /// ignored, and for acme-dns names that are not delegated yet.
    pub async fn check_delegation(
        &self,
        record: &ChallengeRecord,
        propagation: &Propagation,
    ) -> Result<(), String> {
        match self {
            Self::Cloudflare(provider) => provider.check_delegation(record).await,
            Self::AcmeDns(provider) => provider.check_delegation(record, propagation).await,
            _ => Ok(()),
        }
    }
    pub async fn present(&self, record: &ChallengeRecord) -> Result<(), String> {
        match self {
            Self::Cloudflare(provider) => provider.present(record).await,
            Self::AcmeDns(provider) => provider.present(record).await,
            Self::Rfc2136(provider) => provider.present(record).await,
            Self::Rest(provider) => provider.present(record).await,
        }
    }
    /// Removes only the record EmberGate created, never another client's.
    pub async fn cleanup(&self, record: &ChallengeRecord) -> Result<(), String> {
        match self {
            Self::Cloudflare(provider) => provider.cleanup(record).await,
            // acme-dns has no delete; it keeps the two newest values per account.
            Self::AcmeDns(_) => Ok(()),
            Self::Rfc2136(provider) => provider.cleanup(record).await,
            Self::Rest(provider) => provider.cleanup(record).await,
        }
    }
}

/// The record name relative to its zone, or `None` at the zone apex.
fn relative<'a>(name: &'a str, zone: &str) -> Option<&'a str> {
    name.strip_suffix(zone)
        .and_then(|rest| rest.strip_suffix('.'))
        .filter(|rest| !rest.is_empty())
}

/// The longest zone, by DNS label boundary, that contains `domain`.
fn closest_zone<'a>(domain: &str, zones: impl IntoIterator<Item = &'a str>) -> Option<&'a str> {
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    zones
        .into_iter()
        .filter(|zone| {
            let zone = zone.trim_end_matches('.').to_ascii_lowercase();
            domain == zone || domain.ends_with(&format!(".{zone}"))
        })
        .max_by_key(|zone| zone.len())
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
    async fn answers(&self, name: &str, kind: &str) -> Result<Vec<Value>, String> {
        let response = self
            .client
            .get(&self.endpoint)
            .header("Accept", "application/dns-json")
            .query(&[("name", name), ("type", kind)])
            .send()
            .await
            .map_err(|_| "Could not check public DNS propagation.".to_owned())?;
        if !response.status().is_success() {
            return Ok(Vec::new());
        }
        let body: Value = response
            .json()
            .await
            .map_err(|_| "Invalid public DNS response.".to_owned())?;
        if body["Status"] != 0 {
            return Ok(Vec::new());
        }
        Ok(body["Answer"].as_array().cloned().unwrap_or_default())
    }
    pub async fn visible(&self, record: &ChallengeRecord) -> Result<bool, String> {
        // Public recursive DNS must see the TXT value before asking the CA to validate.
        Ok(self
            .answers(&record.name, "TXT")
            .await?
            .iter()
            .any(|answer| {
                answer["type"] == 16
                    && answer["data"]
                        .as_str()
                        .is_some_and(|value| value.trim_matches('"') == record.value)
            }))
    }
    /// The CNAME target of `name` in public DNS, without the trailing dot.
    pub async fn cname(&self, name: &str) -> Result<Option<String>, String> {
        Ok(self
            .answers(name, "CNAME")
            .await?
            .iter()
            .find(|answer| answer["type"] == 5)
            .and_then(|answer| answer["data"].as_str())
            .map(|target| target.trim_end_matches('.').to_ascii_lowercase()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(provider: &str, fields: &[(&str, &str)]) -> Settings {
        Settings {
            provider: provider.into(),
            credentials: fields
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        }
    }

    #[test]
    fn settings_require_known_providers_and_exact_fields() {
        assert!(settings("route53", &[("token", "x")]).validate().is_err());
        assert!(settings("hetzner", &[]).validate().is_err());
        assert!(settings("hetzner", &[("token", "x"), ("extra", "y")])
            .validate()
            .is_err());
        assert!(settings("hetzner", &[("token", "with space")])
            .validate()
            .is_err());
        let mut trimmed = settings("hetzner", &[("token", "  abc \n")]);
        trimmed.validate().unwrap();
        assert_eq!(trimmed.get("token"), "abc");
        assert!(settings("porkbun", &[("api_key", "pk1_a")])
            .validate()
            .is_err());
    }

    #[test]
    fn summaries_and_catalog_never_contain_secrets() {
        let mut porkbun = settings(
            "porkbun",
            &[("api_key", "pk1_public"), ("secret_key", "sk1_private")],
        );
        let provider = Provider::new(&mut porkbun, None).unwrap();
        let summary = provider.summary().to_string();
        assert!(summary.contains("pk1_public") && !summary.contains("sk1_private"));
        assert!(!catalog().to_string().contains("sk1_private"));
        assert_eq!(provider.backup_secret().0, "dns_provider");
        validate_backup(&provider.backup_secret().1).unwrap();
        assert!(
            validate_backup(r#"{"provider":"cloudflare","credentials":{"token":"x"}}"#).is_err()
        );
    }

    #[test]
    fn zones_match_on_label_boundaries() {
        let zones = ["example.com", "sub.example.com", "ample.com"];
        assert_eq!(
            closest_zone("a.sub.example.com", zones),
            Some("sub.example.com")
        );
        assert_eq!(closest_zone("Example.com", zones), Some("example.com"));
        assert_eq!(closest_zone("notexample.com", ["example.com"]), None);
        assert_eq!(
            relative("_acme-challenge.www.example.com", "example.com"),
            Some("_acme-challenge.www")
        );
        assert_eq!(relative("example.com", "example.com"), None);
    }
}

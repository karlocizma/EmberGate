use crate::{
    certificates::{Certificate, CertificateInput, CertificateStore, StoredCertificate},
    dns::{ChallengeRecord, Propagation, Provider, Settings},
    state::{now, Shared},
};
use async_trait::async_trait;
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    OrderStatus, RetryPolicy,
};
use openssl::{
    asn1::Asn1Time,
    hash::{hash, MessageDigest},
};
use pingora::{server::ShutdownWatch, services::background::BackgroundService};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::sync::{Mutex, Notify};

#[derive(Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    #[default]
    Staging,
    Production,
}

/// How the certificate authority checks that EmberGate controls a name.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub enum Challenge {
    /// A TXT record created through the configured DNS provider. Required for wildcards.
    #[default]
    #[serde(rename = "dns-01")]
    Dns01,
    /// A token EmberGate serves itself on port 80; no DNS credentials needed.
    #[serde(rename = "http-01")]
    Http01,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateRequest {
    pub name: String,
    pub domains: Vec<String>,
    pub email: String,
    #[serde(default)]
    pub environment: Environment,
    pub auto_renew: bool,
    pub agree_to_terms: bool,
    #[serde(default)]
    pub challenge: Challenge,
}
impl CertificateRequest {
    pub fn validate(&mut self) -> Result<(), String> {
        self.name = self.name.trim().to_owned();
        self.email = self.email.trim().to_ascii_lowercase();
        if self.name.is_empty() || self.name.len() > 80 {
            return Err("Enter a certificate name of 1–80 characters.".into());
        }
        if !self.agree_to_terms {
            return Err("Agree to the certificate authority's subscriber agreement before requesting a certificate.".into());
        }
        let email_parts: Vec<_> = self.email.split('@').collect();
        if self.email.len() > 254
            || email_parts.len() != 2
            || email_parts[0].is_empty()
            || self
                .email
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
            || !valid_domain(email_parts[1], false)
        {
            return Err("Enter a valid contact email address.".into());
        }
        if self.domains.is_empty() || self.domains.len() > 20 {
            return Err("Request 1–20 DNS names per certificate.".into());
        }
        for domain in &mut self.domains {
            *domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
            if !valid_domain(domain, true) {
                return Err("Use full DNS names such as example.com or *.example.com. Use ASCII/punycode for international names.".into());
            }
        }
        self.domains.sort();
        self.domains.dedup();
        if self.challenge == Challenge::Http01 && self.domains.iter().any(|d| d.starts_with("*.")) {
            return Err("Wildcard names can only be validated through DNS. Choose DNS validation or list each name.".into());
        }
        Ok(())
    }
}
fn valid_domain(domain: &str, wildcard: bool) -> bool {
    let domain = if wildcard {
        domain.strip_prefix("*.").unwrap_or(domain)
    } else {
        domain
    };
    domain.len() <= 253
        && domain.contains('.')
        && domain.parse::<std::net::IpAddr>().is_err()
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ManagedOrder {
    pub id: String,
    pub name: String,
    pub domains: Vec<String>,
    pub email: String,
    pub environment: Environment,
    pub auto_renew: bool,
    pub status: String,
    pub phase: String,
    pub last_error: Option<String>,
    pub last_attempt: Option<u64>,
    pub renewed_at: Option<u64>,
    pub renew_at: Option<u64>,
    pub next_attempt: u64,
    pub failures: u32,
    #[serde(default)]
    pub pending_dns: Vec<ChallengeRecord>,
    #[serde(default)]
    pub challenge: Challenge,
}
impl ManagedOrder {
    fn summary(&self) -> Value {
        json!({"id":self.id,"name":self.name,"domains":self.domains,"email":self.email,
            "environment":self.environment,"auto_renew":self.auto_renew,"status":self.status,"phase":self.phase,
            "last_error":self.last_error,"last_attempt":self.last_attempt,"renewed_at":self.renewed_at,
            "renew_at":self.renew_at,"next_attempt":self.next_attempt,"cleanup_pending":!self.pending_dns.is_empty(),"challenge":self.challenge})
    }
}

// Account credentials and DNS recovery state are stored atomically with mode 0600.
pub fn secure_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let temporary = path.with_extension("tmp");
    let mut options = std::fs::OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(temporary, path)?;
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        if let Err(error) = std::fs::File::open(parent).and_then(|file| file.sync_all()) {
            log::warn!("ACME state saved, but directory sync failed: {error}");
        }
    }
    Ok(())
}

pub struct Acme {
    jobs: Mutex<Vec<ManagedOrder>>,
    path: PathBuf,
    provider: arc_swap::ArcSwapOption<Provider>,
    environment_token: bool,
    cloudflare_base: String,
    /// Overrides other providers' API address, for local fixtures.
    dns_api_base: Option<String>,
    propagation: Propagation,
    /// HTTP-01 tokens being validated: token → (domain, key authorization).
    http_challenges: std::sync::Mutex<HashMap<String, (String, String)>>,
    credential_operation: Mutex<()>,
    directory_override: Option<String>,
    ca_root: Option<PathBuf>,
    propagation_timeout: Duration,
    wake: Notify,
}
impl Acme {
    pub(crate) fn backup_secret(&self) -> Option<(String, String)> {
        self.provider.load().as_ref().map(|p| p.backup_secret())
    }
    pub async fn backup_guard(
        &self,
    ) -> Result<
        (
            tokio::sync::MutexGuard<'_, ()>,
            tokio::sync::MutexGuard<'_, Vec<ManagedOrder>>,
        ),
        String,
    > {
        let operation = self.credential_operation.try_lock().map_err(|_| {
            "Certificate issuance or DNS cleanup is running. Retry once it finishes.".to_owned()
        })?;
        let jobs = self.jobs.lock().await;
        Ok((operation, jobs))
    }

    #[cfg(test)]
    pub fn disabled(data: &Path) -> Self {
        Self {
            jobs: Mutex::new(Vec::new()),
            path: data.join("acme.json"),
            provider: arc_swap::ArcSwapOption::empty(),
            environment_token: false,
            cloudflare_base: "https://api.cloudflare.com/client/v4".into(),
            dns_api_base: None,
            propagation: Propagation::new("https://cloudflare-dns.com/dns-query".into()).unwrap(),
            http_challenges: Default::default(),
            credential_operation: Mutex::new(()),
            directory_override: None,
            ca_root: None,
            propagation_timeout: Duration::from_secs(300),
            wake: Notify::new(),
        }
    }
    pub fn load(data: &Path, stored: Option<Settings>) -> Result<Self, Box<dyn std::error::Error>> {
        let environment_token = match std::env::var("GATEWAY_CLOUDFLARE_API_TOKEN_FILE")
            .ok()
            .filter(|p| !p.is_empty())
        {
            Some(path) => Some(std::fs::read_to_string(path)?.trim().to_owned()),
            None => std::env::var("GATEWAY_CLOUDFLARE_API_TOKEN")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .map(|s| s.trim().to_owned()),
        };
        let overridden = environment_token.is_some();
        let settings = environment_token.map(Settings::cloudflare).or(stored);
        let path = data.join("acme.json");
        let mut jobs: Vec<ManagedOrder> = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(error.into()),
        };
        for job in &mut jobs {
            let mut input = CertificateRequest {
                name: job.name.clone(),
                domains: job.domains.clone(),
                email: job.email.clone(),
                environment: job.environment,
                auto_renew: job.auto_renew,
                agree_to_terms: true,
                challenge: job.challenge,
            };
            input.validate().map_err(std::io::Error::other)?;
            if uuid::Uuid::parse_str(&job.id).is_err()
                || !["queued", "issuing", "ready", "error"].contains(&job.status.as_str())
                || job.pending_dns.iter().any(|record| {
                    !owned_dns_comment(&record.comment, &job.id)
                        || !job.domains.iter().any(|domain| {
                            record.name
                                == format!(
                                    "_acme-challenge.{}",
                                    domain.strip_prefix("*.").unwrap_or(domain)
                                )
                        })
                        || record.zone.is_empty()
                        || record.zone.len() > 253
                        || !record
                            .zone
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || b"-._".contains(&byte))
                        || record.value.is_empty()
                        || record.value.len() > 255
                })
            {
                return Err("Invalid persisted ACME request or DNS recovery record.".into());
            }
            job.name = input.name;
            job.domains = input.domains;
            job.email = input.email;
            if job.status == "issuing" {
                job.status = "queued".into();
                job.phase = "Recovering interrupted request".into();
                job.next_attempt = now() + 60;
            }
        }
        let mut ids = std::collections::HashSet::new();
        let mut domains = std::collections::HashSet::new();
        if jobs.len() > 50
            || jobs.iter().any(|job| {
                !ids.insert(job.id.clone())
                    || job
                        .domains
                        .iter()
                        .any(|domain| !domains.insert(domain.clone()))
            })
        {
            return Err("Duplicate or excessive persisted ACME requests.".into());
        }
        let cloudflare_base = std::env::var("GATEWAY_CLOUDFLARE_API_BASE")
            .unwrap_or_else(|_| "https://api.cloudflare.com/client/v4".into());
        let dns_endpoint = std::env::var("GATEWAY_DNS_CHECK_URL")
            .unwrap_or_else(|_| "https://cloudflare-dns.com/dns-query".into());
        let dns_api_base = std::env::var("GATEWAY_DNS_API_BASE")
            .ok()
            .filter(|base| !base.is_empty());
        let provider = Self::make_provider(settings, &cloudflare_base, dns_api_base.as_deref())?;
        let seconds: u64 = std::env::var("GATEWAY_DNS_PROPAGATION_TIMEOUT")
            .unwrap_or_else(|_| "300".into())
            .parse()?;
        if !(5..=1800).contains(&seconds) {
            return Err("GATEWAY_DNS_PROPAGATION_TIMEOUT must be 5–1800 seconds.".into());
        }
        Ok(Self {
            jobs: Mutex::new(jobs),
            path,
            provider: arc_swap::ArcSwapOption::from(provider),
            environment_token: overridden,
            cloudflare_base,
            dns_api_base,
            propagation: Propagation::new(dns_endpoint)?,
            http_challenges: Default::default(),
            credential_operation: Mutex::new(()),
            directory_override: std::env::var("GATEWAY_ACME_DIRECTORY").ok(),
            ca_root: std::env::var("GATEWAY_ACME_CA_ROOT")
                .ok()
                .map(PathBuf::from),
            propagation_timeout: Duration::from_secs(seconds),
            wake: Notify::new(),
        })
    }
    fn make_provider(
        settings: Option<Settings>,
        cloudflare_base: &str,
        dns_api_base: Option<&str>,
    ) -> Result<Option<Arc<Provider>>, String> {
        let Some(mut settings) = settings else {
            return Ok(None);
        };
        if settings.provider == "cloudflare"
            && settings
                .credentials
                .get("token")
                .is_none_or(|t| t.is_empty())
        {
            return Ok(None);
        }
        let base = if settings.provider == "cloudflare" {
            Some(cloudflare_base)
        } else {
            dns_api_base
        };
        Provider::new(&mut settings, base).map(|provider| Some(Arc::new(provider)))
    }
    pub fn credential_status(&self) -> Value {
        let provider = self.provider.load();
        json!({"configured":self.configured(),"source":if self.environment_token {"environment"}else if self.configured(){"database"}else{"none"},"editable":!self.environment_token,
            "provider":provider.as_ref().map(|p|p.id()),"provider_name":provider.as_ref().map(|p|p.name()),"settings":provider.as_ref().map(|p|p.summary()),"providers":crate::dns::catalog()})
    }
    /// Saves or replaces the Cloudflare token; `None` removes the provider.
    pub async fn save_token(
        &self,
        control: &crate::management::Control,
        token: Option<String>,
    ) -> Result<(), String> {
        let token = token.map(|s| s.trim().to_owned());
        if token.as_ref().is_some_and(|s| s.is_empty()) {
            return Err("Enter a token, or use Remove token to clear the saved credential.".into());
        }
        self.save_provider(control, token.map(Settings::cloudflare))
            .await
    }
    /// Saves the DNS provider used for DNS-01 challenges; `None` removes it.
    /// Blank secret fields keep the saved values when the provider is unchanged.
    pub async fn save_provider(
        &self,
        control: &crate::management::Control,
        settings: Option<Settings>,
    ) -> Result<(), String> {
        if self.environment_token {
            return Err("Cloudflare credentials are overridden by the environment. Remove GATEWAY_CLOUDFLARE_API_TOKEN and GATEWAY_CLOUDFLARE_API_TOKEN_FILE and restart to manage them here.".into());
        }
        let _guard=self.credential_operation.try_lock().map_err(|_|"Certificate issuance or DNS cleanup is running. Wait for it to finish before changing credentials.".to_owned())?;
        let current = self
            .provider
            .load_full()
            .map(|provider| provider.settings());
        let mut settings = settings;
        if let (Some(settings), Some(current)) = (&mut settings, &current) {
            // A saved secret is only reused for the same destination, so changing
            // the server cannot send it somewhere new.
            let same_server = !["acme-dns", "rfc2136"].contains(&current.provider.as_str())
                || settings.credentials.get("server").map(|v| v.trim())
                    == current.credentials.get("server").map(String::as_str);
            if settings.provider == current.provider && same_server {
                for (key, value) in &current.credentials {
                    let entry = settings.credentials.entry(key.clone()).or_default();
                    if entry.trim().is_empty() {
                        *entry = value.clone();
                    }
                }
            }
        }
        let provider = Self::make_provider(
            settings,
            &self.cloudflare_base,
            self.dns_api_base.as_deref(),
        )?;
        let changes_provider = provider.as_ref().map(|p| p.settings().provider)
            != current.map(|current| current.provider);
        if changes_provider
            && self
                .jobs
                .lock()
                .await
                .iter()
                .any(|job| !job.pending_dns.is_empty())
        {
            return Err(
                "DNS cleanup is pending. Keep the current provider configured until cleanup completes."
                    .into(),
            );
        }
        let secret = provider.as_ref().map(|provider| provider.backup_secret());
        control
            .run(move |db| {
                let tx = db
                    .transaction()
                    .map_err(|_| "Could not save DNS credentials.".to_owned())?;
                tx.execute(
                    "DELETE FROM secrets WHERE key IN ('cloudflare_token','dns_provider')",
                    [],
                )
                .map_err(|_| "Could not save DNS credentials.".to_owned())?;
                if let Some((key, value)) = secret {
                    tx.execute(
                        "INSERT INTO secrets VALUES(?1,?2)",
                        rusqlite::params![key, value],
                    )
                    .map_err(|_| "Could not save DNS credentials.".to_owned())?;
                }
                tx.commit()
                    .map_err(|_| "Could not save DNS credentials.".to_owned())
            })
            .await?;
        self.provider.store(provider);
        self.wake.notify_one();
        Ok(())
    }
    /// Whether a DNS provider is configured for DNS-01 challenges.
    pub fn configured(&self) -> bool {
        self.provider.load().is_some()
    }
    /// Whether a request using this challenge can run now.
    fn can_validate(&self, challenge: Challenge) -> bool {
        challenge == Challenge::Http01 || self.configured()
    }
    pub async fn status(&self) -> Value {
        let provider = self.provider.load();
        json!({"configured":self.configured(),"provider":provider.as_ref().map(|p|p.id()),"provider_name":provider.as_ref().map(|p|p.name()),
            "challenges":["http-01","dns-01"],"terms_url":"https://letsencrypt.org/repository/",
            "orders":self.jobs.lock().await.iter().map(ManagedOrder::summary).collect::<Vec<_>>()})
    }
    /// Answers the certificate authority's HTTP-01 request for a token being validated.
    pub fn http_challenge(&self, host: &str, path: &str) -> Option<String> {
        let token = path.strip_prefix("/.well-known/acme-challenge/")?;
        let challenges = self.http_challenges.lock().ok()?;
        let (domain, key) = challenges.get(token)?;
        (domain == host).then(|| key.clone())
    }
    pub async fn manages(&self, id: &str) -> bool {
        self.jobs.lock().await.iter().any(|job| job.id == id)
    }
    pub async fn reserved_domains(&self) -> Vec<String> {
        self.jobs
            .lock()
            .await
            .iter()
            .flat_map(|job| job.domains.clone())
            .collect()
    }
    async fn edit<R, F>(&self, change: F) -> Result<R, String>
    where
        F: FnOnce(&mut Vec<ManagedOrder>) -> Result<R, String>,
    {
        let mut jobs = self.jobs.lock().await;
        let mut next = jobs.clone();
        let result = change(&mut next)?;
        let bytes = serde_json::to_vec_pretty(&next)
            .map_err(|_| "Could not encode ACME state.".to_owned())?;
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || secure_write(&path, &bytes))
            .await
            .map_err(|_| "Could not save ACME state.".to_owned())?
            .map_err(|_| "Could not save ACME state.".to_owned())?;
        *jobs = next;
        Ok(result)
    }
    pub async fn request(
        &self,
        mut request: CertificateRequest,
        state: &Shared,
    ) -> Result<Value, String> {
        request.validate()?;
        if !self.can_validate(request.challenge) {
            return Err(
                "Configure a DNS provider before requesting DNS-validated certificates, or choose HTTP validation."
                    .into(),
            );
        }
        // Serialize registration with certificate uploads so a duplicate cannot slip in.
        let _guard = state.write_lock.lock().await;
        if state.certificates.load().certificates.iter().any(|cert| {
            cert.domains
                .iter()
                .any(|domain| request.domains.contains(domain))
        }) {
            return Err("An uploaded certificate already covers one of these exact DNS names. Remove it before requesting automatic management.".into());
        }
        let job = ManagedOrder {
            id: uuid::Uuid::new_v4().to_string(),
            name: request.name,
            domains: request.domains,
            email: request.email,
            environment: request.environment,
            auto_renew: request.auto_renew,
            status: "queued".into(),
            phase: "Waiting to issue".into(),
            last_error: None,
            last_attempt: None,
            renewed_at: None,
            renew_at: None,
            next_attempt: now(),
            failures: 0,
            pending_dns: Vec::new(),
            challenge: request.challenge,
        };
        let summary = job.summary();
        self.edit(|jobs| {
            if jobs.len() >= 50 {
                return Err("A maximum of 50 managed certificates is supported.".into());
            }
            if jobs.iter().any(|old| {
                old.domains
                    .iter()
                    .any(|domain| job.domains.contains(domain))
            }) {
                return Err("An automatic request already manages one of these DNS names.".into());
            }
            jobs.push(job);
            Ok(())
        })
        .await?;
        self.wake.notify_one();
        Ok(summary)
    }
    pub async fn renew(&self, id: &str) -> Result<(), String> {
        let dns_ready = self.configured();
        self.edit(|jobs| {
            let job = jobs
                .iter_mut()
                .find(|job| job.id == id)
                .ok_or("Certificate request not found.")?;
            if job.challenge == Challenge::Dns01 && !dns_ready {
                return Err("Configure the DNS provider first.".into());
            }
            if job.status == "issuing" || job.status == "queued" {
                return Err("This request is already in progress.".into());
            }
            job.status = "queued".into();
            job.phase = "Renewal queued".into();
            job.next_attempt = now();
            Ok(())
        })
        .await?;
        self.wake.notify_one();
        Ok(())
    }
    pub async fn remove(&self, id: &str) -> Result<(), String> {
        self.edit(|jobs| {
            let job = jobs
                .iter()
                .find(|job| job.id == id)
                .ok_or("Certificate request not found.")?;
            if job.status == "issuing" || !job.pending_dns.is_empty() {
                return Err(
                    "Wait until issuance and DNS cleanup finish before stopping management.".into(),
                );
            }
            jobs.retain(|job| job.id != id);
            Ok(())
        })
        .await
    }
    pub async fn production(&self, id: &str, agree_to_terms: bool) -> Result<(), String> {
        if !agree_to_terms {
            return Err(
                "Agree to the subscriber agreement before requesting production certificates."
                    .into(),
            );
        }
        let dns_ready = self.configured();
        self.edit(|jobs| {
            let job = jobs
                .iter_mut()
                .find(|job| job.id == id)
                .ok_or("Certificate request not found.")?;
            if job.challenge == Challenge::Dns01 && !dns_ready {
                return Err("Configure the DNS provider first.".into());
            }
            if job.environment != Environment::Staging
                || job.status != "ready"
                || !job.pending_dns.is_empty()
            {
                return Err(
                    "Complete the staging request and DNS cleanup before switching to production."
                        .into(),
                );
            }
            job.environment = Environment::Production;
            job.status = "queued".into();
            job.phase = "Production certificate queued".into();
            job.next_attempt = now();
            job.last_error = None;
            job.failures = 0;
            Ok(())
        })
        .await?;
        self.wake.notify_one();
        Ok(())
    }
    async fn phase(&self, id: &str, phase: &str) -> Result<(), String> {
        self.edit(|jobs| {
            let job = jobs
                .iter_mut()
                .find(|job| job.id == id)
                .ok_or("Request no longer exists.")?;
            job.phase = phase.to_owned();
            Ok(())
        })
        .await
    }
    async fn cleanup(&self, id: &str) -> Result<(), String> {
        let records = self
            .jobs
            .lock()
            .await
            .iter()
            .find(|job| job.id == id)
            .ok_or("Request no longer exists.")?
            .pending_dns
            .clone();
        if records.is_empty() {
            return Ok(());
        }
        let provider = self
            .provider
            .load_full()
            .ok_or("The DNS provider is not configured.")?;
        let mut failed = false;
        for record in records {
            if provider.cleanup(&record).await.is_err() {
                failed = true;
                continue;
            }
            self.edit(|jobs| {
                let job = jobs
                    .iter_mut()
                    .find(|job| job.id == id)
                    .ok_or("Request no longer exists.")?;
                job.pending_dns.retain(|old| {
                    old.zone != record.zone
                        || old.name != record.name
                        || old.value != record.value
                        || old.comment != record.comment
                });
                Ok(())
            })
            .await?;
        }
        if failed {
            Err("DNS cleanup is pending; the gateway will retry without deleting unrelated records.".into())
        } else {
            Ok(())
        }
    }
    async fn account(&self, job: &ManagedOrder) -> Result<Account, String> {
        let directory = self
            .directory_override
            .clone()
            .unwrap_or_else(|| match job.environment {
                Environment::Staging => LetsEncrypt::Staging.url().to_owned(),
                Environment::Production => LetsEncrypt::Production.url().to_owned(),
            });
        let digest = hash(
            MessageDigest::sha256(),
            format!("{}:{}", directory, job.email).as_bytes(),
        )
        .map_err(|_| "Could not identify ACME account.")?;
        let filename = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let path = self
            .path
            .with_file_name(format!("acme-account-{filename}.json"));
        let builder = match &self.ca_root {
            Some(root) => Account::builder_with_root(root),
            None => Account::builder(),
        }
        .map_err(|error| format!("Could not initialize ACME: {error}"))?;
        match std::fs::read(&path) {
            Ok(bytes) => builder
                .from_credentials(
                    serde_json::from_slice(&bytes)
                        .map_err(|_| "Could not read the saved ACME account.")?,
                )
                .await
                .map_err(|error| format!("Could not restore ACME account: {error}")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let contact = format!("mailto:{}", job.email);
                let (account, credentials) = builder
                    .create(
                        &NewAccount {
                            contact: &[contact.as_str()],
                            terms_of_service_agreed: true,
                            only_return_existing: false,
                        },
                        directory,
                        None,
                    )
                    .await
                    .map_err(|error| format!("Could not create ACME account: {error}"))?;
                let bytes = serde_json::to_vec_pretty(&credentials)
                    .map_err(|_| "Could not encode ACME account.")?;
                tokio::task::spawn_blocking(move || secure_write(&path, &bytes))
                    .await
                    .map_err(|_| "Could not save ACME account.")?
                    .map_err(|_| "Could not save ACME account.")?;
                Ok(account)
            }
            Err(_) => Err("Could not read the saved ACME account.".into()),
        }
    }
    async fn issue(&self, job: &ManagedOrder) -> Result<CertificateInput, String> {
        let provider = match job.challenge {
            Challenge::Dns01 => Some(
                self.provider
                    .load_full()
                    .ok_or("The DNS provider is not configured.")?,
            ),
            Challenge::Http01 => None,
        };
        if let Some(provider) = &provider {
            if job.domains.len() > provider.name_limit() {
                return Err(format!(
                    "{} validates at most {} names per certificate. Split this certificate.",
                    provider.name(),
                    provider.name_limit()
                ));
            }
        }
        // Tokens stop being served however issuance ends.
        let mut http_tokens = HttpTokens {
            acme: self,
            tokens: Vec::new(),
        };
        self.phase(&job.id, "Connecting to the certificate authority")
            .await?;
        let account = self.account(job).await?;
        let identifiers = job
            .domains
            .iter()
            .cloned()
            .map(Identifier::Dns)
            .collect::<Vec<_>>();
        let mut order = account
            .new_order(&NewOrder::new(&identifiers))
            .await
            .map_err(|error| format!("Could not create ACME order: {error}"))?;
        let mut authorizations = order.authorizations();
        while let Some(authorization) = authorizations.next().await {
            let mut authorization = authorization
                .map_err(|error| format!("Could not read ACME authorization: {error}"))?;
            if authorization.status == AuthorizationStatus::Valid {
                continue;
            }
            if authorization.status != AuthorizationStatus::Pending {
                return Err("The certificate authority rejected a domain authorization.".into());
            }
            let Some(provider) = &provider else {
                let mut challenge = authorization
                    .challenge(ChallengeType::Http01)
                    .ok_or("The certificate authority did not offer HTTP-01 validation.")?;
                let domain = challenge.identifier().to_string();
                self.phase(
                    &job.id,
                    "Waiting for the certificate authority to reach port 80",
                )
                .await?;
                http_tokens.serve(
                    challenge.token.clone(),
                    domain,
                    challenge.key_authorization().as_str().to_owned(),
                );
                challenge
                    .set_ready()
                    .await
                    .map_err(|error| format!("HTTP validation request failed: {error}"))?;
                continue;
            };
            let mut challenge = authorization
                .challenge(ChallengeType::Dns01)
                .ok_or("The certificate authority did not offer DNS-01 validation.")?;
            let domain = challenge.identifier().to_string();
            let domain = domain.strip_prefix("*.").unwrap_or(&domain);
            self.phase(
                &job.id,
                &format!("Preparing {} DNS challenge", provider.name()),
            )
            .await?;
            let record = ChallengeRecord {
                zone: provider.zone_for(domain).await?,
                name: format!("_acme-challenge.{domain}"),
                value: challenge.key_authorization().dns_value(),
                comment: format!("EmberGate ACME {}", job.id),
            };
            provider
                .check_delegation(&record, &self.propagation)
                .await?;
            // Persist intent BEFORE the API write so process crashes can recover ownership.
            self.edit(|jobs| {
                jobs.iter_mut()
                    .find(|old| old.id == job.id)
                    .ok_or("Request no longer exists.")?
                    .pending_dns
                    .push(record.clone());
                Ok(())
            })
            .await?;
            provider.present(&record).await?;
            self.phase(&job.id, "Waiting for public DNS propagation")
                .await?;
            let deadline = tokio::time::Instant::now() + self.propagation_timeout;
            loop {
                if self.propagation.visible(&record).await.unwrap_or(false) {
                    break;
                }
                if tokio::time::Instant::now() >= deadline {
                    return Err(format!(
                        "DNS propagation timed out for {}. Check authoritative DNS and retry.",
                        record.name
                    ));
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
            challenge
                .set_ready()
                .await
                .map_err(|error| format!("DNS validation request failed: {error}"))?;
        }
        self.phase(&job.id, "Validating domains and issuing certificate")
            .await?;
        let retry = RetryPolicy::new().timeout(Duration::from_secs(300));
        if order
            .poll_ready(&retry)
            .await
            .map_err(|error| format!("Domain validation failed: {error}"))?
            != OrderStatus::Ready
        {
            return Err("The certificate authority did not approve this order.".into());
        }
        let private_key_pem = order
            .finalize()
            .await
            .map_err(|error| format!("Could not finalize certificate: {error}"))?;
        let certificate_pem = order
            .poll_certificate(&retry)
            .await
            .map_err(|error| format!("Could not download certificate: {error}"))?;
        drop(http_tokens);
        Ok(CertificateInput {
            name: job.name.clone(),
            certificate_pem,
            private_key_pem,
        })
    }
    async fn install(
        &self,
        state: &Shared,
        job: &ManagedOrder,
        input: CertificateInput,
    ) -> Result<u64, String> {
        let cert = Certificate::parse(
            StoredCertificate {
                id: job.id.clone(),
                input,
            },
            true,
        )?;
        if cert.domains != job.domains {
            return Err("The issued certificate does not match the requested DNS names.".into());
        }
        let renew_at = renewal_time(&cert)?;
        let _guard = state.write_lock.lock().await;
        let mut records = state.certificates.load().records();
        records.retain(|old| old.id != job.id);
        records.push(cert.stored);
        let store = CertificateStore::parse(records)?;
        let path = state.certificates_path.clone();
        let store = tokio::task::spawn_blocking(move || store.persist(&path).map(|_| store))
            .await
            .map_err(|_| "Could not activate the certificate.")?
            .map_err(|_| "Could not save the issued certificate.")?;
        state.certificates.store(Arc::new(store));
        Ok(renew_at)
    }
    async fn run_job(&self, state: &Shared, job: ManagedOrder) -> Result<(), String> {
        let _credential_guard = self.credential_operation.lock().await;
        if state
            .backups
            .pending
            .load(std::sync::atomic::Ordering::SeqCst)
            || crate::cluster::follower(state)
            || !self.can_validate(job.challenge)
        {
            return Ok(());
        }
        self.edit(|jobs| {
            let old = jobs
                .iter_mut()
                .find(|old| old.id == job.id)
                .ok_or("Request no longer exists.")?;
            old.status = "issuing".into();
            old.phase = "Preparing certificate request".into();
            old.last_attempt = Some(now());
            Ok(())
        })
        .await?;
        let cleanup_only = job.status == "ready" && !job.pending_dns.is_empty();
        let result = async {
            self.cleanup(&job.id).await?;
            if cleanup_only {
                return Ok(job.renew_at.unwrap_or(now()));
            }
            let input = tokio::time::timeout(Duration::from_secs(2400), self.issue(&job))
                .await
                .map_err(|_| "Certificate request timed out.".to_owned())??;
            self.install(state, &job, input).await
        }
        .await;
        let cleanup = self.cleanup(&job.id).await;
        self.edit(|jobs| {
            let old = jobs
                .iter_mut()
                .find(|old| old.id == job.id)
                .ok_or("Request no longer exists.")?;
            match result {
                Ok(renew_at) => {
                    old.status = "ready".into();
                    old.phase = if cleanup.is_ok() {
                        "Certificate active"
                    } else {
                        "Certificate active; DNS cleanup pending"
                    }
                    .into();
                    old.last_error = cleanup.err();
                    old.renew_at = Some(renew_at);
                    if !cleanup_only {
                        old.renewed_at = Some(now());
                    }
                    old.failures = 0;
                    old.next_attempt = if old.pending_dns.is_empty() {
                        renew_at
                    } else {
                        now() + 3600
                    };
                }
                Err(error) => {
                    old.status = "error".into();
                    old.phase = "Request failed; retry scheduled".into();
                    old.failures = old.failures.saturating_add(1);
                    old.last_error = Some(error.chars().take(600).collect());
                    old.next_attempt = now() + retry_delay(old.failures);
                }
            }
            Ok(())
        })
        .await
    }
}
/// HTTP-01 tokens served while one request is validated; removed when dropped.
struct HttpTokens<'a> {
    acme: &'a Acme,
    tokens: Vec<String>,
}
impl HttpTokens<'_> {
    fn serve(&mut self, token: String, domain: String, key: String) {
        if let Ok(mut challenges) = self.acme.http_challenges.lock() {
            challenges.insert(token.clone(), (domain, key));
            self.tokens.push(token);
        }
    }
}
impl Drop for HttpTokens<'_> {
    fn drop(&mut self) {
        if let Ok(mut challenges) = self.acme.http_challenges.lock() {
            for token in &self.tokens {
                challenges.remove(token);
            }
        }
    }
}
// Older jobs must retain their exact ownership marker so DNS recovery survives a rebrand.
fn owned_dns_comment(comment: &str, id: &str) -> bool {
    comment == format!("EmberGate ACME {id}") || comment == format!("Current ACME {id}")
}
fn retry_delay(failures: u32) -> u64 {
    3600 * 2u64.pow(failures.saturating_sub(1).min(4))
}
fn renewal_time(cert: &Certificate) -> Result<u64, String> {
    let leaf = &cert.chain[0];
    let lifetime = leaf
        .not_before()
        .diff(leaf.not_after())
        .map_err(|_| "Invalid certificate dates.")?;
    let remaining = Asn1Time::days_from_now(0)
        .map_err(|_| "Could not read current time.")?
        .diff(leaf.not_after())
        .map_err(|_| "Invalid expiry date.")?;
    let lifetime = (i64::from(lifetime.days) * 86400 + i64::from(lifetime.secs)).max(1) as u64;
    let remaining = (i64::from(remaining.days) * 86400 + i64::from(remaining.secs)).max(0) as u64;
    Ok(now() + remaining.saturating_sub((lifetime / 3).min(30 * 86400)))
}

pub struct CertificateAutomation(pub Shared);
#[async_trait]
impl BackgroundService for CertificateAutomation {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let state = &self.0;
        let acme = &state.acme;
        loop {
            if *shutdown.borrow() {
                break;
            }
            let job = if !state
                .backups
                .pending
                .load(std::sync::atomic::Ordering::SeqCst)
                && !crate::cluster::follower(state)
            {
                acme.jobs
                    .lock()
                    .await
                    .iter()
                    .find(|job| {
                        if !acme.can_validate(job.challenge) {
                            return false;
                        }
                        let missing = !state
                            .certificates
                            .load()
                            .certificates
                            .iter()
                            .any(|cert| cert.stored.id == job.id);
                        (job.next_attempt <= now()
                            && (job.status == "queued"
                                || job.status == "error"
                                || !job.pending_dns.is_empty()
                                || (job.status == "ready" && job.auto_renew)))
                            || (job.status == "ready" && job.auto_renew && missing)
                            || (job.status == "issuing"
                                && job
                                    .last_attempt
                                    .is_some_and(|time| time.saturating_add(60) <= now()))
                    })
                    .cloned()
            } else {
                None
            };
            if let Some(job) = job {
                tokio::select! {
                    result=acme.run_job(state,job)=>{if let Err(error)=result{log::error!("Certificate automation could not save state: {error}");tokio::time::sleep(Duration::from_secs(60)).await;}},
                    _=shutdown.changed()=>{break;}
                }
                continue;
            }
            tokio::select! {_=acme.wake.notified()=>{},_=tokio::time::sleep(Duration::from_secs(60))=>{},_=shutdown.changed()=>break}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> CertificateRequest {
        CertificateRequest {
            name: "Test".into(),
            domains: vec!["Example.COM".into(), "*.example.com".into()],
            email: "admin@example.com".into(),
            environment: Environment::Staging,
            auto_renew: true,
            agree_to_terms: true,
            challenge: Challenge::Dns01,
        }
    }
    #[test]
    fn domains_and_consent_are_validated() {
        let mut input = request();
        input.validate().unwrap();
        assert_eq!(input.domains, vec!["*.example.com", "example.com"]);
        for bad in [
            "localhost",
            "127.0.0.1",
            "https://example.com",
            "a.*.example.com",
            "-bad.example.com",
        ] {
            let mut input = request();
            input.domains = vec![bad.into()];
            assert!(input.validate().is_err());
        }
        let mut input = request();
        input.agree_to_terms = false;
        assert!(input.validate().is_err());
    }
    #[test]
    fn http_validation_refuses_wildcards_and_answers_only_its_own_host() {
        let mut input = request();
        input.challenge = Challenge::Http01;
        assert!(input.validate().unwrap_err().contains("Wildcard"));
        input.domains = vec!["example.com".into(), "www.example.com".into()];
        input.validate().unwrap();
        let path = std::env::temp_dir().join(format!("http01-test-{}", uuid::Uuid::new_v4()));
        let acme = Acme::disabled(&path);
        assert!(acme.can_validate(Challenge::Http01) && !acme.can_validate(Challenge::Dns01));
        let mut tokens = HttpTokens {
            acme: &acme,
            tokens: Vec::new(),
        };
        tokens.serve("tok".into(), "example.com".into(), "tok.key".into());
        assert_eq!(
            acme.http_challenge("example.com", "/.well-known/acme-challenge/tok")
                .as_deref(),
            Some("tok.key")
        );
        assert!(acme
            .http_challenge("other.example", "/.well-known/acme-challenge/tok")
            .is_none());
        assert!(acme
            .http_challenge("example.com", "/.well-known/acme-challenge/other")
            .is_none());
        assert!(acme.http_challenge("example.com", "/tok").is_none());
        drop(tokens);
        assert!(acme
            .http_challenge("example.com", "/.well-known/acme-challenge/tok")
            .is_none());
    }
    #[test]
    fn retries_back_off_instead_of_looping() {
        assert_eq!(retry_delay(1), 3600);
        assert_eq!(retry_delay(9), 57600);
    }
    #[tokio::test]
    async fn web_token_rotation_changes_live_dns_authorization_and_respects_operation_lock() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let path = std::env::temp_dir().join(format!("credential-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&path).unwrap();
        let control = crate::management::Control::open(&path.join("management.sqlite3")).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut acme = Acme::disabled(&path);
        acme.cloudflare_base = format!("http://{}", listener.local_addr().unwrap());
        let receiver = tokio::spawn(async move {
            for token in ["first-private-token", "second-private-token"] {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut chunk = [0u8; 1024];
                while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                    let count = socket.read(&mut chunk).await.unwrap();
                    assert!(count > 0);
                    request.extend_from_slice(&chunk[..count]);
                }
                let request = String::from_utf8(request).unwrap().to_ascii_lowercase();
                assert!(request.contains(&format!("authorization: bearer {token}")));
                let body = r#"{"success":true,"result":[{"id":"local-zone"}]}"#;
                socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
            }
        });
        acme.save_token(&control, Some("first-private-token".into()))
            .await
            .unwrap();
        assert_eq!(
            acme.provider
                .load_full()
                .unwrap()
                .zone_for("example.test")
                .await
                .unwrap(),
            "local-zone"
        );
        let guard = acme.credential_operation.lock().await;
        assert!(acme
            .save_token(&control, Some("not-applied".into()))
            .await
            .is_err());
        drop(guard);
        assert_eq!(
            control.secret("cloudflare_token").unwrap().as_deref(),
            Some("first-private-token")
        );
        acme.save_token(&control, Some("second-private-token".into()))
            .await
            .unwrap();
        assert_eq!(
            acme.provider
                .load_full()
                .unwrap()
                .zone_for("example.test")
                .await
                .unwrap(),
            "local-zone"
        );
        receiver.await.unwrap();
        assert!(!json!(acme.credential_status())
            .to_string()
            .contains("private-token"));
        acme.jobs.lock().await.push(ManagedOrder {
            id: uuid::Uuid::new_v4().to_string(),
            name: "Pending cleanup".into(),
            domains: vec!["example.test".into()],
            email: "admin@example.test".into(),
            environment: Environment::Staging,
            auto_renew: true,
            status: "error".into(),
            phase: "Cleanup pending".into(),
            last_error: None,
            last_attempt: None,
            renewed_at: None,
            renew_at: None,
            next_attempt: now(),
            failures: 1,
            pending_dns: vec![ChallengeRecord {
                zone: "local-zone".into(),
                name: "_acme-challenge.example.test".into(),
                value: "pending-challenge".into(),
                comment: "EmberGate ACME fixture".into(),
            }],
            challenge: Challenge::Dns01,
        });
        assert!(acme.save_token(&control, None).await.is_err());
        assert!(acme.configured());
        assert_eq!(
            control.secret("cloudflare_token").unwrap().as_deref(),
            Some("second-private-token")
        );
        acme.jobs.lock().await.clear();
        acme.save_token(&control, None).await.unwrap();
        assert!(!acme.configured());
        assert!(control.secret("cloudflare_token").unwrap().is_none());
        acme.environment_token = true;
        assert!(acme
            .save_token(&control, Some("ignored".into()))
            .await
            .is_err());
        std::fs::remove_dir_all(&path).unwrap();
    }
    #[tokio::test]
    async fn saved_secrets_are_not_sent_to_a_changed_server() {
        let path = std::env::temp_dir().join(format!("dns-secret-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&path).unwrap();
        let control = crate::management::Control::open(&path.join("management.sqlite3")).unwrap();
        let acme = Acme::disabled(&path);
        let settings = |server: &str, password: &str| Settings {
            provider: "acme-dns".into(),
            credentials: [
                ("server", server),
                ("username", "user"),
                ("password", password),
                ("subdomain", "abc"),
            ]
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect(),
        };
        acme.save_provider(
            &control,
            Some(settings("https://auth.example.net", "saved-secret")),
        )
        .await
        .unwrap();
        acme.save_provider(&control, Some(settings("https://auth.example.net", "")))
            .await
            .unwrap();
        assert!(acme
            .save_provider(&control, Some(settings("https://attacker.example", "")))
            .await
            .is_err());
        assert_eq!(
            acme.provider.load_full().unwrap().settings().credentials["password"],
            "saved-secret"
        );
        std::fs::remove_dir_all(&path).unwrap();
    }
    #[test]
    fn legacy_and_rebranded_dns_markers_keep_strict_job_ownership() {
        let id = uuid::Uuid::new_v4().to_string();
        assert!(owned_dns_comment(&format!("Current ACME {id}"), &id));
        assert!(owned_dns_comment(&format!("EmberGate ACME {id}"), &id));
        assert!(!owned_dns_comment("EmberGate ACME another-job", &id));
        assert!(!owned_dns_comment(
            &format!("EmberGate ACME {id} extra"),
            &id
        ));
    }
}

use crate::state::Shared;
use async_trait::async_trait;
use openssl::asn1::Asn1Time;
use pingora::{
    listeners::TlsAccept,
    tls::{
        hash::MessageDigest,
        pkey::{PKey, Private},
        ssl::{NameType, SslRef},
        x509::X509,
    },
};
use serde::{Deserialize, Serialize};
use std::{cmp::Ordering, collections::HashSet, path::Path};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateInput {
    pub name: String,
    pub certificate_pem: String,
    pub private_key_pem: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredCertificate {
    pub id: String,
    #[serde(flatten)]
    pub input: CertificateInput,
}

pub struct Certificate {
    pub stored: StoredCertificate,
    pub chain: Vec<X509>,
    pub key: PKey<Private>,
    pub domains: Vec<String>,
}

#[derive(Serialize)]
pub struct CertificateSummary {
    pub id: String,
    pub name: String,
    pub domains: Vec<String>,
    pub expires_at: String,
    pub days_remaining: i32,
    pub valid: bool,
    pub fingerprint: String,
}

impl Certificate {
    pub fn parse(mut stored: StoredCertificate, require_current: bool) -> Result<Self, String> {
        if uuid::Uuid::parse_str(&stored.id).is_err() {
            return Err("Invalid certificate ID.".into());
        }
        stored.input.name = stored.input.name.trim().to_owned();
        if stored.input.name.is_empty() || stored.input.name.len() > 80 {
            return Err("Certificate names must contain 1–80 characters.".into());
        }
        if stored.input.certificate_pem.len() > 256 * 1024
            || stored.input.private_key_pem.len() > 64 * 1024
        {
            return Err(
                "Certificate chains must be under 256 KB and private keys under 64 KB.".into(),
            );
        }
        let chain = X509::stack_from_pem(stored.input.certificate_pem.as_bytes())
            .map_err(|_| "Could not read the PEM certificate chain.".to_owned())?;
        if chain.is_empty() || chain.len() > 10 {
            return Err("Provide a leaf certificate followed by up to nine intermediates.".into());
        }
        if stored.input.private_key_pem.lines().any(|line| {
            line.trim() == "-----BEGIN ENCRYPTED PRIVATE KEY-----"
                || (line.trim().starts_with("Proc-Type:") && line.contains("ENCRYPTED"))
        }) {
            return Err("Use an unencrypted PEM private key.".into());
        }
        let key =
            PKey::private_key_from_pem_callback(stored.input.private_key_pem.as_bytes(), |_| Ok(0))
                .map_err(|_| {
                    "Could not read the private key. Use an unencrypted PEM key.".to_owned()
                })?;
        let public_key = chain[0]
            .public_key()
            .map_err(|_| "Could not read certificate public key.".to_owned())?;
        if !public_key.public_eq(&key) {
            return Err("The private key does not match the leaf certificate.".into());
        }
        for pair in chain.windows(2) {
            let issuer = pair[1]
                .public_key()
                .map_err(|_| "Invalid intermediate certificate.".to_owned())?;
            if !pair[0]
                .verify(&issuer)
                .map_err(|_| "Invalid certificate chain.".to_owned())?
            {
                return Err("Certificate chain signatures do not match. Put the leaf first, followed by its intermediates.".into());
            }
        }
        let mut domains: Vec<_> = chain[0]
            .subject_alt_names()
            .into_iter()
            .flatten()
            .filter_map(|name| {
                name.dnsname()
                    .map(|dns| dns.trim_end_matches('.').to_ascii_lowercase())
            })
            .collect();
        domains.sort();
        domains.dedup();
        if domains.is_empty() {
            return Err("The leaf certificate must include DNS subject alternative names.".into());
        }
        for domain in &domains {
            let suffix = domain.strip_prefix("*.").unwrap_or(domain);
            if suffix.contains('*')
                || suffix.is_empty()
                || suffix.contains(['/', ':', '@'])
                || suffix.parse::<axum::http::uri::Authority>().is_err()
            {
                return Err("The certificate contains an unsupported DNS name.".into());
            }
        }
        let certificate = Self {
            stored,
            chain,
            key,
            domains,
        };
        if require_current && !certificate.is_current() {
            return Err("The certificate chain is expired or is not valid yet.".into());
        }
        Ok(certificate)
    }

    pub fn is_current(&self) -> bool {
        let Ok(now) = Asn1Time::days_from_now(0) else {
            return false;
        };
        self.chain.iter().all(|cert| {
            matches!(
                cert.not_before().compare(&now),
                Ok(Ordering::Less | Ordering::Equal)
            )
        }) && self
            .chain
            .iter()
            .all(|cert| matches!(cert.not_after().compare(&now), Ok(Ordering::Greater)))
    }

    pub fn summary(&self) -> CertificateSummary {
        let days_remaining = Asn1Time::days_from_now(0)
            .ok()
            .and_then(|now| now.diff(self.chain[0].not_after()).ok())
            .map_or(0, |diff| diff.days);
        CertificateSummary {
            id: self.stored.id.clone(),
            name: self.stored.input.name.clone(),
            domains: self.domains.clone(),
            expires_at: self.chain[0].not_after().to_string(),
            days_remaining,
            valid: self.is_current(),
            fingerprint: self.chain[0]
                .digest(MessageDigest::sha256())
                .map(|bytes| {
                    bytes
                        .iter()
                        .map(|b| format!("{b:02X}"))
                        .collect::<Vec<_>>()
                        .join(":")
                })
                .unwrap_or_default(),
        }
    }
}

#[derive(Default)]
pub struct CertificateStore {
    pub certificates: Vec<Certificate>,
}

pub fn domain_matches(pattern: &str, hostname: &str) -> bool {
    if pattern == hostname {
        return true;
    }
    pattern.strip_prefix("*.").is_some_and(|suffix| {
        hostname
            .strip_suffix(suffix)
            .and_then(|prefix| prefix.strip_suffix('.'))
            .is_some_and(|label| !label.is_empty() && !label.contains('.'))
    })
}

impl CertificateStore {
    pub fn parse(records: Vec<StoredCertificate>) -> Result<Self, String> {
        if records.len() > 100 {
            return Err("A maximum of 100 certificates is supported.".into());
        }
        let mut ids = HashSet::new();
        let mut domains = HashSet::new();
        let mut certificates = Vec::new();
        for record in records {
            if !ids.insert(record.id.clone()) {
                return Err("Duplicate certificate ID.".into());
            }
            let cert = Certificate::parse(record, false)?;
            if cert
                .domains
                .iter()
                .any(|domain| !domains.insert(domain.clone()))
            {
                return Err(
                    "A certificate for one of these DNS names already exists. Replace it instead."
                        .into(),
                );
            }
            certificates.push(cert);
        }
        Ok(Self { certificates })
    }
    pub fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        match std::fs::read(path) {
            Ok(bytes) => Self::parse(serde_json::from_slice(&bytes)?)
                .map_err(|e| std::io::Error::other(e).into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(error.into()),
        }
    }
    pub fn records(&self) -> Vec<StoredCertificate> {
        self.certificates
            .iter()
            .map(|cert| cert.stored.clone())
            .collect()
    }
    pub fn summaries(&self) -> Vec<CertificateSummary> {
        self.certificates.iter().map(Certificate::summary).collect()
    }
    pub fn select(&self, hostname: &str) -> Option<&Certificate> {
        self.certificates
            .iter()
            .filter(|cert| cert.is_current())
            .filter_map(|cert| {
                cert.domains
                    .iter()
                    .filter(|domain| domain_matches(domain, hostname))
                    .map(|domain| (domain == hostname, cert))
                    .max_by_key(|(exact, _)| *exact)
            })
            .max_by_key(|(exact, _)| *exact)
            .map(|(_, cert)| cert)
    }
    pub fn persist(&self, path: &Path) -> std::io::Result<()> {
        use std::io::Write;
        let bytes = serde_json::to_vec_pretty(&self.records())?;
        let temporary = path.with_extension("tmp");
        // Restrict key material before writing, including an old temporary file.
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
        file.write_all(&bytes)?;
        file.sync_all()?;
        std::fs::rename(temporary, path)?;
        #[cfg(unix)]
        if let Some(parent) = path.parent() {
            if let Err(error) = std::fs::File::open(parent).and_then(|dir| dir.sync_all()) {
                log::warn!("Certificates saved, but directory sync failed: {error}");
            }
        }
        Ok(())
    }
}

pub struct DynamicCertificates(pub Shared);
#[async_trait]
impl TlsAccept for DynamicCertificates {
    async fn certificate_callback(&self, ssl: &mut SslRef) {
        let Some(hostname) = ssl
            .servername(NameType::HOST_NAME)
            .map(|host| host.trim_end_matches('.').to_ascii_lowercase())
        else {
            return;
        };
        let store = self.0.certificates.load();
        let Some(cert) = store.select(&hostname) else {
            return;
        };
        let result = (|| {
            ssl.set_certificate(&cert.chain[0])?;
            ssl.set_private_key(&cert.key)?;
            for intermediate in &cert.chain[1..] {
                ssl.add_chain_cert(intermediate.clone())?;
            }
            Ok::<_, pingora::tls::error::ErrorStack>(())
        })();
        if let Err(error) = result {
            log::error!("Could not apply TLS certificate: {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn record(domains: &[&str], starts: i64, ends: i64) -> StoredCertificate {
        use openssl::{
            bn::BigNum,
            rsa::Rsa,
            x509::{extension::SubjectAlternativeName, X509NameBuilder},
        };
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "Gateway test").unwrap();
        let name = name.build();
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder
            .set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&key).unwrap();
        let now = crate::state::now() as i64;
        builder
            .set_not_before(&Asn1Time::from_unix(now + starts).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::from_unix(now + ends).unwrap())
            .unwrap();
        let mut san = SubjectAlternativeName::new();
        for domain in domains {
            san.dns(domain);
        }
        let extension = san.build(&builder.x509v3_context(None, None)).unwrap();
        builder.append_extension(extension).unwrap();
        builder.sign(&key, MessageDigest::sha256()).unwrap();
        StoredCertificate {
            id: uuid::Uuid::new_v4().to_string(),
            input: CertificateInput {
                name: "Test".into(),
                certificate_pem: String::from_utf8(builder.build().to_pem().unwrap()).unwrap(),
                private_key_pem: String::from_utf8(key.private_key_to_pem_pkcs8().unwrap())
                    .unwrap(),
            },
        }
    }
    #[test]
    fn validity_and_private_key_redaction() {
        let valid = Certificate::parse(record(&["app.test"], -60, 86400), true).unwrap();
        assert!(valid.summary().valid);
        let json = serde_json::to_string(&valid.summary()).unwrap();
        assert!(!json.contains("PRIVATE KEY") && !json.contains("private_key_pem"));
        let expired = record(&["app.test"], -86400, -60);
        assert!(Certificate::parse(expired.clone(), true).is_err());
        let stored = CertificateStore::parse(vec![expired]).unwrap();
        assert!(!stored.summaries()[0].valid);
        assert!(stored.select("app.test").is_none());
        assert!(Certificate::parse(record(&["app.test"], 3600, 86400), true).is_err());
    }
    #[test]
    fn exact_certificates_override_wildcards_and_duplicate_names_fail() {
        let wildcard = record(&["*.example.test"], -60, 86400);
        let exact = record(&["api.example.test"], -60, 86400);
        let exact_id = exact.id.clone();
        let store = CertificateStore::parse(vec![wildcard.clone(), exact]).unwrap();
        assert_eq!(
            store.select("api.example.test").unwrap().stored.id,
            exact_id
        );
        let mut duplicate = wildcard.clone();
        duplicate.id = uuid::Uuid::new_v4().to_string();
        assert!(CertificateStore::parse(vec![wildcard, duplicate]).is_err());
    }
    #[test]
    fn wildcards_match_exactly_one_dns_label() {
        assert!(domain_matches("*.example.com", "app.example.com"));
        assert!(!domain_matches("*.example.com", "example.com"));
        assert!(!domain_matches("*.example.com", "a.b.example.com"));
        assert!(!domain_matches("*.example.com", "appexample.com"));
        assert!(domain_matches("example.com", "example.com"));
    }
    #[test]
    fn encrypted_private_keys_are_rejected_without_prompting() {
        let mut stored = record(&["example.com"], -60, 3600);
        let key = PKey::private_key_from_pem(stored.input.private_key_pem.as_bytes()).unwrap();
        stored.input.private_key_pem = String::from_utf8(
            key.private_key_to_pem_pkcs8_passphrase(
                openssl::symm::Cipher::aes_256_cbc(),
                b"fixture-password",
            )
            .unwrap(),
        )
        .unwrap();
        assert!(Certificate::parse(stored, false).is_err());
    }
    #[test]
    fn malformed_uploads_are_rejected() {
        assert!(Certificate::parse(
            StoredCertificate {
                id: uuid::Uuid::new_v4().to_string(),
                input: CertificateInput {
                    name: "Test".into(),
                    certificate_pem: "invalid".into(),
                    private_key_pem: "invalid".into()
                }
            },
            true
        )
        .is_err());
    }
}

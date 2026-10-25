//! Private certificate authorities trusted by EmberGate's own checks: health
//! probes, Diagnostics, and forward-auth requests. Proxy traffic keeps the
//! system trust store. The PEM bundle is stored in the management secrets
//! table, so encrypted backups carry it.
use crate::state::Shared;
use arc_swap::ArcSwap;
use axum::{extract::State, http::StatusCode, routing::get, Json, Router};
use openssl::{hash::MessageDigest, nid::Nid, x509::X509};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

const SECRET: &str = "private_ca_bundle";
const MAX_BYTES: usize = 256 * 1024;
const MAX_CERTIFICATES: usize = 32;

#[derive(Default)]
pub struct Bundle {
    pub pem: String,
    pub certificates: Vec<X509>,
}

/// The current bundle plus a generation that bumps on every change, so cached
/// clients know when to rebuild.
#[derive(Default)]
pub struct Trust {
    bundle: ArcSwap<Bundle>,
    generation: AtomicU64,
}

impl Trust {
    pub fn load(pem: Option<String>) -> Result<Self, String> {
        let trust = Self::default();
        if let Some(pem) = pem {
            trust.set(parse(&pem)?);
        }
        Ok(trust)
    }
    pub fn current(&self) -> Arc<Bundle> {
        self.bundle.load_full()
    }
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }
    fn set(&self, bundle: Bundle) {
        self.bundle.store(Arc::new(bundle));
        self.generation.fetch_add(1, Ordering::SeqCst);
    }
    /// Adds the private authorities to a reqwest client's bundled public roots.
    pub fn reqwest(&self, mut builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
        for certificate in &self.current().certificates {
            match certificate
                .to_der()
                .map_err(|e| e.to_string())
                .and_then(|der| reqwest::Certificate::from_der(&der).map_err(|e| e.to_string()))
            {
                Ok(root) => builder = builder.add_root_certificate(root),
                Err(error) => log::warn!("Skipping a private CA certificate: {error}"),
            }
        }
        builder
    }
}

impl Bundle {
    /// Adds the private authorities to an OpenSSL connector's system store.
    pub fn add_to_openssl(&self, builder: &mut openssl::ssl::SslConnectorBuilder) {
        for certificate in &self.certificates {
            if let Err(error) = builder.cert_store_mut().add_cert(certificate.clone()) {
                // Duplicates of system roots are harmless.
                log::debug!("Private CA certificate not added: {error}");
            }
        }
    }
}

fn parse(pem: &str) -> Result<Bundle, String> {
    let pem = pem.trim();
    if pem.len() > MAX_BYTES {
        return Err("The certificate bundle is larger than 256 KiB.".into());
    }
    if pem.contains("PRIVATE KEY") {
        return Err("Remove the private key. Paste only CA certificates.".into());
    }
    let certificates = X509::stack_from_pem(pem.as_bytes()).map_err(|_| {
        "Paste one or more PEM certificates (-----BEGIN CERTIFICATE-----).".to_owned()
    })?;
    if certificates.is_empty() {
        return Err("Paste one or more PEM certificates (-----BEGIN CERTIFICATE-----).".into());
    }
    if certificates.len() > MAX_CERTIFICATES {
        return Err(format!(
            "A bundle can hold at most {MAX_CERTIFICATES} certificates."
        ));
    }
    for certificate in &certificates {
        if !is_ca(certificate) {
            return Err(format!(
                "“{}” is not a certificate authority. Add the CA that issued it instead.",
                name(certificate.subject_name())
            ));
        }
    }
    Ok(Bundle {
        pem: format!("{pem}\n"),
        certificates,
    })
}

/// Whether the basic constraints extension marks the certificate as a CA.
fn is_ca(certificate: &X509) -> bool {
    // openssl-rs exposes no basic constraints accessor; the text form is stable.
    certificate
        .to_text()
        .map(|text| String::from_utf8_lossy(&text).contains("CA:TRUE"))
        .unwrap_or(false)
}

fn name(name: &openssl::x509::X509NameRef) -> String {
    name.entries_by_nid(Nid::COMMONNAME)
        .next()
        .or_else(|| name.entries().next())
        .and_then(|entry| entry.data().to_string().ok())
        .unwrap_or_else(|| "Unnamed certificate".into())
}

fn summary(bundle: &Bundle) -> Value {
    json!({
        "configured": !bundle.certificates.is_empty(),
        "certificates": bundle.certificates.iter().map(|c| json!({
            "subject": name(c.subject_name()),
            "issuer": name(c.issuer_name()),
            "not_after": c.not_after().to_string(),
            "expired": c.not_after() < openssl::asn1::Asn1Time::days_from_now(0).expect("current time").as_ref(),
            "sha256": c.digest(MessageDigest::sha256()).map(|d| d.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")).unwrap_or_default(),
        })).collect::<Vec<_>>(),
    })
}

pub fn validate_backup(value: &str) -> Result<(), String> {
    parse(value)
        .map(|_| ())
        .map_err(|e| format!("Invalid private CA bundle: {e}"))
}

type Error = (StatusCode, Json<Value>);
fn error(status: StatusCode, message: impl ToString) -> Error {
    (status, Json(json!({"error":message.to_string()})))
}

async fn status(State(state): State<Shared>) -> Json<Value> {
    Json(summary(&state.trust.current()))
}

#[derive(Deserialize)]
struct Save {
    pem: String,
}

async fn save(State(state): State<Shared>, Json(input): Json<Save>) -> Result<Json<Value>, Error> {
    let bundle = parse(&input.pem).map_err(|e| error(StatusCode::UNPROCESSABLE_ENTITY, e))?;
    state
        .control
        .set_secret(SECRET.into(), Some(bundle.pem.clone()))
        .await
        .map_err(|e| error(StatusCode::SERVICE_UNAVAILABLE, e))?;
    state.trust.set(bundle);
    Ok(Json(summary(&state.trust.current())))
}

async fn remove(State(state): State<Shared>) -> Result<Json<Value>, Error> {
    state
        .control
        .set_secret(SECRET.into(), None)
        .await
        .map_err(|e| error(StatusCode::SERVICE_UNAVAILABLE, e))?;
    state.trust.set(Bundle::default());
    Ok(Json(summary(&state.trust.current())))
}

pub fn load_secret(
    control: &crate::management::Control,
) -> Result<Trust, Box<dyn std::error::Error>> {
    Ok(Trust::load(control.secret(SECRET)?)?)
}

pub fn routes() -> Router<Shared> {
    Router::new().route("/api/trust", get(status).put(save).delete(remove))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::{
        asn1::Asn1Time,
        bn::{BigNum, MsbOption},
        pkey::PKey,
        rsa::Rsa,
        x509::{extension::BasicConstraints, X509NameBuilder},
    };

    pub fn certificate(common_name: &str, ca: bool) -> String {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_nid(Nid::COMMONNAME, common_name)
            .unwrap();
        let name = name.build();
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        let mut serial = BigNum::new().unwrap();
        serial.rand(64, MsbOption::MAYBE_ZERO, false).unwrap();
        builder
            .set_serial_number(&serial.to_asn1_integer().unwrap())
            .unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&key).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(30).unwrap())
            .unwrap();
        if ca {
            builder
                .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
                .unwrap();
        }
        builder.sign(&key, MessageDigest::sha256()).unwrap();
        String::from_utf8(builder.build().to_pem().unwrap()).unwrap()
    }

    #[test]
    fn bundles_accept_only_ca_certificates() {
        let root = certificate("Home Lab Root", true);
        let bundle = parse(&format!("{root}{}", certificate("Second Root", true))).unwrap();
        assert_eq!(bundle.certificates.len(), 2);
        let info = summary(&bundle);
        assert_eq!(info["certificates"][0]["subject"], "Home Lab Root");
        assert_eq!(info["certificates"][0]["expired"], false);
        assert!(parse(&certificate("server.lan", false))
            .err()
            .unwrap()
            .contains("not a certificate authority"));
        assert!(parse("not a certificate").is_err());
        assert!(parse(&format!("{root}-----BEGIN PRIVATE KEY-----\n"))
            .err()
            .unwrap()
            .contains("private key"));
        assert!(validate_backup(&root).is_ok());
    }

    #[test]
    fn changes_bump_the_generation() {
        let trust = Trust::load(None).unwrap();
        assert_eq!(trust.generation(), 0);
        assert!(trust.current().certificates.is_empty());
        trust.set(parse(&certificate("Root", true)).unwrap());
        assert_eq!(trust.generation(), 1);
        assert_eq!(trust.current().certificates.len(), 1);
        let _client = trust.reqwest(reqwest::Client::builder()).build().unwrap();
    }
}

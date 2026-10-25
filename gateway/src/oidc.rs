//! OpenID Connect sign-in with one provider: authorization code flow with
//! PKCE, ID token validation, dashboard sign-in for existing accounts, and a
//! per-host login policy that keeps an encrypted session cookie per hostname.
use crate::state::{now, Shared};
use arc_swap::ArcSwap;
use openssl::{
    bn::BigNum,
    ec::{EcGroup, EcKey},
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Public},
    rsa::{Padding, Rsa},
    sign::{RsaPssSaltlen, Verifier},
    symm::{decrypt_aead, encrypt_aead, Cipher},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

pub const SETTINGS: &str = "oidc_provider";
pub const CLIENT_SECRET: &str = "oidc_client_secret";
pub const SESSION_KEY: &str = "oidc_session_key";
/// Reserved paths on protected hosts.
pub const CALLBACK: &str = "/.well-known/embergate/oidc/callback";
pub const LOGOUT: &str = "/.well-known/embergate/oidc/logout";
/// Prefix of every sign-in cookie, which applications never receive.
pub const HOST_COOKIE: &str = "embergate_oidc";
pub const STATE_COOKIE: &str = "embergate_oidc_state";
const PENDING_SECONDS: u64 = 600;
const METADATA_TTL: Duration = Duration::from_secs(3600);
/// Identity headers sent to applications behind the host policy. Incoming
/// copies are always removed so visitors cannot forge them.
pub const IDENTITY_HEADERS: [&str; 4] = [
    "x-auth-request-user",
    "x-auth-request-email",
    "x-auth-request-groups",
    "x-auth-request-preferred-username",
];

// ---------------------------------------------------------------- settings

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// Shown on sign-in buttons, for example "Authentik".
    pub name: String,
    pub issuer: String,
    pub client_id: String,
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
    #[serde(default = "default_groups_claim")]
    pub groups_claim: String,
    #[serde(default)]
    pub dashboard_enabled: bool,
    /// Stable dashboard origin used for the dashboard redirect URI.
    #[serde(default)]
    pub dashboard_origin: String,
    /// Whether provider sign-in satisfies EmberGate two-factor authentication.
    #[serde(default)]
    pub trust_provider_mfa: bool,
}
fn default_scopes() -> Vec<String> {
    vec!["openid".into(), "email".into(), "profile".into()]
}
fn default_groups_claim() -> String {
    "groups".into()
}

fn https_or_local(url: &url::Url) -> bool {
    url.scheme() == "https"
        || (url.scheme() == "http"
            && matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")))
}

impl Settings {
    fn normalize(&mut self) {
        self.name = self.name.trim().to_owned();
        self.issuer = self.issuer.trim().trim_end_matches('/').to_owned();
        self.client_id = self.client_id.trim().to_owned();
        self.groups_claim = self.groups_claim.trim().to_owned();
        self.dashboard_origin = self
            .dashboard_origin
            .trim()
            .trim_end_matches('/')
            .to_owned();
        self.scopes = self
            .scopes
            .iter()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .collect();
        if !self.scopes.iter().any(|s| s == "openid") {
            self.scopes.insert(0, "openid".into());
        }
        self.scopes.dedup();
    }
    pub fn validate(&self) -> Result<(), String> {
        if self.name.is_empty()
            || self.name.chars().count() > 40
            || self.name.chars().any(char::is_control)
        {
            return Err("Enter a provider name of up to 40 characters.".into());
        }
        let issuer =
            url::Url::parse(&self.issuer).map_err(|_| "Enter the provider's issuer URL.")?;
        if !https_or_local(&issuer)
            || issuer.query().is_some()
            || issuer.fragment().is_some()
            || !issuer.username().is_empty()
        {
            return Err("The issuer must be an HTTPS URL without query or credentials (HTTP is allowed for localhost).".into());
        }
        if self.client_id.is_empty()
            || self.client_id.len() > 256
            || self
                .client_id
                .chars()
                .any(|c| c.is_control() || c.is_whitespace())
        {
            return Err("Enter the client ID from your provider.".into());
        }
        if self.scopes.len() > 16
            || self.scopes.iter().any(|s| {
                s.len() > 64
                    || !s
                        .bytes()
                        .all(|b| b.is_ascii_graphic() && b != b'"' && b != b'\\')
            })
        {
            return Err("Scopes must be up to 16 space-free names.".into());
        }
        if self.groups_claim.is_empty()
            || self.groups_claim.len() > 64
            || !self
                .groups_claim
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-.:/".contains(&b))
        {
            return Err("Enter the claim that lists groups, usually groups.".into());
        }
        if self.dashboard_enabled || !self.dashboard_origin.is_empty() {
            let origin = url::Url::parse(&self.dashboard_origin).map_err(|_| {
                "Enter the dashboard address, for example https://gateway.example.com."
            })?;
            if !https_or_local(&origin)
                || origin.path() != "/"
                || origin.query().is_some()
                || !origin.username().is_empty()
            {
                return Err("The dashboard address must be an HTTPS origin with no path (HTTP is allowed for localhost).".into());
            }
        }
        Ok(())
    }
    pub fn dashboard_redirect(&self) -> String {
        format!("{}/api/oidc/callback", self.dashboard_origin)
    }
}

// ----------------------------------------------------------- host policy

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostPolicy {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_emails: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_domains: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_groups: Vec<String>,
    #[serde(default = "default_session_hours")]
    pub session_hours: u32,
}
fn default_session_hours() -> u32 {
    12
}
impl Default for HostPolicy {
    fn default() -> Self {
        Self {
            allowed_emails: Vec::new(),
            allowed_domains: Vec::new(),
            allowed_groups: Vec::new(),
            session_hours: default_session_hours(),
        }
    }
}
impl HostPolicy {
    pub fn validate(&mut self) -> Result<(), String> {
        let clean = |values: &mut Vec<String>, lower: bool| {
            for value in values.iter_mut() {
                *value = value.trim().to_owned();
                if lower {
                    *value = value.to_ascii_lowercase();
                }
            }
            values.retain(|v| !v.is_empty());
            values.sort();
            values.dedup();
        };
        clean(&mut self.allowed_emails, true);
        clean(&mut self.allowed_domains, true);
        clean(&mut self.allowed_groups, false);
        for domain in &mut self.allowed_domains {
            *domain = domain.trim_start_matches('@').to_owned();
        }
        if [
            &self.allowed_emails,
            &self.allowed_domains,
            &self.allowed_groups,
        ]
        .iter()
        .any(|v| v.len() > 100)
        {
            return Err("Use at most 100 entries in each sign-in rule.".into());
        }
        if self.allowed_emails.iter().any(|e| {
            e.len() > 254
                || e.split_once('@')
                    .is_none_or(|(a, d)| a.is_empty() || d.is_empty())
                || e.chars().any(|c| c.is_whitespace() || c.is_control())
        }) {
            return Err("Enter allowed emails as full addresses.".into());
        }
        if self.allowed_domains.iter().any(|d| {
            d.len() > 253
                || d.contains('@')
                || !d
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-.".contains(&b))
        }) {
            return Err("Enter allowed email domains like example.com.".into());
        }
        if self
            .allowed_groups
            .iter()
            .any(|g| g.len() > 256 || g.chars().any(char::is_control))
        {
            return Err("Group names must be up to 256 characters.".into());
        }
        if !(1..=168).contains(&self.session_hours) {
            return Err("Keep host sign-ins for 1 to 168 hours.".into());
        }
        Ok(())
    }
    /// Whether the identity may use the host. Empty rules admit every account
    /// the provider signs in; otherwise any one matching rule is enough.
    pub fn admits(&self, identity: &Identity) -> bool {
        if self.allowed_emails.is_empty()
            && self.allowed_domains.is_empty()
            && self.allowed_groups.is_empty()
        {
            return true;
        }
        let email = identity.verified_email().map(str::to_ascii_lowercase);
        email
            .as_ref()
            .is_some_and(|e| self.allowed_emails.contains(e))
            || email
                .as_ref()
                .and_then(|e| e.rsplit_once('@'))
                .is_some_and(|(_, d)| self.allowed_domains.iter().any(|a| a == d))
            || identity
                .groups
                .iter()
                .any(|g| self.allowed_groups.contains(g))
    }
}

// ---------------------------------------------------------------- identity

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    #[serde(rename = "s")]
    pub subject: String,
    #[serde(rename = "e", default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(rename = "v", default)]
    pub email_verified: bool,
    #[serde(rename = "u", default, skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    #[serde(rename = "g", default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
}
impl Identity {
    /// Email addresses count only when the provider marks them verified.
    pub fn verified_email(&self) -> Option<&str> {
        self.email.as_deref().filter(|_| self.email_verified)
    }
    fn from_claims(claims: &Value, groups_claim: &str) -> Result<Self, String> {
        let text = |key: &str| {
            claims[key]
                .as_str()
                .map(str::to_owned)
                .filter(|v| !v.is_empty() && v.len() <= 512)
        };
        let groups = match &claims[groups_claim] {
            Value::Array(items) => items
                .iter()
                .filter_map(|g| g.as_str())
                .map(str::to_owned)
                .take(256)
                .collect(),
            Value::String(group) => vec![group.clone()],
            _ => Vec::new(),
        };
        Ok(Self {
            subject: text("sub").ok_or("The ID token has no subject.")?,
            email: text("email"),
            email_verified: claims["email_verified"] == true || claims["email_verified"] == "true",
            preferred_username: text("preferred_username"),
            groups: groups
                .into_iter()
                .filter(|g: &String| g.len() <= 256)
                .collect(),
        })
    }
}

// ------------------------------------------------------------------ base64

pub fn b64url_encode(bytes: &[u8]) -> String {
    openssl::base64::encode_block(bytes)
        .trim_end_matches('=')
        .replace('+', "-")
        .replace('/', "_")
}
pub fn b64url_decode(value: &str) -> Option<Vec<u8>> {
    if value
        .bytes()
        .any(|b| !(b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
    {
        return None;
    }
    let mut standard = value.replace('-', "+").replace('_', "/");
    while standard.len() % 4 != 0 {
        standard.push('=');
    }
    openssl::base64::decode_block(&standard).ok()
}
fn random(bytes: usize) -> Vec<u8> {
    let mut value = vec![0u8; bytes];
    openssl::rand::rand_bytes(&mut value).expect("random bytes");
    value
}

// --------------------------------------------------------------- ID tokens

#[derive(Clone, Debug, Deserialize)]
pub struct Metadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    #[serde(default)]
    pub end_session_endpoint: Option<String>,
}

fn public_key(jwk: &Value) -> Option<PKey<Public>> {
    let part = |key: &str| {
        jwk[key]
            .as_str()
            .and_then(b64url_decode)
            .and_then(|b| BigNum::from_slice(&b).ok())
    };
    match jwk["kty"].as_str()? {
        "RSA" => PKey::from_rsa(Rsa::from_public_components(part("n")?, part("e")?).ok()?).ok(),
        "EC" => {
            let nid = match jwk["crv"].as_str()? {
                "P-256" => Nid::X9_62_PRIME256V1,
                "P-384" => Nid::SECP384R1,
                _ => return None,
            };
            let group = EcGroup::from_curve_name(nid).ok()?;
            let (x, y) = (part("x")?, part("y")?);
            PKey::from_ec_key(EcKey::from_public_key_affine_coordinates(&group, &x, &y).ok()?).ok()
        }
        _ => None,
    }
}

/// Checks a JWS signature with the algorithm named in its header.
fn signature_valid(alg: &str, key: &PKey<Public>, input: &[u8], signature: &[u8]) -> bool {
    let check = || -> Result<bool, openssl::error::ErrorStack> {
        let (digest, pss, ec_size) = match alg {
            "RS256" => (MessageDigest::sha256(), false, 0),
            "RS384" => (MessageDigest::sha384(), false, 0),
            "RS512" => (MessageDigest::sha512(), false, 0),
            "PS256" => (MessageDigest::sha256(), true, 0),
            "ES256" => (MessageDigest::sha256(), false, 32),
            "ES384" => (MessageDigest::sha384(), false, 48),
            _ => return Ok(false),
        };
        if ec_size > 0 {
            let ec = key.ec_key()?;
            if signature.len() != ec_size * 2 {
                return Ok(false);
            }
            let r = BigNum::from_slice(&signature[..ec_size])?;
            let s = BigNum::from_slice(&signature[ec_size..])?;
            let hash = openssl::hash::hash(digest, input)?;
            return EcdsaSig::from_private_components(r, s)?.verify(&hash, &ec);
        }
        key.rsa()?;
        let mut verifier = Verifier::new(digest, key)?;
        if pss {
            verifier.set_rsa_padding(Padding::PKCS1_PSS)?;
            verifier.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)?;
        }
        verifier.update(input)?;
        verifier.verify(signature)
    };
    check().unwrap_or(false)
}

/// Validates an ID token's signature and claims; returns its claims.
pub fn validate_id_token(
    token: &str,
    jwks: &Value,
    issuer: &str,
    client_id: &str,
    nonce: &str,
    now: u64,
) -> Result<Value, String> {
    let invalid = |why: &str| format!("The provider's ID token was rejected: {why}.");
    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(invalid("malformed token"));
    };
    let header: Value = b64url_decode(header)
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or_else(|| invalid("malformed header"))?;
    let alg = header["alg"].as_str().unwrap_or_default();
    let kid = header["kid"].as_str();
    let signature = b64url_decode(signature).ok_or_else(|| invalid("malformed signature"))?;
    let candidates: Vec<&Value> = jwks["keys"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|k| kid.is_none_or(|kid| k["kid"].as_str() == Some(kid)))
        .filter(|k| k["use"].as_str().is_none_or(|u| u == "sig"))
        .filter(|k| k["alg"].as_str().is_none_or(|a| a == alg))
        .collect();
    let input = format!("{}.{}", token.split('.').next().unwrap(), payload);
    if !candidates
        .iter()
        .filter_map(|k| public_key(k))
        .any(|key| signature_valid(alg, &key, input.as_bytes(), &signature))
    {
        return Err(invalid("signature did not verify"));
    }
    let claims: Value = b64url_decode(payload)
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or_else(|| invalid("malformed claims"))?;
    if claims["iss"].as_str() != Some(issuer) {
        return Err(invalid("unexpected issuer"));
    }
    let audiences: Vec<&str> = match &claims["aud"] {
        Value::String(aud) => vec![aud.as_str()],
        Value::Array(items) => items.iter().filter_map(|a| a.as_str()).collect(),
        _ => vec![],
    };
    if !audiences.contains(&client_id)
        || (audiences.len() > 1 && claims["azp"].as_str() != Some(client_id))
    {
        return Err(invalid("issued for another client"));
    }
    let time = |key: &str| {
        claims[key]
            .as_u64()
            .or_else(|| claims[key].as_f64().map(|v| v as u64))
    };
    if time("exp").is_none_or(|exp| exp + 60 <= now) {
        return Err(invalid("expired"));
    }
    if time("iat").is_some_and(|iat| iat > now + 300)
        || time("nbf").is_some_and(|nbf| nbf > now + 60)
    {
        return Err(invalid("not valid yet"));
    }
    if claims["nonce"].as_str().is_none_or(|n| !same(n, nonce)) {
        return Err(invalid("nonce mismatch"));
    }
    Ok(claims)
}

/// Constant-time comparison for strings of possibly different lengths.
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len() && openssl::memcmp::eq(a.as_bytes(), b.as_bytes())
}

// ----------------------------------------------------------------- runtime

/// Where a sign-in returns to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Target {
    Dashboard,
    Host { route_id: String, host: String },
}

/// A sign-in in progress. It travels in an encrypted state cookie, so the
/// server holds nothing a flood of unfinished sign-ins could exhaust.
#[derive(Clone, Serialize, Deserialize)]
pub struct Pending {
    pub target: Target,
    pub redirect_uri: String,
    pub return_to: String,
    state: String,
    nonce: String,
    verifier: String,
    created: u64,
}

struct Cached {
    fetched: Instant,
    metadata: Metadata,
    jwks: Value,
    jwks_fetched: Instant,
}

pub struct Provider {
    pub settings: Settings,
    secret: String,
}

#[derive(Default)]
pub struct Oidc {
    pub provider: ArcSwap<Option<Provider>>,
    session_key: ArcSwap<Vec<u8>>,
    cache: tokio::sync::Mutex<Option<Cached>>,
}

impl Oidc {
    pub fn load(control: &crate::management::Control) -> Result<Self, String> {
        let oidc = Self::default();
        let settings: Option<Settings> = control
            .secret(SETTINGS)?
            .map(|v| serde_json::from_str(&v).map_err(|_| "Invalid OIDC settings.".to_owned()))
            .transpose()?;
        let secret = control.secret(CLIENT_SECRET)?.unwrap_or_default();
        oidc.provider.store(Arc::new(
            settings.map(|settings| Provider { settings, secret }),
        ));
        let key = match control
            .secret(SESSION_KEY)?
            .and_then(|k| b64url_decode(&k))
            .filter(|k| k.len() == 32)
        {
            Some(key) => key,
            None => {
                // Host sign-ins survive restarts because the key is stored.
                let key = random(32);
                control.store_secret(SESSION_KEY, &b64url_encode(&key))?;
                key
            }
        };
        oidc.session_key.store(Arc::new(key));
        Ok(oidc)
    }

    pub fn settings(&self) -> Option<Settings> {
        self.provider
            .load()
            .as_ref()
            .as_ref()
            .map(|p| p.settings.clone())
    }

    fn client(trust: &crate::trust::Trust) -> Result<reqwest::Client, String> {
        trust
            .reqwest(reqwest::Client::builder())
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .user_agent(concat!("EmberGate/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| e.to_string())
    }

    async fn fetch_json(client: &reqwest::Client, url: &str) -> Result<Value, String> {
        let response = client
            .get(url)
            .send()
            .await
            .map_err(|_| format!("Could not reach the identity provider at {url}."))?;
        if !response.status().is_success() {
            return Err(format!(
                "The identity provider answered HTTP {} for {url}.",
                response.status().as_u16()
            ));
        }
        response
            .json()
            .await
            .map_err(|_| format!("The identity provider returned invalid JSON at {url}."))
    }

    /// Provider metadata and signing keys, cached for an hour. `refresh_keys`
    /// refetches the keys (at most once a minute) after an unknown key ID.
    async fn metadata(
        &self,
        settings: &Settings,
        trust: &crate::trust::Trust,
        refresh_keys: bool,
    ) -> Result<(Metadata, Value), String> {
        let mut cache = self.cache.lock().await;
        let client = Self::client(trust)?;
        let stale = cache.as_ref().is_none_or(|c| {
            c.fetched.elapsed() > METADATA_TTL || c.metadata.issuer != settings.issuer
        });
        if stale {
            let discovered = Self::fetch_json(
                &client,
                &format!("{}/.well-known/openid-configuration", settings.issuer),
            )
            .await?;
            let metadata: Metadata = serde_json::from_value(discovered)
                .map_err(|_| "The provider's discovery document is incomplete.".to_owned())?;
            if metadata.issuer.trim_end_matches('/') != settings.issuer {
                return Err(format!(
                    "The provider reports issuer {}, not {}.",
                    metadata.issuer, settings.issuer
                ));
            }
            for endpoint in [
                &metadata.authorization_endpoint,
                &metadata.token_endpoint,
                &metadata.jwks_uri,
            ] {
                if !url::Url::parse(endpoint).is_ok_and(|u| https_or_local(&u)) {
                    return Err("The provider's endpoints must use HTTPS.".into());
                }
            }
            let jwks = Self::fetch_json(&client, &metadata.jwks_uri).await?;
            *cache = Some(Cached {
                fetched: Instant::now(),
                metadata,
                jwks,
                jwks_fetched: Instant::now(),
            });
        } else if refresh_keys
            && cache
                .as_ref()
                .is_some_and(|c| c.jwks_fetched.elapsed() > Duration::from_secs(60))
        {
            let cached = cache.as_mut().unwrap();
            cached.jwks = Self::fetch_json(&client, &cached.metadata.jwks_uri).await?;
            cached.jwks_fetched = Instant::now();
        }
        let cached = cache.as_ref().unwrap();
        Ok((cached.metadata.clone(), cached.jwks.clone()))
    }

    /// Starts a sign-in. Returns the provider URL and the sealed flow, which the
    /// caller stores in a short-lived cookie to bind the flow to the browser.
    pub async fn begin(
        &self,
        trust: &crate::trust::Trust,
        target: Target,
        redirect_uri: String,
        return_to: String,
    ) -> Result<(String, String), String> {
        let settings = self.settings().ok_or("Single sign-on is not configured.")?;
        let (metadata, _) = self.metadata(&settings, trust, false).await?;
        let state = b64url_encode(&random(32));
        let nonce = b64url_encode(&random(32));
        let verifier = b64url_encode(&random(32));
        let challenge = b64url_encode(&openssl::sha::sha256(verifier.as_bytes()));
        let flow = self.seal_value(
            b"embergate-oidc-state-v1",
            &serde_json::to_vec(&Pending {
                target,
                redirect_uri: redirect_uri.clone(),
                return_to,
                state: state.clone(),
                nonce: nonce.clone(),
                verifier,
                created: now(),
            })
            .expect("sign-in state"),
        );
        let mut url = url::Url::parse(&metadata.authorization_endpoint)
            .map_err(|_| "Invalid authorization endpoint.")?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &settings.client_id)
            .append_pair("redirect_uri", &redirect_uri)
            .append_pair("scope", &settings.scopes.join(" "))
            .append_pair("state", &state)
            .append_pair("nonce", &nonce)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");
        Ok((url.to_string(), flow))
    }

    /// Completes a sign-in from the provider's redirect. The state must match
    /// the browser's sealed state cookie; the provider's one-use code and the
    /// nonce stop replays.
    pub async fn finish(
        &self,
        trust: &crate::trust::Trust,
        state: &str,
        code: &str,
        cookie_state: Option<&str>,
        redirect_uri: &str,
    ) -> Result<(Identity, Pending), String> {
        let expired = "This sign-in expired or was already used. Start again.";
        let pending: Pending = cookie_state
            .and_then(|c| self.open_value(b"embergate-oidc-state-v1", c))
            .and_then(|body| serde_json::from_slice(&body).ok())
            .ok_or(expired)?;
        if !same(&pending.state, state)
            || pending.created + PENDING_SECONDS <= now()
            || pending.redirect_uri != redirect_uri
        {
            return Err(expired.into());
        }
        if code.is_empty() || code.len() > 4096 {
            return Err("The provider did not return an authorization code.".into());
        }
        let provider = self.provider.load_full();
        let provider = provider
            .as_ref()
            .as_ref()
            .ok_or("Single sign-on is not configured.")?;
        let settings = &provider.settings;
        let (metadata, jwks) = self.metadata(settings, trust, false).await?;
        let response = Self::client(trust)?
            .post(&metadata.token_endpoint)
            .basic_auth(&settings.client_id, Some(&provider.secret))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", redirect_uri),
                ("client_id", settings.client_id.as_str()),
                ("code_verifier", pending.verifier.as_str()),
            ])
            .send()
            .await
            .map_err(|_| "Could not reach the provider's token endpoint.".to_owned())?;
        let status = response.status();
        let tokens: Value = response.json().await.unwrap_or_default();
        if !status.is_success() {
            let reason = tokens["error_description"]
                .as_str()
                .or(tokens["error"].as_str())
                .unwrap_or("no reason given");
            return Err(format!(
                "The provider refused the sign-in: {}.",
                reason.chars().take(200).collect::<String>()
            ));
        }
        let token = tokens["id_token"]
            .as_str()
            .ok_or("The provider returned no ID token.")?;
        let claims = match validate_id_token(
            token,
            &jwks,
            &metadata.issuer,
            &settings.client_id,
            &pending.nonce,
            now(),
        ) {
            Ok(claims) => claims,
            Err(_) => {
                // Signing keys may have rotated since they were cached.
                let (_, jwks) = self.metadata(settings, trust, true).await?;
                validate_id_token(
                    token,
                    &jwks,
                    &metadata.issuer,
                    &settings.client_id,
                    &pending.nonce,
                    now(),
                )?
            }
        };
        Ok((
            Identity::from_claims(&claims, &settings.groups_claim)?,
            pending,
        ))
    }

    pub async fn end_session_url(&self, trust: &crate::trust::Trust) -> Option<String> {
        let settings = self.settings()?;
        self.metadata(&settings, trust, false)
            .await
            .ok()?
            .0
            .end_session_endpoint
    }

    // ------------------------------------------------------ host sessions

    fn seal_value(&self, aad: &[u8], body: &[u8]) -> String {
        let iv = random(12);
        let mut tag = [0u8; 16];
        let key = self.session_key.load();
        let ciphertext = encrypt_aead(Cipher::aes_256_gcm(), &key, Some(&iv), aad, body, &mut tag)
            .expect("AES-GCM");
        b64url_encode(&[iv, ciphertext, tag.to_vec()].concat())
    }
    fn open_value(&self, aad: &[u8], value: &str) -> Option<Vec<u8>> {
        let bytes = b64url_decode(value).filter(|b| b.len() > 28 && b.len() < 16384)?;
        let (iv, rest) = bytes.split_at(12);
        let (ciphertext, tag) = rest.split_at(rest.len() - 16);
        let key = self.session_key.load();
        decrypt_aead(Cipher::aes_256_gcm(), &key, Some(iv), aad, ciphertext, tag).ok()
    }

    /// An encrypted, authenticated cookie value for one host sign-in.
    pub fn seal(&self, route_id: &str, host: &str, identity: &Identity, hours: u32) -> String {
        let body =
            json!({"r": route_id, "h": host, "x": now() + u64::from(hours) * 3600, "i": identity})
                .to_string();
        self.seal_value(b"embergate-oidc-v1", body.as_bytes())
    }

    /// Opens a host cookie issued for this route and hostname.
    pub fn open(&self, value: &str, route_id: &str, host: &str) -> Option<Identity> {
        let body = self.open_value(b"embergate-oidc-v1", value)?;
        let session: Value = serde_json::from_slice(&body).ok()?;
        (session["r"] == route_id
            && session["h"] == host
            && session["x"].as_u64().is_some_and(|x| x > now()))
        .then(|| serde_json::from_value(session["i"].clone()).ok())
        .flatten()
    }

    /// Replaces the provider and signs every host session out.
    fn replace(&self, provider: Option<Provider>, key: Vec<u8>) {
        self.provider.store(Arc::new(provider));
        self.session_key.store(Arc::new(key));
    }
}

/// The session cookie name for one route.
pub fn host_cookie_name(route_id: &str) -> String {
    let id: String = route_id
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .take(12)
        .collect();
    format!("{HOST_COOKIE}_{id}")
}

/// Only same-site paths are allowed after sign-in: the value is resolved
/// against a placeholder origin and must stay on it.
pub fn return_path(value: &str) -> String {
    same_site_path(value)
        .filter(|path| !path.contains(CALLBACK))
        .unwrap_or_else(|| "/".into())
}

pub fn same_site_path(value: &str) -> Option<String> {
    if !value.starts_with('/')
        || value.len() > 4096
        || value
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || c == '\\')
        || value[1..].starts_with('/')
    {
        return None;
    }
    let base = url::Url::parse("https://placeholder.invalid/").expect("base");
    let joined = base.join(value).ok()?;
    let path = format!(
        "{}{}",
        joined.path(),
        joined.query().map(|q| format!("?{q}")).unwrap_or_default()
    );
    // Dot segments can normalize "/.//evil.test" into a protocol-relative URL.
    (joined.origin() == base.origin() && !path[1..].starts_with(['/', '\\'])).then_some(path)
}

pub fn cookie<'a>(headers: &'a axum::http::HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|part| {
            part.trim()
                .strip_prefix(name)
                .and_then(|v| v.strip_prefix('='))
        })
}

// --------------------------------------------------------------- dashboard

#[derive(Deserialize)]
struct Begin {
    #[serde(default)]
    next: String,
}

fn dashboard_error(code: &str) -> axum::response::Response {
    axum::response::Redirect::to(&format!("/?sso_error={code}")).into_response()
}
use axum::response::IntoResponse;

fn state_cookie(state: &str, secure: bool) -> String {
    format!(
        "{STATE_COOKIE}={state}; HttpOnly; SameSite=Lax; Path=/; Max-Age={PENDING_SECONDS}{}",
        if secure { "; Secure" } else { "" }
    )
}
fn clear_state_cookie(secure: bool) -> String {
    format!(
        "{STATE_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0{}",
        if secure { "; Secure" } else { "" }
    )
}

async fn dashboard_begin(
    axum::extract::State(state): axum::extract::State<Shared>,
    axum::extract::Query(input): axum::extract::Query<Begin>,
) -> axum::response::Response {
    let Some(settings) = state.oidc.settings().filter(|s| s.dashboard_enabled) else {
        return dashboard_error("disabled");
    };
    let secure = settings.dashboard_origin.starts_with("https://");
    match state
        .oidc
        .begin(
            &state.trust,
            Target::Dashboard,
            settings.dashboard_redirect(),
            return_path(&input.next),
        )
        .await
    {
        Ok((location, flow)) => (
            [(axum::http::header::SET_COOKIE, state_cookie(&flow, secure))],
            axum::response::Redirect::to(&location),
        )
            .into_response(),
        Err(error) => {
            log::warn!("Dashboard single sign-on could not start: {error}");
            dashboard_error("provider")
        }
    }
}

#[derive(Deserialize)]
struct Callback {
    #[serde(default)]
    code: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    error: Option<String>,
}

async fn dashboard_callback(
    axum::extract::State(state): axum::extract::State<Shared>,
    peer: Option<axum::Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(input): axum::extract::Query<Callback>,
) -> axum::response::Response {
    let Some(settings) = state.oidc.settings().filter(|s| s.dashboard_enabled) else {
        return dashboard_error("disabled");
    };
    let secure = settings.dashboard_origin.starts_with("https://");
    let peer = peer
        .map(|p| p.0 .0.ip().to_string())
        .unwrap_or_else(|| "local".into());
    let fail = |code: &str| {
        (
            [(axum::http::header::SET_COOKIE, clear_state_cookie(secure))],
            dashboard_error(code),
        )
            .into_response()
    };
    if crate::accounts::limit_attempts(&state, &peer).is_err() {
        return fail("throttled");
    }
    if input.error.is_some() {
        return fail("cancelled");
    }
    let (identity, pending) = match state
        .oidc
        .finish(
            &state.trust,
            &input.state,
            &input.code,
            cookie(&headers, STATE_COOKIE),
            &settings.dashboard_redirect(),
        )
        .await
    {
        Ok(result) if result.1.target == Target::Dashboard => result,
        Ok(_) => return fail("expired"),
        Err(error) => {
            log::warn!("Dashboard single sign-on failed: {error}");
            return fail("rejected");
        }
    };
    // Only verified email addresses match accounts; other claims such as
    // preferred_username can often be changed by the user at the provider.
    // The environment recovery account never signs in this way.
    let name = identity
        .verified_email()
        .map(str::to_ascii_lowercase)
        .filter(|name| name != "admin");
    let account = match name.as_deref().map(crate::management::username) {
        Some(Ok(name)) => crate::accounts::credentials(&state, &name)
            .await
            .ok()
            .flatten(),
        _ => None,
    };
    let actor = crate::management::AuditActor {
        user_id: account
            .as_ref()
            .map(|a| a.user.id.clone())
            .unwrap_or_default(),
        username: name.clone().unwrap_or_else(|| identity.subject.clone()),
        role: account
            .as_ref()
            .map_or("unknown", |a| a.user.role.as_str())
            .into(),
        peer: peer.clone(),
        token: None,
    };
    let Some(account) = account.filter(|a| a.user.enabled) else {
        let _ = state
            .control
            .begin_audit(
                actor,
                "GET".into(),
                "/api/oidc/callback".into(),
                json!({"result":"no matching account"}),
            )
            .await;
        return fail("account");
    };
    let mfa_enabled = crate::mfa::enabled(&state, &account.user.id)
        .await
        .unwrap_or(true);
    if mfa_enabled && !settings.trust_provider_mfa {
        let _ = state
            .control
            .begin_audit(
                actor,
                "GET".into(),
                "/api/oidc/callback".into(),
                json!({"result":"two-factor required"}),
            )
            .await;
        return fail("mfa");
    }
    let token = uuid::Uuid::new_v4().to_string();
    {
        let mut sessions = state.sessions.lock().unwrap();
        sessions.retain(|_, s| s.expires > Instant::now());
        if sessions.len() >= 1000 {
            return fail("sessions");
        }
        let mut session = crate::accounts::Session::new(account.user.clone(), peer);
        session.mfa_verified = mfa_enabled;
        sessions.insert(token.clone(), session);
    }
    if let Ok(id) = state
        .control
        .begin_audit(
            actor,
            "GET".into(),
            "/api/oidc/callback".into(),
            json!({"provider":settings.name}),
        )
        .await
    {
        let _ = state
            .control
            .finish_audit(id, 200, None, json!({"provider":settings.name}), None)
            .await;
    }
    let session_cookie = format!(
        "gateway_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200{}",
        if state.secure_cookie || secure {
            "; Secure"
        } else {
            ""
        }
    );
    let mut response = axum::http::StatusCode::SEE_OTHER.into_response();
    let headers = response.headers_mut();
    for (name, value) in [
        (axum::http::header::SET_COOKIE, session_cookie),
        (axum::http::header::SET_COOKIE, clear_state_cookie(secure)),
        (
            axum::http::header::LOCATION,
            format!("/{}", pending.return_to.trim_start_matches('/')),
        ),
    ] {
        if let Ok(value) = value.parse() {
            headers.append(name, value);
        }
    }
    response
}

async fn public_status(
    axum::extract::State(state): axum::extract::State<Shared>,
) -> axum::Json<Value> {
    let settings = state.oidc.settings().filter(|s| s.dashboard_enabled);
    axum::Json(json!({"dashboard": settings.is_some(), "name": settings.map(|s| s.name)}))
}

/// Unauthenticated routes: the sign-in button's status, start, and callback.
pub fn public_routes() -> axum::Router<Shared> {
    axum::Router::new()
        .route("/api/oidc/status", axum::routing::get(public_status))
        .route("/api/oidc/login", axum::routing::get(dashboard_begin))
        .route("/api/oidc/callback", axum::routing::get(dashboard_callback))
}

// ------------------------------------------------------------ management

fn summary(state: &Shared) -> Value {
    let provider = state.oidc.provider.load();
    match provider.as_ref() {
        Some(p) => {
            json!({"configured": true, "settings": p.settings, "secret_configured": !p.secret.is_empty(), "dashboard_redirect_uri": p.settings.dashboard_redirect(), "host_callback_path": CALLBACK})
        }
        None => json!({"configured": false, "host_callback_path": CALLBACK}),
    }
}

async fn status(axum::extract::State(state): axum::extract::State<Shared>) -> axum::Json<Value> {
    axum::Json(summary(&state))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Save {
    #[serde(flatten)]
    settings: Settings,
    #[serde(default)]
    client_secret: Option<String>,
}

type ApiError = (axum::http::StatusCode, axum::Json<Value>);
fn api_error(status: axum::http::StatusCode, message: impl ToString) -> ApiError {
    (status, axum::Json(json!({"error": message.to_string()})))
}

async fn save(
    axum::extract::State(state): axum::extract::State<Shared>,
    axum::Json(input): axum::Json<Save>,
) -> Result<axum::Json<Value>, ApiError> {
    let invalid = |e: String| api_error(axum::http::StatusCode::UNPROCESSABLE_ENTITY, e);
    let unavailable = |e: String| api_error(axum::http::StatusCode::SERVICE_UNAVAILABLE, e);
    let mut settings = input.settings;
    settings.normalize();
    settings.validate().map_err(invalid)?;
    let current = state.oidc.provider.load_full();
    let secret = match input
        .client_secret
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
    {
        Some(secret) if secret.len() <= 1024 && !secret.chars().any(char::is_control) => secret,
        Some(_) => {
            return Err(invalid(
                "Enter the client secret from your provider.".into(),
            ))
        }
        None => current
            .as_ref()
            .as_ref()
            .map(|p| p.secret.clone())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| invalid("Enter the client secret from your provider.".into()))?,
    };
    // Check discovery before saving, so mistakes surface now.
    let probe = Oidc::default();
    probe.provider.store(Arc::new(Some(Provider {
        settings: settings.clone(),
        secret: secret.clone(),
    })));
    probe
        .metadata(&settings, &state.trust, false)
        .await
        .map_err(invalid)?;
    let changed_provider = current.as_ref().as_ref().is_none_or(|p| {
        p.settings.issuer != settings.issuer || p.settings.client_id != settings.client_id
    });
    state
        .control
        .set_secret(
            SETTINGS.into(),
            Some(serde_json::to_string(&settings).expect("settings")),
        )
        .await
        .map_err(unavailable)?;
    state
        .control
        .set_secret(CLIENT_SECRET.into(), Some(secret.clone()))
        .await
        .map_err(unavailable)?;
    let key = if changed_provider {
        let key = random(32);
        state
            .control
            .set_secret(SESSION_KEY.into(), Some(b64url_encode(&key)))
            .await
            .map_err(unavailable)?;
        key
    } else {
        state.oidc.session_key.load().to_vec()
    };
    *state.oidc.cache.lock().await = None;
    state.oidc.replace(Some(Provider { settings, secret }), key);
    Ok(axum::Json(summary(&state)))
}

async fn remove(
    axum::extract::State(state): axum::extract::State<Shared>,
) -> Result<axum::Json<Value>, ApiError> {
    let unavailable = |e: String| api_error(axum::http::StatusCode::SERVICE_UNAVAILABLE, e);
    if state.config.load().routes.iter().any(|r| r.oidc.is_some()) {
        return Err(api_error(
            axum::http::StatusCode::CONFLICT,
            "Turn off single sign-on on every host before removing the provider.",
        ));
    }
    state
        .control
        .set_secret(SETTINGS.into(), None)
        .await
        .map_err(unavailable)?;
    state
        .control
        .set_secret(CLIENT_SECRET.into(), None)
        .await
        .map_err(unavailable)?;
    let key = random(32);
    state
        .control
        .set_secret(SESSION_KEY.into(), Some(b64url_encode(&key)))
        .await
        .map_err(unavailable)?;
    *state.oidc.cache.lock().await = None;
    state.oidc.replace(None, key);
    Ok(axum::Json(summary(&state)))
}

pub fn routes() -> axum::Router<Shared> {
    axum::Router::new().route(
        "/api/integrations/oidc",
        axum::routing::get(status).put(save).delete(remove),
    )
}

pub fn validate_backup(key: &str, value: &str) -> Result<(), String> {
    match key {
        SETTINGS => {
            let settings: Settings =
                serde_json::from_str(value).map_err(|_| "Invalid OIDC settings.".to_owned())?;
            settings.validate()
        }
        CLIENT_SECRET if !value.is_empty() && value.len() <= 1024 => Ok(()),
        SESSION_KEY if b64url_decode(value).is_some_and(|k| k.len() == 32) => Ok(()),
        _ => Err("Invalid OIDC credential.".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::{ec::EcKey, pkey::Private, sign::Signer};

    fn jwt(alg: &str, kid: &str, key: &PKey<Private>, claims: &Value) -> String {
        let header = b64url_encode(
            json!({"alg": alg, "kid": kid, "typ": "JWT"})
                .to_string()
                .as_bytes(),
        );
        let payload = b64url_encode(claims.to_string().as_bytes());
        let input = format!("{header}.{payload}");
        let signature = if alg.starts_with("ES") {
            let hash = openssl::hash::hash(MessageDigest::sha256(), input.as_bytes()).unwrap();
            let sig = EcdsaSig::sign(&hash, &key.ec_key().unwrap()).unwrap();
            let pad = |n: &openssl::bn::BigNumRef| n.to_vec_padded(32).unwrap();
            [pad(sig.r()), pad(sig.s())].concat()
        } else {
            let mut signer = Signer::new(MessageDigest::sha256(), key).unwrap();
            if alg == "PS256" {
                signer.set_rsa_padding(Padding::PKCS1_PSS).unwrap();
                signer
                    .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
                    .unwrap();
            }
            signer.update(input.as_bytes()).unwrap();
            signer.sign_to_vec().unwrap()
        };
        format!("{input}.{}", b64url_encode(&signature))
    }

    fn rsa_jwk(key: &PKey<Private>, kid: &str) -> Value {
        let rsa = key.rsa().unwrap();
        json!({"kty":"RSA","kid":kid,"use":"sig","n":b64url_encode(&rsa.n().to_vec()),"e":b64url_encode(&rsa.e().to_vec())})
    }

    fn claims(now: u64) -> Value {
        json!({"iss":"https://id.example.com","aud":"embergate","sub":"user-1","email":"Ada@Example.com","email_verified":true,"groups":["admins","staff"],"nonce":"n-1","exp":now+300,"iat":now})
    }

    #[test]
    fn id_tokens_verify_signature_and_claims() {
        let now = 1_800_000_000;
        let rsa = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let ec = PKey::from_ec_key(
            EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap(),
        )
        .unwrap();
        let point = ec.ec_key().unwrap();
        let mut ctx = openssl::bn::BigNumContext::new().unwrap();
        let (mut x, mut y) = (BigNum::new().unwrap(), BigNum::new().unwrap());
        point
            .public_key()
            .affine_coordinates(point.group(), &mut x, &mut y, &mut ctx)
            .unwrap();
        let jwks = json!({"keys":[rsa_jwk(&rsa,"r1"),{"kty":"EC","kid":"e1","crv":"P-256","x":b64url_encode(&x.to_vec_padded(32).unwrap()),"y":b64url_encode(&y.to_vec_padded(32).unwrap())}]});
        let check = |token: &str| {
            validate_id_token(
                token,
                &jwks,
                "https://id.example.com",
                "embergate",
                "n-1",
                now,
            )
        };
        for (alg, kid, key) in [
            ("RS256", "r1", &rsa),
            ("PS256", "r1", &rsa),
            ("ES256", "e1", &ec),
        ] {
            assert_eq!(
                check(&jwt(alg, kid, key, &claims(now))).unwrap()["sub"],
                "user-1",
                "{alg}"
            );
        }
        let rejected = |mutate: &dyn Fn(&mut Value), why: &str| {
            let mut c = claims(now);
            mutate(&mut c);
            let error = check(&jwt("RS256", "r1", &rsa, &c)).unwrap_err();
            assert!(error.contains(why), "{why}: {error}");
        };
        rejected(&|c| c["iss"] = json!("https://evil.test"), "issuer");
        rejected(&|c| c["aud"] = json!("other"), "another client");
        rejected(
            &|c| c["aud"] = json!(["embergate", "other"]),
            "another client",
        );
        rejected(&|c| c["exp"] = json!(now - 61), "expired");
        rejected(&|c| c["iat"] = json!(now + 600), "not valid yet");
        rejected(&|c| c["nonce"] = json!("n-2"), "nonce");
        rejected(
            &|c| {
                c.as_object_mut().unwrap().remove("nonce");
            },
            "nonce",
        );
        let mut multi = claims(now);
        multi["aud"] = json!(["embergate", "other"]);
        multi["azp"] = json!("embergate");
        assert!(
            check(&jwt("RS256", "r1", &rsa, &multi)).is_ok(),
            "azp names this client"
        );
        let token = jwt("RS256", "r1", &rsa, &claims(now));
        let (head, rest) = token.split_once('.').unwrap();
        let tampered = format!(
            "{head}.{}{}",
            b64url_encode(
                claims(now)
                    .to_string()
                    .replace("user-1", "user-2")
                    .as_bytes()
            ),
            &rest[rest.find('.').unwrap()..]
        );
        assert!(check(&tampered).unwrap_err().contains("signature"));
        let none = format!(
            "{}.{}.",
            b64url_encode(br#"{"alg":"none"}"#),
            b64url_encode(claims(now).to_string().as_bytes())
        );
        assert!(check(&none).is_err(), "unsigned tokens are refused");
        let other = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        assert!(
            check(&jwt("RS256", "r1", &other, &claims(now))).is_err(),
            "wrong key"
        );
        assert!(
            check(&jwt("RS256", "unknown", &rsa, &claims(now))).is_err(),
            "unknown key ID"
        );
        let hs = format!(
            "{}.{}.{}",
            b64url_encode(br#"{"alg":"HS256","kid":"r1"}"#),
            b64url_encode(claims(now).to_string().as_bytes()),
            b64url_encode(b"x")
        );
        assert!(check(&hs).is_err(), "symmetric algorithms are refused");
    }

    #[test]
    fn identities_and_rules() {
        let identity = Identity::from_claims(&claims(1), "groups").unwrap();
        assert_eq!(identity.verified_email(), Some("Ada@Example.com"));
        assert_eq!(identity.groups, ["admins", "staff"]);
        let mut unverified = identity.clone();
        unverified.email_verified = false;
        let mut policy = HostPolicy {
            allowed_emails: vec![" ADA@example.com ".into()],
            ..HostPolicy::default()
        };
        policy.validate().unwrap();
        assert!(
            policy.admits(&identity) && !policy.admits(&unverified),
            "emails count only when verified"
        );
        let mut domains = HostPolicy {
            allowed_domains: vec!["@example.com".into()],
            ..HostPolicy::default()
        };
        domains.validate().unwrap();
        assert!(domains.admits(&identity));
        let groups = HostPolicy {
            allowed_groups: vec!["staff".into()],
            ..HostPolicy::default()
        };
        assert!(groups.admits(&unverified));
        assert!(
            !HostPolicy {
                allowed_groups: vec!["Staff".into()],
                ..HostPolicy::default()
            }
            .admits(&identity),
            "groups are case-sensitive"
        );
        assert!(
            HostPolicy::default().admits(&unverified),
            "no rules admits every signed-in account"
        );
        for bad in [
            HostPolicy {
                allowed_emails: vec!["nobody".into()],
                ..HostPolicy::default()
            },
            HostPolicy {
                allowed_domains: vec!["exa mple.com".into()],
                ..HostPolicy::default()
            },
            HostPolicy {
                session_hours: 0,
                ..HostPolicy::default()
            },
            HostPolicy {
                session_hours: 169,
                ..HostPolicy::default()
            },
        ] {
            assert!(bad.clone().validate().is_err(), "{bad:?}");
        }
        assert_eq!(
            Identity::from_claims(&json!({"sub":"x","groups":"one"}), "groups")
                .unwrap()
                .groups,
            ["one"]
        );
        assert!(Identity::from_claims(&json!({}), "groups").is_err());
    }

    #[test]
    fn host_cookies_are_sealed_per_route_and_host() {
        let oidc = Oidc::default();
        oidc.session_key.store(Arc::new(random(32)));
        let identity = Identity {
            subject: "user-1".into(),
            ..Identity::default()
        };
        let sealed = oidc.seal("route-a", "app.test", &identity, 1);
        assert_eq!(oidc.open(&sealed, "route-a", "app.test"), Some(identity));
        assert_eq!(oidc.open(&sealed, "route-b", "app.test"), None);
        assert_eq!(oidc.open(&sealed, "route-a", "other.test"), None);
        let mut bytes = b64url_decode(&sealed).unwrap();
        bytes[20] ^= 1;
        assert_eq!(
            oidc.open(&b64url_encode(&bytes), "route-a", "app.test"),
            None,
            "tampering is detected"
        );
        let other = Oidc::default();
        other.session_key.store(Arc::new(random(32)));
        assert_eq!(
            other.open(&sealed, "route-a", "app.test"),
            None,
            "a new key signs everyone out"
        );
        assert_eq!(
            host_cookie_name("3f2a-91bc-77de-0000"),
            "embergate_oidc_3f2a91bc77de"
        );
        assert_eq!(return_path("/photos?x=1"), "/photos?x=1");
        assert_eq!(
            return_path("/%2F/evil.test"),
            "/%2F/evil.test",
            "an encoded slash stays on this site"
        );
        for bad in [
            "https://evil.test",
            "//evil.test",
            "/\\evil",
            "/app/.well-known/embergate/oidc/callback?code=1",
            "/a\\b",
            "/.//evil.test",
            "/x/..//evil.test",
            "/./\\evil.test",
            "/\tx",
            "/ a",
            "/\u{0}x",
        ] {
            assert_eq!(return_path(bad), "/", "{bad}");
        }
    }

    #[test]
    fn settings_validation() {
        let mut settings = Settings {
            name: "Authentik".into(),
            issuer: "https://id.example.com/application/o/embergate/".into(),
            client_id: "embergate".into(),
            scopes: vec!["email".into()],
            groups_claim: "groups".into(),
            dashboard_enabled: true,
            dashboard_origin: "https://gateway.example.com/".into(),
            trust_provider_mfa: false,
        };
        settings.normalize();
        settings.validate().unwrap();
        assert_eq!(settings.scopes, ["openid", "email"]);
        assert_eq!(
            settings.dashboard_redirect(),
            "https://gateway.example.com/api/oidc/callback"
        );
        for mutate in [
            (|s: &mut Settings| s.issuer = "http://id.example.com".into()) as fn(&mut Settings),
            |s| s.client_id = "has space".into(),
            |s| s.dashboard_origin = "https://gateway.example.com/path".into(),
            |s| s.name = String::new(),
        ] {
            let mut bad = settings.clone();
            mutate(&mut bad);
            assert!(bad.validate().is_err(), "{bad:?}");
        }
        let mut local = settings.clone();
        local.issuer = "http://127.0.0.1:5556".into();
        local.dashboard_origin = "http://localhost:9090".into();
        assert!(
            local.validate().is_ok(),
            "HTTP is allowed for local testing"
        );
    }
}

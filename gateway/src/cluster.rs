//! Single-writer replication. Followers never renew certificates or accept shared-state edits.
use crate::{
    accounts::Session,
    certificates::{CertificateStore, StoredCertificate},
    config::Config,
    state::{now, Shared},
};
use async_trait::async_trait;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Extension, Json, Router,
};
use openssl::symm::{decrypt_aead, encrypt_aead, Cipher};
use pingora::{server::ShutdownWatch, services::background::BackgroundService};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::{Arc, LazyLock, Mutex},
    time::{Duration, Instant},
};
const MAX: usize = 40 * 1024 * 1024;
const AAD: &[u8] = b"EmberGate cluster v1";
const JOURNAL: &str = "cluster-pending.json";
type Error = (StatusCode, Json<Value>);
fn error(status: StatusCode, message: impl ToString) -> Error {
    (status, Json(json!({"error":message.to_string()})))
}
fn unavailable(message: String) -> Error {
    error(StatusCode::SERVICE_UNAVAILABLE, message)
}
fn invalid(message: impl ToString) -> Error {
    error(StatusCode::UNPROCESSABLE_ENTITY, message)
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    #[default]
    Standalone,
    Primary,
    Follower,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub role: Role,
    pub peer_url: Option<String>,
    pub expected_primary_id: Option<String>,
    pub interval_seconds: u64,
    pub stale_after_seconds: u64,
    pub version: u64,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            role: Role::Standalone,
            peer_url: None,
            expected_primary_id: None,
            interval_seconds: 5,
            stale_after_seconds: 300,
            version: 0,
        }
    }
}
impl Settings {
    fn validate(&mut self) -> Result<(), String> {
        if !(2..=60).contains(&self.interval_seconds)
            || !(10..=3600).contains(&self.stale_after_seconds)
            || self.stale_after_seconds < self.interval_seconds * 2
        {
            return Err("Use a 2–60 second sync interval and a 10–3600 second stale limit of at least two intervals.".into());
        }
        if self.role == Role::Follower {
            let url = url::Url::parse(self.peer_url.as_deref().unwrap_or(""))
                .map_err(|_| "Enter the primary management HTTP/HTTPS origin.")?;
            if !matches!(url.scheme(), "http" | "https")
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
                || url.path() != "/"
            {
                return Err(
                    "Use an HTTP/HTTPS origin without a path, query, or credentials.".into(),
                );
            }
            self.peer_url = Some(url.origin().ascii_serialization());
            uuid(self.expected_primary_id.as_deref().unwrap_or(""))?;
        } else {
            self.peer_url = None;
            self.expected_primary_id = None;
        }
        Ok(())
    }
}
fn uuid(value: &str) -> Result<(), String> {
    uuid::Uuid::parse_str(value)
        .map(|_| ())
        .map_err(|_| "Invalid instance identity.".into())
}
fn settings(state: &Shared) -> Result<Settings, String> {
    let mut value: Settings = state
        .control
        .secret("cluster_settings")?
        .map(|v| serde_json::from_str(&v).map_err(|_| "Invalid cluster settings."))
        .transpose()?
        .unwrap_or_default();
    value.validate()?;
    Ok(value)
}
fn token(value: &str) -> Result<(), String> {
    if value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err("Use the 64-character shared token generated on the primary.".into())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    source: String,
    generation: u64,
    fingerprint: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    format: u8,
    source: String,
    generation: u64,
    fingerprint: String,
    issued_at: u64,
    nonce: String,
    config: Option<Config>,
    certificates: Option<Vec<StoredCertificate>>,
}
struct Runtime {
    instance: String,
    settings: Settings,
    last_attempt: Option<Instant>,
    last_success: Option<Instant>,
    last_success_at: Option<u64>,
    error: Option<String>,
    received: Option<Receipt>,
    force: bool,
    peers: HashMap<String, u64>,
}
static RUNTIMES: LazyLock<Mutex<HashMap<PathBuf, Arc<Mutex<Runtime>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
fn runtime(state: &Shared) -> Option<Arc<Mutex<Runtime>>> {
    RUNTIMES.lock().unwrap().get(&state.config_path).cloned()
}
fn root(state: &Shared) -> &Path {
    state.config_path.parent().unwrap()
}
fn read(path: &Path) -> Result<Vec<u8>, String> {
    let meta = fs::symlink_metadata(path).map_err(|_| "Cannot read replication state.")?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > MAX as u64 {
        return Err("Invalid replication state file.".into());
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .and_then(|f| f.take(MAX as u64 + 1).read_to_end(&mut bytes))
        .map_err(|_| "Cannot read replication state.")?;
    if bytes.len() > MAX {
        return Err("Replication state is too large.".into());
    }
    Ok(bytes)
}
fn write(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let bytes = serde_json::to_vec(value).map_err(|_| "Cannot serialize replication state.")?;
    if bytes.len() > MAX {
        return Err("Replication state is too large.".into());
    }
    crate::history::write_atomic(path, &bytes)
        .map_err(|_| "Cannot persist replication state.".into())
}
fn digest(config: &Config, certs: &[StoredCertificate]) -> Result<String, String> {
    Ok(openssl::sha::sha256(
        &serde_json::to_vec(&(config, certs)).map_err(|_| "Cannot encode replication state.")?,
    )
    .iter()
    .map(|b| format!("{b:02x}"))
    .collect())
}
fn validate(snapshot: &mut Snapshot) -> Result<CertificateStore, String> {
    uuid(&snapshot.source)?;
    uuid(&snapshot.nonce)?;
    if snapshot.format != 1
        || snapshot.generation == 0
        || snapshot.fingerprint.len() != 64
        || !snapshot.fingerprint.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err("Invalid replication snapshot metadata.".into());
    }
    let config = snapshot
        .config
        .as_mut()
        .ok_or("Replication snapshot is incomplete.")?;
    config.validate()?;
    let certs = snapshot
        .certificates
        .as_ref()
        .ok_or("Replication snapshot is incomplete.")?;
    if digest(config, certs)? != snapshot.fingerprint {
        return Err("Replication fingerprint does not match its data.".into());
    }
    CertificateStore::parse(certs.clone())
}
fn receipt(snapshot: &Snapshot) -> Receipt {
    Receipt {
        source: snapshot.source.clone(),
        generation: snapshot.generation,
        fingerprint: snapshot.fingerprint.clone(),
    }
}
fn apply_files(root: &Path, snapshot: &Snapshot) -> Result<(), String> {
    write(
        &root.join("certificates.json"),
        snapshot
            .certificates
            .as_ref()
            .ok_or("Missing certificates.")?,
    )?;
    write(
        &root.join("routes.json"),
        snapshot.config.as_ref().ok_or("Missing configuration.")?,
    )?;
    write(&root.join("cluster-received.json"), &receipt(snapshot))?;
    fs::remove_file(root.join(JOURNAL)).map_err(|_| "Cannot finalize replication journal.")?;
    fs::File::open(root)
        .and_then(|f| f.sync_all())
        .map_err(|_| "Cannot sync replication directory.")?;
    Ok(())
}
pub fn recover(root: &Path) -> Result<(), String> {
    if root.join(JOURNAL).exists() {
        let mut snapshot: Snapshot = serde_json::from_slice(&read(&root.join(JOURNAL))?)
            .map_err(|_| "Invalid replication journal.")?;
        validate(&mut snapshot)?;
        apply_files(root, &snapshot)?;
    }
    Ok(())
}
pub fn initialize(state: &Shared) -> Result<(), String> {
    let path = root(state).join("instance-id");
    let instance = if path.exists() {
        String::from_utf8(read(&path)?).map_err(|_| "Invalid instance identity.")?
    } else {
        let id = uuid::Uuid::new_v4().to_string();
        crate::history::write_atomic(&path, id.as_bytes())
            .map_err(|_| "Cannot save instance identity.")?;
        id
    };
    uuid(&instance)?;
    let settings = settings(state)?;
    let received = if root(state).join("cluster-received.json").exists() {
        let receipt: Receipt =
            serde_json::from_slice(&read(&root(state).join("cluster-received.json"))?)
                .map_err(|_| "Invalid received replication state.")?;
        uuid(&receipt.source)?;
        if digest(&state.config.load(), &state.certificates.load().records())?
            == receipt.fingerprint
        {
            Some(receipt)
        } else {
            None
        }
    } else {
        None
    };
    RUNTIMES.lock().unwrap().insert(
        state.config_path.clone(),
        Arc::new(Mutex::new(Runtime {
            instance,
            settings,
            last_attempt: None,
            last_success: None,
            last_success_at: None,
            error: None,
            received,
            force: true,
            peers: HashMap::new(),
        })),
    );
    Ok(())
}
pub fn role(state: &Shared) -> Role {
    runtime(state).map_or(Role::Standalone, |r| r.lock().unwrap().settings.role)
}
pub fn follower(state: &Shared) -> bool {
    runtime(state).is_some_and(|r| r.lock().unwrap().settings.role == Role::Follower)
}
pub fn ready(state: &Shared) -> bool {
    runtime(state).is_none_or(|r| {
        let r = r.lock().unwrap();
        r.settings.role != Role::Follower
            || r.last_success.is_some_and(|last| {
                last.elapsed() < Duration::from_secs(r.settings.stale_after_seconds)
            })
    })
}
pub fn shared_write(path: &str) -> bool {
    path == "/api/config"
        || path == "/api/credentials/cloudflare"
        || path == "/api/credentials/dns"
        || path.starts_with("/api/certificates")
        || path.starts_with("/api/acme/")
        || path.starts_with("/api/host-templates")
        || path.starts_with("/api/config/history/")
}
pub async fn health(State(state): State<Shared>) -> Response {
    (
        if ready(&state) {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        Json(json!({"ready":ready(&state)})),
    )
        .into_response()
}
async fn status(State(state): State<Shared>) -> Result<Json<Value>, Error> {
    let r = runtime(&state)
        .ok_or_else(|| unavailable("Instance synchronization is unavailable.".into()))?;
    let r = r.lock().unwrap();
    Ok(Json(
        json!({"instance_id":r.instance,"settings":r.settings,"token_configured":state.control.secret("cluster_token").map_err(unavailable)?.is_some(),"ready":r.settings.role!=Role::Follower||r.last_success.is_some_and(|last|last.elapsed()<Duration::from_secs(r.settings.stale_after_seconds)),"last_success_at":r.last_success_at,"last_error":r.error,"received":r.received,"followers":r.peers.iter().map(|(id,last)|json!({"instance_id":id,"last_seen":last})).collect::<Vec<_>>()}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configure {
    settings: Settings,
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    confirm_replace: bool,
    current_password: String,
    #[serde(default)]
    code: String,
}
async fn proof(
    state: &Shared,
    session: &Session,
    password: String,
    code: String,
) -> Result<(), Error> {
    let factor = crate::mfa::enabled(state, &session.user.id)
        .await
        .map_err(unavailable)?;
    crate::mfa::prove(
        state,
        session,
        &crate::mfa::Proof {
            current_password: password,
            code,
        },
        factor,
    )
    .await
}
async fn configure(
    State(state): State<Shared>,
    Extension(session): Extension<Session>,
    Json(mut input): Json<Configure>,
) -> Result<Json<Value>, Error> {
    let _account = state.account_write_lock.lock().await;
    proof(&state, &session, input.current_password, input.code).await?;
    input.settings.validate().map_err(invalid)?;
    let old = settings(&state).map_err(unavailable)?;
    if input.settings.version != old.version {
        return Err(error(
            StatusCode::CONFLICT,
            "Instance settings changed. Refresh and try again.",
        ));
    }
    let replacing = input.settings.role == Role::Follower
        && (old.role != Role::Follower
            || old.expected_primary_id != input.settings.expected_primary_id);
    if replacing && !input.confirm_replace {
        return Err(error(
            StatusCode::CONFLICT,
            "Confirm replacement of this node's routes and certificates before joining a primary.",
        ));
    }
    if let Some(value) = &mut input.token {
        *value = value.trim().to_owned();
        token(value).map_err(invalid)?;
    }
    if input.settings.role == Role::Follower
        && input.token.is_none()
        && state
            .control
            .secret("cluster_token")
            .map_err(unavailable)?
            .is_none()
    {
        return Err(invalid("Enter the shared token generated by the primary."));
    }
    let _acme = state.acme.backup_guard().await.map_err(invalid)?;
    let _write = state.write_lock.lock().await;
    if root(&state).join(JOURNAL).exists() {
        return Err(error(StatusCode::CONFLICT,"A replication journal is pending. Let synchronization finish or restart before changing roles."));
    }
    let reset_receipt = old.expected_primary_id != input.settings.expected_primary_id;
    if reset_receipt {
        let path = root(&state).join("cluster-received.json");
        if path.exists() {
            fs::remove_file(path).map_err(|_| invalid("Cannot reset replication receipt."))?;
        }
    }
    input.settings.version = old.version.saturating_add(1);
    let saved = serde_json::to_string(&input.settings).unwrap();
    let replacement_token = input.token.clone();
    state.control.run(move |db| {
        let tx=db.transaction().map_err(crate::management::storage)?;
        if let Some(value)=replacement_token { tx.execute("INSERT INTO secrets VALUES('cluster_token',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",[value]).map_err(crate::management::storage)?; }
        tx.execute("INSERT INTO secrets VALUES('cluster_settings',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",[saved]).map_err(crate::management::storage)?;
        tx.commit().map_err(crate::management::storage)?;
        Ok(())
    }).await.map_err(unavailable)?;
    let r = runtime(&state).ok_or_else(|| unavailable("Instance state is unavailable.".into()))?;
    let mut r = r.lock().unwrap();
    if old.role != input.settings.role
        || old.peer_url != input.settings.peer_url
        || old.expected_primary_id != input.settings.expected_primary_id
        || input.token.is_some()
    {
        r.last_success = None;
        r.last_success_at = None;
        r.error = None;
    }
    if reset_receipt {
        r.received = None;
    }
    r.settings = input.settings;
    r.force = true;
    Ok(Json(json!({"ok":true})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Rotate {
    current_password: String,
    #[serde(default)]
    code: String,
}
async fn rotate(
    State(state): State<Shared>,
    Extension(session): Extension<Session>,
    Json(input): Json<Rotate>,
) -> Result<Json<Value>, Error> {
    let _account = state.account_write_lock.lock().await;
    proof(&state, &session, input.current_password, input.code).await?;
    let _write = state.write_lock.lock().await;
    if settings(&state).map_err(unavailable)?.role != Role::Primary {
        return Err(invalid(
            "Configure this instance as primary before generating a token.",
        ));
    }
    let mut bytes = [0u8; 32];
    openssl::rand::rand_bytes(&mut bytes).map_err(|_| invalid("Random generator unavailable."))?;
    let token: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    state
        .control
        .set_secret("cluster_token".into(), Some(token.clone()))
        .await
        .map_err(unavailable)?;
    if let Some(r) = runtime(&state) {
        r.lock().unwrap().peers.clear();
    }
    Ok(Json(json!({"token":token})))
}
async fn synchronize_now(State(state): State<Shared>) -> Result<Json<Value>, Error> {
    let r = runtime(&state).ok_or_else(|| unavailable("Instance state is unavailable.".into()))?;
    let mut r = r.lock().unwrap();
    if r.settings.role != Role::Follower {
        return Err(invalid("Only followers pull shared state."));
    }
    r.force = true;
    Ok(Json(json!({"queued":true})))
}
fn seal(value: &Snapshot, token: &str) -> Result<Vec<u8>, String> {
    let bytes = serde_json::to_vec(value).map_err(|_| "Cannot encode snapshot.")?;
    if bytes.len() > MAX {
        return Err("Snapshot is too large.".into());
    }
    let key = openssl::sha::sha256(token.as_bytes());
    let mut nonce = [0u8; 12];
    openssl::rand::rand_bytes(&mut nonce).map_err(|_| "Random generator unavailable.")?;
    let mut tag = [0u8; 16];
    let cipher = encrypt_aead(
        Cipher::aes_256_gcm(),
        &key,
        Some(&nonce),
        AAD,
        &bytes,
        &mut tag,
    )
    .map_err(|_| "Cannot encrypt snapshot.")?;
    Ok([nonce.to_vec(), tag.to_vec(), cipher].concat())
}
fn open(bytes: &[u8], token: &str) -> Result<Snapshot, String> {
    if bytes.len() < 28 || bytes.len() > MAX + 28 {
        return Err("Invalid encrypted snapshot size.".into());
    }
    let key = openssl::sha::sha256(token.as_bytes());
    let plain = decrypt_aead(
        Cipher::aes_256_gcm(),
        &key,
        Some(&bytes[..12]),
        AAD,
        &bytes[28..],
        &bytes[12..28],
    )
    .map_err(|_| "Snapshot authentication failed.")?;
    serde_json::from_slice(&plain).map_err(|_| "Invalid snapshot data.".into())
}
pub async fn snapshot(State(state): State<Shared>, headers: HeaderMap) -> Result<Response, Error> {
    static CAPACITY: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);
    let _permit = CAPACITY.try_acquire().map_err(|_| {
        error(
            StatusCode::TOO_MANY_REQUESTS,
            "Replication capacity is busy.",
        )
    })?;
    let _write = state.write_lock.lock().await;
    if settings(&state).map_err(unavailable)?.role != Role::Primary
        || state
            .backups
            .pending
            .load(std::sync::atomic::Ordering::SeqCst)
    {
        return Err(error(
            StatusCode::SERVICE_UNAVAILABLE,
            "This instance is not an available primary.",
        ));
    }
    let token = state
        .control
        .secret("cluster_token")
        .map_err(unavailable)?
        .ok_or_else(|| error(StatusCode::UNAUTHORIZED, "Synchronization token required."))?;
    let supplied = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    if !openssl::memcmp::eq(
        &openssl::sha::sha256(token.as_bytes()),
        &openssl::sha::sha256(supplied.as_bytes()),
    ) {
        return Err(error(
            StatusCode::UNAUTHORIZED,
            "Synchronization token required.",
        ));
    }
    let r = runtime(&state).ok_or_else(|| unavailable("Instance state is unavailable.".into()))?;
    let source = r.lock().unwrap().instance.clone();
    let config = (**state.config.load()).clone();
    let certs = state.certificates.load().records();
    let fingerprint = digest(&config, &certs).map_err(unavailable)?;
    let path = root(&state).join("cluster-generation.json");
    let previous: Option<Receipt> = if path.exists() {
        Some(
            serde_json::from_slice(&read(&path).map_err(unavailable)?)
                .map_err(|_| invalid("Invalid primary generation state."))?,
        )
    } else {
        None
    };
    let generation = previous.as_ref().map_or(1, |old| {
        old.generation
            .saturating_add(u64::from(old.fingerprint != fingerprint))
    });
    if previous
        .as_ref()
        .is_none_or(|old| old.fingerprint != fingerprint)
    {
        write(
            &path,
            &Receipt {
                source: source.clone(),
                generation,
                fingerprint: fingerprint.clone(),
            },
        )
        .map_err(unavailable)?;
    }
    let known = headers
        .get("x-embergate-known")
        .and_then(|h| h.to_str().ok())
        == Some(&format!("{generation}:{fingerprint}"));
    let nonce = headers
        .get("x-embergate-challenge")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| invalid("Synchronization challenge required."))?;
    uuid(nonce).map_err(invalid)?;
    let payload = Snapshot {
        format: 1,
        source,
        generation,
        fingerprint,
        issued_at: now(),
        nonce: nonce.to_string(),
        config: if known { None } else { Some(config) },
        certificates: if known { None } else { Some(certs) },
    };
    if let Some(instance) = headers
        .get("x-embergate-instance")
        .and_then(|v| v.to_str().ok())
        .filter(|v| uuid(v).is_ok())
    {
        let mut r = r.lock().unwrap();
        r.peers.retain(|_, last| now().saturating_sub(*last) < 3600);
        if r.peers.len() < 100 || r.peers.contains_key(instance) {
            r.peers.insert(instance.into(), now());
        }
    }
    Ok((
        [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
        seal(&payload, &token).map_err(unavailable)?,
    )
        .into_response())
}
async fn pull(state: &Shared, captured: &Settings) -> Result<(), String> {
    let token = state
        .control
        .secret("cluster_token")?
        .ok_or("Synchronization token is missing.")?;
    let r = runtime(state).ok_or("Instance state is unavailable.")?;
    let (instance, received) = {
        let r = r.lock().unwrap();
        (r.instance.clone(), r.received.clone())
    };
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|_| "Cannot initialize synchronization transport.")?;
    let nonce = uuid::Uuid::new_v4().to_string();
    let mut request = client
        .get(format!(
            "{}/api/cluster/snapshot",
            captured
                .peer_url
                .as_deref()
                .ok_or("Primary origin is missing.")?
        ))
        .bearer_auth(&token)
        .header("x-embergate-instance", &instance)
        .header("x-embergate-challenge", &nonce);
    if let Some(received) = &received {
        request = request.header(
            "x-embergate-known",
            format!("{}:{}", received.generation, received.fingerprint),
        );
    }
    let mut response = request
        .send()
        .await
        .map_err(|_| "Cannot reach the primary; check its address, TLS, and connectivity.")?;
    if !response.status().is_success() {
        return Err("Primary rejected synchronization; check role and shared token.".into());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "Cannot read primary snapshot.")?
    {
        if bytes.len() + chunk.len() > MAX + 28 {
            return Err("Primary snapshot is too large.".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    let mut snapshot = open(&bytes, &token)?;
    if snapshot.nonce != nonce
        || snapshot.format != 1
        || snapshot.source == instance
        || Some(&snapshot.source) != captured.expected_primary_id.as_ref()
        || now().abs_diff(snapshot.issued_at) > 300
    {
        return Err("Primary identity, protocol, or snapshot time did not match.".into());
    }
    if let Some(old) = &received {
        if old.source == snapshot.source
            && (snapshot.generation < old.generation
                || (snapshot.generation == old.generation
                    && snapshot.fingerprint != old.fingerprint))
        {
            return Err("Primary snapshot would roll back a received generation.".into());
        }
    }
    let _mutation = state.backups.mutations.lock().await;
    let _write = state.write_lock.lock().await;
    if settings(state)? != *captured
        || state.control.secret("cluster_token")?.as_deref() != Some(&token)
        || state
            .backups
            .pending
            .load(std::sync::atomic::Ordering::SeqCst)
    {
        return Err("Synchronization settings changed or a restore is queued.".into());
    }
    if snapshot.config.is_some() || snapshot.certificates.is_some() {
        let certs = validate(&mut snapshot)?;
        write(&root(state).join(JOURNAL), &snapshot)?;
        apply_files(root(state), &snapshot)?;
        let config = snapshot.config.take().unwrap();
        state.certificates.store(Arc::new(certs));
        state.metrics.lock().unwrap().prometheus.configure(&config);
        state.config.store(Arc::new(config.clone()));
        state.rate_limits.retain_config(&config);
        state.http_cache.sync_config(&config);
        state.http_cache.purge_route(None, None)?;
        state
            .backups
            .revision
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    } else if !received.as_ref().is_some_and(|old| {
        old.source == snapshot.source
            && old.generation == snapshot.generation
            && old.fingerprint == snapshot.fingerprint
    }) {
        return Err("Primary heartbeat does not match local state.".into());
    }
    let mut r = r.lock().unwrap();
    r.received = Some(receipt(&snapshot));
    r.last_success = Some(Instant::now());
    r.last_success_at = Some(now());
    r.error = None;
    Ok(())
}
pub struct Synchronizer(pub Shared);
#[async_trait]
impl BackgroundService for Synchronizer {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        loop {
            if *shutdown.borrow() {
                break;
            }
            let candidate = runtime(&self.0).and_then(|r| {
                let mut r = r.lock().unwrap();
                if r.settings.role == Role::Follower
                    && (r.force
                        || r.last_attempt.is_none_or(|last| {
                            last.elapsed() >= Duration::from_secs(r.settings.interval_seconds)
                        }))
                {
                    r.force = false;
                    r.last_attempt = Some(Instant::now());
                    Some(r.settings.clone())
                } else {
                    None
                }
            });
            if let Some(settings) = candidate {
                tokio::select! {result=pull(&self.0,&settings)=>{if let Err(error)=result{if let Some(r)=runtime(&self.0){r.lock().unwrap().error=Some(error);}}},_=shutdown.changed()=>break}
            }
            tokio::select! {_=tokio::time::sleep(Duration::from_secs(1))=>{},_=shutdown.changed()=>break}
        }
    }
}
pub fn validate_backup(name: &str, value: &str) -> Result<(), String> {
    match name {
        "cluster_token" => token(value),
        "cluster_settings" => {
            let mut s: Settings =
                serde_json::from_str(value).map_err(|_| "Invalid cluster settings.")?;
            s.validate()
        }
        _ => Err("Invalid cluster credential.".into()),
    }
}
pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/cluster", get(status).put(configure))
        .route("/api/cluster/token", post(rotate))
        .route("/api/cluster/sync", post(synchronize_now))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn sample() -> Snapshot {
        let config = Config::default();
        Snapshot {
            format: 1,
            source: uuid::Uuid::new_v4().to_string(),
            generation: 1,
            fingerprint: digest(&config, &[]).unwrap(),
            issued_at: now(),
            nonce: uuid::Uuid::new_v4().to_string(),
            config: Some(config),
            certificates: Some(vec![]),
        }
    }
    #[test]
    fn encrypted_snapshots_detect_tampering_wrong_keys_and_invalid_content() {
        let s = sample();
        let token = "a".repeat(64);
        let mut bytes = seal(&s, &token).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("trusted_proxies"));
        assert!(open(&bytes, &"b".repeat(64)).is_err());
        let mut copy = open(&bytes, &token).unwrap();
        assert!(validate(&mut copy).is_ok());
        bytes[30] ^= 1;
        assert!(open(&bytes, &token).is_err());
        copy.fingerprint = "0".repeat(64);
        assert!(validate(&mut copy).is_err());
    }
    #[test]
    fn journal_recovery_finishes_fixed_files() {
        let path =
            std::env::temp_dir().join(format!("embergate-cluster-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&path).unwrap();
        let s = sample();
        write(&path.join(JOURNAL), &s).unwrap();
        recover(&path).unwrap();
        assert!(Config::load(&path.join("routes.json")).is_ok());
        assert!(CertificateStore::load(&path.join("certificates.json")).is_ok());
        assert!(!path.join(JOURNAL).exists());
        fs::remove_dir_all(path).unwrap();
    }
}

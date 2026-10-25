//! Encrypted complete snapshots and restart-time restore with a durable roll-forward journal.
use crate::{
    accounts::Session,
    state::{now, Shared},
};
use axum::{
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Extension, Json, Router,
};
use openssl::{
    hash::MessageDigest,
    pkcs5::pbkdf2_hmac,
    symm::{decrypt_aead, encrypt_aead, Cipher},
};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::{Duration, Instant},
};
const MAGIC: &[u8] = b"EMBERGATE-BACKUP\0\x01";
const LIMIT: usize = 64 * 1024 * 1024;
const ARCHIVE_LIMIT: usize = 96 * 1024 * 1024;
const STORE: &str = ".embergate-backups";
const FIXED: [&str; 5] = [
    "routes.json",
    "certificates.json",
    "acme.json",
    "management.sqlite3",
    "analytics.sqlite3",
];
#[derive(Default)]
pub struct Manager {
    pub mutations: tokio::sync::Mutex<()>,
    pub(crate) operation: std::sync::Arc<tokio::sync::Mutex<()>>,
    pub scheduled_running: AtomicBool,
    pub revision: AtomicU64,
    pub pending: AtomicBool,
}
struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    name: String,
    data: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Archive {
    format: u32,
    created_at: u64,
    files: Vec<File>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stage {
    format: u32,
    id: String,
    owner: String,
    expires: u64,
    target_revision: u64,
    target_config: u64,
    created_at: u64,
    files: Vec<(String, String)>,
    summary: Value,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    id: String,
    actor: Value,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    id: String,
    recovery: String,
    actor: Value,
}
type Error = (StatusCode, Json<Value>);
fn error(message: impl ToString) -> Error {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({"error":message.to_string()})),
    )
}
fn io_error(_: impl std::fmt::Display) -> String {
    "Could not read or write backup storage.".into()
}
pub fn lock_data(path: &Path) -> Result<fs::File, String> {
    use std::fs::OpenOptions;
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(path.join(".embergate.lock"))
        .map_err(io_error)?;
    file.try_lock()
        .map_err(|_| "EmberGate is already running or the data directory is locked.".to_owned())?;
    Ok(file)
}
fn sync_dir(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        fs::File::open(path)
            .and_then(|f| f.sync_all())
            .map_err(io_error)?;
    }
    Ok(())
}
fn root(state: &Shared) -> PathBuf {
    state.config_path.parent().unwrap().to_path_buf()
}
fn allowed(name: &str) -> bool {
    (FIXED.contains(&name)
        || name == "routes.previous.json"
        || name == crate::history::FILE
        || name == crate::templates::FILE)
        || name
            .strip_prefix("acme-account-")
            .and_then(|n| n.strip_suffix(".json"))
            .is_some_and(|hash| hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()))
}
fn uuid(value: &str) -> Result<(), String> {
    if uuid::Uuid::parse_str(value).is_ok_and(|id| id.to_string() == value) {
        Ok(())
    } else {
        Err("Invalid restore identifier.".into())
    }
}
fn private_dir(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() && !m.file_type().is_symlink() => {}
        Ok(_) => return Err("Unsafe backup storage directory.".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path).map_err(io_error)?;
        }
        Err(e) => return Err(io_error(e)),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(io_error)?;
    }
    Ok(())
}
fn store(data: &Path) -> Result<PathBuf, String> {
    let path = data.join(STORE);
    private_dir(&path)?;
    Ok(path)
}
fn read(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > LIMIT as u64 {
        return Err("Invalid or oversized backup file.".into());
    }
    fs::read(path).map_err(io_error)
}
fn write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    crate::acme::secure_write(path, bytes).map_err(io_error)
}
fn save_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
    write(path, &serde_json::to_vec(value).map_err(io_error)?)
}
fn hash(bytes: &[u8]) -> String {
    openssl::sha::sha256(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
pub(crate) fn passphrase(value: &str) -> Result<(), String> {
    if value.chars().count() < 12 || value.len() > 1024 {
        return Err(
            "Use a backup passphrase of at least 12 characters and at most 1024 UTF-8 bytes."
                .into(),
        );
    }
    Ok(())
}
fn encrypt(bytes: &[u8], password: &str) -> Result<Vec<u8>, String> {
    passphrase(password)?;
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    openssl::rand::rand_bytes(&mut salt).map_err(io_error)?;
    openssl::rand::rand_bytes(&mut nonce).map_err(io_error)?;
    let mut key = [0u8; 32];
    pbkdf2_hmac(
        password.as_bytes(),
        &salt,
        600_000,
        MessageDigest::sha256(),
        &mut key,
    )
    .map_err(io_error)?;
    let mut header = MAGIC.to_vec();
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);
    let mut tag = [0u8; 16];
    let encrypted = encrypt_aead(
        Cipher::aes_256_gcm(),
        &key,
        Some(&nonce),
        &header,
        bytes,
        &mut tag,
    )
    .map_err(io_error)?;
    key.fill(0);
    header.extend_from_slice(&tag);
    header.extend_from_slice(&encrypted);
    Ok(header)
}
fn decrypt(bytes: &[u8], password: &str) -> Result<Vec<u8>, String> {
    passphrase(password)?;
    let n = MAGIC.len();
    if bytes.len() < n + 44 || bytes.len() > ARCHIVE_LIMIT || !bytes.starts_with(MAGIC) {
        return Err("Choose a supported EmberGate encrypted backup.".into());
    }
    let mut key = [0u8; 32];
    pbkdf2_hmac(
        password.as_bytes(),
        &bytes[n..n + 16],
        600_000,
        MessageDigest::sha256(),
        &mut key,
    )
    .map_err(io_error)?;
    let result = decrypt_aead(
        Cipher::aes_256_gcm(),
        &key,
        Some(&bytes[n + 16..n + 28]),
        &bytes[..n + 28],
        &bytes[n + 44..],
        &bytes[n + 28..n + 44],
    );
    key.fill(0);
    result.map_err(|_| "Incorrect passphrase or damaged backup.".into())
}
pub fn snapshot_db(source: &Connection, path: &Path) -> Result<(), String> {
    write(path, &[])?;
    let mut dest = Connection::open(path).map_err(io_error)?;
    let backup = rusqlite::backup::Backup::new(source, &mut dest).map_err(io_error)?;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match backup.step(256).map_err(io_error)? {
            rusqlite::backup::StepResult::Done => break,
            _ => {
                if Instant::now() > deadline {
                    return Err("Database snapshot timed out. Retry the backup.".into());
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }
    drop(backup);
    drop(dest);
    fs::File::open(path)
        .and_then(|f| f.sync_all())
        .map_err(io_error)?;
    Ok(())
}
fn snapshot_file_db(source: &Path, dest: &Path) -> Result<(), String> {
    let db =
        Connection::open_with_flags(source, OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(io_error)?;
    db.execute_batch("BEGIN; SELECT name FROM sqlite_master LIMIT 1;")
        .map_err(io_error)?;
    snapshot_db(&db, dest)
}
fn names(data: &Path) -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    for entry in fs::read_dir(data).map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        if let Some(name) = entry.file_name().to_str().filter(|n| allowed(n)) {
            names.push(name.to_owned());
        }
    }
    names.sort();
    if names.len() > 108 {
        return Err("Too many backup files.".into());
    }
    Ok(names)
}
fn pack(data: &Path, created_at: u64) -> Result<Archive, String> {
    // Every export, including the previous-state recovery export, removes the automation key.
    // Rebuilding this scratch database also removes obsolete secrets from free SQLite pages.
    let db = Connection::open(data.join("management.sqlite3")).map_err(io_error)?;
    crate::scheduled::sanitize_snapshot(&db)?;
    db.execute_batch("VACUUM; PRAGMA wal_checkpoint(TRUNCATE)")
        .map_err(io_error)?;
    drop(db);
    let mut size = 0usize;
    let mut files = Vec::new();
    for name in names(data)? {
        let bytes = read(&data.join(&name))?;
        size += bytes.len();
        if size > LIMIT {
            return Err("Backup data exceeds the 64 MiB limit.".into());
        }
        files.push(File {
            name,
            data: openssl::base64::encode_block(&bytes),
        });
    }
    Ok(Archive {
        format: 1,
        created_at,
        files,
    })
}
fn unpack(archive: Archive, path: &Path) -> Result<u64, String> {
    if archive.format != 1 || archive.created_at == 0 || archive.files.len() > 108 {
        return Err("Unsupported backup manifest.".into());
    }
    let mut seen = HashSet::new();
    let mut size = 0usize;
    for file in archive.files {
        if !allowed(&file.name) || !seen.insert(file.name.clone()) {
            return Err("Backup contains an unsupported or duplicate file.".into());
        }
        if file.data.len() > LIMIT * 4 / 3 + 4 {
            return Err("Backup file exceeds size limit.".into());
        }
        let bytes = openssl::base64::decode_block(&file.data)
            .map_err(|_| "Invalid backup file encoding.".to_owned())?;
        size += bytes.len();
        if size > LIMIT {
            return Err("Backup data exceeds the 64 MiB limit.".into());
        }
        write(&path.join(file.name), &bytes)?;
    }
    for required in FIXED {
        if !seen.contains(required) {
            return Err("The backup is missing required data.".into());
        }
    }
    Ok(archive.created_at)
}
fn schema(db: &Connection) -> Result<Vec<(String, String, String, Option<String>)>, String> {
    let mut stmt=db.prepare("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE substr(name,1,7) != 'sqlite_' ORDER BY type,name").map_err(io_error)?;
    let rows = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .map_err(io_error)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(io_error)?;
    Ok(rows)
}
fn database(path: &Path, expected: &str) -> Result<Connection, String> {
    let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|_| "Invalid backup database.".to_owned())?;
    db.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA query_only=ON; PRAGMA mmap_size=0;")
        .map_err(io_error)?;
    let reference = Connection::open_in_memory().map_err(io_error)?;
    reference.execute_batch(expected).map_err(io_error)?;
    let actual = schema(&db)?;
    if actual != schema(&reference)? {
        // Older analytics archives predate the additive response timing tables.
        // Accept only that exact legacy schema, retaining all other checks.
        if expected == crate::analytics::SCHEMA {
            reference
                .execute_batch("DROP TABLE response_timings")
                .map_err(io_error)?;
            if actual != schema(&reference)? {
                reference
                    .execute_batch("DROP TABLE latency_classes")
                    .map_err(io_error)?;
            }
        }
        if actual != schema(&reference)? {
            return Err("Unsupported database schema, tables, views, or triggers.".into());
        }
    }
    let result: String = db
        .query_row("PRAGMA quick_check", [], |r| r.get(0))
        .map_err(|_| "Invalid backup database.".to_owned())?;
    if result != "ok" {
        return Err("Backup database integrity check failed.".into());
    }
    Ok(db)
}
fn validate(data: &Path) -> Result<Value, String> {
    let mut config: crate::config::Config =
        serde_json::from_slice(&read(&data.join("routes.json"))?)
            .map_err(|_| "Invalid backed-up routes.".to_owned())?;
    config.validate()?;
    if data.join("routes.previous.json").exists() {
        let mut previous: crate::config::Config =
            serde_json::from_slice(&read(&data.join("routes.previous.json"))?)
                .map_err(|_| "Invalid previous route revision.".to_owned())?;
        previous.validate()?;
    }

    let configuration_revisions = crate::history::load(data)?.len();
    let host_templates = crate::templates::load(data)?.templates.len();
    let certs = crate::certificates::CertificateStore::load(&data.join("certificates.json"))
        .map_err(|_| "Invalid backed-up certificates or private keys.".to_owned())?;
    let acme = crate::acme::Acme::load(data, None)
        .map_err(|_| "Invalid ACME request or DNS recovery data.".to_owned())?;
    drop(acme);
    let jobs: Vec<crate::acme::ManagedOrder> =
        serde_json::from_slice(&read(&data.join("acme.json"))?)
            .map_err(|_| "Invalid ACME state.".to_owned())?;
    for name in names(data)?
        .into_iter()
        .filter(|n| n.starts_with("acme-account-"))
    {
        let account: instant_acme::AccountCredentials =
            serde_json::from_slice(&read(&data.join(name))?)
                .map_err(|_| "Invalid ACME account credentials.".to_owned())?;
        openssl::pkey::PKey::private_key_from_der(account.private_key().secret_pkcs8_der())
            .map_err(|_| "Invalid ACME private key.".to_owned())?;
    }
    let db = database(&data.join("management.sqlite3"), crate::management::SCHEMA)?;
    let mut stmt = db
        .prepare(
            "SELECT id,username,password_hash,role,enabled,version FROM users ORDER BY username",
        )
        .map_err(io_error)?;
    let users = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, i64>(5)?,
            ))
        })
        .map_err(io_error)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(io_error)?;
    if users.is_empty()
        || users.len() > 51
        || !users.iter().any(|(id, name, _, role, enabled, _)| {
            id == "bootstrap" && name == "admin" && role == "administrator" && *enabled == 1
        })
    {
        return Err("The backup requires an enabled primary administrator.".into());
    }
    for (id, name, password, role, enabled, version) in &users {
        if (id != "bootstrap" && uuid(id).is_err())
            || crate::management::username(name)? != *name
            || !["administrator", "read_only"].contains(&role.as_str())
            || ![0, 1].contains(enabled)
            || *version < 0
            || *version > 1_000_000_000_000
        {
            return Err("Invalid backed-up account.".into());
        }
        if password.len() > 1024 {
            return Err("Invalid account password hash.".into());
        }
        let parsed = argon2::password_hash::PasswordHash::new(password)
            .map_err(|_| "Invalid account password hash.".to_owned())?;
        if parsed.algorithm.as_str() != "argon2id"
            || parsed.version != Some(19)
            || !parsed
                .params
                .get_decimal("m")
                .is_some_and(|v| (8..=65536).contains(&v))
            || !parsed
                .params
                .get_decimal("t")
                .is_some_and(|v| (1..=10).contains(&v))
            || !parsed
                .params
                .get_decimal("p")
                .is_some_and(|v| (1..=16).contains(&v))
            || parsed.salt.is_none()
            || parsed.hash.is_none()
        {
            return Err("Unsupported account password hash parameters.".into());
        }
    }
    for (_, _, password, _, _, _) in &users {
        let parsed = argon2::password_hash::PasswordHash::new(password)
            .map_err(|_| "Invalid account password hash.".to_owned())?;
        let length = parsed.hash.as_ref().ok_or("Missing password hash.")?.len();
        argon2::Params::new(
            parsed.params.get_decimal("m").unwrap(),
            parsed.params.get_decimal("t").unwrap(),
            parsed.params.get_decimal("p").unwrap(),
            Some(length),
        )
        .map_err(|_| "Invalid account hash parameters.".to_owned())?;
        let mut salt = [0u8; 64];
        let salt = parsed
            .salt
            .as_ref()
            .ok_or("Missing hash salt.")?
            .decode_b64(&mut salt)
            .map_err(|_| "Invalid account hash salt.".to_owned())?;
        if salt.len() < 8 {
            return Err("Invalid account hash salt.".into());
        }
    }
    let value: Option<String> = db
        .query_row("SELECT settings FROM alert_settings WHERE id=1", [], |r| {
            r.get(0)
        })
        .optional()
        .map_err(io_error)?;
    let settings: crate::alerts::Settings = value
        .map(|v| serde_json::from_str(&v))
        .transpose()
        .map_err(|_| "Invalid alert settings.".to_owned())?
        .unwrap_or_default();
    settings.validate()?;
    if settings.version > 1_000_000_000_000 || config.version > 1_000_000_000_000 {
        return Err("Invalid configuration revision.".into());
    }
    let mut stmt = db
        .prepare("SELECT key,value FROM secrets ORDER BY key")
        .map_err(io_error)?;
    let secrets = stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
        .map_err(io_error)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(io_error)?;
    for (key, value) in &secrets {
        match key.as_str() {
            "cloudflare_token"
                if !value.is_empty()
                    && value.len() <= 4096
                    && value.bytes().all(|b| b.is_ascii_graphic()) => {}
            "dns_provider" => crate::dns::validate_backup(value)?,
            "alert_webhook_url" => {
                crate::alerts::validate_destination(value, settings.webhook_format)?
            }
            "prometheus_token_sha256"
                if value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()) => {}
            key if key == "mfa_policy" || key.starts_with("mfa:") => {
                crate::mfa::validate_backup(
                    key,
                    value,
                    &users.iter().map(|u| u.0.clone()).collect::<Vec<_>>(),
                )?;
            }
            key if key.starts_with("cluster_") => {
                crate::cluster::validate_backup(key, value)?;
            }
            key if key == "passkey_origin" || key.starts_with("passkeys:") => {
                crate::passkeys::validate_backup(
                    key,
                    value,
                    &users.iter().map(|u| u.0.clone()).collect::<Vec<_>>(),
                )?;
            }
            "crowdsec_url" => {
                url::Url::parse(value).map_err(|_| "Invalid CrowdSec URL.".to_owned())?;
            }
            "crowdsec_bouncer_key"
                if !value.is_empty()
                    && value.len() <= 4096
                    && value.bytes().all(|b| b.is_ascii_graphic()) => {}
            "crowdsec_remediation" | "crowdsec_captcha_secret" => {
                crate::captcha::validate_backup(key, value)?
            }
            key if key.starts_with("oidc_") => crate::oidc::validate_backup(key, value)?,
            "access_log_enabled" => crate::access_log::validate_backup(value)?,
            "private_ca_bundle" => crate::trust::validate_backup(value)?,
            key if key.starts_with("api_token:") => crate::tokens::validate_backup(
                key,
                value,
                &users.iter().map(|u| u.0.clone()).collect::<Vec<_>>(),
            )?,
            key if key.starts_with("backup_schedule") => {
                crate::scheduled::validate_backup(key, value)?
            }
            _ => return Err("Invalid or unsupported credential record.".into()),
        }
    }
    if secrets.iter().any(|(key, _)| key.starts_with("passkeys:"))
        && !secrets.iter().any(|(key, _)| key == "passkey_origin")
    {
        return Err("Passkey origin is missing from the backup.".into());
    }
    database(&data.join("analytics.sqlite3"), crate::analytics::SCHEMA)?;
    Ok(
        json!({"host_templates":host_templates,"configuration_revisions":configuration_revisions,"routes":config.routes.iter().map(|r|json!({"name":r.name,"host":r.host,"path_prefix":r.path_prefix})).collect::<Vec<_>>(),"accounts":users.iter().map(|(_,name,_,role,enabled,_)|json!({"username":name,"role":role,"enabled":*enabled==1})).collect::<Vec<_>>(),"certificates":certs.summaries(),"managed_certificates":jobs.len(),"pending_dns_records":jobs.iter().map(|j|j.pending_dns.len()).sum::<usize>(),"credential_types":secrets.iter().map(|(key,_)|if key.starts_with("mfa:"){"two_factor_authentication"}else if key.starts_with("passkeys:"){"passkeys"}else if key.starts_with("api_token:"){"api_tokens"}else{key.as_str()}).collect::<std::collections::BTreeSet<_>>(),"analytics":true,"audit_and_alerts":true}),
    )
}
fn cleanup(base: &Path) -> Result<(), String> {
    let pending: Option<Pending> = read(&base.join("pending.json"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok());
    for entry in fs::read_dir(base).map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some(id) = name.strip_prefix("review-") {
            if uuid(id).is_ok()
                && pending.as_ref().is_none_or(|p| p.id != id)
                && entry.file_type().map_err(io_error)?.is_dir()
            {
                if let Ok(bytes) = read(&entry.path().join("stage.json")) {
                    if serde_json::from_slice::<Stage>(&bytes).is_ok_and(|s| s.expires < now()) {
                        fs::remove_dir_all(entry.path()).map_err(io_error)?;
                    }
                }
            }
        }
    }
    Ok(())
}
async fn capture(state: &Shared, path: &Path) -> Result<(), String> {
    let _files = state.write_lock.lock().await;
    let (_operation, jobs) = state.acme.backup_guard().await?;
    save_json(&path.join("routes.json"), state.config.load().as_ref())?;
    save_json(
        &path.join("certificates.json"),
        &state.certificates.load().records(),
    )?;
    save_json(&path.join("acme.json"), &*jobs)?;
    let history = root(state).join(crate::history::FILE);
    if history.exists() {
        crate::history::load(&root(state))?;
        write(&path.join(crate::history::FILE), &read(&history)?)?;
    }
    let templates = root(state).join(crate::templates::FILE);
    if templates.exists() {
        crate::templates::load(&root(state))?;
        write(&path.join(crate::templates::FILE), &read(&templates)?)?;
    }
    let previous = root(state).join("routes.previous.json");
    if previous.exists() {
        write(&path.join("routes.previous.json"), &read(&previous)?)?;
    }
    for name in names(&root(state))?
        .into_iter()
        .filter(|n| n.starts_with("acme-account-"))
    {
        write(&path.join(&name), &read(&root(state).join(name))?)?;
    }
    state
        .control
        .snapshot(path.join("management.sqlite3"))
        .await?;
    let db = Connection::open(path.join("management.sqlite3")).map_err(io_error)?;
    if let Some(hash) = &state.password_hash {
        db.execute(
            "UPDATE users SET password_hash=?1 WHERE id='bootstrap'",
            rusqlite::params![hash],
        )
        .map_err(io_error)?;
    }
    if let Some((key, value)) = state.acme.backup_secret() {
        // The live provider, including an environment override, is the one restored.
        db.execute(
            "DELETE FROM secrets WHERE key IN ('cloudflare_token','dns_provider')",
            [],
        )
        .map_err(io_error)?;
        db.execute(
            "INSERT INTO secrets VALUES(?1,?2)",
            rusqlite::params![key, value],
        )
        .map_err(io_error)?;
    }
    if let Some(url) = crate::alerts::webhook()? {
        db.execute("INSERT INTO secrets VALUES('alert_webhook_url',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",rusqlite::params![url]).map_err(io_error)?;
    }
    db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .map_err(io_error)?;
    drop(db);
    let source = root(state).join("analytics.sqlite3");
    let dest = path.join("analytics.sqlite3");
    tokio::task::spawn_blocking(move || snapshot_file_db(&source, &dest))
        .await
        .map_err(io_error)??;
    Ok(())
}
pub(crate) async fn automatic_bytes(
    state: &Shared,
    password: String,
    operation: tokio::sync::OwnedMutexGuard<()>,
) -> Result<(Vec<u8>, tokio::sync::OwnedMutexGuard<()>), String> {
    passphrase(&password)?;
    let base = store(&root(state))?;
    let path = base.join(format!("export-{}", uuid::Uuid::new_v4()));
    private_dir(&path)?;
    let scratch = Scratch(path.clone());
    capture(state, &path).await?;
    tokio::task::spawn_blocking(move || {
        let _scratch = scratch;
        let archive = pack(&path, now())?;
        let bytes = encrypt(&serde_json::to_vec(&archive).map_err(io_error)?, &password)?;
        if bytes.len() > ARCHIVE_LIMIT {
            return Err("Encrypted backup exceeds the 96 MiB limit.".into());
        }
        Ok((bytes, operation))
    })
    .await
    .map_err(io_error)?
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Export {
    passphrase: String,
    #[serde(default)]
    recovery: bool,
}
async fn export(State(state): State<Shared>, Json(input): Json<Export>) -> Result<Response, Error> {
    passphrase(&input.passphrase).map_err(error)?;
    let _operation = state
        .backups
        .operation
        .clone()
        .try_lock_owned()
        .map_err(|_| error("A backup operation is already running."))?;
    let base = store(&root(&state)).map_err(error)?;
    cleanup(&base).map_err(error)?;
    let scratch = base.join(format!("export-{}", uuid::Uuid::new_v4()));
    private_dir(&scratch).map_err(error)?;
    let _scratch = Scratch(scratch.clone());
    let result = async {
        if input.recovery {
            let receipt: Value =
                serde_json::from_slice(&read(&base.join("receipt.json"))?).map_err(io_error)?;
            let id = receipt["recovery"]
                .as_str()
                .ok_or("No recovery snapshot is available.")?;
            uuid(id)?;
            let source = base.join(format!("recovery-{id}"));
            for name in names(&source)? {
                write(&scratch.join(&name), &read(&source.join(name))?)?;
            }
        } else {
            capture(&state, &scratch).await?;
        }
        let path = scratch.clone();
        let bytes = tokio::task::spawn_blocking(move || {
            let _operation = _operation;
            let archive = pack(&path, now())?;
            encrypt(
                &serde_json::to_vec(&archive).map_err(io_error)?,
                &input.passphrase,
            )
        })
        .await
        .map_err(io_error)??;
        Ok::<_, String>(
            (
                [
                    ("content-type", "application/octet-stream"),
                    (
                        "content-disposition",
                        &format!(
                            "attachment; filename=\"embergate-full-{}.embergate\"",
                            now()
                        ),
                    ),
                ],
                bytes,
            )
                .into_response(),
        )
    }
    .await;
    let _ = fs::remove_dir_all(&scratch);
    result.map_err(error)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Preview {
    archive: String,
    passphrase: String,
}
async fn preview(
    State(state): State<Shared>,
    Extension(session): Extension<Session>,
    Json(input): Json<Preview>,
) -> Result<Json<Value>, Error> {
    let _operation = state
        .backups
        .operation
        .clone()
        .try_lock_owned()
        .map_err(|_| error("A backup operation is already running."))?;
    if input.archive.len() > ARCHIVE_LIMIT * 4 / 3 + 4 {
        return Err(error("Backup upload exceeds size limit."));
    }
    let base = store(&root(&state)).map_err(error)?;
    cleanup(&base).map_err(error)?;
    let owner = session.id.clone();
    let mut count = 0;
    for entry in fs::read_dir(&base).map_err(io_error).map_err(error)? {
        let entry = entry.map_err(io_error).map_err(error)?;
        if let Some(id) = entry.file_name().to_string_lossy().strip_prefix("review-") {
            if uuid(id).is_ok() {
                let old = read(&entry.path().join("stage.json"))
                    .ok()
                    .and_then(|b| serde_json::from_slice::<Stage>(&b).ok());
                if old.is_some_and(|s| s.owner == owner) {
                    fs::remove_dir_all(entry.path())
                        .map_err(io_error)
                        .map_err(error)?;
                } else {
                    count += 1;
                }
            }
        }
    }
    if count >= 5 {
        return Err(error("Five restore reviews are already staged. Wait for them to expire before uploading another backup."));
    }
    let id = uuid::Uuid::new_v4().to_string();
    let path = base.join(format!("review-{id}"));
    private_dir(&path).map_err(error)?;
    let target_revision = state.backups.revision.load(Ordering::SeqCst);
    let target_config = state.config.load().version;
    let owner = session.id;
    let work = path.clone();
    let result=tokio::task::spawn_blocking(move||{
        let _operation=_operation;
        let encrypted=openssl::base64::decode_block(&input.archive).map_err(|_|"Invalid backup upload encoding.".to_owned())?;let bytes=decrypt(&encrypted,&input.passphrase)?;
        let archive:Archive=serde_json::from_slice(&bytes).map_err(|_|"Invalid backup manifest.".to_owned())?;let created_at=unpack(archive,&work)?;let summary=validate(&work)?;
        let files=names(&work)?.into_iter().map(|name|Ok((name.clone(),hash(&read(&work.join(name))?)))).collect::<Result<Vec<_>,String>>()?;
        let stage=Stage{format:1,id:id.clone(),owner,expires:now()+900,target_revision,target_config,created_at,files,summary:summary.clone()};save_json(&work.join("stage.json"),&stage)?;Ok::<_,String>(json!({"id":id,"created_at":created_at,"expires_at":stage.expires,"summary":summary,"requires_restart":true,"environment_overrides":overrides()}))
    }).await.map_err(io_error);
    match result {
        Ok(Ok(value)) => Ok(Json(value)),
        Ok(Err(e)) => {
            let _ = fs::remove_dir_all(path);
            Err(error(e))
        }
        Err(e) => {
            let _ = fs::remove_dir_all(path);
            Err(error(e))
        }
    }
}
fn overrides() -> Vec<&'static str> {
    [
        "GATEWAY_ADMIN_PASSWORD",
        "GATEWAY_CLOUDFLARE_API_TOKEN",
        "GATEWAY_CLOUDFLARE_API_TOKEN_FILE",
        "GATEWAY_ALERT_WEBHOOK_URL",
    ]
    .into_iter()
    .filter(|key| std::env::var(key).is_ok_and(|v| !v.is_empty()))
    .collect()
}
fn stage(base: &Path, id: &str) -> Result<Stage, String> {
    uuid(id)?;
    let path = base.join(format!("review-{id}"));
    let stage: Stage = serde_json::from_slice(&read(&path.join("stage.json"))?)
        .map_err(|_| "Invalid restore review.".to_owned())?;
    if stage.id != id || stage.format != 1 || stage.files.len() > 108 {
        return Err("Invalid restore review.".into());
    }
    let mut seen = HashSet::new();
    for (name, digest) in &stage.files {
        if !allowed(name) || !seen.insert(name.clone()) || hash(&read(&path.join(name))?) != *digest
        {
            return Err("Restore data changed after validation.".into());
        }
    }
    for name in FIXED {
        if !seen.contains(name) {
            return Err("Incomplete restore data.".into());
        }
    }
    Ok(stage)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Restore {
    id: String,
    confirm: String,
}
async fn restore(
    State(state): State<Shared>,
    Extension(session): Extension<Session>,
    Json(input): Json<Restore>,
) -> Result<Json<Value>, Error> {
    if input.confirm != "RESTORE" {
        return Err(error("Type RESTORE to confirm replacement."));
    }
    let _operation = state
        .backups
        .operation
        .clone()
        .try_lock_owned()
        .map_err(|_| error("A backup operation is already running."))?;
    let base = store(&root(&state)).map_err(error)?;
    let stage = stage(&base, &input.id).map_err(error)?;
    if stage.owner != session.id || stage.expires < now() {
        return Err(error(
            "This restore review expired or belongs to another session. Validate the backup again.",
        ));
    }
    if stage.target_revision != state.backups.revision.load(Ordering::SeqCst)
        || stage.target_config != state.config.load().version
    {
        return Err(error(
            "Gateway settings changed after the review. Validate the backup again.",
        ));
    }
    let _files = state.write_lock.lock().await;
    let (_operation, jobs) = state.acme.backup_guard().await.map_err(error)?;
    if jobs.iter().any(|j| !j.pending_dns.is_empty()) {
        return Err(error(
            "Complete current DNS cleanup before replacing ACME state.",
        ));
    }
    save_json(
        &base.join("pending.json"),
        &Pending {
            id: input.id,
            actor: json!(session.actor()),
        },
    )
    .map_err(error)?;
    state.backups.pending.store(true, Ordering::SeqCst);
    sync_dir(&base).map_err(error)?;
    Ok(Json(json!({"queued":true,"requires_restart":true})))
}
async fn cancel(State(state): State<Shared>) -> Result<Json<Value>, Error> {
    let base = store(&root(&state)).map_err(error)?;
    match fs::remove_file(base.join("pending.json")) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(error(io_error(e))),
    }
    sync_dir(&base).map_err(error)?;
    state.backups.pending.store(false, Ordering::SeqCst);
    Ok(Json(json!({"queued":false})))
}
async fn status(State(state): State<Shared>) -> Result<Json<Value>, Error> {
    let base = store(&root(&state)).map_err(error)?;
    let receipt = read(&base.join("receipt.json"))
        .ok()
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok());
    Ok(Json(
        json!({"pending":state.backups.pending.load(Ordering::SeqCst),"last_restore":receipt,"recovery_available":receipt.is_some(),"maximum_data_bytes":LIMIT,"encrypted":true}),
    ))
}
pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/backups/status", get(status))
        .route("/api/backups/export", post(export))
        .route("/api/backups/preview", post(preview))
        .route("/api/backups/restore", post(restore))
        .route("/api/backups/cancel", post(cancel))
        .layer(DefaultBodyLimit::max(ARCHIVE_LIMIT * 4 / 3 + 1024 * 1024))
}
fn offline_snapshot(data: &Path, path: &Path) -> Result<(), String> {
    private_dir(path)?;
    for name in names(data)? {
        if name.ends_with(".sqlite3") {
            snapshot_file_db(&data.join(&name), &path.join(name))?;
        } else {
            write(&path.join(&name), &read(&data.join(name))?)?;
        }
    }
    for (name, default) in [
        ("routes.json", b"{\"version\":0,\"routes\":[]}".as_slice()),
        ("certificates.json", b"[]".as_slice()),
        ("acme.json", b"[]".as_slice()),
    ] {
        if !path.join(name).exists() {
            write(&path.join(name), default)?;
        }
    }
    Ok(())
}
fn replace(data: &Path, source: &Path) -> Result<(), String> {
    let incoming = names(source)?;
    for name in names(data)? {
        if !incoming.contains(&name) {
            fs::remove_file(data.join(name)).map_err(io_error)?;
        }
    }
    for name in incoming {
        if name.ends_with(".sqlite3") {
            for suffix in ["-wal", "-shm"] {
                let path = data.join(format!("{name}{suffix}"));
                match fs::remove_file(path) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(io_error(e)),
                }
            }
        }
        write(&data.join(&name), &read(&source.join(name))?)?;
    }
    Ok(())
}
pub fn apply_pending(data: &Path) -> Result<(), String> {
    if !data.join(STORE).exists() {
        return Ok(());
    }
    let base = store(data)?;
    let receipt = read(&base.join("receipt.json"))
        .ok()
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok());
    let completed_id = receipt.as_ref().and_then(|r| r["stage_id"].as_str());
    let journal_id = read(&base.join("journal.json"))
        .ok()
        .and_then(|b| serde_json::from_slice::<Journal>(&b).ok())
        .map(|j| j.id);
    let pending_id = read(&base.join("pending.json"))
        .ok()
        .and_then(|b| serde_json::from_slice::<Pending>(&b).ok())
        .map(|p| p.id);
    if completed_id.is_some()
        && (journal_id.as_deref() == completed_id
            || (journal_id.is_none() && pending_id.as_deref() == completed_id))
    {
        for name in ["pending.json", "journal.json"] {
            if base.join(name).exists() {
                fs::remove_file(base.join(name)).map_err(io_error)?;
            }
        }
        fs::File::open(&base)
            .and_then(|f| f.sync_all())
            .map_err(io_error)?;
        return Ok(());
    }
    let journal = base.join("journal.json");
    let journal: Journal = if journal.exists() {
        serde_json::from_slice(&read(&journal)?)
            .map_err(|_| "Invalid restore journal.".to_owned())?
    } else {
        let pending = base.join("pending.json");
        if !pending.exists() {
            return Ok(());
        }
        let pending: Pending = serde_json::from_slice(&read(&pending)?)
            .map_err(|_| "Invalid pending restore.".to_owned())?;
        stage(&base, &pending.id)?;
        validate(&base.join(format!("review-{}", pending.id)))?;
        let recovery = uuid::Uuid::new_v4().to_string();
        offline_snapshot(data, &base.join(format!("recovery-{recovery}")))?;
        let record = Journal {
            id: pending.id,
            recovery,
            actor: pending.actor,
        };
        save_json(&base.join("journal.json"), &record)?;
        sync_dir(&base)?;
        record
    };
    uuid(&journal.id)?;
    uuid(&journal.recovery)?;
    let staged = stage(&base, &journal.id)?;
    let source = base.join(format!("review-{}", journal.id));
    validate(&source)?;
    replace(data, &source)?;
    let db = Connection::open(data.join("management.sqlite3")).map_err(io_error)?;
    db.execute(
        "UPDATE outbox SET state='cancelled' WHERE state='pending'",
        [],
    )
    .map_err(io_error)?;
    db.execute("INSERT INTO audit(timestamp,actor,method,path,phase,status,details) VALUES(?1,?2,'POST','/api/backups/restore','success',200,?3)",rusqlite::params![now(),journal.actor.to_string(),json!({"backup_created_at":staged.created_at,"restored_at":now()}).to_string()]).map_err(io_error)?;
    db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .map_err(io_error)?;
    drop(db);
    save_json(
        &base.join("receipt.json"),
        &json!({"restored_at":now(),"backup_created_at":staged.created_at,"recovery":journal.recovery,"stage_id":journal.id}),
    )?;
    sync_dir(&base)?;
    for name in ["pending.json", "journal.json"] {
        match fs::remove_file(base.join(name)) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(io_error(e)),
        }
    }
    fs::File::open(&base)
        .and_then(|f| f.sync_all())
        .map_err(io_error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn temp() -> Scratch {
        let path =
            std::env::temp_dir().join(format!("embergate-backup-test-{}", uuid::Uuid::new_v4()));
        private_dir(&path).unwrap();
        Scratch(path)
    }
    #[test]
    fn encryption_authenticates_header_password_and_ciphertext() {
        let mut bytes = encrypt(b"private-key=never-plaintext", "a-long-backup-password").unwrap();
        assert!(!bytes.windows(11).any(|w| w == b"private-key"));
        assert_eq!(
            decrypt(&bytes, "a-long-backup-password").unwrap(),
            b"private-key=never-plaintext"
        );
        assert!(decrypt(&bytes, "a-different-password").is_err());
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        assert!(decrypt(&bytes, "a-long-backup-password").is_err());
        bytes[0] ^= 1;
        assert!(decrypt(&bytes, "a-long-backup-password").is_err());
    }
    #[test]
    fn all_export_paths_strip_automation_passphrases_and_free_pages() {
        let tmp = temp();
        let db = Connection::open(tmp.0.join("management.sqlite3")).unwrap();
        db.execute_batch(crate::management::SCHEMA).unwrap();
        db.execute_batch("PRAGMA secure_delete=OFF").unwrap();
        let old = "old-unattended-passphrase-secret".repeat(100);
        db.execute(
            "INSERT INTO secrets VALUES('discarded',?1)",
            rusqlite::params![old],
        )
        .unwrap();
        db.execute("DELETE FROM secrets WHERE key='discarded'", [])
            .unwrap();
        db.execute("INSERT INTO secrets VALUES('backup_schedule_passphrase','current-unattended-passphrase-secret')",[]).unwrap();
        db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)").unwrap();
        drop(db);
        let before = fs::read(tmp.0.join("management.sqlite3")).unwrap();
        assert!(before
            .windows("old-unattended-passphrase-secret".len())
            .any(|w| w == b"old-unattended-passphrase-secret"));
        let archive = pack(&tmp.0, now()).unwrap();
        let management = archive
            .files
            .iter()
            .find(|f| f.name == "management.sqlite3")
            .unwrap();
        let bytes = openssl::base64::decode_block(&management.data).unwrap();
        for secret in [
            "old-unattended-passphrase-secret",
            "current-unattended-passphrase-secret",
            "backup_schedule_passphrase",
        ] {
            assert!(
                !bytes.windows(secret.len()).any(|w| w == secret.as_bytes()),
                "{secret}"
            );
        }
    }
    #[test]
    fn analytics_archives_accept_exact_legacy_schema_but_reject_extra_objects() {
        let path =
            std::env::temp_dir().join(format!("legacy-analytics-{}.sqlite3", uuid::Uuid::new_v4()));
        let db = Connection::open(&path).unwrap();
        db.execute_batch(crate::analytics::SCHEMA).unwrap();
        assert!(database(&path, crate::analytics::SCHEMA).is_ok());
        db.execute_batch("DROP TABLE response_timings").unwrap();
        assert!(database(&path, crate::analytics::SCHEMA).is_ok());
        db.execute_batch("DROP TABLE latency_classes").unwrap();
        assert!(database(&path, crate::analytics::SCHEMA).is_ok());
        db.execute_batch("CREATE TABLE unexpected(value TEXT)")
            .unwrap();
        assert!(database(&path, crate::analytics::SCHEMA).is_err());
        drop(db);
        let _ = std::fs::remove_file(path);
    }
    #[test]
    fn archive_rejects_paths_duplicates_links_and_unknown_schema() {
        let tmp = temp();
        for name in [
            "../routes.json",
            "/etc/passwd",
            "management.sqlite3-wal",
            "nested/file",
            "acme-account-nope.json",
        ] {
            let archive = Archive {
                format: 1,
                created_at: now(),
                files: vec![File {
                    name: name.into(),
                    data: "".into(),
                }],
            };
            assert!(unpack(archive, &tmp.0).is_err());
        }
        let archive = Archive {
            format: 1,
            created_at: now(),
            files: vec![
                File {
                    name: "routes.json".into(),
                    data: "e30=".into(),
                },
                File {
                    name: "routes.json".into(),
                    data: "e30=".into(),
                },
            ],
        };
        assert!(unpack(archive, &tmp.0).is_err());
        let path = tmp.0.join("bad.sqlite3");
        let db = Connection::open(&path).unwrap();
        db.execute_batch(crate::management::SCHEMA).unwrap();
        db.execute_batch(
            "CREATE TRIGGER sqlitexevil AFTER INSERT ON users BEGIN DELETE FROM audit; END;",
        )
        .unwrap();
        drop(db);
        assert!(database(&path, crate::management::SCHEMA).is_err());
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/etc/passwd", tmp.0.join("link")).unwrap();
            assert!(read(&tmp.0.join("link")).is_err());
        }
    }
    #[test]
    fn sqlite_snapshot_includes_committed_wal_and_integrity() {
        let tmp = temp();
        let db = Connection::open(tmp.0.join("source.sqlite3")).unwrap();
        db.execute_batch(crate::management::SCHEMA).unwrap();
        db.execute(
            "INSERT INTO secrets VALUES('cloudflare_token','fixture-token')",
            [],
        )
        .unwrap();
        let target = tmp.0.join("copy.sqlite3");
        snapshot_db(&db, &target).unwrap();
        let copy = database(&target, crate::management::SCHEMA).unwrap();
        assert_eq!(
            copy.query_row("SELECT value FROM secrets", [], |r| r.get::<_, String>(0))
                .unwrap(),
            "fixture-token"
        );
    }
    #[test]
    fn interrupted_restore_rolls_forward_and_keeps_previous_state() {
        let tmp = temp();
        let base = store(&tmp.0).unwrap();
        let db = Connection::open(tmp.0.join("management.sqlite3")).unwrap();
        db.execute_batch(crate::management::SCHEMA).unwrap();
        let password_hash="$argon2id$v=19$m=19456,t=2,p=1$dGVzdHNhbHQ$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        db.execute(
            "INSERT INTO users VALUES('bootstrap','admin',?1,'administrator',1,0)",
            rusqlite::params![password_hash],
        )
        .unwrap();
        drop(db);
        let db = Connection::open(tmp.0.join("analytics.sqlite3")).unwrap();
        db.execute_batch(crate::analytics::SCHEMA).unwrap();
        drop(db);
        write(&tmp.0.join("routes.json"), b"{\"version\":1,\"routes\":[]}").unwrap();
        write(&tmp.0.join("certificates.json"), b"[]").unwrap();
        write(&tmp.0.join("acme.json"), b"[]").unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        let source = base.join(format!("review-{id}"));
        offline_snapshot(&tmp.0, &source).unwrap();
        write(
            &source.join("routes.json"),
            b"{\"version\":9,\"routes\":[]}",
        )
        .unwrap();
        let summary = validate(&source).unwrap();
        let files = names(&source)
            .unwrap()
            .into_iter()
            .map(|name| (name.clone(), hash(&read(&source.join(name)).unwrap())))
            .collect();
        save_json(
            &source.join("stage.json"),
            &Stage {
                format: 1,
                id: id.clone(),
                owner: "session".into(),
                expires: 0,
                target_revision: 0,
                target_config: 1,
                created_at: now(),
                files,
                summary,
            },
        )
        .unwrap();
        let recovery = uuid::Uuid::new_v4().to_string();
        offline_snapshot(&tmp.0, &base.join(format!("recovery-{recovery}"))).unwrap();
        save_json(
            &base.join("journal.json"),
            &Journal {
                id: id.clone(),
                recovery: recovery.clone(),
                actor: json!({"username":"admin"}),
            },
        )
        .unwrap();
        // Simulate a crash after replacing one file but before finishing database replacement.
        write(&tmp.0.join("routes.json"), b"{\"version\":9,\"routes\":[]}").unwrap();
        apply_pending(&tmp.0).unwrap();
        assert!(!base.join("journal.json").exists());
        assert_eq!(
            crate::config::Config::load(&tmp.0.join("routes.json"))
                .unwrap()
                .version,
            9
        );
        assert_eq!(
            crate::config::Config::load(&base.join(format!("recovery-{recovery}/routes.json")))
                .unwrap()
                .version,
            1
        );
        // A crash while removing commit markers must retain the same recovery copy.
        save_json(
            &base.join("pending.json"),
            &Pending {
                id,
                actor: json!({}),
            },
        )
        .unwrap();
        apply_pending(&tmp.0).unwrap();
        let receipt: Value =
            serde_json::from_slice(&read(&base.join("receipt.json")).unwrap()).unwrap();
        assert_eq!(receipt["recovery"], recovery);
    }
}

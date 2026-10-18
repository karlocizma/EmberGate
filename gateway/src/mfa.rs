//! TOTP (RFC 6238), enrollment, and single-use recovery codes.
//! Authenticator secrets remain in private management storage; recovery codes are hashed.
use crate::{
    accounts::Session,
    management,
    state::{now, Shared},
};
use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Extension, Json, Router,
};
use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::{LazyLock, Mutex},
    time::{Duration, Instant},
};

type Error = (StatusCode, Json<Value>);
fn error(status: StatusCode, message: impl ToString) -> Error {
    (status, Json(json!({"error":message.to_string()})))
}
fn storage(message: String) -> Error {
    error(StatusCode::SERVICE_UNAVAILABLE, message)
}
fn invalid(message: impl ToString) -> Error {
    error(StatusCode::UNPROCESSABLE_ENTITY, message)
}
const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    secret: String,
    last_step: Option<u64>,
    recovery_hashes: Vec<String>,
}
impl Record {
    pub fn validate(&self) -> Result<(), String> {
        if self.secret.len() != 32
            || decode(&self.secret).is_err()
            || self.recovery_hashes.len() > 10
            || self
                .recovery_hashes
                .iter()
                .any(|h| h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()))
            || self.last_step.is_some_and(|s| s > 100_000_000_000)
        {
            return Err("Invalid two-factor authentication record.".into());
        }
        Ok(())
    }
}
struct Pending {
    secret: String,
    user_id: String,
    expires: Instant,
}
static PENDING: LazyLock<Mutex<HashMap<String, Pending>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
fn encode(bytes: &[u8]) -> String {
    let mut buffer = 0u32;
    let mut bits = 0;
    let mut result = String::new();
    for b in bytes {
        buffer = (buffer << 8) | u32::from(*b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            result.push(ALPHABET[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        result.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    result
}
fn decode(value: &str) -> Result<Vec<u8>, String> {
    let mut result = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0;
    for b in value.bytes() {
        let index = ALPHABET
            .iter()
            .position(|a| *a == b)
            .ok_or("Invalid authenticator secret.")?;
        buffer = (buffer << 5) | index as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            result.push((buffer >> bits) as u8);
        }
    }
    Ok(result)
}
fn totp(secret: &str, step: u64, digits: u32) -> Result<String, String> {
    let key = PKey::hmac(&decode(secret)?).map_err(|_| "Authenticator unavailable.")?;
    let mut signer =
        Signer::new(MessageDigest::sha1(), &key).map_err(|_| "Authenticator unavailable.")?;
    signer
        .update(&step.to_be_bytes())
        .map_err(|_| "Authenticator unavailable.")?;
    let digest = signer
        .sign_to_vec()
        .map_err(|_| "Authenticator unavailable.")?;
    let offset = (digest[19] & 15) as usize;
    let number = u32::from_be_bytes(digest[offset..offset + 4].try_into().unwrap()) & 0x7fffffff;
    Ok(format!(
        "{:0width$}",
        number % 10u32.pow(digits),
        width = digits as usize
    ))
}
fn step(secret: &str, code: &str, at: u64, last: Option<u64>) -> Result<Option<u64>, String> {
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Ok(None);
    }
    let current = at / 30;
    for candidate in [current, current.saturating_sub(1), current + 1] {
        if last.is_some_and(|last| candidate <= last) {
            continue;
        }
        if openssl::memcmp::eq(totp(secret, candidate, 6)?.as_bytes(), code.as_bytes()) {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}
fn recovery_hash(code: &str) -> String {
    // Codes contain 128 bits of randomness. A fast hash does not make them guessable.
    openssl::sha::sha256(code.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn recovery() -> Result<(Vec<String>, Vec<String>), String> {
    let mut codes = Vec::new();
    for _ in 0..10 {
        let mut bytes = [0u8; 16];
        openssl::rand::rand_bytes(&mut bytes).map_err(|_| "Random generator unavailable.")?;
        codes.push(bytes.iter().map(|b| format!("{b:02x}")).collect::<String>());
    }
    let hashes = codes.iter().map(|c| recovery_hash(c)).collect();
    Ok((codes, hashes))
}
fn key(id: &str) -> String {
    format!("mfa:{id}")
}
fn read(db: &rusqlite::Connection, id: &str) -> Result<Option<Record>, String> {
    let value: Option<String> = db
        .query_row(
            "SELECT value FROM secrets WHERE key=?1",
            params![key(id)],
            |r| r.get(0),
        )
        .optional()
        .map_err(management::storage)?;
    let record: Option<Record> = value
        .map(|v| serde_json::from_str(&v))
        .transpose()
        .map_err(|_| "Two-factor authentication storage unavailable.")?;
    if let Some(r) = &record {
        r.validate()?;
    }
    Ok(record)
}
fn write(db: &rusqlite::Connection, id: &str, record: &Record) -> Result<(), String> {
    db.execute(
        "INSERT INTO secrets VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![
            key(id),
            serde_json::to_string(record).map_err(|_| "Authenticator unavailable.")?
        ],
    )
    .map_err(management::storage)?;
    Ok(())
}
pub async fn enabled(state: &Shared, id: &str) -> Result<bool, String> {
    let id = id.to_owned();
    state
        .control
        .run(move |db| Ok(read(db, &id)?.is_some()))
        .await
}
pub fn policy(state: &Shared) -> Result<bool, String> {
    match state.control.secret("mfa_policy")?.as_deref() {
        None | Some("false") => Ok(false),
        Some("true") => Ok(true),
        _ => Err("Two-factor policy storage unavailable.".into()),
    }
}
pub async fn enrollment_required(state: &Shared, session: &Session) -> Result<bool, String> {
    Ok(session.user.role.admin() && policy(state)? && !enabled(state, &session.user.id).await?)
}
// SQLite transaction makes replay protection and recovery consumption atomic across requests.
pub async fn authenticate(state: &Shared, id: &str, code: &str) -> Result<bool, String> {
    let id = id.to_owned();
    let code = code.trim().to_owned();
    state
        .control
        .run(move |db| consume(db, &id, &code, now()))
        .await
}
fn consume(db: &mut rusqlite::Connection, id: &str, code: &str, at: u64) -> Result<bool, String> {
    let tx = db.transaction().map_err(management::storage)?;
    let Some(mut record) = read(&tx, id)? else {
        return Ok(false);
    };
    if let Some(step) = step(&record.secret, code, at, record.last_step)? {
        record.last_step = Some(step);
    } else {
        if code.len() != 32 || !code.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Ok(false);
        }
        let hash = recovery_hash(&code.to_ascii_lowercase());
        let Some(index) = record
            .recovery_hashes
            .iter()
            .position(|h| openssl::memcmp::eq(h.as_bytes(), hash.as_bytes()))
        else {
            return Ok(false);
        };
        record.recovery_hashes.remove(index);
    }
    write(&tx, id, &record)?;
    tx.commit().map_err(management::storage)?;
    Ok(true)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Proof {
    current_password: String,
    #[serde(default)]
    code: String,
}
async fn prove(
    state: &Shared,
    session: &Session,
    input: &Proof,
    factor: bool,
) -> Result<(), Error> {
    crate::accounts::limit_attempts(state, &session.peer)?;
    crate::accounts::limit_attempts(state, &format!("mfa:{}", session.user.id))?;
    let credentials = crate::accounts::credentials(state, &session.user.username)
        .await?
        .ok_or_else(|| error(StatusCode::UNAUTHORIZED, "Please sign in again."))?;
    if !credentials.user.enabled
        || credentials.user.version != session.user.version
        || !management::verify_password(input.current_password.clone(), credentials.hash).await
    {
        return Err(error(StatusCode::FORBIDDEN, "Incorrect current password."));
    }
    if factor
        && !authenticate(state, &session.user.id, &input.code)
            .await
            .map_err(storage)?
    {
        return Err(error(
            StatusCode::FORBIDDEN,
            "Incorrect or already-used authentication code.",
        ));
    }
    Ok(())
}
fn retain_current(state: &Shared, session: &Session, verified: bool) {
    let mut sessions = state.sessions.lock().unwrap();
    sessions.retain(|_, s| s.user.id != session.user.id || s.id == session.id);
    for s in sessions.values_mut().filter(|s| s.id == session.id) {
        s.mfa_verified = verified;
    }
}
async fn status(
    State(state): State<Shared>,
    Extension(session): Extension<Session>,
) -> Result<Json<Value>, Error> {
    let id = session.user.id.clone();
    let (on, count) = state
        .control
        .run(move |db| {
            Ok(read(db, &id)?
                .map(|r| (true, r.recovery_hashes.len()))
                .unwrap_or((false, 0)))
        })
        .await
        .map_err(storage)?;
    let required = policy(&state).map_err(storage)?;
    Ok(Json(
        json!({"enabled":on,"recovery_codes_remaining":count,"require_administrators":required,"enrollment_required":session.user.role.admin()&&required&&!on}),
    ))
}
async fn setup(
    State(state): State<Shared>,
    Extension(session): Extension<Session>,
    Json(input): Json<Proof>,
) -> Result<Json<Value>, Error> {
    let _guard = state.account_write_lock.lock().await;
    prove(&state, &session, &input, false).await?;
    if enabled(&state, &session.user.id).await.map_err(storage)? {
        return Err(error(
            StatusCode::CONFLICT,
            "Two-factor authentication is already enabled.",
        ));
    }
    let mut bytes = [0u8; 20];
    openssl::rand::rand_bytes(&mut bytes).map_err(|_| invalid("Random generator unavailable."))?;
    let secret = encode(&bytes);
    let mut pending = PENDING.lock().unwrap();
    pending.retain(|_, p| p.expires > Instant::now());
    if pending.len() >= 1000 && !pending.contains_key(&session.id) {
        return Err(error(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many pending enrollments. Try again later.",
        ));
    }
    pending.insert(
        session.id.clone(),
        Pending {
            secret: secret.clone(),
            user_id: session.user.id.clone(),
            expires: Instant::now() + Duration::from_secs(600),
        },
    );
    let label = url::form_urlencoded::byte_serialize(
        format!("EmberGate:{}", session.user.username).as_bytes(),
    )
    .collect::<String>();
    Ok(Json(
        json!({"secret":secret,"uri":format!("otpauth://totp/{label}?secret={secret}&issuer=EmberGate&algorithm=SHA1&digits=6&period=30"),"expires_in_seconds":600}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Confirm {
    code: String,
}
async fn confirm(
    State(state): State<Shared>,
    Extension(session): Extension<Session>,
    Json(input): Json<Confirm>,
) -> Result<Json<Value>, Error> {
    crate::accounts::limit_attempts(&state, &session.peer)?;
    crate::accounts::limit_attempts(&state, &format!("mfa:{}", session.user.id))?;
    let _guard = state.account_write_lock.lock().await;
    if !state
        .sessions
        .lock()
        .unwrap()
        .values()
        .any(|s| s.id == session.id && s.expires > Instant::now())
    {
        return Err(error(StatusCode::UNAUTHORIZED, "Please sign in again."));
    }
    let secret = {
        let pending = PENDING.lock().unwrap();
        pending
            .get(&session.id)
            .filter(|p| p.expires > Instant::now() && p.user_id == session.user.id)
            .map(|p| p.secret.clone())
    }
    .ok_or_else(|| error(StatusCode::CONFLICT, "Enrollment expired. Start again."))?;
    let step = step(&secret, input.code.trim(), now(), None)
        .map_err(storage)?
        .ok_or_else(|| invalid("Incorrect authentication code. Check your device’s clock."))?;
    let (codes, hashes) = recovery().map_err(storage)?;
    let id = session.user.id.clone();
    state
        .control
        .run(move |db| {
            if read(db, &id)?.is_some() {
                return Err("Two-factor authentication is already enabled.".into());
            }
            write(
                db,
                &id,
                &Record {
                    secret,
                    last_step: Some(step),
                    recovery_hashes: hashes,
                },
            )
        })
        .await
        .map_err(storage)?;
    PENDING.lock().unwrap().remove(&session.id);
    retain_current(&state, &session, true);
    Ok(Json(json!({"ok":true,"recovery_codes":codes})))
}
async fn disable(
    State(state): State<Shared>,
    Extension(session): Extension<Session>,
    Json(input): Json<Proof>,
) -> Result<Json<Value>, Error> {
    let _guard = state.account_write_lock.lock().await;
    if session.user.role.admin() && policy(&state).map_err(storage)? {
        return Err(error(StatusCode::CONFLICT,"Administrator two-factor authentication is required. Change the policy before disabling it."));
    }
    prove(&state, &session, &input, true).await?;
    state
        .control
        .set_secret(key(&session.user.id), None)
        .await
        .map_err(storage)?;
    retain_current(&state, &session, false);
    Ok(Json(json!({"ok":true})))
}
async fn regenerate(
    State(state): State<Shared>,
    Extension(session): Extension<Session>,
    Json(input): Json<Proof>,
) -> Result<Json<Value>, Error> {
    let _guard = state.account_write_lock.lock().await;
    prove(&state, &session, &input, true).await?;
    let (codes, hashes) = recovery().map_err(storage)?;
    let id = session.user.id.clone();
    state
        .control
        .run(move |db| {
            let mut record = read(db, &id)?.ok_or("Two-factor authentication is not enabled.")?;
            record.recovery_hashes = hashes;
            write(db, &id, &record)
        })
        .await
        .map_err(storage)?;
    retain_current(&state, &session, true);
    Ok(Json(json!({"ok":true,"recovery_codes":codes})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    require_administrators: bool,
    current_password: String,
    code: String,
}
async fn save_policy(
    State(state): State<Shared>,
    Extension(session): Extension<Session>,
    Json(input): Json<Policy>,
) -> Result<Json<Value>, Error> {
    if !session.user.role.admin() {
        return Err(error(
            StatusCode::FORBIDDEN,
            "Administrator access required.",
        ));
    }
    let _guard = state.account_write_lock.lock().await;
    prove(
        &state,
        &session,
        &Proof {
            current_password: input.current_password,
            code: input.code,
        },
        true,
    )
    .await?;
    state
        .control
        .set_secret(
            "mfa_policy".into(),
            Some(input.require_administrators.to_string()),
        )
        .await
        .map_err(storage)?;
    Ok(Json(json!({"ok":true})))
}
pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/mfa", get(status).delete(disable))
        .route("/api/mfa/setup", post(setup))
        .route("/api/mfa/confirm", post(confirm))
        .route("/api/mfa/recovery", post(regenerate))
        .route("/api/mfa/policy", axum::routing::put(save_policy))
}
pub fn validate_backup(key: &str, value: &str, users: &[String]) -> Result<(), String> {
    if key == "mfa_policy" && matches!(value, "true" | "false") {
        return Ok(());
    }
    if let Some(id) = key.strip_prefix("mfa:") {
        if !users.iter().any(|user| user == id) {
            return Err("Authenticator references an unknown account.".into());
        }
        let record: Record =
            serde_json::from_str(value).map_err(|_| "Invalid authenticator record.")?;
        return record.validate();
    }
    Err("Invalid two-factor authentication setting.".into())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rfc_vectors_and_replay_window() {
        let secret = encode(b"12345678901234567890");
        assert_eq!(decode(&secret).unwrap(), b"12345678901234567890");
        for (at, expected) in [
            (59, "94287082"),
            (1111111109, "07081804"),
            (1111111111, "14050471"),
            (1234567890, "89005924"),
            (2000000000, "69279037"),
            (20000000000, "65353130"),
        ] {
            assert_eq!(totp(&secret, at / 30, 8).unwrap(), expected);
        }
        let code = totp(&secret, 100, 6).unwrap();
        assert_eq!(step(&secret, &code, 3000, None).unwrap(), Some(100));
        assert_eq!(step(&secret, &code, 3000, Some(100)).unwrap(), None);
        assert_eq!(step(&secret, &code, 3060, None).unwrap(), None);
    }
    #[tokio::test]
    async fn recovery_is_hashed_and_single_use() {
        let file = std::env::temp_dir().join(format!("mfa-{}.db", uuid::Uuid::new_v4()));
        let control = management::Control::open(&file).unwrap();
        let (codes, hashes) = recovery().unwrap();
        assert_eq!(codes.len(), 10);
        assert!(!hashes.contains(&codes[0]));
        let record = Record {
            secret: encode(&[5u8; 20]),
            last_step: None,
            recovery_hashes: hashes,
        };
        record.validate().unwrap();
        write(
            &rusqlite::Connection::open(&file).unwrap(),
            "bootstrap",
            &record,
        )
        .unwrap();
        control
            .run(move |db| {
                assert!(!consume(db, "bootstrap", "invalid", 3000)?);
                assert!(consume(db, "bootstrap", &codes[0], 3000)?);
                assert!(!consume(db, "bootstrap", &codes[0], 3000)?);
                assert_eq!(read(db, "bootstrap")?.unwrap().recovery_hashes.len(), 9);
                let code = totp(&encode(&[5u8; 20]), 100, 6)?;
                assert!(consume(db, "bootstrap", &code, 3000)?);
                assert!(!consume(db, "bootstrap", &code, 3000)?);
                assert!(!consume(db, "bootstrap", &code, 3060)?);
                Ok(())
            })
            .await
            .unwrap();
        drop(control);
        let _ = std::fs::remove_file(file);
    }
}

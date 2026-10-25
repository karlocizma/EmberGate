//! Personal API tokens for scripts and the CLI. Tokens live in the management
//! `secrets` table; only a SHA-256 digest of each secret is stored.
use crate::{
    accounts::Session,
    management::{self, AuditExtra, Role, User},
    state::{now, Shared},
};
use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get},
    Extension, Json, Router,
};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::{Duration, Instant};

const PREFIX: &str = "api_token:";
const MAX_PER_USER: usize = 20;
/// Failed token attempts allowed per client address and minute.
const FAILURE_LIMIT: usize = 20;
const EXPIRY_DAYS: [u32; 4] = [7, 30, 90, 365];

type Error = (StatusCode, Json<Value>);
fn error(status: StatusCode, message: impl ToString) -> Error {
    (status, Json(json!({"error":message.to_string()})))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    ReadOnly,
    Full,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Record {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub scope: Scope,
    pub digest: String,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub last_used_at: Option<u64>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn digest(secret: &str) -> String {
    hex(&openssl::sha::sha256(secret.as_bytes()))
}
fn is_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Splits `eg_<16 hex id>_<64 hex secret>` into its id and secret.
fn parse(raw: &str) -> Option<(&str, &str)> {
    let (id, secret) = raw.strip_prefix("eg_")?.split_once('_')?;
    (is_hex(id, 16) && is_hex(secret, 64)).then_some((id, secret))
}

pub fn bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then(|| token.trim())
}

/// Paths a token can never reach, so a leaked token cannot take over its account.
pub fn forbidden(path: &str) -> bool {
    [
        "/api/users",
        "/api/password",
        "/api/sessions",
        "/api/mfa",
        "/api/passkeys",
        "/api/tokens",
        "/api/logout",
    ]
    .iter()
    .any(|prefix| path == *prefix || path.starts_with(&format!("{prefix}/")))
}

fn recent_failures(state: &Shared, key: &str) -> usize {
    let mut attempts = state.login_attempts.lock().unwrap();
    attempts.retain(|_, times| {
        times.retain(|time| time.elapsed() < Duration::from_secs(60));
        !times.is_empty()
    });
    attempts.get(key).map_or(0, |times| times.len())
}
fn record_failure(state: &Shared, key: String) {
    let mut attempts = state.login_attempts.lock().unwrap();
    if attempts.len() < 1024 || attempts.contains_key(&key) {
        attempts.entry(key).or_default().push_back(Instant::now());
    }
}

async fn load(state: &Shared, id: &str) -> Result<Option<Record>, String> {
    let key = format!("{PREFIX}{id}");
    state
        .control
        .run(move |db| {
            db.query_row(
                "SELECT value FROM secrets WHERE key=?1",
                params![key],
                |r| r.get::<_, String>(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                e => Err(management::storage(e)),
            })
        })
        .await?
        .map(|value| serde_json::from_str(&value).map_err(|_| "Invalid API token record.".into()))
        .transpose()
}

async fn store(state: &Shared, record: &Record) -> Result<(), String> {
    state
        .control
        .set_secret(
            format!("{PREFIX}{}", record.id),
            Some(serde_json::to_string(record).expect("token serialization")),
        )
        .await
}

async fn all(state: &Shared) -> Result<Vec<Record>, String> {
    let mut records = state
        .control
        .run(|db| {
            let mut query = db
                .prepare("SELECT value FROM secrets WHERE key LIKE 'api_token:%'")
                .map_err(management::storage)?;
            let rows = query
                .query_map([], |r| r.get::<_, String>(0))
                .map_err(management::storage)?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(management::storage)
        })
        .await?
        .into_iter()
        .map(|value| {
            serde_json::from_str(&value).map_err(|_| "Invalid API token record.".to_owned())
        })
        .collect::<Result<Vec<Record>, _>>()?;
    records.sort_by(|a, b| b.created_at.cmp(&a.created_at).then(a.id.cmp(&b.id)));
    Ok(records)
}

async fn owner(state: &Shared, user_id: &str) -> Result<Option<User>, String> {
    if user_id == "bootstrap" && state.password_hash.is_some() {
        return Ok(Some(management::bootstrap()));
    }
    Ok(state
        .control
        .users()
        .await?
        .into_iter()
        .find(|user| user.id == user_id))
}

/// Resolves a bearer token to a request session. The owner is read on every
/// request, so disabling an account or lowering its role applies at once.
pub async fn authenticate(state: &Shared, raw: &str, peer: &str) -> Result<Session, Response> {
    let throttle = format!("token:{peer}");
    if recent_failures(state, &throttle) >= FAILURE_LIMIT {
        return Err(error(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many failed token attempts. Try again in a minute.",
        )
        .into_response());
    }
    let unavailable = |e: String| error(StatusCode::SERVICE_UNAVAILABLE, e).into_response();
    let found = match parse(raw) {
        Some((id, secret)) => load(state, id)
            .await
            .map_err(unavailable)?
            .filter(|r| openssl::memcmp::eq(r.digest.as_bytes(), digest(secret).as_bytes())),
        None => None,
    };
    let Some(mut record) = found.filter(|r| r.expires_at.is_none_or(|at| at > now())) else {
        record_failure(state, throttle);
        return Err(
            error(StatusCode::UNAUTHORIZED, "Invalid or expired API token.").into_response(),
        );
    };
    let Some(mut user) = owner(state, &record.user_id)
        .await
        .map_err(unavailable)?
        .filter(|u| u.enabled)
    else {
        record_failure(state, throttle);
        return Err(
            error(StatusCode::UNAUTHORIZED, "Invalid or expired API token.").into_response(),
        );
    };
    if record.scope == Scope::ReadOnly {
        user.role = Role::ReadOnly;
    }
    if record.last_used_at.is_none_or(|at| at + 60 <= now()) {
        record.last_used_at = Some(now());
        if let Err(e) = store(state, &record).await {
            log::warn!("Could not record API token use: {e}");
        }
    }
    let mut session = Session::new(user, peer.to_owned());
    session.id = format!("token:{}", record.id);
    session.expires_at = record.expires_at.unwrap_or(session.expires_at);
    session.expires = Instant::now() + Duration::from_secs(60);
    session.mfa_verified = true;
    session.token = Some(record.name);
    Ok(session)
}

#[derive(Serialize)]
struct Summary {
    id: String,
    name: String,
    scope: Scope,
    created_at: u64,
    expires_at: Option<u64>,
    last_used_at: Option<u64>,
    user_id: String,
    username: String,
}

async fn list(
    State(state): State<Shared>,
    Extension(session): Extension<Session>,
) -> Result<Json<Value>, Error> {
    let unavailable = |e| error(StatusCode::SERVICE_UNAVAILABLE, e);
    let records = all(&state).await.map_err(unavailable)?;
    let mut users = state.control.users().await.map_err(unavailable)?;
    users.push(management::bootstrap());
    let tokens: Vec<Summary> = records
        .into_iter()
        .filter(|r| session.user.role.admin() || r.user_id == session.user.id)
        .map(|r| Summary {
            username: users
                .iter()
                .find(|u| u.id == r.user_id)
                .map(|u| u.username.clone())
                .unwrap_or_default(),
            id: r.id,
            name: r.name,
            scope: r.scope,
            created_at: r.created_at,
            expires_at: r.expires_at,
            last_used_at: r.last_used_at,
            user_id: r.user_id,
        })
        .collect();
    Ok(Json(json!({"tokens":tokens})))
}

#[derive(Deserialize)]
struct Create {
    name: String,
    scope: Scope,
    expires_in_days: Option<u32>,
}

fn name(value: &str) -> Result<String, String> {
    let name = value.trim();
    if name.is_empty() || name.chars().count() > 64 || name.chars().any(char::is_control) {
        return Err("Enter a token name of up to 64 characters.".into());
    }
    Ok(name.to_owned())
}

async fn create(
    State(state): State<Shared>,
    Extension(session): Extension<Session>,
    Json(input): Json<Create>,
) -> Result<Response, Error> {
    let invalid = |e| error(StatusCode::UNPROCESSABLE_ENTITY, e);
    let name = name(&input.name).map_err(invalid)?;
    if input.scope == Scope::Full && !session.user.role.admin() {
        return Err(invalid(
            "Read-only accounts can create read-only tokens only.".into(),
        ));
    }
    if input
        .expires_in_days
        .is_some_and(|days| !EXPIRY_DAYS.contains(&days))
    {
        return Err(invalid(
            "Choose an expiry of 7, 30, 90, or 365 days, or no expiry.".into(),
        ));
    }
    let _guard = state.account_write_lock.lock().await;
    let records = all(&state)
        .await
        .map_err(|e| error(StatusCode::SERVICE_UNAVAILABLE, e))?;
    if records
        .iter()
        .filter(|r| r.user_id == session.user.id)
        .count()
        >= MAX_PER_USER
    {
        return Err(invalid(format!(
            "An account can have at most {MAX_PER_USER} API tokens. Revoke one first."
        )));
    }
    let mut id = [0u8; 8];
    let mut secret = [0u8; 32];
    openssl::rand::rand_bytes(&mut id)
        .and_then(|_| openssl::rand::rand_bytes(&mut secret))
        .map_err(|_| {
            error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not generate a token.",
            )
        })?;
    let (id, secret) = (hex(&id), hex(&secret));
    let record = Record {
        id: id.clone(),
        user_id: session.user.id.clone(),
        name,
        scope: input.scope,
        digest: digest(&secret),
        created_at: now(),
        expires_at: input
            .expires_in_days
            .map(|days| now() + u64::from(days) * 86400),
        last_used_at: None,
    };
    store(&state, &record)
        .await
        .map_err(|e| error(StatusCode::SERVICE_UNAVAILABLE, e))?;
    let mut response = (
        StatusCode::CREATED,
        Json(json!({"token":format!("eg_{id}_{secret}"),"id":id,"name":record.name,"scope":record.scope,"expires_at":record.expires_at})),
    )
        .into_response();
    response.extensions_mut().insert(AuditExtra(id));
    Ok(response)
}

async fn revoke(
    State(state): State<Shared>,
    Extension(session): Extension<Session>,
    Path(id): Path<String>,
) -> Result<Response, Error> {
    let not_found = || error(StatusCode::NOT_FOUND, "API token not found.");
    if !is_hex(&id, 16) {
        return Err(not_found());
    }
    let _guard = state.account_write_lock.lock().await;
    let record = load(&state, &id)
        .await
        .map_err(|e| error(StatusCode::SERVICE_UNAVAILABLE, e))?
        .filter(|r| session.user.role.admin() || r.user_id == session.user.id)
        .ok_or_else(not_found)?;
    state
        .control
        .set_secret(format!("{PREFIX}{}", record.id), None)
        .await
        .map_err(|e| error(StatusCode::SERVICE_UNAVAILABLE, e))?;
    let mut response = Json(json!({"ok":true})).into_response();
    response.extensions_mut().insert(AuditExtra(id));
    Ok(response)
}

/// Removes every token of a deleted account inside its deletion transaction.
pub fn delete_for_user(db: &rusqlite::Transaction<'_>, user_id: &str) -> Result<(), String> {
    db.execute(
        "DELETE FROM secrets WHERE key LIKE 'api_token:%' AND json_extract(value,'$.user_id')=?1",
        params![user_id],
    )
    .map_err(management::storage)?;
    Ok(())
}

pub fn validate_backup(key: &str, value: &str, users: &[String]) -> Result<(), String> {
    let invalid = || "Invalid API token record.".to_owned();
    let record: Record = serde_json::from_str(value).map_err(|_| invalid())?;
    if key != format!("{PREFIX}{}", record.id)
        || !is_hex(&record.id, 16)
        || !is_hex(&record.digest, 64)
        || name(&record.name).ok().as_deref() != Some(record.name.as_str())
        || !users.contains(&record.user_id)
    {
        return Err(invalid());
    }
    Ok(())
}

pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/tokens", get(list).post(create))
        .route("/api/tokens/{id}", delete(revoke))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_parse_only_in_the_issued_format() {
        let id = "0123456789abcdef";
        let secret = "ab".repeat(32);
        assert_eq!(
            parse(&format!("eg_{id}_{secret}")),
            Some((id, secret.as_str()))
        );
        for bad in [
            format!("{id}_{secret}"),
            format!("eg_{id}{secret}"),
            format!("eg_{}_{secret}", id.to_uppercase()),
            format!("eg_{id}_{}", &secret[1..]),
            format!("eg_{id}_{secret}_"),
        ] {
            assert_eq!(parse(&bad), None, "{bad}");
        }
    }

    #[test]
    fn backups_accept_only_well_formed_records_of_known_users() {
        let record = Record {
            id: "0123456789abcdef".into(),
            user_id: "bootstrap".into(),
            name: "ci".into(),
            scope: Scope::Full,
            digest: digest("secret"),
            created_at: 1,
            expires_at: None,
            last_used_at: None,
        };
        let users = ["bootstrap".to_string()];
        let value = serde_json::to_string(&record).unwrap();
        assert!(validate_backup("api_token:0123456789abcdef", &value, &users).is_ok());
        assert!(validate_backup("api_token:ffffffffffffffff", &value, &users).is_err());
        assert!(validate_backup("api_token:0123456789abcdef", &value, &["other".into()]).is_err());
        let mut bad = record.clone();
        bad.digest = "plain secret".into();
        assert!(validate_backup(
            "api_token:0123456789abcdef",
            &serde_json::to_string(&bad).unwrap(),
            &users
        )
        .is_err());
        bad = record;
        bad.name = " padded".into();
        assert!(validate_backup(
            "api_token:0123456789abcdef",
            &serde_json::to_string(&bad).unwrap(),
            &users
        )
        .is_err());
    }

    #[test]
    fn bearer_scheme_is_case_insensitive() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "bearer eg_x".parse().unwrap());
        assert_eq!(bearer(&headers), Some("eg_x"));
        headers.insert(header::AUTHORIZATION, "Basic abc".parse().unwrap());
        assert_eq!(bearer(&headers), None);
    }

    #[test]
    fn tokens_cannot_reach_account_or_sign_in_management() {
        for path in [
            "/api/users",
            "/api/users/1",
            "/api/password",
            "/api/sessions/1",
            "/api/mfa",
            "/api/mfa/setup",
            "/api/passkeys/register/start",
            "/api/tokens",
            "/api/tokens/0123456789abcdef",
            "/api/logout",
        ] {
            assert!(forbidden(path), "{path}");
        }
        for path in [
            "/api/config",
            "/api/usersx",
            "/api/session",
            "/api/docker/containers",
            "/api/backups/export",
        ] {
            assert!(!forbidden(path), "{path}");
        }
    }
}

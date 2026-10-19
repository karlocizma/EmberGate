//! WebAuthn with server-held one-use ceremonies, pinned origin, and durable credentials.
use crate::{
    accounts::Session,
    management,
    state::{now, Shared},
};
use axum::{
    extract::{ConnectInfo, Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Extension, Json, Router,
};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    path::PathBuf,
    sync::{LazyLock, Mutex},
    time::{Duration, Instant},
};
use webauthn_rs::prelude::*;
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
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    id: String,
    name: String,
    created_at: u64,
    last_used: Option<u64>,
    key: Passkey,
}
fn key(id: &str) -> String {
    format!("passkeys:{id}")
}
fn read(db: &rusqlite::Connection, id: &str) -> Result<Vec<Stored>, String> {
    let value: Option<String> = db
        .query_row(
            "SELECT value FROM secrets WHERE key=?1",
            params![key(id)],
            |r| r.get(0),
        )
        .optional()
        .map_err(management::storage)?;
    match value {
        None => Ok(vec![]),
        Some(value) => decode(&value),
    }
}
fn decode(value: &str) -> Result<Vec<Stored>, String> {
    if value.len() > 512 * 1024 {
        return Err("Invalid passkey storage.".into());
    }
    let keys: Vec<Stored> = serde_json::from_str(value).map_err(|_| "Invalid passkey storage.")?;
    let mut ids = HashSet::new();
    let mut credentials = Vec::new();
    if keys.len() > 16 {
        return Err("Too many passkeys.".into());
    }
    for item in &keys {
        if Uuid::parse_str(&item.id).is_err()
            || !ids.insert(&item.id)
            || item.name.trim() != item.name
            || item.name.is_empty()
            || item.name.chars().count() > 80
            || item.name.chars().any(char::is_control)
            || item.key.cred_id().as_ref().is_empty()
            || item.key.cred_id().as_ref().len() > 1024
            || credentials.contains(&item.key.cred_id())
        {
            return Err("Invalid passkey record.".into());
        }
        credentials.push(item.key.cred_id());
    }
    Ok(keys)
}
fn write(db: &rusqlite::Connection, id: &str, keys: &[Stored]) -> Result<(), String> {
    if keys.is_empty() {
        db.execute("DELETE FROM secrets WHERE key=?1", params![key(id)])
            .map_err(management::storage)?;
    } else {
        db.execute(
            "INSERT INTO secrets VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![
                key(id),
                serde_json::to_string(keys).map_err(|_| "Cannot save passkey.")?
            ],
        )
        .map_err(management::storage)?;
    }
    Ok(())
}
fn origin(value: &str) -> Result<Url, String> {
    let url = Url::parse(value).map_err(|_| "Enter the dashboard's absolute HTTPS origin.")?;
    let local = url
        .host_str()
        .is_some_and(|host| host == "localhost" || host.ends_with(".localhost"));
    if value.len() > 2048
        || url.host_str().is_none()
        || !(url.scheme() == "https" || (url.scheme() == "http" && local))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err("Passkeys require an HTTPS origin, or http://localhost for local use, with no path, query, or credentials.".into());
    }
    WebauthnBuilder::new(url.host_str().unwrap(), &url)
        .and_then(|builder| builder.rp_name("EmberGate").build())
        .map_err(|_| "Unsupported passkey origin.")?;
    Ok(url)
}
fn webauthn(state: &Shared) -> Result<(Webauthn, String), Error> {
    let value = state
        .control
        .secret("passkey_origin")
        .map_err(storage)?
        .ok_or_else(|| {
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Passkey sign-in is not configured. Sign in with your password first.",
            )
        })?;
    let url = origin(&value).map_err(storage)?;
    let webauthn = WebauthnBuilder::new(url.host_str().unwrap(), &url)
        .and_then(|builder| builder.rp_name("EmberGate").build())
        .map_err(|_| invalid("Passkey origin is invalid."))?;
    Ok((webauthn, url.origin().ascii_serialization()))
}
struct Registration {
    root: PathBuf,
    session: String,
    user: String,
    origin: String,
    name: String,
    expires: Instant,
    state: PasskeyRegistration,
}
struct Authentication {
    root: PathBuf,
    peer: String,
    origin: String,
    expires: Instant,
    user: Option<management::User>,
    state: Option<PasskeyAuthentication>,
}
static REGISTRATIONS: LazyLock<Mutex<HashMap<String, Registration>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static AUTHENTICATIONS: LazyLock<Mutex<HashMap<String, Authentication>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
fn verified(headers: &HeaderMap) -> Result<(), Error> {
    if headers
        .get("x-gateway-request")
        .and_then(|v| v.to_str().ok())
        != Some("1")
    {
        Err(error(
            StatusCode::FORBIDDEN,
            "Missing request verification header.",
        ))
    } else {
        Ok(())
    }
}
fn peer(info: Option<Extension<ConnectInfo<SocketAddr>>>) -> String {
    info.map(|p| p.0 .0.ip().to_string())
        .unwrap_or_else(|| "local".into())
}
fn challenge_cookie(id: &str, secure: bool) -> String {
    format!("embergate_passkey={id}; HttpOnly; SameSite=Strict; Path=/api/passkeys/login; Max-Age=300{}",if secure{"; Secure"}else{""})
}
fn cookie(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|p| p.trim().strip_prefix("embergate_passkey="))
}
async fn prove(state: &Shared, session: &Session, proof: &crate::mfa::Proof) -> Result<(), Error> {
    let factor = crate::mfa::enabled(state, &session.user.id)
        .await
        .map_err(storage)?;
    crate::mfa::prove(state, session, proof, factor).await
}
async fn status(
    State(state): State<Shared>,
    Extension(session): Extension<Session>,
) -> Result<Json<Value>, Error> {
    let id = session.user.id;
    let keys = state
        .control
        .run(move |db| read(db, &id))
        .await
        .map_err(storage)?;
    Ok(Json(
        json!({"origin":state.control.secret("passkey_origin").map_err(storage)?,"keys":keys.iter().map(|k|json!({"id":k.id,"name":k.name,"created_at":k.created_at,"last_used":k.last_used})).collect::<Vec<_>>()}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginInput {
    origin: String,
    current_password: String,
    #[serde(default)]
    code: String,
}
async fn configure(
    State(state): State<Shared>,
    Extension(session): Extension<Session>,
    Json(input): Json<OriginInput>,
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
        &crate::mfa::Proof {
            current_password: input.current_password,
            code: input.code,
        },
    )
    .await?;
    let value = origin(input.origin.trim())
        .map_err(invalid)?
        .origin()
        .ascii_serialization();
    let current = state.control.secret("passkey_origin").map_err(storage)?;
    if current.as_deref() != Some(&value) {
        state
            .control
            .run(|db| {
                let count: i64 = db
                    .query_row(
                        "SELECT COUNT(*) FROM secrets WHERE key LIKE 'passkeys:%'",
                        [],
                        |r| r.get(0),
                    )
                    .map_err(management::storage)?;
                if count != 0 {
                    return Err("Remove all registered passkeys before changing the origin.".into());
                }
                Ok(())
            })
            .await
            .map_err(invalid)?;
    }
    state
        .control
        .set_secret("passkey_origin".into(), Some(value))
        .await
        .map_err(storage)?;
    Ok(Json(json!({"ok":true})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterStart {
    name: String,
    current_password: String,
    #[serde(default)]
    code: String,
}
async fn register_start(
    State(state): State<Shared>,
    Extension(session): Extension<Session>,
    Json(input): Json<RegisterStart>,
) -> Result<Json<Value>, Error> {
    let _guard = state.account_write_lock.lock().await;
    prove(
        &state,
        &session,
        &crate::mfa::Proof {
            current_password: input.current_password,
            code: input.code,
        },
    )
    .await?;
    let name = input.name.trim().to_string();
    if name.is_empty() || name.chars().count() > 80 || name.chars().any(char::is_control) {
        return Err(invalid("Use a passkey name of 1–80 characters."));
    }
    let (webauthn, origin) = webauthn(&state)?;
    let id = session.user.id.clone();
    let existing = state
        .control
        .run(move |db| read(db, &id))
        .await
        .map_err(storage)?;
    if existing.len() >= 16 {
        return Err(invalid(
            "A maximum of 16 passkeys per account is supported.",
        ));
    }
    let digest = openssl::sha::sha256(format!("EmberGate user:{}", session.user.id).as_bytes());
    let handle = Uuid::from_bytes(digest[..16].try_into().unwrap());
    let (options, registration) = webauthn
        .start_passkey_registration(
            handle,
            &session.user.username,
            &session.user.username,
            Some(existing.iter().map(|k| k.key.cred_id().clone()).collect()),
        )
        .map_err(|_| invalid("Cannot begin passkey registration."))?;
    let id = Uuid::new_v4().to_string();
    let mut pending = REGISTRATIONS.lock().unwrap();
    pending.retain(|_, p| p.expires > Instant::now());
    if pending.len() >= 128 {
        return Err(error(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many pending registrations.",
        ));
    }
    pending.insert(
        id.clone(),
        Registration {
            root: state.config_path.clone(),
            session: session.id,
            user: session.user.id,
            origin,
            name,
            expires: Instant::now() + Duration::from_secs(300),
            state: registration,
        },
    );
    Ok(Json(json!({"id":id,"options":options})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterFinish {
    id: String,
    credential: RegisterPublicKeyCredential,
}
async fn register_finish(
    State(state): State<Shared>,
    Extension(session): Extension<Session>,
    Json(input): Json<RegisterFinish>,
) -> Result<Json<Value>, Error> {
    let _guard = state.account_write_lock.lock().await;
    let pending = REGISTRATIONS
        .lock()
        .unwrap()
        .remove(&input.id)
        .ok_or_else(|| invalid("Registration expired. Start again."))?;
    let (webauthn, origin) = webauthn(&state)?;
    if pending.root != state.config_path
        || pending.session != session.id
        || pending.user != session.user.id
        || pending.origin != origin
        || pending.expires <= Instant::now()
    {
        return Err(invalid(
            "Registration expired or belongs to another session.",
        ));
    }
    let passkey = webauthn
        .finish_passkey_registration(&input.credential, &pending.state)
        .map_err(|_| {
            invalid("Passkey registration failed. Verify your device and origin, then try again.")
        })?;
    let user = session.user.id.clone();
    state
        .control
        .run(move |db| {
            let tx = db.transaction().map_err(management::storage)?;
            let mut keys = read(&tx, &user)?;
            if keys.len() >= 16 {
                return Err("Too many passkeys.".into());
            }
            let mut stmt = tx
                .prepare("SELECT value FROM secrets WHERE key LIKE 'passkeys:%'")
                .map_err(management::storage)?;
            let values = stmt
                .query_map([], |r| r.get::<_, String>(0))
                .map_err(management::storage)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(management::storage)?;
            drop(stmt);
            for value in values {
                if decode(&value)?
                    .iter()
                    .any(|k| k.key.cred_id() == passkey.cred_id())
                {
                    return Err("That passkey is already registered.".into());
                }
            }
            keys.push(Stored {
                id: Uuid::new_v4().to_string(),
                name: pending.name,
                created_at: now(),
                last_used: None,
                key: passkey,
            });
            write(&tx, &user, &keys)?;
            tx.commit().map_err(management::storage)?;
            Ok(())
        })
        .await
        .map_err(invalid)?;
    state
        .sessions
        .lock()
        .unwrap()
        .retain(|_, s| s.user.id != session.user.id || s.id == session.id);
    Ok(Json(json!({"ok":true})))
}
async fn remove(
    State(state): State<Shared>,
    Extension(session): Extension<Session>,
    Path(id): Path<String>,
    Json(proof): Json<crate::mfa::Proof>,
) -> Result<Json<Value>, Error> {
    let _guard = state.account_write_lock.lock().await;
    prove(&state, &session, &proof).await?;
    let user = session.user.id.clone();
    state
        .control
        .run(move |db| {
            let mut keys = read(db, &user)?;
            let count = keys.len();
            keys.retain(|k| k.id != id);
            if keys.len() == count {
                return Err("Passkey not found.".into());
            }
            write(db, &user, &keys)
        })
        .await
        .map_err(invalid)?;
    state
        .sessions
        .lock()
        .unwrap()
        .retain(|_, s| s.user.id != session.user.id);
    Ok(Json(json!({"ok":true})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginStart {
    username: String,
}
pub async fn login_start(
    State(state): State<Shared>,
    info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(input): Json<LoginStart>,
) -> Result<Response, Error> {
    verified(&headers)?;
    let peer = peer(info);
    crate::accounts::limit_attempts(&state, &peer)?;
    let (webauthn, origin) = webauthn(&state)?;
    let credentials = if let Ok(name) = management::username(&input.username) {
        crate::accounts::credentials(&state, &name).await?
    } else {
        None
    };
    let user = credentials.filter(|c| c.user.enabled).map(|c| c.user);
    let keys = if let Some(user) = &user {
        let id = user.id.clone();
        state
            .control
            .run(move |db| read(db, &id))
            .await
            .map_err(storage)?
    } else {
        vec![]
    };
    let (options, authentication) = if !keys.is_empty() {
        let (options, pending) = webauthn
            .start_passkey_authentication(&keys.into_iter().map(|k| k.key).collect::<Vec<_>>())
            .map_err(|_| invalid("Cannot begin passkey sign-in."))?;
        (serde_json::to_value(options).unwrap(), Some(pending))
    } else {
        let mut random = [0u8; 32];
        openssl::rand::rand_bytes(&mut random)
            .map_err(|_| invalid("Cannot begin passkey sign-in."))?;
        let challenge = openssl::base64::encode_block(&random)
            .trim_end_matches('=')
            .replace('+', "-")
            .replace('/', "_");
        let rp = Url::parse(&origin).unwrap();
        (
            json!({"publicKey":{"challenge":challenge,"timeout":60000,"rpId":rp.host_str(),"allowCredentials":[{"type":"public-key","id":challenge}],"userVerification":"required"}}),
            None,
        )
    };
    let id = Uuid::new_v4().to_string();
    let mut pending = AUTHENTICATIONS.lock().unwrap();
    pending.retain(|_, p| p.expires > Instant::now());
    if pending.len() >= 256 {
        return Err(error(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many sign-in attempts. Try later.",
        ));
    }
    pending.insert(
        id.clone(),
        Authentication {
            root: state.config_path.clone(),
            peer,
            origin: origin.clone(),
            expires: Instant::now() + Duration::from_secs(300),
            user,
            state: authentication,
        },
    );
    Ok((
        [(
            header::SET_COOKIE,
            challenge_cookie(&id, origin.starts_with("https://")),
        )],
        Json(json!({"id":id,"options":options})),
    )
        .into_response())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginFinish {
    id: String,
    credential: PublicKeyCredential,
}
pub async fn login_finish(
    State(state): State<Shared>,
    info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(input): Json<LoginFinish>,
) -> Result<Response, Error> {
    verified(&headers)?;
    let peer = peer(info);
    crate::accounts::limit_attempts(&state, &peer)?;
    let denied = || {
        error(
            StatusCode::UNAUTHORIZED,
            "Passkey sign-in failed or expired. Try again or use your password.",
        )
    };
    if cookie(&headers) != Some(&input.id) {
        return Err(denied());
    }
    let pending = AUTHENTICATIONS
        .lock()
        .unwrap()
        .remove(&input.id)
        .ok_or_else(denied)?;
    let (webauthn, origin) = webauthn(&state)?;
    if pending.root != state.config_path
        || pending.origin != origin
        || pending.peer != peer
        || pending.expires <= Instant::now()
    {
        return Err(denied());
    }
    let user = pending.user.ok_or_else(denied)?;
    let authentication = pending.state.ok_or_else(denied)?;
    let audit = state
        .control
        .begin_audit(
            management::AuditActor {
                user_id: user.id.clone(),
                username: user.username.clone(),
                role: user.role.as_str().into(),
                peer: peer.clone(),
            },
            "POST".into(),
            "/api/passkeys/login/finish".into(),
            json!({}),
        )
        .await
        .map_err(storage)?;
    let result = async {
        let _mutation = state.backups.mutations.lock().await;
        if state
            .backups
            .pending
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(error(
                StatusCode::CONFLICT,
                "A restore is queued. Restart EmberGate or use password sign-in.",
            ));
        }
        let _guard = state.account_write_lock.lock().await;
        let current = crate::accounts::credentials(&state, &user.username)
            .await?
            .filter(|c| c.user.enabled && c.user.id == user.id && c.user.version == user.version)
            .ok_or_else(denied)?;
        let result = webauthn
            .finish_passkey_authentication(&input.credential, &authentication)
            .map_err(|_| denied())?;
        if !result.user_verified() {
            return Err(denied());
        }
        let id = user.id.clone();
        state
            .control
            .run(move |db| {
                let mut keys = read(db, &id)?;
                let key = keys
                    .iter_mut()
                    .find(|k| k.key.cred_id() == result.cred_id())
                    .ok_or("Passkey was removed.")?;
                key.key
                    .update_credential(&result)
                    .ok_or("Passkey update failed.")?;
                key.last_used = Some(now());
                write(db, &id, &keys)
            })
            .await
            .map_err(storage)?;
        state
            .backups
            .revision
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let token = Uuid::new_v4().to_string();
        let mut sessions = state.sessions.lock().unwrap();
        sessions.retain(|_, s| s.expires > Instant::now());
        if sessions.len() >= 1000 {
            return Err(error(
                StatusCode::TOO_MANY_REQUESTS,
                "Session limit reached.",
            ));
        }
        let mut session = Session::new(current.user.clone(), peer);
        session.mfa_verified = true;
        sessions.insert(token.clone(), session);
        let cookie = format!(
            "gateway_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200{}",
            if state.secure_cookie { "; Secure" } else { "" }
        );
        Ok((
            [(header::SET_COOKIE, cookie)],
            Json(json!({"ok":true,"user":current.user})),
        )
            .into_response())
    }
    .await;
    let status = result
        .as_ref()
        .map(|r| r.status().as_u16())
        .unwrap_or_else(|e: &Error| e.0.as_u16());
    if let Err(e) = state
        .control
        .finish_audit(audit, status, None, json!({}), None)
        .await
    {
        log::error!("Passkey sign-in audit pending: {e}");
    }
    result
}
pub fn validate_backup(name: &str, value: &str, users: &[String]) -> Result<(), String> {
    if name == "passkey_origin" {
        let _ = origin(value)?;
        return Ok(());
    }
    let user = name
        .strip_prefix("passkeys:")
        .ok_or("Invalid passkey record.")?;
    if !users.iter().any(|id| id == user) {
        return Err("Passkey account is missing.".into());
    }
    decode(value)?;
    Ok(())
}
pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/passkeys", get(status))
        .route("/api/passkeys/config", axum::routing::put(configure))
        .route("/api/passkeys/register/start", post(register_start))
        .route("/api/passkeys/register/finish", post(register_finish))
        .route("/api/passkeys/{id}", axum::routing::delete(remove))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn origins_are_pinned_secure_and_pathless() {
        for value in ["https://gateway.example.test", "http://localhost:9090"] {
            assert!(origin(value).is_ok());
        }
        for value in [
            "http://gateway.test",
            "https://gateway.test/path",
            "https://user:secret@gateway.test",
            "https://gateway.test/?x=1",
            "file:///tmp",
        ] {
            assert!(origin(value).is_err());
        }
        assert!(validate_backup("passkeys:missing", "[]", &[]).is_err());
        assert!(validate_backup("passkeys:bootstrap", "[{}]", &["bootstrap".into()]).is_err());
    }
}

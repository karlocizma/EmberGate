use crate::{
    management::{self, AuditActor, AuditExtra, Role, User},
    state::{now, Shared},
};
use axum::{
    extract::{ConnectInfo, Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};
type Error = (StatusCode, Json<Value>);
fn error(status: StatusCode, message: impl ToString) -> Error {
    (status, Json(json!({"error":message.to_string()})))
}
fn invalid(message: impl ToString) -> Error {
    error(StatusCode::UNPROCESSABLE_ENTITY, message)
}
fn unavailable(message: impl ToString) -> Error {
    error(StatusCode::SERVICE_UNAVAILABLE, message)
}
#[derive(Clone)]
pub struct Session {
    pub id: String,
    pub user: User,
    pub created_at: u64,
    pub expires_at: u64,
    pub expires: Instant,
    pub peer: String,
    pub mfa_verified: bool,
}
impl Session {
    pub fn new(user: User, peer: String) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            user,
            created_at: now(),
            expires_at: now() + 43200,
            expires: Instant::now() + Duration::from_secs(43200),
            peer,
            mfa_verified: false,
        }
    }
    pub fn actor(&self) -> AuditActor {
        AuditActor {
            user_id: self.user.id.clone(),
            username: self.user.username.clone(),
            role: self.user.role.as_str().into(),
            peer: self.peer.clone(),
        }
    }
}
pub(crate) fn limit_attempts(state: &Shared, peer: &str) -> Result<(), Error> {
    {
        let mut attempts = state.login_attempts.lock().unwrap();
        attempts.retain(|_, times| {
            times.retain(|time| time.elapsed() < Duration::from_secs(60));
            !times.is_empty()
        });
        if attempts.len() >= 1024 && !attempts.contains_key(peer) {
            return Err(error(
                StatusCode::TOO_MANY_REQUESTS,
                "Try again in a minute.",
            ));
        }
        let times = attempts.entry(peer.to_owned()).or_default();
        if times.len() >= 20 {
            return Err(error(
                StatusCode::TOO_MANY_REQUESTS,
                "Too many attempts. Try again in a minute.",
            ));
        }
        times.push_back(Instant::now());
    }
    Ok(())
}
pub(crate) async fn credentials(
    state: &Shared,
    name: &str,
) -> Result<Option<management::Credentials>, Error> {
    if name == "admin" {
        if let Some(hash) = &state.password_hash {
            return Ok(Some(management::Credentials {
                user: management::bootstrap(),
                hash: hash.clone(),
            }));
        }
    }
    state
        .control
        .credentials(name.to_owned())
        .await
        .map_err(unavailable)
}
#[derive(Deserialize)]
pub struct Login {
    #[serde(default = "admin_name")]
    username: String,
    password: String,
    #[serde(default)]
    code: String,
}
fn admin_name() -> String {
    "admin".into()
}
pub async fn login(
    State(state): State<Shared>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(input): Json<Login>,
) -> Result<Response, Error> {
    if headers
        .get("x-gateway-request")
        .and_then(|h| h.to_str().ok())
        != Some("1")
    {
        return Err(error(
            StatusCode::FORBIDDEN,
            "Missing request verification header.",
        ));
    }
    let peer = peer
        .map(|p| p.0 .0.ip().to_string())
        .unwrap_or_else(|| "local".into());
    limit_attempts(&state, &peer)?;
    let name = management::username(&input.username)
        .map_err(|_| error(StatusCode::UNAUTHORIZED, "Incorrect username or password."))?;
    let credentials = credentials(&state, &name).await?;
    let valid = management::verify_password(
        input.password,
        credentials
            .as_ref()
            .map(|c| c.hash.clone())
            .unwrap_or_else(|| state.dummy_password_hash.clone()),
    )
    .await;
    let actor = AuditActor {
        user_id: credentials
            .as_ref()
            .map(|c| c.user.id.clone())
            .unwrap_or_default(),
        username: name.clone(),
        role: credentials
            .as_ref()
            .map(|c| c.user.role.as_str())
            .unwrap_or("unknown")
            .into(),
        peer: peer.clone(),
    };
    let audit = state
        .control
        .begin_audit(actor, "POST".into(), "/api/login".into(), json!({}))
        .await
        .map_err(unavailable)?;
    let result = async {
        let credentials = credentials
            .filter(|c| c.user.enabled && valid)
            .ok_or_else(|| error(StatusCode::UNAUTHORIZED, "Incorrect username or password."))?;
        let _guard = state.account_write_lock.lock().await;
        if !(name == "admin" && state.password_hash.is_some())
            && !state
                .control
                .credentials(name)
                .await
                .map_err(unavailable)?
                .is_some_and(|c| c.user.enabled && c.user.version == credentials.user.version)
        {
            return Err(error(
                StatusCode::UNAUTHORIZED,
                "Account changed. Please sign in again.",
            ));
        }
        let mfa_enabled = crate::mfa::enabled(&state, &credentials.user.id).await.map_err(unavailable)?;
        if mfa_enabled {
            limit_attempts(&state, &format!("mfa:{}", credentials.user.id))?;
            if !crate::mfa::authenticate(&state, &credentials.user.id, &input.code).await.map_err(unavailable)? {
                return Err((StatusCode::UNAUTHORIZED, Json(json!({"error":"Enter an authenticator code or an unused recovery code.","mfa_required":true}))));
            }
        }
        let token = uuid::Uuid::new_v4().to_string();
        {
            let mut sessions = state.sessions.lock().unwrap();
            sessions.retain(|_, session| session.expires > Instant::now());
            if sessions.len() >= 1000 {
                return Err(error(
                    StatusCode::TOO_MANY_REQUESTS,
                    "Session limit reached. Revoke a session and try again.",
                ));
            }
            if let Some(previous) = headers
                .get(header::COOKIE)
                .and_then(|h| h.to_str().ok())
                .and_then(|h| {
                    h.split(';')
                        .find_map(|part| part.trim().strip_prefix("gateway_session="))
                })
            {
                sessions.remove(previous);
            }
            let mut session = Session::new(credentials.user.clone(), peer);
            session.mfa_verified = mfa_enabled;
            sessions.insert(token.clone(), session);
        }
        let cookie = format!(
            "gateway_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200{}",
            if state.secure_cookie { "; Secure" } else { "" }
        );
        Ok((
            [(header::SET_COOKIE, cookie)],
            Json(json!({"ok":true,"user":credentials.user})),
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
        log::error!("Login audit completion pending: {e}");
    }
    result
}
pub async fn setup_status(State(state): State<Shared>) -> Result<Json<Value>, Error> {
    let required = state.setup_token.is_some()
        && !state
            .control
            .credentials("admin".into())
            .await
            .map_err(unavailable)?
            .is_some();
    Ok(Json(json!({"setup_required":required})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Setup {
    setup_code: String,
    password: String,
}
pub async fn setup(
    State(state): State<Shared>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(input): Json<Setup>,
) -> Result<(StatusCode, Json<Value>), Error> {
    if headers
        .get("x-gateway-request")
        .and_then(|h| h.to_str().ok())
        != Some("1")
    {
        return Err(error(
            StatusCode::FORBIDDEN,
            "Missing request verification header.",
        ));
    }
    let peer = peer
        .map(|p| p.0 .0.ip().to_string())
        .unwrap_or_else(|| "local".into());
    limit_attempts(&state, &peer)?;
    let Some(code) = &state.setup_token else {
        return Err(error(
            StatusCode::CONFLICT,
            "Administrator setup is already complete.",
        ));
    };
    if !state
        .control
        .credentials("admin".into())
        .await
        .map_err(unavailable)?
        .is_some()
        && input.setup_code.trim() != code
    {
        return Err(error(
            StatusCode::FORBIDDEN,
            "Incorrect setup code. Use the one printed in the gateway terminal.",
        ));
    }
    if state
        .control
        .credentials("admin".into())
        .await
        .map_err(unavailable)?
        .is_some()
    {
        return Err(error(
            StatusCode::CONFLICT,
            "Administrator setup is already complete.",
        ));
    }
    let hash = management::hash_password(input.password)
        .await
        .map_err(invalid)?;
    let _guard = state.account_write_lock.lock().await;
    let created = state
        .control
        .run(move |db| management::initialize_admin(db, &hash, &peer))
        .await
        .map_err(unavailable)?;
    if !created {
        return Err(error(
            StatusCode::CONFLICT,
            "Administrator setup is already complete.",
        ));
    }
    Ok((StatusCode::CREATED, Json(json!({"ok":true}))))
}
async fn identity(
    State(state): State<Shared>,
    Extension(session): Extension<Session>,
) -> Result<Json<Value>, Error> {
    let required = crate::mfa::enrollment_required(&state, &session)
        .await
        .map_err(unavailable)?;
    Ok(Json(
        json!({"ok":true,"user":session.user,"password_editable":session.user.id!="bootstrap" || state.password_hash.is_none(),"mfa_enrollment_required":required}),
    ))
}
async fn users(State(state): State<Shared>) -> Result<Json<Value>, Error> {
    let mut users = state.control.users().await.map_err(unavailable)?;
    if !users.iter().any(|user| user.id == "bootstrap") {
        users.insert(0, management::bootstrap());
    }
    Ok(Json(json!({"users":users})))
}
#[derive(Deserialize)]
struct Create {
    username: String,
    password: String,
    role: Role,
}
async fn create(State(state): State<Shared>, Json(input): Json<Create>) -> Result<Response, Error> {
    let name = management::username(&input.username).map_err(invalid)?;
    if name == "admin" {
        return Err(invalid("The admin username is reserved for recovery."));
    }
    let hash = management::hash_password(input.password)
        .await
        .map_err(invalid)?;
    let _guard = state.account_write_lock.lock().await;
    let user = state
        .control
        .create_user(name, hash, input.role)
        .await
        .map_err(invalid)?;
    let mut response = (StatusCode::CREATED, Json(json!({"user":user}))).into_response();
    response.extensions_mut().insert(AuditExtra(user.id));
    Ok(response)
}
#[derive(Deserialize)]
struct Update {
    username: String,
    role: Role,
    enabled: bool,
    version: u64,
    password: Option<String>,
}
async fn update(
    State(state): State<Shared>,
    Path(id): Path<String>,
    Json(input): Json<Update>,
) -> Result<Json<Value>, Error> {
    if id == "bootstrap" {
        return Err(invalid(
            "The recovery account is configured through the environment.",
        ));
    }
    let name = management::username(&input.username).map_err(invalid)?;
    if name == "admin" {
        return Err(invalid("The admin username is reserved for recovery."));
    }
    let hash = match input.password.filter(|p| !p.is_empty()) {
        Some(p) => Some(management::hash_password(p).await.map_err(invalid)?),
        None => None,
    };
    let _guard = state.account_write_lock.lock().await;
    let user = state
        .control
        .update_user(
            id.clone(),
            name,
            input.role,
            input.enabled,
            input.version,
            hash,
        )
        .await
        .map_err(|e| error(StatusCode::CONFLICT, e))?;
    revoke(&state, &id);
    Ok(Json(json!({"user":user})))
}
fn revoke(state: &Shared, id: &str) {
    state
        .sessions
        .lock()
        .unwrap()
        .retain(|_, session| session.user.id != id);
}
async fn remove(State(state): State<Shared>, Path(id): Path<String>) -> Result<Json<Value>, Error> {
    if id == "bootstrap" {
        return Err(invalid("The recovery account cannot be removed."));
    }
    let _guard = state.account_write_lock.lock().await;
    state
        .control
        .delete_user(id.clone())
        .await
        .map_err(invalid)?;
    revoke(&state, &id);
    Ok(Json(json!({"ok":true})))
}
#[derive(Deserialize)]
struct Password {
    current_password: String,
    new_password: String,
}
async fn password(
    State(state): State<Shared>,
    Extension(session): Extension<Session>,
    Json(input): Json<Password>,
) -> Result<Json<Value>, Error> {
    if session.user.id == "bootstrap" && state.password_hash.is_some() {
        return Err(invalid(
            "The administrator password is overridden by GATEWAY_ADMIN_PASSWORD. Remove that variable and restart to manage the saved password here.",
        ));
    }
    let current = state
        .control
        .credentials(session.user.username.clone())
        .await
        .map_err(unavailable)?
        .ok_or_else(|| invalid("Account not found."))?;
    if !management::verify_password(input.current_password, current.hash.clone()).await {
        return Err(error(
            StatusCode::UNAUTHORIZED,
            "Incorrect current password.",
        ));
    }
    let hash = management::hash_password(input.new_password)
        .await
        .map_err(invalid)?;
    let _guard = state.account_write_lock.lock().await;
    let user = current.user;
    state
        .control
        .update_user(
            user.id.clone(),
            user.username,
            user.role,
            user.enabled,
            user.version,
            Some(hash),
        )
        .await
        .map_err(invalid)?;
    revoke(&state, &user.id);
    Ok(Json(json!({"ok":true,"sign_in_required":true})))
}
#[derive(Serialize)]
struct SessionSummary {
    id: String,
    user: User,
    created_at: u64,
    expires_at: u64,
    peer: String,
    current: bool,
}
async fn sessions(
    State(state): State<Shared>,
    Extension(session): Extension<Session>,
) -> Json<Value> {
    let mut sessions = state.sessions.lock().unwrap();
    sessions.retain(|_, s| s.expires > Instant::now());
    let list: Vec<_> = sessions
        .values()
        .filter(|s| session.user.role.admin() || s.user.id == session.user.id)
        .map(|s| SessionSummary {
            id: s.id.clone(),
            user: s.user.clone(),
            created_at: s.created_at,
            expires_at: s.expires_at,
            peer: s.peer.clone(),
            current: s.id == session.id,
        })
        .collect();
    Json(json!({"sessions":list}))
}
async fn end_session(
    State(state): State<Shared>,
    Extension(session): Extension<Session>,
    Path(id): Path<String>,
) -> Result<Json<Value>, Error> {
    let mut sessions = state.sessions.lock().unwrap();
    if sessions
        .values()
        .any(|s| s.id == id && !session.user.role.admin() && s.user.id != session.user.id)
    {
        return Err(error(
            StatusCode::FORBIDDEN,
            "You can only revoke your own sessions.",
        ));
    }
    sessions.retain(|_, s| s.id != id);
    Ok(Json(json!({"ok":true,"sign_in_required":id==session.id})))
}
async fn audit(State(state): State<Shared>) -> Result<Json<Value>, Error> {
    Ok(Json(state.control.audit().await.map_err(unavailable)?))
}
pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/session", get(identity))
        .route("/api/users", get(users).post(create))
        .route("/api/users/{id}", axum::routing::put(update).delete(remove))
        .route("/api/password", post(password))
        .route("/api/sessions", get(sessions))
        .route("/api/sessions/{id}", axum::routing::delete(end_session))
        .route("/api/audit", get(audit))
}

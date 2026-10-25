//! Durable, encrypted automatic snapshots with bounded local retention and optional HTTPS PUT.
use crate::{
    management::{self, AuditActor},
    state::{now, Shared},
};
use async_trait::async_trait;
use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use pingora::{server::ShutdownWatch, services::background::BackgroundService};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
const SETTINGS: &str = "backup_schedule";
const RUNTIME: &str = "backup_schedule_state";
const PASSWORD: &str = "backup_schedule_passphrase";
const AUTH: &str = "backup_schedule_auth";
const LIMIT: u64 = 96 * 1024 * 1024;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    enabled: bool,
    interval_hours: u64,
    retain_count: usize,
    notify_failures: bool,
    offsite_url: Option<String>,
    version: u64,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_hours: 24,
            retain_count: 7,
            notify_failures: true,
            offsite_url: None,
            version: 0,
        }
    }
}
impl Settings {
    fn validate(&self) -> Result<(), String> {
        if !(1..=168).contains(&self.interval_hours)
            || !(1..=30).contains(&self.retain_count)
            || self.version > 1_000_000_000_000
        {
            return Err("Use an interval of 1–168 hours and retain 1–30 local backups.".into());
        }
        if let Some(url) = &self.offsite_url {
            destination(url)?;
        }
        Ok(())
    }
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Runtime {
    next_run_at: u64,
    requested: bool,
    running: bool,
    last_attempt: Option<u64>,
    last_success: Option<u64>,
    last_local_at: Option<u64>,
    last_file: Option<String>,
    last_offsite_success: Option<u64>,
    last_error: Option<String>,
}
impl Runtime {
    fn validate(&self) -> Result<(), String> {
        if self.next_run_at > 1_000_000_000_000
            || [
                self.last_attempt,
                self.last_success,
                self.last_local_at,
                self.last_offsite_success,
            ]
            .into_iter()
            .flatten()
            .any(|v| v > 1_000_000_000_000)
            || self
                .last_file
                .as_ref()
                .is_some_and(|f| file_time(f).is_none())
            || self
                .last_error
                .as_ref()
                .is_some_and(|e| e.len() > 256 || e.chars().any(|c| c.is_control()))
        {
            return Err("Invalid backup schedule state.".into());
        }
        Ok(())
    }
}
#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Kind {
    #[default]
    None,
    Bearer,
    Basic,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Auth {
    kind: Kind,
    #[serde(default)]
    username: String,
    #[serde(default)]
    secret: String,
}
impl Auth {
    fn validate(&self) -> Result<(), String> {
        let valid = match self.kind {
            Kind::None => self.username.is_empty() && self.secret.is_empty(),
            Kind::Bearer => {
                self.username.is_empty()
                    && !self.secret.is_empty()
                    && self.secret.len() <= 4096
                    && self.secret.bytes().all(|b| b.is_ascii_graphic())
            }
            Kind::Basic => {
                !self.username.is_empty()
                    && self.username.len() <= 256
                    && !self.username.contains(':')
                    && !self.secret.is_empty()
                    && self.secret.len() <= 4096
                    && !self
                        .username
                        .chars()
                        .chain(self.secret.chars())
                        .any(|c| c.is_control())
            }
        };
        if valid {
            Ok(())
        } else {
            Err("Provide a valid bearer token, or a username and password for Basic authentication.".into())
        }
    }
}
fn destination(value: &str) -> Result<url::Url, String> {
    let url = url::Url::parse(value).map_err(|_| "Invalid offsite folder URL.")?;
    let local = url.host_str().is_some_and(|h| {
        h == "localhost"
            || h.trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if value.len() > 2048
        || value.chars().any(|c| c.is_whitespace() || c.is_control())
        || !(url.scheme() == "https" || (url.scheme() == "http" && local))
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.path().ends_with('/')
    {
        return Err("Use an HTTPS folder URL ending in /, without URL credentials, queries, or fragments. HTTP is allowed only for loopback fixtures.".into());
    }
    Ok(url)
}
fn record<T: serde::de::DeserializeOwned + Default>(
    db: &Connection,
    key: &str,
) -> Result<T, String> {
    let value: Option<String> = db
        .query_row(
            "SELECT value FROM secrets WHERE key=?1",
            params![key],
            |r| r.get(0),
        )
        .optional()
        .map_err(management::storage)?;
    value
        .map(|v| {
            serde_json::from_str(&v).map_err(|_| "Backup schedule storage unavailable.".into())
        })
        .unwrap_or_else(|| Ok(T::default()))
}
fn put(db: &Connection, key: &str, value: &impl Serialize) -> Result<(), String> {
    db.execute(
        "INSERT INTO secrets VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![
            key,
            serde_json::to_string(value).map_err(|_| "Backup settings could not be saved.")?
        ],
    )
    .map_err(management::storage)?;
    Ok(())
}
fn password(db: &Connection) -> Result<Option<String>, String> {
    db.query_row(
        "SELECT value FROM secrets WHERE key=?1",
        params![PASSWORD],
        |r| r.get(0),
    )
    .optional()
    .map_err(management::storage)
}
fn load(db: &Connection) -> Result<(Settings, Runtime, Auth, Option<String>), String> {
    let settings: Settings = record(db, SETTINGS)?;
    let runtime: Runtime = record(db, RUNTIME)?;
    let auth: Auth = record(db, AUTH)?;
    settings.validate()?;
    runtime.validate()?;
    auth.validate()?;
    let password = password(db)?;
    if let Some(p) = &password {
        crate::backup::passphrase(p)?;
    }
    Ok((settings, runtime, auth, password))
}
pub(crate) fn validate_backup(key: &str, value: &str) -> Result<(), String> {
    match key {
        SETTINGS => serde_json::from_str::<Settings>(value)
            .map_err(|_| "Invalid backup schedule.".to_owned())?
            .validate(),
        RUNTIME => serde_json::from_str::<Runtime>(value)
            .map_err(|_| "Invalid backup schedule state.".to_owned())?
            .validate(),
        AUTH => serde_json::from_str::<Auth>(value)
            .map_err(|_| "Invalid offsite authentication.".to_owned())?
            .validate(),
        // Exported archives deliberately exclude the unattended encryption credential.
        _ => Err("Unsupported backup schedule credential.".into()),
    }
}
pub(crate) fn sanitize_snapshot(db: &Connection) -> Result<(), String> {
    db.execute_batch("PRAGMA secure_delete=ON")
        .map_err(management::storage)?;
    db.execute("DELETE FROM secrets WHERE key=?1", params![PASSWORD])
        .map_err(management::storage)?;
    let mut runtime: Runtime = record(db, RUNTIME)?;
    if db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM secrets WHERE key=?1)",
            params![RUNTIME],
            |r| r.get::<_, bool>(0),
        )
        .map_err(management::storage)?
    {
        runtime.running = false;
        runtime.requested = false;
        runtime.next_run_at = 0;
        put(db, RUNTIME, &runtime)?;
    }
    Ok(())
}
fn directory(state: &Shared) -> Result<PathBuf, String> {
    let base = state
        .config_path
        .parent()
        .unwrap()
        .join(".embergate-backups");
    for path in [&base, &base.join("scheduled")] {
        match fs::symlink_metadata(path) {
            Ok(m) if m.is_dir() && !m.file_type().is_symlink() => {}
            Ok(_) => return Err("Unsafe scheduled backup directory.".into()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(path).map_err(|_| "Could not create scheduled backup directory.")?
            }
            Err(_) => return Err("Scheduled backup storage unavailable.".into()),
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .map_err(|_| "Could not protect scheduled backup directory.")?;
        }
    }
    Ok(base.join("scheduled"))
}
fn file_time(name: &str) -> Option<u64> {
    let value = name
        .strip_prefix("embergate-auto-")?
        .strip_suffix(".embergate")?;
    let (time, id) = value.split_once('-')?;
    if time.len() != 20
        || !time.bytes().all(|b| b.is_ascii_digit())
        || !uuid::Uuid::parse_str(id).is_ok_and(|u| u.to_string() == id)
    {
        return None;
    }
    time.parse().ok()
}
#[derive(Serialize)]
struct File {
    name: String,
    created_at: u64,
    bytes: u64,
}
fn files(state: &Shared) -> Result<Vec<File>, String> {
    let path = directory(state)?;
    let mut files = vec![];
    for entry in fs::read_dir(path).map_err(|_| "Could not list scheduled backups.")? {
        let entry = entry.map_err(|_| "Could not list scheduled backups.")?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some(created) = file_time(&name) {
            let meta = fs::symlink_metadata(entry.path())
                .map_err(|_| "Could not read scheduled backup metadata.")?;
            if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > LIMIT {
                return Err("Unsafe or oversized scheduled backup file.".into());
            }
            files.push(File {
                name,
                created_at: created / 1000,
                bytes: meta.len(),
            });
        }
    }
    files.sort_by(|a, b| b.name.cmp(&a.name));
    Ok(files)
}
fn retain(state: &Shared, count: usize, current: &str) -> Result<(), String> {
    let path = directory(state)?;
    for file in files(state)?
        .into_iter()
        .filter(|file| file.name != current)
        .skip(count.saturating_sub(1))
    {
        fs::remove_file(path.join(file.name))
            .map_err(|_| "Could not apply local backup retention.")?;
    }
    #[cfg(unix)]
    fs::File::open(path)
        .and_then(|f| f.sync_all())
        .map_err(|_| "Could not sync backup retention.")?;
    Ok(())
}
type Error = (StatusCode, Json<Value>);
fn error(status: StatusCode, message: impl ToString) -> Error {
    (status, Json(json!({"error":message.to_string()})))
}
async fn status(State(state): State<Shared>) -> Result<Json<Value>, Error> {
    let (s, r, a, p) = state
        .control
        .run(|db| load(db))
        .await
        .map_err(|e| error(StatusCode::SERVICE_UNAVAILABLE, e))?;
    let files = files(&state).map_err(|e| error(StatusCode::SERVICE_UNAVAILABLE, e))?;
    Ok(Json(
        json!({"settings":{"enabled":s.enabled,"interval_hours":s.interval_hours,"retain_count":s.retain_count,"notify_failures":s.notify_failures,"version":s.version},"passphrase_configured":p.is_some(),"offsite_configured":s.offsite_url.is_some(),"offsite_origin":s.offsite_url.as_ref().and_then(|u|destination(u).ok()).map(|u|u.origin().ascii_serialization()),"auth_kind":a.kind,"runtime":r,"running":state.backups.scheduled_running.load(Ordering::SeqCst),"paused_for_restore":state.backups.pending.load(Ordering::SeqCst),"files":files}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Save {
    enabled: bool,
    interval_hours: u64,
    retain_count: usize,
    notify_failures: bool,
    version: u64,
    passphrase: Option<String>,
    #[serde(default)]
    remove_passphrase: bool,
    offsite_url: Option<String>,
    auth: Option<Auth>,
}
async fn save(State(state): State<Shared>, Json(input): Json<Save>) -> Result<Json<Value>, Error> {
    if state.backups.scheduled_running.load(Ordering::SeqCst) {
        return Err(error(
            StatusCode::CONFLICT,
            "A scheduled backup is running. Wait for it to finish before changing settings.",
        ));
    }
    state.control.run(move|db|{
        let (current,mut runtime,current_auth,current_password)=load(db)?;
        if current.version!=input.version{return Err("Backup settings changed. Refresh and try again.".into())}
        let url=match input.offsite_url{None=>current.offsite_url.clone(),Some(v) if v.is_empty()=>None,Some(v)=>Some(v)};
        let changed=url!=current.offsite_url;
        if changed&&url.is_some()&&input.auth.is_none(){return Err("Choose authentication for the new offsite destination.".into())}
        let auth=if url.is_none(){Auth::default()}else{input.auth.unwrap_or(current_auth)};auth.validate()?;
        if input.remove_passphrase && input.passphrase.as_ref().is_some_and(|p|!p.is_empty()){return Err("Choose either a new passphrase or forgetting the saved passphrase.".into())}
        let pass=if input.remove_passphrase{None}else{input.passphrase.filter(|p|!p.is_empty()).or(current_password)};
        if let Some(p)=&pass{crate::backup::passphrase(p)?;}
        if input.enabled&&pass.is_none(){return Err("Save a backup passphrase before enabling automatic backups.".into())}
        let settings=Settings{enabled:input.enabled,interval_hours:input.interval_hours,retain_count:input.retain_count,notify_failures:input.notify_failures,offsite_url:url,version:current.version+1};settings.validate()?;
        runtime.requested=false;runtime.running=false;runtime.next_run_at=if settings.enabled{now()+settings.interval_hours*3600}else{0};
        if pass.is_none(){runtime.last_error=None;}
        let tx=db.transaction().map_err(management::storage)?;put(&tx,SETTINGS,&settings)?;put(&tx,RUNTIME,&runtime)?;if auth.kind==Kind::None {tx.execute("DELETE FROM secrets WHERE key=?1",params![AUTH]).map_err(management::storage)?;}else{put(&tx,AUTH,&auth)?;}
        match pass{Some(pass)=>{tx.execute("INSERT INTO secrets VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",params![PASSWORD,pass]).map_err(management::storage)?;},None=>{tx.execute("DELETE FROM secrets WHERE key=?1",params![PASSWORD]).map_err(management::storage)?;}}
        tx.commit().map_err(management::storage)?;Ok(())
    }).await.map_err(|e|error(StatusCode::UNPROCESSABLE_ENTITY,e))?;
    Ok(Json(json!({"ok":true})))
}
async fn run_now(State(state): State<Shared>) -> Result<(StatusCode, Json<Value>), Error> {
    if state.backups.scheduled_running.load(Ordering::SeqCst) {
        return Err(error(
            StatusCode::CONFLICT,
            "A scheduled backup is already running.",
        ));
    }
    state
        .control
        .run(|db| {
            let (_, mut r, _, p) = load(db)?;
            if p.is_none() {
                return Err("Save a backup passphrase first.".into());
            }
            if r.requested {
                return Err("A backup is already queued.".into());
            }
            r.requested = true;
            r.next_run_at = now();
            put(db, RUNTIME, &r)
        })
        .await
        .map_err(|e| error(StatusCode::CONFLICT, e))?;
    Ok((StatusCode::ACCEPTED, Json(json!({"queued":true}))))
}
async fn download(
    State(state): State<Shared>,
    Path(name): Path<String>,
) -> Result<Response, Error> {
    if file_time(&name).is_none() {
        return Err(error(StatusCode::NOT_FOUND, "Backup not found."));
    }
    let path = directory(&state)
        .map_err(|e| error(StatusCode::SERVICE_UNAVAILABLE, e))?
        .join(&name);
    let bytes = tokio::task::spawn_blocking(move || {
        let m = fs::symlink_metadata(&path).map_err(|_| "Backup not found.")?;
        if !m.is_file() || m.file_type().is_symlink() || m.len() > LIMIT {
            return Err("Invalid backup file.");
        }
        fs::read(path).map_err(|_| "Could not read backup.")
    })
    .await
    .map_err(|_| {
        error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Backup download unavailable.",
        )
    })?
    .map_err(|e| error(StatusCode::NOT_FOUND, e))?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_owned()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{name}\""),
            ),
        ],
        bytes,
    )
        .into_response())
}
async fn remove(
    State(state): State<Shared>,
    Path(name): Path<String>,
) -> Result<Json<Value>, Error> {
    if state.backups.scheduled_running.load(Ordering::SeqCst) {
        return Err(error(
            StatusCode::CONFLICT,
            "Wait for the running backup before removing files.",
        ));
    }
    if file_time(&name).is_none() {
        return Err(error(StatusCode::NOT_FOUND, "Backup not found."));
    }
    let directory = directory(&state).map_err(|e| error(StatusCode::SERVICE_UNAVAILABLE, e))?;
    let valid = files(&state)
        .map_err(|e| error(StatusCode::SERVICE_UNAVAILABLE, e))?
        .iter()
        .any(|f| f.name == name);
    if !valid {
        return Err(error(StatusCode::NOT_FOUND, "Backup not found."));
    }
    fs::remove_file(directory.join(name))
        .map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "Could not remove backup."))?;
    #[cfg(unix)]
    fs::File::open(directory)
        .and_then(|f| f.sync_all())
        .map_err(|_| {
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Could not sync backup storage.",
            )
        })?;
    Ok(Json(json!({"ok":true})))
}
pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/backups/schedule", get(status).put(save))
        .route("/api/backups/schedule/run", post(run_now))
        .route(
            "/api/backups/scheduled/{name}",
            get(download).delete(remove),
        )
}

async fn upload(
    client: &reqwest::Client,
    url: &str,
    auth: &Auth,
    name: &str,
    bytes: Vec<u8>,
) -> Result<(), String> {
    let mut url = destination(url)?;
    url.path_segments_mut()
        .map_err(|_| "Invalid offsite folder URL.")?
        .pop_if_empty()
        .push(name);
    let mut request = client
        .put(url)
        .header("Content-Type", "application/octet-stream")
        .header("If-None-Match", "*")
        .body(bytes);
    request = match auth.kind {
        Kind::None => request,
        Kind::Bearer => request.bearer_auth(&auth.secret),
        Kind::Basic => request.basic_auth(&auth.username, Some(&auth.secret)),
    };
    match request.send().await {
        Ok(r) if r.status().is_success() => Ok(()),
        Ok(r) => Err(format!(
            "Offsite upload failed (HTTP {}). Local backup is available.",
            r.status().as_u16()
        )),
        Err(_) => Err("Offsite upload failed or timed out. Local backup is available.".into()),
    }
}
struct Running<'a>(&'a AtomicBool);
impl Drop for Running<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}
async fn recover(state: &Shared) -> Result<(), String> {
    state
        .control
        .run(|db| {
            let (_, mut runtime, _, _) = load(db)?;
            if runtime.running {
                runtime.running = false;
                runtime.requested = true;
                runtime.last_error =
                    Some("A backup was interrupted by shutdown. It will be retried.".into());
                runtime.next_run_at = now() + 60;
                put(db, RUNTIME, &runtime)?;
            }
            Ok(())
        })
        .await
}
async fn tick(state: &Shared, client: &reqwest::Client) -> Result<(), String> {
    let mutations = state.backups.mutations.lock().await;
    if state.backups.pending.load(Ordering::SeqCst) {
        return Ok(());
    }
    let (settings, mut runtime, auth, password) = state.control.run(|db| load(db)).await?;
    if !(settings.enabled || runtime.requested) || runtime.next_run_at > now() {
        return Ok(());
    }
    let Some(password) = password else {
        runtime.last_error =
            Some("Scheduled backups need a passphrase. Open Settings to resume.".into());
        runtime.next_run_at = now() + 300;
        runtime.requested = false;
        state
            .control
            .run(move |db| put(db, RUNTIME, &runtime))
            .await?;
        return Ok(());
    };
    let Ok(operation) = state.backups.operation.clone().try_lock_owned() else {
        runtime.next_run_at = now() + 15;
        state
            .control
            .run(move |db| put(db, RUNTIME, &runtime))
            .await?;
        return Ok(());
    };
    state
        .backups
        .scheduled_running
        .store(true, Ordering::SeqCst);
    let _running = Running(&state.backups.scheduled_running);
    runtime.running = true;
    runtime.last_attempt = Some(now());
    runtime.requested = false;
    runtime.next_run_at = now() + 300;
    state
        .control
        .run({
            let runtime = runtime.clone();
            move |db| put(db, RUNTIME, &runtime)
        })
        .await?;
    let actor = AuditActor {
        user_id: "system".into(),
        username: "backup scheduler".into(),
        role: "system".into(),
        peer: "local".into(),
        token: None,
    };
    let audit = state
        .control
        .begin_audit(
            actor,
            "POST".into(),
            "/system/backups/scheduled".into(),
            json!({}),
        )
        .await?;
    let result = crate::backup::automatic_bytes(state, password, operation).await;
    // Configuration and account writes can continue while an encrypted file is uploaded.
    drop(mutations);
    let mut completed = None;
    let mut remote_ok = false;
    let outcome=async {
        let (bytes,_operation)=result?;
        let millis=SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_|"Invalid system clock.")?.as_millis() as u64;
        let name=format!("embergate-auto-{millis:020}-{}.embergate",uuid::Uuid::new_v4());
        let path=directory(state)?.join(&name);
        // Keep the backup operation guard inside the blocking write if shutdown cancels us.
        let (bytes,_operation)=tokio::task::spawn_blocking(move||{if crate::acme::secure_write(&path,&bytes).is_err(){let _=fs::remove_file(path.with_extension("tmp"));return Err("Could not save encrypted scheduled backup.".into())}
            #[cfg(unix)]fs::File::open(path.parent().unwrap()).and_then(|f|f.sync_all()).map_err(|_|"Could not sync encrypted backup storage.")?;
            Ok::<_,String>((bytes,_operation))}).await.map_err(|_|"Backup storage task failed.")??;
        completed=Some(name.clone());
        retain(state,settings.retain_count,&name)?;
        if let Some(url)=&settings.offsite_url{
            if state.backups.pending.load(Ordering::SeqCst){return Err("Offsite upload paused because a restore was queued. Local backup is available.".into())}
            upload(client,url,&auth,&name,bytes).await?;remote_ok=true;
        }
        Ok::<_,String>(())
    }.await;
    runtime.running = false;
    let local_created = completed.is_some();
    if let Some(name) = completed {
        runtime.last_file = Some(name);
        runtime.last_local_at = Some(now());
    }
    if remote_ok {
        runtime.last_offsite_success = Some(now());
    }
    match &outcome {
        Ok(()) => {
            runtime.last_success = Some(now());
            runtime.last_error = None;
            runtime.next_run_at = if settings.enabled {
                now() + settings.interval_hours * 3600
            } else {
                0
            };
        }
        Err(e) => {
            runtime.last_error = Some(e.clone());
            runtime.next_run_at = if settings.enabled { now() + 300 } else { 0 };
        }
    }
    state
        .control
        .run(move |db| put(db, RUNTIME, &runtime))
        .await?;
    state
        .control
        .finish_audit(
            audit,
            if outcome.is_ok() { 200 } else { 500 },
            None,
            json!({"local_backup_created":local_created}),
            None,
        )
        .await?;
    Ok(())
}
pub(crate) async fn problem(state: &Shared) -> Result<Option<String>, String> {
    state
        .control
        .run(|db| {
            let (s, r, _, p) = load(db)?;
            Ok(if s.enabled && s.notify_failures {
                if p.is_none() {
                    Some("Scheduled backups need a passphrase. Open Settings to resume.".into())
                } else {
                    r.last_error
                }
            } else {
                None
            })
        })
        .await
}
pub struct Scheduler(pub Shared);
#[async_trait]
impl BackgroundService for Scheduler {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        if let Err(e) = recover(&self.0).await {
            log::error!("Backup scheduler recovery failed: {e}");
        }
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .user_agent("EmberGate-Backup/1")
            .build()
            .expect("Backup HTTP client");
        let mut ticker = tokio::time::interval(Duration::from_secs(5));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {_=shutdown.changed()=>break,_=ticker.tick()=>{
                tokio::select!{_=shutdown.changed()=>break,result=tick(&self.0,&client)=>{if let Err(e)=result{log::error!("Backup scheduler storage failed: {e}");}}}
            }}
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_destinations_credentials_and_owned_names() {
        for url in [
            "https://backup.test/folder/",
            "http://127.0.0.1:1/folder/",
            "http://[::1]:1/",
        ] {
            assert!(destination(url).is_ok());
        }
        for url in [
            "http://backup.test/",
            "https://user:pass@backup.test/",
            "https://backup.test/?token=secret",
            "https://backup.test/folder",
            "file:///tmp/",
        ] {
            assert!(destination(url).is_err());
        }
        let name = format!(
            "embergate-auto-00000001760708600000-{}.embergate",
            uuid::Uuid::new_v4()
        );
        assert_eq!(file_time(&name), Some(1760708600000));
        for bad in [
            "../routes.json",
            "embergate-auto-1-x.embergate",
            "routes.json",
            "%2e%2e",
        ] {
            assert!(file_time(bad).is_none());
        }
        assert!(Auth {
            kind: Kind::Bearer,
            username: String::new(),
            secret: "bad\r\nheader".into()
        }
        .validate()
        .is_err());
        assert!(validate_backup(PASSWORD, "never-import-an-automation-password").is_err());
    }
}

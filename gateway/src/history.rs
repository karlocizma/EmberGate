//! Prior configurations are archived before replacing routes.json. Every entry was active,
//! even if the following save fails. No second commit or crash recovery journal is needed.
use crate::{
    config::Config,
    state::{now, Shared},
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::HashSet,
    fs,
    io::{Read, Write},
    path::Path as FsPath,
};

pub const FILE: &str = "configuration-history.json";
const LIMIT: usize = 50;
const MAX_BYTES: usize = 32 * 1024 * 1024;
type Error = (StatusCode, Json<Value>);
fn error(status: StatusCode, message: impl ToString) -> Error {
    (status, Json(json!({"error": message.to_string()})))
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    id: String,
    archived_at: u64,
    archived_by: String,
    config: Config,
}
fn identity(config: &Config) -> String {
    openssl::sha::sha256(&serde_json::to_vec(config).expect("configuration serialization"))
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
pub fn load(root: &FsPath) -> Result<Vec<Entry>, String> {
    let path = root.join(FILE);
    let meta = match fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(_) => return Err("Cannot read configuration history.".into()),
    };
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > MAX_BYTES as u64 {
        return Err("Invalid configuration history file.".into());
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .and_then(|file| file.take(MAX_BYTES as u64 + 1).read_to_end(&mut bytes))
        .map_err(|_| "Cannot read configuration history.".to_owned())?;
    if bytes.len() > MAX_BYTES {
        return Err("Configuration history is too large.".into());
    }
    let entries: Vec<Entry> =
        serde_json::from_slice(&bytes).map_err(|_| "Invalid configuration history.".to_owned())?;
    if entries.len() > LIMIT {
        return Err("Too many configuration revisions.".into());
    }
    let mut seen = HashSet::new();
    for entry in &entries {
        if entry.archived_by.is_empty()
            || entry.archived_by.len() > 128
            || entry.archived_by.chars().any(char::is_control)
            || entry.id != identity(&entry.config)
            || !seen.insert(&entry.id)
        {
            return Err("Invalid configuration revision metadata.".into());
        }
        let mut config = entry.config.clone();
        config.validate()?;
        // Keep content hashes stable across loading and backup review.
        if identity(&config) != entry.id {
            return Err("Noncanonical configuration revision.".into());
        }
    }
    Ok(entries)
}
pub fn write_atomic(path: &FsPath, bytes: &[u8]) -> std::io::Result<()> {
    let temporary = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        #[cfg(unix)]
        if let Some(parent) = path.parent() {
            if let Err(error) = fs::File::open(parent).and_then(|file| file.sync_all()) {
                log::warn!("File committed, but directory sync failed: {error}");
            }
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}
pub fn archive(root: &FsPath, config: Config, actor: String) -> Result<(), String> {
    let mut entries = load(root)?;
    let id = identity(&config);
    if entries.iter().any(|entry| entry.id == id) {
        return Ok(());
    }
    entries.insert(
        0,
        Entry {
            id,
            archived_at: now(),
            archived_by: actor,
            config,
        },
    );
    entries.truncate(LIMIT);
    loop {
        let bytes = serde_json::to_vec(&entries).map_err(|e| e.to_string())?;
        if bytes.len() <= MAX_BYTES {
            return write_atomic(&root.join(FILE), &bytes)
                .map_err(|_| "Could not retain configuration history.".into());
        }
        if entries.len() <= 1 {
            return Err("Configuration exceeds the revision storage limit.".into());
        }
        entries.pop();
    }
}
fn difference(path: &str, before: &Value, after: &Value, changes: &mut Vec<Value>) {
    if before == after {
        return;
    }
    if let (Some(a), Some(b)) = (before.as_object(), after.as_object()) {
        let keys: std::collections::BTreeSet<_> = a.keys().chain(b.keys()).collect();
        for key in keys {
            difference(
                &format!("{path}/{key}"),
                a.get(key).unwrap_or(&Value::Null),
                b.get(key).unwrap_or(&Value::Null),
                changes,
            );
        }
    } else {
        changes.push(json!({"field":path,"before":before,"after":after}));
    }
}
fn compare(current: &Config, target: &Config) -> Value {
    let mut routes = vec![];
    for route in &current.routes {
        let before = serde_json::to_value(route).unwrap();
        let other = target.routes.iter().find(|r| r.id == route.id);
        let mut changes = vec![];
        if let Some(other) = other {
            difference(
                "",
                &before,
                &serde_json::to_value(other).unwrap(),
                &mut changes,
            );
        } else {
            changes.push(json!({"field":"/","before":before,"after":null}));
        }
        if !changes.is_empty() {
            routes.push(json!({"name":route.name,"id":route.id,"action":if other.is_some(){"changed"}else{"removed"},"changes":changes}));
        }
    }
    for route in &target.routes {
        if !current.routes.iter().any(|r| r.id == route.id) {
            routes.push(json!({"name":route.name,"id":route.id,"action":"added","changes":[{"field":"/","before":null,"after":route}]}));
        }
    }
    let order_changed = current.routes.iter().map(|r| &r.id).collect::<Vec<_>>()
        != target.routes.iter().map(|r| &r.id).collect::<Vec<_>>();
    let order = |config: &Config| {
        config
            .routes
            .iter()
            .map(|r| json!({"id":r.id,"name":r.name,"host":r.host,"path_prefix":r.path_prefix}))
            .collect::<Vec<_>>()
    };
    json!({"routes":routes,"trusted_proxies":if serde_json::to_value(&current.trusted_proxies).unwrap() != serde_json::to_value(&target.trusted_proxies).unwrap() {json!({"before":current.trusted_proxies,"after":target.trusted_proxies})}else{Value::Null},"route_order_changed":order_changed,"route_order":if order_changed {json!({"before":order(current),"after":order(target)})}else{Value::Null}})
}
async fn entries(state: &Shared) -> Result<Vec<Entry>, Error> {
    let root = state.config_path.parent().unwrap().to_path_buf();
    tokio::task::spawn_blocking(move || load(&root))
        .await
        .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "History read failed."))?
        .map_err(|e| error(StatusCode::SERVICE_UNAVAILABLE, e))
}
async fn list(State(state): State<Shared>) -> Result<Json<Value>, Error> {
    let _guard = state.write_lock.lock().await;
    let entries = entries(&state).await?;
    let current = state.config.load_full();
    let active_id = identity(&current);
    Ok(Json(
        json!({"current_version":current.version,"limit":LIMIT,"maximum_bytes":MAX_BYTES,"revisions":entries.iter().filter(|e|e.id!=active_id).map(|entry|json!({"id":entry.id,"version":entry.config.version,"archived_at":entry.archived_at,"archived_by":entry.archived_by,"hosts":entry.config.routes.len()})).collect::<Vec<_>>()}),
    ))
}
async fn review(State(state): State<Shared>, Path(id): Path<String>) -> Result<Json<Value>, Error> {
    let _guard = state.write_lock.lock().await;
    let entries = entries(&state).await?;
    let target = entries.iter().find(|entry| entry.id == id).ok_or_else(|| {
        error(
            StatusCode::NOT_FOUND,
            "Revision no longer retained. Refresh history.",
        )
    })?;
    let current = state.config.load_full();
    Ok(Json(
        json!({"id":id,"version":target.config.version,"expected_version":current.version,"comparison":compare(&current,&target.config)}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Rollback {
    expected_version: u64,
    confirm: String,
}
async fn rollback(
    State(state): State<Shared>,
    Extension(session): Extension<crate::accounts::Session>,
    Path(id): Path<String>,
    Json(input): Json<Rollback>,
) -> Result<axum::response::Response, Error> {
    if input.confirm != "ROLLBACK" {
        return Err(error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Confirm rollback after reviewing the comparison.",
        ));
    }
    let entries = entries(&state).await?;
    let mut target = entries
        .into_iter()
        .find(|entry| entry.id == id)
        .ok_or_else(|| {
            error(
                StatusCode::NOT_FOUND,
                "Revision no longer retained. Refresh history.",
            )
        })?
        .config;
    let source_version = target.version;
    target.version = input.expected_version;
    let mut response =
        crate::api::save_config(State(state), Extension(session), Json(target)).await?;
    if let Some(details) = response
        .extensions_mut()
        .get_mut::<crate::management::AuditDetails>()
    {
        details.0["rollback_source_version"] = json!(source_version);
        details.0["rollback_source_id"] = json!(id);
    }
    Ok(response)
}
pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/config/history", get(list))
        .route("/api/config/history/{id}", get(review))
        .route("/api/config/history/{id}/rollback", post(rollback))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn archives_are_bounded_private_validated_and_deduplicated() {
        let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        fs::create_dir(&root).unwrap();
        for version in 0..55 {
            archive(
                &root,
                Config {
                    version,
                    routes: vec![],
                    trusted_proxies: vec![],
                },
                "admin".into(),
            )
            .unwrap();
        }
        let entries = load(&root).unwrap();
        assert_eq!(entries.len(), 50);
        assert_eq!(entries[0].config.version, 54);
        assert_eq!(entries[49].config.version, 5);
        archive(&root, entries[0].config.clone(), "other".into()).unwrap();
        assert_eq!(load(&root).unwrap().len(), 50);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(root.join(FILE)).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let mut value = serde_json::to_value(entries).unwrap();
        value[0]["config"]["version"] = json!(900);
        fs::write(root.join(FILE), serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(load(&root).is_err());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn comparisons_include_added_removed_hosts_and_order() {
        let route = |name: &str| {
            serde_json::from_value(json!({"id":uuid::Uuid::new_v4().to_string(),"name":name,"host":format!("{}.local",name.to_lowercase()),"path_prefix":"/","upstream":"http://127.0.0.1:9000","enabled":true,"preserve_host":false})).unwrap()
        };
        let a = Config {
            version: 1,
            trusted_proxies: vec![],
            routes: vec![route("First"), route("Second")],
        };
        let mut b = a.clone();
        b.routes.remove(0);
        b.routes[0].enabled = false;
        b.routes.push(route("Third"));
        let result = compare(&a, &b);
        assert_eq!(result["routes"][0]["action"], "removed");
        assert_eq!(result["routes"][1]["action"], "changed");
        assert_eq!(result["routes"][2]["action"], "added");
        assert_eq!(result["route_order"]["before"][0]["name"], "First");
        assert_eq!(result["route_order"]["after"][0]["name"], "Second");
        b = a.clone();
        b.routes.reverse();
        let result = compare(&a, &b);
        assert_eq!(result["routes"], json!([]));
        assert_eq!(result["route_order_changed"], true);
    }
    #[test]
    fn comparisons_show_proxy_changes_and_ignore_revision_numbers() {
        let a = Config {
            version: 1,
            routes: vec![],
            trusted_proxies: vec![],
        };
        let mut b = a.clone();
        b.version = 6;
        assert_eq!(compare(&a, &b)["routes"], json!([]));
        b.trusted_proxies = serde_json::from_value(
            json!([{"network":"127.0.0.1/32","header":"x_forwarded_for","trust_proto":false}]),
        )
        .unwrap();
        assert_eq!(
            compare(&a, &b)["trusted_proxies"]["after"],
            serde_json::to_value(&b.trusted_proxies).unwrap()
        );
        let mut changes = vec![];
        difference(
            "",
            &json!({"enabled":true,"cache":{"ttl":30}}),
            &json!({"enabled":false,"cache":{"ttl":60}}),
            &mut changes,
        );
        assert_eq!(changes.len(), 2);
        assert_eq!(changes[0]["field"], "/cache/ttl");
    }
}

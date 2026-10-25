//! Named policy copies. Applying a template is an editor operation followed by the normal
//! versioned configuration save; templates have no live linkage to existing hosts.
use crate::{
    config::{Config, Route},
    state::{now, Shared},
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::HashSet, fs, io::Read, path::Path as FsPath};
pub const FILE: &str = "host-templates.json";
const MAX_BYTES: usize = 2 * 1024 * 1024;
const LIMIT: usize = 50;
type Error = (StatusCode, Json<Value>);
fn error(status: StatusCode, message: impl ToString) -> Error {
    (status, Json(json!({"error":message.to_string()})))
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Policies {
    #[serde(
        default,
        skip_serializing_if = "crate::config::UpstreamProtocol::is_http1"
    )]
    upstream_protocol: crate::config::UpstreamProtocol,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    forward_auth: Option<crate::forward_auth::ForwardAuth>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    oidc: Option<crate::oidc::HostPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    compression: Option<crate::compression::CompressionPolicy>,
    cache: Option<crate::cache::CachePolicy>,
    access: Option<crate::policy::AccessPolicy>,
    response: Option<crate::policy::ResponsePolicy>,
    rate_limit: Option<crate::config::RateLimit>,
    reliability: Option<crate::config::Reliability>,
    routing: Option<crate::routing::RoutingPolicy>,
    health_check: Option<crate::config::HealthCheck>,
    preserve_host: bool,
    verify_upstream_tls: bool,
    branded_errors: bool,
}
impl Default for Policies {
    fn default() -> Self {
        Self {
            upstream_protocol: crate::config::UpstreamProtocol::default(),
            forward_auth: None,
            oidc: None,
            compression: None,
            cache: None,
            access: None,
            response: None,
            rate_limit: None,
            reliability: None,
            routing: None,
            health_check: None,
            preserve_host: false,
            verify_upstream_tls: true,
            branded_errors: true,
        }
    }
}
impl Policies {
    fn from_route(route: &Route) -> Self {
        Self {
            upstream_protocol: route.upstream_protocol,
            forward_auth: route.forward_auth.clone(),
            oidc: route.oidc.clone(),
            compression: route.compression.clone(),
            cache: route.cache.clone(),
            access: route.access.clone(),
            response: route.response.clone(),
            rate_limit: route.rate_limit.clone(),
            reliability: route.reliability.clone(),
            routing: route.routing.clone(),
            health_check: route.health_check.clone(),
            preserve_host: route.preserve_host,
            verify_upstream_tls: route.verify_upstream_tls,
            branded_errors: route.pages.as_ref().is_none_or(|p| p.branded_errors),
        }
    }
    fn apply(&self, route: &mut Route) {
        route.upstream_protocol = self.upstream_protocol;
        route.forward_auth = self.forward_auth.clone();
        route.oidc = self.oidc.clone();
        route.compression = self.compression.clone();
        route.cache = self.cache.clone();
        route.access = self.access.clone();
        route.response = self.response.clone();
        route.rate_limit = self.rate_limit.clone();
        route.reliability = self.reliability.clone();
        route.routing = self.routing.clone();
        route.health_check = self.health_check.clone();
        route.preserve_host = self.preserve_host;
        route.verify_upstream_tls = self.verify_upstream_tls;
        // Maintenance is operational state and is deliberately not captured by templates.
        route.pages.get_or_insert_default().branded_errors = self.branded_errors;
    }
    fn validate(&mut self) -> Result<(), String> {
        let mut route:Route=serde_json::from_value(json!({"id":"00000000-0000-4000-8000-000000000001","name":"Template validation","host":"template.invalid","path_prefix":"/","upstream":"http://127.0.0.1:9000","enabled":false,"preserve_host":false})).unwrap();
        self.apply(&mut route);
        let mut config = Config {
            version: 0,
            routes: vec![route],
            trusted_proxies: vec![],
        };
        config.validate()?;
        *self = Self::from_route(&config.routes[0]);
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Template {
    id: String,
    name: String,
    description: String,
    updated_at: u64,
    updated_by: String,
    policies: Policies,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Store {
    pub version: u64,
    pub templates: Vec<Template>,
}
fn text(value: &mut String, limit: usize, empty: bool) -> Result<(), String> {
    *value = value.trim().into();
    if (!empty && value.is_empty())
        || value.chars().count() > limit
        || value.chars().any(char::is_control)
    {
        return Err(format!(
            "Use {}–{limit} characters without control characters.",
            if empty { 0 } else { 1 }
        ));
    }
    Ok(())
}
impl Store {
    fn validate(&mut self) -> Result<(), String> {
        if self.templates.len() > LIMIT {
            return Err("A maximum of 50 host templates is supported.".into());
        }
        let mut ids = HashSet::new();
        let mut names = HashSet::new();
        for template in &mut self.templates {
            if !uuid::Uuid::parse_str(&template.id).is_ok_and(|id| id.to_string() == template.id)
                || !ids.insert(template.id.clone())
            {
                return Err("Invalid template identifier.".into());
            }
            text(&mut template.name, 80, false)?;
            text(&mut template.description, 240, true)?;
            text(&mut template.updated_by, 128, false)?;
            if !names.insert(template.name.to_lowercase()) {
                return Err("Template names must be unique.".into());
            }
            template.policies.validate()?;
        }
        Ok(())
    }
}
pub fn load(root: &FsPath) -> Result<Store, String> {
    let path = root.join(FILE);
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Store::default()),
        Ok(meta)
            if meta.is_file()
                && !meta.file_type().is_symlink()
                && meta.len() <= MAX_BYTES as u64 => {}
        _ => return Err("Cannot read host templates: unsafe or oversized file.".into()),
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .and_then(|file| file.take(MAX_BYTES as u64 + 1).read_to_end(&mut bytes))
        .map_err(|_| "Cannot read host templates.".to_owned())?;
    if bytes.len() > MAX_BYTES {
        return Err("Host templates exceed 2 MiB.".into());
    }
    let mut store: Store =
        serde_json::from_slice(&bytes).map_err(|_| "Invalid host templates file.".to_owned())?;
    store.validate()?;
    Ok(store)
}
async fn read(state: &Shared) -> Result<Store, Error> {
    let root = state.config_path.parent().unwrap().to_path_buf();
    tokio::task::spawn_blocking(move || load(&root))
        .await
        .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Template read failed."))?
        .map_err(|e| error(StatusCode::SERVICE_UNAVAILABLE, e))
}
async fn list(State(state): State<Shared>) -> Result<Json<Store>, Error> {
    let _guard = state.write_lock.lock().await;
    Ok(Json(read(&state).await?))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    #[serde(default)]
    id: Option<String>,
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    source_route_id: Option<String>,
    #[serde(default)]
    expected_config_version: Option<u64>,
    expected_version: u64,
}
async fn persist(
    state: &Shared,
    mut store: Store,
    id: String,
    before: u64,
    source: Option<String>,
) -> Result<Response, Error> {
    store
        .validate()
        .map_err(|e| error(StatusCode::UNPROCESSABLE_ENTITY, e))?;
    store.version = before
        .checked_add(1)
        .ok_or_else(|| error(StatusCode::CONFLICT, "Template version exhausted."))?;
    let bytes = serde_json::to_vec_pretty(&store).map_err(|_| {
        error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Template serialization failed.",
        )
    })?;
    if bytes.len() > MAX_BYTES {
        return Err(error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Host templates exceed the 2 MiB storage limit.",
        ));
    }
    let path = state.config_path.parent().unwrap().join(FILE);
    tokio::task::spawn_blocking(move || crate::history::write_atomic(&path, &bytes))
        .await
        .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Template save failed."))?
        .map_err(|_| {
            error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not save host templates.",
            )
        })?;
    let after = store.version;
    let mut response = Json(store).into_response();
    response
        .extensions_mut()
        .insert(crate::management::AuditExtra(id));
    response.extensions_mut().insert(crate::management::AuditDetails(json!({"template_version_before":before,"template_version_after":after,"source_route_id":source})));
    Ok(response)
}
async fn save(
    State(state): State<Shared>,
    Extension(session): Extension<crate::accounts::Session>,
    Json(input): Json<Input>,
) -> Result<Response, Error> {
    let _guard = state.write_lock.lock().await;
    let mut store = read(&state).await?;
    if input.expected_version != store.version {
        return Err(error(
            StatusCode::CONFLICT,
            "Templates changed in another session. Close and reopen this form.",
        ));
    }
    let policies = if let Some(id) = &input.source_route_id {
        let config = state.config.load_full();
        if input.expected_config_version != Some(config.version) {
            return Err(error(
                StatusCode::CONFLICT,
                "Host configuration changed. Close and reopen this form.",
            ));
        }
        Some(Policies::from_route(
            config
                .routes
                .iter()
                .find(|r| &r.id == id)
                .ok_or_else(|| error(StatusCode::NOT_FOUND, "Source host no longer exists."))?,
        ))
    } else {
        None
    };
    let id = if let Some(id) = input.id {
        let template = store
            .templates
            .iter_mut()
            .find(|t| t.id == id)
            .ok_or_else(|| error(StatusCode::NOT_FOUND, "Template no longer exists."))?;
        template.name = input.name;
        template.description = input.description;
        template.updated_at = now();
        template.updated_by = session.user.username;
        if let Some(policies) = policies {
            template.policies = policies;
        }
        id
    } else {
        let policies = policies.ok_or_else(|| {
            error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Choose a saved host to copy policies from.",
            )
        })?;
        let id = uuid::Uuid::new_v4().to_string();
        store.templates.push(Template {
            id: id.clone(),
            name: input.name,
            description: input.description,
            updated_at: now(),
            updated_by: session.user.username,
            policies,
        });
        id
    };
    let before = store.version;
    persist(&state, store, id, before, input.source_route_id).await
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Remove {
    expected_version: u64,
}
async fn remove(
    State(state): State<Shared>,
    Path(id): Path<String>,
    Json(input): Json<Remove>,
) -> Result<Response, Error> {
    let _guard = state.write_lock.lock().await;
    let mut store = read(&state).await?;
    if store.version != input.expected_version {
        return Err(error(
            StatusCode::CONFLICT,
            "Templates changed. Refresh and review again.",
        ));
    }
    let index = store
        .templates
        .iter()
        .position(|t| t.id == id)
        .ok_or_else(|| error(StatusCode::NOT_FOUND, "Template no longer exists."))?;
    store.templates.remove(index);
    let before = store.version;
    persist(&state, store, id, before, None).await
}
pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/host-templates", get(list).post(save))
        .route("/api/host-templates/{id}", axum::routing::delete(remove))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn policies_are_independent_and_preserve_identity_and_operational_state() {
        let mut route:Route=serde_json::from_value(json!({"id":uuid::Uuid::new_v4().to_string(),"name":"Original","host":"original.test","path_prefix":"/app","upstream":"http://127.0.0.1:9000","enabled":true,"preserve_host":true,"verify_upstream_tls":false,"additional_upstreams":["http://127.0.0.1:9001"],"balancing":{"strategy":"weighted_round_robin","weights":[2,1],"draining":["http://127.0.0.1:9001"]},"pages":{"maintenance":true,"branded_errors":false},"cache":{"max_ttl_seconds":60,"max_object_bytes":1024}})).unwrap();
        let mut policies = Policies::from_route(&route);
        policies.validate().unwrap();
        let captured = serde_json::to_value(&policies).unwrap();
        for key in [
            "id",
            "name",
            "host",
            "path_prefix",
            "upstream",
            "additional_upstreams",
            "balancing",
            "pages",
            "enabled",
        ] {
            assert!(captured.get(key).is_none());
        }
        assert_eq!(captured["branded_errors"], false);
        assert_eq!(captured["verify_upstream_tls"], false);
        let identity = serde_json::to_value(&route).unwrap();
        policies.cache = None;
        policies.preserve_host = false;
        policies.verify_upstream_tls = true;
        policies.apply(&mut route);
        let updated = serde_json::to_value(&route).unwrap();
        assert!(route.verify_upstream_tls);
        for key in [
            "id",
            "name",
            "host",
            "path_prefix",
            "upstream",
            "additional_upstreams",
            "balancing",
            "enabled",
        ] {
            assert_eq!(identity[key], updated[key]);
        }
        assert!(route.pages.unwrap().maintenance);
        assert!(route.cache.is_none());
        assert!(!route.preserve_host);
    }
    #[test]
    fn storage_rejects_unsafe_policies_duplicate_names_and_unknown_fields() {
        let mut policies = Policies::default();
        policies.rate_limit = Some(crate::config::RateLimit {
            requests: 1,
            window_seconds: 1,
            burst: 2,
        });
        assert!(policies.validate().is_err());
        assert!(
            serde_json::from_value::<Policies>(json!({"upstream":"http://secret.test"})).is_err()
        );
        let template = Template {
            id: uuid::Uuid::new_v4().to_string(),
            name: "Public".into(),
            description: String::new(),
            updated_at: now(),
            updated_by: "admin".into(),
            policies: Policies::default(),
        };
        let mut other = template.clone();
        other.id = uuid::Uuid::new_v4().to_string();
        other.name = " public ".into();
        assert!(Store {
            version: 0,
            templates: vec![template, other]
        }
        .validate()
        .is_err());
    }
}

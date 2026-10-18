//! Conservative public-response caching using Pingora's cache pipeline and bounded LRU storage.
use crate::config::{Config, Route};
use async_trait::async_trait;
use axum::http::HeaderMap;
use bytes::Bytes;
use lru::LruCache;
use pingora::{
    cache::{
        key::CacheHashKey,
        storage::{
            HandleHit, HandleMiss, HitHandler, MissFinishType, MissHandler, PurgeOutcome,
            PurgeTarget, PurgeType, Storage,
        },
        trace::SpanHandle,
        CacheKey, CacheMeta, NoCacheReason, RespCacheable,
    },
    http::{RequestHeader, ResponseHeader},
    Error, ErrorType, Result,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    any::Any,
    collections::HashMap,
    num::NonZeroUsize,
    sync::Mutex,
    time::{Duration, SystemTime},
};

pub const CAPACITY: usize = 64 * 1024 * 1024;
const MAX_ENTRIES: usize = 4096;
const MAX_FILLS: usize = 16;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CachePolicy {
    pub max_ttl_seconds: u64,
    pub max_object_bytes: usize,
    #[serde(default)]
    pub cache_query_strings: bool,
}
impl CachePolicy {
    pub fn validate(&self) -> std::result::Result<(), String> {
        if !(1..=86400).contains(&self.max_ttl_seconds)
            || !(1024..=4 * 1024 * 1024).contains(&self.max_object_bytes)
        {
            return Err(
                "Cache limits require 1–86400 seconds and an object size of 1024–4194304 bytes."
                    .into(),
            );
        }
        Ok(())
    }
}
#[derive(Clone)]
pub struct Identity {
    route_id: String,
    epoch: uuid::Uuid,
    path: [u8; 32],
    origin: [u8; 32],
    pub max_object_bytes: usize,
}
struct Entry {
    identity: Identity,
    meta: (Vec<u8>, Vec<u8>),
    body: Bytes,
    expires: SystemTime,
    size: usize,
}
struct Namespace {
    signature: [u8; 32],
    epoch: uuid::Uuid,
    hits: u64,
    misses: u64,
    bypasses: u64,
    purges: u64,
}
struct State {
    version: u64,
    entries: LruCache<String, Entry>,
    routes: HashMap<String, Namespace>,
    used: usize,
    fills: usize,
}
pub struct ResponseCache {
    pub lock: pingora::cache::lock::CacheLock,
    state: Mutex<State>,
    capacity: usize,
    max_entries: usize,
}
impl Default for ResponseCache {
    fn default() -> Self {
        Self::with_capacity(CAPACITY, MAX_ENTRIES)
    }
}
fn hash(data: impl AsRef<[u8]>) -> [u8; 32] {
    openssl::sha::sha256(data.as_ref())
}
fn namespace() -> Namespace {
    Namespace {
        signature: [0; 32],
        epoch: uuid::Uuid::new_v4(),
        hits: 0,
        misses: 0,
        bypasses: 0,
        purges: 0,
    }
}
fn remove(state: &mut State, key: &str) -> bool {
    if let Some(entry) = state.entries.pop(key) {
        state.used -= entry.size;
        true
    } else {
        false
    }
}
fn current(state: &State, id: &Identity) -> bool {
    state
        .routes
        .get(&id.route_id)
        .is_some_and(|route| route.epoch == id.epoch)
}
impl ResponseCache {
    fn with_capacity(capacity: usize, max_entries: usize) -> Self {
        Self {
            lock: pingora::cache::lock::CacheLock::new(Duration::from_secs(2)),
            state: Mutex::new(State {
                version: 0,
                entries: LruCache::new(NonZeroUsize::new(max_entries).unwrap()),
                routes: HashMap::new(),
                used: 0,
                fills: 0,
            }),
            capacity,
            max_entries,
        }
    }
    pub fn sync_config(&self, config: &Config) {
        let mut state = self.state.lock().unwrap();
        state.version = config.version;
        let mut next = HashMap::new();
        for route in config
            .routes
            .iter()
            .filter(|r| r.enabled && r.cache.is_some())
        {
            let signature = hash(serde_json::to_vec(&(route, &config.trusted_proxies)).unwrap());
            let mut ns = state.routes.remove(&route.id).unwrap_or_else(namespace);
            if ns.signature != signature {
                ns.signature = signature;
                ns.epoch = uuid::Uuid::new_v4();
            }
            next.insert(route.id.clone(), ns);
        }
        state.routes = next;
        let invalid: Vec<_> = state
            .entries
            .iter()
            .filter(|(_, entry)| !current(&state, &entry.identity))
            .map(|(key, _)| key.clone())
            .collect();
        for key in invalid {
            remove(&mut state, &key);
        }
    }
    pub fn key(
        &self,
        route: &Route,
        request: &RequestHeader,
        https: bool,
        version: u64,
    ) -> Option<CacheKey> {
        let state = self.state.lock().unwrap();
        if state.version != version {
            return None;
        }
        let ns = state.routes.get(&route.id)?;
        let host = request_authority(request)?;
        let origin = origin(host, https)?;
        let path = request
            .uri
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/");
        let encoding = request
            .headers
            .get_all("accept-encoding")
            .iter()
            .map(|v| v.as_bytes())
            .collect::<Vec<_>>();
        // Length-delimited serialization avoids ambiguity and keeps every query parameter in the key.
        let primary = serde_json::to_vec(&(&route.id, https, host, path, encoding)).ok()?;
        let identity = Identity {
            route_id: route.id.clone(),
            epoch: ns.epoch,
            path: hash(path),
            origin: hash(origin),
            max_object_bytes: route.cache.as_ref()?.max_object_bytes,
        };
        let mut key = CacheKey::new(primary, &route.id);
        key.extensions.insert(identity);
        Some(key)
    }
    pub fn record(&self, route_id: &str, status: &str) {
        if let Some(route) = self.state.lock().unwrap().routes.get_mut(route_id) {
            match status {
                "HIT" => route.hits += 1,
                "MISS" => route.misses += 1,
                "BYPASS" => route.bypasses += 1,
                _ => {}
            }
        }
    }
    pub fn summary(&self, config: &Config) -> serde_json::Value {
        let mut state = self.state.lock().unwrap();
        let expired: Vec<_> = state
            .entries
            .iter()
            .filter(|(_, e)| e.expires <= SystemTime::now())
            .map(|(k, _)| k.clone())
            .collect();
        for key in expired {
            remove(&mut state, &key);
        }
        let mut sizes: HashMap<&str, (usize, usize)> = HashMap::new();
        for (_, entry) in state.entries.iter() {
            let size = sizes.entry(&entry.identity.route_id).or_default();
            size.0 += 1;
            size.1 += entry.size;
        }
        let routes:Vec<_>=config.routes.iter().map(|route| {
            let ns=state.routes.get(&route.id);
            let (entries,bytes)=sizes.get(route.id.as_str()).copied().unwrap_or_default();
            let hits=ns.map_or(0,|s|s.hits);let misses=ns.map_or(0,|s|s.misses);
            json!({"route_id":route.id,"name":route.name,"enabled":route.enabled && route.cache.is_some(),"hits":hits,"misses":misses,
                "bypasses":ns.map_or(0,|s|s.bypasses),"purges":ns.map_or(0,|s|s.purges),"entries":entries,"bytes":bytes,"hit_ratio":if hits+misses>0 {hits as f64/(hits+misses) as f64}else{0.0}})
        }).collect();
        json!({"capacity_bytes":self.capacity,"used_bytes":state.used,"entries":state.entries.len(),"inflight_fills":state.fills,"max_inflight_fills":MAX_FILLS,"max_entries":self.max_entries,"routes":routes})
    }
    pub fn purge_route(
        &self,
        route_id: Option<&str>,
        selector: Option<&str>,
    ) -> std::result::Result<usize, String> {
        let selector = selector.map(parse_selector).transpose()?;
        let mut state = self.state.lock().unwrap();
        // Rotate the epoch even for URL purges: all older in-flight fills for the route become inadmissible.
        for (id, route) in &mut state.routes {
            if route_id.is_none_or(|r| r == id) {
                route.epoch = uuid::Uuid::new_v4();
                route.purges += 1;
            }
        }
        let keys: Vec<_> = state
            .entries
            .iter()
            .filter(|(_, e)| {
                route_id.is_none_or(|id| id == e.identity.route_id)
                    && selector.as_ref().is_none_or(|(path, origin)| {
                        e.identity.path == *path
                            && origin.is_none_or(|origin| origin == e.identity.origin)
                    })
            })
            .map(|(key, _)| key.clone())
            .collect();
        for key in &keys {
            remove(&mut state, key);
        }
        // Entries retained by a URL purge remain valid in the new route epoch.
        let epochs: HashMap<_, _> = state
            .routes
            .iter()
            .map(|(id, ns)| (id.clone(), ns.epoch))
            .collect();
        for (_, entry) in state.entries.iter_mut() {
            if let Some(epoch) = epochs.get(&entry.identity.route_id) {
                entry.identity.epoch = *epoch;
            }
        }
        Ok(keys.len())
    }
}
fn origin(host: &str, https: bool) -> Option<String> {
    let url = url::Url::parse(&format!(
        "{}://{host}",
        if https { "https" } else { "http" }
    ))
    .ok()?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    Some(url.origin().ascii_serialization())
}
fn parse_selector(value: &str) -> std::result::Result<([u8; 32], Option<[u8; 32]>), String> {
    if value.len() > 8192 || value.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("Enter an exact path/query or an HTTP(S) URL up to 8192 bytes.".into());
    }
    if value.starts_with('/') && !value.starts_with("//") {
        let uri = value
            .parse::<axum::http::Uri>()
            .map_err(|_| "Invalid purge path.")?;
        if uri.scheme().is_some() || uri.authority().is_some() || value.contains('#') {
            return Err("Use a path with optional query and no fragment.".into());
        }
        return Ok((hash(value), None));
    }
    let url = url::Url::parse(value).map_err(|_| "Enter an HTTP(S) URL or absolute path.")?;
    if !["http", "https"].contains(&url.scheme())
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err("Purge URLs must use HTTP(S) without credentials or fragments.".into());
    }
    let path = format!(
        "{}{}",
        url.path(),
        url.query().map(|q| format!("?{q}")).unwrap_or_default()
    );
    Ok((hash(path), Some(hash(url.origin().ascii_serialization()))))
}

pub fn request_authority(request: &RequestHeader) -> Option<&str> {
    let mut hosts = request.headers.get_all("host").iter();
    if let Some(host) = hosts.next() {
        if hosts.next().is_some() {
            return None;
        }
        return host.to_str().ok();
    }
    request.uri.authority().map(|authority| authority.as_str())
}
pub fn request_eligible(
    request: &RequestHeader,
    policy: &CachePolicy,
) -> std::result::Result<(), &'static str> {
    if request.method != "GET" && request.method != "HEAD" {
        return Err("method");
    }
    for header in [
        "authorization",
        "proxy-authorization",
        "cookie",
        "range",
        "if-range",
        "if-match",
        "if-none-match",
        "if-modified-since",
        "if-unmodified-since",
        "upgrade",
        "transfer-encoding",
        "pragma",
    ] {
        if request.headers.contains_key(header) {
            return Err("request headers");
        }
    }
    let lengths: Vec<_> = request.headers.get_all("content-length").iter().collect();
    if lengths.len() > 1 || lengths.first().is_some_and(|v| v.as_bytes() != b"0") {
        return Err("request body");
    }
    let controls: Vec<_> = request.headers.get_all("cache-control").iter().collect();
    if !controls.is_empty()
        && (controls.len() != 1
            || !controls[0]
                .as_bytes()
                .eq_ignore_ascii_case(b"only-if-cached"))
    {
        return Err("request cache directives");
    }
    if request.uri.query().is_some() && !policy.cache_query_strings {
        return Err("query string");
    }
    if request.uri.to_string().len() > 8192 || request_authority(request).is_none() {
        return Err("request authority or size");
    }
    Ok(())
}
pub fn only_if_cached(headers: &HeaderMap) -> bool {
    headers
        .get_all("cache-control")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|v| v.trim().eq_ignore_ascii_case("only-if-cached"))
}
fn directives(headers: &HeaderMap) -> Option<HashMap<String, Option<String>>> {
    let mut result = HashMap::new();
    for header in headers.get_all("cache-control").iter() {
        for item in header.to_str().ok()?.split(',') {
            let (name, value) = item
                .trim()
                .split_once('=')
                .map_or((item.trim(), None), |(n, v)| {
                    (n.trim(), Some(v.trim().trim_matches('"').to_owned()))
                });
            if name.is_empty()
                || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                || result.contains_key(&name.to_ascii_lowercase())
            {
                return None;
            }
            if value.as_ref().is_some_and(|v| v.contains([';', '"', '\\'])) {
                return None;
            }
            result.insert(name.to_ascii_lowercase(), value);
        }
    }
    Some(result)
}
pub fn response_meta(
    request: &RequestHeader,
    response: &ResponseHeader,
    policy: &CachePolicy,
    started: SystemTime,
) -> RespCacheable {
    let reject = || RespCacheable::Uncacheable(NoCacheReason::OriginNotCache);
    if request_eligible(request, policy).is_err()
        || request.method != "GET"
        || response.status.as_u16() != 200
        || response.headers.contains_key("set-cookie")
        || response.headers.contains_key("content-range")
        || response.headers.contains_key("trailer")
    {
        return reject();
    }
    for vary in response.headers.get_all("vary").iter() {
        let Ok(vary) = vary.to_str() else {
            return reject();
        };
        if vary
            .split(',')
            .any(|name| !name.trim().eq_ignore_ascii_case("accept-encoding"))
        {
            return reject();
        }
    }
    let Some(cc) = directives(&response.headers) else {
        return reject();
    };
    if ["private", "no-store", "no-cache"]
        .iter()
        .any(|name| cc.contains_key(*name))
    {
        return reject();
    }
    let ttl = cc
        .get("s-maxage")
        .or_else(|| cc.get("max-age"))
        .and_then(|v| v.as_ref())
        .and_then(|v| v.parse::<u64>().ok());
    let Some(ttl) = ttl.filter(|v| *v > 0) else {
        return reject();
    };
    let length: Vec<_> = response.headers.get_all("content-length").iter().collect();
    if length.len() > 1
        || length.first().is_some_and(|v| {
            v.to_str()
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .is_none_or(|v| v > policy.max_object_bytes)
        })
    {
        return reject();
    }
    let now = SystemTime::now();
    let age: Vec<_> = response.headers.get_all("age").iter().collect();
    if age.len() > 1 {
        return reject();
    }
    let age = match age.first() {
        Some(v) => match v.to_str().ok().and_then(|s| s.parse::<u64>().ok()) {
            Some(age) => age,
            None => return reject(),
        },
        None => 0,
    };
    let dates: Vec<_> = response.headers.get_all("date").iter().collect();
    if dates.len() > 1 {
        return reject();
    }
    let apparent = match dates.first() {
        Some(v) => match v
            .to_str()
            .ok()
            .and_then(|s| httpdate::parse_http_date(s).ok())
        {
            Some(date) => now.duration_since(date).unwrap_or_default(),
            None => return reject(),
        },
        None => Duration::ZERO,
    };
    let delay = now.duration_since(started).unwrap_or_default();
    let age = Duration::from_secs(age).saturating_add(delay).max(apparent);
    let lifetime = Duration::from_secs(ttl.min(policy.max_ttl_seconds));
    let Some(remaining) = lifetime.checked_sub(age).filter(|r| !r.is_zero()) else {
        return reject();
    };
    let Some(expires) = now.checked_add(remaining) else {
        return reject();
    };
    let Some(epoch) = now.checked_sub(age) else {
        return reject();
    };
    RespCacheable::Cacheable(CacheMeta::new(expires, epoch, 0, 0, response.clone()))
}

struct Hit {
    body: Option<Bytes>,
}
#[async_trait]
impl HandleHit for Hit {
    async fn read_body(&mut self) -> Result<Option<Bytes>> {
        Ok(self.body.take())
    }
    async fn finish(
        self: Box<Self>,
        _: &'static (dyn Storage + Sync),
        _: &CacheKey,
        _: &SpanHandle,
    ) -> Result<()> {
        Ok(())
    }
    fn as_any(&self) -> &(dyn Any + Send + Sync) {
        self
    }
    fn as_any_mut(&mut self) -> &mut (dyn Any + Send + Sync) {
        self
    }
}
struct Miss {
    storage: &'static ResponseCache,
    key: String,
    identity: Identity,
    meta: (Vec<u8>, Vec<u8>),
    expires: SystemTime,
    body: Vec<u8>,
}
impl Drop for Miss {
    fn drop(&mut self) {
        self.storage.state.lock().unwrap().fills -= 1;
    }
}
#[async_trait]
impl HandleMiss for Miss {
    async fn write_body(&mut self, data: Bytes, _: bool) -> Result<()> {
        if self.body.len().saturating_add(data.len()) > self.identity.max_object_bytes {
            return Err(Error::new(ErrorType::InternalError));
        }
        self.body.extend_from_slice(&data);
        Ok(())
    }
    async fn finish(mut self: Box<Self>) -> Result<MissFinishType> {
        let size = self.body.capacity()
            + self.meta.0.capacity()
            + self.meta.1.capacity()
            + self.key.len()
            + 512;
        let mut state = self.storage.state.lock().unwrap();
        if !current(&state, &self.identity)
            || size > self.storage.capacity
            || self.expires <= SystemTime::now()
        {
            return Ok(MissFinishType::Created(0));
        }
        remove(&mut state, &self.key);
        while state.used + size > self.storage.capacity
            || state.entries.len() >= self.storage.max_entries
        {
            if let Some((_, entry)) = state.entries.pop_lru() {
                state.used -= entry.size;
            } else {
                break;
            }
        }
        let body = Bytes::from(std::mem::take(&mut self.body));
        let entry = Entry {
            identity: self.identity.clone(),
            meta: std::mem::take(&mut self.meta),
            body,
            expires: self.expires,
            size,
        };
        state.used += size;
        state.entries.put(self.key.clone(), entry);
        Ok(MissFinishType::Created(size))
    }
}
#[async_trait]
impl Storage for ResponseCache {
    async fn lookup(
        &'static self,
        key: &CacheKey,
        _: &SpanHandle,
    ) -> Result<Option<(CacheMeta, HitHandler)>> {
        let Some(identity) = key.extensions.get::<Identity>() else {
            return Ok(None);
        };
        let mut state = self.state.lock().unwrap();
        if !current(&state, identity) {
            return Ok(None);
        }
        let hash = key.combined();
        if state
            .entries
            .peek(&hash)
            .is_some_and(|entry| entry.expires <= SystemTime::now())
        {
            remove(&mut state, &hash);
        }
        let Some(entry) = state.entries.get(&hash) else {
            return Ok(None);
        };
        let meta = CacheMeta::deserialize(&entry.meta.0, &entry.meta.1)?;
        Ok(Some((
            meta,
            Box::new(Hit {
                body: Some(entry.body.clone()),
            }),
        )))
    }
    async fn get_miss_handler(
        &'static self,
        key: &CacheKey,
        meta: &CacheMeta,
        _: &SpanHandle,
    ) -> Result<MissHandler> {
        let identity = key
            .extensions
            .get::<Identity>()
            .ok_or_else(|| Error::new(ErrorType::InternalError))?
            .clone();
        let binary = meta.serialize()?;
        if binary.0.len() + binary.1.len() > 64 * 1024 {
            return Err(Error::new(ErrorType::InternalError));
        }
        let mut state = self.state.lock().unwrap();
        if !current(&state, &identity) || state.fills >= MAX_FILLS {
            return Err(Error::new(ErrorType::InternalError));
        }
        state.fills += 1;
        Ok(Box::new(Miss {
            storage: self,
            key: key.combined(),
            identity,
            meta: binary,
            expires: meta.fresh_until(),
            body: vec![],
        }))
    }
    async fn purge(
        &'static self,
        target: PurgeTarget<'_>,
        _: PurgeType,
        _: &SpanHandle,
    ) -> Result<PurgeOutcome> {
        if matches!(
            target,
            PurgeTarget::Exact(pingora::cache::eviction::CacheEntryKey::Identified { .. })
        ) {
            return Ok(PurgeOutcome::NotFound);
        }
        Ok(
            if remove(&mut self.state.lock().unwrap(), &target.key().combined()) {
                PurgeOutcome::Purged(None)
            } else {
                PurgeOutcome::NotFound
            },
        )
    }
    async fn update_meta(
        &'static self,
        _: &CacheKey,
        _: &CacheMeta,
        _: &SpanHandle,
    ) -> Result<bool> {
        Ok(false)
    }
    fn as_any(&self) -> &(dyn Any + Send + Sync + 'static) {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn route() -> Route {
        serde_json::from_value(json!({"id":uuid::Uuid::new_v4().to_string(),"name":"Cache","host":"*","path_prefix":"/","upstream":"http://127.0.0.1:9000","enabled":true,"preserve_host":false,"cache":{"max_ttl_seconds":60,"max_object_bytes":4096,"cache_query_strings":true}})).unwrap()
    }
    fn config(route: &Route) -> Config {
        Config {
            version: 0,
            routes: vec![route.clone()],
            trusted_proxies: vec![],
        }
    }
    fn request(path: &str, host: &str) -> RequestHeader {
        let mut req = RequestHeader::build("GET", path.as_bytes(), None).unwrap();
        req.insert_header("Host", host).unwrap();
        req
    }
    fn meta() -> CacheMeta {
        CacheMeta::new(
            SystemTime::now() + Duration::from_secs(60),
            SystemTime::now(),
            0,
            0,
            ResponseHeader::build(200, None).unwrap(),
        )
    }
    #[test]
    fn admission_rejects_private_ambiguous_and_aged_responses() {
        let route = route();
        let policy = route.cache.as_ref().unwrap();
        let req = request("/", "app.test");
        for control in [
            "private, max-age=60",
            "no-store, max-age=60",
            "no-cache=\"etag\", max-age=60",
            "max-age=60, max-age=600",
            "max-age=0",
            "max-age=bad",
            "max-age=60;private",
        ] {
            let mut resp = ResponseHeader::build(200, None).unwrap();
            resp.insert_header("Cache-Control", control).unwrap();
            assert!(
                matches!(
                    response_meta(&req, &resp, policy, SystemTime::now()),
                    RespCacheable::Uncacheable(_)
                ),
                "{control}"
            );
        }
        for (name, value) in [
            ("Set-Cookie", "session=secret"),
            ("Vary", "*"),
            ("Vary", "Accept-Language"),
            ("Age", "61"),
            ("Content-Length", "4097"),
        ] {
            let mut resp = ResponseHeader::build(200, None).unwrap();
            resp.insert_header("Cache-Control", "public, max-age=60")
                .unwrap();
            resp.insert_header(name, value).unwrap();
            assert!(
                matches!(
                    response_meta(&req, &resp, policy, SystemTime::now()),
                    RespCacheable::Uncacheable(_)
                ),
                "{name}"
            );
        }
        let mut resp = ResponseHeader::build(200, None).unwrap();
        resp.insert_header("Cache-Control", "max-age=600, s-maxage=30")
            .unwrap();
        resp.insert_header("Vary", "Accept-Encoding").unwrap();
        resp.insert_header("Age", "10").unwrap();
        match response_meta(&req, &resp, policy, SystemTime::now()) {
            RespCacheable::Cacheable(meta) => assert!(
                meta.fresh_until()
                    .duration_since(SystemTime::now())
                    .unwrap()
                    .as_secs()
                    <= 20
            ),
            _ => panic!("explicit public freshness should cache"),
        }
    }
    #[test]
    fn key_boundaries_include_scheme_authority_query_and_encoding() {
        let route = route();
        let cache = ResponseCache::default();
        cache.sync_config(&config(&route));
        let one = request("/a?x=1", "app.test");
        let two = request("/a?x=2", "app.test");
        let key = cache.key(&route, &one, false, 0).unwrap().combined();
        assert_ne!(key, cache.key(&route, &two, false, 0).unwrap().combined());
        assert_ne!(key, cache.key(&route, &one, true, 0).unwrap().combined());
        assert_ne!(
            key,
            cache
                .key(&route, &request("/a?x=1", "other.test"), false, 0)
                .unwrap()
                .combined()
        );
        let mut h2 = RequestHeader::build("GET", b"/a?x=1", None).unwrap();
        h2.set_uri("https://app.test/a?x=1".parse().unwrap());
        assert!(request_eligible(&h2, route.cache.as_ref().unwrap()).is_ok());
        assert_eq!(
            cache.key(&route, &h2, true, 0).unwrap().combined(),
            cache.key(&route, &one, true, 0).unwrap().combined()
        );
        let mut encoded = one.clone();
        encoded.insert_header("Accept-Encoding", "gzip").unwrap();
        assert_ne!(
            key,
            cache.key(&route, &encoded, false, 0).unwrap().combined()
        );
        for name in [
            "Cookie",
            "Authorization",
            "Range",
            "If-None-Match",
            "Cache-Control",
        ] {
            let mut req = one.clone();
            req.insert_header(name, "value").unwrap();
            assert!(request_eligible(&req, route.cache.as_ref().unwrap()).is_err());
        }
    }
    #[tokio::test]
    async fn purge_invalidates_late_fills_and_preserves_other_urls() {
        let route = route();
        let cache = Box::leak(Box::new(ResponseCache::default()));
        cache.sync_config(&config(&route));
        let trace = pingora::cache::trace::Span::inactive().handle();
        let req = request("/one", "app.test");
        let old = cache.key(&route, &req, false, 0).unwrap();
        let mut pending = cache.get_miss_handler(&old, &meta(), &trace).await.unwrap();
        pending
            .write_body(Bytes::from_static(b"old"), true)
            .await
            .unwrap();
        cache.purge_route(Some(&route.id), Some("/one")).unwrap();
        pending.finish().await.unwrap();
        let current = cache.key(&route, &req, false, 0).unwrap();
        assert!(cache.lookup(&current, &trace).await.unwrap().is_none());
        for path in ["/one", "/two"] {
            let key = cache
                .key(&route, &request(path, "app.test"), false, 0)
                .unwrap();
            let mut writer = cache.get_miss_handler(&key, &meta(), &trace).await.unwrap();
            writer
                .write_body(Bytes::from_static(b"new"), true)
                .await
                .unwrap();
            writer.finish().await.unwrap();
        }
        assert_eq!(
            cache
                .purge_route(Some(&route.id), Some("http://app.test/one"))
                .unwrap(),
            1
        );
        let second = cache
            .key(&route, &request("/two", "app.test"), false, 0)
            .unwrap();
        assert!(cache.lookup(&second, &trace).await.unwrap().is_some());
        cache.sync_config(&Config::default());
        assert!(cache.state.lock().unwrap().entries.is_empty());
    }
    #[tokio::test]
    async fn storage_budget_and_fill_limits_are_enforced() {
        let route = route();
        let cache = Box::leak(Box::new(ResponseCache::with_capacity(4096, 2)));
        cache.sync_config(&config(&route));
        let trace = pingora::cache::trace::Span::inactive().handle();
        for path in ["/a", "/b", "/c"] {
            let key = cache
                .key(&route, &request(path, "app.test"), false, 0)
                .unwrap();
            let mut writer = cache.get_miss_handler(&key, &meta(), &trace).await.unwrap();
            writer
                .write_body(Bytes::from(vec![0; 1200]), true)
                .await
                .unwrap();
            writer.finish().await.unwrap();
        }
        {
            let state = cache.state.lock().unwrap();
            assert!(state.used <= 4096 && state.entries.len() <= 2);
        }
        let key = cache
            .key(&route, &request("/fills", "app.test"), false, 0)
            .unwrap();
        let mut writers = vec![];
        for _ in 0..MAX_FILLS {
            writers.push(cache.get_miss_handler(&key, &meta(), &trace).await.unwrap());
        }
        assert!(cache.get_miss_handler(&key, &meta(), &trace).await.is_err());
        assert!(writers[0]
            .write_body(Bytes::from(vec![0; 4097]), true)
            .await
            .is_err());
        drop(writers);
        assert_eq!(cache.state.lock().unwrap().fills, 0);
    }
}

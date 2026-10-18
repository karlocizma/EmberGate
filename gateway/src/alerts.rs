use crate::{
    management::storage,
    state::{now, Shared},
};
use async_trait::async_trait;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use pingora::{server::ShutdownWatch, services::background::BackgroundService};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::HashSet, time::Duration};
#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookFormat {
    #[default]
    Generic,
    Discord,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub backend_failures: bool,
    pub certificate_failures: bool,
    pub error_rate: bool,
    pub error_threshold_percent: f64,
    pub minimum_requests: u64,
    pub window_minutes: u64,
    pub webhook_enabled: bool,
    pub webhook_format: WebhookFormat,
    pub version: u64,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            backend_failures: true,
            certificate_failures: true,
            error_rate: true,
            error_threshold_percent: 10.,
            minimum_requests: 20,
            window_minutes: 5,
            webhook_enabled: false,
            webhook_format: WebhookFormat::Generic,
            version: 0,
        }
    }
}
impl Settings {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if !self.error_threshold_percent.is_finite()
            || !(1.0..=100.).contains(&self.error_threshold_percent)
            || !(1..=100000).contains(&self.minimum_requests)
            || !(1..=60).contains(&self.window_minutes)
        {
            Err("Use a threshold of 1–100%, at least 1–100,000 requests, and a window of 1–60 minutes.".into())
        } else {
            Ok(())
        }
    }
}
pub fn webhook() -> Result<Option<String>, String> {
    let Some(value) = std::env::var("GATEWAY_ALERT_WEBHOOK_URL")
        .ok()
        .filter(|v| !v.is_empty())
    else {
        return Ok(None);
    };
    validate_webhook(&value)?;
    Ok(Some(value))
}
pub fn validate_webhook(value: &str) -> Result<(), String> {
    if value.len() > 2048 || value.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("Invalid webhook URL.".into());
    }
    let url = url::Url::parse(value).map_err(|_| "Invalid webhook URL.".to_owned())?;
    let local = url.host_str().is_some_and(|host| {
        host == "localhost"
            || host
                .trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if !(url.scheme() == "https" || (url.scheme() == "http" && local))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err("Alert webhooks require HTTPS (HTTP allowed for loopback testing), without URL credentials or fragments.".into());
    }
    Ok(())
}
const DESTINATION: &str = "alert_webhook_url";
async fn destination(state: &Shared) -> Result<Option<String>, String> {
    if let Some(url) = webhook()? {
        return Ok(Some(url));
    }
    state
        .control
        .run(|db| {
            db.query_row(
                "SELECT value FROM secrets WHERE key=?1",
                params![DESTINATION],
                |r| r.get(0),
            )
            .optional()
            .map_err(storage)
        })
        .await
}
pub(crate) fn validate_destination(value: &str, format: WebhookFormat) -> Result<(), String> {
    validate_webhook(value)?;
    if format == WebhookFormat::Discord {
        let url = url::Url::parse(value).map_err(|_| "Invalid webhook URL.".to_owned())?;
        let local = url.host_str().is_some_and(|h| {
            h == "localhost"
                || h.trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        });
        if !local {
            if !["discord.com", "canary.discord.com", "ptb.discord.com"]
                .contains(&url.host_str().unwrap_or(""))
                || url.port().is_some_and(|p| p != 443)
            {
                return Err("Use a Discord HTTPS webhook URL.".into());
            }
            let parts: Vec<_> = url.path().split('/').skip(1).collect();
            let pair = if parts.len() == 4 && parts[0] == "api" && parts[1] == "webhooks" {
                Some((parts[2], parts[3]))
            } else if parts.len() == 5
                && parts[0] == "api"
                && parts[1].len() > 1
                && parts[1].starts_with('v')
                && parts[1][1..].bytes().all(|b| b.is_ascii_digit())
                && parts[2] == "webhooks"
            {
                Some((parts[3], parts[4]))
            } else {
                None
            };
            if !pair.is_some_and(|(id, token)| {
                !id.is_empty()
                    && id.bytes().all(|b| b.is_ascii_digit())
                    && !token.is_empty()
                    && token
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            }) {
                return Err("Use the complete Discord /api/webhooks/id/token URL.".into());
            }
        }
        let mut seen = HashSet::new();
        for (key, value) in url.query_pairs() {
            if !seen.insert(key.to_string())
                || !match key.as_ref() {
                    "wait" => matches!(value.as_ref(), "true" | "false"),
                    "thread_id" => !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()),
                    _ => false,
                }
            {
                return Err("Discord URLs support only wait and a numeric thread_id query.".into());
            }
        }
    }
    Ok(())
}
fn truncate(value: &str, limit: usize) -> String {
    let mut used = 0;
    value
        .chars()
        .take_while(|c| {
            used += c.len_utf16();
            used <= limit
        })
        .collect()
}
fn notification(payload: &str, format: WebhookFormat) -> Result<Value, String> {
    let event: Value =
        serde_json::from_str(payload).map_err(|_| "Invalid queued notification.".to_owned())?;
    if format == WebhookFormat::Generic {
        return Ok(event);
    }
    let state = event["event"].as_str().unwrap_or("test");
    let title = event["alert"]["title"]
        .as_str()
        .unwrap_or("Notification test");
    let message = event["alert"]["message"]
        .as_str()
        .or_else(|| event["message"].as_str())
        .unwrap_or("EmberGate notification");
    let mut fields = vec![
        json!({"name":"Event","value":if state=="resolved" {"Recovered"}else if state=="opened" {"Alert opened"}else{"Test"},"inline":true}),
    ];
    if let Some(id) = event["alert"]["id"].as_str() {
        fields.push(json!({"name":"Alert ID","value":truncate(id,64),"inline":false}));
    }
    if let Some(timestamp) = event["timestamp"].as_u64() {
        fields.push(json!({"name":"Time","value":format!("<t:{timestamp}:F>"),"inline":false}));
    }
    Ok(
        json!({"username":"EmberGate","allowed_mentions":{"parse":[]},"embeds":[{"title":truncate(title,256),"description":truncate(message,1800),"color":if state=="resolved"{0x2ea66f}else if state=="opened"{0xf6821f}else{0x4385d5},"fields":fields,"footer":{"text":"EmberGate · Powered by Pingora"}}]}),
    )
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DestinationInput {
    url: String,
    webhook_format: WebhookFormat,
    version: u64,
}
async fn save_destination(
    State(state): State<Shared>,
    Json(input): Json<DestinationInput>,
) -> Result<Json<Value>, Error> {
    if webhook().map_err(error)?.is_some() {
        return Err(error("The environment overrides the webhook URL; remove it and restart before editing it here.".into()));
    }
    validate_destination(&input.url, input.webhook_format).map_err(error)?;
    let result=state.control.run(move|db|{
        let tx=db.transaction().map_err(storage)?;
        let value:Option<String>=tx.query_row("SELECT settings FROM alert_settings WHERE id=1",[],|r|r.get(0)).optional().map_err(storage)?;
        let mut settings:Settings=value.map(|v|serde_json::from_str(&v)).transpose().map_err(|_|"Invalid stored settings.".to_owned())?.unwrap_or_default();
        if settings.version!=input.version{return Err("Alert settings changed. Refresh and try again.".into());}
        settings.webhook_format=input.webhook_format;settings.version+=1;
        tx.execute("INSERT INTO secrets VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",params![DESTINATION,input.url]).map_err(storage)?;
        tx.execute("INSERT INTO alert_settings VALUES(1,?1) ON CONFLICT(id) DO UPDATE SET settings=excluded.settings",params![json!(settings).to_string()]).map_err(storage)?;
        tx.execute("UPDATE outbox SET state='cancelled' WHERE state='pending'",[]).map_err(storage)?;tx.commit().map_err(storage)?;
        Ok(json!({"settings":settings,"configured":true}))
    }).await.map_err(error)?;
    Ok(Json(result))
}
async fn remove_destination(State(state): State<Shared>) -> Result<Json<Value>, Error> {
    if webhook().map_err(error)?.is_some() {
        return Err(error("The environment overrides the webhook URL.".into()));
    }
    state.control.run(|db|{
        let tx=db.transaction().map_err(storage)?;
        let value:Option<String>=tx.query_row("SELECT settings FROM alert_settings WHERE id=1",[],|r|r.get(0)).optional().map_err(storage)?;
        let mut settings:Settings=value.map(|v|serde_json::from_str(&v)).transpose().map_err(|_|"Invalid stored settings.".to_owned())?.unwrap_or_default();
        settings.webhook_enabled=false;settings.version+=1;
        tx.execute("DELETE FROM secrets WHERE key=?1",params![DESTINATION]).map_err(storage)?;
        tx.execute("INSERT INTO alert_settings VALUES(1,?1) ON CONFLICT(id) DO UPDATE SET settings=excluded.settings",params![json!(settings).to_string()]).map_err(storage)?;
        tx.execute("UPDATE outbox SET state='cancelled' WHERE state='pending'",[]).map_err(storage)?;tx.commit().map_err(storage)?;Ok(())
    }).await.map_err(error)?;
    Ok(Json(json!({"configured":false})))
}
async fn settings(state: &Shared) -> Result<Settings, String> {
    state
        .control
        .run(|db| {
            let value: Option<String> = db
                .query_row("SELECT settings FROM alert_settings WHERE id=1", [], |r| {
                    r.get(0)
                })
                .optional()
                .map_err(storage)?;
            match value {
                Some(value) => serde_json::from_str(&value)
                    .map_err(|_| "Invalid alert settings in storage.".into()),
                None => Ok(Settings::default()),
            }
        })
        .await
}
type Error = (StatusCode, Json<Value>);
fn error(message: String) -> Error {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({"error":message})),
    )
}
async fn status(State(state): State<Shared>) -> Result<Json<Value>, Error> {
    let settings = settings(&state).await.map_err(error)?;
    let mut value=state.control.run(|db| {
        let mut query=db.prepare("SELECT id,source,title,message,opened_at,last_seen,resolved_at,acknowledged FROM alerts ORDER BY resolved_at IS NULL DESC,opened_at DESC LIMIT 200").map_err(storage)?;
        let rows=query.query_map([],|r|Ok(json!({"id":r.get::<_,String>(0)?,"source":r.get::<_,String>(1)?,"title":r.get::<_,String>(2)?,"message":r.get::<_,String>(3)?,"opened_at":r.get::<_,u64>(4)?,"last_seen":r.get::<_,u64>(5)?,"resolved_at":r.get::<_,Option<u64>>(6)?,"acknowledged":r.get::<_,bool>(7)?}))).map_err(storage)?.collect::<rusqlite::Result<Vec<_>>>().map_err(storage)?;
        let count:u64=db.query_row("SELECT COUNT(*) FROM alerts WHERE resolved_at IS NULL AND acknowledged=0",[],|r|r.get(0)).map_err(storage)?;
        let mut delivery=db.prepare("SELECT state,COUNT(*) FROM outbox GROUP BY state").map_err(storage)?;
        let states=delivery.query_map([],|r|Ok((r.get::<_,String>(0)?,r.get::<_,u64>(1)?))).map_err(storage)?.collect::<rusqlite::Result<Vec<_>>>().map_err(storage)?;
        Ok(json!({"alerts":rows,"unacknowledged_active":count,"delivery":states.into_iter().collect::<std::collections::HashMap<_,_>>()}))
    }).await.map_err(error)?;
    value["settings"] = json!(settings);
    value["webhook_configured"] = json!(destination(&state).await.map_err(error)?.is_some());
    value["webhook_source"] = json!(if webhook().map_err(error)?.is_some() {
        "environment"
    } else if value["webhook_configured"] == true {
        "database"
    } else {
        "none"
    });
    value["webhook_editable"] = json!(webhook().map_err(error)?.is_none());
    Ok(Json(value))
}
async fn save(
    State(state): State<Shared>,
    Json(mut input): Json<Settings>,
) -> Result<Json<Value>, Error> {
    input.validate().map_err(error)?;
    let environment = webhook().map_err(error)?;
    let result=state.control.run(move|db| {
        let transaction=db.transaction().map_err(storage)?;
        let previous:Option<String>=transaction.query_row("SELECT settings FROM alert_settings WHERE id=1",[],|r|r.get(0)).optional().map_err(storage)?;
        let current:Settings=previous.map(|s|serde_json::from_str(&s)).transpose().map_err(|_|"Invalid stored settings.".to_owned())?.unwrap_or_default();
        if current.version!=input.version {return Err("Alert settings changed. Refresh and try again.".into())}
        let url=match environment {Some(url)=>Some(url),None=>transaction.query_row("SELECT value FROM secrets WHERE key=?1",params![DESTINATION],|r|r.get::<_,String>(0)).optional().map_err(storage)?};
        if let Some(url)=&url{validate_destination(url,input.webhook_format)?;}
        if input.webhook_enabled && url.is_none(){return Err("Save a webhook destination before enabling delivery.".into());}
        input.version+=1;
        transaction.execute("INSERT INTO alert_settings VALUES(1,?1) ON CONFLICT(id) DO UPDATE SET settings=excluded.settings",params![json!(input).to_string()]).map_err(storage)?;
        if !input.webhook_enabled || input.webhook_format!=current.webhook_format {transaction.execute("UPDATE outbox SET state='cancelled' WHERE state='pending'",[]).map_err(storage)?;}
        transaction.commit().map_err(storage)?;Ok(json!({"settings":input}))
    }).await.map_err(error)?;
    Ok(Json(result))
}
async fn acknowledge(
    State(state): State<Shared>,
    Path(id): Path<String>,
) -> Result<Json<Value>, Error> {
    state
        .control
        .run(move |db| {
            if db
                .execute("UPDATE alerts SET acknowledged=1 WHERE id=?1", params![id])
                .map_err(storage)?
                == 0
            {
                return Err("Alert not found.".into());
            }
            Ok(())
        })
        .await
        .map_err(error)?;
    Ok(Json(json!({"ok":true})))
}
fn queue(
    db: &rusqlite::Connection,
    id: Option<&str>,
    event: &str,
    payload: Value,
) -> Result<(), String> {
    db.execute("DELETE FROM outbox WHERE state!='pending' AND id<COALESCE((SELECT id FROM outbox ORDER BY id DESC LIMIT 1 OFFSET 999),0)",[]).map_err(storage)?;
    let count: u64 = db
        .query_row(
            "SELECT COUNT(*) FROM outbox WHERE state='pending'",
            [],
            |r| r.get(0),
        )
        .map_err(storage)?;
    if count >= 1000 {
        return Err("Notification queue is full.".into());
    }
    db.execute("INSERT INTO outbox(alert_id,event,payload,state,next_attempt) VALUES(?1,?2,?3,'pending',?4)",params![id,event,payload.to_string(),now()]).map_err(storage)?;
    Ok(())
}
async fn test(State(state): State<Shared>) -> Result<(StatusCode, Json<Value>), Error> {
    let environment_configured = webhook().map_err(error)?.is_some();
    // Check and enqueue under the same database lock as settings changes.
    state
        .control
        .run(move |db| {
            let value: Option<String> = db
                .query_row("SELECT settings FROM alert_settings WHERE id=1", [], |r| {
                    r.get(0)
                })
                .optional()
                .map_err(storage)?;
            let enabled = value
                .and_then(|v| serde_json::from_str::<Settings>(&v).ok())
                .is_some_and(|s| s.webhook_enabled);
            let configured = environment_configured
                || db
                    .query_row(
                        "SELECT COUNT(*) FROM secrets WHERE key=?1",
                        params![DESTINATION],
                        |r| r.get::<_, u64>(0),
                    )
                    .map_err(storage)?
                    > 0;
            if !enabled || !configured {
                return Err("Enable a configured webhook before sending a test.".into());
            }
            queue(
                db,
                None,
                "test",
                json!({"event":"test","timestamp":now(),"message":"EmberGate notification test"}),
            )
        })
        .await
        .map_err(error)?;
    Ok((StatusCode::ACCEPTED, Json(json!({"ok":true,"queued":true}))))
}
pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/alerts", get(status))
        .route("/api/alerts/settings", axum::routing::put(save))
        .route("/api/alerts/{id}/ack", post(acknowledge))
        .route("/api/alerts/test", post(test))
        .route(
            "/api/alerts/destination",
            axum::routing::put(save_destination).delete(remove_destination),
        )
}
#[derive(Clone)]
struct Condition {
    key: String,
    source: String,
    title: String,
    message: String,
}
fn collect_certificate_conditions(
    status: &Value,
    conditions: &mut Vec<Condition>,
    preserve: &mut HashSet<String>,
) {
    let Some(orders) = status["orders"].as_array() else {
        return;
    };
    for order in orders {
        let Some(id) = order["id"].as_str() else {
            continue;
        };
        let key = format!("certificate:{id}");
        let name = order["name"].as_str().unwrap_or("Certificate");
        let cleanup_failed = order["cleanup_pending"].as_bool() == Some(true)
            && order["last_error"].as_str().is_some();
        if cleanup_failed || order["status"] == "error" {
            conditions.push(Condition {key,source:"certificate".into(),title:if cleanup_failed {"Certificate DNS cleanup failed"}else{"Certificate automation failed"}.into(),message:format!("{name} needs attention. Review issuance, renewal, and DNS cleanup progress in Certificates.")});
        } else if matches!(order["status"].as_str(), Some("queued" | "issuing")) {
            preserve.insert(key);
        }
    }
}
async fn scan(state: &Shared, configured: bool) -> Result<(), String> {
    let current = settings(state).await?;
    let config = state.config.load_full();
    let mut conditions = Vec::new();
    let mut preserve = HashSet::new();
    if current.backend_failures {
        for (id, backends) in state.upstreams.snapshot(&config) {
            for backend in backends {
                let key = format!("backend:{id}:{}", backend.upstream);
                if backend.status == "pending" {
                    preserve.insert(key);
                    continue;
                }
                if backend.status == "unhealthy" {
                    let name = config
                        .routes
                        .iter()
                        .find(|r| r.id == id)
                        .map(|r| r.name.as_str())
                        .unwrap_or("Host");
                    conditions.push(Condition {
                        key,
                        source: "backend".into(),
                        title: "Backend unavailable".into(),
                        message: format!("{name}: {} failed its health checks.", backend.upstream),
                    });
                }
            }
        }
    }
    if current.certificate_failures {
        collect_certificate_conditions(&state.acme.status().await, &mut conditions, &mut preserve);
    }
    match crate::scheduled::problem(state).await {
        Ok(Some(message)) => conditions.push(Condition {
            key: "backup:scheduled".into(),
            source: "backup".into(),
            title: "Scheduled backup needs attention".into(),
            message,
        }),
        Ok(None) => {}
        Err(_) => {
            preserve.insert("backup:scheduled".into());
        }
    }
    if current.error_rate {
        let cutoff = now().saturating_sub(current.window_minutes * 60);
        let (requests, errors) = {
            let metrics = state.metrics.lock().unwrap();
            metrics
                .buckets
                .iter()
                .filter(|b| b.timestamp >= cutoff / 60 * 60)
                .fold((0u64, 0u64), |(r, e), b| (r + b.requests, e + b.errors))
        };
        if requests >= current.minimum_requests
            && errors as f64 * 100. / requests as f64 >= current.error_threshold_percent
        {
            conditions.push(Condition {
                key: "error-rate".into(),
                source: "traffic".into(),
                title: "Elevated error rate".into(),
                message: format!(
                    "{errors} of {requests} requests returned 5xx in the last {} minutes.",
                    current.window_minutes
                ),
            });
        } else if state.started.elapsed() < Duration::from_secs(current.window_minutes * 60)
            && requests < current.minimum_requests
        {
            preserve.insert("error-rate".into());
        }
    }
    state.control.run(move|db| {
        let transaction=db.transaction().map_err(storage)?;
        // Do not apply a scan taken before an administrator changed the settings.
        let version:Option<String>=transaction.query_row("SELECT settings FROM alert_settings WHERE id=1",[],|r|r.get(0)).optional().map_err(storage)?;
        let version=version.and_then(|v|serde_json::from_str::<Settings>(&v).ok()).unwrap_or_default().version;
        if version!=current.version {return Ok(())}
        let delivery=current.webhook_enabled && configured;
        let mut query=transaction.prepare("SELECT id,condition_key,source,title,message,opened_at FROM alerts WHERE resolved_at IS NULL").map_err(storage)?;
        let active=query.query_map([],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,String>(4)?,r.get::<_,u64>(5)?))).map_err(storage)?.collect::<rusqlite::Result<Vec<_>>>().map_err(storage)?;drop(query);
        for condition in &conditions {
            preserve.insert(condition.key.clone());
            if active.iter().any(|a|a.1==condition.key) {transaction.execute("UPDATE alerts SET last_seen=?1 WHERE condition_key=?2 AND resolved_at IS NULL",params![now(),condition.key]).map_err(storage)?;continue}
            let id=uuid::Uuid::new_v4().to_string();
            transaction.execute("INSERT INTO alerts(id,condition_key,source,title,message,opened_at,last_seen) VALUES(?1,?2,?3,?4,?5,?6,?6)",params![id,condition.key,condition.source,condition.title,condition.message,now()]).map_err(storage)?;
            if delivery {if let Err(error)=queue(&transaction,Some(&id),"opened",json!({"event":"opened","timestamp":now(),"alert":{"id":id,"source":condition.source,"title":condition.title,"message":condition.message}})) {log::error!("Could not queue opened notification: {error}");}}
        }
        for (id,key,source,title,message,_) in active {
            if preserve.contains(&key) {continue}
            transaction.execute("UPDATE alerts SET resolved_at=?1,last_seen=?1 WHERE id=?2",params![now(),id]).map_err(storage)?;
            if delivery {if let Err(error)=queue(&transaction,Some(&id),"resolved",json!({"event":"resolved","timestamp":now(),"alert":{"id":id,"source":source,"title":title,"message":message}})) {log::error!("Could not queue recovery notification: {error}");}}
        }
        transaction.execute("DELETE FROM alerts WHERE resolved_at IS NOT NULL AND (resolved_at<?1 OR id IN (SELECT id FROM alerts WHERE resolved_at IS NOT NULL ORDER BY opened_at DESC LIMIT -1 OFFSET 1000))",params![now().saturating_sub(90*86400)]).map_err(storage)?;
        transaction.commit().map_err(storage)?;Ok(())
    }).await
}
async fn deliver(
    state: &Shared,
    client: &reqwest::Client,
    environment: Option<String>,
) -> Result<(), String> {
    let item=state.control.run(move |db| {
        let settings:Option<String>=db.query_row("SELECT settings FROM alert_settings WHERE id=1",[],|r|r.get(0)).optional().map_err(storage)?;
        let settings=settings.and_then(|s|serde_json::from_str::<Settings>(&s).ok()).unwrap_or_default();
        if !settings.webhook_enabled {return Ok(None)}
        let destination=match environment{Some(url)=>Some(url),None=>db.query_row("SELECT value FROM secrets WHERE key=?1",params![DESTINATION],|r|r.get::<_,String>(0)).optional().map_err(storage)?};
        let Some(destination)=destination else{return Ok(None)};
        db.query_row("SELECT id,payload,attempts FROM outbox WHERE state='pending' AND next_attempt<=?1 ORDER BY id LIMIT 1",params![now()],|r|Ok((r.get::<_,i64>(0)?,r.get::<_,String>(1)?,r.get::<_,u32>(2)?,settings.webhook_format,destination.clone()))).optional().map_err(storage)
    }).await?;
    let Some((id, payload, attempts, format, destination)) = item else {
        return Ok(());
    };
    validate_destination(&destination, format)?;
    let mut url = url::Url::parse(&destination).map_err(|_| "Invalid webhook URL.".to_owned())?;
    if format == WebhookFormat::Discord {
        let pairs: Vec<_> = url
            .query_pairs()
            .filter(|(key, _)| key != "wait")
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        url.set_query(None);
        url.query_pairs_mut()
            .extend_pairs(pairs)
            .append_pair("wait", "true");
    }
    let response = client
        .post(url)
        .json(&notification(&payload, format)?)
        .send()
        .await;
    let success = response.as_ref().is_ok_and(|r| r.status().is_success());
    // Honor server rate-limit delays without storing or logging response bodies or webhook URLs.
    let retry_after = response
        .as_ref()
        .ok()
        .filter(|r| r.status() == StatusCode::TOO_MANY_REQUESTS)
        .and_then(|r| r.headers().get("retry-after"))
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<f64>().ok())
        .filter(|v| v.is_finite() && *v >= 0.)
        .map(|v| v.ceil().clamp(1., 86400.) as u64)
        .unwrap_or(0);
    state.control.run(move|db| {
        let attempts=attempts+1;
        db.execute("UPDATE outbox SET state=?1,attempts=?2,next_attempt=?3,error=?4,delivered_at=?5 WHERE id=?6 AND state='pending'",params![if success {"delivered"}else if attempts>=5 {"failed"}else{"pending"},attempts,now()+retry_after.max(30*2u64.pow(attempts-1)),if success {None}else{Some("Webhook delivery failed (network error or non-2xx response).")},if success {Some(now())}else{None},id]).map_err(storage)?;Ok(())
    }).await
}
pub struct Monitor(pub Shared, pub Option<String>);
#[async_trait]
impl BackgroundService for Monitor {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .expect("Alert HTTP client");
        let mut ticker = tokio::time::interval(Duration::from_secs(1));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut ticks = 0u64;
        loop {
            tokio::select! {
                _=shutdown.changed()=>break,
                _=ticker.tick()=>{
                    if self.0.backups.pending.load(std::sync::atomic::Ordering::SeqCst) {continue;}
                    let destination=match &self.1 {Some(url)=>Some(url.clone()),None=>match destination(&self.0).await{Ok(url)=>url,Err(error)=>{log::error!("Alert destination unavailable: {error}");None}}};
                    if ticks%10==0 {if let Err(error)=scan(&self.0,destination.is_some()).await {log::error!("Alert scan failed: {error}");}}
                    if destination.is_some() {if let Err(error)=deliver(&self.0,&client,self.1.clone()).await {log::error!("Alert delivery storage failed: {error}");}}
                    ticks+=1;
                }
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn discord_payload_is_bounded_and_mentions_are_disabled() {
        let original=json!({"event":"resolved","timestamp":123,"alert":{"id":"id","title":"🛠".repeat(300),"message":"@everyone ".repeat(400)}}).to_string();
        let body = notification(&original, WebhookFormat::Discord).unwrap();
        assert_eq!(body["allowed_mentions"]["parse"], json!([]));
        assert!(
            body["embeds"][0]["title"]
                .as_str()
                .unwrap()
                .encode_utf16()
                .count()
                <= 256
        );
        assert!(
            body["embeds"][0]["description"]
                .as_str()
                .unwrap()
                .encode_utf16()
                .count()
                <= 1800
        );
        assert_eq!(body["embeds"][0]["color"], 0x2ea66f);
        assert_eq!(
            notification(&original, WebhookFormat::Generic).unwrap(),
            serde_json::from_str::<Value>(&original).unwrap()
        );
        for url in [
            "https://discord.com/api/webhooks/123/abc_DEF-123",
            "https://discord.com/api/v10/webhooks/123/token?thread_id=456",
            "http://127.0.0.1/test",
        ] {
            assert!(validate_destination(url, WebhookFormat::Discord).is_ok());
        }
        for url in [
            "https://discord.com.evil.test/api/webhooks/123/token",
            "https://discord.com/api/webhooks/no/token",
            "https://discord.com/other",
            "https://discord.com/api/webhooks/123/token?token=secret",
            "https://discord.com/api/webhooks/123/token?thread_id=abc",
        ] {
            assert!(validate_destination(url, WebhookFormat::Discord).is_err());
        }
    }
    #[test]
    fn webhook_security_and_settings_validation() {
        for value in [
            "https://example.com/hook?token=secret",
            "http://127.0.0.1/hook",
            "http://[::1]/hook",
        ] {
            assert!(validate_webhook(value).is_ok())
        }
        for value in [
            "http://example.com/hook",
            "https://user:secret@example.com/hook",
            "ftp://example.com",
            "https://example.com/#secret",
        ] {
            assert!(validate_webhook(value).is_err())
        }
        let mut settings = Settings::default();
        assert!(settings.validate().is_ok());
        settings.minimum_requests = 0;
        assert!(settings.validate().is_err());
    }
    #[test]
    fn certificate_errors_open_alerts_retries_preserve_them_and_ready_resolves() {
        let mut conditions = Vec::new();
        let mut preserve = HashSet::new();
        collect_certificate_conditions(
            &json!({"orders":[
                {"id":"failure","name":"Public cert","status":"error","last_error":"token=secret-dns-credential"},
                {"id":"retry","status":"queued"}, {"id":"issuing","status":"issuing"},
                {"id":"ready","status":"ready"},
                {"id":"cleanup","status":"ready","cleanup_pending":true,"last_error":"private API error"}
            ]}),
            &mut conditions,
            &mut preserve,
        );
        assert_eq!(conditions.len(), 2);
        assert_eq!(conditions[0].key, "certificate:failure");
        assert_eq!(conditions[1].key, "certificate:cleanup");
        assert!(!conditions
            .iter()
            .any(|c| c.message.contains("secret-dns-credential")
                || c.message.contains("private API error")));
        assert!(preserve.contains("certificate:retry"));
        assert!(preserve.contains("certificate:issuing"));
        assert!(!preserve.contains("certificate:ready"));
    }
}

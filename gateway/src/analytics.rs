//! Bounded durable analytics. SQLite runs on its own thread, off Pingora's workers.
use crate::state::{now, AccessLog};
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use std::{path::Path, time::Duration};
use tokio::sync::{mpsc, oneshot};

pub const SCHEMA: &str = "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS logs(id INTEGER PRIMARY KEY, timestamp INTEGER NOT NULL, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS hours(bucket INTEGER NOT NULL, route_id TEXT NOT NULL, name TEXT NOT NULL,
                requests INTEGER NOT NULL, errors INTEGER NOT NULL, limited INTEGER NOT NULL, denied INTEGER NOT NULL,
                latency REAL NOT NULL, PRIMARY KEY(bucket,route_id));
            CREATE TABLE IF NOT EXISTS codes(bucket INTEGER NOT NULL,route_id TEXT NOT NULL,code INTEGER NOT NULL,
                count INTEGER NOT NULL,PRIMARY KEY(bucket,route_id,code));";

#[derive(Clone)]
pub struct Analytics {
    sender: mpsc::Sender<Command>,
}
enum Command {
    Record(AccessLog),
    Query {
        hours: u64,
        route: Option<String>,
        logs_only: bool,
        reply: oneshot::Sender<Result<Value, String>>,
    },
}
impl Analytics {
    pub fn open(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(path)?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        let connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch(SCHEMA)?;
        prune(&connection)?;
        let (sender, receiver) = mpsc::channel(4096);
        std::thread::Builder::new()
            .name("gateway-analytics".into())
            .spawn(move || worker(connection, receiver))?;
        Ok(Self { sender })
    }
    pub async fn record(&self, entry: AccessLog) {
        // Backpressure preserves records rather than silently dropping them under load.
        if self.sender.send(Command::Record(entry)).await.is_err() {
            log::error!("Analytics writer unavailable");
        }
    }
    pub async fn query(
        &self,
        hours: u64,
        route: Option<String>,
        logs_only: bool,
    ) -> Result<Value, String> {
        let (reply, response) = oneshot::channel();
        tokio::time::timeout(Duration::from_secs(5), async {
            self.sender
                .send(Command::Query {
                    hours,
                    route,
                    logs_only,
                    reply,
                })
                .await
                .map_err(|_| "Analytics unavailable".to_owned())?;
            response
                .await
                .map_err(|_| "Analytics unavailable".to_owned())?
        })
        .await
        .map_err(|_| "Analytics query timed out. Check gateway storage.".to_owned())?
    }
}
fn prune(db: &Connection) -> rusqlite::Result<()> {
    let oldest = (now() / 3600).saturating_sub(719) * 3600;
    db.execute("DELETE FROM logs WHERE timestamp < ?1 OR id < COALESCE((SELECT id FROM logs ORDER BY id DESC LIMIT 1 OFFSET 9999),0)",params![oldest])?;
    db.execute("DELETE FROM hours WHERE bucket < ?1", params![oldest])?;
    db.execute("DELETE FROM codes WHERE bucket < ?1", params![oldest])?;
    Ok(())
}
fn persist(db: &mut Connection, records: &[AccessLog]) -> rusqlite::Result<()> {
    let transaction = db.transaction()?;
    for entry in records {
        let route = entry.route_id.as_deref().unwrap_or("");
        transaction.execute(
            "INSERT INTO logs(timestamp,payload) VALUES (?1,?2)",
            params![entry.timestamp, serde_json::to_string(entry).unwrap()],
        )?;
        transaction.execute("INSERT INTO hours(bucket,route_id,name,requests,errors,limited,denied,latency)
            VALUES (?1,?2,?3,1,?4,?5,?6,?7) ON CONFLICT(bucket,route_id) DO UPDATE SET
            name=excluded.name, requests=requests+1,errors=errors+excluded.errors,limited=limited+excluded.limited,
            denied=denied+excluded.denied,latency=latency+excluded.latency",
            params![entry.timestamp/3600*3600,route,entry.route.as_deref().unwrap_or("Unmatched requests"),entry.status>=500,entry.rate_limited,entry.access_denied,entry.latency_ms])?;
        transaction.execute(
            "INSERT INTO codes(bucket,route_id,code,count) VALUES (?1,?2,?3,1)
            ON CONFLICT(bucket,route_id,code) DO UPDATE SET count=count+1",
            params![entry.timestamp / 3600 * 3600, route, entry.status],
        )?;
    }
    // Bound recent request storage even during sustained traffic.
    transaction.execute("DELETE FROM logs WHERE id < COALESCE((SELECT id FROM logs ORDER BY id DESC LIMIT 1 OFFSET 9999),0)",[])?;
    transaction.commit()
}
fn worker(mut db: Connection, mut receiver: mpsc::Receiver<Command>) {
    let mut pending = None;
    let mut last_prune = now();
    loop {
        let Some(command) = pending.take().or_else(|| receiver.blocking_recv()) else {
            break;
        };
        match command {
            Command::Record(entry) => {
                let mut batch = vec![entry];
                while batch.len() < 256 {
                    match receiver.try_recv() {
                        Ok(Command::Record(entry)) => batch.push(entry),
                        Ok(other) => {
                            pending = Some(other);
                            break;
                        }
                        Err(_) => break,
                    }
                }
                // Retry transient I/O failures with bounded queue backpressure. Do not discard accepted records.
                while let Err(error) = persist(&mut db, &batch) {
                    log::error!("Analytics write failed; retrying: {error}");
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
            Command::Query {
                hours,
                route,
                logs_only,
                reply,
            } => {
                let result = if logs_only {
                    recent(&db)
                } else {
                    history(&db, hours, route.as_deref())
                };
                let _ = reply.send(result.map_err(|error| {
                    log::error!("Analytics read failed: {error}");
                    "Could not read analytics.".into()
                }));
            }
        }
        if now().saturating_sub(last_prune) >= 60 {
            if let Err(error) = prune(&db) {
                log::error!("Analytics retention cleanup failed: {error}");
            }
            last_prune = now();
        }
    }
    let _ = db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)");
}
fn recent(db: &Connection) -> rusqlite::Result<Value> {
    let mut statement =
        db.prepare("SELECT payload FROM logs WHERE timestamp>=?1 ORDER BY id DESC LIMIT 200")?;
    let rows = statement.query_map(params![now().saturating_sub(30 * 86400)], |row| {
        row.get::<_, String>(0)
    })?;
    let mut logs = vec![];
    for row in rows {
        if let Ok(value) = serde_json::from_str::<Value>(&row?) {
            logs.push(value);
        }
    }
    Ok(json!({"logs":logs}))
}
fn history(db: &Connection, hours: u64, route: Option<&str>) -> rusqlite::Result<Value> {
    let hours = hours.clamp(1, 720);
    let end = now() / 3600 * 3600;
    let since = end.saturating_sub((hours - 1) * 3600);
    let route = route.map(|r| if r == "unmatched" { "" } else { r });
    let totals=db.query_row("SELECT COALESCE(SUM(requests),0),COALESCE(SUM(errors),0),COALESCE(SUM(limited),0),
        COALESCE(SUM(denied),0),COALESCE(SUM(latency),0) FROM hours WHERE bucket>=?1 AND (?2 IS NULL OR route_id=?2)",params![since,route],|row| {
        let requests=row.get::<_,u64>(0)?;
        Ok(json!({"requests":requests,"errors":row.get::<_,u64>(1)?,"rate_limited":row.get::<_,u64>(2)?,
            "access_denied":row.get::<_,u64>(3)?,"avg_latency_ms":if requests>0 {row.get::<_,f64>(4)?/requests as f64}else{0.0}}))
    })?;
    let mut statement=db.prepare("SELECT bucket,SUM(requests),SUM(errors) FROM hours WHERE bucket>=?1 AND (?2 IS NULL OR route_id=?2) GROUP BY bucket")?;
    let rows = statement.query_map(params![since, route], |row| {
        Ok((
            row.get::<_, u64>(0)?,
            row.get::<_, u64>(1)?,
            row.get::<_, u64>(2)?,
        ))
    })?;
    let mut existing = std::collections::HashMap::new();
    for row in rows {
        let (time, requests, errors) = row?;
        existing.insert(time, (requests, errors));
    }
    let buckets: Vec<_> = (0..hours)
        .map(|i| {
            let time = since + i * 3600;
            let (requests, errors) = existing.get(&time).copied().unwrap_or_default();
            json!({"timestamp":time,"requests":requests,"errors":errors})
        })
        .collect();
    let mut statement=db.prepare("SELECT route_id,MAX(name),SUM(requests),SUM(errors),SUM(limited),SUM(denied) FROM hours WHERE bucket>=?1 GROUP BY route_id ORDER BY SUM(requests) DESC LIMIT 1000")?;
    let rows=statement.query_map(params![since],|row|Ok(json!({"route_id":row.get::<_,String>(0)?,"name":row.get::<_,String>(1)?,"requests":row.get::<_,u64>(2)?,"errors":row.get::<_,u64>(3)?,"rate_limited":row.get::<_,u64>(4)?,"access_denied":row.get::<_,u64>(5)?})))?;
    let hosts: Vec<_> = rows.collect::<rusqlite::Result<_>>()?;
    let mut statement=db.prepare("SELECT code,SUM(count) FROM codes WHERE bucket>=?1 AND (?2 IS NULL OR route_id=?2) GROUP BY code ORDER BY code")?;
    let rows = statement.query_map(params![since, route], |row| {
        Ok(json!({"status":row.get::<_,u16>(0)?,"requests":row.get::<_,u64>(1)?}))
    })?;
    let codes: Vec<_> = rows.collect::<rusqlite::Result<_>>()?;
    Ok(
        json!({"hours":hours,"retention_days":30,"totals":totals,"buckets":buckets,"hosts":hosts,"status_codes":codes}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn entry(route: &str, status: u16) -> AccessLog {
        AccessLog {
            timestamp: now(),
            route_id: Some(route.into()),
            route: Some("Test".into()),
            client_ip: Some("203.0.113.5".into()),
            peer_ip: Some("127.0.0.1".into()),
            identity_source: "cloudflare".into(),
            access_denied: status == 403,
            crowdsec_blocked: false,
            maintenance: false,
            rate_limited: status == 429,
            method: "GET".into(),
            host: "app.test".into(),
            path: "/safe".into(),
            upstream: None,
            attempted_upstreams: vec![],
            status,
            cache_status: "OFF".into(),
            latency_ms: 2.0,
        }
    }
    #[tokio::test]
    async fn durable_aggregates_filter_by_route_and_survive_reopen() {
        let path =
            std::env::temp_dir().join(format!("analytics-test-{}.sqlite3", uuid::Uuid::new_v4()));
        let analytics = Analytics::open(&path).unwrap();
        analytics.record(entry("one", 200)).await;
        analytics.record(entry("one", 429)).await;
        analytics.record(entry("two", 403)).await;
        let value = analytics.query(24, None, false).await.unwrap();
        assert_eq!(value["totals"]["requests"], 3);
        assert_eq!(value["totals"]["rate_limited"], 1);
        assert_eq!(value["buckets"].as_array().unwrap().len(), 24);
        assert_eq!(
            analytics
                .query(24, Some("two".into()), false)
                .await
                .unwrap()["totals"]["access_denied"],
            1
        );
        let reopened = Analytics::open(&path).unwrap();
        assert_eq!(
            reopened.query(720, None, false).await.unwrap()["totals"]["requests"],
            3
        );
        assert_eq!(
            reopened.query(24, None, true).await.unwrap()["logs"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        drop(analytics);
        drop(reopened);
        // The writer owns its SQLite connection until its channel closes.
        tokio::time::sleep(Duration::from_millis(30)).await;
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }
    #[test]
    fn retention_removes_old_rows_and_bounds_recent_logs() {
        let mut db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE logs(id INTEGER PRIMARY KEY,timestamp INTEGER,payload TEXT);CREATE TABLE hours(bucket INTEGER,route_id TEXT,name TEXT,requests INTEGER,errors INTEGER,limited INTEGER,denied INTEGER,latency REAL,PRIMARY KEY(bucket,route_id));CREATE TABLE codes(bucket INTEGER,route_id TEXT,code INTEGER,count INTEGER,PRIMARY KEY(bucket,route_id,code));").unwrap();
        let mut old = entry("old", 500);
        old.timestamp = now() - 31 * 86400;
        persist(&mut db, &[old, entry("new", 200)]).unwrap();
        prune(&db).unwrap();
        assert_eq!(history(&db, 720, None).unwrap()["totals"]["requests"], 1);
        let transaction = db.transaction().unwrap();
        for _ in 0..10010 {
            transaction
                .execute(
                    "INSERT INTO logs(timestamp,payload) VALUES (?1,'{}')",
                    params![now()],
                )
                .unwrap();
        }
        transaction.commit().unwrap();
        prune(&db).unwrap();
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM logs", [], |row| row.get::<_, u64>(0))
                .unwrap(),
            10000
        );
    }
}

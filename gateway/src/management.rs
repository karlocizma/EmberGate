//! Durable accounts, audit intents, and notification state. Secrets stay server-side.
use crate::state::now;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Administrator,
    ReadOnly,
}
impl Role {
    pub fn admin(&self) -> bool {
        *self == Self::Administrator
    }
    pub fn as_str(&self) -> &'static str {
        if self.admin() {
            "administrator"
        } else {
            "read_only"
        }
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub role: Role,
    pub enabled: bool,
    pub version: u64,
    pub managed: bool,
}
pub const SCHEMA: &str = "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS secrets(key TEXT PRIMARY KEY,value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,username TEXT NOT NULL UNIQUE,password_hash TEXT NOT NULL,role TEXT NOT NULL,enabled INTEGER NOT NULL,version INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,timestamp INTEGER NOT NULL,actor TEXT NOT NULL,method TEXT NOT NULL,path TEXT NOT NULL,target TEXT,phase TEXT NOT NULL,status INTEGER NOT NULL,details TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS alert_settings(id INTEGER PRIMARY KEY CHECK(id=1),settings TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS alerts(id TEXT PRIMARY KEY,condition_key TEXT NOT NULL,source TEXT NOT NULL,title TEXT NOT NULL,message TEXT NOT NULL,opened_at INTEGER NOT NULL,last_seen INTEGER NOT NULL,resolved_at INTEGER,acknowledged INTEGER NOT NULL DEFAULT 0);
            CREATE UNIQUE INDEX IF NOT EXISTS active_alert_key ON alerts(condition_key) WHERE resolved_at IS NULL;
            CREATE TABLE IF NOT EXISTS outbox(id INTEGER PRIMARY KEY,alert_id TEXT,event TEXT NOT NULL,payload TEXT NOT NULL,state TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,next_attempt INTEGER NOT NULL,error TEXT,delivered_at INTEGER);";

#[derive(Clone)]
pub struct Credentials {
    pub user: User,
    pub hash: String,
}
#[derive(Clone)]
pub struct Control {
    db: Arc<Mutex<Connection>>,
}
#[derive(Clone, Serialize)]
pub struct AuditActor {
    pub user_id: String,
    pub username: String,
    pub role: String,
    pub peer: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}
#[derive(Clone)]
pub struct AuditExtra(pub String);
#[derive(Clone)]
pub struct AuditDetails(pub Value);
impl Control {
    pub async fn snapshot(&self, path: std::path::PathBuf) -> Result<(), String> {
        self.run(move |db| crate::backup::snapshot_db(db, &path))
            .await
    }

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
        let db = Connection::open(path)?;
        db.busy_timeout(Duration::from_secs(5))?;
        db.execute_batch(SCHEMA)?;
        Ok(Self {
            db: Arc::new(Mutex::new(db)),
        })
    }
    pub fn secret(&self, key: &str) -> Result<Option<String>, String> {
        self.db
            .lock()
            .map_err(|_| "Management storage unavailable.")?
            .query_row(
                "SELECT value FROM secrets WHERE key=?1",
                params![key],
                |r| r.get(0),
            )
            .optional()
            .map_err(storage)
    }
    /// Writes a secret synchronously, for startup before the runtime serves requests.
    pub fn store_secret(&self, key: &str, value: &str) -> Result<(), String> {
        self.db
            .lock()
            .map_err(|_| "Management storage unavailable.")?
            .execute("INSERT INTO secrets VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value", params![key, value])
            .map_err(storage)?;
        Ok(())
    }
    pub fn admin_exists(&self) -> Result<bool, String> {
        self.db
            .lock()
            .map_err(|_| "Management storage unavailable.")?
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM users WHERE id='bootstrap')",
                [],
                |r| r.get(0),
            )
            .map_err(storage)
    }
    pub fn seed_admin(&self, hash: &str) -> Result<(), String> {
        let mut guard = self
            .db
            .lock()
            .map_err(|_| "Management storage unavailable.")?;
        initialize_admin(&mut guard, hash, "startup")?;
        Ok(())
    }
    pub async fn set_secret(&self, key: String, value: Option<String>) -> Result<(), String> {
        self.run(move|db| {
            match value {
                Some(value)=>{db.execute("INSERT INTO secrets VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",params![key,value]).map_err(storage)?;},
                None=>{db.execute("DELETE FROM secrets WHERE key=?1",params![key]).map_err(storage)?;}
            }
            Ok(())
        }).await
    }
    pub async fn run<T, F>(&self, action: F) -> Result<T, String>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T, String> + Send + 'static,
    {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || {
            let mut guard = db.lock().map_err(|_| "Management storage unavailable.")?;
            action(&mut guard)
        })
        .await
        .map_err(|_| "Management storage unavailable.".to_owned())?
    }
    pub async fn users(&self) -> Result<Vec<User>, String> {
        self.run(|db| {
            let mut query = db
                .prepare("SELECT id,username,role,enabled,version FROM users ORDER BY username")
                .map_err(storage)?;
            let rows = query.query_map([], user_row).map_err(storage)?;
            rows.collect::<rusqlite::Result<Vec<_>>>().map_err(storage)
        })
        .await
    }
    pub async fn credentials(&self, username: String) -> Result<Option<Credentials>, String> {
        self.run(move|db| {
        db.query_row("SELECT id,username,role,enabled,version,password_hash FROM users WHERE username=?1",params![username],|row|Ok(Credentials {user:user_row(row)?,hash:row.get(5)?})).optional().map_err(storage)
    }).await
    }
    pub async fn create_user(
        &self,
        username: String,
        hash: String,
        role: Role,
    ) -> Result<User, String> {
        self.run(move|db| {
        let count:u64=db.query_row("SELECT COUNT(*) FROM users WHERE id!='bootstrap'",[],|r|r.get(0)).map_err(storage)?;
        if count>=50 {return Err("A maximum of 50 managed accounts is supported.".into())}
        let user=User {id:uuid::Uuid::new_v4().to_string(),username,role,enabled:true,version:1,managed:true};
        db.execute("INSERT INTO users VALUES (?1,?2,?3,?4,1,1)",params![user.id,user.username,hash,user.role.as_str()]).map_err(|error|if matches!(error,rusqlite::Error::SqliteFailure(ref e,_) if e.code==rusqlite::ErrorCode::ConstraintViolation) {"That username is already in use.".into()}else{storage(error)})?;
        Ok(user)
    }).await
    }
    pub async fn update_user(
        &self,
        id: String,
        username: String,
        role: Role,
        enabled: bool,
        version: u64,
        hash: Option<String>,
    ) -> Result<User, String> {
        self.run(move|db| {
        let changed=db.execute("UPDATE users SET username=?1,role=?2,enabled=?3,password_hash=COALESCE(?4,password_hash),version=version+1 WHERE id=?5 AND version=?6",params![username,role.as_str(),enabled,hash,id,version]).map_err(|error|if matches!(error,rusqlite::Error::SqliteFailure(ref e,_) if e.code==rusqlite::ErrorCode::ConstraintViolation) {"That username is already in use.".into()}else{storage(error)})?;
        if changed!=1 {return Err("Account changed or was removed. Refresh and try again.".into())}
        Ok(User {id,username,role,enabled,version:version+1,managed:true})
    }).await
    }
    pub async fn delete_user(&self, id: String) -> Result<(), String> {
        self.run(move |db| {
            let tx = db.transaction().map_err(storage)?;
            if tx
                .execute("DELETE FROM users WHERE id=?1", params![id])
                .map_err(storage)?
                == 0
            {
                return Err("Account not found.".into());
            }
            tx.execute(
                "DELETE FROM secrets WHERE key=?1 OR key=?2",
                params![format!("mfa:{id}"), format!("passkeys:{id}")],
            )
            .map_err(storage)?;
            crate::tokens::delete_for_user(&tx, &id)?;
            tx.commit().map_err(storage)?;
            Ok(())
        })
        .await
    }
    pub async fn begin_audit(
        &self,
        actor: AuditActor,
        method: String,
        path: String,
        details: Value,
    ) -> Result<i64, String> {
        self.run(move|db| {
        db.execute("INSERT INTO audit(timestamp,actor,method,path,phase,status,details) VALUES (?1,?2,?3,?4,'pending',0,?5)",params![now(),serde_json::to_string(&actor).unwrap(),method,path,details.to_string()]).map_err(storage)?;
        let id=db.last_insert_rowid();
        db.execute("DELETE FROM audit WHERE timestamp<?1 OR id<COALESCE((SELECT id FROM audit ORDER BY id DESC LIMIT 1 OFFSET 9999),0)",params![now().saturating_sub(90*86400)]).map_err(storage)?;
        Ok(id)
    }).await
    }
    pub async fn finish_audit(
        &self,
        id: i64,
        status: u16,
        target: Option<String>,
        details: Value,
        actor: Option<AuditActor>,
    ) -> Result<(), String> {
        self.run(move|db| {
        db.execute("UPDATE audit SET phase=?1,status=?2,target=?3,details=?4,actor=COALESCE(?5,actor) WHERE id=?6",params![if status<400 {"success"}else{"failed"},status,target,details.to_string(),actor.map(|a|serde_json::to_string(&a).unwrap()),id]).map_err(storage)?;Ok(())
    }).await
    }
    pub async fn audit(&self) -> Result<Value, String> {
        self.run(|db| {
        let mut query=db.prepare("SELECT id,timestamp,actor,method,path,target,phase,status,details FROM audit ORDER BY id DESC LIMIT 200").map_err(storage)?;
        let rows=query.query_map([],|row|Ok(json!({"id":row.get::<_,i64>(0)?,"timestamp":row.get::<_,u64>(1)?,"actor":serde_json::from_str::<Value>(&row.get::<_,String>(2)?).unwrap_or(Value::Null),"method":row.get::<_,String>(3)?,"path":row.get::<_,String>(4)?,"target":row.get::<_,Option<String>>(5)?,"phase":row.get::<_,String>(6)?,"status":row.get::<_,u16>(7)?,"details":serde_json::from_str::<Value>(&row.get::<_,String>(8)?).unwrap_or(Value::Null)}))).map_err(storage)?;
        Ok(json!({"events":rows.collect::<rusqlite::Result<Vec<_>>>().map_err(storage)?,"retention_days":90}))
    }).await
    }
}
fn user_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<User> {
    Ok(User {
        id: row.get(0)?,
        username: row.get(1)?,
        role: if row.get::<_, String>(2)? == "administrator" {
            Role::Administrator
        } else {
            Role::ReadOnly
        },
        enabled: row.get(3)?,
        version: row.get(4)?,
        managed: row.get::<_, String>(0)? != "bootstrap",
    })
}
pub fn initialize_admin(db: &mut Connection, hash: &str, peer: &str) -> Result<bool, String> {
    let transaction = db.transaction().map_err(storage)?;
    let changed = transaction
        .execute(
            "INSERT OR IGNORE INTO users VALUES('bootstrap','admin',?1,'administrator',1,1)",
            params![hash],
        )
        .map_err(storage)?;
    if changed == 1 {
        let actor = AuditActor {
            user_id: "bootstrap".into(),
            username: "admin".into(),
            role: "administrator".into(),
            peer: peer.into(),
            token: None,
        };
        transaction.execute("INSERT INTO audit(timestamp,actor,method,path,target,phase,status,details) VALUES(?1,?2,'POST','/api/setup','bootstrap','success',201,'{}')",params![now(),json!(actor).to_string()]).map_err(storage)?;
    }
    transaction.commit().map_err(storage)?;
    Ok(changed == 1)
}
pub fn bootstrap() -> User {
    User {
        id: "bootstrap".into(),
        username: "admin".into(),
        role: Role::Administrator,
        enabled: true,
        version: 0,
        managed: false,
    }
}
pub fn username(value: &str) -> Result<String, String> {
    let name = value.trim().to_ascii_lowercase();
    // Email addresses are allowed so accounts can match single sign-on identities.
    if !(3..=64).contains(&name.len())
        || !name
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"._-@+".contains(&c))
    {
        return Err(
            "Usernames require 3–64 letters, digits, dots, underscores, hyphens, @, or +.".into(),
        );
    }
    Ok(name)
}
pub fn password(value: &str) -> Result<(), String> {
    if value.chars().count() < 12 || value.len() > 1024 {
        Err("Passwords require 12–1024 characters.".into())
    } else {
        Ok(())
    }
}
pub async fn hash_password(value: String) -> Result<String, String> {
    password(&value)?;
    tokio::task::spawn_blocking(move || {
        use argon2::{password_hash::SaltString, PasswordHasher};
        argon2::Argon2::default()
            .hash_password(value.as_bytes(), &SaltString::generate(rand_core::OsRng))
            .map(|hash| hash.to_string())
            .map_err(|_| "Could not hash password.".into())
    })
    .await
    .map_err(|_| "Could not hash password.".to_owned())?
}
pub async fn verify_password(value: String, hash: String) -> bool {
    if value.len() > 1024 {
        return false;
    }
    tokio::task::spawn_blocking(move || {
        use argon2::PasswordVerifier;
        argon2::password_hash::PasswordHash::new(&hash)
            .ok()
            .is_some_and(|hash| {
                argon2::Argon2::default()
                    .verify_password(value.as_bytes(), &hash)
                    .is_ok()
            })
    })
    .await
    .unwrap_or(false)
}
pub fn storage(error: rusqlite::Error) -> String {
    log::error!("Management storage error: {error}");
    "Management storage unavailable.".into()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn durable_accounts_conflicts_and_audit_redaction() {
        let path =
            std::env::temp_dir().join(format!("management-{}.sqlite3", uuid::Uuid::new_v4()));
        let control = Control::open(&path).unwrap();
        assert_eq!(username(" Reader ").unwrap(), "reader");
        assert!(username("bad/name").is_err());
        assert!(password("short").is_err());
        let hash = hash_password("test-password-secret".into()).await.unwrap();
        assert!(verify_password("test-password-secret".into(), hash.clone()).await);
        let user = control
            .create_user("reader".into(), hash.clone(), Role::ReadOnly)
            .await
            .unwrap();
        assert!(!json!(user).to_string().contains(&hash));
        let updated = control
            .update_user(
                user.id.clone(),
                user.username.clone(),
                Role::Administrator,
                false,
                user.version,
                None,
            )
            .await
            .unwrap();
        assert!(control
            .update_user(
                user.id.clone(),
                user.username,
                Role::ReadOnly,
                true,
                user.version,
                None
            )
            .await
            .is_err());
        let audit = control
            .begin_audit(
                AuditActor {
                    user_id: updated.id.clone(),
                    username: "reader".into(),
                    role: "administrator".into(),
                    peer: "127.0.0.1".into(),
                    token: None,
                },
                "PUT".into(),
                "/api/config".into(),
                json!({"configuration_version":3}),
            )
            .await
            .unwrap();
        assert_eq!(
            control.audit().await.unwrap()["events"][0]["phase"],
            "pending"
        );
        control
            .finish_audit(
                audit,
                200,
                None,
                json!({"configuration_version_after":4}),
                None,
            )
            .await
            .unwrap();
        drop(control);
        let control = Control::open(&path).unwrap();
        assert!(
            !control
                .credentials("reader".into())
                .await
                .unwrap()
                .unwrap()
                .user
                .enabled
        );
        assert_eq!(
            control.audit().await.unwrap()["events"][0]["phase"],
            "success"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        drop(control);
        let _ = std::fs::remove_file(path);
    }
}

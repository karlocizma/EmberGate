//! Per-session request serialization: holds concurrent requests from the same
//! browser session to a route behind a per-(route, session) lock, so a login
//! response and a racing WebSocket reconnect from the same client can never
//! land out of order at the upstream. Different clients stay fully parallel.
use std::{
    collections::HashMap,
    hash::{Hash, Hasher},
    sync::{Arc, Mutex, Weak},
};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

#[derive(Default)]
pub struct SessionLocks {
    locks: Mutex<HashMap<(String, u64), Weak<AsyncMutex<()>>>>,
}

impl SessionLocks {
    pub async fn acquire(&self, route_id: &str, key: u64) -> OwnedMutexGuard<()> {
        let lock = {
            let mut locks = self.locks.lock().unwrap();
            locks.retain(|_, weak| weak.strong_count() > 0);
            match locks
                .get(&(route_id.to_owned(), key))
                .and_then(Weak::upgrade)
            {
                Some(lock) => lock,
                None => {
                    let lock = Arc::new(AsyncMutex::new(()));
                    locks.insert((route_id.to_owned(), key), Arc::downgrade(&lock));
                    lock
                }
            }
        };
        lock.lock_owned().await
    }
}

/// A stable key identifying the browser session making this request: the raw
/// Cookie header if present (so unrelated users on the same route never
/// contend), falling back to the client address.
pub fn session_key(headers: &pingora::http::RequestHeader, client: Option<std::net::IpAddr>) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    match headers.headers.get("cookie").and_then(|v| v.to_str().ok()) {
        Some(cookie) if !cookie.is_empty() => cookie.hash(&mut hasher),
        _ => client.hash(&mut hasher),
    }
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn same_key_serializes_and_different_keys_do_not_block() {
        let locks = SessionLocks::default();
        let first = locks.acquire("route", 1).await;
        let locks = Arc::new(locks);
        let other_key = locks.acquire("route", 2).await;
        drop(other_key);
        let locks2 = locks.clone();
        let waiting = tokio::spawn(async move {
            let _second = locks2.acquire("route", 1).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(!waiting.is_finished());
        drop(first);
        waiting.await.unwrap();
    }
}

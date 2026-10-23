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

pub const LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

#[derive(Default)]
pub struct SessionLocks {
    locks: Mutex<HashMap<(String, u64), Weak<AsyncMutex<()>>>>,
}

impl SessionLocks {
    /// Waits for the session lock, giving up after `LOCK_WAIT` so one stuck
    /// request cannot stall the rest of its session indefinitely.
    pub async fn acquire_timeout(&self, route_id: &str, key: u64) -> Option<OwnedMutexGuard<()>> {
        tokio::time::timeout(LOCK_WAIT, self.acquire(route_id, key))
            .await
            .ok()
    }

    async fn acquire(&self, route_id: &str, key: u64) -> OwnedMutexGuard<()> {
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
/// Cookie header. Requests without cookies have no session to order, so they
/// return `None` and are never serialized (an IP fallback would make clients
/// behind one NAT block each other).
pub fn session_key(headers: &pingora::http::RequestHeader) -> Option<u64> {
    let cookie = headers.headers.get("cookie")?.to_str().ok()?;
    if cookie.is_empty() {
        return None;
    }
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    cookie.hash(&mut hasher);
    Some(hasher.finish())
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

    #[tokio::test(start_paused = true)]
    async fn waiting_times_out_while_the_lock_is_held() {
        let locks = SessionLocks::default();
        let _held = locks.acquire_timeout("route", 1).await.unwrap();
        assert!(locks.acquire_timeout("route", 1).await.is_none());
        assert!(locks.acquire_timeout("route", 2).await.is_some());
    }

    #[test]
    fn requests_without_cookies_have_no_session_key() {
        let mut header = pingora::http::RequestHeader::build("GET", b"/", None).unwrap();
        assert!(session_key(&header).is_none());
        header.insert_header("cookie", "").unwrap();
        assert!(session_key(&header).is_none());
        header.insert_header("cookie", "sid=1").unwrap();
        assert!(session_key(&header).is_some());
    }
}

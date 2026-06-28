//! Redis [`KvStore`] for cross-node session sharing (DESIGN §8 v3).
//!
//! Stores each session's serialized vault under its (tenant-namespaced) key with
//! a TTL, so any node can rehydrate a session started elsewhere. Secrets are held
//! in Redis only for the session's lifetime — run Redis with AUTH + TLS, and
//! consider value encryption, for production (see DESIGN §7).

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use redis::aio::ConnectionManager;

use crate::session::KvStore;

/// A Redis-backed key/value store using a multiplexed connection manager.
pub struct RedisKv {
    conn: ConnectionManager,
}

impl RedisKv {
    /// Connect to Redis at `url` (e.g. `redis://127.0.0.1/`).
    pub async fn connect(url: &str) -> anyhow::Result<Arc<Self>> {
        let client = redis::Client::open(url)?;
        let conn = ConnectionManager::new(client).await?;
        Ok(Arc::new(Self { conn }))
    }
}

#[async_trait]
impl KvStore for RedisKv {
    async fn hgetall(&self, key: &str) -> Vec<(String, Vec<u8>)> {
        let mut conn = self.conn.clone();
        redis::cmd("HGETALL")
            .arg(key)
            .query_async::<Vec<(String, Vec<u8>)>>(&mut conn)
            .await
            .unwrap_or_default()
    }

    async fn hset_with_ttl(&self, key: &str, fields: &[(String, Vec<u8>)], ttl: Duration) {
        let mut conn = self.conn.clone();
        // HSET the (disjoint, per-node) fields then refresh the TTL. Concurrent
        // commits from other nodes touch different fields, so they don't clobber.
        let mut hset = redis::cmd("HSET");
        hset.arg(key);
        for (field, value) in fields {
            hset.arg(field).arg(value);
        }
        let mut pipe = redis::pipe();
        pipe.add_command(hset)
            .ignore()
            .cmd("EXPIRE")
            .arg(key)
            .arg(ttl.as_secs().max(1))
            .ignore();
        if let Err(e) = pipe.query_async::<()>(&mut conn).await {
            tracing::warn!(error = %e, "redis HSET/EXPIRE failed; session entries not persisted");
        }
    }
}

//! Fixed-window rate limits: per client IP for unauthenticated endpoints,
//! per session token for authenticated ones (devices and admins).
//!
//! Behind a reverse proxy every request shares the proxy's address, so the
//! proxy must enforce its own per-client limit as well. New sessions can only
//! be created at the per-IP rate, so cycling tokens does not lift the limit.

use std::collections::HashMap;
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::header::AUTHORIZATION;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::error::ApiError;

pub struct RateLimiter<K = IpAddr> {
    limit: u32,
    window: Duration,
    hits: Mutex<HashMap<K, (Instant, u32)>>,
}

impl<K: Eq + Hash> RateLimiter<K> {
    pub fn new(limit: u32, window: Duration) -> Arc<Self> {
        Arc::new(Self { limit, window, hits: Mutex::new(HashMap::new()) })
    }

    fn allow(&self, key: K) -> bool {
        let now = Instant::now();
        let mut hits = self.hits.lock().unwrap();
        if hits.len() > 10_000 {
            hits.retain(|_, (start, _)| now.duration_since(*start) < self.window);
        }
        let entry = hits.entry(key).or_insert((now, 0));
        if now.duration_since(entry.0) >= self.window {
            *entry = (now, 0);
        }
        entry.1 += 1;
        entry.1 <= self.limit
    }
}

fn client_ip(request: &Request) -> IpAddr {
    request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip())
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
}

pub async fn limit(State(limiter): State<Arc<RateLimiter>>, request: Request, next: Next) -> Response {
    if !limiter.allow(client_ip(&request)) {
        return ApiError::too_many_requests().into_response();
    }
    next.run(request).await
}

/// Who is calling: the session token's hash, or the IP without a token
/// (such requests are rejected by authentication anyway).
#[derive(PartialEq, Eq, Hash)]
pub enum Caller {
    Token([u8; 32]),
    Ip(IpAddr),
}

pub async fn limit_per_session(
    State(limiter): State<Arc<RateLimiter<Caller>>>,
    request: Request,
    next: Next,
) -> Response {
    let token =
        request.headers().get(AUTHORIZATION).and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer "));
    let caller = match token {
        Some(token) => Caller::Token(crate::secrets::token_hash(token).try_into().unwrap_or([0; 32])),
        None => Caller::Ip(client_ip(&request)),
    };
    if !limiter.allow(caller) {
        return ApiError::too_many_requests().into_response();
    }
    next.run(request).await
}

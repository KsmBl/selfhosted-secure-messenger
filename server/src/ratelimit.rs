//! Fixed-window rate limits: per client IP for unauthenticated endpoints,
//! per session token for authenticated ones (devices and admins).
//!
//! Behind a reverse proxy on the same host (Caddy, scripts/setup-https.sh)
//! the client address is taken from the last `X-Forwarded-For` entry, which
//! the proxy sets itself; that header is only trusted from loopback peers.
//! New sessions can only be created at the per-IP rate, so cycling tokens
//! does not lift the per-session limits.

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
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip())
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    if !peer.is_loopback() {
        return peer;
    }
    request
        .headers()
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .next_back()
        .and_then(|ip| ip.trim().parse().ok())
        .unwrap_or(peer)
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

/// Only loopback and private/VPN addresses may connect, unless
/// `SSM_ALLOW_PUBLIC_CLIENTS=1`. The server speaks plain HTTP; on the
/// internet it belongs behind the TLS proxy (whose connections are loopback).
pub async fn local_only(allow_public: bool, request: Request, next: Next) -> Response {
    // In-process calls (tests) carry no peer address.
    if let Some(ConnectInfo(addr)) = request.extensions().get::<ConnectInfo<SocketAddr>>()
        && !allow_public
        && !is_local(addr.ip())
    {
        return ApiError::forbidden("public-network").into_response();
    }
    next.run(request).await
}

/// Loopback, private (RFC 1918, IPv6 ULA), link-local and CGNAT/VPN
/// (100.64.0.0/10, e.g. Tailscale) addresses.
pub fn is_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            v4.is_loopback() || v4.is_private() || v4.is_link_local() || (a == 100 && (64..128).contains(&b))
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_local(IpAddr::V4(v4));
            }
            let first = v6.segments()[0];
            v6.is_loopback() || (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_addresses() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.220",
            "169.254.1.1",
            "100.100.1.1",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:192.168.0.5",
        ] {
            assert!(is_local(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "100.128.0.1", "172.32.0.1", "2a00:1450::1", "::ffff:1.1.1.1"] {
            assert!(!is_local(ip.parse().unwrap()), "{ip}");
        }
    }
}

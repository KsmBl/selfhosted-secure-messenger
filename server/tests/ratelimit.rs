//! Per-session rate limits for authenticated endpoints.

mod common;

use axum::http::{Method, StatusCode};
use common::{TestEnv, admin_login};

#[tokio::test]
async fn admin_sessions_are_limited_independently() {
    let env = TestEnv::start().await;
    let admin = env.admin().await;
    for i in 0..120 {
        let (status, body) = env.api.call(Method::GET, "/v1/admin/overview", Some(&admin.token), None).await;
        assert_eq!(status, StatusCode::OK, "request {i}: {body}");
    }
    let (status, _) = env.api.call(Method::GET, "/v1/admin/overview", Some(&admin.token), None).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);

    // Another session of the same admin key has its own budget.
    let other = admin_login(&env.api, &admin.key, admin.key_id).await;
    let (status, _) = env.api.call(Method::GET, "/v1/admin/overview", Some(&other), None).await;
    assert_eq!(status, StatusCode::OK);
    env.stop().await;
}

/// Behind the local reverse proxy, clients are told apart by the
/// X-Forwarded-For entry the proxy appends; remote peers cannot spoof it.
#[tokio::test]
async fn forwarded_clients_behind_local_proxy_have_own_limits() {
    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::Request;
    use std::net::SocketAddr;
    use tower::ServiceExt;

    let env = TestEnv::start().await;
    let call = |peer: &str, forwarded: &str| {
        let mut request = Request::builder()
            .method(Method::POST)
            .uri("/v1/auth/challenge")
            .header("x-forwarded-for", forwarded)
            .body(Body::empty())
            .unwrap();
        request.extensions_mut().insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
        let router = env.api.router.clone();
        async move { router.oneshot(request).await.unwrap().status() }
    };
    for _ in 0..30 {
        assert_eq!(call("127.0.0.1:5000", "198.51.100.7").await, StatusCode::OK);
    }
    assert_eq!(call("127.0.0.1:5000", "198.51.100.7").await, StatusCode::TOO_MANY_REQUESTS);
    // Another client behind the same proxy; a spoofed earlier entry is ignored.
    assert_eq!(call("127.0.0.1:5000", "198.51.100.7, 203.0.113.9").await, StatusCode::OK);
    // A remote peer cannot pick its address via the header.
    for _ in 0..30 {
        call("192.168.7.9:4000", "203.0.113.50").await;
    }
    assert_eq!(call("192.168.7.9:4000", "203.0.113.51").await, StatusCode::TOO_MANY_REQUESTS);
    env.stop().await;
}

/// Plain HTTP is only for loopback and private networks unless allowed.
#[tokio::test]
async fn public_clients_are_refused_by_default() {
    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::Request;
    use std::net::SocketAddr;
    use tower::ServiceExt;

    let env = TestEnv::start().await;
    let call = |peer: &str| {
        let mut request = Request::builder().uri("/healthz").body(Body::empty()).unwrap();
        request.extensions_mut().insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
        let router = env.api.router.clone();
        async move { router.oneshot(request).await.unwrap().status() }
    };
    assert_eq!(call("192.168.1.50:5000").await, StatusCode::OK);
    assert_eq!(call("100.101.102.103:5000").await, StatusCode::OK);
    assert_eq!(call("[fd12::5]:5000").await, StatusCode::OK);
    assert_eq!(call("203.0.113.7:5000").await, StatusCode::FORBIDDEN);
    env.stop().await;
}

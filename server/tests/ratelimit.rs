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

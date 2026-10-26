//! Enrollment, approval, revocation and audit log.

mod common;

use axum::http::{Method, StatusCode};
use common::{TestDevice, TestEnv, b64, key};
use serde_json::json;
use ssm_proto::signing;
use ssm_server::audit;
use uuid::Uuid;

#[tokio::test]
async fn enrollment_approval_revocation_and_audit() {
    let env = TestEnv::start().await;
    let api = &env.api;

    // Admin login with the bootstrap key; a wrong key is refused.
    let admin = env.admin().await;
    let nonce = api.nonce("/v1/admin/auth/challenge", None).await;
    let forged = signing::sign(&key(201), &signing::admin_auth_message(&nonce, admin.key_id));
    let body = json!({ "admin_key_id": admin.key_id, "nonce": b64(&nonce), "signature": b64(&forged) });
    let (status, _) = api.call(Method::POST, "/v1/admin/auth/session", None, Some(body)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let admin_token = admin.token.as_str();

    // Account + invite.
    let (status, invite) =
        api.call(Method::POST, "/v1/admin/accounts", Some(admin_token), Some(json!({ "username": "alice" }))).await;
    assert_eq!(status, StatusCode::OK, "{invite}");
    let code = invite["invite_code"].as_str().unwrap().to_owned();
    let (status, _) =
        api.call(Method::POST, "/v1/admin/accounts", Some(admin_token), Some(json!({ "username": "alice" }))).await;
    assert_eq!(status, StatusCode::CONFLICT);

    // First device enrolls with the invite (case-insensitive); the invite is single-use.
    let phone = TestDevice::new(1);
    let (status, enrolled) = phone.enroll(api, Some(&code.to_lowercase()), None).await;
    assert_eq!(status, StatusCode::OK, "{enrolled}");
    assert_eq!(enrolled["status"], "pending");
    let phone_id: Uuid = enrolled["device_id"].as_str().unwrap().parse().unwrap();
    let (status, _) = TestDevice::new(2).enroll(api, Some(&code), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = TestDevice::new(3).enroll(api, None, Some("nobody")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Pending device: status only.
    let (status, session) = phone.login(api, phone_id).await;
    assert_eq!(status, StatusCode::OK, "{session}");
    let phone_token = session["token"].as_str().unwrap().to_owned();
    let (status, body) = api.call(Method::GET, "/v1/devices/status", Some(&phone_token), None).await;
    assert_eq!((status, body["status"].as_str()), (StatusCode::OK, Some("pending")));
    for path in ["/v1/devices", "/v1/events"] {
        let (status, _) = api.call(Method::GET, path, Some(&phone_token), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
    }

    // Device tokens never work on the Admin API.
    let (status, _) = api.call(Method::GET, "/v1/admin/devices", Some(&phone_token), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Admin approves.
    let (status, pending) = api.call(Method::GET, "/v1/admin/devices?status=pending", Some(admin_token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(pending.as_array().unwrap().len(), 1);
    assert_eq!(pending[0]["username"], "alice");
    let (status, approved) =
        api.call(Method::POST, &format!("/v1/admin/devices/{phone_id}/approve"), Some(admin_token), None).await;
    assert_eq!((status, approved["status"].as_str()), (StatusCode::OK, Some("active")));
    let (status, devices) = api.call(Method::GET, "/v1/devices", Some(&phone_token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(devices.as_array().unwrap().len(), 1);

    // A second device enrolls by username and gets rejected.
    let laptop = TestDevice::new(4);
    let (status, enrolled) = laptop.enroll(api, None, Some("alice")).await;
    assert_eq!(status, StatusCode::OK);
    let laptop_id = enrolled["device_id"].as_str().unwrap();
    let (status, _) =
        api.call(Method::POST, &format!("/v1/admin/devices/{laptop_id}/reject"), Some(admin_token), None).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = laptop.login(api, laptop_id.parse().unwrap()).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Revoke needs a confirmation signature bound to action and target.
    let revoke = format!("/v1/admin/devices/{phone_id}/revoke");
    let (status, body) = api.call(Method::POST, &revoke, Some(admin_token), None).await;
    assert_eq!((status, body["type"].as_str()), (StatusCode::FORBIDDEN, Some("urn:ssm:problem:confirmation-required")));
    let wrong_target = admin.confirm(api, "revoke", "device:someone-else").await;
    let (status, _) = api.call(Method::POST, &revoke, Some(admin_token), Some(wrong_target)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let good = admin.confirm(api, "revoke", &format!("device:{phone_id}")).await;
    let (status, body) = api.call(Method::POST, &revoke, Some(admin_token), Some(good.clone())).await;
    assert_eq!((status, body["status"].as_str()), (StatusCode::OK, Some("revoked")));

    // Confirmation nonces are single-use.
    let (status, _) = api.call(Method::POST, &revoke, Some(admin_token), Some(good)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Revocation ends existing sessions and blocks new ones; it is final.
    let (status, _) = api.call(Method::GET, "/v1/devices/status", Some(&phone_token), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = phone.login(api, phone_id).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) =
        api.call(Method::POST, &format!("/v1/admin/devices/{phone_id}/approve"), Some(admin_token), None).await;
    assert_eq!(status, StatusCode::CONFLICT);

    // Audit log: every action recorded, chain intact, tampering detected.
    let (status, events) = api.call(Method::GET, "/v1/admin/audit-events", Some(admin_token), None).await;
    assert_eq!(status, StatusCode::OK);
    let actions: Vec<&str> = events.as_array().unwrap().iter().map(|e| e["action"].as_str().unwrap()).collect();
    assert_eq!(actions, ["device.approve", "device.revoke", "device.reject", "device.approve", "account.create"]);
    assert!(events[0]["result"].as_str().unwrap().starts_with("refused"));
    assert_eq!(audit::verify_chain(&env.pool).await.unwrap(), Ok(5));

    let update = sqlx::query("UPDATE admin_audit_events SET result = 'ok' WHERE action = 'device.reject'")
        .execute(&env.pool)
        .await;
    assert!(update.is_err(), "audit log must be append-only");
    sqlx::query("ALTER TABLE admin_audit_events DISABLE TRIGGER admin_audit_events_no_update_delete")
        .execute(&env.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE admin_audit_events SET target = 'device:tampered' WHERE action = 'device.reject'")
        .execute(&env.pool)
        .await
        .unwrap();
    assert!(audit::verify_chain(&env.pool).await.unwrap().is_err());

    env.stop().await;
}

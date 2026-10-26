//! The TUI's data layer: account/device management, account disabling, mass
//! deletion, audit entries and forwarding of hub events to the server process.

mod common;

use std::time::Duration;

use axum::http::{Method, StatusCode};
use common::{TestDevice, TestEnv, b64};
use serde_json::json;
use ssm_proto::api::{DeviceAction, DeviceStatus};
use ssm_server::hub::{self, HubEvent};
use ssm_server::manage::{self as data, Actor};
use ssm_server::{AppState, Config};
use uuid::Uuid;

#[tokio::test]
async fn tui_actions_are_applied_audited_and_forwarded() {
    let env = TestEnv::start().await;
    let api = &env.api;
    // The TUI is a separate process: its own AppState forwarding hub events.
    let tui = AppState::with_config(env.pool.clone(), Config { remote_hub: true, ..Config::default() });
    hub::spawn_listener(env.pool.clone(), env.state.hub.clone());
    let mut server_hub = env.state.hub.subscribe();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Account creation shows the invite; the invite works.
    let created = data::create_account(&tui, Actor::TUI, "erin").await.unwrap();
    let code = created.lines().find_map(|l| l.strip_prefix("Invite code:")).unwrap().trim().to_owned();
    assert!(data::create_account(&tui, Actor::TUI, "erin").await.unwrap_err().contains("taken"));
    assert!(data::create_account(&tui, Actor::TUI, "X").await.is_err());
    let phone = TestDevice::new(7);
    let (status, enrolled) = phone.enroll(api, Some(&code), None).await;
    assert_eq!(status, StatusCode::OK);
    let device_id: Uuid = enrolled["device_id"].as_str().unwrap().parse().unwrap();

    // Devices list shows it pending; approve it from the TUI.
    let pending = data::devices(&tui, Some(DeviceStatus::Pending)).await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].username, "erin");
    assert_eq!(
        data::device_action(&tui, Actor::TUI, device_id, DeviceAction::Approve).await.unwrap(),
        "Device is now active."
    );
    assert!(
        data::device_action(&tui, Actor::TUI, device_id, DeviceAction::Approve)
            .await
            .unwrap_err()
            .contains("Cannot approve")
    );
    assert_eq!(data::stats(&tui).await.unwrap().devices_active, 1);

    // Disabling from the TUI reaches the server's hub (closes WebSockets).
    let (status, session) = phone.login(api, device_id).await;
    assert_eq!(status, StatusCode::OK);
    data::device_action(&tui, Actor::TUI, device_id, DeviceAction::Disable).await.unwrap();
    let event = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(HubEvent::Close { device_id: closed }) = server_hub.recv().await {
                return closed;
            }
        }
    })
    .await
    .expect("close forwarded to the server");
    assert_eq!(event, device_id);
    let (status, _) = api.call(Method::GET, "/v1/devices/status", Some(session["token"].as_str().unwrap()), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    data::device_action(&tui, Actor::TUI, device_id, DeviceAction::Enable).await.unwrap();

    // Disabling the account blocks all its devices.
    let accounts = data::accounts(&tui).await.unwrap();
    let erin = accounts.iter().find(|a| a.username == "erin").unwrap().id;
    data::set_account_status(&tui, Actor::TUI, erin, true).await.unwrap();
    let (status, _) = phone.login(api, device_id).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    data::set_account_status(&tui, Actor::TUI, erin, false).await.unwrap();
    let (status, session) = phone.login(api, device_id).await;
    assert_eq!(status, StatusCode::OK);
    let token = session["token"].as_str().unwrap().to_owned();

    // Admin role on and off; removing it revokes admin keys.
    assert!(data::set_admin(&tui, Actor::TUI, erin, true).await.unwrap().starts_with("Account is now admin"));
    assert!(data::set_admin(&tui, Actor::TUI, erin, true).await.is_err());
    let key_id = Uuid::new_v4();
    sqlx::query("INSERT INTO admin_keys (id, account_id, public_key) VALUES ($1, $2, $3)")
        .bind(key_id)
        .bind(erin)
        .bind([5u8; 32].as_slice())
        .execute(&env.pool)
        .await
        .unwrap();
    assert_eq!(
        data::set_admin(&tui, Actor::TUI, erin, false).await.unwrap(),
        "Admin role removed (1 admin key(s) revoked)."
    );
    let key_status: String = sqlx::query_scalar("SELECT status FROM admin_keys WHERE id = $1")
        .bind(key_id)
        .fetch_one(&env.pool)
        .await
        .unwrap();
    assert_eq!(key_status, "revoked");
    assert_eq!(data::accounts(&tui).await.unwrap().iter().find(|a| a.id == erin).unwrap().role, "user");

    // Mass deletion from the TUI.
    let admin = env.admin().await;
    let friend = env.active_device(&admin, "frank", 30).await;
    let body = json!({ "kind": "direct", "members": [friend.account_id] });
    let (_, conv) = api.call(Method::POST, "/v1/conversations", Some(&token), Some(body)).await;
    let conv = conv["conversation_id"].as_str().unwrap().to_owned();
    for text in ["a", "b", "c"] {
        let body = json!({ "client_id": Uuid::new_v4(), "session_id": "s", "ciphertext": b64(text.as_bytes()) });
        api.call(Method::POST, &format!("/v1/conversations/{conv}/messages"), Some(&token), Some(body)).await;
    }
    data::start_mass_delete(&tui, Actor::TUI, erin).await.unwrap();
    let mut done = false;
    for _ in 0..50 {
        let jobs = data::jobs(&tui).await.unwrap();
        if jobs[0].status == "backup_purge_pending" {
            assert_eq!(jobs[0].affected, 3);
            assert!(jobs[0].scope.contains("erin"));
            done = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(done, "mass deletion finished");

    // Deleting the account: messages gone for everyone, removed from the
    // conversation with a notice, devices and account deleted, name free.
    let erin_messages: i64 =
        sqlx::query_scalar("SELECT count(*) FROM messages WHERE sender_account_id = $1 AND ciphertext IS NOT NULL")
            .bind(erin)
            .fetch_one(&env.pool)
            .await
            .unwrap();
    assert_eq!(erin_messages, 0, "already deleted by the mass deletion above");
    let body = json!({ "client_id": Uuid::new_v4(), "session_id": "s", "ciphertext": b64(b"one more") });
    api.call(Method::POST, &format!("/v1/conversations/{conv}/messages"), Some(&token), Some(body)).await;
    let result = data::delete_account(&tui, Actor::TUI, erin).await.unwrap();
    assert_eq!(result, "Account 'erin' deleted (1 messages deleted for everyone).");
    assert!(data::accounts(&tui).await.unwrap().iter().all(|a| a.username != "erin"));
    let devices: i64 = sqlx::query_scalar("SELECT count(*) FROM devices WHERE id = $1")
        .bind(device_id)
        .fetch_one(&env.pool)
        .await
        .unwrap();
    assert_eq!(devices, 0);
    let (status, page) =
        api.call(Method::GET, &format!("/v1/conversations/{conv}/messages"), Some(&friend.token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(page["messages"][0]["notice"]["notice"], "account_deleted");
    assert_eq!(page["messages"][0]["notice"]["username"], "erin");
    assert!(page["messages"].as_array().unwrap().iter().all(|m| m["kind"] != "encrypted"));
    assert!(data::jobs(&tui).await.unwrap().iter().any(|j| j.scope.contains("erin (deleted)")));
    assert!(data::create_account(&tui, Actor::TUI, "erin").await.is_ok(), "username is free again");

    // Everything is audited with origin (tui), and the chain is intact.
    let audit = data::audit(&tui).await.unwrap();
    for action in
        ["account.create", "device.approve", "device.disable", "account.disable", "account.delete_all_content"]
    {
        assert!(audit.iter().any(|a| a.action == action && a.result.contains("(tui)")), "{action} audited as (tui)");
    }
    assert!(data::verify_audit(&tui).await.unwrap().starts_with("Audit chain intact"));

    env.stop().await;
}

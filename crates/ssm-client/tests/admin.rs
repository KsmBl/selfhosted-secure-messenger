//! Admin client against a real server: key creation in its own container,
//! registration (as the TUI does it), login, management operations and audit.

use std::net::SocketAddr;

use postgresql_embedded::PostgreSQL;
use sqlx::PgPool;
use ssm_client::{AdminClient, AdminKey, Client, EnrollWith};
use ssm_core::{KdfParams, Pattern};
use ssm_proto::api::{DeviceAction, DeviceStatus};
use ssm_server::manage::{self, Actor};
use ssm_server::{AppState, MIGRATOR, accounts, router};

fn pattern(dots: &[u8]) -> Pattern {
    Pattern::new(dots.to_vec()).unwrap()
}

#[tokio::test]
async fn admin_client_manages_the_server() {
    let mut postgres = PostgreSQL::default();
    postgres.setup().await.unwrap();
    postgres.start().await.unwrap();
    postgres.create_database("ssm_test").await.unwrap();
    let pool = PgPool::connect(&postgres.settings().url("ssm_test")).await.unwrap();
    MIGRATOR.run(&pool).await.unwrap();
    let state = AppState::new(pool.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let app = router(state.clone()).into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    // Alice: chat device, admin role, admin key with its own pattern.
    let mut tx = pool.begin().await.unwrap();
    let alice_id = accounts::create_account(&mut tx, "alice", "user").await.unwrap().unwrap();
    let (code, _) = accounts::create_invite(&mut tx, alice_id).await.unwrap();
    tx.commit().await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let chat_pattern = pattern(&[0, 6, 12, 18, 7, 7]);
    let admin_pattern = pattern(&[24, 18, 12, 6, 0, 1]);
    let alice = Client::enroll(dir.path(), &url, EnrollWith::Invite(code), "pc", &chat_pattern, KdfParams::MIN, None)
        .await
        .unwrap();
    manage::set_admin(&state, Actor::TUI, alice_id, true).await.unwrap();

    assert!(!AdminKey::exists(dir.path()));
    let key = AdminKey::create(dir.path(), &admin_pattern, KdfParams::MIN, None).unwrap();
    let public_key = key.public_key();
    assert!(AdminKey::create(dir.path(), &admin_pattern, KdfParams::MIN, None).is_err(), "only one admin key");
    assert!(AdminKey::open(dir.path(), &chat_pattern, None).unwrap_err().is_wrong_pattern());

    // Not registered yet: no login.
    let err = AdminClient::connect(&url, key).await.err().unwrap();
    assert_eq!(err.problem_kind(), Some("not-found"));
    manage::add_admin_key(&state, Actor::TUI, alice_id, &public_key).await.unwrap();
    let admin = AdminClient::connect(&url, AdminKey::open(dir.path(), &admin_pattern, None).unwrap()).await.unwrap();

    // Overview, new account with invite, device approval.
    assert_eq!(admin.overview().await.unwrap().audit_broken_at, None);
    let invite = admin.create_account("bob").await.unwrap();
    let bob_dir = tempfile::tempdir().unwrap();
    let mut bob = Client::enroll(
        bob_dir.path(),
        &url,
        EnrollWith::Invite(invite.invite_code),
        "phone",
        &chat_pattern,
        KdfParams::MIN,
        None,
    )
    .await
    .unwrap();
    let pending = admin.devices(Some(DeviceStatus::Pending)).await.unwrap();
    let bobs = pending.iter().find(|d| d.username == "bob").expect("bob's device is pending");
    admin.device_action(bobs.device_id, DeviceAction::Approve).await.unwrap();
    assert_eq!(bob.device_status().await.unwrap(), DeviceStatus::Active);

    // Account management with confirmation signatures; not on yourself.
    let bob_id = invite.account_id;
    admin.set_account_locked(bob_id, true).await.unwrap();
    assert!(bob.device_status().await.is_err());
    admin.set_account_locked(bob_id, false).await.unwrap();
    let err = admin.set_admin_role(alice_id, false).await.unwrap_err();
    assert_eq!(err.problem_kind(), Some("not-on-self"));
    let err = admin.delete_account(alice_id).await.unwrap_err();
    assert_eq!(err.problem_kind(), Some("not-on-self"));
    let accounts = admin.accounts().await.unwrap();
    assert_eq!(accounts.iter().find(|a| a.username == "bob").unwrap().active_devices, 1);
    let message = admin.delete_account(bob_id).await.unwrap();
    assert!(message.starts_with("Account 'bob' deleted"), "{message}");
    assert!(admin.accounts().await.unwrap().iter().all(|a| a.username != "bob"));
    assert!(admin.jobs().await.unwrap().iter().any(|j| j.scope.contains("bob")));

    // Audit: attributed to Alice, readable targets.
    let audit = admin.audit().await.unwrap();
    let delete = audit.iter().find(|e| e.action == "account.delete").unwrap();
    assert_eq!(delete.admin_account_id, Some(alice_id));
    // Bob is deleted, so his device approval falls back to the raw target.
    assert!(audit.iter().any(|e| e.action == "device.approve" && e.admin_account_id == Some(alice_id)));
    let grant = audit.iter().find(|e| e.action == "admin_key.add").unwrap();
    assert_eq!(grant.target_label, "account alice");

    drop(alice);
    pool.close().await;
    postgres.stop().await.unwrap();
}

//! Two clients talk through a real server over HTTP: enrollment, approval,
//! key exchange, messages, re-decryption after lock/unlock, deletion and
//! retention.

use std::net::SocketAddr;

use postgresql_embedded::PostgreSQL;
use sqlx::PgPool;
use ssm_client::{Client, DisplayBody, EnrollWith, LockedClient, Update};
use ssm_core::{KdfParams, Pattern};
use ssm_proto::api::{ConversationKind, DeviceStatus, SystemNotice};
use ssm_server::{AppState, MIGRATOR, accounts, router};

struct Server {
    postgres: PostgreSQL,
    pool: PgPool,
    url: String,
}

async fn start_server() -> Server {
    let mut postgres = PostgreSQL::default();
    postgres.setup().await.unwrap();
    postgres.start().await.unwrap();
    postgres.create_database("ssm_test").await.unwrap();
    let pool = PgPool::connect(&postgres.settings().url("ssm_test")).await.unwrap();
    MIGRATOR.run(&pool).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let app = router(AppState::new(pool.clone())).into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move { axum_serve(listener, app).await });
    Server { postgres, pool, url }
}

async fn axum_serve(
    listener: tokio::net::TcpListener,
    app: axum::extract::connect_info::IntoMakeServiceWithConnectInfo<axum::Router, SocketAddr>,
) {
    axum::serve(listener, app).await.unwrap();
}

/// What an admin does: create the account and later approve its devices.
async fn invite(pool: &PgPool, username: &str) -> String {
    let mut tx = pool.begin().await.unwrap();
    let account = accounts::create_account(&mut tx, username, "user").await.unwrap().unwrap();
    let (code, _) = accounts::create_invite(&mut tx, account).await.unwrap();
    tx.commit().await.unwrap();
    code
}

async fn approve_all(pool: &PgPool) {
    sqlx::query("UPDATE devices SET status = 'active' WHERE status = 'pending'").execute(pool).await.unwrap();
}

fn pattern(dots: &[u8]) -> Pattern {
    Pattern::new(dots.to_vec()).unwrap()
}

fn texts(messages: &[ssm_client::DisplayMessage]) -> Vec<String> {
    messages
        .iter()
        .filter_map(|m| match &m.body {
            DisplayBody::Text(t) => Some(t.clone()),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn two_clients_chat_through_the_server() {
    let server = start_server().await;
    let dirs = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let alice_pattern = pattern(&[0, 6, 12, 18, 7, 7]);
    let bob_pattern = pattern(&[4, 8, 12, 16, 11, 11]);

    // Enrollment: pending until approved.
    let code = invite(&server.pool, "alice").await;
    let mut alice = Client::enroll(
        dirs.0.path(),
        &server.url,
        EnrollWith::Invite(code),
        "Alice Laptop",
        &alice_pattern,
        KdfParams::MIN,
        None,
    )
    .await
    .unwrap();
    assert_eq!(alice.device_status().await.unwrap(), DeviceStatus::Pending);
    assert_eq!(alice.sync().await.unwrap_err().problem_kind(), Some("device-pending"));

    let code = invite(&server.pool, "bob").await;
    let mut bob = Client::enroll(
        dirs.1.path(),
        &server.url,
        EnrollWith::Invite(code),
        "Bob Phone",
        &bob_pattern,
        KdfParams::MIN,
        None,
    )
    .await
    .unwrap();
    approve_all(&server.pool).await;
    assert_eq!(alice.device_status().await.unwrap(), DeviceStatus::Active);
    assert_eq!(bob.device_status().await.unwrap(), DeviceStatus::Active);
    assert_eq!(alice.data().username.as_deref(), Some("alice"));
    alice.sync().await.unwrap();
    bob.sync().await.unwrap();

    // Alice starts a direct chat and writes.
    let bob_account = alice.lookup("bob").await.unwrap().account_id;
    let conv = alice.create_conversation(ConversationKind::Direct, vec![bob_account], None).await.unwrap();
    let id = conv.conversation_id;
    alice.send_text(id, "Hallo Bob!").await.unwrap();

    let updates = bob.sync().await.unwrap();
    assert!(updates.contains(&Update::KeyReceived { conversation_id: id }));
    assert!(updates.iter().any(|u| matches!(u, Update::NewMessage { conversation_id, .. } if *conversation_id == id)));
    let (page, _) = bob.messages(id, None).await.unwrap();
    assert_eq!(texts(&page), ["Hallo Bob!"]);
    assert!(matches!(page.last().unwrap().body, DisplayBody::Notice(SystemNotice::ConversationCreated { .. })));

    // Bob answers; Alice reads both, including her own message.
    bob.send_text(id, "Hi Alice").await.unwrap();
    alice.sync().await.unwrap();
    let (page, _) = alice.messages(id, None).await.unwrap();
    assert_eq!(texts(&page), ["Hi Alice", "Hallo Bob!"]);

    // Lock: nothing in memory. Wrong pattern is counted; right one restores keys
    // and the server-side history decrypts again.
    let locked = bob.lock();
    let locked = match locked.unlock(&alice_pattern, None) {
        Err(failed) => {
            assert!(failed.error.is_wrong_pattern());
            *failed.locked
        }
        Ok(_) => panic!("wrong pattern must not unlock"),
    };
    assert_eq!(locked.data().failed_unlocks, 1);
    // Only one client per profile at a time; the count is on disk.
    assert!(matches!(LockedClient::open(dirs.1.path()), Err(ssm_client::ClientError::ProfileInUse)));
    drop(locked);
    let reopened = LockedClient::open(dirs.1.path()).unwrap();
    assert_eq!(reopened.data().failed_unlocks, 1);
    assert_eq!(reopened.notification_hint().await.unwrap().pending_messages, 0);
    let mut bob = reopened.unlock(&bob_pattern, None).map_err(|f| f.error).unwrap();
    assert_eq!(bob.data().failed_unlocks, 0);
    let (page, _) = bob.messages(id, None).await.unwrap();
    assert_eq!(texts(&page), ["Hi Alice", "Hallo Bob!"]);

    // Bob deletes Alice's message for everyone.
    let target = page.iter().find(|m| m.body == DisplayBody::Text("Hallo Bob!".into())).unwrap().message_id;
    bob.delete_for_all(target).await.unwrap();
    let updates = alice.sync().await.unwrap();
    assert!(updates.contains(&Update::MessageDeleted { conversation_id: id, message_id: target }));
    let (page, _) = alice.messages(id, None).await.unwrap();
    assert_eq!(texts(&page), ["Hi Alice"]);
    let deleted = page.iter().find(|m| m.message_id == target).unwrap();
    assert_eq!(deleted.body, DisplayBody::Deleted { by: bob.account_id() });

    // Retention change shows up for both.
    alice.set_retention(id, 30).await.unwrap();
    bob.sync().await.unwrap();
    let (page, _) = bob.messages(id, None).await.unwrap();
    assert!(matches!(
        page[0].body,
        DisplayBody::Notice(SystemNotice::RetentionChanged { from_days: 90, to_days: 30, .. })
    ));

    // A second device of Bob joins later: it cannot read the old messages,
    // but receives keys for new ones.
    let dir3 = tempfile::tempdir().unwrap();
    let mut bob2 = Client::enroll(
        dir3.path(),
        &server.url,
        EnrollWith::Username("bob".into()),
        "Bob Tablet",
        &bob_pattern,
        KdfParams::MIN,
        None,
    )
    .await
    .unwrap();
    approve_all(&server.pool).await;
    bob2.sync().await.unwrap();
    let (page, _) = bob2.messages(id, None).await.unwrap();
    assert!(page.iter().any(|m| m.body == DisplayBody::Unavailable));
    alice.send_text(id, "for all of Bob's devices").await.unwrap();
    bob2.sync().await.unwrap();
    bob.sync().await.unwrap();
    for client in [&mut bob, &mut bob2] {
        let (page, _) = client.messages(id, None).await.unwrap();
        assert_eq!(texts(&page)[0], "for all of Bob's devices");
    }

    // Revoking deletes the device completely; what it sent stays readable.
    bob2.send_text(id, "sent from the tablet").await.unwrap();
    sqlx::query("DELETE FROM devices WHERE id = $1").bind(bob2.device_id()).execute(&server.pool).await.unwrap();
    alice.sync().await.unwrap();
    let (page, _) = alice.messages(id, None).await.unwrap();
    assert_eq!(texts(&page)[0], "sent from the tablet");

    // A device can sign itself out for good; it is gone on the server.
    let dir4 = tempfile::tempdir().unwrap();
    let extra = Client::enroll(
        dir4.path(),
        &server.url,
        EnrollWith::Username("bob".into()),
        "Old PC",
        &bob_pattern,
        KdfParams::MIN,
        None,
    )
    .await
    .unwrap();
    let extra_id = extra.device_id();
    let locked = extra.lock();
    locked.unregister().await.unwrap();
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM devices WHERE id = $1")
        .bind(extra_id)
        .fetch_one(&server.pool)
        .await
        .unwrap();
    assert_eq!(left, 0);
    assert!(LockedClient::open(dir4.path()).is_err(), "still locked by `locked` in this process");
    drop(locked);

    server.pool.close().await;
    server.postgres.stop().await.unwrap();
}

#[tokio::test]
async fn media_is_encrypted_end_to_end() {
    let server = start_server().await;
    let dirs = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let mut clients = Vec::new();
    for (dir, name) in [(&dirs.0, "alice"), (&dirs.1, "bob")] {
        let code = invite(&server.pool, name).await;
        let client = Client::enroll(
            dir.path(),
            &server.url,
            EnrollWith::Invite(code),
            name,
            &pattern(&[0, 1, 2, 3, 4, 5]),
            KdfParams::MIN,
            None,
        )
        .await
        .unwrap();
        clients.push(client);
    }
    approve_all(&server.pool).await;
    let (mut alice, mut bob) = (clients.remove(0), clients.remove(0));
    // Bob has not been online since approval: his keys were published while
    // he was pending, so he can still read what Alice sends now.
    alice.sync().await.unwrap();
    let bob_account = alice.lookup("bob").await.unwrap().account_id;
    let id =
        alice.create_conversation(ConversationKind::Direct, vec![bob_account], None).await.unwrap().conversation_id;

    let photo = b"\x89PNG pretend this is a large photo".repeat(1000);
    alice.send_media(id, "beach.png", "image/png", &photo, Some(b"tiny preview"), Some("Sommer")).await.unwrap();

    // The server only ever sees ciphertext.
    let stored: Vec<i64> =
        sqlx::query_scalar("SELECT size FROM media_objects ORDER BY size DESC").fetch_all(&server.pool).await.unwrap();
    assert_eq!(stored.len(), 2);
    assert!(stored[0] as usize > photo.len());

    bob.sync().await.unwrap();
    let (page, _) = bob.messages(id, None).await.unwrap();
    let DisplayBody::Media(info) = &page[0].body else { panic!("expected media, got {:?}", page[0].body) };
    assert_eq!((info.name.as_str(), info.mime.as_str()), ("beach.png", "image/png"));
    assert_eq!(info.kind, ssm_client::MediaKind::Image);
    assert_eq!(info.caption.as_deref(), Some("Sommer"));
    assert_eq!(bob.fetch_media(info.preview.as_ref().unwrap()).await.unwrap().as_slice(), b"tiny preview");
    assert_eq!(bob.fetch_media(&info.original).await.unwrap().as_slice(), photo.as_slice());

    // Deleting the message makes the file unreachable.
    let message_id = page[0].message_id;
    alice.delete_for_all(message_id).await.unwrap();
    let mut gone = false;
    for _ in 0..50 {
        if bob.fetch_media(&info.original).await.is_err() {
            gone = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(gone, "media still downloadable after delete for everyone");
    drop(server.postgres);
}

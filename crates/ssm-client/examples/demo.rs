//! Development helper: create demo profiles and conversations.
//!
//! ```text
//! cargo run -p ssm-client --example demo -- enroll <server> <dir> <invite> <device-name>
//! cargo run -p ssm-client --example demo -- chat <server> <alice-dir> <bob-dir> [<carol-dir>]
//! cargo run -p ssm-client --example demo -- admin-key <profile-dir>   (prints the public key)
//! cargo run -p ssm-client --example demo -- send <dir> <to-username> <text>
//! cargo run -p ssm-client --example demo -- read <dir> <with-username>
//! ```
//!
//! Profiles use the pattern 0,6,12,18,7,7 and minimal KDF parameters. Devices
//! must be approved between the two steps.

use ssm_client::{Client, EnrollWith, LockedClient};
use ssm_core::{KdfParams, Pattern};
use ssm_proto::api::ConversationKind;

fn pattern() -> Pattern {
    Pattern::new(vec![0, 6, 12, 18, 7, 7]).expect("valid demo pattern")
}

async fn open(dir: &str) -> Client {
    let mut client =
        LockedClient::open(dir).expect("profile").unlock(&pattern(), None).map_err(|f| f.error).expect("unlock");
    client.device_status().await.expect("status");
    client.sync().await.expect("sync");
    client
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["enroll", server, dir, invite, name] => {
            let client = Client::enroll(
                *dir,
                server,
                EnrollWith::Invite(invite.to_string()),
                name,
                &pattern(),
                KdfParams::MIN,
                None,
            )
            .await
            .expect("enroll");
            println!("enrolled device {}, fingerprint {}", client.device_id(), client.fingerprint());
        }
        ["send", dir, to, text] => {
            let mut client = open(dir).await;
            let peer = client.lookup(to).await.expect("user").account_id;
            let conv =
                client.create_conversation(ConversationKind::Direct, vec![peer], None).await.expect("conversation");
            client.send_text(conv.conversation_id, text).await.expect("send");
            println!("sent to {to}");
        }
        ["read", dir, with] => {
            let mut client = open(dir).await;
            let peer = client.lookup(with).await.expect("user").account_id;
            let conv =
                client.create_conversation(ConversationKind::Direct, vec![peer], None).await.expect("conversation");
            let (page, _) = client.messages(conv.conversation_id, None).await.expect("messages");
            for message in page.iter().rev() {
                println!("{:?}", message.body);
            }
        }
        ["admin-key", dir] => {
            // Admin pattern 24,18,12,6,0,1 (differs from the chat pattern).
            let pattern = Pattern::new(vec![24, 18, 12, 6, 0, 1]).expect("valid pattern");
            let key = ssm_client::AdminKey::create(std::path::Path::new(dir), &pattern, KdfParams::MIN, None)
                .expect("admin key");
            println!("{}", key.public_key());
        }
        ["chat", _server, alice_dir, bob_dir, rest @ ..] => {
            let mut alice = open(alice_dir).await;
            let mut bob = open(bob_dir).await;
            let bob_id = alice.lookup("bob").await.expect("bob").account_id;
            let direct = alice.create_conversation(ConversationKind::Direct, vec![bob_id], None).await.expect("direct");
            let id = direct.conversation_id;
            alice.send_text(id, "Hi Bob, did the new server work for you?").await.expect("send");
            bob.sync().await.expect("sync");
            bob.send_text(id, "Yes! Approved this morning. Everything is end-to-end encrypted now.")
                .await
                .expect("send");
            alice.sync().await.expect("sync");
            alice.send_text(id, "Great. I set our chat to 30 days retention.").await.expect("send");
            alice.set_retention(id, 30).await.expect("retention");
            bob.sync().await.expect("sync");
            let oops = bob.send_text(id, "my PIN for the old system is 4711").await.expect("send");
            bob.delete_for_all(oops.message_id).await.expect("delete");
            bob.send_text(id, "Oops, deleted that for everyone.").await.expect("send");

            if let [carol_dir] = rest {
                let mut carol = open(carol_dir).await;
                let carol_id = alice.lookup("carol").await.expect("carol").account_id;
                let group = alice
                    .create_conversation(ConversationKind::Group, vec![bob_id, carol_id], None)
                    .await
                    .expect("group");
                alice.send_text(group.conversation_id, "Welcome to the project group!").await.expect("send");
                carol.sync().await.expect("sync");
                carol.send_text(group.conversation_id, "Thanks, glad to be here.").await.expect("send");
            }
            alice.sync().await.expect("sync");
            println!("demo conversations created");
        }
        _ => eprintln!("usage: see the module documentation"),
    }
}

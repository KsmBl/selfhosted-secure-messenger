//! End-to-end encryption with Olm/Megolm via vodozemac (ADR-0001, TDD §7).
//!
//! - Every conversation is encrypted with Megolm. Each sending device has one
//!   outbound group session per conversation.
//! - Group session keys travel to all recipient devices over pairwise Olm
//!   sessions (to-device messages).
//! - Received group sessions are kept, so ciphertexts stored on the server can
//!   be decrypted again whenever a chat is opened (ADR-0002). The sender keeps
//!   an inbound copy of its own session for the same reason.
//! - Plaintexts are wrapped in an envelope that binds them to conversation and
//!   sender device, so the server cannot move ciphertexts between chats.
//!
//! This module holds no I/O. The whole state is serialized with [`CryptoStore::to_bytes`]
//! and stored inside the pattern-protected container.

use std::collections::{BTreeSet, HashMap};

use serde::{Deserialize, Serialize};
use ssm_proto::B64;
use uuid::Uuid;
use vodozemac::Curve25519PublicKey;
use vodozemac::megolm::{
    GroupSession, GroupSessionPickle, InboundGroupSession, InboundGroupSessionPickle, MegolmMessage,
    SessionConfig as MegolmConfig, SessionKey,
};
use vodozemac::olm::{Account, AccountPickle, OlmMessage, Session, SessionConfig as OlmConfig, SessionPickle};
use zeroize::Zeroizing;

/// Curve25519 public key bytes (Olm identity key or one-time key).
pub type CurveKey = [u8; 32];

/// Rotate an outbound group session after this many messages (ADR-0001).
pub const ROTATION_MESSAGES: u32 = 100;
/// Rotate an outbound group session after this many seconds (7 days).
pub const ROTATION_SECS: i64 = 7 * 24 * 60 * 60;
/// Inbound group sessions older than this are dropped; no message can still
/// exist on the server (max. retention 365 days).
pub const MAX_KEY_AGE_SECS: i64 = 400 * 24 * 60 * 60;
const MAX_OLM_SESSIONS_PER_PEER: usize = 5;
const STORE_VERSION: u8 = 1;
const PAYLOAD_VERSION: u8 = 1;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum E2eeError {
    #[error("the device id is not set yet (device not enrolled)")]
    NotEnrolled,
    #[error("no outbound session for this conversation; share one first")]
    NoOutboundSession,
    #[error("this device never received the key for this message")]
    UnknownSession,
    #[error("decryption failed")]
    Decrypt,
    #[error("encryption failed")]
    Encrypt,
    #[error("message is bound to a different conversation or sender")]
    Mismatch,
    #[error("malformed message or payload")]
    Malformed,
    #[error("invalid key")]
    InvalidKey,
    #[error("stored crypto state is corrupt or has an unsupported version")]
    Store,
}

pub type E2eeResult<T> = Result<T, E2eeError>;

/// A device that should be able to read a conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecipientDevice {
    pub device_id: Uuid,
    pub identity_key: CurveKey,
}

/// A one-time (or fallback) key claimed from the server for a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimedKey {
    pub device_id: Uuid,
    pub one_time_key: CurveKey,
}

/// Olm ciphertext to send through `POST /v1/to-device`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutgoingToDevice {
    pub device_id: Uuid,
    pub message_type: u8,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct ShareResult {
    /// A new outbound session was created.
    pub rotated: bool,
    pub messages: Vec<OutgoingToDevice>,
    /// Recipients without an Olm session and without a claimed key. They are
    /// served as soon as a key for them is passed to a later call.
    pub missing: Vec<Uuid>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedMessage {
    pub session_id: String,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Received {
    GroupKey { conversation_id: Uuid, session_id: String },
}

/// Olm payload carrying a Megolm session key.
#[derive(Serialize, Deserialize)]
struct KeyShare {
    v: u8,
    conversation_id: Uuid,
    sender_device_id: Uuid,
    session_id: String,
    session_key: String,
}

/// Megolm plaintext: binds the body to conversation and sender device.
#[derive(Serialize, Deserialize)]
struct Envelope {
    v: u8,
    conversation_id: Uuid,
    sender_device_id: Uuid,
    body: B64,
}

struct Outbound {
    session: GroupSession,
    created_at: i64,
    message_count: u32,
    /// Devices the session was created for (excluding this device).
    recipients: BTreeSet<Uuid>,
    /// Recipients that have not received the session key yet.
    pending: BTreeSet<Uuid>,
}

struct Inbound {
    session: InboundGroupSession,
    sender_device_id: Uuid,
    received_at: i64,
}

pub struct CryptoStore {
    device_id: Option<Uuid>,
    account: Account,
    olm_sessions: HashMap<CurveKey, Vec<Session>>,
    outbound: HashMap<Uuid, Outbound>,
    inbound: HashMap<(Uuid, String), Inbound>,
}

impl Default for CryptoStore {
    fn default() -> Self {
        Self::new()
    }
}

impl CryptoStore {
    /// Fresh Olm account. The device id is set after enrollment.
    pub fn new() -> Self {
        Self {
            device_id: None,
            account: Account::new(),
            olm_sessions: HashMap::new(),
            outbound: HashMap::new(),
            inbound: HashMap::new(),
        }
    }

    pub fn set_device_id(&mut self, device_id: Uuid) {
        self.device_id = Some(device_id);
    }

    pub fn device_id(&self) -> Option<Uuid> {
        self.device_id
    }

    fn me(&self) -> E2eeResult<Uuid> {
        self.device_id.ok_or(E2eeError::NotEnrolled)
    }

    /// Curve25519 identity key (`olm_identity_key` on the server).
    pub fn identity_key(&self) -> CurveKey {
        self.account.curve25519_key().to_bytes()
    }

    /// Ed25519 fingerprint key (`olm_fingerprint_key` on the server).
    pub fn fingerprint_key(&self) -> [u8; 32] {
        *self.account.ed25519_key().as_bytes()
    }

    /// Generates `count` one-time keys and returns all unpublished ones as
    /// `(key_id, public_key)`. Call [`Self::mark_keys_published`] after upload.
    pub fn generate_one_time_keys(&mut self, count: usize) -> Vec<(String, CurveKey)> {
        self.account.generate_one_time_keys(count);
        let mut keys: Vec<_> =
            self.account.one_time_keys().into_iter().map(|(id, key)| (id.to_base64(), key.to_bytes())).collect();
        keys.sort();
        keys
    }

    /// Generates a new fallback key and returns it as `(key_id, public_key)`.
    pub fn generate_fallback_key(&mut self) -> Option<(String, CurveKey)> {
        self.account.generate_fallback_key();
        self.account.fallback_key().into_iter().next().map(|(id, key)| (id.to_base64(), key.to_bytes()))
    }

    pub fn mark_keys_published(&mut self) {
        self.account.mark_keys_as_published();
    }

    fn has_olm_session(&self, identity_key: &CurveKey) -> bool {
        self.olm_sessions.get(identity_key).is_some_and(|s| !s.is_empty())
    }

    fn add_olm_session(&mut self, identity_key: CurveKey, session: Session) {
        let sessions = self.olm_sessions.entry(identity_key).or_default();
        sessions.push(session);
        if sessions.len() > MAX_OLM_SESSIONS_PER_PEER {
            sessions.remove(0);
        }
    }

    fn needs_rotation(&self, conversation_id: Uuid, targets: &BTreeSet<Uuid>, now: i64) -> bool {
        match self.outbound.get(&conversation_id) {
            None => true,
            Some(out) => {
                out.message_count >= ROTATION_MESSAGES
                    || now - out.created_at >= ROTATION_SECS
                    || out.recipients != *targets
            }
        }
    }

    fn targets(&self, recipients: &[RecipientDevice]) -> E2eeResult<BTreeSet<Uuid>> {
        let me = self.me()?;
        Ok(recipients.iter().map(|r| r.device_id).filter(|id| *id != me).collect())
    }

    /// Devices for which one-time keys must be claimed before calling
    /// [`Self::share_group_session`] with the same arguments.
    pub fn devices_needing_keys(
        &self,
        conversation_id: Uuid,
        recipients: &[RecipientDevice],
        now: i64,
    ) -> E2eeResult<Vec<Uuid>> {
        let targets = self.targets(recipients)?;
        let rotate = self.needs_rotation(conversation_id, &targets, now);
        let pending = self.outbound.get(&conversation_id).map(|o| &o.pending);
        Ok(recipients
            .iter()
            .filter(|r| targets.contains(&r.device_id) && !self.has_olm_session(&r.identity_key))
            .filter(|r| rotate || pending.is_some_and(|p| p.contains(&r.device_id)))
            .map(|r| r.device_id)
            .collect())
    }

    /// Makes sure all `recipients` (the current devices of all members,
    /// including this account's other devices) can read the next message.
    ///
    /// Rotates the outbound session when it is missing, used up (100
    /// messages / 7 days) or the recipient set changed; otherwise only hands
    /// the current key to recipients that are still pending.
    pub fn share_group_session(
        &mut self,
        conversation_id: Uuid,
        recipients: &[RecipientDevice],
        claimed: &[ClaimedKey],
        now: i64,
    ) -> E2eeResult<ShareResult> {
        let me = self.me()?;
        let targets = self.targets(recipients)?;
        let rotated = self.needs_rotation(conversation_id, &targets, now);

        if rotated {
            let session = GroupSession::new(MegolmConfig::version_1());
            // Inbound copy so this device can read its own messages later.
            let own_copy = InboundGroupSession::new(&session.session_key(), MegolmConfig::version_1());
            self.inbound.insert(
                (conversation_id, session.session_id()),
                Inbound { session: own_copy, sender_device_id: me, received_at: now },
            );
            self.outbound.insert(
                conversation_id,
                Outbound { session, created_at: now, message_count: 0, recipients: targets.clone(), pending: targets },
            );
        }

        let out = self.outbound.get(&conversation_id).expect("outbound session exists");
        let payload = Zeroizing::new(
            serde_json::to_vec(&KeyShare {
                v: PAYLOAD_VERSION,
                conversation_id,
                sender_device_id: me,
                session_id: out.session.session_id(),
                session_key: out.session.session_key().to_base64(),
            })
            .map_err(|_| E2eeError::Encrypt)?,
        );
        let pending = out.pending.clone();

        let mut result = ShareResult { rotated, ..ShareResult::default() };
        for recipient in recipients.iter().filter(|r| pending.contains(&r.device_id)) {
            if !self.has_olm_session(&recipient.identity_key) {
                let Some(claimed) = claimed.iter().find(|c| c.device_id == recipient.device_id) else {
                    result.missing.push(recipient.device_id);
                    continue;
                };
                let session = self
                    .account
                    .create_outbound_session(
                        OlmConfig::version_1(),
                        Curve25519PublicKey::from_bytes(recipient.identity_key),
                        Curve25519PublicKey::from_bytes(claimed.one_time_key),
                    )
                    .map_err(|_| E2eeError::InvalidKey)?;
                self.add_olm_session(recipient.identity_key, session);
            }
            let session = self
                .olm_sessions
                .get_mut(&recipient.identity_key)
                .and_then(|s| s.last_mut())
                .expect("olm session exists");
            let (message_type, ciphertext) = session.encrypt(&*payload).map_err(|_| E2eeError::Encrypt)?.to_parts();
            result.messages.push(OutgoingToDevice {
                device_id: recipient.device_id,
                message_type: message_type as u8,
                ciphertext,
            });
        }

        let out = self.outbound.get_mut(&conversation_id).expect("outbound session exists");
        for message in &result.messages {
            out.pending.remove(&message.device_id);
        }
        Ok(result)
    }

    /// Forces a new outbound session before the next message (e.g. after a
    /// membership change was announced).
    pub fn discard_outbound(&mut self, conversation_id: Uuid) {
        self.outbound.remove(&conversation_id);
    }

    /// Encrypts a message body with the conversation's outbound session.
    pub fn encrypt(&mut self, conversation_id: Uuid, body: &[u8]) -> E2eeResult<EncryptedMessage> {
        let me = self.me()?;
        let out = self.outbound.get_mut(&conversation_id).ok_or(E2eeError::NoOutboundSession)?;
        let envelope = Zeroizing::new(
            serde_json::to_vec(&Envelope {
                v: PAYLOAD_VERSION,
                conversation_id,
                sender_device_id: me,
                body: B64(body.to_vec()),
            })
            .map_err(|_| E2eeError::Encrypt)?,
        );
        let message = out.session.encrypt(&*envelope);
        out.message_count += 1;
        Ok(EncryptedMessage { session_id: out.session.session_id(), ciphertext: message.to_bytes() })
    }

    /// Decrypts a stored message. Can be called any number of times for the
    /// same ciphertext. `sender_device_id` is the sender as reported by the
    /// server; it must match the session owner and the envelope.
    pub fn decrypt(
        &mut self,
        conversation_id: Uuid,
        sender_device_id: Uuid,
        session_id: &str,
        ciphertext: &[u8],
    ) -> E2eeResult<Zeroizing<Vec<u8>>> {
        let inbound =
            self.inbound.get_mut(&(conversation_id, session_id.to_owned())).ok_or(E2eeError::UnknownSession)?;
        if inbound.sender_device_id != sender_device_id {
            return Err(E2eeError::Mismatch);
        }
        let message = MegolmMessage::from_bytes(ciphertext).map_err(|_| E2eeError::Malformed)?;
        let plaintext = Zeroizing::new(inbound.session.decrypt(&message).map_err(|_| E2eeError::Decrypt)?.plaintext);
        let envelope: Envelope = serde_json::from_slice(&plaintext).map_err(|_| E2eeError::Malformed)?;
        if envelope.v != PAYLOAD_VERSION
            || envelope.conversation_id != conversation_id
            || envelope.sender_device_id != sender_device_id
        {
            return Err(E2eeError::Mismatch);
        }
        Ok(Zeroizing::new(envelope.body.0))
    }

    /// Handles a to-device event. `sender_device_id` and `sender_identity_key`
    /// are attached by the server.
    pub fn receive_to_device(
        &mut self,
        sender_device_id: Uuid,
        sender_identity_key: CurveKey,
        message_type: u8,
        ciphertext: &[u8],
        now: i64,
    ) -> E2eeResult<Received> {
        let message = OlmMessage::from_parts(message_type as usize, ciphertext).map_err(|_| E2eeError::Malformed)?;
        let plaintext = Zeroizing::new(self.olm_decrypt(sender_identity_key, &message)?);
        let share: KeyShare = serde_json::from_slice(&plaintext).map_err(|_| E2eeError::Malformed)?;
        if share.v != PAYLOAD_VERSION || share.sender_device_id != sender_device_id {
            return Err(E2eeError::Mismatch);
        }
        let key = SessionKey::from_base64(&share.session_key).map_err(|_| E2eeError::Malformed)?;
        let session = InboundGroupSession::new(&key, MegolmConfig::version_1());
        if session.session_id() != share.session_id {
            return Err(E2eeError::Mismatch);
        }
        // Keep the first copy: it can decrypt from the lowest index.
        self.inbound.entry((share.conversation_id, share.session_id.clone())).or_insert(Inbound {
            session,
            sender_device_id,
            received_at: now,
        });
        Ok(Received::GroupKey { conversation_id: share.conversation_id, session_id: share.session_id })
    }

    fn olm_decrypt(&mut self, identity_key: CurveKey, message: &OlmMessage) -> E2eeResult<Vec<u8>> {
        if let Some(sessions) = self.olm_sessions.get_mut(&identity_key) {
            for session in sessions.iter_mut().rev() {
                if let Ok(plaintext) = session.decrypt(message) {
                    return Ok(plaintext);
                }
            }
        }
        let OlmMessage::PreKey(pre_key) = message else { return Err(E2eeError::Decrypt) };
        let created = self
            .account
            .create_inbound_session(OlmConfig::version_1(), Curve25519PublicKey::from_bytes(identity_key), pre_key)
            .map_err(|_| E2eeError::Decrypt)?;
        self.add_olm_session(identity_key, created.session);
        Ok(created.plaintext)
    }

    /// Drops group sessions that can no longer have messages on the server.
    pub fn prune(&mut self, now: i64) {
        self.inbound.retain(|_, inbound| now - inbound.received_at < MAX_KEY_AGE_SECS);
    }

    /// Serialized state for the key container. Contains secret keys.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let stored = Stored {
            version: STORE_VERSION,
            device_id: self.device_id,
            account: self.account.pickle(),
            olm_sessions: self
                .olm_sessions
                .iter()
                .map(|(key, sessions)| StoredOlm {
                    identity_key: B64(key.to_vec()),
                    sessions: sessions.iter().map(Session::pickle).collect(),
                })
                .collect(),
            outbound: self
                .outbound
                .iter()
                .map(|(conversation_id, out)| StoredOutbound {
                    conversation_id: *conversation_id,
                    session: out.session.pickle(),
                    created_at: out.created_at,
                    message_count: out.message_count,
                    recipients: out.recipients.clone(),
                    pending: out.pending.clone(),
                })
                .collect(),
            inbound: self
                .inbound
                .iter()
                .map(|((conversation_id, _), inbound)| StoredInbound {
                    conversation_id: *conversation_id,
                    session: inbound.session.pickle(),
                    sender_device_id: inbound.sender_device_id,
                    received_at: inbound.received_at,
                })
                .collect(),
        };
        Zeroizing::new(serde_json::to_vec(&stored).expect("crypto state serializes"))
    }

    pub fn from_bytes(bytes: &[u8]) -> E2eeResult<Self> {
        let stored: Stored = serde_json::from_slice(bytes).map_err(|_| E2eeError::Store)?;
        if stored.version != STORE_VERSION {
            return Err(E2eeError::Store);
        }
        let mut olm_sessions = HashMap::new();
        for entry in stored.olm_sessions {
            let key: CurveKey = entry.identity_key.to_array().ok_or(E2eeError::Store)?;
            olm_sessions.insert(key, entry.sessions.into_iter().map(Session::from_pickle).collect());
        }
        let outbound = stored
            .outbound
            .into_iter()
            .map(|o| {
                let out = Outbound {
                    session: GroupSession::from_pickle(o.session),
                    created_at: o.created_at,
                    message_count: o.message_count,
                    recipients: o.recipients,
                    pending: o.pending,
                };
                (o.conversation_id, out)
            })
            .collect();
        let inbound = stored
            .inbound
            .into_iter()
            .map(|i| {
                let session = InboundGroupSession::from_pickle(i.session);
                let key = (i.conversation_id, session.session_id());
                (key, Inbound { session, sender_device_id: i.sender_device_id, received_at: i.received_at })
            })
            .collect();
        Ok(Self {
            device_id: stored.device_id,
            account: Account::from_pickle(stored.account),
            olm_sessions,
            outbound,
            inbound,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct Stored {
    version: u8,
    device_id: Option<Uuid>,
    account: AccountPickle,
    olm_sessions: Vec<StoredOlm>,
    outbound: Vec<StoredOutbound>,
    inbound: Vec<StoredInbound>,
}

#[derive(Serialize, Deserialize)]
struct StoredOlm {
    identity_key: B64,
    sessions: Vec<SessionPickle>,
}

#[derive(Serialize, Deserialize)]
struct StoredOutbound {
    conversation_id: Uuid,
    session: GroupSessionPickle,
    created_at: i64,
    message_count: u32,
    recipients: BTreeSet<Uuid>,
    pending: BTreeSet<Uuid>,
}

#[derive(Serialize, Deserialize)]
struct StoredInbound {
    conversation_id: Uuid,
    session: InboundGroupSessionPickle,
    sender_device_id: Uuid,
    received_at: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;

    struct Dev {
        id: Uuid,
        store: CryptoStore,
        keys: Vec<CurveKey>,
    }

    impl Dev {
        fn new() -> Self {
            let id = Uuid::new_v4();
            let mut store = CryptoStore::new();
            store.set_device_id(id);
            let keys = store.generate_one_time_keys(10).into_iter().map(|(_, k)| k).collect();
            store.mark_keys_published();
            Self { id, store, keys }
        }

        fn recipient(&self) -> RecipientDevice {
            RecipientDevice { device_id: self.id, identity_key: self.store.identity_key() }
        }

        /// Simulates `POST /v1/keys/claim`.
        fn claim(&mut self) -> ClaimedKey {
            ClaimedKey { device_id: self.id, one_time_key: self.keys.remove(0) }
        }
    }

    /// Simulates the server: delivers to-device messages to their targets.
    fn deliver(sender: &Dev, result: &ShareResult, targets: &mut [&mut Dev]) {
        for message in &result.messages {
            let target = targets.iter_mut().find(|d| d.id == message.device_id).expect("known target");
            let received = target
                .store
                .receive_to_device(
                    sender.id,
                    sender.store.identity_key(),
                    message.message_type,
                    &message.ciphertext,
                    NOW,
                )
                .unwrap();
            assert!(matches!(received, Received::GroupKey { .. }));
        }
    }

    #[test]
    fn group_messages_can_be_decrypted_repeatedly_by_all_devices() {
        let conversation = Uuid::new_v4();
        let mut alice1 = Dev::new();
        let mut alice2 = Dev::new();
        let mut bob = Dev::new();
        let recipients = [alice1.recipient(), alice2.recipient(), bob.recipient()];

        let need = alice1.store.devices_needing_keys(conversation, &recipients, NOW).unwrap();
        assert_eq!(need.len(), 2);
        let claimed = [alice2.claim(), bob.claim()];
        let share = alice1.store.share_group_session(conversation, &recipients, &claimed, NOW).unwrap();
        assert!(share.rotated && share.missing.is_empty());
        assert_eq!(share.messages.len(), 2);
        deliver(&alice1, &share, &mut [&mut alice2, &mut bob]);

        let sent = alice1.store.encrypt(conversation, b"hello").unwrap();
        let sender = alice1.id;
        for _ in 0..3 {
            for dev in [&mut alice1, &mut alice2, &mut bob] {
                let plain = dev.store.decrypt(conversation, sender, &sent.session_id, &sent.ciphertext).unwrap();
                assert_eq!(plain.as_slice(), b"hello");
            }
        }
    }

    #[test]
    fn state_survives_serialization() {
        let conversation = Uuid::new_v4();
        let mut alice = Dev::new();
        let mut bob = Dev::new();
        let recipients = [alice.recipient(), bob.recipient()];
        let share = alice.store.share_group_session(conversation, &recipients, &[bob.claim()], NOW).unwrap();
        deliver(&alice, &share, &mut [&mut bob]);
        let first = alice.store.encrypt(conversation, b"one").unwrap();

        alice.store = CryptoStore::from_bytes(&alice.store.to_bytes()).unwrap();
        bob.store = CryptoStore::from_bytes(&bob.store.to_bytes()).unwrap();

        // Same session continues; no re-share needed.
        let again = alice.store.share_group_session(conversation, &recipients, &[], NOW).unwrap();
        assert!(!again.rotated && again.messages.is_empty());
        let second = alice.store.encrypt(conversation, b"two").unwrap();
        assert_eq!(first.session_id, second.session_id);
        for msg in [&first, &second] {
            assert!(bob.store.decrypt(conversation, alice.id, &msg.session_id, &msg.ciphertext).is_ok());
        }
        assert!(CryptoStore::from_bytes(b"{}").is_err());
    }

    #[test]
    fn rotation_by_count_age_and_recipient_change() {
        let conversation = Uuid::new_v4();
        let mut alice = Dev::new();
        let mut bob = Dev::new();
        let recipients = [alice.recipient(), bob.recipient()];
        let share = alice.store.share_group_session(conversation, &recipients, &[bob.claim()], NOW).unwrap();
        deliver(&alice, &share, &mut [&mut bob]);

        for _ in 0..ROTATION_MESSAGES {
            alice.store.encrypt(conversation, b"x").unwrap();
        }
        let share = alice.store.share_group_session(conversation, &recipients, &[], NOW).unwrap();
        assert!(share.rotated, "rotates after {ROTATION_MESSAGES} messages");
        // Existing Olm session is reused: no claimed key needed.
        assert_eq!(share.messages.len(), 1);
        deliver(&alice, &share, &mut [&mut bob]);

        let share = alice.store.share_group_session(conversation, &recipients, &[], NOW + ROTATION_SECS).unwrap();
        assert!(share.rotated, "rotates after 7 days");
        deliver(&alice, &share, &mut [&mut bob]);

        let mut carol = Dev::new();
        let with_carol = [alice.recipient(), bob.recipient(), carol.recipient()];
        let share =
            alice.store.share_group_session(conversation, &with_carol, &[carol.claim()], NOW + ROTATION_SECS).unwrap();
        assert!(share.rotated, "rotates when a device joins");
    }

    #[test]
    fn removed_member_cannot_read_new_messages() {
        let conversation = Uuid::new_v4();
        let mut alice = Dev::new();
        let mut bob = Dev::new();
        let mut carol = Dev::new();
        let all = [alice.recipient(), bob.recipient(), carol.recipient()];
        let share = alice.store.share_group_session(conversation, &all, &[bob.claim(), carol.claim()], NOW).unwrap();
        deliver(&alice, &share, &mut [&mut bob, &mut carol]);
        let old = alice.store.encrypt(conversation, b"before").unwrap();

        let without_carol = [alice.recipient(), bob.recipient()];
        let share = alice.store.share_group_session(conversation, &without_carol, &[], NOW).unwrap();
        assert!(share.rotated);
        deliver(&alice, &share, &mut [&mut bob]);
        let new = alice.store.encrypt(conversation, b"after").unwrap();

        assert_ne!(old.session_id, new.session_id);
        assert!(carol.store.decrypt(conversation, alice.id, &old.session_id, &old.ciphertext).is_ok());
        assert_eq!(
            carol.store.decrypt(conversation, alice.id, &new.session_id, &new.ciphertext).unwrap_err(),
            E2eeError::UnknownSession
        );
        assert!(bob.store.decrypt(conversation, alice.id, &new.session_id, &new.ciphertext).is_ok());
    }

    #[test]
    fn missing_device_is_served_later_without_rotation() {
        let conversation = Uuid::new_v4();
        let mut alice = Dev::new();
        let mut bob = Dev::new();
        let recipients = [alice.recipient(), bob.recipient()];

        let share = alice.store.share_group_session(conversation, &recipients, &[], NOW).unwrap();
        assert_eq!(share.missing, [bob.id]);
        let msg = alice.store.encrypt(conversation, b"hi").unwrap();

        assert_eq!(alice.store.devices_needing_keys(conversation, &recipients, NOW).unwrap(), [bob.id]);
        let share = alice.store.share_group_session(conversation, &recipients, &[bob.claim()], NOW).unwrap();
        assert!(!share.rotated && share.messages.len() == 1);
        deliver(&alice, &share, &mut [&mut bob]);
        // The key is shared at its current index, so earlier messages stay unreadable.
        assert_eq!(
            bob.store.decrypt(conversation, alice.id, &msg.session_id, &msg.ciphertext).unwrap_err(),
            E2eeError::Decrypt
        );
        let later = alice.store.encrypt(conversation, b"now").unwrap();
        assert_eq!(
            bob.store.decrypt(conversation, alice.id, &later.session_id, &later.ciphertext).unwrap().as_slice(),
            b"now"
        );
        assert!(alice.store.devices_needing_keys(conversation, &recipients, NOW).unwrap().is_empty());
    }

    #[test]
    fn ciphertexts_are_bound_to_conversation_and_sender() {
        let conversation = Uuid::new_v4();
        let mut alice = Dev::new();
        let mut bob = Dev::new();
        let recipients = [alice.recipient(), bob.recipient()];
        let share = alice.store.share_group_session(conversation, &recipients, &[bob.claim()], NOW).unwrap();
        deliver(&alice, &share, &mut [&mut bob]);
        let msg = alice.store.encrypt(conversation, b"secret").unwrap();

        assert_eq!(
            bob.store.decrypt(Uuid::new_v4(), alice.id, &msg.session_id, &msg.ciphertext).unwrap_err(),
            E2eeError::UnknownSession
        );
        assert_eq!(
            bob.store.decrypt(conversation, Uuid::new_v4(), &msg.session_id, &msg.ciphertext).unwrap_err(),
            E2eeError::Mismatch
        );
        let mut tampered = msg.ciphertext.clone();
        tampered[10] ^= 1;
        assert!(bob.store.decrypt(conversation, alice.id, &msg.session_id, &tampered).is_err());

        // A forged key share claiming another sender device is rejected.
        let mut other = Dev::new();
        let recipients = [other.recipient(), bob.recipient()];
        let share = other.store.share_group_session(conversation, &recipients, &[bob.claim()], NOW).unwrap();
        let message = &share.messages[0];
        let err = bob
            .store
            .receive_to_device(alice.id, other.store.identity_key(), message.message_type, &message.ciphertext, NOW)
            .unwrap_err();
        assert_eq!(err, E2eeError::Mismatch);
    }

    #[test]
    fn prune_drops_old_group_sessions() {
        let conversation = Uuid::new_v4();
        let mut alice = Dev::new();
        let mut bob = Dev::new();
        let recipients = [alice.recipient(), bob.recipient()];
        let share = alice.store.share_group_session(conversation, &recipients, &[bob.claim()], NOW).unwrap();
        deliver(&alice, &share, &mut [&mut bob]);
        let msg = alice.store.encrypt(conversation, b"old").unwrap();
        bob.store.prune(NOW + MAX_KEY_AGE_SECS);
        assert_eq!(
            bob.store.decrypt(conversation, alice.id, &msg.session_id, &msg.ciphertext).unwrap_err(),
            E2eeError::UnknownSession
        );
    }
}

//! Byte strings that devices and admins sign (TDD §5.3, §10.2).
//!
//! Every message is `domain || (u32le len || field)*`, so field boundaries are
//! unambiguous and messages for different purposes can never collide.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use uuid::Uuid;

pub const ENROLL_DOMAIN: &[u8] = b"ssm-enroll-v1";
pub const DEVICE_AUTH_DOMAIN: &[u8] = b"ssm-auth-v1";
pub const ADMIN_AUTH_DOMAIN: &[u8] = b"ssm-admin-auth-v1";
pub const ADMIN_CONFIRM_DOMAIN: &[u8] = b"ssm-admin-confirm-v1";

fn framed(domain: &[u8], fields: &[&[u8]]) -> Vec<u8> {
    let mut out = domain.to_vec();
    for field in fields {
        out.extend_from_slice(&(field.len() as u32).to_le_bytes());
        out.extend_from_slice(field);
    }
    out
}

/// Proof of possession during enrollment; binds all submitted public keys.
pub fn enroll_message(
    nonce: &[u8],
    signing_key: &[u8],
    olm_identity_key: &[u8],
    olm_fingerprint_key: &[u8],
) -> Vec<u8> {
    framed(ENROLL_DOMAIN, &[nonce, signing_key, olm_identity_key, olm_fingerprint_key])
}

pub fn device_auth_message(nonce: &[u8], device_id: Uuid) -> Vec<u8> {
    framed(DEVICE_AUTH_DOMAIN, &[nonce, device_id.as_bytes()])
}

pub fn admin_auth_message(nonce: &[u8], admin_key_id: Uuid) -> Vec<u8> {
    framed(ADMIN_AUTH_DOMAIN, &[nonce, admin_key_id.as_bytes()])
}

/// Fresh confirmation for a destructive admin action on `target`.
pub fn admin_confirm_message(nonce: &[u8], action: &str, target: &str) -> Vec<u8> {
    framed(ADMIN_CONFIRM_DOMAIN, &[nonce, action.as_bytes(), target.as_bytes()])
}

pub fn sign(key: &SigningKey, message: &[u8]) -> [u8; 64] {
    key.sign(message).to_bytes()
}

/// Strict Ed25519 verification. Returns false for malformed keys or signatures.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(public_key) = <[u8; 32]>::try_from(public_key) else { return false };
    let Ok(key) = VerifyingKey::from_bytes(&public_key) else { return false };
    let Ok(signature) = Signature::from_slice(signature) else { return false };
    key.verify_strict(message, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_and_domain_separation() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let public = key.verifying_key().to_bytes();
        let id = Uuid::from_bytes([1; 16]);
        let msg = device_auth_message(b"nonce", id);
        let sig = sign(&key, &msg);
        assert!(verify(&public, &msg, &sig));
        assert!(!verify(&public, &admin_auth_message(b"nonce", id), &sig));
        assert!(!verify(&public[..31], &msg, &sig));
        assert!(!verify(&public, &msg, &sig[..63]));
    }

    #[test]
    fn framing_prevents_field_shifting() {
        assert_ne!(admin_confirm_message(b"n", "ab", "c"), admin_confirm_message(b"n", "a", "bc"));
    }
}

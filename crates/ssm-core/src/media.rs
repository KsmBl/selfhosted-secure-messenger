//! Media encryption (FR-011): every object (original or preview) gets its own
//! random 256-bit key and is sealed with XChaCha20-Poly1305 in one piece.
//! The key travels inside the Megolm-encrypted message, the server only
//! stores `nonce || ciphertext`.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

const NONCE_LEN: usize = 24;
/// Associated data: binds ciphertexts to this format.
const AD: &[u8] = b"ssm/media/v1";

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum MediaError {
    #[error("system random number generator failed")]
    Rng,
    #[error("the media data is damaged or the key does not match")]
    Decrypt,
}

/// Encrypts `plaintext` with a fresh key. Returns `(key, nonce || ciphertext)`.
pub fn encrypt(plaintext: &[u8]) -> Result<(Zeroizing<[u8; 32]>, Vec<u8>), MediaError> {
    let mut key = Zeroizing::new([0u8; 32]);
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(key.as_mut()).map_err(|_| MediaError::Rng)?;
    getrandom::fill(&mut nonce).map_err(|_| MediaError::Rng)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| MediaError::Rng)?;
    let sealed = cipher
        .encrypt(&XNonce::from(nonce), chacha20poly1305::aead::Payload { msg: plaintext, aad: AD })
        .map_err(|_| MediaError::Rng)?;
    let mut out = Vec::with_capacity(NONCE_LEN + sealed.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    Ok((key, out))
}

pub fn decrypt(key: &[u8; 32], data: &[u8]) -> Result<Zeroizing<Vec<u8>>, MediaError> {
    if data.len() < NONCE_LEN + 16 {
        return Err(MediaError::Decrypt);
    }
    let (nonce, sealed) = data.split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| MediaError::Decrypt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| MediaError::Decrypt)?;
    cipher
        .decrypt(&XNonce::from(nonce), chacha20poly1305::aead::Payload { msg: sealed, aad: AD })
        .map(Zeroizing::new)
        .map_err(|_| MediaError::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_tamper_detection() {
        let (key, sealed) = encrypt(b"picture bytes").unwrap();
        assert_eq!(decrypt(&key, &sealed).unwrap().as_slice(), b"picture bytes");
        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(decrypt(&key, &tampered).unwrap_err(), MediaError::Decrypt);
        let (other_key, _) = encrypt(b"x").unwrap();
        assert_eq!(decrypt(&other_key, &sealed).unwrap_err(), MediaError::Decrypt);
        assert_eq!(decrypt(&key, &sealed[..10]).unwrap_err(), MediaError::Decrypt);
    }

    #[test]
    fn same_content_gives_different_ciphertexts() {
        let (_, a) = encrypt(b"same").unwrap();
        let (_, b) = encrypt(b"same").unwrap();
        assert_ne!(a, b);
    }
}

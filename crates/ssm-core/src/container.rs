//! Pattern-protected local key container (ADR-0005, TDD §4.3).
//!
//! ```text
//! k_pattern = Argon2id(pattern.encode(), salt, m, t, p)
//! KEK       = HKDF-SHA256(ikm = k_pattern || hw, salt = salt, info = "ssm/kek/v1")
//! MEK       = random 256 bit, wrapped with XChaCha20-Poly1305 under KEK
//! payload   = XChaCha20-Poly1305 under MEK
//! ```
//!
//! Byte layout:
//!
//! ```text
//! header  = "SSMC" | version u8 | flags u8 | m_kib u32le | t u32le | p u32le | salt [16]
//! wrapped = nonce [24] | ciphertext(MEK) [32 + 16]
//! payload = nonce [24] | ciphertext(plaintext) [n + 16]
//! ```
//!
//! The header is authenticated as associated data for both ciphertexts.

use std::time::{Duration, Instant};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::pattern::Pattern;

const MAGIC: &[u8; 4] = b"SSMC";
const VERSION: u8 = 1;
const FLAG_HARDWARE: u8 = 0b0000_0001;
const SALT_LEN: usize = 16;
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = 4 + 1 + 1 + 4 + 4 + 4 + SALT_LEN;
const WRAPPED_LEN: usize = NONCE_LEN + KEY_LEN + TAG_LEN;
const KEK_INFO: &[u8] = b"ssm/kek/v1";
const AD_MEK: &[u8] = b"ssm/mek";
const AD_PAYLOAD: &[u8] = b"ssm/payload";

/// 32-byte secret provided by hardware key storage (Android Keystore, TPM2).
pub type HardwareSecret = Zeroizing<[u8; KEY_LEN]>;

#[derive(Debug, thiserror::Error)]
pub enum ContainerError {
    #[error("wrong pattern or corrupted container")]
    Unlock,
    #[error("container is malformed")]
    Malformed,
    #[error("unsupported container version {0}")]
    UnsupportedVersion(u8),
    #[error("container is hardware-bound but no hardware secret was provided")]
    HardwareSecretRequired,
    #[error("KDF parameters are outside the allowed range")]
    InvalidKdfParams,
    #[error("encryption failed")]
    Encrypt,
    #[error("system random number generator failed")]
    Rng,
}

/// Argon2id parameters. Memory is given in KiB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl KdfParams {
    /// Lower bound from ADR-0005: 64 MiB, 3 passes.
    pub const MIN: Self = Self { m_kib: 64 * 1024, t: 3, p: 1 };
    /// Upper bound to reject absurd headers (and memory exhaustion) on open.
    pub const MAX: Self = Self { m_kib: 2 * 1024 * 1024, t: 64, p: 8 };
    const CALIBRATION_MAX_M_KIB: u32 = 256 * 1024;

    fn is_allowed(&self) -> bool {
        (Self::MIN.m_kib..=Self::MAX.m_kib).contains(&self.m_kib)
            && (Self::MIN.t..=Self::MAX.t).contains(&self.t)
            && (Self::MIN.p..=Self::MAX.p).contains(&self.p)
    }

    /// Picks parameters so that one derivation takes roughly `target` on this
    /// device: memory is raised first (up to 256 MiB), then the pass count.
    pub fn calibrate(target: Duration) -> Result<Self, ContainerError> {
        let mut params = Self::MIN;
        loop {
            let elapsed = time_derivation(params)?;
            if elapsed >= target {
                return Ok(params);
            }
            if params.m_kib < Self::CALIBRATION_MAX_M_KIB {
                params.m_kib = (params.m_kib * 2).min(Self::CALIBRATION_MAX_M_KIB);
                continue;
            }
            let factor = target.as_secs_f64() / elapsed.as_secs_f64().max(1e-3);
            params.t = ((params.t as f64 * factor).ceil() as u32).clamp(Self::MIN.t, Self::MAX.t);
            return Ok(params);
        }
    }
}

fn time_derivation(params: KdfParams) -> Result<Duration, ContainerError> {
    let pattern = Pattern::new(vec![0, 6, 12, 18, 7, 13]).expect("calibration pattern is valid");
    let start = Instant::now();
    argon2_derive(&pattern, &[0u8; SALT_LEN], params)?;
    Ok(start.elapsed())
}

#[derive(Clone, Copy)]
struct Header {
    hardware_bound: bool,
    params: KdfParams,
    salt: [u8; SALT_LEN],
}

impl Header {
    fn to_bytes(self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0..4].copy_from_slice(MAGIC);
        out[4] = VERSION;
        out[5] = if self.hardware_bound { FLAG_HARDWARE } else { 0 };
        out[6..10].copy_from_slice(&self.params.m_kib.to_le_bytes());
        out[10..14].copy_from_slice(&self.params.t.to_le_bytes());
        out[14..18].copy_from_slice(&self.params.p.to_le_bytes());
        out[18..].copy_from_slice(&self.salt);
        out
    }

    fn parse(bytes: &[u8]) -> Result<Self, ContainerError> {
        if bytes.len() < HEADER_LEN || &bytes[0..4] != MAGIC {
            return Err(ContainerError::Malformed);
        }
        if bytes[4] != VERSION {
            return Err(ContainerError::UnsupportedVersion(bytes[4]));
        }
        if bytes[5] & !FLAG_HARDWARE != 0 {
            return Err(ContainerError::Malformed);
        }
        let u32_at = |i: usize| u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap());
        let params = KdfParams { m_kib: u32_at(6), t: u32_at(10), p: u32_at(14) };
        if !params.is_allowed() {
            return Err(ContainerError::InvalidKdfParams);
        }
        Ok(Self {
            hardware_bound: bytes[5] & FLAG_HARDWARE != 0,
            params,
            salt: bytes[18..HEADER_LEN].try_into().unwrap(),
        })
    }

    fn associated_data(&self, domain: &[u8]) -> Vec<u8> {
        let mut ad = self.to_bytes().to_vec();
        ad.extend_from_slice(domain);
        ad
    }
}

/// An opened container. Holds the MEK in memory until dropped.
pub struct UnlockedContainer {
    header: Header,
    wrapped_mek: [u8; WRAPPED_LEN],
    mek: Zeroizing<[u8; KEY_LEN]>,
}

impl std::fmt::Debug for UnlockedContainer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnlockedContainer")
            .field("hardware_bound", &self.header.hardware_bound)
            .field("params", &self.header.params)
            .finish_non_exhaustive()
    }
}

impl UnlockedContainer {
    /// Creates a new container with a fresh random MEK.
    pub fn create(
        pattern: &Pattern,
        params: KdfParams,
        hardware: Option<&HardwareSecret>,
    ) -> Result<Self, ContainerError> {
        let mut mek = Zeroizing::new([0u8; KEY_LEN]);
        fill_random(mek.as_mut())?;
        let (header, wrapped_mek) = wrap_mek(&mek, pattern, params, hardware)?;
        Ok(Self { header, wrapped_mek, mek })
    }

    /// Opens a sealed container and returns it together with its plaintext.
    pub fn open(
        sealed: &[u8],
        pattern: &Pattern,
        hardware: Option<&HardwareSecret>,
    ) -> Result<(Self, Zeroizing<Vec<u8>>), ContainerError> {
        let header = Header::parse(sealed)?;
        if sealed.len() < HEADER_LEN + WRAPPED_LEN + NONCE_LEN + TAG_LEN {
            return Err(ContainerError::Malformed);
        }
        let hardware = match (header.hardware_bound, hardware) {
            (true, None) => return Err(ContainerError::HardwareSecretRequired),
            (true, Some(hw)) => Some(hw),
            (false, _) => None,
        };

        let wrapped_mek: [u8; WRAPPED_LEN] = sealed[HEADER_LEN..HEADER_LEN + WRAPPED_LEN].try_into().unwrap();
        let kek = derive_kek(pattern, &header, hardware)?;
        let mek_bytes = Zeroizing::new(
            decrypt(&kek, &wrapped_mek, &header.associated_data(AD_MEK)).map_err(|_| ContainerError::Unlock)?,
        );
        let mek =
            Zeroizing::new(<[u8; KEY_LEN]>::try_from(mek_bytes.as_slice()).map_err(|_| ContainerError::Malformed)?);

        let payload = &sealed[HEADER_LEN + WRAPPED_LEN..];
        let plaintext = Zeroizing::new(
            decrypt(&mek, payload, &header.associated_data(AD_PAYLOAD)).map_err(|_| ContainerError::Malformed)?,
        );
        Ok((Self { header, wrapped_mek, mek }, plaintext))
    }

    /// Encrypts `plaintext` as the new container content.
    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, ContainerError> {
        let mut out = Vec::with_capacity(HEADER_LEN + WRAPPED_LEN + NONCE_LEN + plaintext.len() + TAG_LEN);
        out.extend_from_slice(&self.header.to_bytes());
        out.extend_from_slice(&self.wrapped_mek);
        out.extend_from_slice(&encrypt(&self.mek, plaintext, &self.header.associated_data(AD_PAYLOAD))?);
        Ok(out)
    }

    /// Re-wraps the MEK under a new pattern (and fresh salt). Call `seal`
    /// afterwards to persist the change.
    pub fn change_pattern(
        &mut self,
        pattern: &Pattern,
        params: KdfParams,
        hardware: Option<&HardwareSecret>,
    ) -> Result<(), ContainerError> {
        let (header, wrapped_mek) = wrap_mek(&self.mek, pattern, params, hardware)?;
        self.header = header;
        self.wrapped_mek = wrapped_mek;
        Ok(())
    }

    pub fn is_hardware_bound(&self) -> bool {
        self.header.hardware_bound
    }

    pub fn kdf_params(&self) -> KdfParams {
        self.header.params
    }
}

fn wrap_mek(
    mek: &[u8; KEY_LEN],
    pattern: &Pattern,
    params: KdfParams,
    hardware: Option<&HardwareSecret>,
) -> Result<(Header, [u8; WRAPPED_LEN]), ContainerError> {
    if !params.is_allowed() {
        return Err(ContainerError::InvalidKdfParams);
    }
    let mut salt = [0u8; SALT_LEN];
    fill_random(&mut salt)?;
    let header = Header { hardware_bound: hardware.is_some(), params, salt };
    let kek = derive_kek(pattern, &header, hardware)?;
    let wrapped = encrypt(&kek, mek, &header.associated_data(AD_MEK))?;
    Ok((header, wrapped.try_into().map_err(|_| ContainerError::Encrypt)?))
}

fn argon2_derive(
    pattern: &Pattern,
    salt: &[u8],
    params: KdfParams,
) -> Result<Zeroizing<[u8; KEY_LEN]>, ContainerError> {
    let argon_params =
        Params::new(params.m_kib, params.t, params.p, Some(KEY_LEN)).map_err(|_| ContainerError::InvalidKdfParams)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon.hash_password_into(&pattern.encode(), salt, out.as_mut()).map_err(|_| ContainerError::InvalidKdfParams)?;
    Ok(out)
}

fn derive_kek(
    pattern: &Pattern,
    header: &Header,
    hardware: Option<&HardwareSecret>,
) -> Result<Zeroizing<[u8; KEY_LEN]>, ContainerError> {
    let k_pattern = argon2_derive(pattern, &header.salt, header.params)?;
    let mut ikm = Zeroizing::new(Vec::with_capacity(2 * KEY_LEN));
    ikm.extend_from_slice(k_pattern.as_ref());
    if let Some(hw) = hardware {
        ikm.extend_from_slice(hw.as_ref());
    }
    let mut kek = Zeroizing::new([0u8; KEY_LEN]);
    Hkdf::<Sha256>::new(Some(&header.salt), &ikm)
        .expand(KEK_INFO, kek.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    Ok(kek)
}

fn encrypt(key: &[u8; KEY_LEN], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, ContainerError> {
    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut nonce)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| ContainerError::Encrypt)?;
    let ciphertext =
        cipher.encrypt(&XNonce::from(nonce), Payload { msg: plaintext, aad }).map_err(|_| ContainerError::Encrypt)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn decrypt(key: &[u8; KEY_LEN], data: &[u8], aad: &[u8]) -> Result<Vec<u8>, ContainerError> {
    if data.len() < NONCE_LEN + TAG_LEN {
        return Err(ContainerError::Malformed);
    }
    let (nonce, ciphertext) = data.split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce.try_into().unwrap();
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| ContainerError::Malformed)?;
    cipher.decrypt(&XNonce::from(nonce), Payload { msg: ciphertext, aad }).map_err(|_| ContainerError::Unlock)
}

fn fill_random(buf: &mut [u8]) -> Result<(), ContainerError> {
    getrandom::fill(buf).map_err(|_| ContainerError::Rng)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern(dots: &[u8]) -> Pattern {
        Pattern::new(dots.to_vec()).unwrap()
    }

    fn hw(byte: u8) -> HardwareSecret {
        Zeroizing::new([byte; KEY_LEN])
    }

    #[test]
    fn roundtrip_without_hardware() {
        let p = pattern(&[0, 6, 12, 18, 7, 7]);
        let c = UnlockedContainer::create(&p, KdfParams::MIN, None).unwrap();
        let sealed = c.seal(b"olm account + megolm keys").unwrap();
        let (opened, plaintext) = UnlockedContainer::open(&sealed, &p, None).unwrap();
        assert_eq!(plaintext.as_slice(), b"olm account + megolm keys");
        assert!(!opened.is_hardware_bound());
        assert_eq!(opened.kdf_params(), KdfParams::MIN);
    }

    #[test]
    fn wrong_pattern_fails() {
        let c = UnlockedContainer::create(&pattern(&[0, 6, 12, 18, 7, 7]), KdfParams::MIN, None).unwrap();
        let sealed = c.seal(b"secret").unwrap();
        let err = UnlockedContainer::open(&sealed, &pattern(&[0, 6, 12, 18, 7, 8]), None).unwrap_err();
        assert!(matches!(err, ContainerError::Unlock));
    }

    #[test]
    fn hardware_secret_is_required_and_checked() {
        let p = pattern(&[1, 7, 13, 19, 8, 2]);
        let c = UnlockedContainer::create(&p, KdfParams::MIN, Some(&hw(1))).unwrap();
        let sealed = c.seal(b"secret").unwrap();
        assert!(matches!(
            UnlockedContainer::open(&sealed, &p, None).unwrap_err(),
            ContainerError::HardwareSecretRequired
        ));
        assert!(matches!(UnlockedContainer::open(&sealed, &p, Some(&hw(2))).unwrap_err(), ContainerError::Unlock));
        let (_, plaintext) = UnlockedContainer::open(&sealed, &p, Some(&hw(1))).unwrap();
        assert_eq!(plaintext.as_slice(), b"secret");
    }

    #[test]
    fn tampered_header_or_payload_is_rejected() {
        let p = pattern(&[0, 6, 12, 18, 7, 7]);
        let sealed = UnlockedContainer::create(&p, KdfParams::MIN, None).unwrap().seal(b"secret").unwrap();

        let mut salt_flip = sealed.clone();
        salt_flip[HEADER_LEN - 1] ^= 1;
        assert!(matches!(UnlockedContainer::open(&salt_flip, &p, None).unwrap_err(), ContainerError::Unlock));

        let mut payload_flip = sealed.clone();
        *payload_flip.last_mut().unwrap() ^= 1;
        assert!(UnlockedContainer::open(&payload_flip, &p, None).is_err());

        let mut weak = sealed.clone();
        weak[10..14].copy_from_slice(&1u32.to_le_bytes());
        assert!(matches!(UnlockedContainer::open(&weak, &p, None).unwrap_err(), ContainerError::InvalidKdfParams));

        assert!(matches!(UnlockedContainer::open(&sealed[..40], &p, None).unwrap_err(), ContainerError::Malformed));
    }

    #[test]
    fn change_pattern_keeps_mek_and_content() {
        let old = pattern(&[0, 6, 12, 18, 7, 7]);
        let new = pattern(&[24, 18, 12, 11, 10, 5]);
        let mut c = UnlockedContainer::create(&old, KdfParams::MIN, None).unwrap();
        c.change_pattern(&new, KdfParams::MIN, None).unwrap();
        let sealed = c.seal(b"keys").unwrap();
        assert!(UnlockedContainer::open(&sealed, &old, None).is_err());
        let (reopened, plaintext) = UnlockedContainer::open(&sealed, &new, None).unwrap();
        assert_eq!(plaintext.as_slice(), b"keys");
        assert_eq!(*reopened.mek, *c.mek);
    }

    #[test]
    fn rejects_params_below_minimum_on_create() {
        let weak = KdfParams { m_kib: 1024, t: 1, p: 1 };
        assert!(matches!(
            UnlockedContainer::create(&pattern(&[0, 6, 12, 18, 7, 7]), weak, None),
            Err(ContainerError::InvalidKdfParams)
        ));
    }
}

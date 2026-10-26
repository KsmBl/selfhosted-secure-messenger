//! Random tokens, nonces and invite codes. Only hashes are persisted.

use data_encoding::BASE32_NOPAD;
use sha2::{Digest, Sha256};
use ssm_proto::B64;

pub const NONCE_LEN: usize = 32;

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).expect("system random number generator failed");
    out
}

pub fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

/// Returns `(token, sha256(token))` for a new bearer token.
pub fn new_token() -> (String, Vec<u8>) {
    let token = B64::encode(&random_bytes::<32>());
    let hash = sha256(token.as_bytes());
    (token, hash)
}

pub fn token_hash(token: &str) -> Vec<u8> {
    sha256(token.as_bytes())
}

/// 128-bit invite code, Base32 in groups of four: `ABCD-EFGH-...`.
pub fn new_invite_code() -> (String, Vec<u8>) {
    let raw = BASE32_NOPAD.encode(&random_bytes::<16>());
    let grouped = raw.as_bytes().chunks(4).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join("-");
    let hash = invite_code_hash(&grouped);
    (grouped, hash)
}

/// Hash of the normalized code: case, dashes and whitespace are ignored.
pub fn invite_code_hash(code: &str) -> Vec<u8> {
    let normalized: String =
        code.chars().filter(|c| !c.is_whitespace() && *c != '-').map(|c| c.to_ascii_uppercase()).collect();
    sha256(normalized.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_code_normalization() {
        let (code, hash) = new_invite_code();
        assert_eq!(code.replace('-', "").len(), 26);
        assert_eq!(invite_code_hash(&code.to_lowercase().replace('-', " ")), hash);
    }
}

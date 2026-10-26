//! Binary values on the wire are base64url without padding.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, PartialEq, Eq)]
pub struct B64(pub Vec<u8>);

impl B64 {
    pub fn encode(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    pub fn decode(text: &str) -> Option<Vec<u8>> {
        URL_SAFE_NO_PAD.decode(text).ok()
    }

    /// Returns the value as a fixed-size array, or `None` on length mismatch.
    pub fn to_array<const N: usize>(&self) -> Option<[u8; N]> {
        self.0.as_slice().try_into().ok()
    }
}

impl From<&[u8]> for B64 {
    fn from(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }
}

impl std::fmt::Debug for B64 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "B64({})", Self::encode(&self.0))
    }
}

impl Serialize for B64 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&Self::encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for B64 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::decode(&text).map(Self).ok_or_else(|| serde::de::Error::custom("invalid base64url"))
    }
}

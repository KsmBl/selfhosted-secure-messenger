//! On-disk profile of one device. Contains no message content.
//!
//! ```text
//! <dir>/profile.json   server URL, device/account ids, event cursor (no secrets)
//! <dir>/device.key     Ed25519 device signing key (mode 0600). Usable while the
//!                      app is locked, so push wake-ups can be handled (ADR-0008).
//! <dir>/keys.ssmc      pattern-protected container with the Olm/Megolm state
//! ```
//!
//! All writes go through a temporary file and an atomic rename.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use ssm_proto::B64;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::{ClientError, ClientResult};

const PROFILE_FILE: &str = "profile.json";
const DEVICE_KEY_FILE: &str = "device.key";
const CONTAINER_FILE: &str = "keys.ssmc";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileData {
    pub server_url: String,
    pub username: Option<String>,
    pub display_name: String,
    pub device_id: Option<Uuid>,
    pub account_id: Option<Uuid>,
    /// Last acknowledged event sequence.
    #[serde(default)]
    pub event_cursor: i64,
    /// Consecutive wrong unlock patterns (drives the delay policy). Stored in
    /// a plain file, so it only slows down attempts on this device.
    #[serde(default)]
    pub failed_unlocks: u32,
}

pub struct Profile {
    dir: PathBuf,
}

fn write_private(path: &Path, bytes: &[u8]) -> ClientResult<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut file = fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

impl Profile {
    /// Opens (and creates with mode 0700) a profile directory.
    pub fn at(dir: impl Into<PathBuf>) -> ClientResult<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        Ok(Self { dir })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn exists(&self) -> bool {
        self.dir.join(PROFILE_FILE).exists() && self.dir.join(CONTAINER_FILE).exists()
    }

    pub fn load(&self) -> ClientResult<ProfileData> {
        let bytes = fs::read(self.dir.join(PROFILE_FILE))?;
        serde_json::from_slice(&bytes).map_err(|e| ClientError::Profile(e.to_string()))
    }

    pub fn save(&self, data: &ProfileData) -> ClientResult<()> {
        let bytes = serde_json::to_vec_pretty(data).map_err(|e| ClientError::Profile(e.to_string()))?;
        write_private(&self.dir.join(PROFILE_FILE), &bytes)
    }

    pub fn load_device_key(&self) -> ClientResult<SigningKey> {
        let text = Zeroizing::new(fs::read_to_string(self.dir.join(DEVICE_KEY_FILE))?);
        let bytes = Zeroizing::new(B64::decode(text.trim()).ok_or_else(|| ClientError::Profile("device key".into()))?);
        let secret: [u8; 32] =
            bytes.as_slice().try_into().map_err(|_| ClientError::Profile("device key length".into()))?;
        Ok(SigningKey::from_bytes(&secret))
    }

    pub fn save_device_key(&self, key: &SigningKey) -> ClientResult<()> {
        let encoded = Zeroizing::new(B64::encode(&key.to_bytes()));
        write_private(&self.dir.join(DEVICE_KEY_FILE), encoded.as_bytes())
    }

    pub fn load_container(&self) -> ClientResult<Vec<u8>> {
        Ok(fs::read(self.dir.join(CONTAINER_FILE))?)
    }

    pub fn save_container(&self, sealed: &[u8]) -> ClientResult<()> {
        write_private(&self.dir.join(CONTAINER_FILE), sealed)
    }
}

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

const LOCK_FILE: &str = ".lock";
const PROFILES_DIR: &str = "profiles";

/// Exclusive lock on a profile directory, held while a client uses it. Two
/// processes writing the same key container would corrupt the Olm state.
/// The OS releases the lock when the file is closed (also on crash).
#[derive(Debug)]
pub struct ProfileLock {
    _file: fs::File,
}

impl ProfileLock {
    pub fn acquire(dir: &Path) -> ClientResult<Self> {
        let file =
            fs::OpenOptions::new().create(true).truncate(false).write(true).mode(0o600).open(dir.join(LOCK_FILE))?;
        match file.try_lock() {
            Ok(()) => Ok(Self { _file: file }),
            Err(fs::TryLockError::WouldBlock) => Err(ClientError::ProfileInUse),
            Err(fs::TryLockError::Error(err)) => Err(err.into()),
        }
    }

    /// True if another process (or this one) currently holds the lock.
    pub fn is_held(dir: &Path) -> bool {
        match Self::acquire(dir) {
            Ok(_) => false,
            Err(ClientError::ProfileInUse) => true,
            Err(_) => false,
        }
    }
}

/// One account on this computer, as shown in the account picker.
#[derive(Debug, Clone)]
pub struct ProfileSummary {
    pub dir: PathBuf,
    pub data: ProfileData,
    pub in_use: bool,
}

impl ProfileSummary {
    pub fn label(&self) -> String {
        format!(
            "{} — {} ({})",
            self.data.username.as_deref().unwrap_or("(not approved yet)"),
            self.data.server_url,
            self.data.display_name
        )
    }
}

/// All profiles (accounts) of this computer: `<base>/profiles/<id>/`.
pub struct ProfileStore {
    base: PathBuf,
}

impl ProfileStore {
    /// Opens the store; moves a single-profile layout (files directly in
    /// `base`, used before multi-account support) into `profiles/`.
    pub fn open(base: impl Into<PathBuf>) -> ClientResult<Self> {
        let store = Self { base: base.into() };
        Profile::at(&store.base)?;
        Profile::at(store.base.join(PROFILES_DIR))?;
        if store.base.join(PROFILE_FILE).exists() {
            let target = store.new_profile_dir()?;
            for name in [PROFILE_FILE, DEVICE_KEY_FILE, CONTAINER_FILE] {
                let from = store.base.join(name);
                if from.exists() {
                    fs::rename(from, target.join(name))?;
                }
            }
        }
        Ok(store)
    }

    pub fn base(&self) -> &Path {
        &self.base
    }

    /// Complete profiles, sorted by username.
    pub fn list(&self) -> ClientResult<Vec<ProfileSummary>> {
        let mut profiles = Vec::new();
        for entry in fs::read_dir(self.base.join(PROFILES_DIR))? {
            let dir = entry?.path();
            let profile = Profile { dir: dir.clone() };
            if !dir.is_dir() || !profile.exists() {
                continue;
            }
            if let Ok(data) = profile.load() {
                profiles.push(ProfileSummary { in_use: ProfileLock::is_held(&dir), dir, data });
            }
        }
        profiles.sort_by(|a, b| a.data.username.cmp(&b.data.username).then(a.dir.cmp(&b.dir)));
        Ok(profiles)
    }

    /// A fresh, empty profile directory.
    pub fn new_profile_dir(&self) -> ClientResult<PathBuf> {
        let dir = self.base.join(PROFILES_DIR).join(uuid::Uuid::new_v4().to_string());
        Profile::at(&dir)?;
        Ok(dir)
    }

    /// Deletes a profile directory (keys included). Only inside this store.
    pub fn remove(&self, dir: &Path) -> ClientResult<()> {
        let profiles = fs::canonicalize(self.base.join(PROFILES_DIR))?;
        let dir = fs::canonicalize(dir)?;
        if dir.parent() != Some(profiles.as_path()) {
            return Err(ClientError::Profile("not a profile of this store".into()));
        }
        fs::remove_dir_all(dir)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(username: &str) -> ProfileData {
        ProfileData {
            server_url: "http://127.0.0.1:8080".into(),
            username: Some(username.into()),
            display_name: "pc".into(),
            device_id: None,
            account_id: None,
            event_cursor: 0,
            failed_unlocks: 0,
        }
    }

    fn make_profile(dir: &Path, username: &str) {
        let profile = Profile::at(dir).unwrap();
        profile.save(&data(username)).unwrap();
        profile.save_container(b"sealed").unwrap();
    }

    #[test]
    fn migrates_old_layout_and_lists_profiles() {
        let base = tempfile::tempdir().unwrap();
        make_profile(base.path(), "zoe");
        let store = ProfileStore::open(base.path()).unwrap();
        assert!(!base.path().join(PROFILE_FILE).exists(), "old files moved");
        let second = store.new_profile_dir().unwrap();
        make_profile(&second, "anna");
        store.new_profile_dir().unwrap(); // incomplete profiles are not listed
        let names: Vec<_> = store.list().unwrap().into_iter().map(|p| p.data.username.unwrap()).collect();
        assert_eq!(names, ["anna", "zoe"]);
    }

    #[test]
    fn lock_prevents_double_use_and_is_released() {
        let base = tempfile::tempdir().unwrap();
        let store = ProfileStore::open(base.path()).unwrap();
        let dir = store.new_profile_dir().unwrap();
        make_profile(&dir, "anna");
        let lock = ProfileLock::acquire(&dir).unwrap();
        assert!(matches!(ProfileLock::acquire(&dir), Err(ClientError::ProfileInUse)));
        assert!(store.list().unwrap()[0].in_use);
        drop(lock);
        assert!(!store.list().unwrap()[0].in_use);
        assert!(ProfileLock::acquire(&dir).is_ok());
    }

    #[test]
    fn remove_only_inside_the_store() {
        let base = tempfile::tempdir().unwrap();
        let store = ProfileStore::open(base.path()).unwrap();
        let dir = store.new_profile_dir().unwrap();
        make_profile(&dir, "anna");
        let outside = tempfile::tempdir().unwrap();
        assert!(store.remove(outside.path()).is_err());
        assert!(outside.path().exists());
        store.remove(&dir).unwrap();
        assert!(store.list().unwrap().is_empty());
    }
}

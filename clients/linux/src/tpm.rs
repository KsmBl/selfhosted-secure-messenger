//! Optional TPM2 binding of a profile (FR-019, ADR-0003).
//!
//! A new profile gets a random 32-byte secret sealed by the TPM (stored as
//! `tpm.seal` in the profile directory); the key container then needs both
//! the pattern and this secret, so a copied profile is useless on another
//! computer. Strictly optional:
//!
//! - built only with the cargo feature `tpm` (needs the tpm2-tss libraries),
//! - used only if the TPM can be opened (`/dev/tpmrm0`, user in group `tss`,
//!   or `SSM_TPM_TCTI`), and not with `SSM_NO_TPM=1`,
//! - profiles without `tpm.seal` keep working everywhere.

use std::path::Path;

use ssm_core::container::HardwareSecret;

pub const SEAL_FILE: &str = "tpm.seal";

#[derive(Debug, thiserror::Error)]
#[allow(dead_code)] // which variants occur depends on the `tpm` feature
pub enum TpmError {
    #[error("this profile is bound to a TPM, but this build has no TPM support")]
    NotBuilt,
    #[error("the TPM is not reachable (is the user in the 'tss' group?)")]
    Unavailable,
    #[error("TPM: {0}")]
    Tpm(String),
    #[error("{0}")]
    Io(#[from] std::io::Error),
}

/// A freshly sealed secret, written to the profile once enrollment worked.
pub struct Sealed(Vec<u8>);

impl Sealed {
    pub fn save(&self, profile_dir: &Path) -> Result<(), TpmError> {
        let path = profile_dir.join(SEAL_FILE);
        std::fs::write(&path, &self.0)?;
        Ok(())
    }
}

fn disabled() -> bool {
    std::env::var("SSM_NO_TPM").is_ok_and(|v| v == "1")
}

/// Whether new profiles will be bound to the TPM.
pub fn available() -> bool {
    !disabled() && imp::available()
}

/// Creates and seals a new secret. Call only if [`available`].
pub fn seal_new() -> Result<(HardwareSecret, Sealed), TpmError> {
    imp::seal_new()
}

/// The profile's secret, or `None` if the profile is not TPM-bound.
pub fn unseal(profile_dir: &Path) -> Result<Option<HardwareSecret>, TpmError> {
    let blob = match std::fs::read(profile_dir.join(SEAL_FILE)) {
        Ok(blob) => blob,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    imp::unseal(&blob).map(Some)
}

#[cfg(not(feature = "tpm"))]
mod imp {
    use super::*;

    pub fn available() -> bool {
        false
    }

    pub fn seal_new() -> Result<(HardwareSecret, Sealed), TpmError> {
        Err(TpmError::NotBuilt)
    }

    pub fn unseal(_blob: &[u8]) -> Result<HardwareSecret, TpmError> {
        Err(TpmError::NotBuilt)
    }
}

#[cfg(feature = "tpm")]
mod imp {
    use std::str::FromStr;

    use tss_esapi::attributes::ObjectAttributesBuilder;
    use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
    use tss_esapi::interface_types::key_bits::RsaKeyBits;
    use tss_esapi::interface_types::resource_handles::Hierarchy;
    use tss_esapi::structures::{
        KeyedHashScheme, Private, Public, PublicBuilder, PublicKeyedHashParameters, RsaExponent, SensitiveData,
        SymmetricDefinitionObject,
    };
    use tss_esapi::tcti_ldr::TctiNameConf;
    use tss_esapi::traits::{Marshall, UnMarshall};
    use tss_esapi::{Context, utils};
    use zeroize::Zeroizing;

    use super::*;

    const MAGIC: &[u8; 8] = b"SSMTPM1\0";
    const DEVICE: &str = "/dev/tpmrm0";

    fn tpm_err(err: tss_esapi::Error) -> TpmError {
        TpmError::Tpm(err.to_string())
    }

    fn tcti() -> Result<TctiNameConf, TpmError> {
        match std::env::var("SSM_TPM_TCTI") {
            Ok(conf) => TctiNameConf::from_str(&conf).map_err(tpm_err),
            Err(_) => {
                // Check access first: the TSS library logs errors to stderr
                // when it cannot open the device.
                std::fs::OpenOptions::new().read(true).write(true).open(DEVICE).map_err(|_| TpmError::Unavailable)?;
                TctiNameConf::from_str(&format!("device:{DEVICE}")).map_err(tpm_err)
            }
        }
    }

    fn context() -> Result<Context, TpmError> {
        Context::new(tcti()?).map_err(tpm_err)
    }

    pub fn available() -> bool {
        tcti().is_ok() && context().is_ok()
    }

    /// The storage root key, derived the same way every time (not persisted).
    fn primary(ctx: &mut Context) -> tss_esapi::Result<tss_esapi::handles::KeyHandle> {
        let template = utils::create_restricted_decryption_rsa_public(
            SymmetricDefinitionObject::AES_128_CFB,
            RsaKeyBits::Rsa2048,
            RsaExponent::default(),
        )?;
        Ok(ctx.create_primary(Hierarchy::Owner, template, None, None, None, None)?.key_handle)
    }

    fn sealed_object_template() -> tss_esapi::Result<Public> {
        let attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_no_da(true)
            .with_user_with_auth(true)
            .build()?;
        PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::KeyedHash)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(attributes)
            .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
            .with_keyed_hash_unique_identifier(Default::default())
            .build()
    }

    fn put(out: &mut Vec<u8>, field: &[u8]) {
        out.extend_from_slice(&(field.len() as u32).to_le_bytes());
        out.extend_from_slice(field);
    }

    fn take<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], TpmError> {
        let bad = || TpmError::Tpm("damaged tpm.seal".into());
        let (len, rest) = input.split_first_chunk::<4>().ok_or_else(bad)?;
        let len = u32::from_le_bytes(*len) as usize;
        if rest.len() < len {
            return Err(bad());
        }
        let (field, rest) = rest.split_at(len);
        *input = rest;
        Ok(field)
    }

    pub fn seal_new() -> Result<(HardwareSecret, Sealed), TpmError> {
        let mut ctx = context()?;
        let secret: HardwareSecret = {
            let mut bytes = Zeroizing::new([0u8; 32]);
            getrandom::fill(bytes.as_mut()).map_err(|e| TpmError::Tpm(e.to_string()))?;
            bytes
        };
        let created = ctx
            .execute_with_nullauth_session(|ctx| {
                let parent = primary(ctx)?;
                let sensitive = SensitiveData::try_from(secret.to_vec())?;
                let result = ctx.create(parent, sealed_object_template()?, None, Some(sensitive), None, None);
                ctx.flush_context(parent.into())?;
                result
            })
            .map_err(tpm_err)?;
        let public = created.out_public.marshall().map_err(tpm_err)?;
        let mut blob = MAGIC.to_vec();
        put(&mut blob, &public);
        put(&mut blob, created.out_private.value());
        // Check that it unseals before the profile depends on it.
        if unseal(&blob)?.as_ref() != secret.as_ref() {
            return Err(TpmError::Tpm("sealed secret does not match".into()));
        }
        Ok((secret, Sealed(blob)))
    }

    pub fn unseal(blob: &[u8]) -> Result<HardwareSecret, TpmError> {
        let mut rest =
            blob.strip_prefix(MAGIC.as_slice()).ok_or_else(|| TpmError::Tpm("unknown tpm.seal format".into()))?;
        let public = Public::unmarshall(take(&mut rest)?).map_err(tpm_err)?;
        let private = Private::try_from(take(&mut rest)?.to_vec()).map_err(tpm_err)?;
        let mut ctx = context()?;
        let data = ctx
            .execute_with_nullauth_session(|ctx| {
                let parent = primary(ctx)?;
                let loaded = ctx.load(parent, private, public);
                ctx.flush_context(parent.into())?;
                let loaded = loaded?;
                let data = ctx.unseal(loaded.into());
                ctx.flush_context(loaded.into())?;
                data
            })
            .map_err(tpm_err)?;
        let bytes = Zeroizing::new(data.value().to_vec());
        let secret: [u8; 32] =
            bytes.as_slice().try_into().map_err(|_| TpmError::Tpm("unexpected secret length".into()))?;
        Ok(Zeroizing::new(secret))
    }
}

/// Runs against a real or software TPM only, e.g.
/// `swtpm socket --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags startup-clear`
/// and `SSM_TPM_TCTI=swtpm:port=2321 cargo test -p ssm-linux --features tpm`.
#[cfg(all(test, feature = "tpm"))]
mod tests {
    use super::*;

    #[test]
    fn seal_and_unseal_roundtrip() {
        if std::env::var_os("SSM_TPM_TCTI").is_none() {
            eprintln!("SSM_TPM_TCTI not set, skipping");
            return;
        }
        assert!(available());
        let dir = std::env::temp_dir().join(format!("ssm-tpm-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(unseal(&dir).unwrap().is_none(), "no seal file: not bound");

        let (secret, sealed) = seal_new().unwrap();
        sealed.save(&dir).unwrap();
        assert_eq!(unseal(&dir).unwrap().unwrap().as_ref(), secret.as_ref());

        let path = dir.join(SEAL_FILE);
        let mut blob = std::fs::read(&path).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 1;
        std::fs::write(&path, &blob).unwrap();
        assert!(unseal(&dir).is_err(), "tampered blob must not unseal");
        std::fs::remove_dir_all(dir).unwrap();
    }
}

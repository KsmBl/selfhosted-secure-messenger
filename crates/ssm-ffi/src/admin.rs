//! Administration for the Android app (FR-016 – FR-019): the admin key lives
//! in its own container (own pattern, Android Keystore binding) next to the
//! chat profile; every request is authorised by the server.

use std::sync::Arc;

use ssm_client::{AdminClient, AdminKey, ClientError};
use ssm_core::KdfParams;
use ssm_proto::B64;
use ssm_proto::api::{DeviceAction, DeviceStatus};

use crate::{FfiError, FfiResult, KDF_TARGET, SsmSession, hardware, parse_id, pattern};

/// Admin API errors as readable text (the server's detail where it has one).
fn admin_error(err: ClientError) -> FfiError {
    match err {
        ClientError::Api { kind, detail, .. } => FfiError::Other(match (kind.as_str(), detail) {
            (_, Some(detail)) => detail,
            ("forbidden", None) => "Not allowed.".into(),
            ("not-found", None) => "Not found.".into(),
            (kind, None) => kind.replace('-', " "),
        }),
        other => other.into(),
    }
}

/// The admin key exists but is not registered on the server yet.
#[derive(uniffi::Record)]
pub struct FfiAdminLogin {
    /// Set when logged in.
    pub admin: Option<Arc<SsmAdmin>>,
    /// Public key to register (TUI: Accounts → k) while not registered.
    pub unregistered_public_key: Option<String>,
}

#[derive(uniffi::Record)]
pub struct FfiAdminOverview {
    pub accounts: i64,
    pub admins: i64,
    pub devices_pending: i64,
    pub devices_active: i64,
    pub devices_disabled: i64,
    pub conversations: i64,
    pub messages: i64,
    pub jobs_running: i64,
    pub audit_entries: i64,
    /// `None` when the audit hash chain is intact.
    pub audit_broken_at: Option<i64>,
}

#[derive(uniffi::Record)]
pub struct FfiAdminDevice {
    pub id: String,
    pub username: String,
    pub name: String,
    /// `pending`, `active`, `disabled`, `revoked` or `rejected`.
    pub status: String,
    pub fingerprint: String,
    pub created_at: String,
}

#[derive(uniffi::Record)]
pub struct FfiAdminAccount {
    pub id: String,
    pub username: String,
    /// `user` or `admin`.
    pub role: String,
    /// `active` or `disabled`.
    pub status: String,
    pub active_devices: i64,
    pub messages: i64,
    pub created_at: String,
}

#[derive(uniffi::Record)]
pub struct FfiInvite {
    pub account_id: String,
    pub code: String,
    pub expires_at: String,
}

#[derive(uniffi::Record)]
pub struct FfiAdminJob {
    pub id: String,
    pub scope: String,
    pub status: String,
    pub affected_messages: i64,
    pub created_at: String,
    pub error: Option<String>,
}

#[derive(uniffi::Record)]
pub struct FfiAuditEntry {
    pub id: i64,
    pub action: String,
    pub target: String,
    pub result: String,
    pub created_at: String,
}

#[derive(uniffi::Record)]
pub struct FfiContentSummary {
    pub username: String,
    pub messages: i64,
    pub conversations: i64,
}

fn fingerprint(key: &[u8]) -> String {
    let encoded = B64::encode(key);
    encoded.as_bytes().chunks(4).map(|c| String::from_utf8_lossy(c).into_owned()).collect::<Vec<_>>().join(" ")
}

fn status_str(status: DeviceStatus) -> String {
    serde_json::to_value(status).ok().and_then(|v| v.as_str().map(str::to_owned)).unwrap_or_default()
}

fn job_status(status: impl serde::Serialize) -> String {
    serde_json::to_value(status).ok().and_then(|v| v.as_str().map(str::to_owned)).unwrap_or_default()
}

#[uniffi::export(async_runtime = "tokio")]
impl SsmSession {
    /// Whether this profile has an admin key (Administration was set up).
    pub async fn admin_key_exists(&self) -> FfiResult<bool> {
        self.with(async |c| Ok(AdminKey::exists(c.dir()))).await
    }

    /// Creates the admin key, protected by its own pattern and the device's
    /// Keystore. Returns the public key to register on the server.
    pub async fn create_admin_key(&self, dots: Vec<u8>, hardware_secret: Option<Vec<u8>>) -> FfiResult<String> {
        let pattern = pattern(dots)?;
        let hardware = hardware(hardware_secret)?;
        let dir = self.with(async |c| Ok(c.dir().to_owned())).await?;
        tokio::task::spawn_blocking(move || {
            let params = KdfParams::calibrate(KDF_TARGET).map_err(ClientError::from)?;
            Ok(AdminKey::create(&dir, &pattern, params, hardware.as_ref())?.public_key())
        })
        .await
        .map_err(|e| FfiError::Other(e.to_string()))?
    }

    /// Opens the admin key with its pattern and logs in.
    pub async fn admin_login(&self, dots: Vec<u8>, hardware_secret: Option<Vec<u8>>) -> FfiResult<FfiAdminLogin> {
        let pattern = pattern(dots)?;
        let hardware = hardware(hardware_secret)?;
        let (dir, server) = self.with(async |c| Ok((c.dir().to_owned(), c.data().server_url.clone()))).await?;
        let key = tokio::task::spawn_blocking(move || AdminKey::open(&dir, &pattern, hardware.as_ref()))
            .await
            .map_err(|e| FfiError::Other(e.to_string()))??;
        let public_key = key.public_key();
        match AdminClient::connect(&server, key).await {
            Ok(client) => {
                Ok(FfiAdminLogin { admin: Some(Arc::new(SsmAdmin { client })), unregistered_public_key: None })
            }
            Err(err) if err.problem_kind() == Some("not-found") => {
                Ok(FfiAdminLogin { admin: None, unregistered_public_key: Some(public_key) })
            }
            Err(err) => Err(admin_error(err)),
        }
    }

    /// Deletes this device's admin key (e.g. to set up a new one).
    pub async fn remove_admin_key(&self) -> FfiResult<()> {
        self.with(async |c| Ok(AdminKey::remove(c.dir())?)).await
    }
}

/// A logged-in admin session (token valid 10 minutes, renewed by signing).
#[derive(uniffi::Object)]
pub struct SsmAdmin {
    client: AdminClient,
}

#[uniffi::export(async_runtime = "tokio")]
impl SsmAdmin {
    pub async fn overview(&self) -> FfiResult<FfiAdminOverview> {
        let o = self.client.overview().await.map_err(admin_error)?;
        Ok(FfiAdminOverview {
            accounts: o.accounts,
            admins: o.admins,
            devices_pending: o.devices_pending,
            devices_active: o.devices_active,
            devices_disabled: o.devices_disabled,
            conversations: o.conversations,
            messages: o.messages,
            jobs_running: o.jobs_running,
            audit_entries: o.audit_entries,
            audit_broken_at: o.audit_broken_at,
        })
    }

    pub async fn devices(&self) -> FfiResult<Vec<FfiAdminDevice>> {
        let devices = self.client.devices(None).await.map_err(admin_error)?;
        Ok(devices
            .into_iter()
            .map(|d| FfiAdminDevice {
                id: d.device_id.to_string(),
                username: d.username,
                name: d.display_name,
                status: status_str(d.status),
                fingerprint: fingerprint(&d.olm_fingerprint_key.0),
                created_at: d.created_at,
            })
            .collect())
    }

    /// `approve`, `reject`, `disable`, `enable` or `revoke`.
    pub async fn device_action(&self, device_id: String, action: String) -> FfiResult<()> {
        let id = parse_id(&device_id)?;
        let action = match action.as_str() {
            "approve" => DeviceAction::Approve,
            "reject" => DeviceAction::Reject,
            "disable" => DeviceAction::Disable,
            "enable" => DeviceAction::Enable,
            "revoke" => DeviceAction::Revoke,
            other => return Err(FfiError::Other(format!("unknown action {other}"))),
        };
        self.client.device_action(id, action).await.map_err(admin_error)?;
        Ok(())
    }

    pub async fn accounts(&self) -> FfiResult<Vec<FfiAdminAccount>> {
        let accounts = self.client.accounts().await.map_err(admin_error)?;
        Ok(accounts
            .into_iter()
            .map(|a| FfiAdminAccount {
                id: a.account_id.to_string(),
                username: a.username,
                role: a.role,
                status: a.status,
                active_devices: a.active_devices,
                messages: a.messages,
                created_at: a.created_at,
            })
            .collect())
    }

    pub async fn create_account(&self, username: String) -> FfiResult<FfiInvite> {
        let invite = self.client.create_account(username.trim()).await.map_err(admin_error)?;
        Ok(FfiInvite {
            account_id: invite.account_id.to_string(),
            code: invite.invite_code,
            expires_at: invite.expires_at,
        })
    }

    pub async fn new_invite(&self, account_id: String) -> FfiResult<FfiInvite> {
        let invite = self.client.new_invite(parse_id(&account_id)?).await.map_err(admin_error)?;
        Ok(FfiInvite {
            account_id: invite.account_id.to_string(),
            code: invite.invite_code,
            expires_at: invite.expires_at,
        })
    }

    pub async fn set_account_locked(&self, account_id: String, locked: bool) -> FfiResult<String> {
        self.client.set_account_locked(parse_id(&account_id)?, locked).await.map_err(admin_error)
    }

    pub async fn set_admin_role(&self, account_id: String, admin: bool) -> FfiResult<String> {
        self.client.set_admin_role(parse_id(&account_id)?, admin).await.map_err(admin_error)
    }

    pub async fn add_admin_key(&self, account_id: String, public_key: String) -> FfiResult<String> {
        self.client.add_admin_key(parse_id(&account_id)?, public_key.trim()).await.map_err(admin_error)
    }

    pub async fn content_summary(&self, account_id: String) -> FfiResult<FfiContentSummary> {
        let s = self.client.content_summary(parse_id(&account_id)?).await.map_err(admin_error)?;
        Ok(FfiContentSummary { username: s.username, messages: s.messages, conversations: s.conversations })
    }

    /// FR-018: deletes everything the account ever sent, for everyone.
    pub async fn delete_all_content(&self, account_id: String) -> FfiResult<FfiAdminJob> {
        let job = self.client.delete_all_content(parse_id(&account_id)?).await.map_err(admin_error)?;
        Ok(FfiAdminJob {
            id: job.job_id.to_string(),
            scope: "all content".into(),
            status: job_status(job.status),
            affected_messages: job.affected_messages,
            created_at: job.created_at,
            error: job.error_summary,
        })
    }

    /// FR-028: deletes the account completely (messages for everyone too).
    pub async fn delete_account(&self, account_id: String) -> FfiResult<String> {
        self.client.delete_account(parse_id(&account_id)?).await.map_err(admin_error)
    }

    pub async fn jobs(&self) -> FfiResult<Vec<FfiAdminJob>> {
        let jobs = self.client.jobs().await.map_err(admin_error)?;
        Ok(jobs
            .into_iter()
            .map(|j| FfiAdminJob {
                id: j.job_id.to_string(),
                scope: j.scope,
                status: job_status(j.status),
                affected_messages: j.affected_messages,
                created_at: j.created_at,
                error: j.error_summary,
            })
            .collect())
    }

    pub async fn audit(&self) -> FfiResult<Vec<FfiAuditEntry>> {
        let events = self.client.audit().await.map_err(admin_error)?;
        Ok(events
            .into_iter()
            .map(|e| FfiAuditEntry {
                id: e.id,
                action: e.action,
                target: if e.target_label.is_empty() { e.target } else { e.target_label },
                result: e.result,
                created_at: e.created_at,
            })
            .collect())
    }
}

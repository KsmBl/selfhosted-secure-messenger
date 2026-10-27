//! Where the server listens (this computer only or the local network, and
//! the port), shown and changed in `ssm-server tui`.
//!
//! The TUI runs as the unprivileged service user. The change itself is made
//! by the root-owned helper [`HELPER`], which `scripts/install-server.sh`
//! installs together with a sudo rule that allows only this one command. The
//! helper validates its arguments, updates `SSM_BIND`, restarts the service
//! and restores the previous address if the server does not come up.

use std::net::SocketAddr;
use std::path::PathBuf;

pub const HELPER: &str = "/usr/local/sbin/ssm-netconfig";
const DEFAULT_BIND: &str = "127.0.0.1:8080";
const CADDY_SITE: &str = "/etc/caddy/ssm.caddy";

#[derive(Debug, Clone)]
pub struct NetStatus {
    pub bind: String,
    /// Reachable from other devices (not bound to loopback).
    pub lan: bool,
    pub port: u16,
    /// IPv4 addresses of this host in the local network(s).
    pub lan_addresses: Vec<String>,
    /// Domain of the HTTPS proxy from `scripts/setup-https.sh`, if set up.
    pub https_domain: Option<String>,
    pub helper_installed: bool,
}

fn config_file() -> PathBuf {
    std::env::var_os("SSM_CONFIG_FILE").map(PathBuf::from).unwrap_or_else(|| "/etc/ssm/ssm.env".into())
}

/// The configured address: the config file (it may have changed since this
/// process started), else the environment, else the default.
fn configured_bind() -> String {
    std::fs::read_to_string(config_file())
        .ok()
        .and_then(|text| {
            text.lines().filter_map(|l| l.strip_prefix("SSM_BIND=")).next_back().map(|v| v.trim().to_owned())
        })
        .or_else(|| std::env::var("SSM_BIND").ok())
        .unwrap_or_else(|| DEFAULT_BIND.into())
}

fn lan_addresses() -> Vec<String> {
    let Ok(output) = std::process::Command::new("ip").args(["-4", "-o", "addr", "show", "scope", "global"]).output()
    else {
        return Vec::new();
    };
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.split_whitespace().skip_while(|w| *w != "inet").nth(1))
        .filter_map(|cidr| cidr.split('/').next().map(str::to_owned))
        .collect()
}

fn https_domain() -> Option<String> {
    let text = std::fs::read_to_string(CADDY_SITE).ok()?;
    text.lines()
        .map(str::trim)
        .find(|l| !l.starts_with('#') && l.ends_with('{'))
        .map(|l| l.trim_end_matches('{').trim().to_owned())
}

pub fn status() -> NetStatus {
    let bind = configured_bind();
    let (lan, port) = match bind.parse::<SocketAddr>() {
        Ok(addr) => (!addr.ip().is_loopback(), addr.port()),
        Err(_) => (false, 8080),
    };
    NetStatus {
        bind,
        lan,
        port,
        lan_addresses: lan_addresses(),
        https_domain: https_domain(),
        helper_installed: std::path::Path::new(HELPER).exists(),
    }
}

/// Ports the service may bind: the systemd unit grants no capabilities, so
/// privileged ports (< 1024) are not possible.
pub fn valid_port(port: u16) -> bool {
    port >= 1024
}

/// Runs the helper via sudo. Returns its message, or the error text.
pub async fn apply(lan: bool, port: u16) -> Result<String, String> {
    if !valid_port(port) {
        return Err("The port must be between 1024 and 65535.".into());
    }
    if !std::path::Path::new(HELPER).exists() {
        return Err("The helper is missing: run scripts/install-server.sh again.".into());
    }
    let output = tokio::process::Command::new("sudo")
        .args(["-n", HELPER, if lan { "lan" } else { "local" }, &port.to_string()])
        .output()
        .await
        .map_err(|e| format!("Could not run sudo: {e}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    if output.status.success() {
        Ok(stdout)
    } else if stderr.contains("password is required") || stderr.contains("not allowed") {
        Err("Not permitted: the sudo rule for ssm-netconfig is missing (run scripts/install-server.sh again).".into())
    } else {
        Err(if stderr.is_empty() { stdout } else { stderr })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ports() {
        assert!(!valid_port(80));
        assert!(valid_port(1024));
        assert!(valid_port(8080));
        assert!(valid_port(65535));
    }
}

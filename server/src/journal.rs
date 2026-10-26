//! Deletion journal (FR-010): the IDs of messages and accounts deleted, kept
//! outside the database (`SSM_DELETION_JOURNAL`, default next to the media
//! files) for the backup retention period. After a restore from an older
//! backup, `ssm-admin replay-deletions` deletes them again, so a restore
//! cannot bring deleted content back.
//!
//! Lines: `<unix seconds> <message|account> <uuid>`. Only IDs, no content.

use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use uuid::Uuid;

use crate::AppState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Entry {
    Message(Uuid),
    Account(Uuid),
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

fn line(at: u64, entry: Entry) -> String {
    match entry {
        Entry::Message(id) => format!("{at} message {id}\n"),
        Entry::Account(id) => format!("{at} account {id}\n"),
    }
}

fn parse(line: &str) -> Option<(u64, Entry)> {
    let mut parts = line.split_whitespace();
    let at = parts.next()?.parse().ok()?;
    let kind = parts.next()?;
    let id = parts.next()?.parse().ok()?;
    match kind {
        "message" => Some((at, Entry::Message(id))),
        "account" => Some((at, Entry::Account(id))),
        _ => None,
    }
}

/// Appends entries. Failures are logged, never fatal: the deletion itself
/// already happened in the database.
pub fn record(state: &AppState, entries: &[Entry]) {
    let Some(path) = &state.config.deletion_journal else { return };
    if entries.is_empty() {
        return;
    }
    let at = now_secs();
    let text: String = entries.iter().map(|e| line(at, *e)).collect();
    let result = (|| {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let mut file = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
        file.write_all(text.as_bytes())?;
        file.sync_data()
    })();
    if let Err(err) = result {
        tracing::error!(error = %err, path = %path.display(), "writing the deletion journal failed");
    }
}

/// All entries of a journal file (unknown lines are skipped).
pub fn read(path: &Path) -> std::io::Result<Vec<Entry>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(text.lines().filter_map(parse).map(|(_, e)| e).collect()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(err) => Err(err),
    }
}

/// Drops entries older than the backup retention (no backup can contain
/// the deleted data any more). Called by the maintenance loop.
pub fn prune(state: &AppState) -> std::io::Result<()> {
    let Some(path) = &state.config.deletion_journal else { return Ok(()) };
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
    };
    // A backup taken just before a deletion can be restored for this long.
    let keep_secs = (state.config.backup_retention_days.max(0) as u64 + 1) * 86_400;
    let cutoff = now_secs().saturating_sub(keep_secs);
    let kept: String =
        text.lines().filter(|l| parse(l).is_some_and(|(at, _)| at >= cutoff)).map(|l| format!("{l}\n")).collect();
    if kept.len() == text.len() {
        return Ok(());
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, kept)?;
    std::fs::rename(tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_roundtrip() {
        let id = Uuid::new_v4();
        assert_eq!(parse(&line(5, Entry::Message(id))), Some((5, Entry::Message(id))));
        assert_eq!(parse(&line(7, Entry::Account(id))), Some((7, Entry::Account(id))));
        assert_eq!(parse("garbage"), None);
    }
}

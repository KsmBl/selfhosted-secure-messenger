-- No backups: a deletion is complete as soon as the active data is gone.
-- Former states active_removed / backup_purge_pending / backup_purge_done
-- become completed; the backup due date is dropped.
ALTER TABLE delete_jobs DROP CONSTRAINT delete_jobs_status_check;
UPDATE delete_jobs
SET status = 'completed', completed_at = COALESCE(completed_at, updated_at)
WHERE status IN ('active_removed', 'backup_purge_pending', 'backup_purge_done');
ALTER TABLE delete_jobs ADD CONSTRAINT delete_jobs_status_check
    CHECK (status IN ('requested', 'in_progress', 'completed', 'failed'));
DROP INDEX IF EXISTS delete_jobs_backup_idx;
ALTER TABLE delete_jobs DROP COLUMN backup_purge_due_at;

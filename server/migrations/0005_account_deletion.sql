-- Accounts can be deleted (TUI). The creator of a conversation is kept only
-- as information, so it becomes NULL; group rights come from the member role.

ALTER TABLE conversations ALTER COLUMN created_by DROP NOT NULL;
ALTER TABLE conversations DROP CONSTRAINT conversations_created_by_fkey;
ALTER TABLE conversations
    ADD CONSTRAINT conversations_created_by_fkey FOREIGN KEY (created_by) REFERENCES accounts (id) ON DELETE SET NULL;

-- Revoked and rejected devices are deleted completely. Messages keep the id
-- of the sending device without a foreign key: recipients need it to match
-- the Megolm session, so old messages stay readable.
ALTER TABLE messages DROP CONSTRAINT messages_sender_device_id_fkey;
DELETE FROM devices WHERE status IN ('revoked', 'rejected');

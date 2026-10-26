-- Group admin: only the admin invites or removes members; anyone may leave.
-- When the admin leaves, the longest-standing remaining member takes over.

ALTER TABLE conversation_members
    ADD COLUMN role TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('admin', 'member'));

UPDATE conversation_members m SET role = 'admin'
FROM conversations c
WHERE c.id = m.conversation_id AND c.kind = 'group' AND m.account_id = c.created_by AND m.status = 'active';

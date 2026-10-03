-- A locking read is filtered by the UPDATE policies' USING clause on top of the
-- SELECT policies, so it returns fewer rows than a plain read.

CREATE TABLE users (
    id TEXT PRIMARY KEY
);

CREATE TABLE notes (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL REFERENCES users(id)
);

CREATE FUNCTION auth_current_user_id() RETURNS TEXT
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';

ALTER TABLE notes ENABLE ROW LEVEL SECURITY;

CREATE POLICY notes_readable ON notes
    FOR SELECT TO PUBLIC
    USING (TRUE);

CREATE POLICY notes_owner_writes ON notes
    FOR UPDATE TO PUBLIC
    USING (owner_id = auth_current_user_id())
    WITH CHECK (TRUE);

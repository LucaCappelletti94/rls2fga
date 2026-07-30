-- WITH CHECK admits the new row and says nothing about the existing one, so an
-- UPDATE policy storing no USING clause leaves no row updatable.

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

CREATE POLICY notes_owner_reads ON notes
    FOR SELECT TO PUBLIC
    USING (owner_id = auth_current_user_id());

CREATE POLICY notes_owner_writes ON notes
    FOR UPDATE TO PUBLIC
    WITH CHECK (owner_id = auth_current_user_id());

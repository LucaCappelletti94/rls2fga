-- ALTER POLICY supersedes the clause the policy was created with, so the rule
-- PostgreSQL enforces is the narrowed one and never the original.

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

CREATE POLICY notes_sel ON notes
    FOR SELECT TO PUBLIC
    USING (TRUE);

ALTER POLICY notes_sel ON notes
    USING (owner_id = auth_current_user_id());

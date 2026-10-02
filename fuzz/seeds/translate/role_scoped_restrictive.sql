-- A RESTRICTIVE policy scoped to `contractor` binds only that role. An owner
-- outside it keeps the read the permissive policy grants.

CREATE TABLE users (
    id TEXT PRIMARY KEY
);

CREATE TABLE notes (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL REFERENCES users(id),
    reviewer_id TEXT NOT NULL REFERENCES users(id)
);

CREATE FUNCTION auth_current_user_id() RETURNS TEXT
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';

ALTER TABLE notes ENABLE ROW LEVEL SECURITY;

CREATE POLICY notes_owner ON notes
    FOR SELECT TO PUBLIC
    USING (owner_id = auth_current_user_id());

CREATE POLICY notes_reviewed ON notes
    AS RESTRICTIVE FOR SELECT TO contractor
    USING (reviewer_id = auth_current_user_id());

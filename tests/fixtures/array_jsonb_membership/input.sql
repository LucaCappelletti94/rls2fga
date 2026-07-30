-- The caller as an element of an array column, and the caller named by a jsonb field.
-- Both are exact: UNNEST enumerates what `= ANY` admits, and dropping the NULL `->>`
-- yields enumerates what the comparison admits.

CREATE TABLE users (
    id TEXT PRIMARY KEY
);

CREATE TABLE notes (
    id TEXT PRIMARY KEY,
    editors TEXT[],
    meta JSONB
);

CREATE FUNCTION auth_current_user_id() RETURNS TEXT
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';

ALTER TABLE notes ENABLE ROW LEVEL SECURITY;

CREATE POLICY notes_editors ON notes
    FOR SELECT TO PUBLIC
    USING (auth_current_user_id() = ANY (editors));

CREATE POLICY notes_meta_owner ON notes
    FOR SELECT TO PUBLIC
    USING (meta ->> 'owner_id' = auth_current_user_id());

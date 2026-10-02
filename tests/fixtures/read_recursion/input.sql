-- Reading a table expands the USING clauses of its SELECT policies, and each of these
-- reads the other, so PostgreSQL raises infinite recursion on every read of either.
-- The ownership branch saves nothing: the loop is found while the policy is expanded,
-- before any row is evaluated.

CREATE TABLE users (
    id TEXT PRIMARY KEY
);

CREATE TABLE folders (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL REFERENCES users(id),
    note_id TEXT
);

CREATE TABLE notes (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL REFERENCES users(id),
    folder_id TEXT REFERENCES folders(id)
);

ALTER TABLE folders
    ADD CONSTRAINT folders_note_fk FOREIGN KEY (note_id) REFERENCES notes(id);

CREATE FUNCTION auth_current_user_id() RETURNS TEXT
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';

ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
ALTER TABLE folders ENABLE ROW LEVEL SECURITY;

CREATE POLICY notes_reads ON notes
    FOR SELECT TO PUBLIC
    USING (owner_id = auth_current_user_id()
           OR EXISTS (SELECT 1 FROM folders
                      WHERE folders.id = notes.folder_id
                        AND folders.owner_id = auth_current_user_id()));

CREATE POLICY folders_reads ON folders
    FOR SELECT TO PUBLIC
    USING (owner_id = auth_current_user_id()
           OR EXISTS (SELECT 1 FROM notes
                      WHERE notes.id = folders.note_id
                        AND notes.owner_id = auth_current_user_id()));

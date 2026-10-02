-- PostgreSQL folds an unquoted identifier to lowercase, so the schema's spelling
-- is not the name it stores. Every comparison and every generated statement has
-- to use the stored name.

CREATE TABLE Users (
    ID TEXT PRIMARY KEY
);

CREATE TABLE Notes (
    ID TEXT PRIMARY KEY,
    Owner_Id TEXT NOT NULL REFERENCES Users(ID)
);

CREATE TABLE Note_Members (
    ID TEXT PRIMARY KEY,
    Note_Id TEXT NOT NULL REFERENCES Notes(ID),
    User_Id TEXT NOT NULL REFERENCES Users(ID)
);

CREATE FUNCTION auth_current_user_id() RETURNS TEXT
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';

ALTER TABLE Notes ENABLE ROW LEVEL SECURITY;

CREATE POLICY notes_owner ON Notes
    FOR SELECT USING (owner_id = auth_current_user_id());

CREATE POLICY notes_member ON Notes
    FOR SELECT USING (
        EXISTS (
            SELECT 1 FROM note_members m
            WHERE m.note_id = notes.id AND m.user_id = auth_current_user_id()
        )
    );

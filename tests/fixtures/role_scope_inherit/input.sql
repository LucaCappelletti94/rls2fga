-- A policy TO editors admits the role's inheriting members: PostgreSQL applies the
-- clause with has_privs_of_role, so a NOINHERIT member holds MEMBER and stays outside.

CREATE TABLE docs (
    id TEXT PRIMARY KEY
);

ALTER TABLE docs ENABLE ROW LEVEL SECURITY;

CREATE POLICY docs_editor_select ON docs
    FOR SELECT TO editors
    USING (true);

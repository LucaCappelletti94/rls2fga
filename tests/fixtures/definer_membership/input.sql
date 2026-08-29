-- Probe A's idiom: a SECURITY DEFINER wrapper around the membership EXISTS,
-- called by the guarded table and by the membership table's own policy, so the
-- self-reference PostgreSQL would refuse to plan runs as the owner instead.

CREATE TABLE users (
    id TEXT PRIMARY KEY
);

CREATE TABLE docs (
    id TEXT PRIMARY KEY
);

CREATE TABLE doc_members (
    id TEXT PRIMARY KEY,
    doc_id TEXT NOT NULL REFERENCES docs(id),
    user_id TEXT NOT NULL REFERENCES users(id)
);

CREATE FUNCTION is_doc_member(d TEXT) RETURNS BOOLEAN
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO public, pg_catalog, pg_temp
    AS 'SELECT EXISTS (
        SELECT 1 FROM doc_members m
        WHERE m.doc_id = d
        AND m.user_id = current_setting(''app.current_user_id'', true)
    )';

ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE doc_members ENABLE ROW LEVEL SECURITY;

CREATE POLICY docs_select_policy ON docs
    FOR SELECT TO PUBLIC
    USING (is_doc_member(id));

CREATE POLICY doc_members_select_policy ON doc_members
    FOR SELECT TO PUBLIC
    USING (is_doc_member(doc_id));

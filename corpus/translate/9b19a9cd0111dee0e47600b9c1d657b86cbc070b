-- Compound OR: owner can see their own docs, OR docs that are public.
-- This is a very common pattern combining P3 and P6.

CREATE TABLE users (
    id UUID PRIMARY KEY
);

CREATE TABLE documents (
    id UUID PRIMARY KEY,
    owner_id UUID NOT NULL REFERENCES users(id),
    is_public BOOLEAN NOT NULL DEFAULT FALSE,
    title TEXT
);

CREATE FUNCTION auth_current_user_id() RETURNS UUID
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')::uuid';

ALTER TABLE documents ENABLE ROW LEVEL SECURITY;

CREATE POLICY documents_select ON documents
    FOR SELECT TO PUBLIC
    USING (owner_id = auth_current_user_id() OR is_public = TRUE);

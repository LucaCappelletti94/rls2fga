-- Inventory row 7, from the Supabase multi-factor authentication documentation.
--
-- A scalar the request carries, compared against a constant, as a RESTRICTIVE barrier
-- beside an ordinary ownership grant. The barrier is decided entirely by the request,
-- so no row supplies anything to it.

CREATE TABLE users (
    id UUID PRIMARY KEY
);

CREATE TABLE documents (
    id UUID PRIMARY KEY,
    owner_id UUID NOT NULL REFERENCES users(id),
    body TEXT
);

CREATE FUNCTION auth.jwt() RETURNS JSONB
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''request.jwt.claims'')::jsonb';

CREATE FUNCTION auth.uid() RETURNS UUID
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''request.jwt.claim.sub'')::uuid';

ALTER TABLE documents ENABLE ROW LEVEL SECURITY;

CREATE POLICY documents_owner ON documents
    FOR SELECT TO PUBLIC
    USING (owner_id = auth.uid());

CREATE POLICY documents_mfa ON documents
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING ((SELECT auth.jwt() ->> 'aal') = 'aal2');

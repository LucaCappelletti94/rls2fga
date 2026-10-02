-- pg_has_role names a PostgreSQL role rather than anything in a row, so the grant is a
-- role membership no generated query can read: the model has to let an operator supply it
-- and then walk it, which is the same shape a TO clause scope is consumed through.

CREATE TABLE docs (
    id TEXT PRIMARY KEY,
    title TEXT
);

ALTER TABLE docs ENABLE ROW LEVEL SECURITY;

CREATE POLICY docs_select ON docs
    FOR SELECT TO PUBLIC
    USING (pg_has_role(current_user, 'editor', 'MEMBER'));

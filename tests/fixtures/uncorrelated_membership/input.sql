-- An uncorrelated membership names no column of the guarded table, so it admits every
-- row at once to whoever appears in the member table. The generator stands one holder
-- object for the whole member list, so the facts grow as rows plus members rather than
-- rows times members.
--
-- Two member tables, so the holders cannot pool: `staff` is a plain list, and
-- `reviewers` carries a clock the request completes, which is the shape that rides a
-- condition rather than filtering the load.

CREATE TABLE users (
    id TEXT PRIMARY KEY
);

CREATE TABLE staff (
    user_id TEXT REFERENCES users(id)
);

CREATE TABLE reviewers (
    user_id TEXT REFERENCES users(id),
    vetted_at TIMESTAMPTZ
);

CREATE TABLE docs (
    id TEXT PRIMARY KEY,
    owner_id TEXT REFERENCES users(id)
);

CREATE TABLE memos (
    id TEXT PRIMARY KEY
);

CREATE FUNCTION auth_current_user_id() RETURNS TEXT
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';

ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE memos ENABLE ROW LEVEL SECURITY;

CREATE POLICY docs_staff ON docs
    FOR SELECT
    USING (EXISTS (SELECT 1 FROM staff WHERE staff.user_id = auth_current_user_id()));

CREATE POLICY memos_reviewers ON memos
    FOR SELECT
    USING (EXISTS (SELECT 1 FROM reviewers
        WHERE reviewers.user_id = auth_current_user_id() AND reviewers.vetted_at > now()));

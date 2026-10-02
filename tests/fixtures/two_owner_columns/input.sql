-- One table whose rows are judged through two owner values: the party that owns the record
-- and the party it is delegated to. Each call passes its own column, so each gets its own
-- pointer at the owner it named, and the two are unioned.
--
-- The thresholds differ, so a delegate needs a higher role than an owner to read the same
-- row, which is what shows the two pointers are not interchangeable.

CREATE TABLE users (
    id UUID PRIMARY KEY
);

CREATE TABLE owner_grants (
    grantee_owner_id UUID NOT NULL,
    granted_owner_id UUID NOT NULL,
    role_id INTEGER NOT NULL
);

CREATE TABLE records (
    id UUID PRIMARY KEY,
    owner_id UUID NOT NULL,
    delegate_id UUID
);

CREATE FUNCTION auth_current_user_id() RETURNS UUID
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')::uuid';

CREATE FUNCTION get_owner_role(user_uuid UUID, target_owner_id UUID) RETURNS INTEGER
    LANGUAGE sql STABLE
    AS '
    SELECT COALESCE(MAX(role), 0)
    FROM (
        SELECT 4 AS role
        WHERE user_uuid = target_owner_id
        AND user_uuid IN (SELECT id FROM users)

        UNION ALL

        SELECT og.role_id AS role
        FROM owner_grants og
        WHERE og.granted_owner_id = target_owner_id
        AND og.grantee_owner_id = user_uuid
    ) sub
    ';

ALTER TABLE records ENABLE ROW LEVEL SECURITY;

CREATE POLICY records_select_policy ON records
    FOR SELECT TO PUBLIC
    USING (
        get_owner_role(auth_current_user_id(), owner_id) >= 2
        OR get_owner_role(auth_current_user_id(), delegate_id) >= 4
    );

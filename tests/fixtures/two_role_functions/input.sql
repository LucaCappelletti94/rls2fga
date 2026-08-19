-- Two role-threshold functions reading one grant table on two different scales: the
-- projects rule counts the same `role_id` column as viewer/editor/admin, the ledgers rule
-- counts it as clerk/auditor. Nothing here can prove the two scales agree, so each function
-- gets its own owner and the grants must not pool across them.

CREATE TABLE users (
    id UUID PRIMARY KEY
);

CREATE TABLE owner_grants (
    grantee_owner_id UUID NOT NULL,
    granted_owner_id UUID NOT NULL,
    role_id INTEGER NOT NULL
);

CREATE TABLE projects (
    id UUID PRIMARY KEY,
    owner_id UUID NOT NULL
);

CREATE TABLE ledgers (
    id UUID PRIMARY KEY,
    owner_id UUID NOT NULL
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

CREATE FUNCTION get_owner_tier(user_uuid UUID, target_owner_id UUID) RETURNS INTEGER
    LANGUAGE sql STABLE
    AS '
    SELECT COALESCE(MAX(tier), 0)
    FROM (
        SELECT 9 AS tier
        WHERE user_uuid = target_owner_id
        AND user_uuid IN (SELECT id FROM users)

        UNION ALL

        SELECT og.role_id AS tier
        FROM owner_grants og
        WHERE og.granted_owner_id = target_owner_id
        AND og.grantee_owner_id = user_uuid
    ) sub
    ';

ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledgers ENABLE ROW LEVEL SECURITY;

CREATE POLICY projects_select_policy ON projects
    FOR SELECT TO PUBLIC
    USING (get_owner_role(auth_current_user_id(), owner_id) >= 2);

CREATE POLICY ledgers_select_policy ON ledgers
    FOR SELECT TO PUBLIC
    USING (get_owner_tier(auth_current_user_id(), owner_id) >= 5);

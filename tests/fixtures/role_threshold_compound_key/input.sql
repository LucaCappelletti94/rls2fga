-- The `earth_metabolome` grant rule over a table two columns identify together, carrying
-- both principal tables so every arm of the rule emits a query.
--
-- Which columns such a follow-up query binds is pinned by `COMPOSITE_KEY_GRANTS` in
-- `relation_shapes_tests`. This fixture exists so the same shape reaches the corpus-wide
-- sweeps and runs against a real database, where a query can name the right columns and
-- still fail to execute.

CREATE TABLE users (
    id UUID PRIMARY KEY
);

CREATE TABLE teams (
    id UUID PRIMARY KEY
);

CREATE TABLE team_members (
    team_id UUID NOT NULL REFERENCES teams(id),
    user_id UUID NOT NULL REFERENCES users(id),
    PRIMARY KEY (team_id, user_id)
);

CREATE TABLE ownables (
    tenant_id UUID NOT NULL,
    ownable_id UUID NOT NULL,
    owner_id UUID NOT NULL,
    PRIMARY KEY (tenant_id, ownable_id)
);

CREATE TABLE owner_grants (
    grantee_owner_id UUID NOT NULL,
    granted_owner_id UUID NOT NULL,
    role_id INTEGER NOT NULL
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

        SELECT 4 AS role
        FROM team_members tm
        WHERE tm.user_id = user_uuid
        AND tm.team_id = target_owner_id

        UNION ALL

        SELECT og.role_id AS role
        FROM owner_grants og
        WHERE og.granted_owner_id = target_owner_id
        AND (
            og.grantee_owner_id = user_uuid
            OR og.grantee_owner_id IN (
                SELECT tm.team_id FROM team_members tm WHERE tm.user_id = user_uuid
            )
        )
    ) sub
    ';

ALTER TABLE ownables ENABLE ROW LEVEL SECURITY;

CREATE POLICY ownables_select_policy ON ownables
    FOR SELECT TO PUBLIC
    USING (get_owner_role(auth_current_user_id(), owner_id) >= 2);

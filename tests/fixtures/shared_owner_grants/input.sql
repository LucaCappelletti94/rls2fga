-- Two guarded tables reading one role-threshold function, so the grants they both consult
-- are facts about the owner they share and are written once rather than once per table.
--
-- The thresholds differ, which is what proves one shared ladder can answer two tables at
-- different levels: a viewer may read a sample and not a spectrum.

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

CREATE TABLE owner_grants (
    grantee_owner_id UUID NOT NULL,
    granted_owner_id UUID NOT NULL,
    role_id INTEGER NOT NULL
);

CREATE TABLE samples (
    id UUID PRIMARY KEY,
    owner_id UUID NOT NULL
);

CREATE TABLE spectra (
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

ALTER TABLE samples ENABLE ROW LEVEL SECURITY;
ALTER TABLE spectra ENABLE ROW LEVEL SECURITY;

CREATE POLICY samples_select_policy ON samples
    FOR SELECT TO PUBLIC
    USING (get_owner_role(auth_current_user_id(), owner_id) >= 2);

CREATE POLICY spectra_select_policy ON spectra
    FOR SELECT TO PUBLIC
    USING (get_owner_role(auth_current_user_id(), owner_id) >= 3);

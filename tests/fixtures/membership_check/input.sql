CREATE TABLE users (
    id UUID PRIMARY KEY
);

CREATE TABLE teams (
    id UUID PRIMARY KEY
);

CREATE TABLE team_members (
    team_id UUID NOT NULL REFERENCES teams(id),
    user_id UUID NOT NULL REFERENCES users(id)
);

CREATE TABLE projects (
    id UUID PRIMARY KEY,
    team_id UUID NOT NULL REFERENCES teams(id),
    name TEXT
);

CREATE FUNCTION auth_current_user_id() RETURNS UUID
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')::uuid';

ALTER TABLE projects ENABLE ROW LEVEL SECURITY;

CREATE POLICY projects_select ON projects
    FOR SELECT TO PUBLIC
    USING (EXISTS (
        SELECT 1 FROM team_members
        WHERE team_id = projects.team_id
        AND user_id = auth_current_user_id()
    ));

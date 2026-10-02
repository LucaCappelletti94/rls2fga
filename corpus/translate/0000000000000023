CREATE TABLE users (
    id UUID PRIMARY KEY
);

CREATE TABLE resources (
    id UUID PRIMARY KEY,
    owner_id UUID REFERENCES users(id),
    title TEXT
);

CREATE FUNCTION auth_current_user_id() RETURNS UUID
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')::uuid';

ALTER TABLE resources ENABLE ROW LEVEL SECURITY;

CREATE POLICY resources_select ON resources
    FOR SELECT TO PUBLIC
    USING (owner_id = auth_current_user_id());

CREATE POLICY resources_delete ON resources
    FOR DELETE TO PUBLIC
    USING (owner_id = auth_current_user_id());

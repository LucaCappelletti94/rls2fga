-- Supabase-style auth pattern using auth.uid() function.
-- This is the most common pattern in Supabase applications.

CREATE TABLE users (
    id UUID PRIMARY KEY
);

CREATE TABLE profiles (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    display_name TEXT
);

CREATE FUNCTION auth.uid() RETURNS UUID
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''request.jwt.claim.sub'')::uuid';

ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view their own profile" ON profiles
    FOR SELECT TO PUBLIC
    USING (user_id = auth.uid());

CREATE POLICY "Users can update their own profile" ON profiles
    FOR UPDATE TO PUBLIC
    USING (user_id = auth.uid());

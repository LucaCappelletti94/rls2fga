CREATE TABLE users (
    id UUID PRIMARY KEY
);

CREATE TABLE articles (
    id UUID PRIMARY KEY,
    title TEXT,
    is_public BOOLEAN NOT NULL DEFAULT FALSE
);

ALTER TABLE articles ENABLE ROW LEVEL SECURITY;

CREATE POLICY articles_select ON articles
    FOR SELECT TO PUBLIC
    USING (is_public = TRUE);

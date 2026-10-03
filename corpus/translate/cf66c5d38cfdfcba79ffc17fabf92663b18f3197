-- P9: standalone attribute condition (status = 'published')
CREATE TABLE articles (
  id UUID PRIMARY KEY,
  title TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'draft'
);

ALTER TABLE articles ENABLE ROW LEVEL SECURITY;

CREATE POLICY articles_published ON articles FOR SELECT
    USING (status = 'published');

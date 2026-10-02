-- Upstream connetto R86, quoted from `upstream/rls2fga-clause-below-threshold.md`.
--
-- A share grants a read only when its weight beats the average weight across the whole
-- share table. That average is decided by rows the granted row does not name, so the
-- membership row alone cannot decide it. `paper_shares` carries no row security, so the
-- average is the same number for the tuple loader and for every caller, which is what
-- makes precomputing it ask the caller's own question.

CREATE TABLE papers (
    id INT PRIMARY KEY,
    owner TEXT
);

CREATE TABLE paper_shares (
    paper_id INT NOT NULL REFERENCES papers(id),
    viewer TEXT NOT NULL,
    weight INT NOT NULL,
    PRIMARY KEY (paper_id, viewer)
);

ALTER TABLE papers ENABLE ROW LEVEL SECURITY;

CREATE POLICY papers_p ON papers FOR SELECT USING (
    EXISTS (
        SELECT 1
        FROM paper_shares s
        WHERE s.paper_id = papers.id
          AND s.viewer = current_setting('app.user_id', true)
          AND s.weight > (SELECT avg(weight) FROM paper_shares)
    )
);

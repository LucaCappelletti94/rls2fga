-- Inventory rows 3 and 4, quoted from connetto `crates/connetto-server/tests/capabilities.rs`.
-- All four real policies, so the fixture is the deployment rather than a sample of it.
--
-- `papers_p` is one policy carrying two arms: ownership by the caller's identity, and a
-- share row whose viewer is in the caller's held set. `shares_read` is the same set
-- against a column of the guarded table with no join, and its rows are named by the two
-- columns that identify them together. `shares_insert` delegates to the parent's own RLS
-- with no predicate of its own.

CREATE TABLE papers (
    id INT PRIMARY KEY,
    owner TEXT,
    body TEXT
);

CREATE TABLE paper_shares (
    paper_id INT,
    viewer TEXT,
    PRIMARY KEY (paper_id, viewer)
);

ALTER TABLE papers ENABLE ROW LEVEL SECURITY;
ALTER TABLE paper_shares ENABLE ROW LEVEL SECURITY;

CREATE POLICY papers_p ON papers USING (
    owner = current_setting('app.user_id', true)
    OR EXISTS (
        SELECT 1
        FROM paper_shares s
        WHERE s.paper_id = papers.id
          AND s.viewer = ANY(string_to_array(current_setting('app.subjects', true), ','))
    )
);

CREATE POLICY shares_read ON paper_shares FOR SELECT USING (
    viewer = ANY(string_to_array(current_setting('app.subjects', true), ','))
);

-- You may only grant over a paper you can see. The subquery runs under `papers_p` as
-- the sharer, so a grant naming somebody else's paper finds no row.
CREATE POLICY shares_insert ON paper_shares FOR INSERT WITH CHECK (
    EXISTS (SELECT 1 FROM papers p WHERE p.id = paper_id)
);

CREATE POLICY shares_delete ON paper_shares FOR DELETE USING (true);

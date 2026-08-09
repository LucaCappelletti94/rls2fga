-- Inventory row 8: the caller's set arrives from a set returning function.
--
-- Admitted only because that function's whole body expands a declared setting, so the
-- setting is the source and the function is a spelling of it. A body reading a table
-- would put the authority in the table, where a value the caller sends would let it
-- assert its own membership, and stays refused.
--
-- Two tables, one per spelling, because they are the same database and must land the
-- same way. The body splits, so the separator survives into the caller's contract.

CREATE TABLE documents (
    id INT PRIMARY KEY,
    team_id TEXT
);

CREATE TABLE reports (
    id INT PRIMARY KEY,
    team_id TEXT
);

CREATE FUNCTION user_teams() RETURNS SETOF TEXT
    LANGUAGE sql STABLE
    AS 'SELECT unnest(string_to_array(current_setting(''app.teams'', true), '',''))';

ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE reports ENABLE ROW LEVEL SECURITY;

CREATE POLICY documents_team ON documents FOR SELECT USING (
    team_id IN (SELECT user_teams())
);

CREATE POLICY reports_team ON reports FOR SELECT USING (
    team_id = ANY (ARRAY(SELECT user_teams()))
);

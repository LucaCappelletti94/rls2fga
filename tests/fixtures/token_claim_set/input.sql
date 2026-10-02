-- Inventory row 6: the caller's set arrives as a real list inside the token rather than
-- as a delimited string, so the contract is simply to send the list.
--
-- Two tables, one per spelling, because they are the same database and must land the
-- same way. The chain ends in `->` rather than `->>` because the claim is a jsonb array
-- and `jsonb_array_elements_text` refuses the text `->>` would hand it.
--
-- Containment (`claims -> 'teams' ? team_id`) is deliberately absent: probed on
-- PostgreSQL 18.4, it matches only the string elements of the array, so it is a
-- different database rather than a third spelling of this one.

CREATE TABLE documents (
    id INT PRIMARY KEY,
    team_id TEXT
);

CREATE TABLE reports (
    id INT PRIMARY KEY,
    team_id TEXT
);

ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE reports ENABLE ROW LEVEL SECURITY;

CREATE POLICY documents_team ON documents FOR SELECT USING (
    team_id IN (SELECT jsonb_array_elements_text(
        current_setting('request.jwt.claims')::jsonb -> 'teams'))
);

CREATE POLICY reports_team ON reports FOR SELECT USING (
    team_id = ANY (ARRAY(SELECT jsonb_array_elements_text(
        current_setting('request.jwt.claims')::jsonb -> 'teams')))
);

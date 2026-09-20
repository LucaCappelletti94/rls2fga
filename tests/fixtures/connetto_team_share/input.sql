-- A membership granted to a share key the caller holds, correlated on the team an item
-- belongs to rather than on the item itself. The same shape as `membership_check` with the
-- member column compared against the caller's declared set instead of the caller.

CREATE TABLE teams (
    id INT PRIMARY KEY
);

CREATE TABLE team_members (
    member TEXT NOT NULL,
    team_id INT REFERENCES teams(id),
    PRIMARY KEY (team_id, member)
);

CREATE TABLE items (
    id INT PRIMARY KEY,
    owner TEXT NOT NULL,
    team_id INT NOT NULL REFERENCES teams(id),
    label TEXT
);

ALTER TABLE items ENABLE ROW LEVEL SECURITY;

CREATE POLICY items_p ON items FOR SELECT USING (
    owner = current_setting('app.user_id', true)
    OR EXISTS (
        SELECT 1
        FROM team_members
        WHERE team_members.team_id = items.team_id
          AND team_members.member = ANY(string_to_array(current_setting('app.subjects', true), ','))
    )
);

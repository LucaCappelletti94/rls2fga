-- Inventory row 2. The same database as `connetto_or_policy`, written as two permissive
-- policies instead of one policy carrying an OR.
--
-- PostgreSQL unions permissive policies exactly as it unions the arms of one clause, so
-- these two fixtures must translate to the same thing. Design principle 6: syntax must
-- not pick semantics.

CREATE TABLE notes (
    id INT PRIMARY KEY,
    owner TEXT,
    body TEXT,
    edited_at TEXT
);

ALTER TABLE notes ENABLE ROW LEVEL SECURITY;

CREATE POLICY notes_own ON notes USING (
    owner = current_setting('app.user_id', true)
);

CREATE POLICY notes_subject ON notes USING (
    owner = ANY(string_to_array(current_setting('app.subjects', true), ','))
);

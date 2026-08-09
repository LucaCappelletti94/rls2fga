-- Inventory row 1, quoted from connetto `crates/connetto-server/tests/rls_write_filter.rs`.
--
-- The caller's held set of share keys against the row's owner column, written as one
-- policy with the union inside it. A caller holding no key leaves `app.subjects` unset,
-- so `string_to_array` yields NULL and the second disjunct is NULL rather than true.

CREATE TABLE notes (
    id INT PRIMARY KEY,
    owner TEXT,
    body TEXT,
    edited_at TEXT
);

ALTER TABLE notes ENABLE ROW LEVEL SECURITY;

CREATE POLICY notes_p ON notes USING (
    owner = current_setting('app.user_id', true)
    OR owner = ANY(string_to_array(current_setting('app.subjects', true), ','))
);

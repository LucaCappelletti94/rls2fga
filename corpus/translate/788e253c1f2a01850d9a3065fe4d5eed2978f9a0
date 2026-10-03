-- PostgreSQL built-in current_user pattern.
-- Uses the SQL standard current_user keyword instead of a function.

CREATE TABLE accounts (
    id SERIAL PRIMARY KEY,
    manager TEXT NOT NULL,
    company TEXT
);

ALTER TABLE accounts ENABLE ROW LEVEL SECURITY;

CREATE POLICY account_managers ON accounts
    FOR ALL TO PUBLIC
    USING (manager = current_user);

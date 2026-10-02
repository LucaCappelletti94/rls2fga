-- PostgreSQL policy names are unique per table, so one name is reused freely across
-- tables. OpenFGA condition names are global to the model, so the two guards below have
-- to reach two conditions: they read different columns and compare them opposite ways.

CREATE TABLE campaigns (
    id TEXT PRIMARY KEY,
    starts_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE embargoes (
    id TEXT PRIMARY KEY,
    lifts_at TIMESTAMPTZ NOT NULL
);

ALTER TABLE campaigns ENABLE ROW LEVEL SECURITY;
ALTER TABLE embargoes ENABLE ROW LEVEL SECURITY;

-- Already running.
CREATE POLICY visible_now ON campaigns
    FOR SELECT TO PUBLIC
    USING (starts_at <= now());

-- Not yet lifted.
CREATE POLICY visible_now ON embargoes
    FOR SELECT TO PUBLIC
    USING (lifts_at > now());

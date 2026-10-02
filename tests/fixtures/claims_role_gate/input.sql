-- Inventory row 10. A constant tested against the caller's held set, with no row column
-- in the comparison at all, so the grant is decided by the request alone.

CREATE TABLE audit_log (
    id UUID PRIMARY KEY,
    actor TEXT,
    body TEXT
);

ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;

CREATE POLICY audit_admin ON audit_log
    FOR SELECT TO PUBLIC
    USING ('admin' = ANY(string_to_array(current_setting('app.roles', true), ',')));

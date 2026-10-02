-- Tenant isolation: the most common SaaS multi-tenancy pattern.
-- tenant_id column compared against a session variable via function call.

CREATE TABLE tenants (
    id UUID PRIMARY KEY
);

CREATE TABLE users (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id)
);

CREATE TABLE orders (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    total_amount NUMERIC
);

CREATE FUNCTION current_tenant_id() RETURNS UUID
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.tenant_id'')::uuid';

ALTER TABLE orders ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON orders
    FOR ALL TO PUBLIC
    USING (tenant_id = current_tenant_id());

-- Inventory row 5, the generic multi-tenant shape with the setting read inline.
--
-- `tenant_isolation` already covers the same comparison behind a declared function. This
-- one reads the GUC in the policy itself, and the value it holds is a tenant rather than
-- a person: classifying it as ownership would declare tenant identifiers to be users.

CREATE TABLE tenants (
    id UUID PRIMARY KEY
);

CREATE TABLE documents (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    body TEXT
);

ALTER TABLE documents ENABLE ROW LEVEL SECURITY;

CREATE POLICY documents_tenant ON documents
    FOR ALL TO PUBLIC
    USING (tenant_id = current_setting('app.tenant_id')::uuid);

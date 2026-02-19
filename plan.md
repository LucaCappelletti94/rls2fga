# PostgreSQL RLS → OpenFGA: Formal Translation, Software Support, and Agent Assistance

## Scope

This document defines:
1. A **formal taxonomy** of PostgreSQL Row Level Security patterns and their canonical OpenFGA (Zanzibar) equivalents, with precise rules for when translation is deterministic and when human judgment is required.
2. The **architecture of a software tool** (`rls2fga`) that automates the translation pipeline.
3. An **LLM agent strategy** for the cases the deterministic tool cannot handle.

The ground truth throughout is the `earth-metabolome-initiative/asset-procedure-schema` schema already analyzed in this repo (see `REPORT.md` §3, `data/project-metadata.json`).

---

## 1. Background: What We Are Translating

### 1.1 PostgreSQL RLS Policy Structure

A policy is attached to a table with:

```sql
CREATE POLICY <name> ON <table>
  FOR <command>        -- SELECT | INSERT | UPDATE | DELETE | ALL
  TO <role>            -- role or PUBLIC
  USING (<expr>)       -- filter applied to EXISTING rows (visibility gate)
  WITH CHECK (<expr>); -- filter applied to NEW/MODIFIED rows (write gate)
```

- `USING` is the predicate that decides which rows a user can **see** (SELECT, UPDATE visibility, DELETE).
- `WITH CHECK` is the predicate that decides which rows a user can **write** (INSERT, UPDATE).
- Expressions are arbitrary SQL: function calls, subqueries, JOINs, boolean operators.

The critical point: **RLS is row-filtering**. OpenFGA is **relationship-graph traversal**. Both answer the same question (`can user X do action Y on resource Z?`), but the mechanistic model is completely different.

### 1.2 OpenFGA Authorization Model Structure

```
model
  schema 1.1

type <TypeName>          -- an entity class (user, team, document)
  relations
    define <relation>: [<allowed-types>]           -- a direct graph edge
    define <permission>: <expr using relations>    -- a derived set
```

Permissions are defined as set-algebraic expressions over relations:
- `or` — union of sets
- `and` — intersection
- `but not` — set difference
- `<relation>->member` — traverse from a relation to a nested relation

Tuples are the actual data: `object#relation@subject` (e.g., `document:42#owner@user:alice`).

---

## 2. The Formal Taxonomy: 8 RLS Pattern Classes

Each pattern has:
- **SQL template** — the structural shape of the `USING` / `WITH CHECK` expression
- **Authorization semantic** — what the policy *means* in plain English
- **OpenFGA translation** — the canonical model fragment
- **Tuple generation SQL** — the SELECT that populates the model with data
- **Confidence level**: A (fully automatic) · B (template composition, safe but annotated) · C (needs human review) · D (manual only)

---

### P1 — Numeric Role Threshold on a Known Function

**Confidence: A (fully automatic)**

**SQL template:**
```sql
USING ( get_owner_role(auth_current_user_id(), owner_id) >= N )
```

where `N` is a literal integer corresponding to a role level, and the function body is available and recognizable as a role-threshold checker.

The function `get_owner_role(user_uuid, resource_id) → INTEGER` returns:
- 0 = no access
- 2 = viewer
- 3 = editor
- 4 = admin

by checking: (1) direct ownership → returns max level, (2) team membership → returns max level, (3) explicit grants via a grant table.

**Mapping table:**

| Threshold N | Policy command | OpenFGA permission name |
|-------------|---------------|------------------------|
| ≥ 2 | SELECT | `can_select` |
| ≥ 3 | INSERT | `can_insert` |
| ≥ 3 | UPDATE | `can_update` |
| ≥ 4 | DELETE | `can_delete` |

**OpenFGA translation (complete type block for the EMI schema):**

```
model
  schema 1.1

type user

type team
  relations
    define member: [user]

type ownable
  relations
    define owner_user: [user]
    define owner_team: [team]
    define grant_viewer: [user, team]
    define grant_editor: [user, team]
    define grant_admin:  [user, team]

    -- Role fan-out: each level subsumes all lower levels
    define role_admin:  owner_user or owner_team->member or grant_admin or grant_admin->member
    define role_editor: role_admin or grant_editor or grant_editor->member
    define role_viewer: role_editor or grant_viewer or grant_viewer->member

    -- Action permissions matching the SQL thresholds
    define can_select: role_viewer    -- >= 2
    define can_insert: role_editor    -- >= 3
    define can_update: role_editor    -- >= 3
    define can_delete: role_admin     -- >= 4
```

**Tuple generation SQL:**

```sql
-- User ownership (owner_id references users)
SELECT 'ownable:' || id AS object, 'owner_user' AS relation, 'user:' || owner_id AS subject
FROM ownables
WHERE owner_id IN (SELECT id FROM users)
  AND owner_id IS NOT NULL;

-- Team ownership (owner_id references teams)
SELECT 'ownable:' || id AS object, 'owner_team' AS relation, 'team:' || owner_id AS subject
FROM ownables
WHERE owner_id IN (SELECT id FROM teams)
  AND owner_id IS NOT NULL;

-- Team memberships
SELECT 'team:' || team_id AS object, 'member' AS relation, 'user:' || user_id AS subject
FROM team_members;

-- Explicit grants (role_id: 2=viewer, 3=editor, 4=admin)
SELECT
  'ownable:' || og.granted_owner_id AS object,
  CASE og.role_id
    WHEN 2 THEN 'grant_viewer'
    WHEN 3 THEN 'grant_editor'
    WHEN 4 THEN 'grant_admin'
  END AS relation,
  CASE
    WHEN u.id IS NOT NULL THEN 'user:' || og.grantee_owner_id
    ELSE 'team:' || og.grantee_owner_id
  END AS subject
FROM owner_grants og
LEFT JOIN users u ON u.id = og.grantee_owner_id
WHERE og.role_id IN (2, 3, 4);
```

**Why this is Level A:** The SQL expression structure is unambiguous — a single function call compared to a literal integer. Once the function's semantics are extracted from its body (or from the function registry), the translation is purely mechanical template instantiation.

---

### P2 — Role Name IN-List on a Known Function

**Confidence: A (fully automatic)**

**SQL template:**
```sql
USING ( get_user_role(auth.user_id(), id) IN ('viewer', 'editor', 'admin') )
```

This is semantically identical to P1 but uses role names instead of integer levels. The role-name-to-integer mapping comes from the `roles` table or an ENUM type in the schema.

**OpenFGA translation:** Identical to P1. The tool maps role names to levels via the function registry and instantiates the same template.

**Tuple generation SQL:** Identical to P1 with a role-name-to-integer lookup join.

**Why this is Level A:** Same reasoning as P1. The only added step is the name→level mapping, which is extracted from the schema.

**Edge case within A:** If the IN-list is partial (e.g., `IN ('editor', 'admin')` but not `'viewer'`), the permission definition omits the viewer level:
```
define can_select: role_editor    -- only editor and above, viewer intentionally excluded
```
This is still fully automatic but the tool emits a comment noting that `viewer` access is intentionally excluded.

---

### P3 — Direct Column Equality (Simple Ownership)

**Confidence: A (fully automatic)**

**SQL template:**
```sql
USING ( owner_id = auth.user_id() )
-- or equivalently:
USING ( created_by = current_setting('app.current_user_id')::uuid )
```

**OpenFGA translation:**
```
type resource
  relations
    define owner: [user]
    define can_view:   owner
    define can_edit:   owner
    define can_delete: owner
```

**Tuple generation SQL:**
```sql
SELECT 'resource:' || id AS object, 'owner' AS relation, 'user:' || owner_id AS subject
FROM resources
WHERE owner_id IS NOT NULL;
```

**Why this is Level A:** The expression is a binary equality between a column and the current user accessor. There are no joins, subqueries, or function bodies to inspect.

---

### P4 — EXISTS Subquery: Simple Membership Check

**Confidence: A for simple joins, B for complex WHERE**

**SQL template (Level A):**
```sql
USING (
  EXISTS (
    SELECT 1 FROM team_members
    WHERE team_id = resource.team_id
    AND user_id = auth.user_id()
  )
)
```

**OpenFGA translation:**
```
type team
  relations
    define member: [user]

type resource
  relations
    define team: [team]
    define can_view: team->member
```

**Tuple generation SQL:**
```sql
SELECT 'resource:' || id AS object, 'team' AS relation, 'team:' || team_id AS subject
FROM resources;

SELECT 'team:' || team_id AS object, 'member' AS relation, 'user:' || user_id AS subject
FROM team_members;
```

**Why simple joins are Level A:** The EXISTS subquery contains exactly one table reference with a foreign key join and the current user filter. This is a direct structural match.

**What makes it Level B:**
- The inner SELECT has more than one WHERE condition beyond the FK join and user filter.
- The inner SELECT JOINs more than one table.
- The correlation (e.g., `resource.team_id`) is indirect (goes through another table).

In Level B cases the tool emits the translation with an annotation: `-- REVIEW: verify join path is complete`.

---

### P5 — Parent Resource Permission Inheritance

**Confidence: B (template composition, needs verification)**

**SQL template:**
```sql
-- Document inherits view permission from its parent folder
USING (
  EXISTS (
    SELECT 1 FROM folders f
    WHERE f.id = documents.folder_id
    AND get_user_role(auth.user_id(), f.id) IN ('viewer', 'editor', 'admin')
  )
)
```

**OpenFGA translation:**
```
type folder
  relations
    define owner: [user, team]
    define viewer: [user, team]
    define editor: [user, team]
    define admin:  [user, team]
    define can_view: owner or owner->member or viewer or viewer->member or editor or editor->member or admin or admin->member

type document
  relations
    define parent_folder: [folder]
    define viewer: [user, team]
    -- Inherits from folder AND has own direct grants
    define can_view: viewer or viewer->member or parent_folder->can_view
```

**Tuple generation SQL:**
```sql
SELECT 'document:' || id AS object, 'parent_folder' AS relation, 'folder:' || folder_id AS subject
FROM documents
WHERE folder_id IS NOT NULL;
```

**Why this is Level B, not A:**
- It requires recognizing that the EXISTS wraps a P1/P2 check on a *different table* (the parent).
- The tool must trace the foreign key from `documents.folder_id` → `folders.id` to build the `parent_folder` relation.
- If the parent chain is more than one level deep (folder → project → workspace), the tool emits one level and annotates: `-- TODO: extend hierarchy to project->can_view`.

---

### P6 — Boolean Flag / Public Access Toggle

**Confidence: A for pure flag, B for OR composite with another pattern**

**SQL template (pure flag, Level A):**
```sql
USING ( is_public = TRUE )
```

**OpenFGA translation:**
```
type resource
  relations
    define public_viewer: [user:*]   -- wildcard: any user
    define can_view: public_viewer
```

**Tuple generation SQL:**
```sql
SELECT 'resource:' || id AS object, 'public_viewer' AS relation, 'user:*' AS subject
FROM resources
WHERE is_public = TRUE;
```

**SQL template (composite with role check, Level B):**
```sql
USING (
  is_public = TRUE
  OR get_user_role(auth.user_id(), id) >= 2
)
```

**OpenFGA translation:**
```
type resource
  relations
    define public_viewer: [user:*]
    define owner: [user, team]
    define viewer: [user, team]
    define editor: [user, team]
    define admin:  [user, team]
    define can_view: public_viewer or owner or owner->member or viewer or viewer->member or editor or editor->member or admin or admin->member
```

**Why pure flag is Level A:** Trivial structural match — a boolean column equality.

**Why composite is Level B:** Requires recognizing the P6 + P1 combination, generating and merging both templates, and ensuring the `user:*` wildcard tuple lifecycle is maintained in sync with the `is_public` column.

---

### P7 — AND with Attribute Column (ABAC Crossover)

**Confidence: C — always requires human review**

**SQL template:**
```sql
USING (
  get_user_role(auth.user_id(), id) >= 3
  AND status = 'active'
)
```

**Why this cannot be fully automated:**
OpenFGA is a **relationship-based** authorization system. It has no native concept of querying a resource's own columns (`status = 'active'`). The `status` attribute lives in the database row, not in the authorization graph.

There are three valid ways to handle this, and the correct choice depends on the application's requirements. Only a human can make this decision:

**Option A — Materialize as a relation (recommended if status changes infrequently):**
```
type resource
  relations
    define editor: [user, team]
    define active: [resource:*]   -- present when status='active', absent otherwise
    define can_update: editor and active
```
Requires a sync trigger or outbox event that writes/deletes `resource:X#active@resource:*` when `status` changes. OpenFGA's `and` operator performs intersection.

**Option B — Move the condition to application middleware:**
```
type resource
  relations
    define editor: [user, team]
    define can_update: editor      -- ignores status; application checks status separately
```
The application checks `resource.status = 'active'` from its own query, then calls OpenFGA for the relationship check. Used when the attribute is rarely relevant or when status is always fetched for other reasons.

**Option C — Ignore and rely on RLS as the attribute gate:**
Keep `AND status = 'active'` in the RLS policy unchanged. OpenFGA handles the relationship portion; RLS handles the attribute portion. Defense-in-depth: both must pass.

**Tool behavior for P7:** Emits a commented-out stub with all three options explained, and exits with code 1, requiring human resolution before the model can be considered complete.

---

### P8 — Composite OR / AND of Sub-patterns

**Confidence: B if all sub-patterns are A; C if any sub-pattern is B or C**

**SQL template:**
```sql
USING (
  owner_id = auth.user_id()                    -- P3
  OR get_user_role(auth.user_id(), id) >= 2    -- P1
  OR is_public = TRUE                          -- P6
)
```

**OpenFGA translation (all sub-patterns are A → composite is B):**

The tool recognizes each disjunct, generates the template for each, and merges via `or`:

```
type resource
  relations
    define owner: [user]
    define public_viewer: [user:*]
    define viewer: [user, team]
    define editor: [user, team]
    define admin:  [user, team]
    define can_view: owner or public_viewer or viewer or viewer->member or editor or editor->member or admin or admin->member
```

**What makes it Level C:** If any disjunct contains a P7 (attribute check) or an unrecognized subquery, the whole expression escalates to Level C.

---

## 3. Pattern Decision Tree

The classifier applies this decision tree to each USING/WITH CHECK expression:

```
Root node is...
│
├── BoolExpr(OR) → classify each branch recursively, merge via or
│     ├── All branches Level A → composite is Level B (P8)
│     └── Any branch Level B or above → composite escalates to that level
│
├── BoolExpr(AND) → classify each branch
│     ├── All branches are relationship-based (P1–P6) → intersection → Level B
│     └── Any branch is attribute-based (column comparison, non-user column) → P7 → Level C
│
├── A_Expr with >= or > operator (comparison)
│     ├── Left side is FuncCall AND function is in FunctionRegistry → P1 → Level A
│     ├── Left side is FuncCall AND function NOT in registry but body is available
│     │     ├── Analyze body → if role-threshold pattern: register and apply P1
│     │     └── If body not recognizable as role-threshold → Level C
│     ├── Left side is FuncCall AND body NOT available → Level D
│     └── Left side is ColumnRef to owner/created_by column → P3 → Level A
│
├── A_Expr with IN operator
│     └── Left side is FuncCall → P2 → Level A (same as P1)
│
├── SubLink(EXISTS)
│     ├── Inner SELECT: one table, one FK join, one user filter → P4 Level A
│     ├── Inner SELECT wraps P1/P2 check on a parent table → P5 Level B
│     └── Inner SELECT has complex WHERE or multiple joins → P4 Level B or C
│
├── ColumnRef where column type = boolean → P6 → Level A
│
└── Anything else → Level D (unknown, manual only)
```

---

## 4. Corner Cases and Human Intervention Requirements

These are the specific situations where the tool halts with a human-review annotation (Level C) or produces a stub only (Level D).

---

### Corner Case 1: USING ≠ WITH CHECK (Asymmetric UPDATE)

**Trigger:**
```sql
CREATE POLICY update_doc ON documents FOR UPDATE
  USING (get_role(auth.user_id(), id) >= 2)       -- viewer or above can see the row
  WITH CHECK (get_role(auth.user_id(), id) >= 3);  -- but only editor+ can write it
```

**Problem:** This expresses a visibility/writability split. A user can SELECT the row (to begin an edit) but cannot commit the write unless they meet the stricter condition. Standard Zanzibar models have no built-in notion of this split.

**Tool behavior:** Emits two separate permissions:
```
define can_update_visibility: role_viewer    -- for row filtering (USING clause)
define can_update_write:      role_editor    -- for write validation (WITH CHECK clause)
-- REVIEW: UPDATE has split USING/WITH CHECK. Decide how to enforce both in the application layer.
```

**Human decision required:** Choose one of:
- Enforce both in application middleware (check `can_update_visibility` for SELECT, `can_update_write` for PATCH/PUT).
- Use only `can_update_write` (stricter) and accept that SELECT-before-UPDATE flows may be restricted.
- Redesign the policy to use the same predicate for both (most common resolution).

---

### Corner Case 2: Function Body Uses PL/pgSQL Conditional Logic

**Trigger:**
```sql
USING ( complex_authz(auth.user_id(), id) )
```

where `complex_authz` is:
```plpgsql
CREATE FUNCTION complex_authz(p_user UUID, p_res UUID) RETURNS BOOLEAN AS $$
DECLARE v_org_type TEXT;
BEGIN
  SELECT org_type INTO v_org_type FROM resources WHERE id = p_res;
  IF v_org_type = 'enterprise' THEN
    RETURN EXISTS (SELECT 1 FROM enterprise_admins WHERE user_id = p_user);
  ELSIF v_org_type = 'community' THEN
    RETURN TRUE;  -- public access
  ELSE
    RETURN get_standard_role(p_user, p_res) >= 2;
  END IF;
END;
$$ LANGUAGE plpgsql;
```

**Problem:** The function returns different authorization logic based on a runtime attribute (`org_type`). This is a branching ABAC pattern that cannot be expressed as a single static OpenFGA type without materializing the branches.

**Tool behavior:** Level D. Emits:
```
-- TODO [Level D]: complex_authz() contains conditional logic on resource attribute 'org_type'.
-- This requires one of:
--   (a) Separate OpenFGA types per org_type (e.g., type enterprise_resource, type community_resource)
--   (b) OpenFGA Conditions (schema 1.2+) with org_type as a context parameter on every Check call
--   (c) Keep this policy in RLS entirely; only translate non-branching policies to OpenFGA
-- Function body: [body printed here for reference]
```

---

### Corner Case 3: Multi-Level Parent Hierarchy (Recursive)

**Trigger:**
```sql
-- Items inherit from folders, folders from projects, projects from workspaces
USING ( get_role_on_ancestor(auth.user_id(), id) >= 2 )
```

where `get_role_on_ancestor` recursively walks a parent chain using a recursive CTE or a recursive PL/pgSQL loop.

**Problem:** OpenFGA does not support recursive relations. The authorization graph must be a DAG with finite depth. The parent chain must be explicitly modeled at each level.

**Tool behavior:** Level D. Emits:
```
-- TODO [Level D]: get_role_on_ancestor() performs recursive hierarchy traversal.
-- OpenFGA does not support recursive relations. Options:
--   (a) Flatten to a known fixed depth in the model:
--       item->folder->project->workspace (3 explicit hops)
--   (b) Denormalize: at write time, write tuples for every ancestor level
--       (item:X#ancestor_project@project:Y AND item:X#ancestor_workspace@workspace:Z)
--   (c) Keep this policy in RLS; it cannot be expressed in standard OpenFGA.
-- If maximum depth is ≤ 4 and known at design time, option (a) is feasible.
```

---

### Corner Case 4: Policy Targets a Specific Database Role (Not PUBLIC)

**Trigger:**
```sql
CREATE POLICY admin_override ON documents
  TO service_role           -- only applies when connected as service_role
  USING (TRUE);             -- unrestricted access
```

**Problem:** OpenFGA has no concept of a Postgres connection role. `service_role` is a database-level identity, not an application user identity propagated through `auth.user_id()`.

**Tool behavior:** Level C. Emits:
```
-- REVIEW [Level C]: Policy 'admin_override' targets database role 'service_role'.
-- Database roles are Postgres-level and have no OpenFGA equivalent. Options:
--   (a) If service_role is used only by background jobs/migrations: skip translation (keep in RLS).
--   (b) If service_role maps to a service account application identity: add a 'service_account'
--       user type and grant it 'admin' relation on all relevant resource types.
--   (c) If this is an intentional superuser bypass: use 'user:*' wildcard for the service identity.
```

---

### Corner Case 5: NULL Handling in Owner Checks

**Trigger:**
```sql
USING ( owner_id = auth.user_id() )
-- where owner_id can be NULL for some rows
```

In SQL, `NULL = anything` evaluates to `NULL` (falsy), so NULL owners correctly deny access in RLS. In OpenFGA, a missing tuple means no access — semantically equivalent — but the tuple generation query must not emit `resource:X#owner@user:null-uuid` for NULL-owner rows.

**Tool behavior:** Level A — **handled automatically** — but always emits an explicit NULL guard in the tuple query:
```sql
WHERE owner_id IS NOT NULL   -- always added; NULL rows have no tuples, OpenFGA denies by default
```

This is the most common source of parity mismatches in practice when the guard is omitted. The tool adds it unconditionally for all FK-based tuple queries.

---

### Corner Case 6: Function Body Not Available

**Trigger:** The policy references a function defined in an extension, a compiled library, or a migration file not included in the tool's input.

**Tool behavior:** Level D. Emits:
```
-- TODO [Level D]: Function 'get_tenant_role' body is not available in the provided DDL.
-- Options to resolve:
--   (a) Include the migration file defining the function in the input DDL.
--   (b) Add the function to the function registry JSON with manual semantic annotation.
--   (c) Run rls2fga with --db-url to introspect the live database.
```

The function registry JSON resolves this without requiring DB access:
```json
{
  "get_tenant_role": {
    "kind": "role_threshold",
    "role_levels": {"member": 1, "admin": 2},
    "grant_table": "tenant_memberships",
    "grant_role_col": "role"
  }
}
```

---

### Corner Case 7: Temporal / Expiry-Based Access

**Trigger:**
```sql
USING (
  get_role(auth.user_id(), id) >= 2
  AND expires_at > NOW()
)
```

**Problem:** `expires_at > NOW()` is a time-based condition on a resource attribute (P7 sub-case). Unlike a static attribute like `status`, this condition changes autonomously over time without any application-initiated write event — there is no INSERT/UPDATE to hook a sync on.

**Tool behavior:** Level C (P7 escalation). Emits:
```
-- REVIEW [Level C]: Policy includes temporal condition 'expires_at > NOW()'.
-- Time-based conditions require one of:
--   (a) OpenFGA Conditions (schema 1.2+): define condition expiry_check(expiry: timestamp)
--       and pass expires_at as a context parameter on every Check API call.
--       Pro: no sync required. Con: requires OpenFGA 1.2+, changes all call sites.
--   (b) Scheduled job: write tuple on grant, delete tuple when expires_at passes
--       (requires cron/background worker). Risk: sync lag causes window of incorrect access.
--   (c) Keep temporal gate in RLS; translate only the relationship portion to OpenFGA.
--       This is the safest option: RLS enforces expiry, OpenFGA enforces relationships.
```

---

### Corner Case 8: Policy Uses Session Variables Beyond User ID

**Trigger:**
```sql
USING (
  owner_id = auth.user_id()
  AND tenant_id = current_setting('app.tenant_id')::uuid
)
```

**Problem:** The policy enforces multi-tenancy through a session variable (`app.tenant_id`). OpenFGA does not read session variables during authorization checks.

**Tool behavior:** Level C. Emits:
```
-- REVIEW [Level C]: Policy uses session variable 'app.tenant_id' for tenant isolation.
-- Options:
--   (a) Add tenant as a type in OpenFGA and model resource ownership under tenant:
--         define can_view: (tenant_member and owner) or ...
--       This requires populating 'resource:X#tenant@tenant:Y' tuples for every resource.
--   (b) Pass tenant_id as a contextual tuple on each Check call (ephemeral, not stored).
--       The application constructs the tuple at call time from the session.
--   (c) Keep tenant isolation in RLS and translate only user-level authorization to OpenFGA.
--       Most practical when tenant_id is stable and checked uniformly across all tables.
```

---

## 5. Confidence Level Summary

| Pattern | Name | SQL Structure | Confidence | Notes |
|---------|------|--------------|------------|-------|
| P1 | Numeric role threshold | `func(user, res) >= N` | **A** | Function must be in registry or body parseable |
| P2 | Role name IN-list | `func(user, res) IN ('viewer', ...)` | **A** | Same as P1; name→level from roles table |
| P3 | Direct ownership | `owner_id = auth.user_id()` | **A** | Always with NULL guard |
| P4 (simple) | EXISTS membership | `EXISTS (SELECT 1 FROM members WHERE ...)` | **A** | One table, one FK join, one user filter |
| P4 (complex) | EXISTS with joins | EXISTS with multiple tables or WHERE clauses | **B** | Emit with REVIEW annotation |
| P5 | Parent inheritance | EXISTS wrapping P1/P2 on parent table | **B** | FK tracing required; only one level |
| P6 (pure) | Boolean flag | `is_public = TRUE` | **A** | Wildcard tuple lifecycle must be synced |
| P6 (composite) | Flag OR role check | `is_public OR func(user, res) >= N` | **B** | Merge of P1 and P6 templates |
| P8 | OR of A-level patterns | `P3 OR P1 OR P6` | **B** | B if all sub-patterns are A |
| P8 | OR with B/C patterns | Any sub-pattern ≥ B | **C** | Escalates to highest sub-pattern level |
| P7 | AND with attribute | `func(...) >= N AND status = 'active'` | **C** | Human must choose materialization strategy |
| CC1 | Asymmetric UPDATE | USING ≠ WITH CHECK | **C** | Human must decide how to unify |
| CC2 | Branching PL/pgSQL | IF/ELSIF on resource attribute | **D** | Cannot express as single static type |
| CC3 | Recursive hierarchy | Recursive CTE / recursive function | **D** | OpenFGA does not support recursion |
| CC4 | Database role target | `TO service_role` | **C** | No OpenFGA equivalent for DB roles |
| CC6 | Unknown function | Function body unavailable | **D** | Use function registry to resolve |
| CC7 | Temporal condition | `AND expires_at > NOW()` | **C** | Requires scheduled sync or Conditions |
| CC8 | Session variable | `AND tenant_id = current_setting(...)` | **C** | Tenant must be modeled as a type or contextual tuple |

---

## 6. Software Tool: `rls2fga`

### 6.1 Language and Dependencies

**Language:** Rust

**Core dependencies:**
- `sqlparser` (`sqlparser-rs`) — pure Rust SQL parser, PostgreSQL dialect; returns native Rust AST types with no C FFI or protobuf; actively maintained and well-tested against real Postgres DDL
- `tera` — Jinja2-compatible template engine for DSL output generation
- `clap` — CLI argument parsing
- `serde` / `serde_json` — function registry serialization and agent JSON validation
- `reqwest` + `tokio` — async HTTP client for Anthropic API calls (LLM agent, optional feature flag `agent`)
- `sqlx` — optional (`db` feature flag), for `--db-url` live introspection mode

**Why `sqlparser` over `pg_query`:** `sqlparser-rs` is pure Rust with no FFI, produces native strongly-typed AST enums that are trivial to pattern-match in Rust, and handles all the DDL we need (`CREATE TABLE`, `CREATE FUNCTION`, `ALTER TABLE ENABLE ROW LEVEL SECURITY`, `CREATE POLICY`). The `pg_query` Rust crate requires the `libpg_query` C library and returns a protobuf blob, making AST traversal significantly more verbose.

### 6.2 Seven-Stage Pipeline

```
Input: PostgreSQL DDL files (or --db-url for live introspection)
│
├─ Stage 1: SQL Parser
│    pglast.parse_sql() → list of Statement AST nodes
│
├─ Stage 2: Schema Indexer
│    Builds: TableIndex (columns, FKs), FunctionIndex, PolicyIndex
│    Output: SchemaContext
│
├─ Stage 3: Function Body Analyzer
│    For each function referenced in any policy:
│      Parse body (SQL or plpgsql)
│      Classify as role_threshold / membership / unknown
│      Memoize as FunctionSemantic in FunctionRegistry
│    Output: FunctionRegistry
│
├─ Stage 4: Pattern Classifier
│    Visits each policy's USING and WITH CHECK AST
│    Applies P1–P8 recognizers recursively (handles AND/OR composition)
│    Assigns PatternClass + ConfidenceLevel per expression
│    Output: list of ClassifiedPolicy
│
├─ Stage 5: OpenFGA Model Generator
│    For each resource type (table with RLS enabled):
│      Instantiate Jinja2 template matching the classified pattern
│      Merge USING and WITH CHECK into unified permissions
│      Detect and annotate USING ≠ WITH CHECK splits (Corner Case 1)
│    Output: AuthzModel (OpenFGA DSL text)
│
├─ Stage 6: Tuple Query Generator
│    For each relation in the model:
│      Trace FK path in SchemaContext → emit parameterized SELECT
│      Always add IS NOT NULL guards (Corner Case 5)
│    Output: TupleSQL (annotated SQL file)
│
└─ Stage 7: Output Formatter
     Writes: {name}.fga               (OpenFGA DSL model)
     Writes: {name}_tuples.sql        (tuple generation queries)
     Writes: {name}_report.md         (confidence table, all TODOs)
     Writes: {name}_parity.sql        (parity test harness scaffold)
```

### 6.3 Directory Structure

```
translator/
├── Cargo.toml                           # workspace member; features: agent (reqwest/tokio), db (sqlx)
├── src/
│   ├── main.rs                          # clap CLI entry point; orchestrates the 7 stages
│   ├── parser/
│   │   ├── mod.rs
│   │   ├── sql_parser.rs                # sqlparser-rs (PostgreSQL dialect) → SchemaContext
│   │   └── function_analyzer.rs         # function body AST → FunctionSemantic
│   ├── classifier/
│   │   ├── mod.rs
│   │   ├── patterns.rs                  # PatternClass enum (P1–P8), ConfidenceLevel (A–D)
│   │   ├── recognizers.rs               # one recognizer fn per pattern; matches on sqlparser AST enums
│   │   ├── policy_classifier.rs         # recursive AND/OR handler → ClassifiedPolicy
│   │   └── function_registry.rs         # load/save FunctionSemantic (serde_json)
│   ├── generator/
│   │   ├── mod.rs
│   │   ├── templates/openfga/           # Tera templates per pattern
│   │   │   ├── p1_role_threshold.tera
│   │   │   ├── p3_direct_owner.tera
│   │   │   ├── p4_membership.tera
│   │   │   ├── p5_parent_hierarchy.tera
│   │   │   └── p6_public_flag.tera
│   │   ├── templates/spicedb/           # same patterns, ZED dialect
│   │   ├── model_generator.rs           # ClassifiedPolicy → AuthzModel (calls Tera)
│   │   ├── tuple_generator.rs           # AuthzModel + SchemaContext → TupleSQL
│   │   └── parity_generator.rs          # parity test harness SQL scaffold
│   ├── agent/                           # feature = "agent"
│   │   ├── mod.rs
│   │   ├── agent.rs                     # 5-step Anthropic API calls via reqwest
│   │   ├── prompts.rs                   # structured context builder
│   │   └── validator.rs                 # DSL syntax + semantic completeness check
│   └── output/
│       ├── mod.rs
│       ├── formatter.rs                 # writes .fga, _tuples.sql, _report.md, _parity.sql
│       └── report.rs                    # builds _report.md confidence table
└── tests/
    ├── fixtures/
    │   ├── earth_metabolome/            # PRIMARY: EMI schema (P1 pattern)
    │   │   ├── input.sql                # DDL for users, teams, owner_grants, ownables, policies
    │   │   ├── expected.fga             # canonical model from REPORT.md §3.2
    │   │   ├── expected_tuples.sql      # 4 tuple queries from REPORT.md §3.4
    │   │   └── function_registry.json   # pre-built registry for get_owner_role
    │   ├── simple_ownership/            # P3: owner_id = auth.user_id()
    │   ├── membership_check/            # P4: EXISTS team_members
    │   ├── parent_hierarchy/            # P5: document inherits from folder
    │   ├── public_flag/                 # P6: is_public = TRUE
    │   ├── asymmetric_update/           # Corner Case 1: USING ≠ WITH CHECK
    │   ├── null_owner/                  # Corner Case 5: NULL owner handling
    │   └── abac_status/                 # Corner Case P7: status attribute AND
    ├── parser_tests.rs
    ├── classifier_tests.rs
    ├── model_generator_tests.rs
    ├── tuple_generator_tests.rs
    └── end_to_end_tests.rs              # golden-file diff: output == expected.fga
```

### 6.4 CLI Reference

```
rls2fga [OPTIONS] <input.sql>...

Options:
  --schema-dir DIR           Process all .sql files in directory
  --db-url URL               Introspect live PostgreSQL (reads DDL via information_schema)
  --function-registry FILE   Pre-built JSON mapping function names to FunctionSemantic
  --output-dir DIR           Where to write output files (default: ./rls2fga-output)
  --target {openfga,spicedb} DSL dialect (default: openfga)
  --min-confidence {A,B,C,D} Downgrade patterns below this level to TODO blocks (default: B)
  --agent                    Invoke LLM agent for Level C/D patterns
  --agent-provider {anthropic,openai}  (default: anthropic)
  --verbose                  Print AST dumps for unrecognized patterns

Exit codes:
  0  All policies translated at confidence >= --min-confidence
  1  Some policies below --min-confidence (see _report.md for TODOs)
  2  SQL parse error in input
  3  Agent invocation failed
```

### 6.5 Function Registry Format

The pre-built function registry eliminates the need to re-parse known function bodies and resolves Level D → A for functions defined outside the input DDL (Corner Case 6). The EMI-specific registry is a ready deliverable at `data/function_registry_emi.json`:

```json
{
  "get_owner_role": {
    "kind": "role_threshold",
    "user_param_index": 0,
    "resource_param_index": 1,
    "role_levels": {
      "viewer": 2,
      "editor": 3,
      "admin": 4
    },
    "grant_table": "owner_grants",
    "grant_grantee_col": "grantee_owner_id",
    "grant_resource_col": "granted_owner_id",
    "grant_role_col": "role_id",
    "team_membership_table": "team_members",
    "team_membership_user_col": "user_id",
    "team_membership_team_col": "team_id"
  },
  "auth_current_user_id": {
    "kind": "current_user_accessor",
    "returns": "uuid"
  }
}
```

---

## 7. LLM Agent for Level C and Level D Patterns

### 7.1 When the Agent Runs

The agent is invoked **only for Level C and Level D patterns** and only when `--agent` is passed. Level A and B are handled deterministically — no LLM involvement.

The agent's job: given a policy expression the rule-based classifier could not resolve, produce a plausible OpenFGA DSL fragment with an explicit confidence label and a list of assumptions.

### 7.2 Structured Context Passed to the Agent

The agent receives a structured JSON context, not raw prompt text. This keeps the context focused and reduces hallucination:

```json
{
  "task": "Translate the following PostgreSQL RLS policy to OpenFGA DSL.",
  "policy": {
    "table": "resources",
    "command": "UPDATE",
    "using_sql": "complex_authz(auth.user_id(), id) AND status = 'active'",
    "classifier_result": {
      "pattern": "P7_ABAC_AND",
      "confidence": "C",
      "reason": "Policy contains attribute check on 'status' column (non-relationship condition)"
    }
  },
  "relevant_schema": {
    "resources": {"id": "uuid", "owner_id": "uuid", "status": "text"},
    "users": {"id": "uuid"},
    "team_members": {"team_id": "uuid", "user_id": "uuid"}
  },
  "function_definitions": {
    "complex_authz": {"language": "plpgsql", "body": "-- [full body]"}
  },
  "style_reference": {
    "description": "OpenFGA DSL 1.1. Use 'or' for union, '->' for traversal.",
    "example": "define can_view: owner or owner->member or viewer or viewer->member"
  },
  "target": "openfga",
  "schema_version": "1.1"
}
```

### 7.3 Five-Step Agent Protocol

Each step's output is validated before the next step runs. On validation failure, one retry with the error shown is attempted; on second failure, the step produces a stub with a TODO.

**Step 1 — Function Semantic Extraction**
Prompt: "Read the function body. Describe what cases it returns TRUE and which RLS pattern (ownership / threshold / membership) each case corresponds to."
Output schema: `FunctionSemantic` JSON (validated against JSON schema).

**Step 2 — Policy Interpretation**
Prompt: "Given the function semantic, explain what class of users the policy permits. Identify which sub-expressions are relationship-based and which are attribute-based."
Output: structured explanation with `relationship_part` and `attribute_part` fields.

**Step 3 — OpenFGA DSL Generation**
Prompt: "Generate the OpenFGA 1.1 DSL type block. Annotate attribute-based conditions with `-- CONDITION: ...`. Include all commands for this table."
Output: DSL code block. Validated with `openfga model validate` subprocess call.

**Step 4 — Tuple Query Generation**
Prompt: "Generate SQL SELECTs that populate OpenFGA tuples from Postgres data. Each query must produce `(object, relation, subject)` rows. Add `IS NOT NULL` guards for nullable FK columns."
Output: SQL code blocks.

**Step 5 — Self-Review**
Prompt: "Review your translation. Does `can_select` correctly reflect `>= 2`? Does `can_delete` reflect `>= 4`? List all assumptions and assign confidence: `confident`, `plausible`, or `speculative`."
Output: `{ "confidence": "...", "assumptions": [...], "review_notes": "..." }`.

### 7.4 Agent Output Annotation in .fga Files

Agent-generated blocks are always marked:

```
-- [agent: confident] Translation generated by claude-sonnet-4-6
define can_update: editor or editor->member or admin or admin->member

-- [agent: plausible] Attribute condition handled via relation materialization
-- ASSUMPTION: sync service writes resource:X#active@resource:* on status='active'
-- ASSUMPTION: sync service deletes the tuple when status changes away from 'active'
-- REVIEW: verify sync service handles all status transitions
define can_update_active: can_update and active
```

Blocks marked `speculative` always include `-- REVIEW REQUIRED` and are excluded from the emitted model unless `--min-confidence D` is explicitly passed.

### 7.5 Agent Output Validation

**Layer 1 — DSL syntax:** Run `openfga model validate` as a subprocess. Feed the error back to the agent on failure; retry once.

**Layer 2 — Semantic completeness:** For every `CREATE POLICY FOR <command>` on table T, verify a corresponding `can_<action>` permission exists in the generated type block for T. Missing permissions are emitted as stubs with `-- TODO`.

**Layer 3 — Parity spot-check (optional, requires `--db-url`):** Run the generated tuple queries against the live DB, populate a sample of 1,000 `(user, resource, action)` triples, and compare `get_owner_role()` results against OpenFGA `Check` API results. Reports parity percentage in the `_report.md`.

---

## 8. GitHub Actions CI Integration

### `rls2fga-ci.yml` — Per-PR SQL Change Check

Runs on every pull request that touches `.sql` files:

1. Install `rls2fga` from `translator/`
2. Run `rls2fga --schema-dir sql/ --function-registry data/function_registry_emi.json --min-confidence B`
3. Upload `.fga`, `_tuples.sql`, and `_report.md` as artifacts
4. Post PR comment with the confidence table from `_report.md`
5. If a committed `.fga` reference model exists, diff against it and show changes
6. Exit code 0 → green. Exit code 1 → warning comment listing Level C/D items. Exit code 2 → red failure.

### `schema-drift.yml` — Nightly Drift Detection

Runs nightly against the production database:

1. Run `rls2fga --db-url $PG_URL` against the live schema
2. Diff generated model against the committed reference `.fga` in the repo
3. If a diff exists: open a GitHub issue tagged `schema-drift` with the diff attached
4. Run parity spot-check (100 random triples via the `authz-parity` Rust crate)
5. If parity < 99.9%: send a Slack/email alert

---

## 9. Verification Strategy

### 9.1 Golden-File End-to-End Test (Primary)

The `earth_metabolome` fixture is the primary correctness oracle. It must pass before any other work is considered done:

```
Input:    tests/fixtures/earth_metabolome/input.sql
          tests/fixtures/earth_metabolome/function_registry.json
Expected: tests/fixtures/earth_metabolome/expected.fga    ← from REPORT.md §3.2
          tests/fixtures/earth_metabolome/expected_tuples.sql ← from REPORT.md §3.4

Test:     rls2fga input.sql --function-registry function_registry.json
          diff output.fga expected.fga         → must be empty
          diff output_tuples.sql expected_tuples.sql → must be empty
```

### 9.2 Pattern Unit Tests

For each pattern P1–P8: a minimal single-pattern SQL fixture, run through the classifier, assert:
- Correct `PatternClass`
- Correct `ConfidenceLevel`
- Generated DSL fragment matches the template output for that pattern exactly

### 9.3 Corner Case Tests

For each of the 8 corner cases (§4):
- Assert the tool produces the correct confidence level (C or D)
- Assert the correct TODO annotation text is present in the output
- Assert no DSL model block is emitted for Level D patterns (only the stub comment)

### 9.4 Parity Test Infrastructure

The generated `_parity.sql` scaffold creates a harness table and sample queries:

```sql
CREATE TABLE IF NOT EXISTS authz_parity_tests (
    id          SERIAL PRIMARY KEY,
    user_id     UUID NOT NULL,
    resource_id UUID NOT NULL,
    action      TEXT NOT NULL,       -- 'select' | 'insert' | 'update' | 'delete'
    rls_result  BOOLEAN NOT NULL,
    fga_result  BOOLEAN,
    matches     BOOLEAN GENERATED ALWAYS AS (rls_result = fga_result) STORED,
    tested_at   TIMESTAMPTZ
);

-- Populate with random samples
INSERT INTO authz_parity_tests (user_id, resource_id, action, rls_result)
SELECT u.id, o.id, 'select', (get_owner_role(u.id, o.owner_id) >= 2)
FROM (SELECT id FROM users ORDER BY RANDOM() LIMIT 100) u,
     (SELECT id, owner_id FROM ownables ORDER BY RANDOM() LIMIT 100) o
ON CONFLICT DO NOTHING;
-- (repeated for insert/update/delete thresholds)

-- Check parity after fga_result populated by authz-parity Rust crate
SELECT action,
       COUNT(*) FILTER (WHERE matches) AS matching,
       COUNT(*) AS total,
       ROUND(100.0 * COUNT(*) FILTER (WHERE matches) / COUNT(*), 4) AS parity_pct
FROM authz_parity_tests
WHERE fga_result IS NOT NULL
GROUP BY action;
```

**Acceptance criterion before any cutover:** 99.99% parity on ≥ 10,000 samples per action type.

---

## 10. Implementation Sequence

Each step has a concrete, verifiable milestone. Steps are ordered by dependency.

| Step | Deliverable | Milestone |
|------|-------------|-----------|
| 1 | `RLS-PATTERN-TAXONOMY.md` (this file) | Formal vocabulary established |
| 2 | `tests/fixtures/earth_metabolome/` | Ground truth fixture from REPORT.md §3.2 and §3.4 |
| 3 | `parser/sql_parser.py` + `function_analyzer.py` + `test_parser.py` | `parse_schema_files()` returns correct `SchemaContext` for EMI DDL |
| 4 | P1, P3, P6 recognizers + P1 Jinja2 template | `rls2fga earth_metabolome/input.sql` output matches `expected.fga` |
| 5 | `tuple_generator.py` + `test_tuple_generator.py` | Output `_tuples.sql` matches `expected_tuples.sql` |
| 6 | P2, P4, P5 recognizers + fixtures | All three additional pattern tests pass |
| 7 | P7, P8 recognizers (Level C/D stub output) | Corner case test suite passes |
| 8 | `cli.py` + `formatter.py` + `report.py` | Full `rls2fga` command works end-to-end |
| 9 | `agent/agent.py` + `agent/validator.py` | Agent tests pass with mocked LLM responses |
| 10 | `parity_generator.py` | `_parity.sql` scaffold generated for EMI schema |
| 11 | GitHub Actions workflows | CI runs in a staging branch |
| 12 | `translator/README.md` | Usage guide and function registry format reference |

---

## 11. Critical Files in This Repo

| File | Role |
|------|------|
| `REPORT.md` §3.2 | Canonical EMI OpenFGA model → ground truth for `expected.fga` |
| `REPORT.md` §3.4 | Tuple derivation SQL → ground truth for `expected_tuples.sql` |
| `RLS-TO-ZANZIBAR-GUIDE.md` | Pattern examples (P1–P6), parity test SQL for `parity_generator.py` |
| `data/project-metadata.json` | Exact RLS policy SQL expressions (`using`, `with_check`) for EMI |
| `examples/openfga_full.rs` | Third canonical form of the EMI model (cross-check for `expected.fga`) |
| `examples/sync_service.rs` | Tuple sync pattern to follow in `tuple_generator.py` output comments |

---

*Last updated: February 17, 2026*

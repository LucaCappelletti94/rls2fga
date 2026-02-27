# rls2fga

[![CI](https://github.com/LucaCappelletti94/rls2fga/actions/workflows/ci.yml/badge.svg)](https://github.com/LucaCappelletti94/rls2fga/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/LucaCappelletti94/rls2fga/graph/badge.svg)](https://codecov.io/gh/LucaCappelletti94/rls2fga)
[![License](https://img.shields.io/github/license/LucaCappelletti94/rls2fga)](https://github.com/LucaCappelletti94/rls2fga/blob/main/LICENSE)

Convert `PostgreSQL` [Row Level Security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html) (RLS) policies into [OpenFGA](https://openfga.dev/docs) authorization model definitions and relationship tuples.

## What it does

`PostgreSQL` RLS lets you gate row access with SQL expressions such as `owner_id = current_user_id()` or `EXISTS (SELECT 1 FROM memberships ...)`. [OpenFGA](https://openfga.dev/docs) represents those rules as typed authorization models and relationship tuples — fine-grained, per-resource permissions evaluated at the application layer.

`rls2fga` classifies each RLS `USING` / `WITH CHECK` expression into one of ten canonical patterns (P1–P10) and generates:

- an **`OpenFGA` DSL model** with the corresponding types and relations
- **SQL queries** that populate the relationship tuples from your live database

Policies that cannot be fully translated are flagged with a confidence level and emit `-- TODO` items for manual review.

## Installation

`rls2fga` is not published to crates.io — it depends on a git-sourced `sqlparser`, which crates.io forbids. Use a git dependency:

```toml
[dependencies]
rls2fga = { git = "https://github.com/LucaCappelletti94/rls2fga", branch = "main" }
```

Or with `cargo add`:

```bash
cargo add rls2fga --git https://github.com/LucaCappelletti94/rls2fga --branch main
```

To enable optional integrations, add the relevant feature flag:

```toml
rls2fga = { git = "https://github.com/LucaCappelletti94/rls2fga", branch = "main", features = ["db"] }
```

## Cargo Features

No features are enabled by default.

| Feature | Enables | Purpose |
|---------|---------|---------|
| `agent` | `reqwest`, `tokio` | Push generated models and tuples to a live `OpenFGA` instance via its HTTP API |
| `db` | `diesel` (`PostgreSQL`) | Connect to a live `PostgreSQL` database to read schema metadata and execute tuple queries |

## Usage

The library is a four-stage pipeline: parse a SQL schema, classify its RLS policies, generate an `OpenFGA` authorization model, and generate SQL queries to populate the corresponding tuples.

```rust
use rls2fga::classifier::function_registry::FunctionRegistry;
use rls2fga::classifier::patterns::ConfidenceLevel;
use rls2fga::classifier::policy_classifier::classify_policies;
use rls2fga::generator::model_generator::generate_model;
use rls2fga::generator::tuple_generator::{format_tuples, generate_tuple_queries};
use rls2fga::parser::sql_parser::parse_schema;

let sql = "
    CREATE TABLE documents (
        id       UUID PRIMARY KEY,
        owner_id UUID NOT NULL
    );
    ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
    CREATE POLICY documents_owner ON documents
        FOR SELECT TO PUBLIC
        USING (owner_id = current_user_id());
";

// Stage 1: Parse the SQL schema
let db = parse_schema(sql).expect("parse error");

// Stage 2: Classify RLS policies into patterns P1–P10
let registry = FunctionRegistry::default();
let policies = classify_policies(&db, &registry);

// Stage 3: Generate the OpenFGA DSL authorization model
let model = generate_model(&policies, &db, &registry, ConfidenceLevel::B);
println!("{}", model.dsl);

// Stage 4: Generate SQL that populates OpenFGA relationship tuples
let tuples = generate_tuple_queries(&policies, &db, &registry, ConfidenceLevel::B);
println!("{}", format_tuples(&tuples));

// Review translation gaps
for todo in &model.todos {
    eprintln!("[{}] {}: {}", todo.level, todo.policy_name, todo.message);
}
```

The `min_confidence` parameter controls which policies appear in the output:

| Level | Meaning |
|-------|---------|
| `A` | Fully translated; no manual review needed |
| `B` | Composite patterns where all sub-expressions are A-level |
| `C` | Partial translation; ABAC crossovers or attribute guards present |
| `D` | Unrecognised expression; always emits a TODO item |

### Generated model (example)

For the ownership example above, `model.dsl` contains:

```fga
model
  schema 1.1

type user

type documents
  relations
    define owner: [user]
    define can_select: owner
```

Apply it with the [OpenFGA CLI](https://openfga.dev/docs/getting-started/setup-openfga):

```bash
fga model write --store-id "$FGA_STORE_ID" --file model.fga
```

### Generated tuple SQL (example)

```sql
-- documents#owner: direct ownership
SELECT 'documents:' || id    AS object,
       'owner'               AS relation,
       'user:' || owner_id   AS subject
FROM documents
WHERE owner_id IS NOT NULL;
```

Run this query against your database, convert the rows to `OpenFGA` tuple objects, and load them with `fga tuple write`.

Build API documentation locally:

```bash
cargo doc --all-features --no-deps --open
```

## Supported RLS Patterns

| Pattern | Name | RLS expression shape | `OpenFGA` mapping |
|---------|------|----------------------|-----------------|
| P1 | `NumericThreshold` | `role_fn(user, resource) >= N` | Hierarchical relations derived from a numeric level |
| P2 | `RoleNameInList` | `role_fn(user, resource) IN ('viewer', ...)` | One direct relation per allowed role name |
| P3 | `DirectOwnership` | `owner_id = current_user_id()` | `define owner: [user]` direct relation |
| P4 | `ExistsMembership` | `EXISTS (SELECT 1 FROM members WHERE ...)` | Group membership via a `member` relation |
| P5 | `ParentInheritance` | FK join carrying a parent table's policy | Tuple-to-userset (`parent->relation`) |
| P6 | `BooleanFlag` | `is_public = TRUE` | Wildcard `[user:*]` public access |
| P7 | `AbacAnd` | Relationship check `AND` attribute guard | Relationship part translated; attribute guard emitted as `-- TODO [Level C]` |
| P8 | `Composite` | `expr1 OR expr2` / `expr1 AND expr2` | `union` / `intersection` of sub-expressions |
| P9 | `AttributeCondition` | `status = 'published'`, `priority >= 3` | Not directly translatable; emitted as `-- TODO [Level C]` |
| P10 | `ConstantBool` | `TRUE` / `FALSE` | Open (`[user:*]`) or closed (no access) |
| — | `Unknown` | Unrecognised expression | Always emitted as `-- TODO [Level D]` |

## Limitations

- **Not on crates.io**: the `sqlparser` dependency is tracked from a git branch; crates.io forbids git dependencies in published crates.
- **Library only**: there is no CLI binary. The library must be called from Rust code.
- **Partial ABAC (P7)**: policies with an attribute guard (`AND col = value`) are only partially translated; the attribute condition becomes a `-- TODO [Level C]` comment.

## Policy Role Scope (`TO <role>`)

When a `PostgreSQL` policy targets a specific role — for example `CREATE POLICY ... TO analyst USING (...)` — `rls2fga` preserves that scope:

- adds role-scope relations in the generated model
- adds a `pg_role` type with a `member` relation
- emits tuples that tie protected rows to `pg_role:<role>`

**Required runtime data:** you must load `pg_role#member` tuples that map users to `PostgreSQL` roles in your `OpenFGA` store. Without them, role-scoped policies will not match any user.

## License

Licensed under the MIT License. See `LICENSE`.

# rls2fga

[![CI](https://github.com/LucaCappelletti94/rls2fga/actions/workflows/ci.yml/badge.svg)](https://github.com/LucaCappelletti94/rls2fga/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/LucaCappelletti94/rls2fga/graph/badge.svg)](https://codecov.io/gh/LucaCappelletti94/rls2fga)
[![License](https://img.shields.io/github/license/LucaCappelletti94/rls2fga)](https://github.com/LucaCappelletti94/rls2fga/blob/main/LICENSE)

Convert `PostgreSQL` [Row Level Security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html) (RLS) policies into [OpenFGA](https://openfga.dev/docs) authorization model definitions and relationship tuples.

`PostgreSQL` RLS lets you gate row access with SQL expressions such as `owner_id = current_user_id()` or `EXISTS (SELECT 1 FROM memberships ...)`. [OpenFGA](https://openfga.dev/docs) represents those rules as typed authorization models and relationship tuples, fine-grained, per-resource permissions evaluated at the application layer.

`rls2fga` classifies each RLS `USING` / `WITH CHECK` expression against the canonical patterns listed below and generates an `OpenFGA` DSL model with the corresponding types and relations, alongside SQL queries that populate the relationship tuples from your live database.

Policies that cannot be fully translated are flagged with a confidence level and emit `-- TODO` items for manual review.

> [!WARNING]
> The crate is not published yet on crates.io because we are waiting for the latest `sqlparser` version to be released.

> [!WARNING]
> An attribute guard beside a relationship check (`owner_id = current_user AND status = 'published'`) translates only its relationship half. The attribute half becomes a `-- TODO` for your application to enforce. A guard standing on its own does translate.

## Cargo Features

The `std` feature is enabled by default.

| Feature | Enables | Purpose |
| --------- | --------- | --------- |
| `std` | standard library | File output (`Translator::write_output`, `output::formatter`) and stack-overflow protection in the SQL parser. On by default. Disable with `--no-default-features` for a `no_std` + `alloc` build of the parse, classify, and generate pipeline. |
| `agent` | `reqwest`, `tokio` | Push generated models and tuples to a live `OpenFGA` instance via its HTTP API (implies `std`) |
| `db` | `diesel` (`PostgreSQL`) | Connect to a live `PostgreSQL` database to read schema metadata and execute tuple queries (implies `std`) |

### `no_std`

With `default-features = false` the crate builds on `no_std` + `alloc` targets (verified against `thumbv7em-none-eabi`). The full pipeline stays available: `parse_schema`, classification, DSL/JSON model generation, and tuple-query generation. Only the filesystem output surface (`Translator::write_output` and the `output::formatter` module) is gated behind `std`, since it writes files. Model, tuple, and report strings are still produced in memory via `output::report::build_report` and the generator APIs.

## Usage

The library is a three-stage pipeline: parse a SQL schema, plan a translation of its RLS policies, then ask that translation for each output you want. The plan is built once, so a caller wanting the model, the JSON and the tuple SQL pays for the analysis once.

```rust
use rls2fga::classifier::patterns::ConfidenceLevel;
use rls2fga::generator::tuple_generator::format_tuples;
use rls2fga::parser::sql_parser::parse_schema;
use rls2fga::translator::TranslatorBuilder;

let sql = "
    CREATE TABLE documents (
        id       UUID PRIMARY KEY,
        owner_id UUID NOT NULL
    );
    CREATE FUNCTION current_user_id() RETURNS UUID
        LANGUAGE sql STABLE
        AS 'SELECT current_setting(''app.current_user_id'', true)::uuid';
    ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
    CREATE POLICY documents_owner ON documents
        FOR SELECT TO PUBLIC
        USING (owner_id = current_user_id());
";

// Stage 1: Parse the SQL schema
let db = parse_schema(sql).expect("parse error");

// Stage 2: Plan the translation
let translator = TranslatorBuilder::new()
    .with_min_confidence(ConfidenceLevel::B)
    .build();
let translation = translator.translate(&db);

// Stage 3: Take the outputs. This refuses while any expression went unclassified,
// because such a model denies what the database grants.
let outputs = translation.outputs().expect("every clause translated");

println!("{}", outputs.model());
println!("{}", format_tuples(&outputs.tuple_queries()));

for note in outputs.notes() {
    eprintln!("[{}] {}: {note}", note.severity(), note.subject());
}
```

When something did go unclassified and you want the narrower model anyway, say so: `translation.outputs_accepting_gaps()` gives the same outputs without the check. That is one visible line rather than an omission, and `translation.unhandled()` names exactly what it costs.

The `min_confidence` parameter controls which policies appear in the output:

| Level | Meaning |
| ------- | --------- |
| `A` | Fully translated, no manual review needed |
| `B` | A composed pattern, or an attribute guard the row alone decides. A composed pattern is graded by its weakest part and never rises above `B` |
| `C` | Partial translation, an ABAC crossover where the relationship half translates and the attribute half does not |
| `D` | Unrecognised expression. Denied, and emits a TODO item, unless an oracle classifies it |

Dropping is not silent: `output::report::build_report` lists every clause below the threshold. A dropped `PERMISSIVE` clause grants nothing, so the model is narrower than the policy. A `RESTRICTIVE` clause instead becomes `no_access`, since RLS is `(permissive OR ...) AND restrictive AND ...`, and so does a `SELECT` policy reading its own table, which `PostgreSQL` rejects with `infinite recursion detected in policy for relation`.

### Generated model (example)

For the ownership example above, `model.dsl` contains:

```fga
model
  schema 1.1

type user

type documents
  relations
    define no_access: [user]
    define owner: [user]
    define can_delete: no_access
    define can_insert: no_access
    define can_select: owner
    define can_select_for_update: can_update
    define can_update: no_access
```

Only `SELECT` has a policy, and an RLS-enabled table denies every command no permissive policy covers.

Apply it with the [OpenFGA CLI](https://openfga.dev/docs/getting-started/setup-openfga):

```bash
fga model write --store-id "$FGA_STORE_ID" --file model.fga
```

### Generated tuple SQL (example)

```sql
-- User ownership (owner_id references users)
SELECT 'documents:' || "id" AS object, 'owner' AS relation, 'user:' || "owner_id" AS subject
FROM "documents"
WHERE "owner_id" IS NOT NULL;
```

Run this query against your database, convert the rows to `OpenFGA` tuple objects, and load them with `fga tuple write`. Only relations a permission can reach get a query, so a table that denies everything yields nothing to load.

## Supported RLS Patterns

| Pattern | Name | RLS expression shape | `OpenFGA` mapping |
| --------- | ------ | ---------------------- | ----------------- |
| P1 | `NumericThreshold` | `role_fn(user, resource) >= N` | Hierarchical relations derived from a numeric level |
| P2 | `RoleNameInList` | `role_fn(user, resource) IN ('viewer', ...)` | One direct relation per allowed role name |
| P3 | `DirectOwnership` | `owner_id = current_user_id()` | `define owner: [user]` direct relation |
| P4 | `ExistsMembership` | `EXISTS (SELECT 1 FROM members WHERE ...)`, `id IN (SELECT ...)`, `id = ANY (SELECT ...)` | Group membership via a `member` relation |
| P5 | `ParentInheritance` | FK join carrying a parent-side rule | Tuple-to-userset onto that rule (`owner from parent`), gated by the parent's own `can_select` |
| P6 | `BooleanFlag` | `is_public = TRUE` | Wildcard `[user:*]` public access |
| P7 | `AbacAnd` | Relationship check `AND` attribute guard | Relationship part translated, attribute guard emitted as `-- TODO [Level C]` |
| P8 | `Composite` | `expr1 OR expr2` / `expr1 AND expr2` | `union` / `intersection` of sub-expressions |
| P9 | `AttributeCondition` | `status = 'published'`, `expires_at > now()` | A value the row alone decides becomes a wildcard whose tuple query carries the guard in its `WHERE`, so only matching rows get one. A value the clock decides becomes an `OpenFGA` condition instead, since a tuple written once would outlive it |
| P10 | `ConstantBool` | `TRUE` / `FALSE` | Open (`[user:*]`) or closed (no access) |
| P11 | `ArrayMembership` | `current_user = ANY (editors)` | Direct relation named after the column, one tuple per array element |
| P12 | `JsonbFieldOwnership` | `data ->> 'owner' = current_user` | `define owner: [user]` direct relation, read from the jsonb field |
| P13 | `UncorrelatedMembership` | `EXISTS (SELECT 1 FROM staff WHERE user_id = current_user)` | One holder object per member source, every row pointing at it, so the grant reads as `member from staff_holder` |
| P14 | `RowValueInCallerSet` | `owner = ANY(string_to_array(current_setting('app.subjects', true), ','))` | A gate relation `[user:* with ...]` whose condition asks whether the caller's list holds the row's value, one tuple per row carrying that value |
| P15 | `RowValueEqualsCallerScalar` | `tenant_id = current_setting('app.tenant_id')::uuid` | The same gate, with the condition comparing for equality against the caller's single value instead of asking a list |
| P16 | `ConstantInCallerSet` | `'admin' = ANY(string_to_array(current_setting('app.roles', true), ','))` | The same gate, with the row's side a constant the policy named, so no column takes part |
| P17 | `CallerScalarEqualsConstant` | `(SELECT auth.jwt() ->> 'aal') = 'aal2'` | The same gate, comparing the caller's single value against a constant, so again no column takes part |
| P18 | `MembershipInCallerSet` | `EXISTS (SELECT 1 FROM shares s WHERE s.parent_id = t.id AND s.viewer = ANY(string_to_array(current_setting('app.subjects', true), ',')))` | A gate on the membership row rather than on the guarded row, since the member value is a value the request completes and not a person. Refused unless the correlated column is the guarded table's single primary key |
| - | `Unknown` | Unrecognised expression | Denied, and emitted as `-- TODO [Level D]`, unless an oracle classifies it |

## Classifying What This Crate Refuses

An expression `rls2fga` does not recognise is denied rather than guessed at, which is safe but narrower than the policy. When you know what your own expression means, implement `PolicyOracle` and call `consult_oracle` on the classified policies before generating anything. The oracle is offered each refused expression as written, along with the reason it was refused, and answers in one of three ways: with a classification, with a deliberate denial when the expression grants nobody, or by bailing. Bailing is the default, so an oracle implementing nothing changes nothing, and it is the only answer that leaves a gap in the report. A classification is emitted exactly as a pattern the crate recognised itself, and the grade it claims still faces your confidence threshold, so an oracle cannot push a guess past a gate you set.

Reach for it rather than walking the classification yourself. A refusal nests inside a parent join and inside a composite, so a walk that misses one leaves the model quietly denying, and every pattern enclosing a refusal has to be regraded or the clause is dropped for a refusal that is no longer there. `rls2fga::classifier::oracle` documents both traps and carries a worked example.

**This is the general answer for a shape `rls2fga` will not bake in.** Two refusals are deliberate rather than unfinished, and both are yours to answer. A function marked `SECURITY DEFINER` that reads a table is the documented way around a policy that would otherwise recurse on its own table, and reading its body would defeat the point of the marking: the function sees rows the caller cannot, so a misreading widens access. Whoever wrote the function knows what it means and can say so. A document read by position, `data -> 0 ->> 'owner'`, identifies a value by offset rather than by name, and a permission whose name encoded an offset would be repointed silently by unrelated code that reordered the document. Neither gets a convention baked into the crate, and both reach you through the same seam.

## Reads Gate The Other Commands

Naming the row to change requires reading it, so `can_update` and `can_delete` are intersected with `can_select`. Plain `INSERT` reads nothing, so `can_insert` stays ungated, but returning a table column and naming an `ON CONFLICT` target both read the new row back, so `PostgreSQL` checks it against the `SELECT` policies as well. `can_insert_returning` is that intersection, omitted where the insert rule already implies the read. Check it against the tuples the new row would produce, the same contextual tuples `can_insert` needs. `INSERT ... ON CONFLICT ... DO UPDATE` takes the update path on a conflict, so the `UPDATE` policies apply to the conflicting row as well, which `can_upsert` intersects. A locking read (`FOR UPDATE`, `FOR NO KEY UPDATE`, `FOR SHARE`, `FOR KEY SHARE`) is filtered by the `UPDATE` policies' `USING` clause on top of the `SELECT` policies, so `can_select` overstates what it returns and `can_select_for_update` is the relation to check. A policy expression also reads any table it names, filtered by that table's own policies: an inherited parent rule is intersected with the parent's `can_select`, and a membership table that grants no reads denies the command outright. Which membership rows a user sees is otherwise up to that table's policies, which no relation can express, so load tuples only for the rows it exposes.

## Policy Role Scope (`TO <role>`)

When a `PostgreSQL` policy targets a specific role, for example `CREATE POLICY ... TO analyst USING (...)`, `rls2fga` preserves that scope. It adds role-scope relations in the generated model, adds a `pg_role` type with a `member` relation, and emits tuples that tie protected rows to `pg_role:<role>`.

Required runtime data: you must load `pg_role#member` tuples that map users to `PostgreSQL` roles in your `OpenFGA` store. Without them, role-scoped policies will not match any user.

## Policies That Depend On The Clock

A guard comparing a column against statement time, such as `expires_at > now()`, cannot become a tuple: whatever the comparison decided when the tuple was written stays decided, and the grant outlives the moment it was true for. `rls2fga` emits an `OpenFGA` condition instead. The row's own value travels with the tuple, and the time comes from the caller at check time, so the same tuple stops granting once the clock passes it.

Required runtime data: every `Check` against such a relation must supply the time in its context, under the parameter name `request_time`. Nothing computes it for you, which is the point, since a server clock reading would put the decision back where it cannot be audited. `TranslatorBuilder::with_request_time_parameter` renames it when your service already has a convention.

## License

Licensed under the MIT License. See `LICENSE`.

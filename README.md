# rls2fga

[![CI](https://github.com/LucaCappelletti94/rls2fga/actions/workflows/ci.yml/badge.svg)](https://github.com/LucaCappelletti94/rls2fga/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/LucaCappelletti94/rls2fga/graph/badge.svg)](https://codecov.io/gh/LucaCappelletti94/rls2fga)
[![License](https://img.shields.io/github/license/LucaCappelletti94/rls2fga)](https://github.com/LucaCappelletti94/rls2fga/blob/main/LICENSE)

Convert `PostgreSQL` [Row Level Security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html) policies into an [OpenFGA](https://openfga.dev/docs) authorization model, plus the SQL that fills its relationship tuples from your database.

Each `USING` and `WITH CHECK` expression is classified against the patterns below. What is recognised becomes types and relations, what is not is denied and reported, so the model is never wider than the policy.

> [!WARNING]
> Not on crates.io yet, pending a `sqlparser` release with `no_std` fixes.

> [!WARNING]
> An attribute guard beside a relationship check (`owner_id = current_user AND status = 'published'`) translates only its relationship half. The guard becomes a `-- TODO` for your application. A guard standing on its own does translate.

## Usage

Parse a schema, plan a translation, then ask it for each output. The plan is built once, so the model, the JSON and the tuple SQL cost one analysis between them.

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

let db = parse_schema(sql).expect("parse error");
let translation = TranslatorBuilder::new()
    .with_min_confidence(ConfidenceLevel::B)
    .build()
    .translate(&db)
    .expect("schema should plan");
let outputs = translation.outputs().expect("every clause translated");

println!("{}", outputs.model());
println!("{}", format_tuples(&outputs.tuple_queries()));

for note in outputs.notes() {
    eprintln!("[{}] {}: {note}", note.severity(), note.subject());
}
```

`outputs()` refuses while anything went unclassified, because such a model denies what the database grants. `outputs_accepting_gaps()` takes the narrower model on purpose and `unhandled()` names what that costs. `min_confidence` sets the bar: `A` is fully translated, `B` a composed pattern or a guard the row alone decides, `C` the relationship half of an ABAC crossover, `D` unrecognised. Nothing is dropped silently, `output::report::build_report` lists every clause below the bar. A dropped `PERMISSIVE` clause grants nothing and a dropped `RESTRICTIVE` one becomes `no_access`.

## Output

The example above yields this model, where only `SELECT` has a policy and an RLS-enabled table denies every command no permissive policy covers. Apply it with `fga model write --store-id "$FGA_STORE_ID" --file model.fga`.

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

Beside it comes one query per relation a permission can reach, so a table that denies everything yields nothing to load.

```sql
-- User ownership (owner_id references users)
SELECT 'documents:' || "id" AS object, 'owner' AS relation, 'user:' || "owner_id" AS subject
FROM "documents"
WHERE "owner_id" IS NOT NULL;
```

Every query projects `object`, `relation` and `subject`. One whose `TupleQuery::condition` is `Some` adds `condition`, the name its tuples carry, and `context`, a one-key `jsonb` object. `Outputs::record_from_tuple_row` reads such a row back as a `Record`, refusing one the model holds no such fact for, and `generator::records::records_from_row` produces the same records from a row's values with no database at all.

Running the SQL and writing the tuples are yours, since the crate keeps no database handle and batching and retry are your policy. The model is the exception: `client::write_authorization_model` puts it on a running server over a client you built and answers with the id it was stored under.

## Cargo features

`std` is on by default and carries the file output surface (`Outputs::write`, backed by `output::formatter`). Without it the crate builds on `no_std` plus `alloc`, verified against `thumbv7em-none-eabi`, with the whole parse, classify and generate pipeline intact. `client` adds the model writer and implies `std`.

## Supported patterns

A report names a pattern by its number, so `P4 (EXISTS members)` beside a TODO points at a row here.

| # | Pattern | Shape | Mapping |
| --- | --- | --- | --- |
| P1 | `NumericThreshold` | `role_fn(user, resource) >= N` | Hierarchical relations from the level |
| P2 | `RoleNameInList` | `role_fn(user, resource) IN ('viewer', ...)` | One relation per role name |
| P3 | `DirectOwnership` | `owner_id = current_user_id()` | `owner: [user]` |
| P4 | `ExistsMembership` | `EXISTS (SELECT 1 FROM members ...)`, `IN`, `= ANY` | A `member` relation |
| P5 | `ParentInheritance` | FK join carrying a parent-side rule | `owner from parent`, gated by the parent's `can_select` |
| P6 | `BooleanFlag` | `is_public = TRUE` | `[user:*]` |
| P7 | `AbacAnd` | Relationship check `AND` attribute guard | Relationship half only, guard as a TODO |
| P8 | `Composite` | `expr OR expr`, `expr AND expr` | Union, intersection |
| P9 | `AttributeCondition` | `status = 'published'`, `expires_at > now()` | A row-decided value guards the tuple query, a clock-decided one becomes a condition |
| P10 | `ConstantBool` | `TRUE`, `FALSE` | `[user:*]`, or no access |
| P11 | `ArrayMembership` | `current_user = ANY (editors)` | Relation named after the column, one tuple per element |
| P12 | `JsonbFieldOwnership` | `data ->> 'owner' = current_user` | `owner: [user]`, read from the field |
| P13 | `UncorrelatedMembership` | `EXISTS (SELECT 1 FROM staff WHERE user_id = current_user)` | One holder object, so the grant reads as `member from staff_holder` |
| P14 | `RowValueInCallerSet` | `owner = ANY(string_to_array(current_setting('app.subjects', true), ','))` | A gate asking whether the caller's list holds the row's value |
| P15 | `RowValueEqualsCallerScalar` | `tenant_id = current_setting('app.tenant_id')::uuid` | The same gate, equality against the caller's value |
| P16 | `ConstantInCallerSet` | `'admin' = ANY(string_to_array(current_setting('app.roles', true), ','))` | The same gate, no column takes part |
| P17 | `CallerScalarEqualsConstant` | `(SELECT auth.jwt() ->> 'aal') = 'aal2'` | The same gate, caller's value against a constant |
| P18 | `MembershipInCallerSet` | `EXISTS (SELECT 1 FROM shares s WHERE s.parent_id = t.id AND s.viewer = ANY(...))` | The gate on the membership row, refused unless the correlated column is the guarded table's single primary key |
| - | `Unknown` | Anything else | Denied, with a TODO, unless an oracle classifies it |

## What the crate refuses

An unrecognised expression is denied rather than guessed at, which is safe but narrower than the policy. Implement `PolicyOracle` and call `consult_oracle` to answer for your own shapes: it is offered each refusal with its reason and may classify it, deny it deliberately, or bail, and bailing is the default, so an oracle implementing nothing changes nothing. Reach for it rather than walking the classification yourself, since a refusal nests inside parent joins and composites and every pattern enclosing one has to be regraded. `classifier::oracle` documents both traps with a worked example.

Two refusals are deliberate. Reading the body of a `SECURITY DEFINER` function would defeat the marking, since it sees rows the caller cannot. A jsonb field read by position, `data -> 0 ->> 'owner'`, would name a permission after an offset that unrelated code can repoint. Both reach you through the oracle.

## Reads gate the other commands

Naming a row to change means reading it, so `can_update` and `can_delete` intersect `can_select`. Plain `INSERT` reads nothing, but `RETURNING` a column and naming an `ON CONFLICT` target both read the new row back, which is `can_insert_returning`, and `INSERT ... ON CONFLICT DO UPDATE` is `can_upsert`. A locking read (`FOR UPDATE` and friends) also applies the `UPDATE` policies, so `can_select_for_update` is the relation to check rather than `can_select`. A policy expression reads every table it names, so an inherited parent rule intersects the parent's `can_select` and a membership table granting no reads denies outright.

## Runtime data you have to supply

A policy scoped `TO analyst` keeps that scope through a `pg_role` type, so load `pg_role#member` tuples mapping users to roles or those policies match nobody.

A guard against statement time such as `expires_at > now()` cannot be a tuple, since whatever it decided when written stays decided. It becomes an `OpenFGA` condition instead: the row's value travels with the tuple and every check must carry the time in its context under `request_time`, renamed by `TranslatorBuilder::with_request_time_parameter`. Nothing computes it for you, which is the point, since a server clock reading puts the decision where it cannot be audited.

## License

Licensed under the MIT License. See `LICENSE`.

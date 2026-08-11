//! Differential test for the per-row record descriptions.
//!
//! The whole-table SQL is the reference implementation. For every row of every
//! table a description reads, evaluating the description must yield exactly the
//! records the description's own query yields for that row. No expected output is
//! written by hand, so a description that disagrees with its own SQL fails here.

#![cfg(not(target_os = "windows"))]

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::thread;
use std::time::Duration;

use diesel::connection::SimpleConnection;
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::sql_types::{Jsonb, Text};
use testcontainers::{
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
    GenericImage, ImageExt,
};

use openfga_client::client::OpenFgaClient;
use openfga_client::tonic::transport::Channel;
use rls2fga::classifier::patterns::ConfidenceLevel;
use rls2fga::generator::action_relations::{ActionAnswer, ActionStatement};
use rls2fga::generator::json_model::AuthorizationModel;
use rls2fga::generator::model_generator::GeneratorSettings;
use rls2fga::generator::records::{
    records_from_row, BoundQuery, Record, RecordContextValue, RecordDerivation, RecordDescription,
    RowValues, ValueSource,
};
use rls2fga::generator::relations::RowDecision;
use rls2fga::generator::tuple_generator::TupleQuery;
use rls2fga::translator::Translation;

mod support;

const PG_USER: &str = "postgres";
const PG_PASSWORD: &str = "postgres";
const PG_DB: &str = "rls2fga";

/// One `(object, relation, subject)` triple as the generated SQL returns it.
///
/// The query under test is generated text, so it cannot go through the typed
/// query DSL. The row type still binds every column to its declared SQL type.
#[derive(QueryableByName, Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
struct TupleRow {
    #[diesel(sql_type = Text)]
    object: String,
    #[diesel(sql_type = Text)]
    relation: String,
    #[diesel(sql_type = Text)]
    subject: String,
}

/// The same, for a query whose tuples carry a condition context. A conditional record
/// grants nobody until the request completes the comparison, so the context is part of
/// what the two sides have to agree on.
#[derive(QueryableByName, Debug, Clone)]
struct ConditionalTupleRow {
    #[diesel(sql_type = Text)]
    object: String,
    #[diesel(sql_type = Text)]
    relation: String,
    #[diesel(sql_type = Text)]
    subject: String,
    #[diesel(sql_type = Jsonb)]
    context: serde_json::Value,
}

/// A whole row as JSON, which is how a test reads columns it only learns about
/// from the description at runtime.
#[derive(QueryableByName)]
struct JsonRow {
    #[diesel(sql_type = Jsonb)]
    row: serde_json::Value,
}

/// One key value a bound query is replayed for.
#[derive(QueryableByName)]
struct KeyRow {
    #[diesel(sql_type = Text)]
    value: String,
}

/// `serde_json` view of one row, adapting it to the crate's row interface.
struct JsonRowValues<'a>(&'a serde_json::Value);

/// Text of a JSON scalar the way `PostgreSQL` renders it in `||` and `->>`.
fn scalar_text(value: &serde_json::Value) -> Option<Cow<'_, str>> {
    match value {
        serde_json::Value::String(text) => Some(Cow::Borrowed(text.as_str())),
        serde_json::Value::Number(number) => Some(Cow::Owned(number.to_string())),
        serde_json::Value::Bool(flag) => Some(Cow::Borrowed(if *flag { "true" } else { "false" })),
        // A JSON null has no text, and neither does an object or an array, which
        // `||` would refuse anyway.
        _ => None,
    }
}

impl RowValues for JsonRowValues<'_> {
    fn text(&self, column: &str) -> Option<Cow<'_, str>> {
        self.0.get(column).and_then(scalar_text)
    }

    fn boolean(&self, column: &str) -> Option<bool> {
        self.0.get(column).and_then(serde_json::Value::as_bool)
    }

    fn list(&self, column: &str) -> Option<Vec<Option<Cow<'_, str>>>> {
        Some(
            self.0
                .get(column)?
                .as_array()?
                .iter()
                .map(scalar_text)
                .collect(),
        )
    }

    fn json_text(&self, column: &str, path: &[String]) -> Option<Cow<'_, str>> {
        let mut current = self.0.get(column)?;
        for step in path {
            current = current.get(step)?;
        }
        scalar_text(current)
    }
}

fn connect_postgres_with_retry(database_url: &str) -> PgConnection {
    let mut last_error = String::new();
    for _ in 0..30 {
        match PgConnection::establish(database_url) {
            Ok(conn) => return conn,
            Err(error) => {
                last_error = error.to_string();
                thread::sleep(Duration::from_millis(200));
            }
        }
    }
    panic!("Failed to connect to PostgreSQL after retries: {last_error}");
}

async fn start_postgres() -> (testcontainers::ContainerAsync<GenericImage>, PgConnection) {
    let container = GenericImage::new("postgres", "18")
        .with_exposed_port(5432.tcp())
        .with_wait_for(WaitFor::message_on_stderr(
            "database system is ready to accept connections",
        ))
        .with_env_var("POSTGRES_USER", PG_USER)
        .with_env_var("POSTGRES_PASSWORD", PG_PASSWORD)
        .with_env_var("POSTGRES_DB", PG_DB)
        .start()
        .await
        .expect("Failed to start PostgreSQL 18 container");
    let port = container.get_host_port_ipv4(5432).await.unwrap();
    let url = format!("postgres://{PG_USER}:{PG_PASSWORD}@127.0.0.1:{port}/{PG_DB}");
    let conn = connect_postgres_with_retry(&url);
    (container, conn)
}

/// One fact as the three strings a tuple carries.
///
/// The database hands this side back text, and a [`Record`]'s relation is a typed name
/// only the crate mints, so both sides are compared through this rather than by building
/// a `Record` out of a row.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Fact {
    object: String,
    relation: String,
    subject: String,
    context: Option<RecordContextValue>,
}

impl Fact {
    fn of(record: &Record) -> Self {
        Self {
            object: record.object.clone(),
            relation: record.relation.to_string(),
            subject: record.subject.clone(),
            context: record.context.clone(),
        }
    }
}

/// Records the generated query returns.
fn records_from_sql(conn: &mut PgConnection, query: &TupleQuery) -> BTreeSet<Fact> {
    let failed = |error: diesel::result::Error| -> ! {
        panic!(
            "the generated query failed on PostgreSQL 18: {}\n{}\nError: {error}",
            query.comment, query.sql
        )
    };
    if query.condition.is_some() {
        let rows: Vec<ConditionalTupleRow> = diesel::sql_query(&query.sql)
            .load(conn)
            .unwrap_or_else(|error| failed(error));
        return rows
            .into_iter()
            .map(|row| Fact {
                object: row.object,
                relation: row.relation,
                subject: row.subject,
                context: Some(context_of(&row.context, &query.sql)),
            })
            .collect();
    }
    let rows: Vec<TupleRow> = diesel::sql_query(&query.sql)
        .load(conn)
        .unwrap_or_else(|error| failed(error));
    rows.into_iter()
        .map(|row| Fact {
            object: row.object,
            relation: row.relation,
            subject: row.subject,
            context: None,
        })
        .collect()
}

/// The one key a conditional tuple's context carries. More than one would mean the
/// request supplies nothing, which the model's own invariant already forbids.
fn context_of(context: &serde_json::Value, sql: &str) -> RecordContextValue {
    let object = context
        .as_object()
        .unwrap_or_else(|| panic!("a conditional tuple's context is an object:\n{sql}"));
    let [(key, value)] = object.iter().collect::<Vec<_>>()[..] else {
        panic!("a conditional tuple carries exactly one context key:\n{sql}");
    };
    RecordContextValue {
        key: key.clone(),
        value: scalar_text(value)
            .unwrap_or_else(|| panic!("a context value renders as text:\n{sql}"))
            .into_owned(),
    }
}

/// Every row of `table`, as JSON.
fn rows_of(conn: &mut PgConnection, table: &str) -> Vec<serde_json::Value> {
    // The table is discovered from the description at runtime, so the typed DSL
    // cannot name it. `to_jsonb` keeps every column without a per-table struct.
    let quoted = table
        .split('.')
        .map(|part| format!("\"{part}\""))
        .collect::<Vec<_>>()
        .join(".");
    let sql = format!("SELECT to_jsonb(t) AS row FROM {quoted} t");
    let rows: Vec<JsonRow> = diesel::sql_query(&sql)
        .load(conn)
        .unwrap_or_else(|error| panic!("failed to read rows of {table}: {error}"));
    rows.into_iter().map(|row| row.row).collect()
}

/// Records the description yields over every row of its table.
fn records_from_descriptions(
    conn: &mut PgConnection,
    description: &RecordDescription,
) -> BTreeSet<Fact> {
    let table = description
        .row_table()
        .expect("only a pure description reaches here");
    rows_of(conn, table)
        .iter()
        .flat_map(|row| {
            records_from_row(description, &JsonRowValues(row))
                .expect("a pure description evaluates without a database")
        })
        .map(|record| Fact::of(&record))
        .collect()
}

/// Distinct non-null values of `column` in `table`, as text.
fn distinct_keys(conn: &mut PgConnection, table: &str, column: &str) -> Vec<String> {
    // Both names come from the description at runtime, so the typed DSL cannot
    // name them.
    let sql = format!(
        "SELECT DISTINCT \"{column}\"::text AS value FROM \"{table}\" \
         WHERE \"{column}\" IS NOT NULL ORDER BY value"
    );
    let rows: Vec<KeyRow> = diesel::sql_query(&sql)
        .load(conn)
        .unwrap_or_else(|error| panic!("failed to read keys of {table}.{column}: {error}"));
    rows.into_iter().map(|row| row.value).collect()
}

/// Run a bound query for one key.
///
/// The key is substituted as a literal rather than bound as a parameter, because
/// a literal carries `unknown` type and coerces to whatever the column is, while
/// a text-typed parameter against a `uuid` column raises `operator does not
/// exist`. What is under test is the SQL the description carries, not the wire
/// form of the placeholder.
fn records_from_bound_query(
    conn: &mut PgConnection,
    bound: &BoundQuery,
    key: &str,
    conditional: bool,
) -> BTreeSet<Fact> {
    let literal = format!("'{}'", key.replace('\'', "''"));
    let sql = bound.sql.replace("$1", &literal);
    let failed = |error: diesel::result::Error| -> ! {
        panic!(
            "a bound query failed on PostgreSQL 18 for {}.{} = {literal}\n{sql}\nError: {error}",
            bound.table, bound.key_column
        )
    };
    // The whole-table query and its bound replay have to agree on the context too, or a
    // consumer replaying a change would answer differently from the loader.
    if conditional {
        let rows: Vec<ConditionalTupleRow> = diesel::sql_query(&sql)
            .load(conn)
            .unwrap_or_else(|error| failed(error));
        return rows
            .into_iter()
            .map(|row| Fact {
                object: row.object,
                relation: row.relation,
                subject: row.subject,
                context: Some(context_of(&row.context, &sql)),
            })
            .collect();
    }
    let rows: Vec<TupleRow> = diesel::sql_query(&sql)
        .load(conn)
        .unwrap_or_else(|error| failed(error));
    rows.into_iter()
        .map(|row| Fact {
            object: row.object,
            relation: row.relation,
            subject: row.subject,
            context: None,
        })
        .collect()
}

/// A joining shape answers a change by querying, so every bound query has to run,
/// return only records the whole-table query returns, and between them account for
/// all of them. Replaying every changed row is how the consumer stays complete.
fn assert_bound_queries_account_for_every_record(
    conn: &mut PgConnection,
    query: &TupleQuery,
    bound_queries: &[BoundQuery],
    label: &str,
) {
    let whole = records_from_sql(conn, query);
    assert!(
        !whole.is_empty(),
        "{label}: nothing to compare, the seed produces no records for {}",
        query.comment
    );

    for bound in bound_queries {
        let keys = distinct_keys(conn, &bound.table, bound.key_column.as_str());
        assert!(
            !keys.is_empty(),
            "{label}: no key values in {}.{}, so the bound query is untested for {}",
            bound.table,
            bound.key_column,
            query.comment
        );

        let mut union = BTreeSet::new();
        let mut narrowed = false;
        for key in &keys {
            let bound_records =
                records_from_bound_query(conn, bound, key, query.condition.is_some());
            let invented: Vec<_> = bound_records.difference(&whole).collect();
            assert!(
                invented.is_empty(),
                "{label}: the bound query on {}.{} = {key} returned records the \
                 whole-table query does not: {invented:?}\n{}",
                bound.table,
                bound.key_column,
                bound.sql
            );
            narrowed |= bound_records.len() < whole.len();
            union.extend(bound_records);
        }

        assert_eq!(
            union,
            whole,
            "{label}: replaying every key of {}.{} must reproduce the whole table for {}\n{}\n\
             missing: {:?}",
            bound.table,
            bound.key_column,
            query.comment,
            bound.sql,
            whole.difference(&union).collect::<Vec<_>>(),
        );

        // A query ignoring its key would pass both checks above, so require that
        // at least one key answered with less than everything.
        assert!(
            narrowed || keys.len() == 1,
            "{label}: the bound query on {}.{} returned every record for every one of \
             its {} keys, so it does not bind:\n{}",
            bound.table,
            bound.key_column,
            keys.len(),
            bound.sql
        );
    }
}

/// Compare both sides for every query the schema emits, and report what was covered.
fn assert_descriptions_match_their_sql(
    conn: &mut PgConnection,
    queries: &[TupleQuery],
    label: &str,
) -> (usize, usize, usize) {
    let (mut pure, mut joined, mut records) = (0, 0, 0);

    for query in queries {
        let Some(description) = &query.description else {
            // Only the TODO placeholder produces no records, and it emits no query.
            assert!(
                query.sql.trim_start().starts_with("--"),
                "{label}: a real query must carry a description:\n{}\n{}",
                query.comment,
                query.sql
            );
            continue;
        };

        match &description.derivation {
            RecordDerivation::Joined { queries: bound, .. } => {
                joined += 1;
                assert!(
                    !bound.is_empty(),
                    "{label}: a joining description must carry a bound query per side it reads: {}",
                    query.comment
                );
                // Requirement 7: the consumer refuses to start by name, so every
                // table a bound query reads has to appear in the list.
                for query_side in bound {
                    assert!(
                        description.tables.contains(&query_side.table),
                        "{label}: {} is bound but absent from the table list {:?}: {}",
                        query_side.table,
                        description.tables,
                        query.comment
                    );
                }
                assert_bound_queries_account_for_every_record(conn, query, bound, label);
                continue;
            }
            RecordDerivation::FromRow { table, .. } => {
                assert!(
                    description.tables.contains(table),
                    "{label}: the table list must name the row's own table: {}",
                    query.comment
                );
            }
            // `RecordDerivation` is non_exhaustive, so a variant added later has
            // to be judged here rather than passing as one of the two above.
            other => panic!("{label}: unhandled derivation {other:?}"),
        }

        pure += 1;
        let expected = records_from_sql(conn, query);
        let actual = records_from_descriptions(conn, description);
        records += expected.len();

        assert_eq!(
            actual,
            expected,
            "{label}: the description disagrees with its own SQL for {}\n{}\n\
             only the description produced: {:?}\nonly the SQL produced: {:?}",
            query.comment,
            query.sql,
            actual.difference(&expected).collect::<Vec<_>>(),
            expected.difference(&actual).collect::<Vec<_>>(),
        );
    }

    (pure, joined, records)
}

/// Schema covering every shape whose records follow from one row, with rows
/// chosen for the cases that decide the answer: a null owner, a null list, an
/// empty list, a list holding only null, a null beside a real element, a missing
/// JSON key, and a false flag.
const ROW_SHAPES_SCHEMA: &str = "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE folders (id TEXT PRIMARY KEY, owner_id TEXT);
CREATE TABLE notes (
    id TEXT PRIMARY KEY,
    folder_id TEXT REFERENCES folders(id),
    owner_id TEXT,
    editors TEXT[],
    meta JSONB,
    status TEXT,
    priority INT,
    is_public BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE TABLE note_members (note_id TEXT REFERENCES notes(id), user_id TEXT);
CREATE TABLE note_reviewers (note_id TEXT REFERENCES notes(id), user_id TEXT, role TEXT);
CREATE TABLE announcements (id TEXT PRIMARY KEY, body TEXT);
CREATE TABLE audits (id TEXT PRIMARY KEY, body TEXT);

CREATE FUNCTION auth_current_user_id() RETURNS TEXT
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';

ALTER TABLE folders ENABLE ROW LEVEL SECURITY;
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
ALTER TABLE announcements ENABLE ROW LEVEL SECURITY;
ALTER TABLE audits ENABLE ROW LEVEL SECURITY;

-- P3 direct ownership.
CREATE POLICY folders_owner ON folders FOR SELECT
    USING (owner_id = auth_current_user_id());
-- P3 again, plus P11 list membership, P12 JSON field, P6 public flag,
-- and P4 membership, which also mints the note to folder bridge.
CREATE POLICY notes_owner ON notes FOR SELECT
    USING (owner_id = auth_current_user_id());
CREATE POLICY notes_editors ON notes FOR SELECT
    USING (auth_current_user_id() = ANY (editors));
CREATE POLICY notes_meta ON notes FOR SELECT
    USING (meta ->> 'owner_id' = auth_current_user_id());
CREATE POLICY notes_public ON notes FOR SELECT
    USING (is_public = TRUE);
CREATE POLICY notes_members ON notes FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM note_members
        WHERE note_members.note_id = notes.id
          AND note_members.user_id = auth_current_user_id()));
-- The same membership with a residual predicate, which reaches the query as SQL
-- text no evaluator here can read, so the shape has to be answered by querying.
CREATE POLICY notes_reviewers ON notes FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM note_reviewers
        WHERE note_reviewers.note_id = notes.id
          AND note_reviewers.user_id = auth_current_user_id()
          AND note_reviewers.role = 'editor'));
-- P9 attribute guards over literal constants, which the row decides just as the
-- boolean flag does.
CREATE POLICY notes_published ON notes FOR SELECT USING (status = 'published');
CREATE POLICY notes_priority ON notes FOR SELECT USING (priority >= 3);
-- P10 constant TRUE.
CREATE POLICY announcements_all ON announcements FOR SELECT USING (TRUE);
-- A role-scoped policy, which mints the pg_role scope.
CREATE POLICY audits_auditor ON audits FOR SELECT TO auditor USING (TRUE);
";

const ROW_SHAPES_SEED: &str = "
INSERT INTO users (id) VALUES ('alice'), ('bob'), ('carol');

INSERT INTO folders (id, owner_id) VALUES
    ('f1', 'alice'),
    ('f2', NULL);

-- `status` and `priority` cover what an attribute guard turns on: the value it
-- admits, one it refuses, NULL (which fails every comparison including `<>`), and
-- both sides of a numeric boundary.
INSERT INTO notes (id, folder_id, owner_id, editors, meta, status, priority, is_public) VALUES
    ('n-owned',        'f1',  'alice', NULL,                    NULL,                          'published', 5,    FALSE),
    ('n-null-owner',   'f1',  NULL,    NULL,                    NULL,                          'draft',     1,    FALSE),
    ('n-null-list',    'f2',  'bob',   NULL,                    NULL,                          NULL,        NULL, FALSE),
    ('n-empty-list',   NULL,  'bob',   '{}',                    NULL,                          'draft',     3,    FALSE),
    ('n-only-null',    NULL,  'bob',   '{NULL}',                NULL,                          'published', 2,    FALSE),
    ('n-null-beside',  NULL,  'bob',   '{NULL,carol}',          NULL,                          NULL,        4,    FALSE),
    ('n-two-editors',  'f1',  'bob',   '{alice,carol}',         NULL,                          'archived',  10,   FALSE),
    ('n-meta-owner',   NULL,  'bob',   NULL,                    '{\"owner_id\": \"carol\"}',   'published', NULL, FALSE),
    ('n-meta-absent',  NULL,  'bob',   NULL,                    '{\"other\": \"carol\"}',      'draft',     0,    FALSE),
    ('n-meta-null',    NULL,  'bob',   NULL,                    '{\"owner_id\": null}',        NULL,        3,    FALSE),
    ('n-public',       NULL,  'bob',   NULL,                    NULL,                          'archived',  -1,   TRUE);

INSERT INTO note_members (note_id, user_id) VALUES
    ('n-owned', 'bob'),
    ('n-owned', NULL),
    ('n-public', 'carol');

-- Rows the residual predicate keeps and rows it drops, over more than one note so
-- the bound query has something to narrow.
INSERT INTO note_reviewers (note_id, user_id, role) VALUES
    ('n-owned',      'alice', 'editor'),
    ('n-owned',      'bob',   'viewer'),
    ('n-public',     'carol', 'editor'),
    ('n-null-list',  'alice', 'editor'),
    ('n-null-list',  NULL,    'editor');

INSERT INTO announcements (id, body) VALUES ('a1', 'hello'), ('a2', 'world');
INSERT INTO audits (id, body) VALUES ('au1', 'secret');
";

#[tokio::test]
#[ignore = "requires Docker: starts a PostgreSQL 18 container"]
async fn every_row_shape_description_matches_its_own_sql() {
    let (_container, mut conn) = start_postgres().await;

    conn.batch_execute("CREATE ROLE auditor;")
        .expect("failed to create the scoped role");
    conn.batch_execute(ROW_SHAPES_SCHEMA)
        .expect("failed to apply the row-shapes schema");
    conn.batch_execute(ROW_SHAPES_SEED)
        .expect("failed to seed the row-shapes schema");

    // Without the accessor the ownership, list, field and membership policies fall
    // below the threshold and the schema exercises only three shapes.
    let (classified, db, registry) = support::classify_sql(
        ROW_SHAPES_SCHEMA,
        Some(r#"{"auth_current_user_id": {"kind": "current_user_accessor", "returns": "text"}}"#),
    );
    let queries = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps()
    .tuple_queries();

    let (pure, joined, records) =
        assert_descriptions_match_their_sql(&mut conn, &queries, "row shapes");

    // Non-vacuous: the schema really does exercise the fast path, and the rows
    // really do produce records on both sides.
    assert!(
        pure >= 10,
        "the schema must exercise every row-decidable shape, saw {pure}"
    );
    // The residual predicate is the one shape here a row cannot decide, and its
    // bound query is executed by the same comparison.
    assert_eq!(
        joined, 1,
        "only the residual predicate membership reads more than the row"
    );
    assert!(
        records > 20,
        "the seed must produce records to compare, saw {records}"
    );
}

/// Rows chosen for what decides the answer: two teams that differ, a repeat so the
/// record set cannot pass by being a bijection with the rows, and a NULL that must yield
/// no record at all, since a comparison against NULL is NULL and `PostgreSQL` hides the
/// row.
const REQUEST_GATE_SEED: &str = "
INSERT INTO documents (id, team_id) VALUES (1, 'team-a'), (2, 'team-b'), (3, 'team-a'), (4, NULL);
INSERT INTO reports (id, team_id) VALUES (1, 'team-a'), (2, 'team-b'), (3, 'team-a'), (4, NULL);
";

/// The request-gated shape, which nothing else in this file produces.
///
/// Every other schema here reaches the caller through an accessor rather than through a
/// declared set, so no conditional tuple from a request gate ever reached this
/// comparison and the context a description carries went unchecked against the context
/// its own SQL emits. Both fixtures are run because they differ in what the caller has
/// to send, a list against a split, while the record each row yields must be identical.
#[tokio::test]
#[ignore = "requires Docker: starts a PostgreSQL 18 container"]
async fn a_request_gated_description_matches_its_own_sql() {
    let (_container, mut conn) = start_postgres().await;

    for fixture in ["token_claim_set", "function_carried_set"] {
        conn.batch_execute(
            "DROP TABLE IF EXISTS documents, reports CASCADE; \
             DROP FUNCTION IF EXISTS user_teams();",
        )
        .expect("failed to clear the previous fixture");
        conn.batch_execute(&support::read_fixture_sql(fixture))
            .unwrap_or_else(|error| panic!("failed to apply the {fixture} schema: {error}"));
        conn.batch_execute(REQUEST_GATE_SEED)
            .unwrap_or_else(|error| panic!("failed to seed {fixture}: {error}"));

        let (classified, db, registry) = support::try_load_fixture_classified(fixture);
        let queries = Translation::plan(
            classified,
            &db,
            &registry,
            ConfidenceLevel::B,
            &GeneratorSettings::default(),
        )
        .outputs_accepting_gaps()
        .tuple_queries();

        // Non-vacuous: without this the comparison below could pass by comparing two
        // empty sets, which is exactly how this shape went uncovered until now.
        let conditional = queries
            .iter()
            .filter(|query| query.condition.is_some())
            .count();
        assert_eq!(
            conditional, 2,
            "{fixture}: both spellings emit a conditional query, got {conditional}"
        );

        let (pure, joined, records) =
            assert_descriptions_match_their_sql(&mut conn, &queries, fixture);
        assert_eq!(
            joined, 0,
            "{fixture}: a request gate is decided by the row alone"
        );
        assert_eq!(
            pure, 2,
            "{fixture}: one description per spelling, got {pure}"
        );
        assert_eq!(
            records, 6,
            "{fixture}: three named teams per table and none for the NULL, got {records}"
        );
    }
}

#[tokio::test]
#[ignore = "requires Docker: starts a PostgreSQL 18 container"]
async fn role_ownership_and_grant_shapes_are_marked_joining() {
    let (_container, mut conn) = start_postgres().await;

    let schema_sql = support::read_fixture_sql("earth_metabolome");
    conn.batch_execute(&schema_sql)
        .expect("failed to apply the earth_metabolome schema");
    conn.batch_execute(
        "
INSERT INTO users (id) VALUES
    ('00000000-0000-0000-0000-0000000000a1'),
    ('00000000-0000-0000-0000-0000000000a2'),
    ('00000000-0000-0000-0000-0000000000a3');
INSERT INTO teams (id) VALUES
    ('00000000-0000-0000-0000-0000000000b1'),
    ('00000000-0000-0000-0000-0000000000b2');
INSERT INTO team_members (team_id, user_id) VALUES
    ('00000000-0000-0000-0000-0000000000b1', '00000000-0000-0000-0000-0000000000a1'),
    ('00000000-0000-0000-0000-0000000000b2', '00000000-0000-0000-0000-0000000000a2');
INSERT INTO ownables (id, owner_id) VALUES
    ('00000000-0000-0000-0000-0000000000d1', '00000000-0000-0000-0000-0000000000a1'),
    ('00000000-0000-0000-0000-0000000000d2', '00000000-0000-0000-0000-0000000000a2'),
    -- Team owned, which is the only way the team-ownership shape produces a record.
    ('00000000-0000-0000-0000-0000000000d3', '00000000-0000-0000-0000-0000000000b1'),
    ('00000000-0000-0000-0000-0000000000d4', '00000000-0000-0000-0000-0000000000b2'),
    -- Owned by nobody the schema records. `owner_id` carries no foreign key, so
    -- this row is legal, and it is what separates a row-derived record from the
    -- principal-table filter the query applies. Marking the shape row-derived
    -- claims a record here that the query refuses.
    ('00000000-0000-0000-0000-0000000000d9', '00000000-0000-0000-0000-0000000000ff');
INSERT INTO owner_grants (grantee_owner_id, granted_owner_id, role_id) VALUES
    ('00000000-0000-0000-0000-0000000000a3', '00000000-0000-0000-0000-0000000000a1', 3),
    ('00000000-0000-0000-0000-0000000000a1', '00000000-0000-0000-0000-0000000000a2', 2),
    ('00000000-0000-0000-0000-0000000000b2', '00000000-0000-0000-0000-0000000000b1', 4);
",
    )
    .expect("failed to seed the earth_metabolome schema");

    let (classified, db, registry) = support::load_fixture_classified("earth_metabolome");
    let queries = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps()
    .tuple_queries();

    let (pure, joined, _) =
        assert_descriptions_match_their_sql(&mut conn, &queries, "earth_metabolome");

    // The membership table is row-decidable; the two role-ownership shapes and the
    // grant expansion are not, because each reads a table the row does not carry.
    assert!(
        pure >= 1,
        "team membership follows from one row, saw {pure} pure"
    );
    assert!(
        joined >= 3,
        "role ownership and grant expansion read a second table, saw {joined} joining"
    );
}

/// An uncorrelated membership grants the whole table at once, so the generator mints
/// a holder object standing for the member list. Two of them: one whose list the row
/// decides, and one carrying a predicate only SQL can read.
const HOLDER_SCHEMA: &str = "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE staff (user_id TEXT);
CREATE TABLE reviewers (user_id TEXT, active BOOLEAN);
CREATE TABLE docs (id TEXT PRIMARY KEY, owner_id TEXT);
CREATE TABLE memos (id TEXT PRIMARY KEY);

CREATE FUNCTION auth_current_user_id() RETURNS TEXT
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';

ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE memos ENABLE ROW LEVEL SECURITY;

CREATE POLICY docs_staff ON docs FOR SELECT
    USING (EXISTS (SELECT 1 FROM staff WHERE staff.user_id = auth_current_user_id()));
CREATE POLICY memos_reviewers ON memos FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM reviewers
        WHERE reviewers.user_id = auth_current_user_id()
          AND reviewers.active));
";

/// A duplicated member and a null one, which is what separates a set of records from
/// a row count, and reviewers on both sides of the predicate so a bound query has
/// something to narrow.
const HOLDER_SEED: &str = "
INSERT INTO users (id) VALUES ('alice'), ('bob'), ('carol');

INSERT INTO staff (user_id) VALUES ('alice'), ('alice'), ('bob'), (NULL);

INSERT INTO reviewers (user_id, active) VALUES
    ('alice', TRUE),
    ('alice', TRUE),
    ('bob',   TRUE),
    ('carol', FALSE),
    (NULL,    TRUE);

INSERT INTO docs (id, owner_id) VALUES ('d1', 'alice'), ('d2', NULL);
INSERT INTO memos (id) VALUES ('m1'), ('m2');
";

#[tokio::test]
#[ignore = "requires Docker: starts a PostgreSQL 18 container"]
async fn holder_shapes_match_their_own_sql() {
    let (_container, mut conn) = start_postgres().await;

    conn.batch_execute(HOLDER_SCHEMA)
        .expect("failed to apply the holder schema");
    conn.batch_execute(HOLDER_SEED)
        .expect("failed to seed the holder schema");

    let (classified, db, registry) = support::classify_sql(
        HOLDER_SCHEMA,
        Some(r#"{"auth_current_user_id": {"kind": "current_user_accessor", "returns": "text"}}"#),
    );
    let queries = Translation::plan(
        classified,
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps()
    .tuple_queries();

    let (pure, joined, records) =
        assert_descriptions_match_their_sql(&mut conn, &queries, "holder shapes");

    // Two bridges and one member list the row decides, plus the guarded member list.
    assert_eq!(
        pure, 3,
        "both bridges and the unguarded member list follow from one row, saw {pure}"
    );
    assert_eq!(
        joined, 1,
        "only the guarded member list reads more than the row, saw {joined}"
    );
    assert!(
        records >= 6,
        "the seed must produce records to compare, saw {records}"
    );
}

/// A table keyed on two columns, carrying its own read policy, seeded with values the
/// target cannot spell verbatim.
///
/// This is the case the encoding exists for. The whole batch is refused if one value
/// renders wrong, and a compound name the evaluator spells differently from the SQL is
/// drift no DSL assertion can see, so the two are compared row by row here.
const COMPOUND_IDENTITY_SCHEMA: &str = "
CREATE TABLE paper_shares (
    paper_id TEXT,
    viewer TEXT,
    PRIMARY KEY (paper_id, viewer)
);

CREATE FUNCTION auth_current_user_id() RETURNS TEXT
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';

ALTER TABLE paper_shares ENABLE ROW LEVEL SECURITY;
CREATE POLICY shares_read ON paper_shares FOR SELECT
    USING (viewer = auth_current_user_id());
";

/// Every member of the refused family, on both sides of the key and in the subject.
/// `alice smith` is the ordinary one: a space in a name breaks the load today.
const COMPOUND_IDENTITY_SEED: &str = "
INSERT INTO paper_shares (paper_id, viewer) VALUES
  ('p1', 'alice'),
  ('p1', 'alice smith'),
  ('p|2', 'bob'),
  ('p2', 'a|b'),
  ('p3', ''),
  ('p4', '*'),
  ('p5', 'carol#member'),
  ('p6', 'ali\u{00e7}e'),
  ('p:7', 'dave'),
  ('', 'erin');
";

#[tokio::test]
#[ignore = "requires Docker: starts a PostgreSQL 18 container"]
async fn a_compound_identity_matches_between_the_sql_and_the_evaluator() {
    let (_container, mut conn) = start_postgres().await;

    conn.batch_execute(COMPOUND_IDENTITY_SCHEMA)
        .expect("failed to apply the compound identity schema");
    conn.batch_execute(COMPOUND_IDENTITY_SEED)
        .expect("failed to seed the compound identity schema");

    let (classified, db, registry) = support::classify_sql(
        COMPOUND_IDENTITY_SCHEMA,
        Some(r#"{"auth_current_user_id": {"kind": "current_user_accessor", "returns": "text"}}"#),
    );
    let queries = Translation::plan(
        classified,
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps()
    .tuple_queries();

    let (pure, joined, records) =
        assert_descriptions_match_their_sql(&mut conn, &queries, "compound identity");

    assert_eq!(
        pure, 1,
        "the ownership shape follows from one row of the share table, saw {pure}"
    );
    assert_eq!(joined, 0, "nothing here reads a second table, saw {joined}");
    assert_eq!(
        records, 10,
        "every seeded row must be named, including the ones the target refuses \
         verbatim, saw {records}"
    );
}

/// A schema whose reads compose all three ways a recipe can: one relation's records
/// alone, a union of two, and an intersection a barrier makes. `can_delete` nests the
/// union inside the intersection, since a per-row `DELETE` reads the table.
const RECIPE_SCHEMA: &str = "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE docs (id TEXT PRIMARY KEY, owner_id TEXT, editor_id TEXT, reviewer_id TEXT);
CREATE TABLE memos (id TEXT PRIMARY KEY, owner_id TEXT, editor_id TEXT);

CREATE FUNCTION auth_current_user_id() RETURNS TEXT
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';

ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE memos ENABLE ROW LEVEL SECURITY;

CREATE POLICY docs_read ON docs FOR SELECT
    USING (owner_id = auth_current_user_id() OR editor_id = auth_current_user_id());
CREATE POLICY docs_purge ON docs FOR DELETE
    USING (reviewer_id = auth_current_user_id());
CREATE POLICY memos_owner ON memos FOR SELECT
    USING (owner_id = auth_current_user_id());
CREATE POLICY memos_barrier ON memos AS RESTRICTIVE FOR SELECT
    USING (editor_id = auth_current_user_id());
";

/// Rows for both sides of every composition. `m-disagree` and `d-reviewer-out` are the
/// ones that matter: each names a subject one side of an intersection grants and the
/// other refuses, so a recipe flattened into a single list would read them wrong.
const RECIPE_SEED: &str = "
INSERT INTO users (id) VALUES ('alice'), ('bob'), ('carol');

INSERT INTO docs (id, owner_id, editor_id, reviewer_id) VALUES
    ('d-owner',        'alice', NULL,    NULL),
    ('d-editor',       NULL,    'bob',   NULL),
    ('d-both',         'alice', 'bob',   NULL),
    ('d-neither',      NULL,    NULL,    NULL),
    ('d-reviewer',     'alice', NULL,    'alice'),
    ('d-reviewer-out', 'alice', NULL,    'carol'),
    ('d-all-three',    'alice', 'alice', 'alice');

INSERT INTO memos (id, owner_id, editor_id) VALUES
    ('m-agree',    'alice', 'alice'),
    ('m-disagree', 'alice', 'bob'),
    ('m-owner',    'alice', NULL),
    ('m-editor',   NULL,    'bob'),
    ('m-neither',  NULL,    NULL);
";

/// Which composition a recipe is, for the coverage count.
fn recipe_kind(decision: &RowDecision) -> &'static str {
    match decision {
        RowDecision::Leaf { .. } => "leaf",
        RowDecision::Any(_) => "any",
        RowDecision::All(_) => "all",
        RowDecision::RequestGated { .. } => "request-gated",
        other => panic!("a recipe shape this test cannot read: {other:?}"),
    }
}

/// The first shape a recipe reaches, which names the table and object type every other
/// leaf of the same recipe has to agree on.
fn first_shape(decision: &RowDecision) -> &RecordDescription {
    match decision {
        RowDecision::Leaf { relation, shapes }
        | RowDecision::RequestGated {
            relation, shapes, ..
        } => shapes
            .first()
            .unwrap_or_else(|| panic!("leaf {relation} carries no shape, so it decides nothing")),
        RowDecision::Any(children) | RowDecision::All(children) => children
            .first()
            .map(first_shape)
            .expect("a recipe reaches at least one leaf"),
        other => panic!("a recipe shape this test cannot read: {other:?}"),
    }
}

/// The object one row of a recipe's table names, `None` when the row has no identity.
fn recipe_object(decision: &RowDecision, row: &serde_json::Value) -> Option<String> {
    let RecordDerivation::FromRow { template, .. } = &first_shape(decision).derivation else {
        panic!("a leaf resolves from the row");
    };
    let [ValueSource::Column(column)] = template.object_key.parts() else {
        panic!("a leaf keys its object on a column");
    };
    let key = scalar_text(row.get(column.as_str())?)?;
    Some(format!("{}:{key}", template.object_type))
}

/// Evaluate a recipe: a leaf is the union of the subjects its shapes produce for this
/// row, [`RowDecision::Any`] the union of its children and [`RowDecision::All`] their
/// intersection. Nothing else, which is the whole contract a consumer implements.
fn recipe_subjects(
    decision: &RowDecision,
    row: &serde_json::Value,
    object: &str,
) -> BTreeSet<String> {
    match decision {
        RowDecision::Leaf { relation, shapes } => shapes
            .iter()
            .flat_map(|shape| {
                records_from_row(shape, &JsonRowValues(row))
                    .expect("a leaf shape resolves without a database")
            })
            .map(|record| {
                assert_eq!(
                    record.object, object,
                    "leaf {relation} produced a record for another object"
                );
                assert_eq!(&record.relation, relation, "leaf {relation} misattributed");
                record.subject
            })
            .collect(),
        RowDecision::Any(children) => children
            .iter()
            .flat_map(|child| recipe_subjects(child, row, object))
            .collect(),
        RowDecision::All(children) => children
            .iter()
            .map(|child| recipe_subjects(child, row, object))
            .reduce(|left, right| left.intersection(&right).cloned().collect())
            .expect("a recipe reaches at least one leaf"),
        other => panic!("a recipe shape this test cannot evaluate: {other:?}"),
    }
}

/// Subjects a recipe would grant if its composition were thrown away and every leaf
/// unioned into one list, which is the shape the intersection has to differ from.
fn flattened_subjects(
    decision: &RowDecision,
    row: &serde_json::Value,
    object: &str,
) -> BTreeSet<String> {
    match decision {
        RowDecision::Leaf { .. } => recipe_subjects(decision, row, object),
        RowDecision::Any(children) | RowDecision::All(children) => children
            .iter()
            .flat_map(|child| flattened_subjects(child, row, object))
            .collect(),
        other => panic!("a recipe shape this test cannot evaluate: {other:?}"),
    }
}

async fn start_openfga(
    model: &AuthorizationModel,
    tuples: &BTreeSet<Fact>,
) -> (
    testcontainers::ContainerAsync<GenericImage>,
    OpenFgaClient<Channel>,
) {
    let container = GenericImage::new("openfga/openfga", "v1.11.6")
        .with_exposed_port(8080.tcp())
        .with_exposed_port(8081.tcp())
        .with_wait_for(WaitFor::message_on_stdout("starting HTTP server"))
        .with_cmd(["run"])
        .start()
        .await
        .expect("Failed to start OpenFGA container");
    let grpc_port = container.get_host_port_ipv4(8081).await.unwrap();

    let mut service = support::openfga::connect(grpc_port).await;
    let store_id = support::openfga::create_store(&mut service, "recipe-parity").await;
    let model_id =
        support::openfga::write_authorization_model(&mut service, &store_id, model).await;
    let client = service.into_client(&store_id, &model_id);
    support::openfga::write_tuples(
        &client,
        tuples
            .iter()
            .map(|record| {
                support::openfga::make_tuple(
                    &record.object,
                    record.relation.as_str(),
                    &record.subject,
                )
            })
            .collect(),
    )
    .await;
    (container, client)
}

/// The recipe is the whole answer, so the subjects it yields for a row have to be the
/// subjects the emitted model grants once the whole-table SQL has loaded it. Neither
/// side is written by hand: the tuples come from the generated queries and the answers
/// come from real `OpenFGA` resolving the model it was handed.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn every_recipe_grants_the_subjects_the_model_grants() {
    let (_postgres, mut conn) = start_postgres().await;
    conn.batch_execute(RECIPE_SCHEMA)
        .expect("failed to apply the recipe schema");
    conn.batch_execute(RECIPE_SEED)
        .expect("failed to seed the recipe schema");

    let (classified, db, registry) = support::classify_sql(
        RECIPE_SCHEMA,
        Some(r#"{"auth_current_user_id": {"kind": "current_user_accessor", "returns": "text"}}"#),
    );
    let planned = Translation::plan(
        classified,
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    );
    let reported = planned.relations();
    let outputs = planned.outputs_accepting_gaps();

    let mut tuples: BTreeSet<Fact> = BTreeSet::new();
    for query in &outputs.tuple_queries() {
        tuples.extend(records_from_sql(&mut conn, query));
    }
    assert!(
        !tuples.is_empty(),
        "the loader must produce tuples, otherwise every check answers no"
    );

    let (_openfga, client) = start_openfga(&outputs.json_model(), &tuples).await;

    // Every user any tuple names, which bounds the comparison: a subject outside it
    // could only reach the relation through a tuple, and every tuple is in here.
    let universe: BTreeSet<String> = tuples
        .iter()
        .filter(|record| record.subject.starts_with("user:"))
        .map(|record| record.subject.clone())
        .collect();

    let mut kinds: BTreeSet<&str> = BTreeSet::new();
    let mut compared = 0usize;
    let mut granting_rows = 0usize;
    let mut refusals = 0usize;
    let mut narrowed_by_composition = 0usize;
    let mut failures = Vec::new();

    for entry in &reported {
        let Some(decision) = entry.decision.as_ref() else {
            continue;
        };
        kinds.insert(recipe_kind(decision));
        let table = first_shape(decision)
            .row_table()
            .expect("a leaf resolves from a row of one table")
            .to_string();

        for row in rows_of(&mut conn, &table) {
            let Some(object) = recipe_object(decision, &row) else {
                continue;
            };
            let expected = recipe_subjects(decision, &row, &object);
            if !expected.is_empty() {
                granting_rows += 1;
            }
            if flattened_subjects(decision, &row, &object) != expected {
                narrowed_by_composition += 1;
            }

            let mut allowed = BTreeSet::new();
            for candidate in universe.union(&expected) {
                compared += 1;
                if support::openfga::check_allowed(
                    &client,
                    candidate,
                    entry.relation.as_str(),
                    &object,
                )
                .await
                {
                    allowed.insert(candidate.clone());
                } else {
                    refusals += 1;
                }
            }
            if allowed != expected {
                failures.push(format!(
                    "{object}#{}: the recipe grants {expected:?}, the model grants {allowed:?}",
                    entry.relation
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "the recipe and the model disagree:\n{}",
        failures.join("\n")
    );

    // Non-vacuous on every axis the comparison could be blind on.
    assert_eq!(
        kinds,
        BTreeSet::from(["all", "any", "leaf"]),
        "the schema has to exercise every composition, saw {kinds:?}"
    );
    assert!(
        granting_rows > 0,
        "no row grants anybody, so nothing is compared against a grant"
    );
    assert!(
        refusals > 0,
        "nothing is refused, so granting everybody would pass"
    );
    assert!(
        narrowed_by_composition > 0,
        "no row is narrowed by an intersection, so a recipe flattened into one list \
         would pass this comparison"
    );
    assert!(
        compared > 50,
        "too few checks to be meaningful, saw {compared}"
    );
}

/// The other half of the compound identity case: the names the two renderers agree on
/// have to be names the service actually takes, and they have to answer for the right
/// caller.
///
/// The load is all or nothing, so one value the target cannot spell fails the write and
/// the whole seed with it. That is the failure this encoding exists to remove, and the
/// seed carries every member of the refused family.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn a_compound_identity_loads_and_answers_against_the_service() {
    let (_postgres, mut conn) = start_postgres().await;
    conn.batch_execute(COMPOUND_IDENTITY_SCHEMA)
        .expect("failed to apply the compound identity schema");
    conn.batch_execute(COMPOUND_IDENTITY_SEED)
        .expect("failed to seed the compound identity schema");

    let (classified, db, registry) = support::classify_sql(
        COMPOUND_IDENTITY_SCHEMA,
        Some(r#"{"auth_current_user_id": {"kind": "current_user_accessor", "returns": "text"}}"#),
    );
    let outputs = Translation::plan(
        classified,
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps();

    let mut tuples: BTreeSet<Fact> = BTreeSet::new();
    for query in &outputs.tuple_queries() {
        tuples.extend(records_from_sql(&mut conn, query));
    }
    assert_eq!(
        tuples.len(),
        10,
        "every seeded share must produce a fact, or the encoding lost a row: {tuples:#?}"
    );

    // The write is where an unspellable name fails, and it fails the whole batch.
    let (_openfga, client) = start_openfga(&outputs.json_model(), &tuples).await;

    let mut allowed = 0usize;
    let mut denied = 0usize;
    for record in &tuples {
        assert!(
            support::openfga::check_allowed(
                &client,
                &record.subject,
                record.relation.as_str(),
                &record.object
            )
            .await,
            "the viewer a share names must reach it: {record:?}"
        );
        allowed += 1;

        // A stranger must not, or the encoding has collapsed two names into one. The
        // wildcard spelling is the one that would: an owner of `*` renders `user:*`
        // verbatim and grants everybody.
        assert!(
            !support::openfga::check_allowed(
                &client,
                "user:stranger",
                record.relation.as_str(),
                &record.object
            )
            .await,
            "nobody else may reach it: {record:?}"
        );
        denied += 1;
    }

    assert!(allowed > 0 && denied > 0, "the case has to cut both ways");
}

/// A schema whose naming is not the obvious one: two tables canonicalise alike, so one
/// takes a suffix, and a third is keyed by two columns.
const NAMING_SCHEMA: &str = "
CREATE SCHEMA a;
CREATE SCHEMA b;
CREATE TABLE a.notes (id TEXT PRIMARY KEY, owner_id TEXT);
CREATE TABLE b.notes (id TEXT PRIMARY KEY, owner_id TEXT);
CREATE TABLE parts (order_id TEXT, line_no INT, owner_id TEXT, PRIMARY KEY (order_id, line_no));
CREATE FUNCTION auth_current_user_id() RETURNS TEXT
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE a.notes ENABLE ROW LEVEL SECURITY;
ALTER TABLE b.notes ENABLE ROW LEVEL SECURITY;
ALTER TABLE parts ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON a.notes FOR SELECT USING (owner_id = auth_current_user_id());
CREATE POLICY q ON b.notes FOR SELECT USING (owner_id = auth_current_user_id());
CREATE POLICY r ON parts FOR SELECT USING (owner_id = auth_current_user_id());
";

/// Keys chosen for what the encoder has to survive: a separator inside a value, a space,
/// and a non-ASCII character, each of which the object name escapes rather than passes on.
const NAMING_SEED: &str = "
INSERT INTO a.notes (id, owner_id) VALUES ('n1', 'alice'), ('a|b', 'bob');
INSERT INTO b.notes (id, owner_id) VALUES ('n1', 'carol'), ('two words', 'dave');
INSERT INTO parts (order_id, line_no, owner_id) VALUES ('o|1', 2, 'alice'), ('\u{00e9}', 3, 'bob');
";

/// The name a row-naming entry renders is the name the table's own SQL writes.
///
/// A consumer asking the authorization service about one changed row spells the name from
/// the entry, and the store holds the names the generated SQL loaded. Derived apart, the
/// two can disagree on the collision suffix, on the key, or on the encoding, and every
/// question about that row would then be asked about nothing.
#[tokio::test]
#[ignore = "requires Docker: starts a PostgreSQL 18 container"]
async fn a_row_naming_entry_spells_the_object_its_own_sql_writes() {
    let (_container, mut conn) = start_postgres().await;

    conn.batch_execute(NAMING_SCHEMA)
        .expect("failed to apply the naming schema");
    conn.batch_execute(NAMING_SEED)
        .expect("failed to seed the naming schema");

    let (classified, db, registry) = support::classify_sql(
        NAMING_SCHEMA,
        Some(r#"{"auth_current_user_id": {"kind": "current_user_accessor", "returns": "text"}}"#),
    );
    let translation = Translation::plan(
        classified,
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    );
    let naming = translation.row_naming();
    assert_eq!(
        naming.len(),
        3,
        "every guarded table is named, got {naming:?}"
    );
    // The case is only worth running while the naming is not the obvious one.
    assert!(
        naming
            .iter()
            .any(|entry| entry.type_name != entry.table && entry.type_name.contains('_')),
        "one table has to take a collision suffix: {naming:?}"
    );
    assert!(
        naming.iter().any(|entry| entry.key.parts().len() > 1),
        "one table has to be keyed by two columns: {naming:?}"
    );

    let queries = translation.outputs_accepting_gaps().tuple_queries();
    let written: BTreeSet<String> = queries
        .iter()
        .filter(|query| !query.sql.trim_start().starts_with("--"))
        .flat_map(|query| records_from_sql(&mut conn, query))
        .map(|record| record.object)
        .collect();

    let mut compared = 0usize;
    for entry in &naming {
        let rendered: BTreeSet<String> = rows_of(&mut conn, &entry.table)
            .iter()
            .filter_map(|row| {
                entry
                    .key
                    .render(entry.type_name.as_str(), &JsonRowValues(row))
                    .unwrap_or_else(|error| {
                        panic!("a row of {} cannot be named: {error:?}", entry.table)
                    })
            })
            .collect();
        let prefix = format!("{}:", entry.type_name);
        let mine: Vec<&String> = written
            .iter()
            .filter(|object| object.starts_with(&prefix))
            .collect();
        assert!(
            !mine.is_empty(),
            "the SQL wrote no object for {}, so the comparison is vacuous",
            entry.table
        );
        for object in mine {
            assert!(
                rendered.contains(object),
                "the SQL wrote {object} for {}, which the entry's key never renders: {rendered:?}",
                entry.table
            );
            compared += 1;
        }
    }

    // A naming that rendered nothing, or a seed that loaded nothing, would pass silently.
    assert_eq!(
        compared, 6,
        "every seeded row is named on both sides, compared {compared}"
    );
}

/// Two clauses spelled apart, which is the shape whose `UPDATE` the model answers with
/// two relations instead of one.
const REPLACEMENT_SCHEMA: &str = "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE notes (
    id TEXT PRIMARY KEY,
    writer_user_id TEXT NOT NULL REFERENCES users(id),
    reviewer_user_id TEXT NOT NULL REFERENCES users(id),
    body TEXT NOT NULL
);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY notes_read ON notes FOR SELECT USING (writer_user_id = auth_current_user_id());
CREATE POLICY notes_write ON notes FOR UPDATE
    USING (writer_user_id = auth_current_user_id())
    WITH CHECK (reviewer_user_id = auth_current_user_id());
";

/// One row per way the two clauses can disagree, so a comparison that ignored one of
/// them still has a row to be wrong about.
const REPLACEMENT_SEED: &str = "
INSERT INTO users (id) VALUES ('alice'), ('bob');
INSERT INTO notes (id, writer_user_id, reviewer_user_id, body) VALUES
    ('both', 'alice', 'alice', 'x'),
    ('write-only', 'alice', 'bob', 'x'),
    ('review-only', 'bob', 'alice', 'x'),
    ('neither', 'bob', 'bob', 'x');
";

/// Asking every judgement the report names, and requiring all of them, has to answer as
/// the model's own relation does where the two row versions are the same row. That is
/// what says the report and the emitted model have not drifted apart.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn every_judgement_together_answers_as_the_action_relation_does() {
    let (_postgres, mut conn) = start_postgres().await;
    conn.batch_execute(REPLACEMENT_SCHEMA)
        .expect("failed to apply the replacement schema");
    conn.batch_execute(REPLACEMENT_SEED)
        .expect("failed to seed the replacement schema");

    let (classified, db, registry) = support::classify_sql(
        REPLACEMENT_SCHEMA,
        Some(r#"{"auth_current_user_id": {"kind": "current_user_accessor", "returns": "text"}}"#),
    );
    let planned = Translation::plan(
        classified,
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    );
    let reported = planned.action_relations();
    let outputs = planned.outputs_accepting_gaps();

    let mut tuples: BTreeSet<Fact> = BTreeSet::new();
    for query in &outputs.tuple_queries() {
        tuples.extend(records_from_sql(&mut conn, query));
    }
    let (_openfga, client) = start_openfga(&outputs.json_model(), &tuples).await;

    let update = reported
        .iter()
        .find(|entry| {
            entry.type_name.as_str() == "notes" && entry.statement == ActionStatement::Update
        })
        .expect("the guarded table answers for an UPDATE");
    let ActionAnswer::Judged(judges) = &update.answer else {
        panic!("a replacement is judged, got {:?}", update.answer);
    };
    let named: BTreeSet<&str> = judges.iter().map(|judge| judge.relation.as_str()).collect();
    assert_eq!(
        named,
        BTreeSet::from(["can_update_using", "can_update_check"]),
        "the case only tests anything while the two clauses are answered apart"
    );

    let mut agreed = 0usize;
    let mut granted = 0usize;
    let mut split_by_a_half = 0usize;
    let mut failures = Vec::new();
    for id in ["both", "write-only", "review-only", "neither"] {
        let object = format!("notes:{id}");
        for user in ["user:alice", "user:bob"] {
            let mut halves = Vec::new();
            for judge in judges {
                halves.push(
                    support::openfga::check_allowed(
                        &client,
                        user,
                        judge.relation.as_str(),
                        &object,
                    )
                    .await,
                );
            }
            let together = halves.iter().all(|granted| *granted);
            let whole = support::openfga::check_allowed(&client, user, "can_update", &object).await;
            if together != whole {
                failures.push(format!(
                    "{object} for {user}: the judgements answer {together}, can_update answers \
                     {whole}"
                ));
            }
            agreed += 1;
            granted += usize::from(whole);
            split_by_a_half += usize::from(halves.iter().any(|granted| *granted) && !together);
        }
    }

    assert!(
        failures.is_empty(),
        "the report and the model disagree:\n{}",
        failures.join("\n")
    );
    assert_eq!(agreed, 8, "every seeded row is asked about by both callers");
    assert!(
        granted > 0,
        "nothing is granted, so a report naming a denial for everything would pass"
    );
    assert!(
        split_by_a_half > 0,
        "no row is admitted by one half alone, so requiring either half would pass"
    );
}

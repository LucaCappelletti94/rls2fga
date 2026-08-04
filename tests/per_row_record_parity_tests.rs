//! Differential test for the per-row record descriptions.
//!
//! The whole-table SQL is the reference implementation. For every row of every
//! table a description reads, evaluating the description must yield exactly the
//! records the description's own query yields for that row. No expected output is
//! written by hand, so a description that disagrees with its own SQL fails here.

#![cfg(not(target_os = "windows"))]
#![cfg(feature = "db")]

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

use rls2fga::classifier::patterns::ConfidenceLevel;
use rls2fga::generator::model_generator::GeneratorSettings;
use rls2fga::generator::records::{
    records_from_row, BoundQuery, Record, RecordDerivation, RecordDescription, RowValues,
};
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

/// Records the generated query returns.
fn records_from_sql(conn: &mut PgConnection, query: &TupleQuery) -> BTreeSet<Record> {
    let rows: Vec<TupleRow> = diesel::sql_query(&query.sql)
        .load(conn)
        .unwrap_or_else(|error| {
            panic!(
                "the generated query failed on PostgreSQL 18: {}\n{}\nError: {error}",
                query.comment, query.sql
            )
        });
    rows.into_iter()
        .map(|row| Record {
            object: row.object,
            relation: row.relation,
            subject: row.subject,
        })
        .collect()
}

/// Every row of `table`, as JSON.
fn rows_of(conn: &mut PgConnection, table: &str) -> Vec<serde_json::Value> {
    // The table is discovered from the description at runtime, so the typed DSL
    // cannot name it. `to_jsonb` keeps every column without a per-table struct.
    let sql = format!("SELECT to_jsonb(t) AS row FROM \"{table}\" t");
    let rows: Vec<JsonRow> = diesel::sql_query(&sql)
        .load(conn)
        .unwrap_or_else(|error| panic!("failed to read rows of {table}: {error}"));
    rows.into_iter().map(|row| row.row).collect()
}

/// Records the description yields over every row of its table.
fn records_from_descriptions(
    conn: &mut PgConnection,
    description: &RecordDescription,
) -> BTreeSet<Record> {
    let table = description
        .row_table()
        .expect("only a pure description reaches here");
    rows_of(conn, table)
        .iter()
        .flat_map(|row| {
            records_from_row(description, &JsonRowValues(row))
                .expect("a pure description evaluates without a database")
        })
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
) -> BTreeSet<Record> {
    let literal = format!("'{}'", key.replace('\'', "''"));
    let sql = bound.sql.replace("$1", &literal);
    let rows: Vec<TupleRow> = diesel::sql_query(&sql).load(conn).unwrap_or_else(|error| {
        panic!(
            "a bound query failed on PostgreSQL 18 for {}.{} = {literal}\n{sql}\nError: {error}",
            bound.table, bound.key_column
        )
    });
    rows.into_iter()
        .map(|row| Record {
            object: row.object,
            relation: row.relation,
            subject: row.subject,
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
        let keys = distinct_keys(conn, &bound.table, &bound.key_column);
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
            let bound_records = records_from_bound_query(conn, bound, key);
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

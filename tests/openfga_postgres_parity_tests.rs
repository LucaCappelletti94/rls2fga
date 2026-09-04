#![cfg(not(target_os = "windows"))]

use std::collections::BTreeSet;

use diesel::connection::SimpleConnection;
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::sql_types::{Integer, Text};

use rls2fga::generator::model_generator::GeneratorSettings;
use rls2fga::generator::tuple_generator::TupleQuery;
use rls2fga::translator::Translation;
use rls2fga::types::ConfidenceLevel;
use rls2fga::types::{records_from_row, RecordDerivation, RecordDescription};

mod support;

use support::containers::{PG_DB, PG_PASSWORD, PG_USER};

const USER_ALICE: &str = "00000000-0000-0000-0000-0000000000a1";
const USER_BOB: &str = "00000000-0000-0000-0000-0000000000a2";
const USER_CAROL: &str = "00000000-0000-0000-0000-0000000000a3";
const USER_DAVE: &str = "00000000-0000-0000-0000-0000000000a4";
const USER_EVE: &str = "00000000-0000-0000-0000-0000000000a5";

const TEAM_ALPHA: &str = "00000000-0000-0000-0000-0000000000b1";
const TEAM_BETA: &str = "00000000-0000-0000-0000-0000000000b2";

const DOC_1: &str = "00000000-0000-0000-0000-0000000000d1";
const DOC_2: &str = "00000000-0000-0000-0000-0000000000d2";

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
struct TupleKey {
    object: String,
    relation: String,
    subject: String,
}

#[derive(QueryableByName)]
struct TupleRow {
    #[diesel(sql_type = Text)]
    object: String,
    #[diesel(sql_type = Text)]
    relation: String,
    #[diesel(sql_type = Text)]
    subject: String,
}

#[derive(QueryableByName)]
struct RoleRow {
    #[diesel(sql_type = Integer)]
    role: i32,
}

fn seed_emi_data(conn: &mut PgConnection) {
    let seed_sql = format!(
        "
INSERT INTO users (id) VALUES
    ('{USER_ALICE}'),
    ('{USER_BOB}'),
    ('{USER_CAROL}'),
    ('{USER_DAVE}'),
    ('{USER_EVE}');

INSERT INTO teams (id) VALUES
    ('{TEAM_ALPHA}'),
    ('{TEAM_BETA}');

INSERT INTO team_members (team_id, user_id) VALUES
    ('{TEAM_ALPHA}', '{USER_BOB}'),
    ('{TEAM_BETA}', '{USER_DAVE}');

INSERT INTO ownables (id, owner_id) VALUES
    ('{DOC_1}', '{USER_ALICE}'),
    ('{DOC_2}', '{TEAM_ALPHA}');

INSERT INTO owner_grants (grantee_owner_id, granted_owner_id, role_id) VALUES
    ('{USER_CAROL}', '{USER_ALICE}', 3),
    ('{TEAM_BETA}', '{USER_ALICE}', 2),
    ('{USER_EVE}', '{TEAM_ALPHA}', 4);
"
    );

    conn.batch_execute(&seed_sql)
        .expect("Failed to seed EMI fixture data");
}

fn execute_tuple_queries(conn: &mut PgConnection, tuple_queries: &[TupleQuery]) -> Vec<TupleKey> {
    let mut keys = BTreeSet::new();

    for query in tuple_queries {
        let rows: Vec<TupleRow> =
            diesel::sql_query(&query.sql)
                .load(conn)
                .unwrap_or_else(|error| {
                    panic!(
                        "Tuple SQL failed in PostgreSQL 18: {}\n{}\nError: {error}",
                        query.comment, query.sql
                    )
                });

        for row in rows {
            keys.insert(TupleKey {
                object: row.object,
                relation: row.relation,
                subject: row.subject,
            });
        }
    }

    keys.into_iter().collect()
}

fn postgres_role_for_user_and_doc(conn: &mut PgConnection, user_id: &str, doc_id: &str) -> i32 {
    let row: RoleRow = diesel::sql_query(
        "SELECT get_owner_role($1::text::uuid, owner_id)
             AS role
         FROM ownables
         WHERE id = $2::text::uuid",
    )
    .bind::<Text, _>(user_id)
    .bind::<Text, _>(doc_id)
    .get_result(conn)
    .unwrap();
    row.role
}

#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn translated_schema_parity_postgres18_and_openfga() {
    let postgres = support::containers::start_postgres().await;

    let pg_port = postgres.get_host_port_ipv4(5432).await.unwrap();
    let pg_url = format!("postgres://{PG_USER}:{PG_PASSWORD}@127.0.0.1:{pg_port}/{PG_DB}");
    let mut conn = support::containers::connect_postgres_with_retry(&pg_url);

    let schema_sql = support::read_fixture_sql("earth_metabolome");
    let (classified, db, registry) = support::load_fixture_classified("earth_metabolome");
    conn.batch_execute(&schema_sql)
        .expect("Failed to apply EMI schema on PostgreSQL 18");
    seed_emi_data(&mut conn);

    let model = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .expect("translation should plan")
    .outputs_accepting_gaps()
    .json_model();
    let outputs = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .expect("translation should plan")
    .outputs_accepting_gaps();
    let tuple_queries = outputs.tuple_queries();
    let tuple_keys = execute_tuple_queries(&mut conn, tuple_queries);
    assert!(
        !tuple_keys.is_empty(),
        "Expected generated tuple SQL to produce at least one tuple"
    );

    let openfga = support::containers::start_openfga().await;

    let grpc_port = openfga.get_host_port_ipv4(8081).await.unwrap();
    let mut service_client = support::openfga::connect(grpc_port).await;

    let store_id = support::openfga::create_store(&mut service_client, "pg18-parity-test").await;
    let model_id =
        support::openfga::write_authorization_model(&mut service_client, &store_id, &model).await;

    let writes: Vec<openfga_client::client::TupleKey> = tuple_keys
        .iter()
        .map(|tuple| support::openfga::make_tuple(&tuple.object, &tuple.relation, &tuple.subject))
        .collect();

    let client = service_client.into_client(&store_id, &model_id);
    support::openfga::write_tuples(&client, writes).await;

    let users = [USER_ALICE, USER_BOB, USER_CAROL, USER_DAVE, USER_EVE];
    let docs = [DOC_1, DOC_2];
    let relations = [
        ("can_select", 2),
        ("can_insert", 3),
        ("can_update", 3),
        ("can_delete", 4),
    ];

    let mut failures = Vec::new();
    for user_id in users {
        for doc_id in docs {
            let role = postgres_role_for_user_and_doc(&mut conn, user_id, doc_id);
            let user = format!("user:{user_id}");
            let object = format!("ownables:{doc_id}");

            for (relation, threshold) in relations {
                let expected = role >= threshold;
                let actual =
                    support::openfga::check_allowed(&client, &user, relation, &object).await;
                if expected != actual {
                    failures.push(format!(
                        "{user} {relation} {object}: postgres={expected} (role={role}), openfga={actual}"
                    ));
                }
            }
        }
    }

    assert!(
        failures.is_empty(),
        "PostgreSQL/OpenFGA parity mismatches:\n{}",
        failures.join("\n")
    );
}

diesel::table! {
    users (id) {
        id -> diesel::sql_types::Text,
    }
}

diesel::table! {
    notes (id) {
        id -> diesel::sql_types::Text,
        owner_id -> diesel::sql_types::Text,
        author_id -> diesel::sql_types::Text,
    }
}

/// One seeded `notes` row: `(id, owner_id, author_id)`.
const SEEDED_NOTES: [(&str, &str, &str); 4] = [
    ("note-author-only", USER_BOB, USER_ALICE),
    ("note-owner-only", USER_ALICE, USER_BOB),
    ("note-both", USER_ALICE, USER_ALICE),
    ("note-neither", USER_BOB, USER_BOB),
];

/// The `INSERT` statement shapes whose row-level security differs.
#[derive(Debug, Clone, Copy)]
enum InsertShape {
    /// Only the `INSERT` policies apply.
    Plain,
    /// Returns table columns, so the `SELECT` policies apply to the new row too.
    Returning,
    /// Naming a conflict arbiter applies them as well, conflict or not.
    ConflictOnTarget,
    /// Without an arbiter nothing extra is read.
    ConflictWithoutTarget,
}

/// Either the statement ran, or it was rejected before the deliberate rollback.
#[derive(Debug)]
enum AttemptError {
    Rejected(diesel::result::Error),
    Rollback,
}

impl From<diesel::result::Error> for AttemptError {
    fn from(error: diesel::result::Error) -> Self {
        Self::Rejected(error)
    }
}

fn seed_notes_data(conn: &mut PgConnection) {
    diesel::insert_into(users::table)
        .values([USER_ALICE, USER_BOB].map(|id| users::id.eq(id)).to_vec())
        .execute(conn)
        .expect("Failed to seed users");

    let rows: Vec<_> = SEEDED_NOTES
        .iter()
        .map(|(id, owner, author)| {
            (
                notes::id.eq(*id),
                notes::owner_id.eq(*owner),
                notes::author_id.eq(*author),
            )
        })
        .collect();
    diesel::insert_into(notes::table)
        .values(rows)
        .execute(conn)
        .expect("Failed to seed notes");
}

/// Whether `app_user` acting as `user_id` may insert a row carrying `owner_id`
/// and `author_id`. The row is never kept.
fn postgres_allows_insert(
    conn: &mut PgConnection,
    user_id: &str,
    owner_id: &str,
    author_id: &str,
    shape: InsertShape,
) -> bool {
    let new_id = format!("probe-{user_id}-{owner_id}-{author_id}-{shape:?}");
    let outcome = conn.transaction::<(), AttemptError, _>(|conn| {
        // Session settings and role switching have no query DSL form.
        diesel::sql_query("SET LOCAL ROLE app_user").execute(conn)?;
        diesel::sql_query("SELECT set_config('app.current_user_id', $1, true)")
            .bind::<Text, _>(user_id)
            .execute(conn)?;

        let values = (
            notes::id.eq(&new_id),
            notes::owner_id.eq(owner_id),
            notes::author_id.eq(author_id),
        );
        match shape {
            InsertShape::Plain => {
                diesel::insert_into(notes::table)
                    .values(values)
                    .execute(conn)?;
            }
            InsertShape::Returning => {
                diesel::insert_into(notes::table)
                    .values(values)
                    .returning(notes::id)
                    .get_result::<String>(conn)?;
            }
            InsertShape::ConflictOnTarget => {
                diesel::insert_into(notes::table)
                    .values(values)
                    .on_conflict(notes::id)
                    .do_nothing()
                    .execute(conn)?;
            }
            InsertShape::ConflictWithoutTarget => {
                diesel::insert_into(notes::table)
                    .values(values)
                    .on_conflict_do_nothing()
                    .execute(conn)?;
            }
        }
        Err(AttemptError::Rollback)
    });

    match outcome {
        Err(AttemptError::Rollback) => true,
        Err(AttemptError::Rejected(error)) => {
            let rendered = error.to_string();
            assert!(
                rendered.contains("row-level security"),
                "{shape:?} as {user_id} failed for a reason other than RLS: {rendered}"
            );
            false
        }
        Ok(()) => unreachable!("the transaction body always rolls back"),
    }
}

/// `INSERT ... RETURNING` and `INSERT ... ON CONFLICT` check the new row against
/// the `SELECT` policies, which is what `can_insert_returning` expresses. Plain
/// `INSERT` does not, which is what leaves `can_insert` ungated.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn insert_readback_parity_postgres18_and_openfga() {
    let postgres = support::containers::start_postgres().await;

    let pg_port = postgres.get_host_port_ipv4(5432).await.unwrap();
    let pg_url = format!("postgres://{PG_USER}:{PG_PASSWORD}@127.0.0.1:{pg_port}/{PG_DB}");
    let mut conn = support::containers::connect_postgres_with_retry(&pg_url);

    let schema_sql = support::read_fixture_sql("insert_readback");
    let (classified, db, registry) = support::load_fixture_classified("insert_readback");
    conn.batch_execute(&schema_sql)
        .expect("Failed to apply the insert_readback schema on PostgreSQL 18");
    conn.batch_execute("CREATE ROLE app_user LOGIN; GRANT SELECT, INSERT ON notes TO app_user;")
        .expect("Failed to create the querying role");
    seed_notes_data(&mut conn);

    let model = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .expect("translation should plan")
    .outputs_accepting_gaps()
    .json_model();
    let outputs = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .expect("translation should plan")
    .outputs_accepting_gaps();
    let tuple_queries = outputs.tuple_queries();
    let tuple_keys = execute_tuple_queries(&mut conn, tuple_queries);

    let openfga = support::containers::start_openfga().await;

    let grpc_port = openfga.get_host_port_ipv4(8081).await.unwrap();
    let mut service_client = support::openfga::connect(grpc_port).await;
    let store_id =
        support::openfga::create_store(&mut service_client, "insert-readback-parity").await;
    let model_id =
        support::openfga::write_authorization_model(&mut service_client, &store_id, &model).await;

    let writes: Vec<openfga_client::client::TupleKey> = tuple_keys
        .iter()
        .map(|tuple| support::openfga::make_tuple(&tuple.object, &tuple.relation, &tuple.subject))
        .collect();
    let client = service_client.into_client(&store_id, &model_id);
    support::openfga::write_tuples(&client, writes).await;

    let mut failures = Vec::new();
    for user_id in [USER_ALICE, USER_BOB] {
        for (note_id, owner_id, author_id) in SEEDED_NOTES {
            let user = format!("user:{user_id}");
            let object = format!("notes:{note_id}");

            let mut allows =
                |shape| postgres_allows_insert(&mut conn, user_id, owner_id, author_id, shape);
            let plain = allows(InsertShape::Plain);
            let returning = allows(InsertShape::Returning);
            assert_eq!(
                returning,
                allows(InsertShape::ConflictOnTarget),
                "naming a conflict arbiter reads the new row back, like RETURNING, for {user} on {object}"
            );
            assert_eq!(
                plain,
                allows(InsertShape::ConflictWithoutTarget),
                "ON CONFLICT without an arbiter reads nothing back for {user} on {object}"
            );

            for (relation, expected) in [("can_insert", plain), ("can_insert_returning", returning)]
            {
                let actual =
                    support::openfga::check_allowed(&client, &user, relation, &object).await;
                if expected != actual {
                    failures.push(format!(
                        "{user} {relation} {object}: postgres={expected}, openfga={actual}"
                    ));
                }
            }
        }
    }

    assert!(
        failures.is_empty(),
        "PostgreSQL/OpenFGA insert parity mismatches:\n{}",
        failures.join("\n")
    );
}

diesel::table! {
    docs (id) {
        id -> diesel::sql_types::Text,
    }
}

diesel::table! {
    doc_members (id) {
        id -> diesel::sql_types::Text,
        doc_id -> diesel::sql_types::Text,
        user_id -> diesel::sql_types::Text,
    }
}

diesel::table! {
    #[sql_name = "notes"]
    notes_reviewed (id) {
        id -> diesel::sql_types::Text,
        owner_id -> diesel::sql_types::Text,
        reviewer_id -> diesel::sql_types::Text,
    }
}

/// One seeded `notes` row: `(id, owner_id, author_id, editor_id)`.
const SEEDED_UPSERT_NOTES: [(&str, &str, &str, &str); 5] = [
    ("note-alice-all", USER_ALICE, USER_ALICE, USER_ALICE),
    ("note-author-only", USER_BOB, USER_ALICE, USER_BOB),
    ("note-author-editor", USER_BOB, USER_ALICE, USER_ALICE),
    ("note-owner-author", USER_ALICE, USER_ALICE, USER_BOB),
    ("note-bob-all", USER_BOB, USER_BOB, USER_BOB),
];

diesel::table! {
    #[sql_name = "notes"]
    notes_upsert (id) {
        id -> diesel::sql_types::Text,
        owner_id -> diesel::sql_types::Text,
        author_id -> diesel::sql_types::Text,
        editor_id -> diesel::sql_types::Text,
        body -> diesel::sql_types::Nullable<diesel::sql_types::Text>,
    }
}

/// Whether `app_user` acting as `user_id` may write `note` back. `conflict` picks
/// the statement: an upsert onto the seeded row, or a plain insert of a fresh row
/// carrying the same column values. Neither row is kept.
fn postgres_allows_upsert(
    conn: &mut PgConnection,
    user_id: &str,
    note: (&str, &str, &str, &str),
    conflict: bool,
) -> bool {
    let (note_id, owner_id, author_id, editor_id) = note;
    let fresh_id = format!("probe-{user_id}-{note_id}");
    let outcome = conn.transaction::<(), AttemptError, _>(|conn| {
        // Session settings and role switching have no query DSL form.
        diesel::sql_query("SET LOCAL ROLE app_user").execute(conn)?;
        diesel::sql_query("SELECT set_config('app.current_user_id', $1, true)")
            .bind::<Text, _>(user_id)
            .execute(conn)?;

        let id = if conflict { note_id } else { fresh_id.as_str() };
        let values = (
            notes_upsert::id.eq(id),
            notes_upsert::owner_id.eq(owner_id),
            notes_upsert::author_id.eq(author_id),
            notes_upsert::editor_id.eq(editor_id),
            notes_upsert::body.eq(Some("probe")),
        );
        if conflict {
            diesel::insert_into(notes_upsert::table)
                .values(values)
                .on_conflict(notes_upsert::id)
                .do_update()
                .set(notes_upsert::body.eq(Some("probe")))
                .execute(conn)?;
        } else {
            diesel::insert_into(notes_upsert::table)
                .values(values)
                .execute(conn)?;
        }
        Err(AttemptError::Rollback)
    });

    match outcome {
        Err(AttemptError::Rollback) => true,
        Err(AttemptError::Rejected(error)) => {
            let rendered = error.to_string();
            assert!(
                rendered.contains("row-level security"),
                "writing {note_id} as {user_id} failed for a reason other than RLS: {rendered}"
            );
            false
        }
        Ok(()) => unreachable!("the transaction body always rolls back"),
    }
}

/// `INSERT ... ON CONFLICT ... DO UPDATE` updates the conflicting row, so
/// `PostgreSQL` applies the UPDATE policies to it as well as the INSERT ones, which
/// is what `can_upsert` expresses.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn upsert_parity_postgres18_and_openfga() {
    let postgres = support::containers::start_postgres().await;

    let pg_port = postgres.get_host_port_ipv4(5432).await.unwrap();
    let pg_url = format!("postgres://{PG_USER}:{PG_PASSWORD}@127.0.0.1:{pg_port}/{PG_DB}");
    let mut conn = support::containers::connect_postgres_with_retry(&pg_url);

    let schema_sql = support::read_fixture_sql("upsert");
    let (classified, db, registry) = support::load_fixture_classified("upsert");
    conn.batch_execute(&schema_sql)
        .expect("Failed to apply the upsert schema on PostgreSQL 18");
    conn.batch_execute(
        "CREATE ROLE app_user LOGIN; GRANT SELECT, INSERT, UPDATE ON notes TO app_user;",
    )
    .expect("Failed to create the querying role");

    diesel::insert_into(users::table)
        .values([USER_ALICE, USER_BOB].map(|id| users::id.eq(id)).to_vec())
        .execute(&mut conn)
        .expect("Failed to seed users");
    let rows: Vec<_> = SEEDED_UPSERT_NOTES
        .iter()
        .map(|(id, owner, author, editor)| {
            (
                notes_upsert::id.eq(*id),
                notes_upsert::owner_id.eq(*owner),
                notes_upsert::author_id.eq(*author),
                notes_upsert::editor_id.eq(*editor),
            )
        })
        .collect();
    diesel::insert_into(notes_upsert::table)
        .values(rows)
        .execute(&mut conn)
        .expect("Failed to seed notes");

    let model = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .expect("translation should plan")
    .outputs_accepting_gaps()
    .json_model();
    let outputs = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .expect("translation should plan")
    .outputs_accepting_gaps();
    let tuple_queries = outputs.tuple_queries();
    let tuple_keys = execute_tuple_queries(&mut conn, tuple_queries);

    let openfga = support::containers::start_openfga().await;

    let grpc_port = openfga.get_host_port_ipv4(8081).await.unwrap();
    let mut service_client = support::openfga::connect(grpc_port).await;
    let store_id = support::openfga::create_store(&mut service_client, "upsert-parity").await;
    let model_id =
        support::openfga::write_authorization_model(&mut service_client, &store_id, &model).await;

    let writes: Vec<openfga_client::client::TupleKey> = tuple_keys
        .iter()
        .map(|tuple| support::openfga::make_tuple(&tuple.object, &tuple.relation, &tuple.subject))
        .collect();
    let client = service_client.into_client(&store_id, &model_id);
    support::openfga::write_tuples(&client, writes).await;

    let mut failures = Vec::new();
    let mut separated = 0;
    for user_id in [USER_ALICE, USER_BOB] {
        for note in SEEDED_UPSERT_NOTES {
            let user = format!("user:{user_id}");
            let object = format!("notes:{}", note.0);

            let plain = postgres_allows_upsert(&mut conn, user_id, note, false);
            let upsert = postgres_allows_upsert(&mut conn, user_id, note, true);
            if plain && !upsert {
                separated += 1;
            }

            for (relation, expected) in [("can_insert", plain), ("can_upsert", upsert)] {
                let actual =
                    support::openfga::check_allowed(&client, &user, relation, &object).await;
                if expected != actual {
                    failures.push(format!(
                        "{user} {relation} {object}: postgres={expected}, openfga={actual}"
                    ));
                }
            }
        }
    }

    assert!(
        separated > 0,
        "no row separates a plain insert from an upsert, so the comparison proves nothing"
    );
    assert!(
        failures.is_empty(),
        "PostgreSQL/OpenFGA upsert parity mismatches:\n{}",
        failures.join("\n")
    );
}

diesel::table! {
    #[sql_name = "notes"]
    notes_folded (id) {
        id -> diesel::sql_types::Text,
        owner_id -> diesel::sql_types::Text,
    }
}

diesel::table! {
    note_members (id) {
        id -> diesel::sql_types::Text,
        note_id -> diesel::sql_types::Text,
        user_id -> diesel::sql_types::Text,
    }
}

diesel::table! {
    #[sql_name = "notes"]
    notes_owned (id) {
        id -> diesel::sql_types::Text,
        owner_id -> diesel::sql_types::Text,
    }
}

/// One row of a conditional tuple query, which yields five columns rather than three.
#[derive(QueryableByName)]
struct ConditionalTupleRow {
    #[diesel(sql_type = Text)]
    object: String,
    #[diesel(sql_type = Text)]
    relation: String,
    #[diesel(sql_type = Text)]
    subject: String,
    #[diesel(sql_type = Text)]
    condition: String,
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    context: serde_json::Value,
}

/// Run a conditional tuple query. The generated SQL is text the crate produced, so it
/// cannot go through the typed DSL, and the row type binds each column's SQL type.
fn execute_conditional_tuple_query(
    conn: &mut PgConnection,
    query: &TupleQuery,
) -> Vec<ConditionalTupleRow> {
    diesel::sql_query(&query.sql)
        .load(conn)
        .unwrap_or_else(|error| {
            panic!(
                "Conditional tuple SQL failed in PostgreSQL 18: {}\n{}\nError: {error}",
                query.comment, query.sql
            )
        })
}

#[derive(QueryableByName)]
struct InstantRow {
    #[diesel(sql_type = Text)]
    instant: String,
}

/// The moment `PostgreSQL` is at, formatted the way a condition parameter expects.
fn postgres_now(conn: &mut PgConnection) -> String {
    let rows: Vec<InstantRow> =
        diesel::sql_query("SELECT to_char(now(), 'YYYY-MM-DD\"T\"HH24:MI:SSOF:00') AS instant")
            .load(conn)
            .expect("reading now() should succeed");
    rows.into_iter()
        .next()
        .expect("now() returns a row")
        .instant
}

// ── Phase 3: a value the request carries, against both real services ──────────

#[derive(QueryableByName)]
struct IdRow {
    #[diesel(sql_type = Integer)]
    id: i32,
}

/// What the caller sends for a `list<string>` parameter, per the recorded contract:
/// exactly what `string_to_array(guc, ',')` would produce, and `[]` where the setting is
/// unset. Sending the caller's own subjects instead would grant a comma-bearing subject
/// the database refuses.
fn caller_subject_list(subjects: Option<&str>) -> serde_json::Value {
    match subjects {
        // Unset yields NULL and the empty string yields no elements, and both admit
        // nothing, which an empty list reproduces exactly.
        None | Some("") => serde_json::json!([]),
        Some(text) => serde_json::Value::Array(
            text.split(',')
                .map(|part| serde_json::Value::String(part.to_string()))
                .collect(),
        ),
    }
}

/// The connetto papers, one per way in: owned, shared, and neither.
const SEEDED_PAPERS: [(i32, &str); 3] = [(1, "alice"), (2, "bob"), (3, "bob")];

/// Paper 2 is shared with a key `alice` carries, paper 3 with one she does not.
const SEEDED_SHARES: [(i32, &str); 2] = [(2, "team-a"), (3, "team-z")];

/// Caller states, as `(app.user_id, app.subjects)`.
const PAPER_CALLERS: [(Option<&str>, Option<&str>); 5] = [
    (None, None),
    (Some("alice"), None),
    (None, Some("team-a")),
    (Some("alice"), Some("team-a")),
    (Some("alice"), Some("")),
];

/// Papers a `LOGIN` role reads under one caller state, which is the oracle.
fn papers_visible_to(
    conn: &mut PgConnection,
    user_id: Option<&str>,
    subjects: Option<&str>,
) -> BTreeSet<i32> {
    let mut seen = BTreeSet::new();
    conn.transaction::<_, diesel::result::Error, _>(|conn| {
        conn.batch_execute("SET LOCAL ROLE app_reader")?;
        diesel::sql_query("SELECT set_config('app.user_id', $1, true)")
            .bind::<diesel::sql_types::Nullable<Text>, _>(user_id)
            .execute(conn)?;
        diesel::sql_query("SELECT set_config('app.subjects', $1, true)")
            .bind::<diesel::sql_types::Nullable<Text>, _>(subjects)
            .execute(conn)?;
        let rows: Vec<IdRow> = diesel::sql_query("SELECT id FROM papers ORDER BY id").load(conn)?;
        seen = rows.into_iter().map(|row| row.id).collect();
        Err::<(), _>(diesel::result::Error::RollbackTransaction)
    })
    .ok();
    seen
}

diesel::table! {
    /// The `token_claim_set` fixture's guarded table.
    ///
    /// Typed rather than spelled as SQL text so the seed and the read are checked
    /// against one schema, which is what stops the oracle and the fixture drifting.
    #[sql_name = "documents"]
    claim_documents (id) {
        id -> Integer,
        team_id -> Nullable<Text>,
    }
}

// ── The replay of one changed row, against both real services ─────────────────

mod clock_gate_schema {
    diesel::table! {
        readings (tenant_id, reading_id) {
            tenant_id -> diesel::sql_types::Integer,
            reading_id -> diesel::sql_types::Integer,
        }
    }
}

/// Keys of the readings the plain login role reads, rendered as the objects name them.
fn postgres_readable_readings(conn: &mut PgConnection) -> BTreeSet<String> {
    use clock_gate_schema::readings;

    conn.transaction::<BTreeSet<String>, diesel::result::Error, _>(|conn| {
        // Role switching has no query DSL form.
        diesel::sql_query("SET LOCAL ROLE app_user").execute(conn)?;
        let keys: Vec<(i32, i32)> = readings::table
            .select((readings::tenant_id, readings::reading_id))
            .load(conn)?;
        Ok(keys
            .into_iter()
            .map(|(tenant, reading)| format!("{tenant}|{reading}"))
            .collect())
    })
    .expect("reading the guarded table should succeed")
}

/// One row read back whole as JSON, the shape the record evaluator reads.
#[derive(QueryableByName)]
struct JsonRow {
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    row: serde_json::Value,
}

/// Whole rows of one table as JSON. Raw SQL because the schema is a per-test
/// string, so no `table!` exists to type the read against.
fn rows_as_json(conn: &mut PgConnection, sql: &str) -> Vec<serde_json::Value> {
    let rows: Vec<JsonRow> = diesel::sql_query(sql).load(conn).unwrap_or_else(|error| {
        panic!("the row read failed in PostgreSQL 18:\n{sql}\nError: {error}")
    });
    rows.into_iter().map(|json| json.row).collect()
}

/// A clock guard is settled at check time, and which record exists is settled by the
/// row alone, so a consumer watching the change stream answers a change by evaluating
/// the description against the row it arrived on. Here that evaluation is the only
/// loader: nothing runs the whole-table query, so a description disagreeing with its
/// own SQL about the condition or the context writes a wrong tuple and fails.
///
/// Two-sided by construction: each tenant holds a reading its guard admits and one it
/// refuses, so a model granting everything or denying everything fails. Each record is
/// also required to name the row it came from, whole compound key and all.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn clock_gated_from_row_parity_postgres18_and_openfga() {
    let postgres = support::containers::start_postgres().await;

    let pg_port = postgres.get_host_port_ipv4(5432).await.unwrap();
    let pg_url = format!("postgres://{PG_USER}:{PG_PASSWORD}@127.0.0.1:{pg_port}/{PG_DB}");
    let mut conn = support::containers::connect_postgres_with_retry(&pg_url);

    let schema_sql = "
CREATE TABLE readings (
    tenant_id INT,
    reading_id INT,
    starts_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, reading_id)
);
ALTER TABLE readings ENABLE ROW LEVEL SECURITY;
CREATE POLICY readings_visible ON readings FOR SELECT TO PUBLIC USING (starts_at <= now());
";
    let (classified, db, registry) = support::classify_sql(schema_sql, None);
    conn.batch_execute(schema_sql)
        .expect("Failed to apply the clock-gate schema on PostgreSQL 18");
    conn.batch_execute("CREATE ROLE app_user LOGIN; GRANT SELECT ON readings TO app_user;")
        .expect("Failed to create the querying role");
    // One row each side of now() per tenant, so each tenant's guard admits one and refuses
    // one, and a replay keyed on the tenant alone would answer for both.
    conn.batch_execute(
        "INSERT INTO readings (tenant_id, reading_id, starts_at) VALUES
            (7, 9, now() - interval '1 day'),
            (7, 10, now() + interval '1 day'),
            (8, 9, now() - interval '1 day'),
            (8, 10, now() + interval '1 day');",
    )
    .expect("Failed to seed the guarded rows");

    let outputs = Translation::plan(
        classified,
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .expect("translation should plan")
    .outputs_accepting_gaps();
    let model = outputs.json_model();
    let tuple_queries = outputs.tuple_queries();

    let descriptions: Vec<&RecordDescription> = tuple_queries
        .iter()
        .filter_map(|query| query.description.as_ref())
        .collect();
    let [description] = descriptions.as_slice() else {
        panic!("one gate, one description, got {descriptions:?}");
    };
    assert!(
        matches!(description.derivation, RecordDerivation::FromRow { .. }),
        "the row decides which record exists: {description:?}"
    );

    let openfga = support::containers::start_openfga().await;

    let grpc_port = openfga.get_host_port_ipv4(8081).await.unwrap();
    let mut service_client = support::openfga::connect(grpc_port).await;
    let store_id = support::openfga::create_store(&mut service_client, "clock-replay-parity").await;
    let model_id =
        support::openfga::write_authorization_model(&mut service_client, &store_id, &model).await;

    let seeded = [("7", "9"), ("7", "10"), ("8", "9"), ("8", "10")];
    let mut writes = Vec::new();
    for (tenant, reading) in seeded {
        let rows = rows_as_json(
            &mut conn,
            &format!(
                "SELECT to_jsonb(r) AS row FROM readings r \
                 WHERE tenant_id = {tenant} AND reading_id = {reading}"
            ),
        );
        let [row] = rows.as_slice() else {
            panic!("one seeded row for {tenant},{reading}, got {}", rows.len());
        };
        let records = records_from_row(description, &support::JsonRowValues(row))
            .expect("the seeded row evaluates");
        // The record answers for the row it was read from and no other, which is
        // what a prefix of the compound key could not say.
        let [record] = records.as_slice() else {
            panic!("the row states one record, got {records:?}");
        };
        assert_eq!(
            record.object,
            format!("readings:{tenant}|{reading}"),
            "the record names the row it came from"
        );
        let context = record
            .context
            .as_ref()
            .expect("a clock-gated record carries its context");
        let mut context_map = serde_json::Map::new();
        for (key, value) in &context.values {
            context_map.insert(key.clone(), serde_json::Value::String(value.clone()));
        }
        writes.push(support::openfga::make_conditional_tuple(
            &record.object,
            record.relation.as_str(),
            &record.subject,
            &context.condition,
            serde_json::Value::Object(context_map),
        ));
    }
    let client = service_client.into_client(&store_id, &model_id);
    support::openfga::write_tuples(&client, writes).await;

    let context = serde_json::json!({ "request_time": postgres_now(&mut conn) });
    let readable = postgres_readable_readings(&mut conn);
    assert_eq!(
        readable.len(),
        2,
        "one reading per tenant has started, PostgreSQL showed {readable:?}"
    );

    let mut failures = Vec::new();
    let (mut granted, mut denied) = (0usize, 0usize);
    for (tenant, reading) in seeded {
        let key = format!("{tenant}|{reading}");
        let expected = readable.contains(&key);
        if expected {
            granted += 1;
        } else {
            denied += 1;
        }
        let actual = support::openfga::check_allowed_with_context(
            &client,
            "user:anyone",
            "can_select",
            &format!("readings:{key}"),
            context.clone(),
        )
        .await;
        if expected != actual {
            failures.push(format!(
                "readings:{key}: postgres={expected}, openfga={actual}"
            ));
        }
    }

    assert!(granted == 2 && denied == 2, "the case needs both answers");
    assert!(
        failures.is_empty(),
        "PostgreSQL/OpenFGA clock-gated replay parity mismatches:\n{}",
        failures.join("\n")
    );
}

/// The share arm settles from the share row, so a consumer watching the change stream
/// answers a changed share by evaluating the description against that row alone.
///
/// `shared_paper_parity_postgres18_and_openfga` covers the same fixture through the
/// whole-table load, and `clock_gated_from_row_parity_postgres18_and_openfga` covers a
/// record keyed on the guarded table's own key. This is the remaining corner: a record
/// keyed on a foreign column, so one membership row states a record about another
/// type's object. Here the evaluation is the only loader of the share arm: nothing
/// runs its whole-table query, so a description disagreeing with its own SQL about
/// the object, the condition, or the context fails.
///
/// Two-sided by construction: the caller states include one holding the shared key and one
/// without it, and the owner arm is loaded too, so a model keeping one arm or granting
/// everything cannot pass.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn shared_paper_from_row_parity_postgres18_and_openfga() {
    let postgres = support::containers::start_postgres().await;

    let pg_port = postgres.get_host_port_ipv4(5432).await.unwrap();
    let pg_url = format!("postgres://{PG_USER}:{PG_PASSWORD}@127.0.0.1:{pg_port}/{PG_DB}");
    let mut conn = support::containers::connect_postgres_with_retry(&pg_url);

    conn.batch_execute(&support::read_fixture_sql("connetto_capability"))
        .expect("Failed to apply the connetto capability schema on PostgreSQL 18");
    conn.batch_execute(
        "CREATE ROLE app_reader LOGIN; \
         GRANT SELECT ON papers TO app_reader; \
         GRANT SELECT ON paper_shares TO app_reader;",
    )
    .expect("Failed to create the querying role");
    let papers: Vec<String> = SEEDED_PAPERS
        .iter()
        .map(|(id, owner)| format!("({id}, '{owner}')"))
        .collect();
    let shares: Vec<String> = SEEDED_SHARES
        .iter()
        .map(|(paper, viewer)| format!("({paper}, '{viewer}')"))
        .collect();
    conn.batch_execute(&format!(
        "INSERT INTO papers (id, owner) VALUES {}; \
         INSERT INTO paper_shares (paper_id, viewer) VALUES {};",
        papers.join(", "),
        shares.join(", ")
    ))
    .expect("Failed to seed the papers and shares");

    let (classified, db, registry) = support::try_load_fixture_classified("connetto_capability");
    let planned = || {
        Translation::plan(
            classified.clone(),
            &db,
            &registry,
            ConfidenceLevel::B,
            &GeneratorSettings::default(),
        )
        .expect("translation should plan")
        .outputs_accepting_gaps()
    };
    let model = planned().json_model();
    let outputs = planned();
    let tuple_queries = outputs.tuple_queries();

    // Two conditional shapes read `paper_shares`: the papers share arm and the
    // sharing table's own read gate. The arm under test is the one whose records
    // move another type's objects.
    let share_arm = tuple_queries
        .iter()
        .find(|query| {
            query.condition.is_some()
                && query.description.as_ref().is_some_and(|description| {
                    match &description.derivation {
                        RecordDerivation::FromRow {
                            table, template, ..
                        } => {
                            table.to_string() == "paper_shares"
                                && template.object_type == "paper_shares_share"
                        }
                        _ => false,
                    }
                })
        })
        .expect("the share arm settles from the share row and its rows carry a condition");
    let description = share_arm
        .description
        .as_ref()
        .expect("the query carries a description");

    let openfga = support::containers::start_openfga().await;

    let grpc_port = openfga.get_host_port_ipv4(8081).await.unwrap();
    let mut service_client = support::openfga::connect(grpc_port).await;
    let store_id = support::openfga::create_store(&mut service_client, "shared-paper-replay").await;
    let model_id =
        support::openfga::write_authorization_model(&mut service_client, &store_id, &model).await;

    // The share arm comes only from evaluating each share row. Every other query
    // loads whole, so the owner arm and the sharing table's own rows still answer.
    let mut writes: Vec<openfga_client::client::TupleKey> = Vec::new();
    for (paper, viewer) in SEEDED_SHARES {
        let rows = rows_as_json(
            &mut conn,
            &format!(
                "SELECT to_jsonb(s) AS row FROM paper_shares s \
                 WHERE paper_id = {paper} AND viewer = '{viewer}'"
            ),
        );
        let [row] = rows.as_slice() else {
            panic!("one seeded share for paper {paper}, got {}", rows.len());
        };
        let records = records_from_row(description, &support::JsonRowValues(row))
            .expect("the share row evaluates");
        let [record] = records.as_slice() else {
            panic!("the share row states one record, got {records:?}");
        };
        assert_eq!(
            record.object,
            format!("paper_shares_share:{paper}|{viewer}"),
            "the record names the share row the paper reaches its grant through"
        );
        let context = record
            .context
            .as_ref()
            .expect("the share record carries the viewer it admits");
        assert!(
            context.values.values().any(|value| *value == viewer),
            "the record carries the row's own viewer"
        );
        let mut context_map = serde_json::Map::new();
        for (key, value) in &context.values {
            context_map.insert(key.clone(), serde_json::Value::String(value.clone()));
        }
        writes.push(support::openfga::make_conditional_tuple(
            &record.object,
            record.relation.as_str(),
            &record.subject,
            &context.condition,
            serde_json::Value::Object(context_map),
        ));
    }
    for query in tuple_queries {
        if query.skipped.is_some() || core::ptr::eq(query, share_arm) {
            continue;
        }
        if query.condition.is_some() {
            writes.extend(
                execute_conditional_tuple_query(&mut conn, query)
                    .iter()
                    .map(|row| {
                        support::openfga::make_conditional_tuple(
                            &row.object,
                            &row.relation,
                            &row.subject,
                            &row.condition,
                            row.context.clone(),
                        )
                    }),
            );
            continue;
        }
        writes.extend(
            execute_tuple_queries(&mut conn, core::slice::from_ref(query))
                .iter()
                .map(|key| support::openfga::make_tuple(&key.object, &key.relation, &key.subject)),
        );
    }
    let client = service_client.into_client(&store_id, &model_id);
    support::openfga::write_tuples(&client, writes).await;

    let mut failures = Vec::new();
    let mut share_only = 0usize;
    let mut denied = 0usize;
    for (user_id, subjects) in PAPER_CALLERS {
        let visible = papers_visible_to(&mut conn, user_id, subjects);
        let owner_arm = papers_visible_to(&mut conn, user_id, None);
        share_only += visible.difference(&owner_arm).count();

        let caller = user_id.unwrap_or("nobody");
        for (id, _) in SEEDED_PAPERS {
            let expected = visible.contains(&id);
            if !expected {
                denied += 1;
            }
            let actual = support::openfga::check_allowed_with_context(
                &client,
                &format!("user:{caller}"),
                "can_select",
                &format!("papers:{id}"),
                serde_json::json!({ "app_subjects": caller_subject_list(subjects) }),
            )
            .await;
            if expected != actual {
                failures.push(format!(
                    "papers:{id} for user_id={user_id:?} subjects={subjects:?}: \
                     postgres={expected}, openfga={actual}"
                ));
            }
        }
    }

    assert!(
        share_only > 0,
        "no paper is readable by a shared key alone, so the replayed arm carried nothing"
    );
    assert!(
        denied > 0,
        "no paper is denied anywhere, so granting everything would pass"
    );
    assert!(
        failures.is_empty(),
        "PostgreSQL/OpenFGA shared-paper from-row parity mismatches:\n{}",
        failures.join("\n")
    );
}

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

/// Whether `login_role`, acting as `user_id`, can read the `docs` row `doc_id`.
fn postgres_allows_select(
    conn: &mut PgConnection,
    user_id: &str,
    login_role: &str,
    doc_id: &str,
) -> bool {
    conn.transaction::<bool, diesel::result::Error, _>(|conn| {
        // Session settings and role switching have no query DSL form.
        diesel::sql_query(format!("SET LOCAL ROLE {login_role}")).execute(conn)?;
        diesel::sql_query("SELECT set_config('app.current_user_id', $1, true)")
            .bind::<Text, _>(user_id)
            .execute(conn)?;

        let visible: i64 = docs::table
            .filter(docs::id.eq(doc_id))
            .count()
            .get_result(conn)?;
        Ok(visible == 1)
    })
    .expect("reading docs under row level security should not error")
}

/// One reader for the definer fixture: `(app user id, login role, has any grant
/// on doc_members)`. The third reader is probe A's point: no grant on the
/// membership table at all, and the definer still answers their docs.
const DEFINER_READERS: [(&str, &str, bool); 3] = [
    (USER_ALICE, "app_alice", true),
    (USER_BOB, "app_bob", true),
    (USER_CAROL, "app_carol", false),
];

/// One seeded `doc_members` row: `(id, doc_id, user_id)`.
const DEFINER_DOC_MEMBERS: [(&str, &str, &str); 3] = [
    ("dm-alice", DOC_1, USER_ALICE),
    ("dm-bob", DOC_1, USER_BOB),
    ("dm-carol", DOC_2, USER_CAROL),
];

/// Whether `login_role`, acting as `user_id`, can read the `doc_members` row.
fn postgres_allows_member_select(
    conn: &mut PgConnection,
    user_id: &str,
    login_role: &str,
    member_row_id: &str,
) -> bool {
    conn.transaction::<bool, diesel::result::Error, _>(|conn| {
        // Session settings and role switching have no query DSL form.
        diesel::sql_query(format!("SET LOCAL ROLE {login_role}")).execute(conn)?;
        diesel::sql_query("SELECT set_config('app.current_user_id', $1, true)")
            .bind::<Text, _>(user_id)
            .execute(conn)?;

        let visible: i64 = doc_members::table
            .filter(doc_members::id.eq(member_row_id))
            .count()
            .get_result(conn)?;
        Ok(visible == 1)
    })
    .expect("reading doc_members under row level security should not error")
}

/// Probe A end to end: a `SECURITY DEFINER` wrapper around the membership
/// EXISTS, called by `docs` and by `doc_members`' own self-referential policy.
/// The pre-expansion tree translated this fixture as all-deny.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn definer_membership_parity_postgres18_and_openfga() {
    let postgres = support::containers::start_postgres().await;

    let pg_port = postgres.get_host_port_ipv4(5432).await.unwrap();
    let pg_url = format!("postgres://{PG_USER}:{PG_PASSWORD}@127.0.0.1:{pg_port}/{PG_DB}");
    let mut conn = support::containers::connect_postgres_with_retry(&pg_url);

    let schema_sql = support::read_fixture_sql("definer_membership");
    let (classified, db, registry) = support::load_fixture_classified("definer_membership");
    conn.batch_execute(&schema_sql)
        .expect("Failed to apply the definer_membership schema on PostgreSQL 18");

    diesel::insert_into(users::table)
        .values(
            DEFINER_READERS
                .map(|(user_id, _, _)| users::id.eq(user_id))
                .to_vec(),
        )
        .execute(&mut conn)
        .expect("Failed to seed users");
    diesel::insert_into(docs::table)
        .values([DOC_1, DOC_2].map(|id| docs::id.eq(id)).to_vec())
        .execute(&mut conn)
        .expect("Failed to seed docs");
    diesel::insert_into(doc_members::table)
        .values(
            DEFINER_DOC_MEMBERS
                .map(|(id, doc_id, user_id)| {
                    (
                        doc_members::id.eq(id),
                        doc_members::doc_id.eq(doc_id),
                        doc_members::user_id.eq(user_id),
                    )
                })
                .to_vec(),
        )
        .execute(&mut conn)
        .expect("Failed to seed doc_members");

    for (_, login_role, member_grant) in DEFINER_READERS {
        let member_grant = if member_grant {
            format!("GRANT SELECT ON doc_members TO {login_role};")
        } else {
            String::new()
        };
        conn.batch_execute(&format!(
            "CREATE ROLE {login_role} LOGIN; \
             GRANT SELECT ON docs TO {login_role}; \
             {member_grant}"
        ))
        .expect("Failed to create a querying role");
    }

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
        support::openfga::create_store(&mut service_client, "definer-membership-parity").await;
    let model_id =
        support::openfga::write_authorization_model(&mut service_client, &store_id, &model).await;

    let writes: Vec<openfga_client::client::TupleKey> = tuple_keys
        .iter()
        .map(|tuple| support::openfga::make_tuple(&tuple.object, &tuple.relation, &tuple.subject))
        .collect();
    let client = service_client.into_client(&store_id, &model_id);
    support::openfga::write_tuples(&client, writes).await;

    let mut failures = Vec::new();
    for (user_id, login_role, member_grant) in DEFINER_READERS {
        for doc_id in [DOC_1, DOC_2] {
            let expected = postgres_allows_select(&mut conn, user_id, login_role, doc_id);
            let user = format!("user:{user_id}");
            let object = format!("docs:{doc_id}");
            let actual =
                support::openfga::check_allowed(&client, &user, "can_select", &object).await;
            if expected != actual {
                failures.push(format!(
                    "{user} as {login_role} can_select {object}: postgres={expected}, openfga={actual}"
                ));
            }
        }
        // A reader with no privilege on the table cannot ask PostgreSQL at all,
        // so only granted readers compare the membership rows.
        if !member_grant {
            continue;
        }
        for (member_row_id, _, _) in DEFINER_DOC_MEMBERS {
            let expected =
                postgres_allows_member_select(&mut conn, user_id, login_role, member_row_id);
            let user = format!("user:{user_id}");
            let object = format!("doc_members:{member_row_id}");
            let actual =
                support::openfga::check_allowed(&client, &user, "can_select", &object).await;
            if expected != actual {
                failures.push(format!(
                    "{user} as {login_role} can_select {object}: postgres={expected}, openfga={actual}"
                ));
            }
        }
    }

    let granted =
        failures.is_empty() && postgres_allows_select(&mut conn, USER_CAROL, "app_carol", DOC_2);
    assert!(
        granted,
        "PostgreSQL/OpenFGA definer membership parity mismatches (an empty list means \
         the case went vacuous: carol must reach her doc through the definer):\n{}",
        failures.join("\n")
    );
}

/// One reviewer relationship: `(note id, owner, reviewer)`. The last row is owned by
/// the reader outside `contractor`, whom the barrier must not touch.
const SEEDED_REVIEWED_NOTES: [(&str, &str, &str); 3] = [
    ("note-reviewed", USER_ALICE, USER_ALICE),
    ("note-unreviewed", USER_ALICE, USER_BOB),
    ("note-outside-the-role", USER_BOB, USER_ALICE),
];

/// One reader: `(app user id, login role, member of contractor)`.
const RESTRICTED_READERS: [(&str, &str, bool); 2] = [
    (USER_ALICE, "app_alice", true),
    (USER_BOB, "app_bob", false),
];

diesel::table! {
    #[sql_name = "notes"]
    notes_reviewed (id) {
        id -> diesel::sql_types::Text,
        owner_id -> diesel::sql_types::Text,
        reviewer_id -> diesel::sql_types::Text,
    }
}

/// Whether `login_role`, acting as `user_id`, can read the `notes` row `note_id`.
fn postgres_allows_reviewed_select(
    conn: &mut PgConnection,
    user_id: &str,
    login_role: &str,
    note_id: &str,
) -> bool {
    conn.transaction::<bool, diesel::result::Error, _>(|conn| {
        // Session settings and role switching have no query DSL form.
        diesel::sql_query(format!("SET LOCAL ROLE {login_role}")).execute(conn)?;
        diesel::sql_query("SELECT set_config('app.current_user_id', $1, true)")
            .bind::<Text, _>(user_id)
            .execute(conn)?;

        let visible: i64 = notes_reviewed::table
            .filter(notes_reviewed::id.eq(note_id))
            .count()
            .get_result(conn)?;
        Ok(visible == 1)
    })
    .expect("reading notes under row level security should not error")
}

/// A RESTRICTIVE policy scoped to a role binds that role alone, which the model can
/// only express by subtracting the role from the grant.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn role_scoped_restrictive_parity_postgres18_and_openfga() {
    let postgres = support::containers::start_postgres().await;

    let pg_port = postgres.get_host_port_ipv4(5432).await.unwrap();
    let pg_url = format!("postgres://{PG_USER}:{PG_PASSWORD}@127.0.0.1:{pg_port}/{PG_DB}");
    let mut conn = support::containers::connect_postgres_with_retry(&pg_url);

    let schema_sql = support::read_fixture_sql("role_scoped_restrictive");
    let (classified, db, registry) = support::load_fixture_classified("role_scoped_restrictive");
    // The policy names the role, so it has to exist before the schema is applied.
    conn.batch_execute("CREATE ROLE contractor")
        .expect("Failed to create the scoped role");
    conn.batch_execute(&schema_sql)
        .expect("Failed to apply the role_scoped_restrictive schema on PostgreSQL 18");

    diesel::insert_into(users::table)
        .values(
            RESTRICTED_READERS
                .map(|(user_id, _, _)| users::id.eq(user_id))
                .to_vec(),
        )
        .execute(&mut conn)
        .expect("Failed to seed users");
    let rows: Vec<_> = SEEDED_REVIEWED_NOTES
        .iter()
        .map(|(id, owner, reviewer)| {
            (
                notes_reviewed::id.eq(*id),
                notes_reviewed::owner_id.eq(*owner),
                notes_reviewed::reviewer_id.eq(*reviewer),
            )
        })
        .collect();
    diesel::insert_into(notes_reviewed::table)
        .values(rows)
        .execute(&mut conn)
        .expect("Failed to seed notes");

    for (_, login_role, in_contractor) in RESTRICTED_READERS {
        let grant_contractor = if in_contractor {
            format!("GRANT contractor TO {login_role};")
        } else {
            String::new()
        };
        conn.batch_execute(&format!(
            "CREATE ROLE {login_role} LOGIN; \
             GRANT SELECT ON notes TO {login_role}; \
             {grant_contractor}"
        ))
        .expect("Failed to create a querying role");
    }

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
        support::openfga::create_store(&mut service_client, "role-scoped-restrictive-parity").await;
    let model_id =
        support::openfga::write_authorization_model(&mut service_client, &store_id, &model).await;

    let mut writes: Vec<openfga_client::client::TupleKey> = tuple_keys
        .iter()
        .map(|tuple| support::openfga::make_tuple(&tuple.object, &tuple.relation, &tuple.subject))
        .collect();
    for (user_id, _, in_contractor) in RESTRICTED_READERS {
        if in_contractor {
            writes.push(support::openfga::make_tuple(
                "pg_role:contractor",
                "usage",
                &format!("user:{user_id}"),
            ));
        }
    }
    let client = service_client.into_client(&store_id, &model_id);
    support::openfga::write_tuples(&client, writes).await;

    let mut failures = Vec::new();
    for (user_id, login_role, _) in RESTRICTED_READERS {
        for (note_id, _, _) in SEEDED_REVIEWED_NOTES {
            let expected = postgres_allows_reviewed_select(&mut conn, user_id, login_role, note_id);
            let user = format!("user:{user_id}");
            let object = format!("notes:{note_id}");
            let actual =
                support::openfga::check_allowed(&client, &user, "can_select", &object).await;
            if expected != actual {
                failures.push(format!(
                    "{user} as {login_role} can_select {object}: postgres={expected}, openfga={actual}"
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "PostgreSQL/OpenFGA role scoped restrictive parity mismatches:\n{}",
        failures.join("\n")
    );
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

/// A year on from that moment.
fn postgres_a_year_on(conn: &mut PgConnection) -> String {
    let rows: Vec<InstantRow> = diesel::sql_query(
        "SELECT to_char(now() + interval '1 year', 'YYYY-MM-DD\"T\"HH24:MI:SSOF:00') AS instant",
    )
    .load(conn)
    .expect("reading a future instant should succeed");
    rows.into_iter()
        .next()
        .expect("the expression returns a row")
        .instant
}

/// Typed schema for the shared-policy-name case. The timestamps are written by SQL,
/// since this build carries no Rust type for `TIMESTAMPTZ`.
mod shared_name_schema {
    diesel::table! {
        campaigns (id) {
            id -> diesel::sql_types::Text,
        }
    }

    diesel::table! {
        embargoes (id) {
            id -> diesel::sql_types::Text,
        }
    }

    diesel::allow_tables_to_appear_in_same_query!(campaigns, embargoes);
}

/// Ids of one table the plain login role reads.
fn postgres_readable_ids(conn: &mut PgConnection, table: &str) -> BTreeSet<String> {
    use shared_name_schema::{campaigns, embargoes};

    conn.transaction::<BTreeSet<String>, diesel::result::Error, _>(|conn| {
        // Role switching has no query DSL form.
        diesel::sql_query("SET LOCAL ROLE app_user").execute(conn)?;
        let ids: Vec<String> = if table == "campaigns" {
            campaigns::table.select(campaigns::id).load(conn)?
        } else {
            embargoes::table.select(embargoes::id).load(conn)?
        };
        Ok(ids.into_iter().collect())
    })
    .expect("reading the guarded table should succeed")
}

/// `PostgreSQL` policy names are unique per table and `OpenFGA` condition names are global
/// to the model, so one name on two tables has to reach two conditions.
///
/// Both guards here read a column of the same name and compare it opposite ways, which is
/// the **silent** form of the defect: every tuple carries the context key the shared
/// condition declares, so the load succeeds and one table simply answers with the other's
/// rule. The louder form, two tables whose columns are named differently, is refused by
/// the service on the tuple write and is covered by the `shared_policy_name` fixture and
/// `every_condition_parameter_is_supplied_by_its_own_tuples`.
///
/// Two-sided by construction: each table has a row its own guard admits and a row it
/// refuses, so a model that grants everything, denies everything, or answers one table
/// with the other's rule fails.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn shared_policy_name_condition_parity_postgres18_and_openfga() {
    let postgres = support::containers::start_postgres().await;

    let pg_port = postgres.get_host_port_ipv4(5432).await.unwrap();
    let pg_url = format!("postgres://{PG_USER}:{PG_PASSWORD}@127.0.0.1:{pg_port}/{PG_DB}");
    let mut conn = support::containers::connect_postgres_with_retry(&pg_url);

    let schema_sql = "
CREATE TABLE campaigns (id TEXT PRIMARY KEY, at TIMESTAMPTZ NOT NULL);
CREATE TABLE embargoes (id TEXT PRIMARY KEY, at TIMESTAMPTZ NOT NULL);
ALTER TABLE campaigns ENABLE ROW LEVEL SECURITY;
ALTER TABLE embargoes ENABLE ROW LEVEL SECURITY;
CREATE POLICY visible_now ON campaigns FOR SELECT TO PUBLIC USING (at <= now());
CREATE POLICY visible_now ON embargoes FOR SELECT TO PUBLIC USING (at > now());
";
    let (classified, db, registry) = support::classify_sql(schema_sql, None);
    conn.batch_execute(schema_sql)
        .expect("Failed to apply the shared-name schema on PostgreSQL 18");
    conn.batch_execute(
        "CREATE ROLE app_user LOGIN; GRANT SELECT ON campaigns, embargoes TO app_user;",
    )
    .expect("Failed to create the querying role");
    // One row each side of now() per table, so each guard admits one and refuses one.
    conn.batch_execute(
        "INSERT INTO campaigns (id, at) VALUES
            ('c-running', now() - interval '1 day'),
            ('c-upcoming', now() + interval '1 day');
         INSERT INTO embargoes (id, at) VALUES
            ('e-held', now() + interval '1 day'),
            ('e-lifted', now() - interval '1 day');",
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

    let conditional: Vec<&TupleQuery> = tuple_queries
        .iter()
        .filter(|query| query.condition.is_some())
        .collect();
    assert_eq!(
        conditional.len(),
        2,
        "each table carries its own conditional query, got {} of {}",
        conditional.len(),
        tuple_queries.len()
    );

    let openfga = support::containers::start_openfga().await;

    let grpc_port = openfga.get_host_port_ipv4(8081).await.unwrap();
    let mut service_client = support::openfga::connect(grpc_port).await;
    let store_id = support::openfga::create_store(&mut service_client, "shared-name-parity").await;
    // A model naming a condition it does not declare is rejected outright, so this write
    // is itself an assertion about the two specs.
    let model_id =
        support::openfga::write_authorization_model(&mut service_client, &store_id, &model).await;

    let mut writes = Vec::new();
    for query in &conditional {
        for row in execute_conditional_tuple_query(&mut conn, query) {
            writes.push(support::openfga::make_conditional_tuple(
                &row.object,
                &row.relation,
                &row.subject,
                &row.condition,
                row.context.clone(),
            ));
        }
    }
    assert_eq!(writes.len(), 4, "every seeded row carries a tuple");
    let client = service_client.into_client(&store_id, &model_id);
    support::openfga::write_tuples(&client, writes).await;

    let now = postgres_now(&mut conn);
    let context = serde_json::json!({ "request_time": now });

    let mut failures = Vec::new();
    let mut granted = 0usize;
    let mut denied = 0usize;
    for (table, ids) in [
        ("campaigns", ["c-running", "c-upcoming"]),
        ("embargoes", ["e-held", "e-lifted"]),
    ] {
        let readable = postgres_readable_ids(&mut conn, table);
        assert_eq!(
            readable.len(),
            1,
            "{table} must admit exactly one of its two rows, got {readable:?}"
        );
        for id in ids {
            let expected = readable.contains(id);
            if expected {
                granted += 1;
            } else {
                denied += 1;
            }
            let actual = support::openfga::check_allowed_with_context(
                &client,
                "user:anyone",
                "can_select",
                &format!("{table}:{id}"),
                context.clone(),
            )
            .await;
            if expected != actual {
                failures.push(format!(
                    "{table}:{id}: postgres={expected}, openfga={actual}"
                ));
            }
        }
    }

    assert!(granted == 2 && denied == 2, "the case needs both answers");
    assert!(
        failures.is_empty(),
        "PostgreSQL/OpenFGA shared-policy-name parity mismatches:\n{}",
        failures.join("\n")
    );
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

/// A paper shared to two viewers must load and union rather than collide. Keying every
/// share tuple on the paper put both viewers on one `(user:*, gate, papers:1)` triple,
/// which `OpenFGA` rejects as a duplicate write. Each share is now its own object, so the
/// load succeeds and either viewer reaches the paper while a third does not. The reported
/// bug's second half: the load itself is the assertion.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn two_viewers_of_one_paper_load_and_union_parity_postgres18_and_openfga() {
    let postgres = support::containers::start_postgres().await;

    let pg_port = postgres.get_host_port_ipv4(5432).await.unwrap();
    let pg_url = format!("postgres://{PG_USER}:{PG_PASSWORD}@127.0.0.1:{pg_port}/{PG_DB}");
    let mut conn = support::containers::connect_postgres_with_retry(&pg_url);

    let schema_sql = "
CREATE TABLE papers (id INT PRIMARY KEY, owner TEXT);
CREATE TABLE paper_shares (paper_id INT, viewer TEXT, PRIMARY KEY (paper_id, viewer));
ALTER TABLE papers ENABLE ROW LEVEL SECURITY;
ALTER TABLE paper_shares ENABLE ROW LEVEL SECURITY;
CREATE POLICY papers_p ON papers FOR SELECT USING (
    EXISTS (
        SELECT 1 FROM paper_shares s
        WHERE s.paper_id = papers.id
          AND s.viewer = ANY(string_to_array(current_setting('app.subjects', true), ','))
    )
);
CREATE POLICY shares_read ON paper_shares FOR SELECT USING (true);
";
    conn.batch_execute(schema_sql)
        .expect("Failed to apply the two-viewer schema");
    conn.batch_execute(
        "CREATE ROLE app_reader LOGIN; GRANT SELECT ON papers TO app_reader; \
         GRANT SELECT ON paper_shares TO app_reader;",
    )
    .expect("Failed to create the querying role");
    // Paper 1 is shared to two viewers, which the paper-keyed shape could not load.
    conn.batch_execute(
        "INSERT INTO papers (id, owner) VALUES (1, 'alice'), (2, 'bob'); \
         INSERT INTO paper_shares (paper_id, viewer) VALUES \
         (1, 'viewer_x'), (1, 'viewer_y'), (2, 'viewer_z');",
    )
    .expect("Failed to seed the papers and shares");

    let (classified, db, registry) = support::classify_sql_with_session_attributes(
        schema_sql,
        r#"[{ "key": "app.subjects", "kind": "set_attribute" }]"#,
    );
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

    let openfga = support::containers::start_openfga().await;

    let grpc_port = openfga.get_host_port_ipv4(8081).await.unwrap();
    let mut service_client = support::openfga::connect(grpc_port).await;
    let store_id = support::openfga::create_store(&mut service_client, "two-viewer-parity").await;
    let model_id =
        support::openfga::write_authorization_model(&mut service_client, &store_id, &model).await;

    // Writing the tuples is itself the assertion: the paper-keyed shape wrote two tuples
    // on the same `(user:*, gate, papers:1)` triple, which OpenFGA refuses as a duplicate.
    let mut writes: Vec<openfga_client::client::TupleKey> = Vec::new();
    for query in tuple_queries {
        if query.skipped.is_some() {
            continue;
        }
        if query.condition.is_some() {
            for row in execute_conditional_tuple_query(&mut conn, query) {
                writes.push(support::openfga::make_conditional_tuple(
                    &row.object,
                    &row.relation,
                    &row.subject,
                    &row.condition,
                    row.context.clone(),
                ));
            }
        } else {
            writes.extend(
                execute_tuple_queries(&mut conn, core::slice::from_ref(query))
                    .iter()
                    .map(|key| {
                        support::openfga::make_tuple(&key.object, &key.relation, &key.subject)
                    }),
            );
        }
    }
    let client = service_client.into_client(&store_id, &model_id);
    support::openfga::write_tuples(&client, writes).await;

    let mut failures = Vec::new();
    for (subject, paper, expected) in [
        ("viewer_x", 1, true),
        ("viewer_y", 1, true),
        ("viewer_z", 1, false),
        ("viewer_x", 2, false),
        ("viewer_z", 2, true),
        ("viewer_w", 1, false),
    ] {
        let pg = papers_visible_to(&mut conn, None, Some(subject)).contains(&paper);
        assert_eq!(
            pg, expected,
            "the oracle disagrees for {subject} on papers:{paper}"
        );
        let actual = support::openfga::check_allowed_with_context(
            &client,
            "user:reader",
            "can_select",
            &format!("papers:{paper}"),
            serde_json::json!({ "app_subjects": caller_subject_list(Some(subject)) }),
        )
        .await;
        if actual != expected {
            failures.push(format!(
                "papers:{paper} for subject {subject}: postgres={expected}, openfga={actual}"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "PostgreSQL/OpenFGA two-viewer union parity mismatches:\n{}",
        failures.join("\n")
    );
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

/// One paper shared to two viewers, one live and one expired. The two shares must load as
/// two objects rather than collide, and each viewer's own expiry has to gate it: the
/// caller holding the live share reaches the paper, the one holding the expired share does
/// not, and a year on neither does. Where issue 1 (per-share objects) and the clock meet.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn two_expiring_viewers_of_one_paper_gate_independently_parity_postgres18_and_openfga() {
    let postgres = support::containers::start_postgres().await;

    let pg_port = postgres.get_host_port_ipv4(5432).await.unwrap();
    let pg_url = format!("postgres://{PG_USER}:{PG_PASSWORD}@127.0.0.1:{pg_port}/{PG_DB}");
    let mut conn = support::containers::connect_postgres_with_retry(&pg_url);

    let schema_sql = r"
CREATE TABLE papers (id INT PRIMARY KEY, owner TEXT);
CREATE TABLE paper_shares (
    paper_id INT,
    viewer TEXT,
    expires_at TIMESTAMPTZ,
    PRIMARY KEY (paper_id, viewer)
);
ALTER TABLE papers ENABLE ROW LEVEL SECURITY;
ALTER TABLE paper_shares ENABLE ROW LEVEL SECURITY;
CREATE POLICY shares_read ON paper_shares FOR SELECT USING (true);
CREATE POLICY papers_p ON papers FOR SELECT USING (
    EXISTS (
        SELECT 1
        FROM paper_shares s
        WHERE s.paper_id = papers.id
          AND s.viewer = ANY(string_to_array(current_setting('app.subjects', true), ','))
          AND s.expires_at > now()
    )
);
";
    let (classified, db, registry) = support::classify_sql_with_session_attributes(
        schema_sql,
        r#"[{ "key": "app.subjects", "kind": "set_attribute" }]"#,
    );
    conn.batch_execute(schema_sql)
        .expect("Failed to apply the two-viewer expiry schema on PostgreSQL 18");
    conn.batch_execute(
        "CREATE ROLE app_reader LOGIN; \
         GRANT SELECT ON papers TO app_reader; \
         GRANT SELECT ON paper_shares TO app_reader;",
    )
    .expect("Failed to create the querying role");
    // Paper 1 is shared to two viewers, one live and one already expired.
    conn.batch_execute(
        "INSERT INTO papers (id, owner) VALUES (1, 'alice'); \
         INSERT INTO paper_shares (paper_id, viewer, expires_at) VALUES \
            (1, 'viewer_live', now() + interval '1 day'), \
            (1, 'viewer_gone', now() - interval '1 day');",
    )
    .expect("Failed to seed the paper and its two shares");

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

    let openfga = support::containers::start_openfga().await;

    let grpc_port = openfga.get_host_port_ipv4(8081).await.unwrap();
    let mut service_client = support::openfga::connect(grpc_port).await;
    let store_id =
        support::openfga::create_store(&mut service_client, "two-expiring-viewers").await;
    let model_id =
        support::openfga::write_authorization_model(&mut service_client, &store_id, &model).await;

    // The load itself asserts the two shares do not collide on one object.
    let mut writes: Vec<openfga_client::client::TupleKey> = Vec::new();
    for query in tuple_queries {
        if query.skipped.is_some() {
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

    let now = postgres_now(&mut conn);
    let later = postgres_a_year_on(&mut conn);
    let mut failures = Vec::new();
    let mut allowed = 0usize;
    let mut denied = 0usize;
    for (subject, instant, label) in [
        ("viewer_live", now.as_str(), "now"),
        ("viewer_gone", now.as_str(), "now"),
        ("viewer_live", later.as_str(), "a year on"),
    ] {
        let expected = if label == "now" {
            papers_visible_to(&mut conn, None, Some(subject)).contains(&1)
        } else {
            // PostgreSQL cannot be asked about the future. A year on every share has expired.
            false
        };
        if expected {
            allowed += 1;
        } else {
            denied += 1;
        }
        let actual = support::openfga::check_allowed_with_context(
            &client,
            "user:reader",
            "can_select",
            "papers:1",
            serde_json::json!({
                "app_subjects": caller_subject_list(Some(subject)),
                "request_time": instant,
            }),
        )
        .await;
        if actual != expected {
            failures.push(format!(
                "papers:1 for subject {subject} at {label}: postgres={expected}, openfga={actual}"
            ));
        }
    }
    assert!(
        allowed > 0 && denied > 0,
        "the case must both grant and deny, or one viewer's expiry proves nothing"
    );
    assert!(
        failures.is_empty(),
        "PostgreSQL/OpenFGA two-expiring-viewer parity mismatches:\n{}",
        failures.join("\n")
    );
}

/// Ids of `table` a login role reads, the oracle for the membership arms whose caller is
/// `current_user`. Raw SQL: the per-test table has no `table!` schema, and the read runs
/// under the caller's own role so the policy sees the right `current_user`.
fn readable_ids_as_role(conn: &mut PgConnection, role: &str, table: &str) -> BTreeSet<i32> {
    let mut seen = BTreeSet::new();
    conn.transaction::<_, diesel::result::Error, _>(|conn| {
        conn.batch_execute(&format!("SET LOCAL ROLE {role}"))?;
        let rows: Vec<IdRow> =
            diesel::sql_query(format!("SELECT id FROM {table} ORDER BY id")).load(conn)?;
        seen = rows.into_iter().map(|row| row.id).collect();
        Err::<(), _>(diesel::result::Error::RollbackTransaction)
    })
    .ok();
    seen
}

/// Load every generated tuple query into `OpenFGA`, conditional and plain alike, exactly
/// as the loader would.
fn all_tuple_writes(
    conn: &mut PgConnection,
    tuple_queries: &[TupleQuery],
) -> Vec<openfga_client::client::TupleKey> {
    let mut writes: Vec<openfga_client::client::TupleKey> = Vec::new();
    for query in tuple_queries {
        if query.skipped.is_some() {
            continue;
        }
        if query.condition.is_some() {
            writes.extend(
                execute_conditional_tuple_query(conn, query)
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
            execute_tuple_queries(conn, core::slice::from_ref(query))
                .iter()
                .map(|key| support::openfga::make_tuple(&key.object, &key.relation, &key.subject)),
        );
    }
    writes
}

/// Two future deadlines on a membership table whose rows are not uniquely keyed by
/// `(doc, user)`: `PostgreSQL` grants only when one single row passes both comparisons
/// at check time. Bob's two rows each pass one comparison and fail the other, so he is
/// denied although each column's latest value alone would pass: a model compressing the
/// rows per column grants him and fails this case in the over-grant direction, while
/// Carol's one live row keeps the grant direction honest.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn two_deadline_witness_parity_postgres18_and_openfga() {
    let postgres = support::containers::start_postgres().await;
    let pg_port = postgres.get_host_port_ipv4(5432).await.unwrap();
    let pg_url = format!("postgres://{PG_USER}:{PG_PASSWORD}@127.0.0.1:{pg_port}/{PG_DB}");
    let mut conn = support::containers::connect_postgres_with_retry(&pg_url);

    let schema_sql = "
CREATE TABLE docs (id INT PRIMARY KEY);
CREATE TABLE members (
    id INT PRIMARY KEY,
    doc_id INT NOT NULL REFERENCES docs(id),
    user_id TEXT NOT NULL,
    trial_ends TIMESTAMPTZ NOT NULL,
    support_ends TIMESTAMPTZ NOT NULL
);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_p ON docs FOR SELECT USING (
    EXISTS (
        SELECT 1 FROM members m
        WHERE m.doc_id = docs.id AND m.user_id = current_user
          AND m.trial_ends > now() AND m.support_ends > now()
    )
);
";
    conn.batch_execute(schema_sql)
        .expect("Failed to apply the two-deadline schema");
    conn.batch_execute(
        "CREATE ROLE bob LOGIN; CREATE ROLE carol LOGIN; \
         GRANT SELECT ON docs, members TO bob, carol;",
    )
    .expect("Failed to create the querying roles");
    conn.batch_execute(
        "INSERT INTO docs (id) VALUES (1), (2); \
         INSERT INTO members (id, doc_id, user_id, trial_ends, support_ends) VALUES \
            (1, 1, 'bob', now() + interval '10 days', now() - interval '10 days'), \
            (2, 1, 'bob', now() - interval '10 days', now() + interval '10 days'), \
            (3, 1, 'carol', now() + interval '10 days', now() + interval '10 days'), \
            (4, 2, 'carol', now() + interval '10 days', now() - interval '10 days');",
    )
    .expect("Failed to seed the mixed-deadline rows");

    let (classified, db, registry) = support::classify_sql(schema_sql, None);
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

    let openfga = support::containers::start_openfga().await;
    let grpc_port = openfga.get_host_port_ipv4(8081).await.unwrap();
    let mut service_client = support::openfga::connect(grpc_port).await;
    let store_id =
        support::openfga::create_store(&mut service_client, "two-deadline-witness").await;
    let model_id =
        support::openfga::write_authorization_model(&mut service_client, &store_id, &model).await;
    let client = service_client.into_client(&store_id, &model_id);
    support::openfga::write_tuples(&client, all_tuple_writes(&mut conn, tuple_queries)).await;

    let now = postgres_now(&mut conn);
    let mut failures = Vec::new();
    let mut granted = 0usize;
    let mut denied = 0usize;
    for role in ["bob", "carol"] {
        let readable = readable_ids_as_role(&mut conn, role, "docs");
        for id in [1, 2] {
            let expected = readable.contains(&id);
            if expected {
                granted += 1;
            } else {
                denied += 1;
            }
            let actual = support::openfga::check_allowed_with_context(
                &client,
                &format!("user:{role}"),
                "can_select",
                &format!("docs:{id}"),
                serde_json::json!({ "request_time": now }),
            )
            .await;
            if expected != actual {
                failures.push(format!(
                    "docs:{id} for {role}: postgres={expected}, openfga={actual}"
                ));
            }
        }
    }
    assert!(
        granted > 0,
        "no live pair grants, so the case proves nothing"
    );
    assert!(
        denied > 0,
        "nothing is denied, so granting everything would pass"
    );
    assert!(
        failures.is_empty(),
        "PostgreSQL/OpenFGA two-deadline parity mismatches:\n{}",
        failures.join("\n")
    );
}

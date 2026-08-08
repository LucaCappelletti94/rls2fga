#![cfg(not(target_os = "windows"))]
#![cfg(feature = "db")]

use std::collections::BTreeSet;
use std::thread;
use std::time::Duration;

use diesel::connection::SimpleConnection;
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::sql_types::{Integer, Text};
use testcontainers::{
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
    GenericImage, ImageExt,
};

use rls2fga::classifier::patterns::ConfidenceLevel;
use rls2fga::generator::model_generator::GeneratorSettings;
use rls2fga::generator::tuple_generator::TupleQuery;
use rls2fga::translator::Translation;

mod support;

const PG_USER: &str = "postgres";
const PG_PASSWORD: &str = "postgres";
const PG_DB: &str = "rls2fga";

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
    let postgres = GenericImage::new("postgres", "18")
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

    let pg_port = postgres.get_host_port_ipv4(5432).await.unwrap();
    let pg_url = format!("postgres://{PG_USER}:{PG_PASSWORD}@127.0.0.1:{pg_port}/{PG_DB}");
    let mut conn = connect_postgres_with_retry(&pg_url);

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
    .outputs_accepting_gaps()
    .json_model();
    let tuple_queries = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps()
    .tuple_queries();
    let tuple_keys = execute_tuple_queries(&mut conn, &tuple_queries);
    assert!(
        !tuple_keys.is_empty(),
        "Expected generated tuple SQL to produce at least one tuple"
    );

    let openfga = GenericImage::new("openfga/openfga", "v1.11.6")
        .with_exposed_port(8080.tcp())
        .with_exposed_port(8081.tcp())
        .with_wait_for(WaitFor::message_on_stdout("starting HTTP server"))
        .with_cmd(["run"])
        .start()
        .await
        .expect("Failed to start OpenFGA container");

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
    let postgres = GenericImage::new("postgres", "18")
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

    let pg_port = postgres.get_host_port_ipv4(5432).await.unwrap();
    let pg_url = format!("postgres://{PG_USER}:{PG_PASSWORD}@127.0.0.1:{pg_port}/{PG_DB}");
    let mut conn = connect_postgres_with_retry(&pg_url);

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
    .outputs_accepting_gaps()
    .json_model();
    let tuple_queries = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps()
    .tuple_queries();
    let tuple_keys = execute_tuple_queries(&mut conn, &tuple_queries);

    let openfga = GenericImage::new("openfga/openfga", "v1.11.6")
        .with_exposed_port(8080.tcp())
        .with_exposed_port(8081.tcp())
        .with_wait_for(WaitFor::message_on_stdout("starting HTTP server"))
        .with_cmd(["run"])
        .start()
        .await
        .expect("Failed to start OpenFGA container");

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

/// One reader: `(app user id, login role, member of auditor)`.
const SCOPED_READERS: [(&str, &str, bool); 2] = [
    (USER_ALICE, "app_alice", true),
    (USER_BOB, "app_bob", false),
];

/// One seeded `doc_members` row: `(id, doc_id, user_id)`. `DOC_2` has none.
const SEEDED_DOC_MEMBERS: [(&str, &str, &str); 2] =
    [("dm-alice", DOC_1, USER_ALICE), ("dm-bob", DOC_1, USER_BOB)];

fn seed_doc_members_data(conn: &mut PgConnection) {
    diesel::insert_into(users::table)
        .values(
            SCOPED_READERS
                .map(|(user_id, _, _)| users::id.eq(user_id))
                .to_vec(),
        )
        .execute(conn)
        .expect("Failed to seed users");
    diesel::insert_into(docs::table)
        .values([DOC_1, DOC_2].map(|id| docs::id.eq(id)).to_vec())
        .execute(conn)
        .expect("Failed to seed docs");

    let rows: Vec<_> = SEEDED_DOC_MEMBERS
        .iter()
        .map(|(id, doc_id, user_id)| {
            (
                doc_members::id.eq(*id),
                doc_members::doc_id.eq(*doc_id),
                doc_members::user_id.eq(*user_id),
            )
        })
        .collect();
    diesel::insert_into(doc_members::table)
        .values(rows)
        .execute(conn)
        .expect("Failed to seed doc_members");
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

/// The membership subquery reads `doc_members` as the querying user, and only
/// `auditor` may read it, so a member outside that role is denied.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn role_scoped_membership_parity_postgres18_and_openfga() {
    let postgres = GenericImage::new("postgres", "18")
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

    let pg_port = postgres.get_host_port_ipv4(5432).await.unwrap();
    let pg_url = format!("postgres://{PG_USER}:{PG_PASSWORD}@127.0.0.1:{pg_port}/{PG_DB}");
    let mut conn = connect_postgres_with_retry(&pg_url);

    let schema_sql = support::read_fixture_sql("role_scoped_membership");
    let (classified, db, registry) = support::load_fixture_classified("role_scoped_membership");
    // The policy names the role, so it has to exist before the schema is applied.
    conn.batch_execute("CREATE ROLE auditor")
        .expect("Failed to create the scoped role");
    conn.batch_execute(&schema_sql)
        .expect("Failed to apply the role_scoped_membership schema on PostgreSQL 18");
    seed_doc_members_data(&mut conn);

    for (_, login_role, in_auditor) in SCOPED_READERS {
        let grant_auditor = if in_auditor {
            format!("GRANT auditor TO {login_role};")
        } else {
            String::new()
        };
        conn.batch_execute(&format!(
            "CREATE ROLE {login_role} LOGIN; \
             GRANT SELECT ON docs, doc_members TO {login_role}; \
             {grant_auditor}"
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
    .outputs_accepting_gaps()
    .json_model();
    let tuple_queries = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps()
    .tuple_queries();
    let tuple_keys = execute_tuple_queries(&mut conn, &tuple_queries);

    let openfga = GenericImage::new("openfga/openfga", "v1.11.6")
        .with_exposed_port(8080.tcp())
        .with_exposed_port(8081.tcp())
        .with_wait_for(WaitFor::message_on_stdout("starting HTTP server"))
        .with_cmd(["run"])
        .start()
        .await
        .expect("Failed to start OpenFGA container");

    let grpc_port = openfga.get_host_port_ipv4(8081).await.unwrap();
    let mut service_client = support::openfga::connect(grpc_port).await;
    let store_id =
        support::openfga::create_store(&mut service_client, "role-scoped-membership-parity").await;
    let model_id =
        support::openfga::write_authorization_model(&mut service_client, &store_id, &model).await;

    let mut writes: Vec<openfga_client::client::TupleKey> = tuple_keys
        .iter()
        .map(|tuple| support::openfga::make_tuple(&tuple.object, &tuple.relation, &tuple.subject))
        .collect();
    // The report asks the operator for these: role membership lives outside the
    // policy tables, so no generated query can produce it.
    for (user_id, _, in_auditor) in SCOPED_READERS {
        if in_auditor {
            writes.push(support::openfga::make_tuple(
                "pg_role:auditor",
                "usage",
                &format!("user:{user_id}"),
            ));
        }
    }
    let client = service_client.into_client(&store_id, &model_id);
    support::openfga::write_tuples(&client, writes).await;

    let mut failures = Vec::new();
    for (user_id, login_role, _) in SCOPED_READERS {
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
    }

    assert!(
        failures.is_empty(),
        "PostgreSQL/OpenFGA role scoped membership parity mismatches:\n{}",
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
    let postgres = GenericImage::new("postgres", "18")
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

    let pg_port = postgres.get_host_port_ipv4(5432).await.unwrap();
    let pg_url = format!("postgres://{PG_USER}:{PG_PASSWORD}@127.0.0.1:{pg_port}/{PG_DB}");
    let mut conn = connect_postgres_with_retry(&pg_url);

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
    .outputs_accepting_gaps()
    .json_model();
    let tuple_queries = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps()
    .tuple_queries();
    let tuple_keys = execute_tuple_queries(&mut conn, &tuple_queries);

    let openfga = GenericImage::new("openfga/openfga", "v1.11.6")
        .with_exposed_port(8080.tcp())
        .with_exposed_port(8081.tcp())
        .with_wait_for(WaitFor::message_on_stdout("starting HTTP server"))
        .with_cmd(["run"])
        .start()
        .await
        .expect("Failed to start OpenFGA container");

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

/// One reader: `(app user id, login role, grants inherit)`. Both are members of
/// `editors`, only the first inherits its privileges.
const INHERIT_READERS: [(&str, &str, bool); 2] = [
    (USER_ALICE, "app_alice", true),
    (USER_BOB, "app_bob", false),
];

/// A `TO editors` policy admits the role's inheriting members and nobody else:
/// a `NOINHERIT` member holds `MEMBER` yet reads nothing, so the scope has to walk
/// `usage` facts, which only the inheriting member gets.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn noinherit_member_parity_postgres18_and_openfga() {
    let postgres = GenericImage::new("postgres", "18")
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

    let pg_port = postgres.get_host_port_ipv4(5432).await.unwrap();
    let pg_url = format!("postgres://{PG_USER}:{PG_PASSWORD}@127.0.0.1:{pg_port}/{PG_DB}");
    let mut conn = connect_postgres_with_retry(&pg_url);

    let schema_sql = support::read_fixture_sql("role_scope_inherit");
    let (classified, db, registry) = support::load_fixture_classified("role_scope_inherit");
    // The policy names the role, so it has to exist before the schema is applied.
    conn.batch_execute("CREATE ROLE editors")
        .expect("Failed to create the scoped role");
    conn.batch_execute(&schema_sql)
        .expect("Failed to apply the role_scope_inherit schema on PostgreSQL 18");
    diesel::insert_into(docs::table)
        .values([docs::id.eq(DOC_1), docs::id.eq(DOC_2)])
        .execute(&mut conn)
        .expect("Failed to seed docs");

    for (_, login_role, inherits) in INHERIT_READERS {
        let attribute = if inherits { "" } else { " NOINHERIT" };
        conn.batch_execute(&format!(
            "CREATE ROLE {login_role} LOGIN{attribute}; \
             GRANT editors TO {login_role}; \
             GRANT SELECT ON docs TO {login_role};"
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
    .outputs_accepting_gaps()
    .json_model();
    let tuple_queries = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps()
    .tuple_queries();
    let tuple_keys = execute_tuple_queries(&mut conn, &tuple_queries);

    let openfga = GenericImage::new("openfga/openfga", "v1.11.6")
        .with_exposed_port(8080.tcp())
        .with_exposed_port(8081.tcp())
        .with_wait_for(WaitFor::message_on_stdout("starting HTTP server"))
        .with_cmd(["run"])
        .start()
        .await
        .expect("Failed to start OpenFGA container");

    let grpc_port = openfga.get_host_port_ipv4(8081).await.unwrap();
    let mut service_client = support::openfga::connect(grpc_port).await;
    let store_id =
        support::openfga::create_store(&mut service_client, "noinherit-member-parity").await;
    let model_id =
        support::openfga::write_authorization_model(&mut service_client, &store_id, &model).await;

    let mut writes: Vec<openfga_client::client::TupleKey> = tuple_keys
        .iter()
        .map(|tuple| support::openfga::make_tuple(&tuple.object, &tuple.relation, &tuple.subject))
        .collect();
    // The report asks the operator for usage facts, the grants whose whole chain
    // inherits, so the NOINHERIT member gets none however real their membership is.
    for (user_id, _, inherits) in INHERIT_READERS {
        if inherits {
            writes.push(support::openfga::make_tuple(
                "pg_role:editors",
                "usage",
                &format!("user:{user_id}"),
            ));
        }
    }
    let client = service_client.into_client(&store_id, &model_id);
    support::openfga::write_tuples(&client, writes).await;

    let mut failures = Vec::new();
    let mut granted = 0usize;
    let mut denied = 0usize;
    for (user_id, login_role, _) in INHERIT_READERS {
        for doc_id in [DOC_1, DOC_2] {
            let expected = postgres_allows_select(&mut conn, user_id, login_role, doc_id);
            if expected {
                granted += 1;
            } else {
                denied += 1;
            }
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
    }

    assert!(
        failures.is_empty(),
        "PostgreSQL/OpenFGA NOINHERIT member parity mismatches:\n{}",
        failures.join("\n")
    );
    // Two-sided by construction: the inheriting member reads and the NOINHERIT member
    // does not, so a model granting everything or nothing cannot pass.
    assert!(
        granted > 0 && denied > 0,
        "the fixture must separate the two members, got granted={granted} denied={denied}"
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
    let postgres = GenericImage::new("postgres", "18")
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

    let pg_port = postgres.get_host_port_ipv4(5432).await.unwrap();
    let pg_url = format!("postgres://{PG_USER}:{PG_PASSWORD}@127.0.0.1:{pg_port}/{PG_DB}");
    let mut conn = connect_postgres_with_retry(&pg_url);

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
    .outputs_accepting_gaps()
    .json_model();
    let tuple_queries = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps()
    .tuple_queries();
    let tuple_keys = execute_tuple_queries(&mut conn, &tuple_queries);

    let openfga = GenericImage::new("openfga/openfga", "v1.11.6")
        .with_exposed_port(8080.tcp())
        .with_exposed_port(8081.tcp())
        .with_wait_for(WaitFor::message_on_stdout("starting HTTP server"))
        .with_cmd(["run"])
        .start()
        .await
        .expect("Failed to start OpenFGA container");

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

/// One seeded `notes` row: `(id, owner_id)`.
const SEEDED_FOLDED_NOTES: [(&str, &str); 3] = [
    ("note-owned-by-alice", USER_ALICE),
    ("note-owned-by-bob-shared", USER_BOB),
    ("note-owned-by-bob-private", USER_BOB),
];

/// One seeded `note_members` row: `(id, note_id, user_id)`.
const SEEDED_FOLDED_MEMBERS: [(&str, &str, &str); 1] = [(
    "member-alice-shared",
    "note-owned-by-bob-shared",
    USER_ALICE,
)];

/// One reader: `(app user id, login role)`.
const FOLDED_READERS: [(&str, &str); 2] = [(USER_ALICE, "app_alice"), (USER_BOB, "app_bob")];

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

/// Whether `login_role`, acting as `user_id`, can read the `notes` row `note_id`.
fn postgres_allows_folded_select(
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

        let visible: i64 = notes_folded::table
            .filter(notes_folded::id.eq(note_id))
            .count()
            .get_result(conn)?;
        Ok(visible == 1)
    })
    .expect("reading notes under row level security should not error")
}

/// The schema spells every table and column in a case `PostgreSQL` does not store,
/// so the generated statements only run if they name the stored identifiers.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn folded_identifier_parity_postgres18_and_openfga() {
    let postgres = GenericImage::new("postgres", "18")
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

    let pg_port = postgres.get_host_port_ipv4(5432).await.unwrap();
    let pg_url = format!("postgres://{PG_USER}:{PG_PASSWORD}@127.0.0.1:{pg_port}/{PG_DB}");
    let mut conn = connect_postgres_with_retry(&pg_url);

    let schema_sql = support::read_fixture_sql("folded_identifiers");
    let (classified, db, registry) = support::load_fixture_classified("folded_identifiers");
    conn.batch_execute(&schema_sql)
        .expect("Failed to apply the folded_identifiers schema on PostgreSQL 18");

    diesel::insert_into(users::table)
        .values(
            FOLDED_READERS
                .map(|(user_id, _)| users::id.eq(user_id))
                .to_vec(),
        )
        .execute(&mut conn)
        .expect("Failed to seed users");
    diesel::insert_into(notes_folded::table)
        .values(
            SEEDED_FOLDED_NOTES
                .map(|(id, owner)| (notes_folded::id.eq(id), notes_folded::owner_id.eq(owner)))
                .to_vec(),
        )
        .execute(&mut conn)
        .expect("Failed to seed notes");
    diesel::insert_into(note_members::table)
        .values(
            SEEDED_FOLDED_MEMBERS
                .map(|(id, note_id, user_id)| {
                    (
                        note_members::id.eq(id),
                        note_members::note_id.eq(note_id),
                        note_members::user_id.eq(user_id),
                    )
                })
                .to_vec(),
        )
        .execute(&mut conn)
        .expect("Failed to seed note_members");

    for (_, login_role) in FOLDED_READERS {
        conn.batch_execute(&format!(
            "CREATE ROLE {login_role} LOGIN; \
             GRANT SELECT ON notes, note_members TO {login_role};"
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
    .outputs_accepting_gaps()
    .json_model();
    let tuple_queries = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps()
    .tuple_queries();
    let tuple_keys = execute_tuple_queries(&mut conn, &tuple_queries);
    assert!(
        !tuple_keys.is_empty(),
        "the generated statements must return rows, otherwise every check answers no"
    );

    let openfga = GenericImage::new("openfga/openfga", "v1.11.6")
        .with_exposed_port(8080.tcp())
        .with_exposed_port(8081.tcp())
        .with_wait_for(WaitFor::message_on_stdout("starting HTTP server"))
        .with_cmd(["run"])
        .start()
        .await
        .expect("Failed to start OpenFGA container");

    let grpc_port = openfga.get_host_port_ipv4(8081).await.unwrap();
    let mut service_client = support::openfga::connect(grpc_port).await;
    let store_id =
        support::openfga::create_store(&mut service_client, "folded-identifier-parity").await;
    let model_id =
        support::openfga::write_authorization_model(&mut service_client, &store_id, &model).await;

    let writes: Vec<openfga_client::client::TupleKey> = tuple_keys
        .iter()
        .map(|tuple| support::openfga::make_tuple(&tuple.object, &tuple.relation, &tuple.subject))
        .collect();
    let client = service_client.into_client(&store_id, &model_id);
    support::openfga::write_tuples(&client, writes).await;

    let mut failures = Vec::new();
    let mut denied = 0usize;
    for (user_id, login_role) in FOLDED_READERS {
        for (note_id, _) in SEEDED_FOLDED_NOTES {
            let expected = postgres_allows_folded_select(&mut conn, user_id, login_role, note_id);
            if !expected {
                denied += 1;
            }
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
        denied > 0,
        "every row is readable by everyone, so the comparison proves nothing"
    );
    assert!(
        failures.is_empty(),
        "PostgreSQL/OpenFGA folded identifier parity mismatches:\n{}",
        failures.join("\n")
    );
}

diesel::table! {
    #[sql_name = "notes"]
    notes_owned (id) {
        id -> diesel::sql_types::Text,
        owner_id -> diesel::sql_types::Text,
    }
}

/// One seeded `notes` row: `(id, owner_id)`.
const SEEDED_OWNED_NOTES: [(&str, &str); 2] = [("note-alice", USER_ALICE), ("note-bob", USER_BOB)];

fn seed_owned_notes(conn: &mut PgConnection) {
    diesel::insert_into(users::table)
        .values([USER_ALICE, USER_BOB].map(|id| users::id.eq(id)).to_vec())
        .execute(conn)
        .expect("Failed to seed users");
    diesel::insert_into(notes_owned::table)
        .values(
            SEEDED_OWNED_NOTES
                .map(|(id, owner)| (notes_owned::id.eq(id), notes_owned::owner_id.eq(owner)))
                .to_vec(),
        )
        .execute(conn)
        .expect("Failed to seed notes");
}

/// Whether `app_user` acting as `user_id` sees the `notes` row `note_id`.
/// `locking` adds `FOR UPDATE`, which also applies the `UPDATE` policies.
fn postgres_returns_note(
    conn: &mut PgConnection,
    user_id: &str,
    note_id: &str,
    locking: bool,
) -> bool {
    conn.transaction::<bool, diesel::result::Error, _>(|conn| {
        // Session settings and role switching have no query DSL form.
        diesel::sql_query("SET LOCAL ROLE app_user").execute(conn)?;
        diesel::sql_query("SELECT set_config('app.current_user_id', $1, true)")
            .bind::<Text, _>(user_id)
            .execute(conn)?;

        let rows = notes_owned::table
            .filter(notes_owned::id.eq(note_id))
            .select(notes_owned::id);
        // A locking clause bars an aggregate, so count the rows returned.
        let returned: Vec<String> = if locking {
            rows.for_update().load(conn)?
        } else {
            rows.load(conn)?
        };
        Ok(returned.len() == 1)
    })
    .expect("reading notes under row level security should not error")
}

/// Whether `app_user` acting as `user_id` may write the `notes` row `note` back
/// unchanged. The write is never kept.
fn postgres_updates_note(conn: &mut PgConnection, user_id: &str, note: (&str, &str)) -> bool {
    let (note_id, owner_id) = note;
    let mut changed = 0usize;
    let outcome = conn.transaction::<(), AttemptError, _>(|conn| {
        // Session settings and role switching have no query DSL form.
        diesel::sql_query("SET LOCAL ROLE app_user").execute(conn)?;
        diesel::sql_query("SELECT set_config('app.current_user_id', $1, true)")
            .bind::<Text, _>(user_id)
            .execute(conn)?;

        // Writing the row's own owner back keeps whatever a WITH CHECK admits.
        changed = diesel::update(notes_owned::table.filter(notes_owned::id.eq(note_id)))
            .set(notes_owned::owner_id.eq(owner_id))
            .execute(conn)?;
        Err(AttemptError::Rollback)
    });

    match outcome {
        Err(AttemptError::Rollback) => changed == 1,
        Err(AttemptError::Rejected(error)) => {
            let rendered = error.to_string();
            assert!(
                rendered.contains("row-level security"),
                "updating {note_id} as {user_id} failed for a reason other than RLS: {rendered}"
            );
            false
        }
        Ok(()) => unreachable!("the transaction body always rolls back"),
    }
}

/// A locking read applies the `UPDATE` policies' `USING` clause on top of the
/// `SELECT` policies, so `can_select` answers for rows `SELECT ... FOR UPDATE`
/// never returns. `can_select_for_update` is what answers for that statement.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn locking_read_parity_postgres18_and_openfga() {
    let postgres = GenericImage::new("postgres", "18")
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

    let pg_port = postgres.get_host_port_ipv4(5432).await.unwrap();
    let pg_url = format!("postgres://{PG_USER}:{PG_PASSWORD}@127.0.0.1:{pg_port}/{PG_DB}");
    let mut conn = connect_postgres_with_retry(&pg_url);

    let schema_sql = support::read_fixture_sql("locking_read");
    let (classified, db, registry) = support::load_fixture_classified("locking_read");
    conn.batch_execute(&schema_sql)
        .expect("Failed to apply the locking_read schema on PostgreSQL 18");
    // A locking read needs the UPDATE privilege as well as SELECT.
    conn.batch_execute("CREATE ROLE app_user LOGIN; GRANT SELECT, UPDATE ON notes TO app_user;")
        .expect("Failed to create the querying role");
    seed_owned_notes(&mut conn);

    let model = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps()
    .json_model();
    let tuple_queries = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps()
    .tuple_queries();
    let tuple_keys = execute_tuple_queries(&mut conn, &tuple_queries);

    let openfga = GenericImage::new("openfga/openfga", "v1.11.6")
        .with_exposed_port(8080.tcp())
        .with_exposed_port(8081.tcp())
        .with_wait_for(WaitFor::message_on_stdout("starting HTTP server"))
        .with_cmd(["run"])
        .start()
        .await
        .expect("Failed to start OpenFGA container");

    let grpc_port = openfga.get_host_port_ipv4(8081).await.unwrap();
    let mut service_client = support::openfga::connect(grpc_port).await;
    let store_id = support::openfga::create_store(&mut service_client, "locking-read-parity").await;
    let model_id =
        support::openfga::write_authorization_model(&mut service_client, &store_id, &model).await;

    let writes: Vec<openfga_client::client::TupleKey> = tuple_keys
        .iter()
        .map(|tuple| support::openfga::make_tuple(&tuple.object, &tuple.relation, &tuple.subject))
        .collect();
    let client = service_client.into_client(&store_id, &model_id);
    support::openfga::write_tuples(&client, writes).await;

    let mut failures = Vec::new();
    let mut separated = 0usize;
    for user_id in [USER_ALICE, USER_BOB] {
        for (note_id, _) in SEEDED_OWNED_NOTES {
            let plain = postgres_returns_note(&mut conn, user_id, note_id, false);
            let locking = postgres_returns_note(&mut conn, user_id, note_id, true);
            if plain && !locking {
                separated += 1;
            }

            let user = format!("user:{user_id}");
            let object = format!("notes:{note_id}");
            for (relation, expected) in [("can_select", plain), ("can_select_for_update", locking)]
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
        separated > 0,
        "no row separates a plain read from a locking read, so the comparison proves nothing"
    );
    assert!(
        failures.is_empty(),
        "PostgreSQL/OpenFGA locking read parity mismatches:\n{}",
        failures.join("\n")
    );
}

/// An `UPDATE` policy that stores no `USING` clause leaves `PostgreSQL` without a
/// permissive qual for the row being changed, so nothing is updatable even where
/// the `WITH CHECK` would admit the new row.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn absent_clause_parity_postgres18_and_openfga() {
    let postgres = GenericImage::new("postgres", "18")
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

    let pg_port = postgres.get_host_port_ipv4(5432).await.unwrap();
    let pg_url = format!("postgres://{PG_USER}:{PG_PASSWORD}@127.0.0.1:{pg_port}/{PG_DB}");
    let mut conn = connect_postgres_with_retry(&pg_url);

    let schema_sql = support::read_fixture_sql("clause_absent");
    let (classified, db, registry) = support::load_fixture_classified("clause_absent");
    conn.batch_execute(&schema_sql)
        .expect("Failed to apply the clause_absent schema on PostgreSQL 18");
    conn.batch_execute("CREATE ROLE app_user LOGIN; GRANT SELECT, UPDATE ON notes TO app_user;")
        .expect("Failed to create the querying role");
    seed_owned_notes(&mut conn);

    let model = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps()
    .json_model();
    let tuple_queries = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps()
    .tuple_queries();
    let tuple_keys = execute_tuple_queries(&mut conn, &tuple_queries);

    let openfga = GenericImage::new("openfga/openfga", "v1.11.6")
        .with_exposed_port(8080.tcp())
        .with_exposed_port(8081.tcp())
        .with_wait_for(WaitFor::message_on_stdout("starting HTTP server"))
        .with_cmd(["run"])
        .start()
        .await
        .expect("Failed to start OpenFGA container");

    let grpc_port = openfga.get_host_port_ipv4(8081).await.unwrap();
    let mut service_client = support::openfga::connect(grpc_port).await;
    let store_id =
        support::openfga::create_store(&mut service_client, "absent-clause-parity").await;
    let model_id =
        support::openfga::write_authorization_model(&mut service_client, &store_id, &model).await;

    let writes: Vec<openfga_client::client::TupleKey> = tuple_keys
        .iter()
        .map(|tuple| support::openfga::make_tuple(&tuple.object, &tuple.relation, &tuple.subject))
        .collect();
    let client = service_client.into_client(&store_id, &model_id);
    support::openfga::write_tuples(&client, writes).await;

    let mut failures = Vec::new();
    let mut readable_but_frozen = 0usize;
    for user_id in [USER_ALICE, USER_BOB] {
        for note in SEEDED_OWNED_NOTES {
            let readable = postgres_returns_note(&mut conn, user_id, note.0, false);
            let updatable = postgres_updates_note(&mut conn, user_id, note);
            if readable && !updatable {
                readable_but_frozen += 1;
            }

            let user = format!("user:{user_id}");
            let object = format!("notes:{}", note.0);
            for (relation, expected) in [("can_select", readable), ("can_update", updatable)] {
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
        readable_but_frozen > 0,
        "no row is readable yet unwritable, so the comparison proves nothing"
    );
    assert!(
        failures.is_empty(),
        "PostgreSQL/OpenFGA absent clause parity mismatches:\n{}",
        failures.join("\n")
    );
}

/// `ALTER POLICY` replaces the clause the policy was created with, so `PostgreSQL`
/// enforces the narrowed rule. Translating the original instead would publish a model
/// open to everyone, which is why the fixture widens on creation and narrows after.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn altered_policy_parity_postgres18_and_openfga() {
    let postgres = GenericImage::new("postgres", "18")
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

    let pg_port = postgres.get_host_port_ipv4(5432).await.unwrap();
    let pg_url = format!("postgres://{PG_USER}:{PG_PASSWORD}@127.0.0.1:{pg_port}/{PG_DB}");
    let mut conn = connect_postgres_with_retry(&pg_url);

    let schema_sql = support::read_fixture_sql("policy_altered");
    let (classified, db, registry) = support::load_fixture_classified("policy_altered");
    conn.batch_execute(&schema_sql)
        .expect("Failed to apply the policy_altered schema on PostgreSQL 18");
    conn.batch_execute("CREATE ROLE app_user LOGIN; GRANT SELECT ON notes TO app_user;")
        .expect("Failed to create the querying role");
    seed_owned_notes(&mut conn);

    let model = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps()
    .json_model();
    let tuple_queries = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps()
    .tuple_queries();
    let tuple_keys = execute_tuple_queries(&mut conn, &tuple_queries);

    let openfga = GenericImage::new("openfga/openfga", "v1.11.6")
        .with_exposed_port(8080.tcp())
        .with_exposed_port(8081.tcp())
        .with_wait_for(WaitFor::message_on_stdout("starting HTTP server"))
        .with_cmd(["run"])
        .start()
        .await
        .expect("Failed to start OpenFGA container");

    let grpc_port = openfga.get_host_port_ipv4(8081).await.unwrap();
    let mut service_client = support::openfga::connect(grpc_port).await;
    let store_id =
        support::openfga::create_store(&mut service_client, "altered-policy-parity").await;
    let model_id =
        support::openfga::write_authorization_model(&mut service_client, &store_id, &model).await;

    let writes: Vec<openfga_client::client::TupleKey> = tuple_keys
        .iter()
        .map(|tuple| support::openfga::make_tuple(&tuple.object, &tuple.relation, &tuple.subject))
        .collect();
    let client = service_client.into_client(&store_id, &model_id);
    support::openfga::write_tuples(&client, writes).await;

    let mut failures = Vec::new();
    let mut narrowed_away = 0usize;
    for user_id in [USER_ALICE, USER_BOB] {
        for (note_id, owner_id) in SEEDED_OWNED_NOTES {
            let readable = postgres_returns_note(&mut conn, user_id, note_id, false);
            // USING (TRUE) admitted every row, so a refusal is the alteration taking hold.
            if user_id != owner_id {
                assert!(
                    !readable,
                    "{user_id} still reads {note_id}, so PostgreSQL never applied the ALTER POLICY"
                );
                narrowed_away += 1;
            }

            let user = format!("user:{user_id}");
            let object = format!("notes:{note_id}");
            let actual =
                support::openfga::check_allowed(&client, &user, "can_select", &object).await;
            if readable != actual {
                failures.push(format!(
                    "{user} can_select {object}: postgres={readable}, openfga={actual}"
                ));
            }
        }
    }

    assert!(
        narrowed_away > 0,
        "no row is refused by the narrowed rule, so the comparison proves nothing"
    );
    assert!(
        failures.is_empty(),
        "PostgreSQL/OpenFGA altered policy parity mismatches:\n{}",
        failures.join("\n")
    );
}

/// Typed schema for the `array_jsonb_membership` fixture. `editors` is nullable and its
/// elements are nullable, because the rows that matter carry `NULL`, `ARRAY[]` and
/// `ARRAY[NULL]`.
mod array_jsonb_schema {
    diesel::table! {
        notes (id) {
            id -> diesel::sql_types::Text,
            editors -> diesel::sql_types::Nullable<
                diesel::sql_types::Array<diesel::sql_types::Nullable<diesel::sql_types::Text>>,
            >,
            meta -> diesel::sql_types::Nullable<diesel::sql_types::Jsonb>,
        }
    }
}

/// One seeded row: `(id, editors, the owner_id the jsonb names)`.
///
/// `None` editors is a NULL column, an empty slice is `ARRAY[]`, and a `None` element is
/// `ARRAY[NULL]`. `None` for the owner means the key is absent. `PostgreSQL` 18 admits a
/// row only where the caller is an element or the extracted text equals the caller, so
/// every shape below is denied to everyone except where it names one of them.
type SeededDocumentRow = (
    &'static str,
    Option<&'static [Option<&'static str>]>,
    Option<&'static str>,
);
const SEEDED_DOCUMENT_ROWS: [SeededDocumentRow; 8] = [
    ("aj-editor-only", Some(&[Some(USER_ALICE)]), Some(USER_BOB)),
    ("aj-meta-only", Some(&[Some(USER_BOB)]), Some(USER_ALICE)),
    ("aj-both", Some(&[Some(USER_ALICE)]), Some(USER_ALICE)),
    ("aj-neither", Some(&[Some(USER_BOB)]), Some(USER_BOB)),
    ("aj-empty-array", Some(&[]), Some(USER_ALICE)),
    ("aj-null-array", None, Some(USER_ALICE)),
    ("aj-null-element", Some(&[None]), None),
    ("aj-missing-key", Some(&[Some(USER_ALICE)]), None),
];

fn seed_document_notes(conn: &mut PgConnection) {
    use array_jsonb_schema::notes as aj_notes;

    diesel::insert_into(users::table)
        .values([USER_ALICE, USER_BOB].map(|id| users::id.eq(id)).to_vec())
        .execute(conn)
        .expect("Failed to seed users");

    for (id, editors, owner) in SEEDED_DOCUMENT_ROWS {
        let meta = owner.map_or_else(
            || serde_json::json!({}),
            |owner| serde_json::json!({ "owner_id": owner }),
        );
        diesel::insert_into(aj_notes::table)
            .values((
                aj_notes::id.eq(id),
                aj_notes::editors.eq(editors.map(<[Option<&str>]>::to_vec)),
                aj_notes::meta.eq(Some(meta)),
            ))
            .execute(conn)
            .expect("Failed to seed a document note");
    }
}

/// Ids `user_id` can read through the fixture's two `SELECT` policies.
fn postgres_readable_document_notes(conn: &mut PgConnection, user_id: &str) -> BTreeSet<String> {
    use array_jsonb_schema::notes as aj_notes;

    conn.transaction::<BTreeSet<String>, diesel::result::Error, _>(|conn| {
        // Role switching and session settings have no query DSL form.
        diesel::sql_query("SET LOCAL ROLE app_user").execute(conn)?;
        diesel::sql_query("SELECT set_config('app.current_user_id', $1, true)")
            .bind::<Text, _>(user_id)
            .execute(conn)?;
        let ids: Vec<String> = aj_notes::table.select(aj_notes::id).load(conn)?;
        Ok(ids.into_iter().collect())
    })
    .expect("Failed to read the document notes")
}

/// The caller as an array element and the caller named by a jsonb field are both exact,
/// so `can_select` must agree with a real read row for row.
///
/// Both policies are permissive and each admits rows the other refuses, so a model that
/// kept only one of them fails, and rows nobody may read stop it passing by granting
/// everything. Pointing `can_select` at either relation alone makes it fail.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn array_and_jsonb_membership_parity_postgres18_and_openfga() {
    let postgres = GenericImage::new("postgres", "18")
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

    let pg_port = postgres.get_host_port_ipv4(5432).await.unwrap();
    let pg_url = format!("postgres://{PG_USER}:{PG_PASSWORD}@127.0.0.1:{pg_port}/{PG_DB}");
    let mut conn = connect_postgres_with_retry(&pg_url);

    let schema_sql = support::read_fixture_sql("array_jsonb_membership");
    let (classified, db, registry) = support::load_fixture_classified("array_jsonb_membership");
    conn.batch_execute(&schema_sql)
        .expect("Failed to apply the array_jsonb_membership schema on PostgreSQL 18");
    conn.batch_execute("CREATE ROLE app_user LOGIN; GRANT SELECT ON notes TO app_user;")
        .expect("Failed to create the querying role");
    seed_document_notes(&mut conn);

    let model = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps()
    .json_model();
    let tuple_queries = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps()
    .tuple_queries();
    let tuple_keys = execute_tuple_queries(&mut conn, &tuple_queries);

    let openfga = GenericImage::new("openfga/openfga", "v1.11.6")
        .with_exposed_port(8080.tcp())
        .with_exposed_port(8081.tcp())
        .with_wait_for(WaitFor::message_on_stdout("starting HTTP server"))
        .with_cmd(["run"])
        .start()
        .await
        .expect("Failed to start OpenFGA container");

    let grpc_port = openfga.get_host_port_ipv4(8081).await.unwrap();
    let mut service_client = support::openfga::connect(grpc_port).await;
    let store_id =
        support::openfga::create_store(&mut service_client, "array-jsonb-membership-parity").await;
    let model_id =
        support::openfga::write_authorization_model(&mut service_client, &store_id, &model).await;

    let writes: Vec<openfga_client::client::TupleKey> = tuple_keys
        .iter()
        .map(|tuple| support::openfga::make_tuple(&tuple.object, &tuple.relation, &tuple.subject))
        .collect();
    let client = service_client.into_client(&store_id, &model_id);
    support::openfga::write_tuples(&client, writes).await;

    let mut failures = Vec::new();
    let mut denied = 0usize;
    let mut only_editors = 0usize;
    let mut only_meta = 0usize;

    for user_id in [USER_ALICE, USER_BOB] {
        let readable = postgres_readable_document_notes(&mut conn, user_id);
        for (note_id, editors, owner) in SEEDED_DOCUMENT_ROWS {
            let expected = readable.contains(note_id);
            let listed = editors.is_some_and(|e| e.contains(&Some(user_id)));
            let named = owner == Some(user_id);
            if !expected {
                denied += 1;
            }
            if expected && listed && !named {
                only_editors += 1;
            }
            if expected && named && !listed {
                only_meta += 1;
            }

            let user = format!("user:{user_id}");
            let object = format!("notes:{note_id}");
            let actual =
                support::openfga::check_allowed(&client, &user, "can_select", &object).await;
            if expected != actual {
                failures.push(format!(
                    "{user} can_select {object}: postgres={expected}, openfga={actual}"
                ));
            }
        }
    }

    assert!(
        only_editors > 0,
        "no row is readable through the array alone, so dropping the array relation would still pass"
    );
    assert!(
        only_meta > 0,
        "no row is readable through the jsonb field alone, so dropping it would still pass"
    );
    assert!(
        denied > 0,
        "every row is readable, so the comparison cannot catch an over-grant"
    );
    assert!(
        failures.is_empty(),
        "PostgreSQL/OpenFGA array and jsonb membership parity mismatches:\n{}",
        failures.join("\n")
    );
}

/// Rows whose grant depends on the clock, plus one the guard can never admit.
const SEEDED_EXPIRING_DOCS: [(&str, &str); 4] = [
    ("d-live", "2099-01-01T00:00:00+00:00"),
    ("d-stale", "2000-01-01T00:00:00+00:00"),
    ("d-soon", "2027-01-01T00:00:00+00:00"),
    ("d-null", "NULL"),
];

/// A guard against `now()` cannot become tuples: a tuple computed once would keep
/// granting after the value passed. It becomes an `OpenFGA` condition instead, and this
/// case proves the service evaluates it as the policy means, at two instants, against
/// what `PostgreSQL` itself answers.
#[tokio::test]
#[ignore = "requires Docker: starts PostgreSQL 18 and OpenFGA containers"]
async fn request_time_condition_parity_postgres18_and_openfga() {
    let postgres = GenericImage::new("postgres", "18")
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

    let pg_port = postgres.get_host_port_ipv4(5432).await.unwrap();
    let pg_url = format!("postgres://{PG_USER}:{PG_PASSWORD}@127.0.0.1:{pg_port}/{PG_DB}");
    let mut conn = connect_postgres_with_retry(&pg_url);

    let schema_sql = "
CREATE TABLE docs (id TEXT PRIMARY KEY, expires_at TIMESTAMPTZ);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_unexpired ON docs FOR SELECT USING (expires_at > now());
";
    conn.batch_execute(schema_sql)
        .expect("Failed to apply the expiring-docs schema");
    conn.batch_execute("CREATE ROLE app_user LOGIN; GRANT SELECT ON docs TO app_user;")
        .expect("Failed to create the querying role");

    let values: Vec<String> = SEEDED_EXPIRING_DOCS
        .iter()
        .map(|(id, expires)| {
            if *expires == "NULL" {
                format!("('{id}', NULL)")
            } else {
                format!("('{id}', '{expires}')")
            }
        })
        .collect();
    conn.batch_execute(&format!(
        "INSERT INTO docs (id, expires_at) VALUES {};",
        values.join(", ")
    ))
    .expect("Failed to seed the expiring docs");

    let (classified, db, registry) = support::classify_sql(schema_sql, None);
    let model = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps()
    .json_model();
    let tuple_queries = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps()
    .tuple_queries();

    // The condition-bearing query names its condition rather than making a loader
    // parse the SQL to find it.
    let conditional: Vec<&TupleQuery> = tuple_queries
        .iter()
        .filter(|query| query.condition.is_some())
        .collect();
    assert_eq!(
        conditional.len(),
        1,
        "the guard must emit exactly one conditional query, got {} queries",
        tuple_queries.len()
    );
    let conditional_rows = execute_conditional_tuple_query(&mut conn, conditional[0]);
    assert_eq!(
        conditional_rows.len(),
        3,
        "every row with a value carries a tuple and the NULL row carries none"
    );

    let openfga = GenericImage::new("openfga/openfga", "v1.11.6")
        .with_exposed_port(8080.tcp())
        .with_exposed_port(8081.tcp())
        .with_wait_for(WaitFor::message_on_stdout("starting HTTP server"))
        .with_cmd(["run"])
        .start()
        .await
        .expect("Failed to start OpenFGA container");

    let grpc_port = openfga.get_host_port_ipv4(8081).await.unwrap();
    let mut service_client = support::openfga::connect(grpc_port).await;
    let store_id = support::openfga::create_store(&mut service_client, "request-time-parity").await;
    // A model whose condition is malformed is rejected outright, so this write is
    // itself an assertion about the generated model.
    let model_id =
        support::openfga::write_authorization_model(&mut service_client, &store_id, &model).await;

    let writes: Vec<openfga_client::client::TupleKey> = conditional_rows
        .iter()
        .map(|row| {
            support::openfga::make_conditional_tuple(
                &row.object,
                &row.relation,
                &row.subject,
                &row.condition,
                row.context.clone(),
            )
        })
        .collect();
    let client = service_client.into_client(&store_id, &model_id);
    support::openfga::write_tuples(&client, writes).await;

    // Two instants: the moment PostgreSQL is at, and a year later. The first compares
    // against a real RLS read, the second against the policy's own predicate evaluated
    // at that instant, since PostgreSQL cannot be asked about the future.
    let now = postgres_now(&mut conn);
    let later = postgres_a_year_on(&mut conn);

    let mut failures = Vec::new();
    let mut expired_between = 0usize;
    for (instant, label) in [(now.as_str(), "now"), (later.as_str(), "a year on")] {
        for (doc_id, _) in SEEDED_EXPIRING_DOCS {
            let readable_now = postgres_reads_doc_as_app_user(&mut conn, doc_id);
            let expected = if label == "now" {
                readable_now
            } else {
                postgres_doc_unexpired_at(&mut conn, doc_id, instant)
            };
            let actual = support::openfga::check_allowed_with_context(
                &client,
                "user:alice",
                "can_select",
                &format!("docs:{doc_id}"),
                serde_json::json!({ "request_time": instant }),
            )
            .await;
            if expected != actual {
                failures.push(format!(
                    "docs:{doc_id} at {label}: postgres={expected}, openfga={actual}"
                ));
            }
            if label == "a year on" && readable_now && !expected {
                expired_between += 1;
            }
        }
    }

    // Without a row the clock takes away, the case would pass against a model that
    // ignored the condition entirely.
    assert!(
        expired_between > 0,
        "no row loses its grant between the two instants, so the condition proves nothing"
    );
    assert!(
        failures.is_empty(),
        "PostgreSQL/OpenFGA request-time condition parity mismatches:\n{}",
        failures.join("\n")
    );
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

/// Whether the policy admits the row to a real read, as the plain login role.
fn postgres_reads_doc_as_app_user(conn: &mut PgConnection, doc_id: &str) -> bool {
    let mut visible = false;
    conn.transaction::<_, diesel::result::Error, _>(|conn| {
        conn.batch_execute("SET LOCAL ROLE app_user")?;
        let rows: Vec<InstantRow> =
            diesel::sql_query("SELECT id AS instant FROM docs WHERE id = $1")
                .bind::<Text, _>(doc_id)
                .load(conn)?;
        visible = !rows.is_empty();
        Err::<(), _>(diesel::result::Error::RollbackTransaction)
    })
    .ok();
    visible
}

/// The policy's own predicate evaluated at `instant`, which is what a read would
/// return then. `PostgreSQL` cannot be asked about the future, so the predicate stands
/// in for it.
fn postgres_doc_unexpired_at(conn: &mut PgConnection, doc_id: &str, instant: &str) -> bool {
    let rows: Vec<InstantRow> = diesel::sql_query(
        "SELECT id AS instant FROM docs WHERE id = $1 AND expires_at > $2::timestamptz",
    )
    .bind::<Text, _>(doc_id)
    .bind::<Text, _>(instant)
    .load(conn)
    .expect("evaluating the predicate should succeed");
    !rows.is_empty()
}

/// Typed schema for the zoneless-guard case. Only `id` is declared, since nothing reads
/// the temporal columns from Rust and this build carries no date type for them.
mod zoneless_guard_schema {
    diesel::table! {
        zoned_docs (id) {
            id -> diesel::sql_types::Text,
        }
    }

    diesel::table! {
        dated_docs (id) {
            id -> diesel::sql_types::Text,
        }
    }
}

/// Ids the plain login role can read from a table its `SELECT` policy guards.
fn postgres_readable_zoned_docs(conn: &mut PgConnection) -> BTreeSet<String> {
    use zoneless_guard_schema::zoned_docs;

    conn.transaction::<BTreeSet<String>, diesel::result::Error, _>(|conn| {
        // Role switching has no query DSL form.
        diesel::sql_query("SET LOCAL ROLE app_user").execute(conn)?;
        let ids: Vec<String> = zoned_docs::table.select(zoned_docs::id).load(conn)?;
        Ok(ids.into_iter().collect())
    })
    .expect("Failed to read the zoned docs")
}

fn postgres_readable_dated_docs(conn: &mut PgConnection) -> BTreeSet<String> {
    use zoneless_guard_schema::dated_docs;

    conn.transaction::<BTreeSet<String>, diesel::result::Error, _>(|conn| {
        diesel::sql_query("SET LOCAL ROLE app_user").execute(conn)?;
        let ids: Vec<String> = dated_docs::table.select(dated_docs::id).load(conn)?;
        Ok(ids.into_iter().collect())
    })
    .expect("Failed to read the dated docs")
}

/// A tuple's context must be RFC 3339, and only a zoned column renders one: `DATE` gives
/// `2099-01-01` and `TIMESTAMP` gives `2099-01-01T12:00:00`, both of which `OpenFGA`
/// refuses at load. It accepts the **model** that names them, so the refusal surfaced
/// only for whoever loaded the tuples, and a sibling policy granting the same row hid it
/// even then. This case loads what the crate emits and fails if the service refuses any
/// of it, so the guard cannot regrow a parameter type the store will not take.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn zoneless_temporal_guard_parity_postgres18_and_openfga() {
    let postgres = GenericImage::new("postgres", "18")
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

    let pg_port = postgres.get_host_port_ipv4(5432).await.unwrap();
    let pg_url = format!("postgres://{PG_USER}:{PG_PASSWORD}@127.0.0.1:{pg_port}/{PG_DB}");
    let mut conn = connect_postgres_with_retry(&pg_url);

    let schema_sql = "
CREATE TABLE zoned_docs (id TEXT PRIMARY KEY, expires_at TIMESTAMPTZ);
CREATE TABLE dated_docs (id TEXT PRIMARY KEY, expires_on DATE);
ALTER TABLE zoned_docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE dated_docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY zoned_unexpired ON zoned_docs FOR SELECT USING (expires_at > now());
CREATE POLICY dated_unexpired ON dated_docs FOR SELECT USING (expires_on > now());
";
    conn.batch_execute(schema_sql)
        .expect("Failed to apply the zoneless-guard schema");
    conn.batch_execute(
        "CREATE ROLE app_user LOGIN; \
         GRANT SELECT ON zoned_docs, dated_docs TO app_user;",
    )
    .expect("Failed to create the querying role");
    // Literal temporal values: no Rust date type is available to bind here.
    conn.batch_execute(
        "INSERT INTO zoned_docs (id, expires_at) VALUES \
           ('z-live', TIMESTAMPTZ '2099-01-01 00:00:00+00'), \
           ('z-stale', TIMESTAMPTZ '2000-01-01 00:00:00+00'); \
         INSERT INTO dated_docs (id, expires_on) VALUES \
           ('d-live', DATE '2099-01-01'), \
           ('d-stale', DATE '2000-01-01');",
    )
    .expect("Failed to seed the guarded rows");

    let (classified, db, registry) = support::classify_sql(schema_sql, None);
    let model = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps()
    .json_model();
    let tuple_queries = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps()
    .tuple_queries();

    let mut conditional_rows = Vec::new();
    for query in tuple_queries
        .iter()
        .filter(|query| query.condition.is_some())
    {
        conditional_rows.extend(execute_conditional_tuple_query(&mut conn, query));
    }

    let openfga = GenericImage::new("openfga/openfga", "v1.11.6")
        .with_exposed_port(8080.tcp())
        .with_exposed_port(8081.tcp())
        .with_wait_for(WaitFor::message_on_stdout("starting HTTP server"))
        .with_cmd(["run"])
        .start()
        .await
        .expect("Failed to start OpenFGA container");

    let grpc_port = openfga.get_host_port_ipv4(8081).await.unwrap();
    let mut service_client = support::openfga::connect(grpc_port).await;
    let store_id =
        support::openfga::create_store(&mut service_client, "zoneless-guard-parity").await;
    let model_id =
        support::openfga::write_authorization_model(&mut service_client, &store_id, &model).await;
    let client = service_client.into_client(&store_id, &model_id);

    let writes: Vec<openfga_client::client::TupleKey> = conditional_rows
        .iter()
        .map(|row| {
            support::openfga::make_conditional_tuple(
                &row.object,
                &row.relation,
                &row.subject,
                &row.condition,
                row.context.clone(),
            )
        })
        .collect();
    assert!(!writes.is_empty(), "the zoned guard must still emit tuples");
    // The assertion: every context the crate produced is one the service takes. A date
    // or a zoneless timestamp fails here with "expected RFC 3339 formatted timestamp".
    if let Err(error) = client.write(writes, None).await {
        panic!("OpenFGA refused a context the crate emitted: {error}");
    }

    let now = postgres_now(&mut conn);
    let readable = postgres_readable_zoned_docs(&mut conn);
    let mut failures = Vec::new();
    for doc_id in ["z-live", "z-stale"] {
        let expected = readable.contains(doc_id);
        let actual = support::openfga::check_allowed_with_context(
            &client,
            "user:alice",
            "can_select",
            &format!("zoned_docs:{doc_id}"),
            serde_json::json!({ "request_time": now }),
        )
        .await;
        if expected != actual {
            failures.push(format!(
                "zoned_docs:{doc_id}: postgres={expected}, openfga={actual}"
            ));
        }
    }
    assert!(
        readable.len() == 1,
        "one zoned row must be live and one expired, got {readable:?}"
    );

    // The cost of the refusal, stated rather than implied: PostgreSQL admits the live
    // dated row and the model denies it, because no tuple can carry that value.
    let dated_readable = postgres_readable_dated_docs(&mut conn);
    assert!(
        dated_readable.contains("d-live"),
        "PostgreSQL must admit the live dated row, got {dated_readable:?}"
    );
    for doc_id in ["d-live", "d-stale"] {
        let actual = support::openfga::check_allowed_with_context(
            &client,
            "user:alice",
            "can_select",
            &format!("dated_docs:{doc_id}"),
            serde_json::json!({ "request_time": now }),
        )
        .await;
        assert!(
            !actual,
            "the dated guard must fall closed, but dated_docs:{doc_id} was allowed"
        );
    }

    assert!(
        failures.is_empty(),
        "PostgreSQL/OpenFGA zoned guard parity mismatches:\n{}",
        failures.join("\n")
    );
}

/// Typed schema for the blanket-update case. `body` is what both statements write, and
/// reading it back as the owner of the database is how the case sees which rows a
/// blanket update actually touched.
mod blanket_update_schema {
    diesel::table! {
        notes (id) {
            id -> diesel::sql_types::Text,
            reader_user_id -> diesel::sql_types::Text,
            writer_user_id -> diesel::sql_types::Text,
            body -> diesel::sql_types::Text,
        }
    }
}

/// One seeded row: `(id, reader, writer)`. Alice reads what she is reader of and may
/// change what she is writer of, and `bu-write-only` is the row where those differ.
const SEEDED_BLANKET_ROWS: [(&str, &str, &str); 4] = [
    ("bu-both", USER_ALICE, USER_ALICE),
    ("bu-write-only", USER_BOB, USER_ALICE),
    ("bu-read-only", USER_ALICE, USER_BOB),
    ("bu-neither", USER_BOB, USER_BOB),
];

/// Ids a statement changed, read back as the database owner so RLS does not hide the
/// rows the statement reached.
fn postgres_rows_a_statement_changed(conn: &mut PgConnection, statement: &str) -> BTreeSet<String> {
    use blanket_update_schema::notes as bu_notes;

    let mut changed = BTreeSet::new();
    conn.transaction::<(), diesel::result::Error, _>(|conn| {
        // Role switching and session settings have no query DSL form.
        diesel::sql_query("SET LOCAL ROLE app_user").execute(conn)?;
        diesel::sql_query("SELECT set_config('app.current_user_id', $1, true)")
            .bind::<Text, _>(USER_ALICE)
            .execute(conn)?;
        diesel::sql_query(statement).execute(conn)?;
        diesel::sql_query("RESET ROLE").execute(conn)?;
        changed = bu_notes::table
            .filter(bu_notes::body.eq("touched"))
            .select(bu_notes::id)
            .load::<String>(conn)?
            .into_iter()
            .collect();
        Err(diesel::result::Error::RollbackTransaction)
    })
    .ok();
    changed
}

/// `UPDATE t SET c = 1` reads no row to decide which to change, so `PostgreSQL` applies
/// the `UPDATE` policies to it and not the `SELECT` policies. `can_update` intersects
/// `can_select`, so it is the wrong relation for that one statement shape, and
/// `can_update_without_reading` is the right one.
///
/// The case runs both statements for real and counts the rows where they disagree,
/// failing when none do, so it cannot pass by treating the two alike.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn blanket_update_parity_postgres18_and_openfga() {
    let postgres = GenericImage::new("postgres", "18")
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

    let pg_port = postgres.get_host_port_ipv4(5432).await.unwrap();
    let pg_url = format!("postgres://{PG_USER}:{PG_PASSWORD}@127.0.0.1:{pg_port}/{PG_DB}");
    let mut conn = connect_postgres_with_retry(&pg_url);

    let schema_sql = "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE notes (id TEXT PRIMARY KEY, reader_user_id TEXT NOT NULL REFERENCES users(id), writer_user_id TEXT NOT NULL REFERENCES users(id), body TEXT NOT NULL);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY notes_read ON notes FOR SELECT USING (reader_user_id = auth_current_user_id());
CREATE POLICY notes_write ON notes FOR UPDATE USING (writer_user_id = auth_current_user_id());
";
    conn.batch_execute(schema_sql)
        .expect("Failed to apply the blanket-update schema");
    conn.batch_execute("CREATE ROLE app_user LOGIN; GRANT SELECT, UPDATE ON notes TO app_user;")
        .expect("Failed to create the querying role");

    {
        use blanket_update_schema::notes as bu_notes;
        diesel::insert_into(users::table)
            .values([USER_ALICE, USER_BOB].map(|id| users::id.eq(id)).to_vec())
            .execute(&mut conn)
            .expect("Failed to seed users");
        for (id, reader, writer) in SEEDED_BLANKET_ROWS {
            diesel::insert_into(bu_notes::table)
                .values((
                    bu_notes::id.eq(id),
                    bu_notes::reader_user_id.eq(reader),
                    bu_notes::writer_user_id.eq(writer),
                    bu_notes::body.eq("original"),
                ))
                .execute(&mut conn)
                .expect("Failed to seed a note");
        }
    }

    let registry_json =
        r#"{"auth_current_user_id": {"kind":"current_user_accessor","returns":"text"}}"#;
    let (classified, db, registry) = support::classify_sql(schema_sql, Some(registry_json));
    let outputs = Translation::plan(
        classified,
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps();
    let model = outputs.json_model();
    let tuple_queries = outputs.tuple_queries();

    let openfga = GenericImage::new("openfga/openfga", "v1.11.6")
        .with_exposed_port(8080.tcp())
        .with_exposed_port(8081.tcp())
        .with_wait_for(WaitFor::message_on_stdout("starting HTTP server"))
        .with_cmd(["run"])
        .start()
        .await
        .expect("Failed to start OpenFGA container");

    let grpc_port = openfga.get_host_port_ipv4(8081).await.unwrap();
    let mut service_client = support::openfga::connect(grpc_port).await;
    let store_id =
        support::openfga::create_store(&mut service_client, "blanket-update-parity").await;
    let model_id =
        support::openfga::write_authorization_model(&mut service_client, &store_id, &model).await;
    let client = service_client.into_client(&store_id, &model_id);

    let rows = execute_tuple_queries(&mut conn, &tuple_queries);
    let writes = rows
        .iter()
        .map(|row| support::openfga::make_tuple(&row.object, &row.relation, &row.subject))
        .collect();
    support::openfga::write_tuples(&client, writes).await;

    // Two statements over the same rows: one names a row, one does not.
    let per_row = postgres_rows_a_statement_changed(
        &mut conn,
        "UPDATE notes SET body = 'touched' WHERE id IN \
         ('bu-both', 'bu-write-only', 'bu-read-only', 'bu-neither')",
    );
    let blanket = postgres_rows_a_statement_changed(&mut conn, "UPDATE notes SET body = 'touched'");

    let mut disagreements = 0usize;
    let mut failures = Vec::new();
    for (id, _, _) in SEEDED_BLANKET_ROWS {
        if per_row.contains(id) != blanket.contains(id) {
            disagreements += 1;
        }
        for (relation, expected) in [
            ("can_update", per_row.contains(id)),
            ("can_update_without_reading", blanket.contains(id)),
        ] {
            let actual = support::openfga::check_allowed(
                &client,
                &format!("user:{USER_ALICE}"),
                relation,
                &format!("notes:{id}"),
            )
            .await;
            if expected != actual {
                failures.push(format!(
                    "notes:{id} {relation}: postgres={expected}, openfga={actual}"
                ));
            }
        }
    }

    // Without a row the two statements treat differently, the case would pass against a
    // model that pointed both relations at the same thing.
    assert!(
        disagreements > 0,
        "the two statements changed the same rows, so nothing here separates them: \
         per_row={per_row:?}, blanket={blanket:?}"
    );
    assert!(
        failures.is_empty(),
        "PostgreSQL/OpenFGA blanket update parity mismatches:\n{}",
        failures.join("\n")
    );
}

/// Typed schema for the holder case.
mod holder_schema {
    diesel::table! {
        staff (id) {
            id -> diesel::sql_types::Text,
            user_id -> diesel::sql_types::Text,
        }
    }

    diesel::table! {
        #[sql_name = "docs"]
        holder_docs (id) {
            id -> diesel::sql_types::Text,
        }
    }
}

/// Ids the plain login role can read, with `app.current_user_id` set to `user_id`.
fn postgres_readable_holder_docs(conn: &mut PgConnection, user_id: &str) -> BTreeSet<String> {
    use holder_schema::holder_docs;

    conn.transaction::<BTreeSet<String>, diesel::result::Error, _>(|conn| {
        // Role switching and session settings have no query DSL form.
        diesel::sql_query("SET LOCAL ROLE app_user").execute(conn)?;
        diesel::sql_query("SELECT set_config('app.current_user_id', $1, true)")
            .bind::<Text, _>(user_id)
            .execute(conn)?;
        let ids: Vec<String> = holder_docs::table.select(holder_docs::id).load(conn)?;
        Ok(ids.into_iter().collect())
    })
    .expect("Failed to read the holder docs")
}

/// `EXISTS (SELECT 1 FROM staff WHERE user_id = caller)` never relates the check to the
/// row, so `PostgreSQL` shows a member every row and a non-member none. The model says
/// that through one holder object every row points at.
///
/// The case seeds three rows and two users, one in `staff` and one not, so it fails both
/// on a model that denies the member (the old behaviour) and on one that grants the
/// non-member. It also counts the tuples, because the whole reason for the holder is
/// that they grow as rows plus members rather than rows times members.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn uncorrelated_membership_parity_postgres18_and_openfga() {
    let postgres = GenericImage::new("postgres", "18")
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

    let pg_port = postgres.get_host_port_ipv4(5432).await.unwrap();
    let pg_url = format!("postgres://{PG_USER}:{PG_PASSWORD}@127.0.0.1:{pg_port}/{PG_DB}");
    let mut conn = connect_postgres_with_retry(&pg_url);

    let schema_sql = "
CREATE TABLE staff (id TEXT PRIMARY KEY, user_id TEXT NOT NULL);
CREATE TABLE docs (id TEXT PRIMARY KEY);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_staff ON docs FOR SELECT USING (
    EXISTS (SELECT 1 FROM staff WHERE staff.user_id = auth_current_user_id()));
";
    conn.batch_execute(schema_sql)
        .expect("Failed to apply the holder schema");
    conn.batch_execute("CREATE ROLE app_user LOGIN; GRANT SELECT ON docs, staff TO app_user;")
        .expect("Failed to create the querying role");

    {
        use holder_schema::{holder_docs, staff};
        // Two rows for one member, so a holder that wrote a tuple per membership row
        // rather than per member would show up as a duplicate.
        for (id, user) in [("s-1", USER_ALICE), ("s-2", USER_ALICE)] {
            diesel::insert_into(staff::table)
                .values((staff::id.eq(id), staff::user_id.eq(user)))
                .execute(&mut conn)
                .expect("Failed to seed staff");
        }
        for id in ["d-1", "d-2", "d-3"] {
            diesel::insert_into(holder_docs::table)
                .values(holder_docs::id.eq(id))
                .execute(&mut conn)
                .expect("Failed to seed docs");
        }
    }

    let registry_json =
        r#"{"auth_current_user_id": {"kind":"current_user_accessor","returns":"text"}}"#;
    let (classified, db, registry) = support::classify_sql(schema_sql, Some(registry_json));
    let outputs = Translation::plan(
        classified,
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps();
    let model = outputs.json_model();
    let tuple_queries = outputs.tuple_queries();

    let openfga = GenericImage::new("openfga/openfga", "v1.11.6")
        .with_exposed_port(8080.tcp())
        .with_exposed_port(8081.tcp())
        .with_wait_for(WaitFor::message_on_stdout("starting HTTP server"))
        .with_cmd(["run"])
        .start()
        .await
        .expect("Failed to start OpenFGA container");

    let grpc_port = openfga.get_host_port_ipv4(8081).await.unwrap();
    let mut service_client = support::openfga::connect(grpc_port).await;
    let store_id = support::openfga::create_store(&mut service_client, "holder-parity").await;
    let model_id =
        support::openfga::write_authorization_model(&mut service_client, &store_id, &model).await;
    let client = service_client.into_client(&store_id, &model_id);

    let rows = execute_tuple_queries(&mut conn, &tuple_queries);
    // Three rows plus one member, not three times one: the point of the holder.
    assert_eq!(
        rows.len(),
        4,
        "expected one tuple per row plus one per member, got {rows:#?}"
    );
    let writes = rows
        .iter()
        .map(|row| support::openfga::make_tuple(&row.object, &row.relation, &row.subject))
        .collect();
    support::openfga::write_tuples(&client, writes).await;

    let mut failures = Vec::new();
    let mut granted = 0usize;
    let mut denied = 0usize;
    for user in [USER_ALICE, USER_BOB] {
        let readable = postgres_readable_holder_docs(&mut conn, user);
        for doc in ["d-1", "d-2", "d-3"] {
            let expected = readable.contains(doc);
            if expected {
                granted += 1;
            } else {
                denied += 1;
            }
            let actual = support::openfga::check_allowed(
                &client,
                &format!("user:{user}"),
                "can_select",
                &format!("docs:{doc}"),
            )
            .await;
            if expected != actual {
                failures.push(format!(
                    "docs:{doc} for {user}: postgres={expected}, openfga={actual}"
                ));
            }
        }
    }

    // A model that denied everything, or granted everything, would pass a one-sided case.
    assert!(granted > 0 && denied > 0, "the case needs both answers");
    assert!(
        failures.is_empty(),
        "PostgreSQL/OpenFGA uncorrelated membership parity mismatches:\n{}",
        failures.join("\n")
    );
}

/// Typed schema for the parent-key case.
mod parent_key_schema {
    diesel::table! {
        parent_docs (id) {
            id -> diesel::sql_types::Text,
            owner_id -> diesel::sql_types::Text,
        }
    }

    diesel::table! {
        doc_links (id) {
            id -> diesel::sql_types::Text,
            parent_id -> diesel::sql_types::Text,
        }
    }

    diesel::allow_tables_to_appear_in_same_query!(parent_docs, doc_links);
}

/// Link ids the plain login role can read, with `app.current_user_id` set to `user_id`.
fn postgres_readable_doc_links(conn: &mut PgConnection, user_id: &str) -> BTreeSet<String> {
    use parent_key_schema::doc_links;

    conn.transaction::<BTreeSet<String>, diesel::result::Error, _>(|conn| {
        // Role switching and session settings have no query DSL form.
        diesel::sql_query("SET LOCAL ROLE app_user").execute(conn)?;
        diesel::sql_query("SELECT set_config('app.current_user_id', $1, true)")
            .bind::<Text, _>(user_id)
            .execute(conn)?;
        let ids: Vec<String> = doc_links::table.select(doc_links::id).load(conn)?;
        Ok(ids.into_iter().collect())
    })
    .expect("Failed to read the doc links")
}

/// `parent_id IN (SELECT id FROM parent_docs WHERE <owner>)` names one parent row per
/// child row, so it is parent inheritance rather than a subquery over membership rows.
/// Read the other way it correlates on nothing and grants every link to anyone owning any
/// doc, which is what the model did.
///
/// Two owners with one link each, so the case fails both on a model that grants the link
/// whose parent the caller does not own (the old behaviour) and on one that denies the
/// link they do own (what dropping the parent-inheritance route leaves).
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn parent_key_in_subquery_parity_postgres18_and_openfga() {
    let postgres = GenericImage::new("postgres", "18")
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

    let pg_port = postgres.get_host_port_ipv4(5432).await.unwrap();
    let pg_url = format!("postgres://{PG_USER}:{PG_PASSWORD}@127.0.0.1:{pg_port}/{PG_DB}");
    let mut conn = connect_postgres_with_retry(&pg_url);

    let schema_sql = "
CREATE TABLE parent_docs (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL);
CREATE TABLE doc_links (
    id TEXT PRIMARY KEY,
    parent_id TEXT NOT NULL REFERENCES parent_docs(id)
);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE parent_docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE doc_links ENABLE ROW LEVEL SECURITY;
CREATE POLICY parent_docs_owner ON parent_docs FOR SELECT
    USING (owner_id = auth_current_user_id());
CREATE POLICY doc_links_visible ON doc_links FOR SELECT
    USING (parent_id IN (SELECT id FROM parent_docs WHERE owner_id = auth_current_user_id()));
";
    conn.batch_execute(schema_sql)
        .expect("Failed to apply the parent-key schema");
    conn.batch_execute(
        "CREATE ROLE app_user LOGIN; GRANT SELECT ON parent_docs, doc_links TO app_user;",
    )
    .expect("Failed to create the querying role");

    let links = [("l-alice", USER_ALICE), ("l-bob", USER_BOB)];
    {
        use parent_key_schema::{doc_links, parent_docs};
        for (link, owner) in links {
            let parent = format!("p-{owner}");
            diesel::insert_into(parent_docs::table)
                .values((parent_docs::id.eq(&parent), parent_docs::owner_id.eq(owner)))
                .execute(&mut conn)
                .expect("Failed to seed parent docs");
            diesel::insert_into(doc_links::table)
                .values((doc_links::id.eq(link), doc_links::parent_id.eq(&parent)))
                .execute(&mut conn)
                .expect("Failed to seed doc links");
        }
    }

    let registry_json =
        r#"{"auth_current_user_id": {"kind":"current_user_accessor","returns":"text"}}"#;
    let (classified, db, registry) = support::classify_sql(schema_sql, Some(registry_json));
    let outputs = Translation::plan(
        classified,
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps();
    let model = outputs.json_model();
    let tuple_queries = outputs.tuple_queries();

    let openfga = GenericImage::new("openfga/openfga", "v1.11.6")
        .with_exposed_port(8080.tcp())
        .with_exposed_port(8081.tcp())
        .with_wait_for(WaitFor::message_on_stdout("starting HTTP server"))
        .with_cmd(["run"])
        .start()
        .await
        .expect("Failed to start OpenFGA container");

    let grpc_port = openfga.get_host_port_ipv4(8081).await.unwrap();
    let mut service_client = support::openfga::connect(grpc_port).await;
    let store_id = support::openfga::create_store(&mut service_client, "parent-key-parity").await;
    let model_id =
        support::openfga::write_authorization_model(&mut service_client, &store_id, &model).await;
    let client = service_client.into_client(&store_id, &model_id);

    let rows = execute_tuple_queries(&mut conn, &tuple_queries);
    let writes = rows
        .iter()
        .map(|row| support::openfga::make_tuple(&row.object, &row.relation, &row.subject))
        .collect();
    support::openfga::write_tuples(&client, writes).await;

    let mut failures = Vec::new();
    let mut granted = 0usize;
    let mut denied = 0usize;
    for (_, user) in links {
        let readable = postgres_readable_doc_links(&mut conn, user);
        // One link each, so a seed that made every link visible could not pass quietly.
        assert_eq!(
            readable.len(),
            1,
            "{user} owns one link, PostgreSQL showed {readable:?}"
        );
        for (link, _) in links {
            let expected = readable.contains(link);
            if expected {
                granted += 1;
            } else {
                denied += 1;
            }
            let actual = support::openfga::check_allowed(
                &client,
                &format!("user:{user}"),
                "can_select",
                &format!("doc_links:{link}"),
            )
            .await;
            if expected != actual {
                failures.push(format!(
                    "doc_links:{link} for {user}: postgres={expected}, openfga={actual}"
                ));
            }
        }
    }

    // A model that denied everything, or granted everything, would pass a one-sided case.
    assert!(granted > 0 && denied > 0, "the case needs both answers");
    assert!(
        failures.is_empty(),
        "PostgreSQL/OpenFGA parent-key IN-subquery parity mismatches:\n{}",
        failures.join("\n")
    );
}

/// Typed schema for the read-recursion case. Both foreign keys are nullable, since the
/// two tables reference each other and the rows have to go in one at a time.
mod read_recursion_schema {
    diesel::table! {
        users (id) {
            id -> diesel::sql_types::Text,
        }
    }

    diesel::table! {
        folders (id) {
            id -> diesel::sql_types::Text,
            owner_id -> diesel::sql_types::Text,
            note_id -> diesel::sql_types::Nullable<diesel::sql_types::Text>,
        }
    }

    diesel::table! {
        notes (id) {
            id -> diesel::sql_types::Text,
            owner_id -> diesel::sql_types::Text,
            folder_id -> diesel::sql_types::Nullable<diesel::sql_types::Text>,
        }
    }

    diesel::allow_tables_to_appear_in_same_query!(users, folders, notes);
}

/// Note ids the plain login role reads with `app.current_user_id` set to `user_id`, or
/// `None` when `PostgreSQL` refuses to plan the read. The refusal reason is checked, so a
/// statement broken some other way cannot masquerade as one.
fn postgres_readable_recursive_notes(
    conn: &mut PgConnection,
    user_id: &str,
) -> Option<BTreeSet<String>> {
    use read_recursion_schema::notes;

    let outcome = conn.transaction::<Vec<String>, diesel::result::Error, _>(|conn| {
        // Role switching and session settings have no query DSL form.
        diesel::sql_query("SET LOCAL ROLE app_user").execute(conn)?;
        diesel::sql_query("SELECT set_config('app.current_user_id', $1, true)")
            .bind::<Text, _>(user_id)
            .execute(conn)?;
        notes::table.select(notes::id).load(conn)
    });

    match outcome {
        Ok(ids) => Some(ids.into_iter().collect()),
        Err(error) => {
            let rendered = error.to_string();
            assert!(
                rendered.contains("infinite recursion"),
                "reading notes as {user_id} failed for another reason: {rendered}"
            );
            None
        }
    }
}

/// Two `SELECT` policies reading each other's table make `PostgreSQL` raise on every read
/// of both, so an owner sees nothing of the row they own. The model has to deny to match,
/// which is the one shape where an error and a denial agree.
///
/// Two-sided by construction: a model that keeps the ownership grant, which is what
/// reading each policy on its own produces, grants each owner their own row against a
/// database that returns none, and the seed gives each owner a row so a bad one cannot
/// make it pass quietly.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn read_recursion_parity_postgres18_and_openfga() {
    let postgres = GenericImage::new("postgres", "18")
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

    let pg_port = postgres.get_host_port_ipv4(5432).await.unwrap();
    let pg_url = format!("postgres://{PG_USER}:{PG_PASSWORD}@127.0.0.1:{pg_port}/{PG_DB}");
    let mut conn = connect_postgres_with_retry(&pg_url);

    let schema_sql = support::read_fixture_sql("read_recursion");
    let (classified, db, registry) = support::load_fixture_classified("read_recursion");
    conn.batch_execute(&schema_sql)
        .expect("Failed to apply the read_recursion schema on PostgreSQL 18");
    conn.batch_execute(
        "CREATE ROLE app_user LOGIN; GRANT SELECT ON users, notes, folders TO app_user;",
    )
    .expect("Failed to create the querying role");

    let owners = [USER_ALICE, USER_BOB];
    {
        use read_recursion_schema::{folders, notes, users};
        diesel::insert_into(users::table)
            .values(owners.map(|id| users::id.eq(id)).to_vec())
            .execute(&mut conn)
            .expect("Failed to seed users");
        for owner in owners {
            let folder = format!("f-{owner}");
            let note = format!("n-{owner}");
            diesel::insert_into(folders::table)
                .values((folders::id.eq(&folder), folders::owner_id.eq(owner)))
                .execute(&mut conn)
                .expect("Failed to seed folders");
            diesel::insert_into(notes::table)
                .values((
                    notes::id.eq(&note),
                    notes::owner_id.eq(owner),
                    notes::folder_id.eq(&folder),
                ))
                .execute(&mut conn)
                .expect("Failed to seed notes");
            diesel::update(folders::table.find(&folder))
                .set(folders::note_id.eq(&note))
                .execute(&mut conn)
                .expect("Failed to close the reference loop");
        }
    }

    let outputs = Translation::plan(
        classified,
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps();
    let model = outputs.json_model();
    let tuple_queries = outputs.tuple_queries();

    let openfga = GenericImage::new("openfga/openfga", "v1.11.6")
        .with_exposed_port(8080.tcp())
        .with_exposed_port(8081.tcp())
        .with_wait_for(WaitFor::message_on_stdout("starting HTTP server"))
        .with_cmd(["run"])
        .start()
        .await
        .expect("Failed to start OpenFGA container");

    let grpc_port = openfga.get_host_port_ipv4(8081).await.unwrap();
    let mut service_client = support::openfga::connect(grpc_port).await;
    let store_id =
        support::openfga::create_store(&mut service_client, "read-recursion-parity").await;
    let model_id =
        support::openfga::write_authorization_model(&mut service_client, &store_id, &model).await;
    let client = service_client.into_client(&store_id, &model_id);

    let rows = execute_tuple_queries(&mut conn, &tuple_queries);
    let writes = rows
        .iter()
        .map(|row| support::openfga::make_tuple(&row.object, &row.relation, &row.subject))
        .collect();
    support::openfga::write_tuples(&client, writes).await;

    let mut failures = Vec::new();
    let mut raised = 0usize;
    for owner in owners {
        let readable = postgres_readable_recursive_notes(&mut conn, owner);
        if readable.is_none() {
            raised += 1;
        }
        for other in owners {
            let note = format!("n-{other}");
            let expected = readable
                .as_ref()
                .is_some_and(|ids| ids.contains(note.as_str()));
            let user = format!("user:{owner}");
            let object = format!("notes:{note}");
            let actual =
                support::openfga::check_allowed(&client, &user, "can_select", &object).await;
            if expected != actual {
                failures.push(format!(
                    "{user} can_select {object}: postgres={expected}, openfga={actual}"
                ));
            }
        }
    }

    // Each owner owns a row, so a read that returned rows instead of raising would make
    // the comparison two-sided rather than let it pass quietly.
    assert_eq!(
        raised,
        owners.len(),
        "every read must raise for this case to be the shape it claims"
    );
    assert!(
        failures.is_empty(),
        "PostgreSQL/OpenFGA read-recursion parity mismatches:\n{}",
        failures.join("\n")
    );
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
    let postgres = GenericImage::new("postgres", "18")
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

    let pg_port = postgres.get_host_port_ipv4(5432).await.unwrap();
    let pg_url = format!("postgres://{PG_USER}:{PG_PASSWORD}@127.0.0.1:{pg_port}/{PG_DB}");
    let mut conn = connect_postgres_with_retry(&pg_url);

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

    let openfga = GenericImage::new("openfga/openfga", "v1.11.6")
        .with_exposed_port(8080.tcp())
        .with_exposed_port(8081.tcp())
        .with_wait_for(WaitFor::message_on_stdout("starting HTTP server"))
        .with_cmd(["run"])
        .start()
        .await
        .expect("Failed to start OpenFGA container");

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

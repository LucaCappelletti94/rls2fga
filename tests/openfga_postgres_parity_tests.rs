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
use rls2fga::generator::json_model;
use rls2fga::generator::tuple_generator::{self, TupleQuery};

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

    let model = json_model::generate_json_model(&classified, &db, &registry, ConfidenceLevel::B);
    let tuple_queries =
        tuple_generator::generate_tuple_queries(&classified, &db, &registry, ConfidenceLevel::B);
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

    let model = json_model::generate_json_model(&classified, &db, &registry, ConfidenceLevel::B);
    let tuple_queries =
        tuple_generator::generate_tuple_queries(&classified, &db, &registry, ConfidenceLevel::B);
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

    let model = json_model::generate_json_model(&classified, &db, &registry, ConfidenceLevel::B);
    let tuple_queries =
        tuple_generator::generate_tuple_queries(&classified, &db, &registry, ConfidenceLevel::B);
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
                "member",
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

    let model = json_model::generate_json_model(&classified, &db, &registry, ConfidenceLevel::B);
    let tuple_queries =
        tuple_generator::generate_tuple_queries(&classified, &db, &registry, ConfidenceLevel::B);
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
                "member",
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

    let model = json_model::generate_json_model(&classified, &db, &registry, ConfidenceLevel::B);
    let tuple_queries =
        tuple_generator::generate_tuple_queries(&classified, &db, &registry, ConfidenceLevel::B);
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

    let model = json_model::generate_json_model(&classified, &db, &registry, ConfidenceLevel::B);
    let tuple_queries =
        tuple_generator::generate_tuple_queries(&classified, &db, &registry, ConfidenceLevel::B);
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

#![cfg(not(target_os = "windows"))]

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

use rls2fga::generator::model_generator::GeneratorSettings;
use rls2fga::generator::tuple_generator::TupleQuery;
use rls2fga::translator::Translation;
use rls2fga::types::ConfidenceLevel;
use rls2fga::types::{
    records_from_row, ColumnKind, RecordDerivation, RecordDescription, RowCell, RowList, RowValues,
};

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

    let schema_sql = r#"
CREATE TABLE docs (id TEXT PRIMARY KEY, foo TEXT, "Foo" TIMESTAMPTZ);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_unexpired ON docs FOR SELECT USING ("Foo" > now());
"#;
    conn.batch_execute(schema_sql)
        .expect("Failed to apply the expiring-docs schema");
    conn.batch_execute("CREATE ROLE app_user LOGIN; GRANT SELECT ON docs TO app_user;")
        .expect("Failed to create the querying role");

    let values: Vec<String> = SEEDED_EXPIRING_DOCS
        .iter()
        .map(|(id, expires)| {
            if *expires == "NULL" {
                format!("('{id}', 'text', NULL)")
            } else {
                format!("('{id}', 'text', '{expires}')")
            }
        })
        .collect();
    conn.batch_execute(&format!(
        "INSERT INTO docs (id, foo, \"Foo\") VALUES {};",
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
                postgres_quoted_doc_unexpired_at(&mut conn, doc_id, instant)
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

/// A grace period spelled `now() - interval '30 days'` must survive translation with its
/// offset intact: the condition takes the interval from the request clock as a duration,
/// so a row that expired inside the window still reads as allowed and one past it does
/// not. Bare-clock translation would deny the graced row, so this pins the offset against
/// what `PostgreSQL` itself answers.
#[tokio::test]
#[ignore = "requires Docker: starts PostgreSQL 18 and OpenFGA containers"]
async fn interval_grace_condition_parity_postgres18_and_openfga() {
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
CREATE POLICY docs_grace ON docs FOR SELECT USING (expires_at > now() - interval '30 days');
";
    conn.batch_execute(schema_sql)
        .expect("Failed to apply the grace-period schema");
    conn.batch_execute("CREATE ROLE app_user LOGIN; GRANT SELECT ON docs TO app_user;")
        .expect("Failed to create the querying role");

    // Seeded relative to the run clock: one still valid, one expired inside the 30-day
    // grace, one expired past it, and one with no boundary at all.
    conn.batch_execute(
        "INSERT INTO docs (id, expires_at) VALUES \
         ('g-fresh', now() + interval '5 days'), \
         ('g-grace', now() - interval '10 days'), \
         ('g-stale', now() - interval '40 days'), \
         ('g-null', NULL);",
    )
    .expect("Failed to seed the grace-period docs");
    let seeded = ["g-fresh", "g-grace", "g-stale", "g-null"];

    let (classified, db, registry) = support::classify_sql(schema_sql, None);
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

    let conditional: Vec<&TupleQuery> = tuple_queries
        .iter()
        .filter(|query| query.condition.is_some())
        .collect();
    assert_eq!(
        conditional.len(),
        1,
        "the grace guard must emit exactly one conditional query, got {} queries",
        tuple_queries.len()
    );
    let conditional_rows = execute_conditional_tuple_query(&mut conn, conditional[0]);
    assert_eq!(
        conditional_rows.len(),
        3,
        "every row with a boundary carries a tuple and the NULL row carries none"
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
        support::openfga::create_store(&mut service_client, "interval-grace-parity").await;
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

    let now = postgres_now(&mut conn);
    let later = postgres_a_year_on(&mut conn);

    let mut failures = Vec::new();
    let mut expired_between = 0usize;
    let mut graced = 0usize;
    for (instant, label) in [(now.as_str(), "now"), (later.as_str(), "a year on")] {
        for doc_id in seeded {
            let readable_now = postgres_reads_doc_as_app_user(&mut conn, doc_id);
            let expected = if label == "now" {
                readable_now
            } else {
                postgres_doc_within_grace_at(&mut conn, doc_id, instant)
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
            if label == "now"
                && readable_now
                && !postgres_doc_unexpired_at(&mut conn, doc_id, instant)
            {
                graced += 1;
            }
            if label == "a year on" && readable_now && !expected {
                expired_between += 1;
            }
        }
    }

    // A row already past its own boundary yet still readable proves the 30-day offset is
    // applied: the bare clock would deny it.
    assert!(
        graced > 0,
        "no row is admitted only by the grace window, so the offset proves nothing"
    );
    assert!(
        expired_between > 0,
        "no row loses its grant between the two instants, so the condition proves nothing"
    );
    assert!(
        failures.is_empty(),
        "PostgreSQL/OpenFGA interval-grace condition parity mismatches:\n{}",
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

/// Whether the quoted-column clock guard admits the row at `instant`.
fn postgres_quoted_doc_unexpired_at(conn: &mut PgConnection, doc_id: &str, instant: &str) -> bool {
    let rows: Vec<InstantRow> = diesel::sql_query(
        "SELECT id AS instant FROM docs WHERE id = $1 AND \"Foo\" > $2::timestamptz",
    )
    .bind::<Text, _>(doc_id)
    .bind::<Text, _>(instant)
    .load(conn)
    .expect("evaluating the predicate should succeed");
    !rows.is_empty()
}

/// Whether the grace guard admits the row at `instant`. `PostgreSQL` cannot be asked
/// about the future, so the policy's own predicate with its interval stands in for it.
fn postgres_doc_within_grace_at(conn: &mut PgConnection, doc_id: &str, instant: &str) -> bool {
    let rows: Vec<InstantRow> = diesel::sql_query(
        "SELECT id AS instant FROM docs \
         WHERE id = $1 AND expires_at > $2::timestamptz - interval '30 days'",
    )
    .bind::<Text, _>(doc_id)
    .bind::<Text, _>(instant)
    .load(conn)
    .expect("evaluating the grace predicate should succeed");
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
    .expect("translation should plan")
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

    let rows = execute_tuple_queries(&mut conn, tuple_queries);
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
    .expect("translation should plan")
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

    let rows = execute_tuple_queries(&mut conn, tuple_queries);
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
    .expect("translation should plan")
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

    let rows = execute_tuple_queries(&mut conn, tuple_queries);
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
    .expect("translation should plan")
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

    let rows = execute_tuple_queries(&mut conn, tuple_queries);
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

// ── Phase 3: a value the request carries, against both real services ──────────

/// The connetto rows: one the owner arm admits, one only the subject arm admits, one
/// neither admits, and one whose owner is NULL.
///
/// No empty-string owner, although `PostgreSQL` admits one: the ownership tuple generator
/// renders it as the subject `user:`, which v1.11.6 refuses as malformed, aborting the
/// whole load. That is a defect of its own and is tracked as an open lead rather than
/// folded in here.
const SEEDED_CONNETTO_NOTES: [(i32, Option<&str>); 4] = [
    (1, Some("alice")),
    (2, Some("team-a")),
    (3, Some("bob")),
    (4, None),
];

/// The caller states the phase 2 probes covered, as `(app.user_id, app.subjects)`.
/// `None` means the setting is unset, which is what a caller holding nothing sends.
const CALLER_STATES: [(Option<&str>, Option<&str>); 6] = [
    (None, None),
    (Some("alice"), None),
    (Some("alice"), Some("")),
    (Some("alice"), Some("team-a")),
    (None, Some("team-a")),
    (None, Some("team-a,team-a")),
];

/// Rows a `LOGIN` role reads under one caller state, which is the oracle.
fn notes_visible_to(
    conn: &mut PgConnection,
    user_id: Option<&str>,
    subjects: Option<&str>,
) -> BTreeSet<i32> {
    let mut seen = BTreeSet::new();
    conn.transaction::<_, diesel::result::Error, _>(|conn| {
        conn.batch_execute("SET LOCAL ROLE app_writer")?;
        // `set_config` with NULL leaves the setting unset, which is the state a caller
        // holding nothing is in.
        diesel::sql_query("SELECT set_config('app.user_id', $1, true)")
            .bind::<diesel::sql_types::Nullable<Text>, _>(user_id)
            .execute(conn)?;
        diesel::sql_query("SELECT set_config('app.subjects', $1, true)")
            .bind::<diesel::sql_types::Nullable<Text>, _>(subjects)
            .execute(conn)?;
        let rows: Vec<IdRow> = diesel::sql_query("SELECT id FROM notes ORDER BY id").load(conn)?;
        seen = rows.into_iter().map(|row| row.id).collect();
        Err::<(), _>(diesel::result::Error::RollbackTransaction)
    })
    .ok();
    seen
}

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

/// The `connetto_or_policy` fixture against both services, over the caller states the
/// phase 2 probes covered.
///
/// Two-sided by construction: the case counts the rows only the owner arm admits and the
/// rows only the subject arm admits, and fails when either is zero, so a model keeping
/// one arm cannot pass. It also counts denials, so a model granting everything cannot.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn session_attribute_parity_postgres18_and_openfga() {
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

    let schema_sql = support::read_fixture_sql("connetto_or_policy");
    conn.batch_execute(&schema_sql)
        .expect("Failed to apply the connetto schema on PostgreSQL 18");
    conn.batch_execute("CREATE ROLE app_writer LOGIN; GRANT SELECT ON notes TO app_writer;")
        .expect("Failed to create the querying role");
    let values: Vec<String> = SEEDED_CONNETTO_NOTES
        .iter()
        .map(|(id, owner)| match owner {
            Some(owner) => format!("({id}, '{owner}')"),
            None => format!("({id}, NULL)"),
        })
        .collect();
    conn.batch_execute(&format!(
        "INSERT INTO notes (id, owner) VALUES {};",
        values.join(", ")
    ))
    .expect("Failed to seed the notes");

    let (classified, db, registry) = support::try_load_fixture_classified("connetto_or_policy");
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

    let conditional: Vec<&TupleQuery> = tuple_queries
        .iter()
        .filter(|query| query.condition.is_some())
        .collect();
    assert_eq!(
        conditional.len(),
        1,
        "the declared set emits exactly one conditional query, got {} queries",
        tuple_queries.len()
    );
    let conditional_rows = execute_conditional_tuple_query(&mut conn, conditional[0]);
    assert_eq!(
        conditional_rows.len(),
        3,
        "a NULL owner matches nothing in PostgreSQL, so its row carries no tuple"
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
        support::openfga::create_store(&mut service_client, "session-attribute-parity").await;
    let model_id =
        support::openfga::write_authorization_model(&mut service_client, &store_id, &model).await;

    let mut writes: Vec<openfga_client::client::TupleKey> = conditional_rows
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
    let plain: Vec<TupleQuery> = tuple_queries
        .iter()
        .filter(|query| query.condition.is_none())
        .cloned()
        .collect();
    writes.extend(
        execute_tuple_queries(&mut conn, &plain)
            .iter()
            .map(|key| support::openfga::make_tuple(&key.object, &key.relation, &key.subject)),
    );
    let client = service_client.into_client(&store_id, &model_id);
    support::openfga::write_tuples(&client, writes).await;

    let mut failures = Vec::new();
    let mut owner_only = 0usize;
    let mut subject_only = 0usize;
    let mut denied = 0usize;
    for (user_id, subjects) in CALLER_STATES {
        let visible = notes_visible_to(&mut conn, user_id, subjects);
        // The two arms apart, so the case knows each one carries rows of its own.
        let owner_arm = notes_visible_to(&mut conn, user_id, None);
        let subject_arm = notes_visible_to(&mut conn, None, subjects);
        owner_only += owner_arm.difference(&subject_arm).count();
        subject_only += subject_arm.difference(&owner_arm).count();

        let caller = user_id.unwrap_or("nobody");
        for (id, _) in SEEDED_CONNETTO_NOTES {
            let expected = visible.contains(&id);
            if !expected {
                denied += 1;
            }
            let actual = support::openfga::check_allowed_with_context(
                &client,
                &format!("user:{caller}"),
                "can_select",
                &format!("notes:{id}"),
                serde_json::json!({ "app_subjects": caller_subject_list(subjects) }),
            )
            .await;
            if expected != actual {
                failures.push(format!(
                    "notes:{id} for user_id={user_id:?} subjects={subjects:?}: \
                     postgres={expected}, openfga={actual}"
                ));
            }
        }
    }

    assert!(
        owner_only > 0,
        "no row is readable through the owner arm alone, so keeping only the subject arm would pass"
    );
    assert!(
        subject_only > 0,
        "no row is readable through the subject arm alone, so keeping only the owner arm would pass"
    );
    assert!(
        denied > 0,
        "no row is denied anywhere, so granting everything would pass"
    );
    assert!(
        failures.is_empty(),
        "PostgreSQL/OpenFGA session-attribute parity mismatches:\n{}",
        failures.join("\n")
    );
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

/// Inventory row 3 against both services: a grant recorded on a sharing table, decided
/// by a set the caller carries.
///
/// Two-sided by construction, and both counts come from `papers`: the sharing table's
/// own rows cannot be named until compound identity exists, so exercising them here
/// would prove nothing. The case counts papers readable only by owning them and only by
/// holding a shared key, and fails when either is zero, so a model keeping one arm
/// cannot pass. It counts denials too, so granting everything cannot pass.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn shared_paper_parity_postgres18_and_openfga() {
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

    let schema_sql = support::read_fixture_sql("connetto_capability");
    conn.batch_execute(&schema_sql)
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

    // The share arm gates a per-share object and bridges each paper to it, and
    // `shares_read` gates the share table's own rows. Two conditional queries, plus the
    // plain bridge that links a paper to its shares.
    let runnable: Vec<TupleQuery> = tuple_queries
        .iter()
        .filter(|query| query.sql.contains("SELECT "))
        .cloned()
        .collect();
    let conditional: Vec<&TupleQuery> = runnable
        .iter()
        .filter(|query| query.condition.is_some())
        .collect();
    assert_eq!(
        conditional.len(),
        2,
        "the share arm gates the share objects and shares_read gates the share table, \
         got {} runnable queries",
        runnable.len()
    );
    let share_gate = conditional
        .iter()
        .find(|query| query.sql.contains("'paper_shares_share:'"))
        .expect("the share arm keys its gate on the per-share object");
    assert!(
        runnable.iter().any(|query| query.condition.is_none()
            && query.sql.contains("'papers:'")
            && query.sql.contains("'paper_shares_share:'")),
        "a bridge links each paper to its share objects"
    );
    let share_rows = execute_conditional_tuple_query(&mut conn, share_gate);
    assert_eq!(
        share_rows.len(),
        SEEDED_SHARES.len(),
        "one conditional fact per sharing row, keyed on its own share object"
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
    let store_id = support::openfga::create_store(&mut service_client, "shared-paper-parity").await;
    let model_id =
        support::openfga::write_authorization_model(&mut service_client, &store_id, &model).await;

    let mut writes: Vec<openfga_client::client::TupleKey> = Vec::new();
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
    let plain: Vec<TupleQuery> = runnable
        .iter()
        .filter(|query| query.condition.is_none())
        .cloned()
        .collect();
    writes.extend(
        execute_tuple_queries(&mut conn, &plain)
            .iter()
            .map(|key| support::openfga::make_tuple(&key.object, &key.relation, &key.subject)),
    );
    let client = service_client.into_client(&store_id, &model_id);
    support::openfga::write_tuples(&client, writes).await;

    let mut failures = Vec::new();
    let mut owner_only = 0usize;
    let mut share_only = 0usize;
    let mut denied = 0usize;
    for (user_id, subjects) in PAPER_CALLERS {
        let visible = papers_visible_to(&mut conn, user_id, subjects);
        let owner_arm = papers_visible_to(&mut conn, user_id, None);
        let share_arm = papers_visible_to(&mut conn, None, subjects);
        owner_only += owner_arm.difference(&share_arm).count();
        share_only += share_arm.difference(&owner_arm).count();

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
        owner_only > 0,
        "no paper is readable by owning it alone, so keeping only the share arm would pass"
    );
    assert!(
        share_only > 0,
        "no paper is readable by a shared key alone, so keeping only the owner arm would pass"
    );
    assert!(
        denied > 0,
        "no paper is denied anywhere, so granting everything would pass"
    );
    assert!(
        failures.is_empty(),
        "PostgreSQL/OpenFGA shared-paper parity mismatches:\n{}",
        failures.join("\n")
    );
}

/// A paper shared to two viewers must load and union rather than collide. Keying every
/// share tuple on the paper put both viewers on one `(user:*, gate, papers:1)` triple,
/// which `OpenFGA` rejects as a duplicate write. Each share is now its own object, so the
/// load succeeds and either viewer reaches the paper while a third does not. The reported
/// bug's second half: the load itself is the assertion.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn two_viewers_of_one_paper_load_and_union_parity_postgres18_and_openfga() {
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

/// Rows covering what the jsonb expansion has to get right: a team the claim names, one
/// it does not, a NULL that matches nothing, and a value that looks numeric, since
/// `jsonb_array_elements_text` renders a JSON number as text and so matches it.
const SEEDED_CLAIM_DOCUMENTS: [(i32, Option<&str>); 4] = [
    (1, Some("team-a")),
    (2, Some("team-b")),
    (3, None),
    (4, Some("1")),
];

/// The claim states worth checking, as the raw jsonb `request.jwt.claims` holds.
/// `None` leaves the setting unset, which is what a caller holding no token sends.
const CLAIM_STATES: [Option<&str>; 5] = [
    None,
    Some(r#"{"teams": []}"#),
    Some(r#"{"teams": ["team-a"]}"#),
    Some(r#"{"teams": ["team-a", "team-b"]}"#),
    Some(r#"{"teams": [1]}"#),
];

/// What the caller puts in the check context for a claim carried list.
///
/// The contract is the elements `jsonb_array_elements_text` would produce, which renders
/// a JSON number as its text, and `[]` where the claim is unset.
fn caller_team_list(claims: Option<&str>) -> serde_json::Value {
    let Some(claims) = claims else {
        return serde_json::json!([]);
    };
    let parsed: serde_json::Value = serde_json::from_str(claims).expect("claims should be JSON");
    let teams = parsed.get("teams").and_then(serde_json::Value::as_array);
    serde_json::Value::Array(
        teams
            .map(|values| {
                values
                    .iter()
                    .map(|value| match value {
                        serde_json::Value::String(text) => serde_json::Value::String(text.clone()),
                        other => serde_json::Value::String(other.to_string()),
                    })
                    .collect()
            })
            .unwrap_or_default(),
    )
}

/// Rows a `LOGIN` role reads under one claim state, which is the oracle.
fn claim_documents_visible_to(conn: &mut PgConnection, claims: Option<&str>) -> BTreeSet<i32> {
    let mut seen = BTreeSet::new();
    conn.transaction::<_, diesel::result::Error, _>(|conn| {
        conn.batch_execute("SET LOCAL ROLE app_reader")?;
        // `set_config` is a vendor function the query DSL cannot express, and NULL
        // leaves the setting unset, which is the state a caller with no token is in.
        diesel::sql_query("SELECT set_config('request.jwt.claims', $1, true)")
            .bind::<diesel::sql_types::Nullable<Text>, _>(claims)
            .execute(conn)?;
        seen = claim_documents::table
            .select(claim_documents::id)
            .order(claim_documents::id)
            .load::<i32>(conn)?
            .into_iter()
            .collect();
        Err::<(), _>(diesel::result::Error::RollbackTransaction)
    })
    .ok();
    seen
}

/// Inventory row 6 against both services: the caller's set arrives as a real list inside
/// the token, expanded by `jsonb_array_elements_text`.
///
/// Two sided by construction: the case counts rows admitted and rows denied across the
/// claim states and fails when either is zero, so neither a model that grants everything
/// nor one that grants nothing can pass. The numeric row is what makes the contract's
/// rendering rule load bearing rather than decorative.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn token_claim_set_parity_postgres18_and_openfga() {
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

    conn.batch_execute(&support::read_fixture_sql("token_claim_set"))
        .expect("Failed to apply the token_claim_set schema on PostgreSQL 18");
    conn.batch_execute("CREATE ROLE app_reader LOGIN; GRANT SELECT ON documents TO app_reader;")
        .expect("Failed to create the querying role");
    let seed: Vec<_> = SEEDED_CLAIM_DOCUMENTS
        .iter()
        .map(|(id, team)| {
            (
                claim_documents::id.eq(id),
                claim_documents::team_id.eq(team),
            )
        })
        .collect();
    diesel::insert_into(claim_documents::table)
        .values(&seed)
        .execute(&mut conn)
        .expect("Failed to seed the documents");

    let (classified, db, registry) = support::try_load_fixture_classified("token_claim_set");
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

    let conditional: Vec<&TupleQuery> = tuple_queries
        .iter()
        .filter(|query| query.condition.is_some() && query.sql.contains("documents"))
        .collect();
    assert_eq!(
        conditional.len(),
        1,
        "the guarded table emits exactly one conditional query, got {}",
        conditional.len()
    );
    let conditional_rows = execute_conditional_tuple_query(&mut conn, conditional[0]);
    assert_eq!(
        conditional_rows.len(),
        3,
        "a NULL team matches nothing in PostgreSQL, so its row carries no tuple"
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
    let store_id = support::openfga::create_store(&mut service_client, "token-claim-set").await;
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

    let mut failures = Vec::new();
    let mut admitted = 0usize;
    let mut denied = 0usize;
    for claims in CLAIM_STATES {
        let visible = claim_documents_visible_to(&mut conn, claims);
        for (id, _) in SEEDED_CLAIM_DOCUMENTS {
            let expected = visible.contains(&id);
            if expected {
                admitted += 1;
            } else {
                denied += 1;
            }
            let actual = support::openfga::check_allowed_with_context(
                &client,
                "user:anybody",
                "can_select",
                &format!("documents:{id}"),
                serde_json::json!({ "request_jwt_claims_teams": caller_team_list(claims) }),
            )
            .await;
            if expected != actual {
                failures.push(format!(
                    "documents:{id} for claims={claims:?}: postgres={expected}, openfga={actual}"
                ));
            }
        }
    }

    assert!(
        admitted > 0,
        "no row is readable in any claim state, so a model denying everything would pass"
    );
    assert!(
        denied > 0,
        "no row is denied anywhere, so a model granting everything would pass"
    );
    assert!(
        failures.is_empty(),
        "PostgreSQL/OpenFGA token claim set parity mismatches:\n{}",
        failures.join("\n")
    );
}

/// Typed schema for the correlated-column case. `line_items` carries `sku` and `status`,
/// and only one of them is the column the policy compares.
mod correlated_column_schema {
    diesel::table! {
        orders (id) {
            id -> diesel::sql_types::Text,
            customer_id -> diesel::sql_types::Text,
            status -> diesel::sql_types::Text,
        }
    }

    diesel::table! {
        line_items (id) {
            id -> diesel::sql_types::Text,
            order_id -> diesel::sql_types::Text,
            sku -> diesel::sql_types::Text,
            status -> diesel::sql_types::Text,
        }
    }

    diesel::allow_tables_to_appear_in_same_query!(orders, line_items);
}

/// Line item ids the plain login role reads with `app.current_user_id` set to `user_id`.
fn postgres_readable_line_items(conn: &mut PgConnection, user_id: &str) -> BTreeSet<String> {
    use correlated_column_schema::line_items;

    conn.transaction::<BTreeSet<String>, diesel::result::Error, _>(|conn| {
        // Role switching and session settings have no query DSL form.
        diesel::sql_query("SET LOCAL ROLE app_user").execute(conn)?;
        diesel::sql_query("SELECT set_config('app.current_user_id', $1, true)")
            .bind::<Text, _>(user_id)
            .execute(conn)?;
        let ids: Vec<String> = line_items::table.select(line_items::id).load(conn)?;
        Ok(ids.into_iter().collect())
    })
    .expect("Failed to read the line items")
}

/// `sku IN (SELECT status FROM orders WHERE <owner>)` compares two columns that are
/// spelled differently, and the guarded table carries a `status` of its own. Keyed on
/// the subquery's projection instead of the compared column, the bridge grants each
/// caller the row the other one may read.
///
/// The seed crosses the two values, so a bridge on the wrong column fails in both
/// directions rather than merely widening.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn correlated_column_membership_parity_postgres18_and_openfga() {
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
CREATE TABLE orders (id TEXT PRIMARY KEY, customer_id TEXT NOT NULL, status TEXT NOT NULL);
CREATE TABLE line_items (
    id TEXT PRIMARY KEY,
    order_id TEXT NOT NULL REFERENCES orders(id),
    sku TEXT NOT NULL,
    status TEXT NOT NULL
);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE line_items ENABLE ROW LEVEL SECURITY;
CREATE POLICY line_items_visible ON line_items FOR SELECT
    USING (sku IN (SELECT status FROM orders WHERE customer_id = auth_current_user_id()));
";
    conn.batch_execute(schema_sql)
        .expect("Failed to apply the correlated-column schema");
    conn.batch_execute(
        "CREATE ROLE app_user LOGIN; GRANT SELECT ON orders, line_items TO app_user;",
    )
    .expect("Failed to create the querying role");

    // Each caller owns one order status, and each line item carries the other caller's
    // status in its own `status` column.
    let items = [
        ("li-alice", USER_ALICE, "WIDGET", "GADGET"),
        ("li-bob", USER_BOB, "GADGET", "WIDGET"),
    ];
    {
        use correlated_column_schema::{line_items, orders};
        for (item, customer, sku, status) in items {
            let order = format!("o-{customer}");
            diesel::insert_into(orders::table)
                .values((
                    orders::id.eq(&order),
                    orders::customer_id.eq(customer),
                    orders::status.eq(sku),
                ))
                .execute(&mut conn)
                .expect("Failed to seed orders");
            diesel::insert_into(line_items::table)
                .values((
                    line_items::id.eq(item),
                    line_items::order_id.eq(&order),
                    line_items::sku.eq(sku),
                    line_items::status.eq(status),
                ))
                .execute(&mut conn)
                .expect("Failed to seed line items");
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
    .expect("translation should plan")
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
        support::openfga::create_store(&mut service_client, "correlated-column-parity").await;
    let model_id =
        support::openfga::write_authorization_model(&mut service_client, &store_id, &model).await;
    let client = service_client.into_client(&store_id, &model_id);

    let rows = execute_tuple_queries(&mut conn, tuple_queries);
    let writes = rows
        .iter()
        .map(|row| support::openfga::make_tuple(&row.object, &row.relation, &row.subject))
        .collect();
    support::openfga::write_tuples(&client, writes).await;

    let mut failures = Vec::new();
    let mut granted = 0usize;
    let mut denied = 0usize;
    for (_, user, _, _) in items {
        let readable = postgres_readable_line_items(&mut conn, user);
        // One item each, so a seed that showed every item could not pass quietly.
        assert_eq!(
            readable.len(),
            1,
            "{user} reads one line item, PostgreSQL showed {readable:?}"
        );
        for (item, _, _, _) in items {
            let expected = readable.contains(item);
            if expected {
                granted += 1;
            } else {
                denied += 1;
            }
            let actual = support::openfga::check_allowed(
                &client,
                &format!("user:{user}"),
                "can_select",
                &format!("line_items:{item}"),
            )
            .await;
            if expected != actual {
                failures.push(format!(
                    "line_items:{item} for {user}: postgres={expected}, openfga={actual}"
                ));
            }
        }
    }

    // A model that denied everything, or granted everything, would pass a one-sided case.
    assert!(granted > 0 && denied > 0, "the case needs both answers");
    assert!(
        failures.is_empty(),
        "PostgreSQL/OpenFGA correlated-column membership parity mismatches:\n{}",
        failures.join("\n")
    );
}

mod joined_inner_rule_schema {
    diesel::table! {
        customers (id) {
            id -> diesel::sql_types::Text,
            org_id -> diesel::sql_types::Text,
        }
    }

    diesel::table! {
        orders (id) {
            id -> diesel::sql_types::Text,
            customer_id -> diesel::sql_types::Nullable<diesel::sql_types::Text>,
        }
    }

    diesel::table! {
        line_items (id) {
            id -> diesel::sql_types::Text,
            order_id -> diesel::sql_types::Text,
        }
    }

    diesel::allow_tables_to_appear_in_same_query!(customers, orders, line_items);
}

/// Line item ids the plain login role reads with `app.current_user_id` set to `user_id`.
fn postgres_readable_joined_line_items(conn: &mut PgConnection, user_id: &str) -> BTreeSet<String> {
    use joined_inner_rule_schema::line_items;

    conn.transaction::<BTreeSet<String>, diesel::result::Error, _>(|conn| {
        // Role switching and session settings have no query DSL form.
        diesel::sql_query("SET LOCAL ROLE app_user").execute(conn)?;
        diesel::sql_query("SELECT set_config('app.current_user_id', $1, true)")
            .bind::<Text, _>(user_id)
            .execute(conn)?;
        let ids: Vec<String> = line_items::table.select(line_items::id).load(conn)?;
        Ok(ids.into_iter().collect())
    })
    .expect("Failed to read the line items")
}

/// `WHERE c.id = <caller>` over `ON o.customer_id = c.id` is rewritten into the parent's
/// own column, which is a claim about which rows the database returns and therefore
/// belongs here rather than in a model assertion.
///
/// The seed carries an order whose `customer_id` is NULL, which the join drops and the
/// rewritten filter also drops, and one whose customer is another caller, so a rewrite
/// that lost the comparison would fail in both directions.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn joined_inner_rule_parity_postgres18_and_openfga() {
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
CREATE TABLE customers (id TEXT PRIMARY KEY, org_id TEXT NOT NULL);
CREATE TABLE orders (id TEXT PRIMARY KEY, customer_id TEXT REFERENCES customers(id));
CREATE TABLE line_items (id TEXT PRIMARY KEY, order_id TEXT NOT NULL REFERENCES orders(id));
CREATE FUNCTION auth_current_user_id() RETURNS TEXT
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE line_items ENABLE ROW LEVEL SECURITY;
CREATE POLICY line_items_visible ON line_items FOR SELECT
    USING (order_id IN (SELECT o.id FROM orders o JOIN customers c ON o.customer_id = c.id
                        WHERE c.id = auth_current_user_id()));
";
    conn.batch_execute(schema_sql)
        .expect("Failed to apply the joined-inner-rule schema");
    conn.batch_execute(
        "CREATE ROLE app_user LOGIN; GRANT SELECT ON customers, orders, line_items TO app_user;",
    )
    .expect("Failed to create the querying role");

    {
        use joined_inner_rule_schema::{customers, line_items, orders};
        for user in [USER_ALICE, USER_BOB] {
            diesel::insert_into(customers::table)
                .values((customers::id.eq(user), customers::org_id.eq("acme")))
                .execute(&mut conn)
                .expect("Failed to seed customers");
        }
        // One order per caller, plus an ownerless one the join drops.
        let seeded = [
            ("o-alice", Some(USER_ALICE)),
            ("o-bob", Some(USER_BOB)),
            ("o-none", None),
        ];
        for (order, customer) in seeded {
            diesel::insert_into(orders::table)
                .values((orders::id.eq(order), orders::customer_id.eq(customer)))
                .execute(&mut conn)
                .expect("Failed to seed orders");
            diesel::insert_into(line_items::table)
                .values((
                    line_items::id.eq(format!("li-{order}")),
                    line_items::order_id.eq(order),
                ))
                .execute(&mut conn)
                .expect("Failed to seed line items");
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
    .expect("translation should plan")
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
    let store_id = support::openfga::create_store(&mut service_client, "joined-inner-rule").await;
    let model_id =
        support::openfga::write_authorization_model(&mut service_client, &store_id, &model).await;
    let client = service_client.into_client(&store_id, &model_id);

    let rows = execute_tuple_queries(&mut conn, tuple_queries);
    let writes = rows
        .iter()
        .map(|row| support::openfga::make_tuple(&row.object, &row.relation, &row.subject))
        .collect();
    support::openfga::write_tuples(&client, writes).await;

    let items = ["li-o-alice", "li-o-bob", "li-o-none"];
    let mut failures = Vec::new();
    let (mut granted, mut denied) = (0usize, 0usize);
    for user in [USER_ALICE, USER_BOB] {
        let readable = postgres_readable_joined_line_items(&mut conn, user);
        assert_eq!(
            readable.len(),
            1,
            "{user} reads one line item, PostgreSQL showed {readable:?}"
        );
        for item in items {
            let expected = readable.contains(item);
            if expected {
                granted += 1;
            } else {
                denied += 1;
            }
            let actual = support::openfga::check_allowed(
                &client,
                &format!("user:{user}"),
                "can_select",
                &format!("line_items:{item}"),
            )
            .await;
            if expected != actual {
                failures.push(format!(
                    "line_items:{item} for {user}: postgres={expected}, openfga={actual}"
                ));
            }
        }
    }

    assert!(granted > 0 && denied > 0, "the case needs both answers");
    assert!(
        failures.is_empty(),
        "PostgreSQL/OpenFGA joined-inner-rule parity mismatches:\n{}",
        failures.join("\n")
    );
}

mod partition_schema {
    diesel::table! {
        events (id, region) {
            id -> diesel::sql_types::Text,
            tenant -> diesel::sql_types::Text,
            region -> diesel::sql_types::Text,
        }
    }
}

/// One row of a partition, so the naming entry's key can be rendered against it.
struct PartitionRow {
    id: String,
    region: String,
}

impl RowValues for PartitionRow {
    fn cell(&self, column: &str, kind: ColumnKind) -> RowCell<'_> {
        let value = match column {
            "id" => &self.id,
            "region" => &self.region,
            _ => return RowCell::Absent,
        };
        if kind == ColumnKind::Text {
            RowCell::Text(value.into())
        } else {
            RowCell::Undecodable
        }
    }

    fn list(&self, _column: &str, _kind: ColumnKind) -> RowList<'_> {
        RowList::Absent
    }

    fn json_text(&self, _column: &str, _path: &[String]) -> RowCell<'_> {
        RowCell::Absent
    }
}

/// Event ids the plain login role reads **through the root**, which is how an application
/// reads a partitioned table.
fn postgres_readable_events(conn: &mut PgConnection, user_id: &str) -> BTreeSet<String> {
    use partition_schema::events;

    conn.transaction::<BTreeSet<String>, diesel::result::Error, _>(|conn| {
        // Role switching and session settings have no query DSL form.
        diesel::sql_query("SET LOCAL ROLE app_user").execute(conn)?;
        diesel::sql_query("SELECT set_config('app.current_user_id', $1, true)")
            .bind::<Text, _>(user_id)
            .execute(conn)?;
        let ids: Vec<String> = events::table.select(events::id).load(conn)?;
        Ok(ids.into_iter().collect())
    })
    .expect("Failed to read the events")
}

/// A row of a partition is named after the root, and the service answers about that name
/// as `PostgreSQL` answers a read through the root.
///
/// A change stream delivers the row at the partition, whose own row-level-security flag is
/// off because enabling it on the root does not set it, while the policy and the tuples
/// live on the root. Reading the partition's flag alone says every row is visible, so this
/// is the case that keeps the report from granting rows the database only shows filtered.
///
/// One row per partition, each owned by a different caller, so a model answering from one
/// partition only, or granting everyone, fails in both directions.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn partitioned_table_parity_postgres18_and_openfga() {
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
CREATE TABLE events (id TEXT, tenant TEXT NOT NULL, region TEXT NOT NULL, PRIMARY KEY (id, region))
    PARTITION BY LIST (region);
CREATE TABLE events_eu PARTITION OF events FOR VALUES IN ('eu');
CREATE TABLE events_us PARTITION OF events FOR VALUES IN ('us');
CREATE FUNCTION auth_current_user_id() RETURNS TEXT
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE events ENABLE ROW LEVEL SECURITY;
CREATE POLICY events_visible ON events FOR SELECT USING (tenant = auth_current_user_id());
";
    conn.batch_execute(schema_sql)
        .expect("Failed to apply the partitioned schema");
    conn.batch_execute(
        "CREATE ROLE app_user LOGIN; GRANT SELECT ON events, events_eu, events_us TO app_user;",
    )
    .expect("Failed to create the querying role");

    let seeded = [("e-eu", USER_ALICE, "eu"), ("e-us", USER_BOB, "us")];
    {
        use partition_schema::events;
        for (id, tenant, region) in seeded {
            diesel::insert_into(events::table)
                .values((
                    events::id.eq(id),
                    events::tenant.eq(tenant),
                    events::region.eq(region),
                ))
                .execute(&mut conn)
                .expect("Failed to seed events");
        }
    }

    let registry_json =
        r#"{"auth_current_user_id": {"kind":"current_user_accessor","returns":"text"}}"#;
    let (classified, db, registry) = support::classify_sql(schema_sql, Some(registry_json));
    let translation = Translation::plan(
        classified,
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .expect("translation should plan");

    // The object every question names comes from the report, not from this test.
    let naming = translation.row_naming();
    let mut objects: Vec<(String, String)> = Vec::new();
    for (partition, id, region) in [("events_eu", "e-eu", "eu"), ("events_us", "e-us", "us")] {
        let entry = naming
            .iter()
            .find(|entry| entry.table.to_string() == partition)
            .unwrap_or_else(|| panic!("no naming entry for {partition}, got {naming:?}"));
        assert_eq!(
            entry.type_name, "events",
            "a partition's rows are objects of its root"
        );
        let row = PartitionRow {
            id: id.to_string(),
            region: region.to_string(),
        };
        let object = entry
            .render(&row)
            .expect("the key renders")
            .expect("every key column is filled");
        objects.push((id.to_string(), object));
    }

    let outputs = translation.outputs_accepting_gaps();
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
    let store_id = support::openfga::create_store(&mut service_client, "partitioned-parity").await;
    let model_id =
        support::openfga::write_authorization_model(&mut service_client, &store_id, &model).await;
    let client = service_client.into_client(&store_id, &model_id);

    let rows = execute_tuple_queries(&mut conn, tuple_queries);
    let writes = rows
        .iter()
        .map(|row| support::openfga::make_tuple(&row.object, &row.relation, &row.subject))
        .collect();
    support::openfga::write_tuples(&client, writes).await;

    let mut failures = Vec::new();
    let mut granted = 0usize;
    let mut denied = 0usize;
    for (_, user, _) in seeded {
        let readable = postgres_readable_events(&mut conn, user);
        // One row each, so a seed that showed every row could not pass quietly.
        assert_eq!(
            readable.len(),
            1,
            "{user} reads one event through the root, PostgreSQL showed {readable:?}"
        );
        for (id, object) in &objects {
            let expected = readable.contains(id);
            if expected {
                granted += 1;
            } else {
                denied += 1;
            }
            let actual = support::openfga::check_allowed(
                &client,
                &format!("user:{user}"),
                "can_select",
                object,
            )
            .await;
            if expected != actual {
                failures.push(format!(
                    "{object} for {user}: postgres={expected}, openfga={actual}"
                ));
            }
        }
    }

    // A model that denied everything, or granted everything, would pass a one-sided case.
    assert!(granted > 0 && denied > 0, "the case needs both answers");
    assert!(
        failures.is_empty(),
        "PostgreSQL/OpenFGA partitioned-table parity mismatches:\n{}",
        failures.join("\n")
    );
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

/// The share arm with an expiry: the clock moves into the condition the share row's tuple
/// names, so the row alone decides the record and the store stops answering allowed the
/// instant the clock passes the boundary, with no change event. The reported bug.
///
/// Two-sided across two instants: at now a live share grants and an expired one does not,
/// and a year on every share has expired, so a model ignoring the clock would keep
/// granting the live share and fail.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn expiring_share_condition_parity_postgres18_and_openfga() {
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

    let schema_sql = r"
CREATE TABLE papers (id INT PRIMARY KEY, owner TEXT);
CREATE TABLE paper_shares (
    paper_id INT,
    viewer TEXT,
    expires_at TIMESTAMPTZ,
    PRIMARY KEY (paper_id, viewer)
);
ALTER TABLE papers ENABLE ROW LEVEL SECURITY;
CREATE POLICY papers_p ON papers FOR SELECT USING (
    owner = current_setting('app.user_id', true)
    OR EXISTS (
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
        r#"[
      { "key": "app.user_id", "kind": "caller_id" },
      { "key": "app.subjects", "kind": "set_attribute" }
    ]"#,
    );
    conn.batch_execute(schema_sql)
        .expect("Failed to apply the expiring share schema on PostgreSQL 18");
    conn.batch_execute(
        "CREATE ROLE app_reader LOGIN; \
         GRANT SELECT ON papers TO app_reader; \
         GRANT SELECT ON paper_shares TO app_reader;",
    )
    .expect("Failed to create the querying role");
    // Paper 2 is shared live, paper 3 is shared already expired, paper 1 is only owned.
    conn.batch_execute(
        "INSERT INTO papers (id, owner) VALUES (1, 'alice'), (2, 'bob'), (3, 'bob'); \
         INSERT INTO paper_shares (paper_id, viewer, expires_at) VALUES \
            (2, 'team-a', now() + interval '1 day'), \
            (3, 'team-z', now() - interval '1 day');",
    )
    .expect("Failed to seed the papers and shares");

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
        support::openfga::create_store(&mut service_client, "expiring-share-condition").await;
    let model_id =
        support::openfga::write_authorization_model(&mut service_client, &store_id, &model).await;

    // Load exactly what the loader loads: every query, conditional and plain.
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

    // Two instants: the moment PostgreSQL is at, and a year later. At the second every
    // seeded share has expired, so only the owner arm remains, which PostgreSQL reads
    // with no subjects, since ownership does not depend on the clock.
    let now = postgres_now(&mut conn);
    let later = postgres_a_year_on(&mut conn);
    let callers: [(Option<&str>, Option<&str>); 5] = [
        (None, None),
        (Some("alice"), None),
        (Some("bob"), None),
        (None, Some("team-a")),
        (None, Some("team-z")),
    ];
    let mut failures = Vec::new();
    let mut share_only = 0usize;
    let mut denied = 0usize;
    let mut expired_between = 0usize;
    for (user_id, subjects) in callers {
        let visible_now = papers_visible_to(&mut conn, user_id, subjects);
        let owner_only = papers_visible_to(&mut conn, user_id, None);
        share_only += visible_now.difference(&owner_only).count();
        let caller = user_id.unwrap_or("nobody");
        for id in [1, 2, 3] {
            for (instant, expected_set, label) in [
                (now.as_str(), &visible_now, "now"),
                (later.as_str(), &owner_only, "a year on"),
            ] {
                let expected = expected_set.contains(&id);
                if !expected {
                    denied += 1;
                }
                let actual = support::openfga::check_allowed_with_context(
                    &client,
                    &format!("user:{caller}"),
                    "can_select",
                    &format!("papers:{id}"),
                    serde_json::json!({
                        "app_subjects": caller_subject_list(subjects),
                        "request_time": instant,
                    }),
                )
                .await;
                if expected != actual {
                    failures.push(format!(
                        "papers:{id} for user_id={user_id:?} subjects={subjects:?} at {label}: \
                         postgres={expected}, openfga={actual}"
                    ));
                }
                if label == "a year on" && visible_now.contains(&id) && !expected {
                    expired_between += 1;
                }
            }
        }
    }

    assert!(
        share_only > 0,
        "no paper is readable by a shared key alone, so the share arm carried nothing"
    );
    assert!(
        denied > 0,
        "no paper is denied anywhere, so granting everything would pass"
    );
    assert!(
        expired_between > 0,
        "no paper loses its grant between the two instants, so the clock condition proves \
         nothing"
    );
    assert!(
        failures.is_empty(),
        "PostgreSQL/OpenFGA expiring-share condition parity mismatches:\n{}",
        failures.join("\n")
    );
}

/// The membership arm carries a grace period, `s.expires_at > now() - interval '30 days'`.
/// The offset has to reach the condition and ride the request clock, so a share expired
/// inside the window still grants and one past it does not, two-sided across two instants.
/// The interval's single-table door has parity already. This pins the membership door the
/// same generic path reaches.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn interval_grace_membership_condition_parity_postgres18_and_openfga() {
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

    let schema_sql = r"
CREATE TABLE papers (id INT PRIMARY KEY, owner TEXT);
CREATE TABLE paper_shares (
    paper_id INT,
    viewer TEXT,
    expires_at TIMESTAMPTZ,
    PRIMARY KEY (paper_id, viewer)
);
ALTER TABLE papers ENABLE ROW LEVEL SECURITY;
CREATE POLICY papers_p ON papers FOR SELECT USING (
    owner = current_setting('app.user_id', true)
    OR EXISTS (
        SELECT 1
        FROM paper_shares s
        WHERE s.paper_id = papers.id
          AND s.viewer = ANY(string_to_array(current_setting('app.subjects', true), ','))
          AND s.expires_at > now() - interval '30 days'
    )
);
";
    let (classified, db, registry) = support::classify_sql_with_session_attributes(
        schema_sql,
        r#"[
      { "key": "app.user_id", "kind": "caller_id" },
      { "key": "app.subjects", "kind": "set_attribute" }
    ]"#,
    );
    conn.batch_execute(schema_sql)
        .expect("Failed to apply the grace membership schema on PostgreSQL 18");
    conn.batch_execute(
        "CREATE ROLE app_reader LOGIN; \
         GRANT SELECT ON papers TO app_reader; \
         GRANT SELECT ON paper_shares TO app_reader;",
    )
    .expect("Failed to create the querying role");
    // Paper 2's share expired inside the 30-day grace, paper 3's past it, paper 1 is owned.
    conn.batch_execute(
        "INSERT INTO papers (id, owner) VALUES (1, 'alice'), (2, 'bob'), (3, 'bob'); \
         INSERT INTO paper_shares (paper_id, viewer, expires_at) VALUES \
            (2, 'team-a', now() - interval '10 days'), \
            (3, 'team-z', now() - interval '40 days');",
    )
    .expect("Failed to seed the papers and shares");

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
        support::openfga::create_store(&mut service_client, "interval-grace-membership").await;
    let model_id =
        support::openfga::write_authorization_model(&mut service_client, &store_id, &model).await;

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
    let callers: [(Option<&str>, Option<&str>); 4] = [
        (Some("alice"), None),
        (Some("bob"), None),
        (None, Some("team-a")),
        (None, Some("team-z")),
    ];
    let mut failures = Vec::new();
    let mut share_only = 0usize;
    let mut denied = 0usize;
    let mut graced = 0usize;
    let mut expired_between = 0usize;
    for (user_id, subjects) in callers {
        let visible_now = papers_visible_to(&mut conn, user_id, subjects);
        let owner_only = papers_visible_to(&mut conn, user_id, None);
        share_only += visible_now.difference(&owner_only).count();
        let caller = user_id.unwrap_or("nobody");
        for id in [1, 2, 3] {
            for (instant, expected_set, label) in [
                (now.as_str(), &visible_now, "now"),
                (later.as_str(), &owner_only, "a year on"),
            ] {
                let expected = expected_set.contains(&id);
                if !expected {
                    denied += 1;
                }
                let actual = support::openfga::check_allowed_with_context(
                    &client,
                    &format!("user:{caller}"),
                    "can_select",
                    &format!("papers:{id}"),
                    serde_json::json!({
                        "app_subjects": caller_subject_list(subjects),
                        "request_time": instant,
                    }),
                )
                .await;
                if expected != actual {
                    failures.push(format!(
                        "papers:{id} for user_id={user_id:?} subjects={subjects:?} at {label}: \
                         postgres={expected}, openfga={actual}"
                    ));
                }
                if label == "now" && expected && subjects == Some("team-a") && id == 2 {
                    graced += 1;
                }
                if label == "a year on" && visible_now.contains(&id) && !expected {
                    expired_between += 1;
                }
            }
        }
    }

    // Paper 2's share expired ten days ago yet reads allowed only because the 30-day grace
    // rides the clock: the bare clock would deny it.
    assert!(
        graced > 0,
        "no share is admitted only by the grace window, so the offset proves nothing"
    );
    assert!(
        share_only > 0,
        "no paper is readable by a shared key alone, so the share arm carried nothing"
    );
    assert!(
        denied > 0,
        "no paper is denied anywhere, so granting everything would pass"
    );
    assert!(
        expired_between > 0,
        "no paper loses its grant between the two instants, so the clock proves nothing"
    );
    assert!(
        failures.is_empty(),
        "PostgreSQL/OpenFGA interval-grace membership parity mismatches:\n{}",
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

/// The EXISTS-membership arm with an expiry: the clock rides the member tuple's condition,
/// reached through member-from-parent, so the store stops granting the instant the clock
/// passes the boundary. Two instants prove the flip. A model ignoring the clock keeps the
/// live share and fails.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn expiring_exists_membership_condition_parity_postgres18_and_openfga() {
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
CREATE TABLE docs (id INT PRIMARY KEY);
CREATE TABLE doc_shares (
    doc_id INT,
    user_id TEXT,
    expires_at TIMESTAMPTZ,
    PRIMARY KEY (doc_id, user_id)
);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_p ON docs FOR SELECT USING (
    EXISTS (
        SELECT 1 FROM doc_shares s
        WHERE s.doc_id = docs.id AND s.user_id = current_user AND s.expires_at > now()
    )
);
";
    conn.batch_execute(schema_sql)
        .expect("Failed to apply the expiring EXISTS-membership schema");
    conn.batch_execute(
        "CREATE ROLE alice LOGIN; CREATE ROLE bob LOGIN; \
         GRANT SELECT ON docs, doc_shares TO alice, bob;",
    )
    .expect("Failed to create the querying roles");
    conn.batch_execute(
        "INSERT INTO docs (id) VALUES (1), (2), (3); \
         INSERT INTO doc_shares (doc_id, user_id, expires_at) VALUES \
            (1, 'alice', now() + interval '1 day'), \
            (2, 'bob', now() - interval '1 day'), \
            (3, 'alice', now() + interval '1 day');",
    )
    .expect("Failed to seed the doc shares");

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
    let store_id = support::openfga::create_store(&mut service_client, "expiring-exists").await;
    let model_id =
        support::openfga::write_authorization_model(&mut service_client, &store_id, &model).await;
    let client = service_client.into_client(&store_id, &model_id);
    support::openfga::write_tuples(&client, all_tuple_writes(&mut conn, tuple_queries)).await;

    let now = postgres_now(&mut conn);
    let later = postgres_a_year_on(&mut conn);
    let mut failures = Vec::new();
    let mut granted = 0usize;
    let mut denied = 0usize;
    let mut expired_between = 0usize;
    for role in ["alice", "bob"] {
        let readable_now = readable_ids_as_role(&mut conn, role, "docs");
        for id in [1, 2, 3] {
            for (instant, label) in [(now.as_str(), "now"), (later.as_str(), "a year on")] {
                // Every seeded share expires within a day, so a year on grants nothing.
                let expected = label == "now" && readable_now.contains(&id);
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
                    serde_json::json!({ "request_time": instant }),
                )
                .await;
                if expected != actual {
                    failures.push(format!(
                        "docs:{id} for {role} at {label}: postgres={expected}, openfga={actual}"
                    ));
                }
                if label == "a year on" && readable_now.contains(&id) && !expected {
                    expired_between += 1;
                }
            }
        }
    }
    assert!(
        granted > 0,
        "no live share grants, so the membership arm carried nothing"
    );
    assert!(
        denied > 0,
        "nothing is denied, so granting everything would pass"
    );
    assert!(
        expired_between > 0,
        "no share expires between the instants, so the clock condition proves nothing"
    );
    assert!(
        failures.is_empty(),
        "PostgreSQL/OpenFGA expiring EXISTS-membership parity mismatches:\n{}",
        failures.join("\n")
    );
}

/// The holder (uncorrelated) membership with an expiry over a member table with several
/// rows per user: the clock rides an aggregated member tuple carrying the latest deadline.
/// The aggregation is load-bearing: an expired reviewer row beside a live one must not
/// deny, and one tuple per user is the only shape `OpenFGA` can hold on the one holder.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn expiring_holder_membership_condition_parity_postgres18_and_openfga() {
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
CREATE TABLE memos (id INT PRIMARY KEY);
CREATE TABLE reviewers (user_id TEXT, vetted_at TIMESTAMPTZ);
ALTER TABLE memos ENABLE ROW LEVEL SECURITY;
CREATE POLICY memos_p ON memos FOR SELECT USING (
    EXISTS (
        SELECT 1 FROM reviewers
        WHERE reviewers.user_id = current_user AND reviewers.vetted_at > now()
    )
);
";
    conn.batch_execute(schema_sql)
        .expect("Failed to apply the expiring holder-membership schema");
    conn.batch_execute(
        "CREATE ROLE alice LOGIN; CREATE ROLE bob LOGIN; \
         GRANT SELECT ON memos, reviewers TO alice, bob;",
    )
    .expect("Failed to create the querying roles");
    // Alice has an expired reviewer row and a live one, so her latest deadline is live and
    // the expired row must not deny her. Bob has only an expired row.
    conn.batch_execute(
        "INSERT INTO memos (id) VALUES (1), (2); \
         INSERT INTO reviewers (user_id, vetted_at) VALUES \
            ('alice', now() - interval '1 day'), \
            ('alice', now() + interval '1 day'), \
            ('bob', now() - interval '1 day');",
    )
    .expect("Failed to seed the reviewers");

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
    let store_id = support::openfga::create_store(&mut service_client, "expiring-holder").await;
    let model_id =
        support::openfga::write_authorization_model(&mut service_client, &store_id, &model).await;
    let client = service_client.into_client(&store_id, &model_id);
    support::openfga::write_tuples(&client, all_tuple_writes(&mut conn, tuple_queries)).await;

    let now = postgres_now(&mut conn);
    let later = postgres_a_year_on(&mut conn);
    let mut failures = Vec::new();
    let mut granted = 0usize;
    let mut denied = 0usize;
    let mut expired_between = 0usize;
    for role in ["alice", "bob"] {
        let readable_now = readable_ids_as_role(&mut conn, role, "memos");
        for id in [1, 2] {
            for (instant, label) in [(now.as_str(), "now"), (later.as_str(), "a year on")] {
                let expected = label == "now" && readable_now.contains(&id);
                if expected {
                    granted += 1;
                } else {
                    denied += 1;
                }
                let actual = support::openfga::check_allowed_with_context(
                    &client,
                    &format!("user:{role}"),
                    "can_select",
                    &format!("memos:{id}"),
                    serde_json::json!({ "request_time": instant }),
                )
                .await;
                if expected != actual {
                    failures.push(format!(
                        "memos:{id} for {role} at {label}: postgres={expected}, openfga={actual}"
                    ));
                }
                if label == "a year on" && readable_now.contains(&id) && !expected {
                    expired_between += 1;
                }
            }
        }
    }
    // Alice's latest reviewer row is live, so she reads every memo at now despite her
    // expired row and loses it a year on. Bob's only row is expired, so he reads nothing.
    assert!(
        granted > 0,
        "alice's live latest deadline grants nothing, so the aggregation dropped it"
    );
    assert!(
        denied > 0,
        "nothing is denied, so granting everything would pass"
    );
    assert!(
        expired_between > 0,
        "no memo loses its grant between the instants, so the clock condition proves nothing"
    );
    assert!(
        failures.is_empty(),
        "PostgreSQL/OpenFGA expiring holder-membership parity mismatches:\n{}",
        failures.join("\n")
    );
}

const SAMPLE_1: &str = "00000000-0000-0000-0000-0000000000e1";
const SAMPLE_2: &str = "00000000-0000-0000-0000-0000000000e2";
const SPECTRUM_1: &str = "00000000-0000-0000-0000-0000000000f1";
const SPECTRUM_2: &str = "00000000-0000-0000-0000-0000000000f2";

/// The role one caller holds over the owner named by `column` on one row of `table`, asked
/// of the database itself. A NULL there answers zero, exactly as the function's aggregate
/// does.
///
/// Raw SQL because the answer comes from a schema-defined function over a table and column
/// the caller names, which the typed DSL cannot express. Both names are constants from this
/// file, never input.
fn postgres_role_for_column(
    conn: &mut PgConnection,
    user_id: &str,
    table: &str,
    column: &str,
    row_id: &str,
) -> i32 {
    let row: RoleRow = diesel::sql_query(format!(
        "SELECT get_owner_role($1::text::uuid, {column}) AS role
         FROM {table}
         WHERE id = $2::text::uuid"
    ))
    .bind::<Text, _>(user_id)
    .bind::<Text, _>(row_id)
    .get_result(conn)
    .unwrap();
    row.role
}

/// Two guarded tables reading one role function share the owner the grants are about, so
/// each grant row is one stored fact rather than one per row the owner owns, and both
/// tables answer through it at their own threshold.
///
/// Seeded so the sharing is load-bearing: the granted owners own rows in both tables, so a
/// model that fanned the grants out over rows would write more facts, and a model that
/// pooled the two thresholds would let a viewer read a spectrum.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn shared_owner_grants_parity_postgres18_and_openfga() {
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

    let schema_sql = support::read_fixture_sql("shared_owner_grants");
    let (classified, db, registry) = support::load_fixture_classified("shared_owner_grants");
    conn.batch_execute(&schema_sql)
        .expect("Failed to apply the shared-owner schema on PostgreSQL 18");
    // Seeded as a script: every key here is a `uuid` column and the test driver is built
    // without diesel's uuid feature, so the values cannot be bound through the typed DSL.
    conn.batch_execute(&format!(
        "
INSERT INTO users (id) VALUES
    ('{USER_ALICE}'), ('{USER_BOB}'), ('{USER_CAROL}'), ('{USER_DAVE}'), ('{USER_EVE}');
INSERT INTO teams (id) VALUES ('{TEAM_ALPHA}'), ('{TEAM_BETA}');
INSERT INTO team_members (team_id, user_id) VALUES
    ('{TEAM_ALPHA}', '{USER_BOB}'),
    ('{TEAM_BETA}', '{USER_CAROL}'),
    -- Only in the team holding the viewer grant, so this caller reads a sample and not a
    -- spectrum, which is what one shared ladder answering two thresholds means.
    ('{TEAM_BETA}', '{USER_DAVE}');
INSERT INTO samples (id, owner_id) VALUES
    ('{SAMPLE_1}', '{USER_ALICE}'),
    ('{SAMPLE_2}', '{TEAM_ALPHA}');
INSERT INTO spectra (id, owner_id) VALUES
    ('{SPECTRUM_1}', '{USER_ALICE}'),
    ('{SPECTRUM_2}', '{TEAM_ALPHA}');
INSERT INTO owner_grants (grantee_owner_id, granted_owner_id, role_id) VALUES
    ('{USER_CAROL}', '{USER_ALICE}', 3),
    ('{TEAM_BETA}', '{USER_ALICE}', 2),
    ('{USER_EVE}', '{TEAM_ALPHA}', 4);
"
    ))
    .expect("Failed to seed the shared-owner fixture");

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
    let grant_facts = tuple_keys
        .iter()
        .filter(|tuple| tuple.relation.starts_with("grant_"))
        .count();
    assert_eq!(
        grant_facts, 3,
        "one stored fact per grant row, whatever either table holds: {tuple_keys:#?}"
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
    let store_id = support::openfga::create_store(&mut service_client, "shared-owner-parity").await;
    let model_id =
        support::openfga::write_authorization_model(&mut service_client, &store_id, &model).await;
    let writes: Vec<openfga_client::client::TupleKey> = tuple_keys
        .iter()
        .map(|tuple| support::openfga::make_tuple(&tuple.object, &tuple.relation, &tuple.subject))
        .collect();
    let client = service_client.into_client(&store_id, &model_id);
    support::openfga::write_tuples(&client, writes).await;

    let mut failures = Vec::new();
    let (mut granted, mut denied, mut differed) = (0usize, 0usize, 0usize);
    for user_id in [USER_ALICE, USER_BOB, USER_CAROL, USER_DAVE, USER_EVE] {
        for (table, threshold, rows) in [
            ("samples", 2, [SAMPLE_1, SAMPLE_2]),
            ("spectra", 3, [SPECTRUM_1, SPECTRUM_2]),
        ] {
            for row_id in rows {
                let role = postgres_role_for_column(&mut conn, user_id, table, "owner_id", row_id);
                let expected = role >= threshold;
                let user = format!("user:{user_id}");
                let object = format!("{table}:{row_id}");
                let actual =
                    support::openfga::check_allowed(&client, &user, "can_select", &object).await;
                if expected {
                    granted += 1;
                } else {
                    denied += 1;
                }
                if table == "spectra" && role == 2 {
                    differed += 1;
                }
                if expected != actual {
                    failures.push(format!(
                        "{user} can_select {object}: postgres={expected} (role={role}), \
                         openfga={actual}"
                    ));
                }
            }
        }
    }

    assert!(
        granted > 0,
        "nothing is granted, so denying everything would pass"
    );
    assert!(
        denied > 0,
        "nothing is denied, so granting everything would pass"
    );
    assert!(
        differed > 0,
        "no caller sits between the two thresholds, so one shared ladder proves nothing"
    );
    assert!(
        failures.is_empty(),
        "PostgreSQL/OpenFGA shared-owner parity mismatches:\n{}",
        failures.join("\n")
    );
}

const RECORD_1: &str = "00000000-0000-0000-0000-00000000ee01";
const RECORD_2: &str = "00000000-0000-0000-0000-00000000ee02";

/// One table judged through two owner values, which the translator refused outright before
/// each value got its own pointer.
///
/// Seeded so the two pointers cannot be interchanged: one caller holds the viewer level over
/// the delegate, which the delegate side does not admit, and another holds the admin level
/// over the same delegate, which it does. Reading either side through the other flips both.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn two_owner_columns_parity_postgres18_and_openfga() {
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

    let schema_sql = support::read_fixture_sql("two_owner_columns");
    let (classified, db, registry) = support::load_fixture_classified("two_owner_columns");
    conn.batch_execute(&schema_sql)
        .expect("Failed to apply the two-column schema on PostgreSQL 18");
    // Seeded as a script: every key here is a `uuid` column and the test driver is built
    // without diesel's uuid feature, so the values cannot be bound through the typed DSL.
    conn.batch_execute(&format!(
        "
INSERT INTO users (id) VALUES
    ('{USER_ALICE}'), ('{USER_BOB}'), ('{USER_CAROL}'), ('{USER_DAVE}'), ('{USER_EVE}');
INSERT INTO records (id, owner_id, delegate_id) VALUES
    ('{RECORD_1}', '{USER_ALICE}', '{USER_BOB}'),
    ('{RECORD_2}', '{USER_ALICE}', NULL);
INSERT INTO owner_grants (grantee_owner_id, granted_owner_id, role_id) VALUES
    ('{USER_CAROL}', '{USER_ALICE}', 2),
    -- Viewer over the delegate, which the delegate side does not admit.
    ('{USER_DAVE}', '{USER_BOB}', 2),
    -- Admin over the same delegate, which it does.
    ('{USER_EVE}', '{USER_BOB}', 4);
"
    ))
    .expect("Failed to seed the two-column fixture");

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
    let store_id = support::openfga::create_store(&mut service_client, "two-column-parity").await;
    let model_id =
        support::openfga::write_authorization_model(&mut service_client, &store_id, &model).await;
    let writes: Vec<openfga_client::client::TupleKey> = tuple_keys
        .iter()
        .map(|tuple| support::openfga::make_tuple(&tuple.object, &tuple.relation, &tuple.subject))
        .collect();
    let client = service_client.into_client(&store_id, &model_id);
    support::openfga::write_tuples(&client, writes).await;

    let mut failures = Vec::new();
    let (mut granted, mut denied, mut through_delegate) = (0usize, 0usize, 0usize);
    for user_id in [USER_ALICE, USER_BOB, USER_CAROL, USER_DAVE, USER_EVE] {
        for row_id in [RECORD_1, RECORD_2] {
            let as_owner =
                postgres_role_for_column(&mut conn, user_id, "records", "owner_id", row_id);
            let as_delegate =
                postgres_role_for_column(&mut conn, user_id, "records", "delegate_id", row_id);
            let expected = as_owner >= 2 || as_delegate >= 4;
            let user = format!("user:{user_id}");
            let object = format!("records:{row_id}");
            let actual =
                support::openfga::check_allowed(&client, &user, "can_select", &object).await;
            if expected {
                granted += 1;
            } else {
                denied += 1;
            }
            if expected && as_owner < 2 {
                through_delegate += 1;
            }
            if expected != actual {
                failures.push(format!(
                    "{user} can_select {object}: postgres={expected} \
                     (owner={as_owner}, delegate={as_delegate}), openfga={actual}"
                ));
            }
        }
    }

    assert!(
        granted > 0,
        "nothing is granted, so denying everything would pass"
    );
    assert!(
        denied > 0,
        "nothing is denied, so granting everything would pass"
    );
    assert!(
        through_delegate > 0,
        "nobody reads a row only through its delegate, so the second pointer proves nothing"
    );
    assert!(
        failures.is_empty(),
        "PostgreSQL/OpenFGA two-column parity mismatches:\n{}",
        failures.join("\n")
    );
}

/// Quoted and unquoted role identities stay distinct across role scopes.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn quoted_role_identity_parity_postgres18_and_openfga() {
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

    let schema_sql = r#"
CREATE TABLE docs (id TEXT PRIMARY KEY);
CREATE TABLE memos (id TEXT PRIMARY KEY);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE memos ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT TO admin USING (TRUE);
CREATE POLICY p ON memos FOR SELECT TO "Admin" USING (TRUE);
"#;
    conn.batch_execute(r#"CREATE ROLE admin; CREATE ROLE "Admin";"#)
        .expect("Failed to create the scoped roles");
    conn.batch_execute(schema_sql)
        .expect("Failed to apply the shared policy name schema on PostgreSQL 18");
    conn.batch_execute(
        "INSERT INTO docs (id) VALUES ('d1'); \
         INSERT INTO memos (id) VALUES ('m1');",
    )
    .expect("Failed to seed the guarded rows");

    let readers = [("alice", "admin")];
    for (user, role) in readers {
        conn.batch_execute(&format!(
            "CREATE ROLE {user} LOGIN; \
             GRANT SELECT ON docs TO {user}; \
             GRANT SELECT ON memos TO {user}; \
             GRANT {role} TO {user};"
        ))
        .expect("Failed to create a querying role");
    }

    let (classified, db, registry) = support::classify_sql(schema_sql, None);
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
    let tuple_keys = execute_tuple_queries(&mut conn, planned().tuple_queries());

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
    let store_id = support::openfga::create_store(&mut service_client, "quoted-role-parity").await;
    let model_id =
        support::openfga::write_authorization_model(&mut service_client, &store_id, &model).await;

    let mut writes: Vec<openfga_client::client::TupleKey> = tuple_keys
        .iter()
        .map(|tuple| support::openfga::make_tuple(&tuple.object, &tuple.relation, &tuple.subject))
        .collect();
    // A `TO` clause is `has_privs_of_role`, so the caller's grant is usage of the role.
    for (user, role) in readers {
        writes.push(support::openfga::make_tuple(
            &format!("pg_role:{role}"),
            "usage",
            &format!("user:{user}"),
        ));
    }
    let client = service_client.into_client(&store_id, &model_id);
    support::openfga::write_tuples(&client, writes).await;

    let mut failures = Vec::new();
    for (user, _) in readers {
        for (table, row) in [("docs", "d1"), ("memos", "m1")] {
            let expected = postgres_row_is_visible(&mut conn, user, table, row);
            let actual = support::openfga::check_allowed(
                &client,
                &format!("user:{user}"),
                "can_select",
                &format!("{table}:{row}"),
            )
            .await;
            if expected != actual {
                failures.push(format!(
                    "user:{user} can_select {table}:{row}: postgres={expected}, openfga={actual}"
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "PostgreSQL/OpenFGA quoted role parity mismatches:\n{}",
        failures.join("\n")
    );
}

/// Whether `login_role` sees `row` of `table` under row level security.
///
/// Raw SQL because the table is chosen per case and role switching has no query DSL form.
fn postgres_row_is_visible(
    conn: &mut PgConnection,
    login_role: &str,
    table: &str,
    row: &str,
) -> bool {
    #[derive(QueryableByName)]
    struct Counted {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        rows: i64,
    }

    conn.transaction::<bool, diesel::result::Error, _>(|conn| {
        diesel::sql_query(format!("SET LOCAL ROLE {login_role}")).execute(conn)?;
        let counted: Counted = diesel::sql_query(format!(
            "SELECT count(*) AS rows FROM {table} WHERE id = $1"
        ))
        .bind::<Text, _>(row)
        .get_result(conn)?;
        Ok(counted.rows == 1)
    })
    .expect("reading under row level security should not error")
}

/// Typed schema for the composite-key self-membership case. Both tables key rows by
/// `(tenant_id, <id>)`, and the share table's pair points at the paper's own key.
mod tenant_paper_schema {
    diesel::table! {
        tenant_papers (tenant_id, id) {
            tenant_id -> diesel::sql_types::Text,
            id -> diesel::sql_types::Text,
            title -> diesel::sql_types::Text,
        }
    }

    diesel::table! {
        tenant_shares (tenant_id, paper_id, viewer) {
            tenant_id -> diesel::sql_types::Text,
            paper_id -> diesel::sql_types::Text,
            viewer -> diesel::sql_types::Text,
        }
    }

    diesel::allow_tables_to_appear_in_same_query!(tenant_papers, tenant_shares);
}

/// Paper keys the plain login role reads, with `app.current_user_id` set to `user_id`,
/// rendered as the objects name them.
fn postgres_readable_tenant_papers(conn: &mut PgConnection, user_id: &str) -> BTreeSet<String> {
    use tenant_paper_schema::tenant_papers;

    conn.transaction::<BTreeSet<String>, diesel::result::Error, _>(|conn| {
        // Role switching and session settings have no query DSL form.
        diesel::sql_query("SET LOCAL ROLE app_user").execute(conn)?;
        diesel::sql_query("SELECT set_config('app.current_user_id', $1, true)")
            .bind::<Text, _>(user_id)
            .execute(conn)?;
        let keys: Vec<(String, String)> = tenant_papers::table
            .select((tenant_papers::tenant_id, tenant_papers::id))
            .load(conn)?;
        Ok(keys
            .into_iter()
            .map(|(tenant, id)| format!("{tenant}|{id}"))
            .collect())
    })
    .expect("Failed to read the tenant papers")
}

/// A share joined on both columns of the guarded table's key, the shape the connetto
/// report probed. The two tenants deliberately share one `paper_id`, so a model keyed
/// on either column alone grants each viewer the other tenant's paper and fails in
/// both directions.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn composite_key_self_membership_parity_postgres18_and_openfga() {
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
CREATE TABLE tenant_papers (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    title TEXT NOT NULL,
    PRIMARY KEY (tenant_id, id)
);
CREATE TABLE tenant_shares (
    tenant_id TEXT NOT NULL,
    paper_id TEXT NOT NULL,
    viewer TEXT NOT NULL,
    PRIMARY KEY (tenant_id, paper_id, viewer)
);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE tenant_papers ENABLE ROW LEVEL SECURITY;
CREATE POLICY papers_visible ON tenant_papers FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM tenant_shares s
        WHERE s.tenant_id = tenant_papers.tenant_id
          AND s.paper_id = tenant_papers.id
          AND s.viewer = auth_current_user_id()));
";
    conn.batch_execute(schema_sql)
        .expect("Failed to apply the tenant-paper schema");
    conn.batch_execute(
        "CREATE ROLE app_user LOGIN; GRANT SELECT ON tenant_papers, tenant_shares TO app_user;",
    )
    .expect("Failed to create the querying role");

    // One `paper_id` exists in both tenants, plus one unshared paper.
    let papers = [
        ("t1", "p-shared", "alpha"),
        ("t2", "p-shared", "beta"),
        ("t1", "p-solo", "gamma"),
    ];
    let shares = [("t1", "p-shared", USER_ALICE), ("t2", "p-shared", USER_BOB)];
    {
        use tenant_paper_schema::{tenant_papers, tenant_shares};
        diesel::insert_into(tenant_papers::table)
            .values(
                papers
                    .map(|(tenant, id, title)| {
                        (
                            tenant_papers::tenant_id.eq(tenant),
                            tenant_papers::id.eq(id),
                            tenant_papers::title.eq(title),
                        )
                    })
                    .to_vec(),
            )
            .execute(&mut conn)
            .expect("Failed to seed tenant papers");
        diesel::insert_into(tenant_shares::table)
            .values(
                shares
                    .map(|(tenant, paper, viewer)| {
                        (
                            tenant_shares::tenant_id.eq(tenant),
                            tenant_shares::paper_id.eq(paper),
                            tenant_shares::viewer.eq(viewer),
                        )
                    })
                    .to_vec(),
            )
            .execute(&mut conn)
            .expect("Failed to seed tenant shares");
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
    .expect("translation should plan")
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
        support::openfga::create_store(&mut service_client, "composite-key-self-parity").await;
    let model_id =
        support::openfga::write_authorization_model(&mut service_client, &store_id, &model).await;
    let client = service_client.into_client(&store_id, &model_id);

    let rows = execute_tuple_queries(&mut conn, tuple_queries);
    let writes = rows
        .iter()
        .map(|row| support::openfga::make_tuple(&row.object, &row.relation, &row.subject))
        .collect();
    support::openfga::write_tuples(&client, writes).await;

    let mut failures = Vec::new();
    let mut granted = 0usize;
    let mut denied = 0usize;
    for user in [USER_ALICE, USER_BOB] {
        let readable = postgres_readable_tenant_papers(&mut conn, user);
        // One paper each: the shared id must not leak across tenants.
        assert_eq!(
            readable.len(),
            1,
            "{user} reads one paper, PostgreSQL showed {readable:?}"
        );
        for (tenant, id, _) in papers {
            let key = format!("{tenant}|{id}");
            let expected = readable.contains(&key);
            if expected {
                granted += 1;
            } else {
                denied += 1;
            }
            let actual = support::openfga::check_allowed(
                &client,
                &format!("user:{user}"),
                "can_select",
                &format!("tenant_papers:{key}"),
            )
            .await;
            if expected != actual {
                failures.push(format!(
                    "tenant_papers:{key} for {user}: postgres={expected}, openfga={actual}"
                ));
            }
        }
    }

    // A model that denied everything, or granted everything, would pass a one-sided case.
    assert!(granted > 0 && denied > 0, "the case needs both answers");
    assert!(
        failures.is_empty(),
        "PostgreSQL/OpenFGA composite-key self-membership parity mismatches:\n{}",
        failures.join("\n")
    );
}

/// Typed schema for the composite-FK membership case: docs group under projects keyed
/// by `(tenant_id, id)`, and both `docs` and `project_members` carry a declared
/// composite foreign key onto that whole key.
mod composite_fk_schema {
    diesel::table! {
        projects (tenant_id, id) {
            tenant_id -> diesel::sql_types::Text,
            id -> diesel::sql_types::Text,
        }
    }

    diesel::table! {
        docs (doc_id) {
            doc_id -> diesel::sql_types::Text,
            tenant_id -> diesel::sql_types::Text,
            project_id -> diesel::sql_types::Text,
        }
    }

    diesel::table! {
        project_members (tenant_id, project_id, user_id) {
            tenant_id -> diesel::sql_types::Text,
            project_id -> diesel::sql_types::Text,
            user_id -> diesel::sql_types::Text,
        }
    }

    diesel::allow_tables_to_appear_in_same_query!(projects, docs, project_members);
}

/// Doc ids the plain login role reads, with `app.current_user_id` set to `user_id`.
fn postgres_readable_composite_fk_docs(conn: &mut PgConnection, user_id: &str) -> BTreeSet<String> {
    use composite_fk_schema::docs;

    conn.transaction::<BTreeSet<String>, diesel::result::Error, _>(|conn| {
        // Role switching and session settings have no query DSL form.
        diesel::sql_query("SET LOCAL ROLE app_user").execute(conn)?;
        diesel::sql_query("SELECT set_config('app.current_user_id', $1, true)")
            .bind::<Text, _>(user_id)
            .execute(conn)?;
        let ids: Vec<String> = docs::table.select(docs::doc_id).load(conn)?;
        Ok(ids.into_iter().collect())
    })
    .expect("Failed to read the composite-FK docs")
}

/// The FK route: the membership pairs are the host columns of one declared composite
/// foreign key onto `projects`' whole key. The two tenants share one project id, so a
/// parent keyed on `project_id` alone merges the projects and grants each member the
/// other tenant's doc.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn composite_fk_membership_parity_postgres18_and_openfga() {
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
CREATE TABLE projects (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    PRIMARY KEY (tenant_id, id)
);
CREATE TABLE docs (
    doc_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    FOREIGN KEY (tenant_id, project_id) REFERENCES projects (tenant_id, id)
);
CREATE TABLE project_members (
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    PRIMARY KEY (tenant_id, project_id, user_id),
    FOREIGN KEY (tenant_id, project_id) REFERENCES projects (tenant_id, id)
);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_visible ON docs FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM project_members m
        WHERE m.tenant_id = docs.tenant_id
          AND m.project_id = docs.project_id
          AND m.user_id = auth_current_user_id()));
";
    conn.batch_execute(schema_sql)
        .expect("Failed to apply the composite-FK schema");
    conn.batch_execute(
        "CREATE ROLE app_user LOGIN; \
         GRANT SELECT ON projects, docs, project_members TO app_user;",
    )
    .expect("Failed to create the querying role");

    // One project id exists in both tenants, plus a memberless project.
    let projects = [("t1", "proj"), ("t2", "proj"), ("t1", "proj-empty")];
    let docs = [
        ("doc-t1", "t1", "proj"),
        ("doc-t2", "t2", "proj"),
        ("doc-empty", "t1", "proj-empty"),
    ];
    let members = [("t1", "proj", USER_ALICE), ("t2", "proj", USER_BOB)];
    {
        use composite_fk_schema::{
            docs as docs_table, project_members, projects as projects_table,
        };
        diesel::insert_into(projects_table::table)
            .values(
                projects
                    .map(|(tenant, id)| {
                        (
                            projects_table::tenant_id.eq(tenant),
                            projects_table::id.eq(id),
                        )
                    })
                    .to_vec(),
            )
            .execute(&mut conn)
            .expect("Failed to seed projects");
        diesel::insert_into(docs_table::table)
            .values(
                docs.map(|(doc, tenant, project)| {
                    (
                        docs_table::doc_id.eq(doc),
                        docs_table::tenant_id.eq(tenant),
                        docs_table::project_id.eq(project),
                    )
                })
                .to_vec(),
            )
            .execute(&mut conn)
            .expect("Failed to seed docs");
        diesel::insert_into(project_members::table)
            .values(
                members
                    .map(|(tenant, project, user)| {
                        (
                            project_members::tenant_id.eq(tenant),
                            project_members::project_id.eq(project),
                            project_members::user_id.eq(user),
                        )
                    })
                    .to_vec(),
            )
            .execute(&mut conn)
            .expect("Failed to seed project members");
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
    .expect("translation should plan")
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
    let store_id = support::openfga::create_store(&mut service_client, "composite-fk-parity").await;
    let model_id =
        support::openfga::write_authorization_model(&mut service_client, &store_id, &model).await;
    let client = service_client.into_client(&store_id, &model_id);

    let rows = execute_tuple_queries(&mut conn, tuple_queries);
    let writes = rows
        .iter()
        .map(|row| support::openfga::make_tuple(&row.object, &row.relation, &row.subject))
        .collect();
    support::openfga::write_tuples(&client, writes).await;

    let mut failures = Vec::new();
    let mut granted = 0usize;
    let mut denied = 0usize;
    for user in [USER_ALICE, USER_BOB] {
        let readable = postgres_readable_composite_fk_docs(&mut conn, user);
        // One doc each: the shared project id must not leak across tenants.
        assert_eq!(
            readable.len(),
            1,
            "{user} reads one doc, PostgreSQL showed {readable:?}"
        );
        for (doc, _, _) in docs {
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
        "PostgreSQL/OpenFGA composite-FK membership parity mismatches:\n{}",
        failures.join("\n")
    );
}

mod quoted_residual_schema {
    diesel::table! {
        #[sql_name = "docs"]
        guarded_docs (id) {
            id -> diesel::sql_types::Text,
        }
    }

    diesel::table! {
        memberships (doc_id, user_id) {
            doc_id -> diesel::sql_types::Text,
            user_id -> diesel::sql_types::Text,
        }
    }

    diesel::table! {
        #[sql_name = "Memberships"]
        protected_memberships (doc_id) {
            doc_id -> diesel::sql_types::Text,
        }
    }
}

#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn quoted_nested_membership_parity_postgres18_and_openfga() {
    use quoted_residual_schema::{guarded_docs, memberships, protected_memberships};

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
    let schema_sql = r#"
CREATE TABLE docs(id TEXT PRIMARY KEY);
CREATE TABLE memberships(doc_id TEXT REFERENCES docs(id), user_id TEXT);
CREATE TABLE "Memberships"(doc_id TEXT REFERENCES docs(id));
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE "Memberships" ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_members ON docs FOR SELECT USING (
  EXISTS (
    SELECT 1 FROM memberships m
    WHERE m.doc_id = docs.id
      AND m.user_id = current_user
      AND EXISTS (
        SELECT 1 FROM "Memberships"
      )
  )
);
"#;
    conn.batch_execute(schema_sql)
        .expect("Failed to apply the quoted membership schema");
    conn.batch_execute(
        r#"CREATE ROLE app_reader LOGIN;
           GRANT SELECT ON docs, memberships, "Memberships" TO app_reader;"#,
    )
    .expect("Failed to create the querying role");
    diesel::insert_into(guarded_docs::table)
        .values(guarded_docs::id.eq("d1"))
        .execute(&mut conn)
        .expect("Failed to seed the guarded row");
    diesel::insert_into(memberships::table)
        .values((
            memberships::doc_id.eq("d1"),
            memberships::user_id.eq("app_reader"),
        ))
        .execute(&mut conn)
        .expect("Failed to seed the membership row");
    diesel::insert_into(protected_memberships::table)
        .values(protected_memberships::doc_id.eq("d1"))
        .execute(&mut conn)
        .expect("Failed to seed the protected row");

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
    let tuple_keys = execute_tuple_queries(&mut conn, outputs.tuple_queries());

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
        support::openfga::create_store(&mut service_client, "quoted-membership-parity").await;
    let model_id =
        support::openfga::write_authorization_model(&mut service_client, &store_id, &model).await;
    let client = service_client.into_client(&store_id, &model_id);
    let writes = tuple_keys
        .iter()
        .map(|tuple| support::openfga::make_tuple(&tuple.object, &tuple.relation, &tuple.subject))
        .collect();
    support::openfga::write_tuples(&client, writes).await;

    let expected = conn
        .transaction::<bool, diesel::result::Error, _>(|conn| {
            diesel::sql_query("SET LOCAL ROLE app_reader").execute(conn)?;
            let visible = guarded_docs::table
                .filter(guarded_docs::id.eq("d1"))
                .count()
                .get_result::<i64>(conn)?;
            Ok(visible == 1)
        })
        .expect("reading under row level security should not error");
    let actual =
        support::openfga::check_allowed(&client, "user:app_reader", "can_select", "docs:d1").await;

    assert!(!expected, "the nested protected table must deny the row");
    assert_eq!(actual, expected);
}

#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn quoted_definer_owner_parity_postgres18_and_openfga() {
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
    let schema_sql = r#"
CREATE ROLE actor;
CREATE ROLE "Actor";
CREATE TABLE docs(id TEXT PRIMARY KEY);
CREATE TABLE doc_members(id TEXT PRIMARY KEY, doc_id TEXT REFERENCES docs(id), user_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE doc_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE doc_members OWNER TO actor;
GRANT SELECT ON doc_members TO "Actor";
CREATE FUNCTION is_member(d TEXT) RETURNS BOOLEAN LANGUAGE sql SECURITY DEFINER
SET search_path TO public, pg_temp AS
'SELECT EXISTS (
    SELECT 1 FROM doc_members m
    WHERE m.doc_id = d
      AND m.user_id = current_setting(''app.current_user_id'', true)
)';
ALTER FUNCTION is_member(TEXT) OWNER TO "Actor";
CREATE POLICY docs_members ON docs FOR SELECT USING (is_member(id));
"#;
    conn.batch_execute(schema_sql)
        .expect("Failed to apply the quoted owner schema");
    conn.batch_execute("CREATE ROLE app_reader LOGIN; GRANT SELECT ON docs TO app_reader;")
        .expect("Failed to create the querying role");
    diesel::insert_into(docs::table)
        .values(docs::id.eq("d1"))
        .execute(&mut conn)
        .expect("Failed to seed the guarded row");
    diesel::insert_into(doc_members::table)
        .values((
            doc_members::id.eq("dm1"),
            doc_members::doc_id.eq("d1"),
            doc_members::user_id.eq("app_reader"),
        ))
        .execute(&mut conn)
        .expect("Failed to seed the membership row");

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
    let tuple_keys = execute_tuple_queries(&mut conn, outputs.tuple_queries());

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
        support::openfga::create_store(&mut service_client, "quoted-definer-parity").await;
    let model_id =
        support::openfga::write_authorization_model(&mut service_client, &store_id, &model).await;
    let client = service_client.into_client(&store_id, &model_id);
    let writes = tuple_keys
        .iter()
        .map(|tuple| support::openfga::make_tuple(&tuple.object, &tuple.relation, &tuple.subject))
        .collect();
    support::openfga::write_tuples(&client, writes).await;

    let expected = conn
        .transaction::<bool, diesel::result::Error, _>(|conn| {
            diesel::sql_query("SET LOCAL ROLE app_reader").execute(conn)?;
            diesel::sql_query("SELECT set_config('app.current_user_id', 'app_reader', true)")
                .execute(conn)?;
            let visible = docs::table
                .filter(docs::id.eq("d1"))
                .count()
                .get_result::<i64>(conn)?;
            Ok(visible == 1)
        })
        .expect("reading under row level security should not error");
    let actual =
        support::openfga::check_allowed(&client, "user:app_reader", "can_select", "docs:d1").await;

    assert!(
        !expected,
        "the split function owner must not bypass row level security"
    );
    assert_eq!(actual, expected);
}

mod strict_function_schema {
    diesel::table! {
        #[sql_name = "docs"]
        strict_docs (id) {
            id -> diesel::sql_types::Text,
            gate -> diesel::sql_types::Nullable<diesel::sql_types::Text>,
        }
    }
}

#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn strict_function_null_parity_postgres18_and_openfga() {
    use strict_function_schema::strict_docs;

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
    let schema_sql = r"
CREATE TABLE docs(id TEXT PRIMARY KEY, gate TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION strict_true(value TEXT) RETURNS BOOLEAN LANGUAGE sql STRICT AS
'SELECT true';
CREATE POLICY docs_select ON docs FOR SELECT USING (strict_true(gate));
";
    conn.batch_execute(schema_sql)
        .expect("Failed to apply the strict function schema");
    conn.batch_execute("CREATE ROLE app_reader LOGIN; GRANT SELECT ON docs TO app_reader;")
        .expect("Failed to create the querying role");
    diesel::insert_into(strict_docs::table)
        .values((
            strict_docs::id.eq("d-null"),
            strict_docs::gate.eq(Option::<&str>::None),
        ))
        .execute(&mut conn)
        .expect("Failed to seed the null row");
    diesel::insert_into(strict_docs::table)
        .values((
            strict_docs::id.eq("d-value"),
            strict_docs::gate.eq(Some("present")),
        ))
        .execute(&mut conn)
        .expect("Failed to seed the non-null row");

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
    let tuple_keys = execute_tuple_queries(&mut conn, outputs.tuple_queries());

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
        support::openfga::create_store(&mut service_client, "strict-function-parity").await;
    let model_id =
        support::openfga::write_authorization_model(&mut service_client, &store_id, &model).await;
    let client = service_client.into_client(&store_id, &model_id);
    let writes = tuple_keys
        .iter()
        .map(|tuple| support::openfga::make_tuple(&tuple.object, &tuple.relation, &tuple.subject))
        .collect();
    support::openfga::write_tuples(&client, writes).await;

    let expected = conn
        .transaction::<Vec<String>, diesel::result::Error, _>(|conn| {
            diesel::sql_query("SET LOCAL ROLE app_reader").execute(conn)?;
            strict_docs::table
                .select(strict_docs::id)
                .order(strict_docs::id)
                .load(conn)
        })
        .expect("reading under row level security should not error");
    let mut actual = Vec::new();
    for id in ["d-null", "d-value"] {
        if support::openfga::check_allowed(
            &client,
            "user:app_reader",
            "can_select",
            &format!("docs:{id}"),
        )
        .await
        {
            actual.push(id.to_string());
        }
    }
    actual.sort();

    assert_eq!(expected, vec!["d-value"]);
    assert_eq!(actual, expected);
}

mod registry_function_schema {
    diesel::table! {
        #[sql_name = "docs"]
        registry_docs (id) {
            id -> diesel::sql_types::Text,
            owner_id -> diesel::sql_types::Text,
        }
    }
}

#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn qualified_registry_identity_parity_postgres18_and_openfga() {
    use registry_function_schema::registry_docs;

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
    let schema_sql = r"
CREATE SCHEMA auth;
CREATE SCHEMA other;
CREATE TABLE docs(id TEXT PRIMARY KEY, owner_id TEXT NOT NULL);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION auth.uid() RETURNS TEXT LANGUAGE sql AS
'SELECT current_setting(''app.current_user_id'', true)';
CREATE FUNCTION other.uid() RETURNS TEXT LANGUAGE sql AS
'SELECT ''other_user''::text';
CREATE POLICY docs_select ON docs FOR SELECT USING (owner_id = other.uid());
";
    conn.batch_execute(schema_sql)
        .expect("Failed to apply the qualified registry schema");
    conn.batch_execute("CREATE ROLE app_reader LOGIN; GRANT SELECT ON docs TO app_reader;")
        .expect("Failed to create the querying role");
    diesel::insert_into(registry_docs::table)
        .values((
            registry_docs::id.eq("d1"),
            registry_docs::owner_id.eq("app_reader"),
        ))
        .execute(&mut conn)
        .expect("Failed to seed the guarded row");

    let registry_json = r#"{"auth.uid":{"kind":"current_user_accessor","returns":"text"}}"#;
    let (classified, db, registry) = support::classify_sql(schema_sql, Some(registry_json));
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
    let tuple_keys = execute_tuple_queries(&mut conn, outputs.tuple_queries());

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
        support::openfga::create_store(&mut service_client, "registry-identity-parity").await;
    let model_id =
        support::openfga::write_authorization_model(&mut service_client, &store_id, &model).await;
    let client = service_client.into_client(&store_id, &model_id);
    let writes = tuple_keys
        .iter()
        .map(|tuple| support::openfga::make_tuple(&tuple.object, &tuple.relation, &tuple.subject))
        .collect();
    support::openfga::write_tuples(&client, writes).await;

    let expected = conn
        .transaction::<bool, diesel::result::Error, _>(|conn| {
            diesel::sql_query("SET LOCAL ROLE app_reader").execute(conn)?;
            diesel::sql_query("SELECT set_config('app.current_user_id', 'app_reader', true)")
                .execute(conn)?;
            let visible = registry_docs::table
                .filter(registry_docs::id.eq("d1"))
                .count()
                .get_result::<i64>(conn)?;
            Ok(visible == 1)
        })
        .expect("reading under row level security should not error");
    let actual =
        support::openfga::check_allowed(&client, "user:app_reader", "can_select", "docs:d1").await;

    assert!(!expected);
    assert_eq!(actual, expected);
}

mod function_path_schema {
    diesel::table! {
        docs (id) {
            id -> diesel::sql_types::Text,
        }
    }

    pub(crate) mod a {
        diesel::table! {
            a.doc_members (id) {
                id -> diesel::sql_types::Text,
                doc_id -> diesel::sql_types::Text,
                user_id -> diesel::sql_types::Text,
            }
        }
    }

    pub(crate) mod b {
        diesel::table! {
            b.doc_members (id) {
                id -> diesel::sql_types::Text,
                doc_id -> diesel::sql_types::Text,
                user_id -> diesel::sql_types::Text,
            }
        }
    }
}

#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn function_local_search_path_parity_postgres18_and_openfga() {
    use function_path_schema::{a, b, docs};

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
    let schema_sql = r"
CREATE SCHEMA a;
CREATE SCHEMA b;
CREATE TABLE docs(id TEXT PRIMARY KEY);
CREATE TABLE a.doc_members(
    id TEXT PRIMARY KEY,
    doc_id TEXT NOT NULL REFERENCES public.docs(id),
    user_id TEXT NOT NULL
);
CREATE TABLE b.doc_members(
    id TEXT PRIMARY KEY,
    doc_id TEXT NOT NULL REFERENCES public.docs(id),
    user_id TEXT NOT NULL
);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION public.is_member(d TEXT) RETURNS BOOLEAN LANGUAGE sql
SET search_path TO b, pg_catalog, pg_temp AS
'SELECT EXISTS (SELECT 1 FROM doc_members m WHERE m.doc_id = d AND m.user_id = current_setting(''app.current_user_id'', true))';
CREATE POLICY docs_select ON docs FOR SELECT USING (public.is_member(id));
SET search_path TO a, public;
";
    conn.batch_execute(schema_sql)
        .expect("Failed to apply the function search-path schema");
    conn.batch_execute(
        "CREATE ROLE app_reader LOGIN;
         GRANT USAGE ON SCHEMA b TO app_reader;
         GRANT SELECT ON docs, b.doc_members TO app_reader;",
    )
    .expect("Failed to create the querying role");
    diesel::insert_into(docs::table)
        .values(docs::id.eq("d1"))
        .execute(&mut conn)
        .expect("Failed to seed the guarded row");
    diesel::insert_into(a::doc_members::table)
        .values((
            a::doc_members::id.eq("a1"),
            a::doc_members::doc_id.eq("d1"),
            a::doc_members::user_id.eq("other_user"),
        ))
        .execute(&mut conn)
        .expect("Failed to seed the caller path table");
    diesel::insert_into(b::doc_members::table)
        .values((
            b::doc_members::id.eq("b1"),
            b::doc_members::doc_id.eq("d1"),
            b::doc_members::user_id.eq("app_reader"),
        ))
        .execute(&mut conn)
        .expect("Failed to seed the function path table");

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
    let tuple_keys = execute_tuple_queries(&mut conn, outputs.tuple_queries());

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
        support::openfga::create_store(&mut service_client, "function-search-path-parity").await;
    let model_id =
        support::openfga::write_authorization_model(&mut service_client, &store_id, &model).await;
    let client = service_client.into_client(&store_id, &model_id);
    let writes = tuple_keys
        .iter()
        .map(|tuple| support::openfga::make_tuple(&tuple.object, &tuple.relation, &tuple.subject))
        .collect();
    support::openfga::write_tuples(&client, writes).await;

    let expected = conn
        .transaction::<bool, diesel::result::Error, _>(|conn| {
            diesel::sql_query("SET LOCAL ROLE app_reader").execute(conn)?;
            diesel::sql_query("SELECT set_config('app.current_user_id', 'app_reader', true)")
                .execute(conn)?;
            let visible = docs::table
                .filter(docs::id.eq("d1"))
                .count()
                .get_result::<i64>(conn)?;
            Ok(visible == 1)
        })
        .expect("reading under row level security should not error");
    let actual =
        support::openfga::check_allowed(&client, "user:app_reader", "can_select", "docs:d1").await;

    assert!(expected);
    assert_eq!(actual, expected);
}

mod resolved_membership_schema {
    diesel::table! {
        docs (id) {
            id -> diesel::sql_types::Text,
        }
    }
}

#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn resolved_membership_table_parity_postgres18_and_openfga() {
    use resolved_membership_schema::docs;

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
    let schema_sql = r"
CREATE SCHEMA app;
CREATE TABLE public.docs(id TEXT PRIMARY KEY);
CREATE TABLE app.memberships(doc_id TEXT NOT NULL, user_id TEXT NOT NULL);
CREATE TABLE public.memberships(doc_id TEXT NOT NULL, user_id TEXT NOT NULL);
CREATE ROLE app_reader LOGIN;
GRANT USAGE ON SCHEMA app TO app_reader;
GRANT SELECT ON public.docs, app.memberships, public.memberships TO app_reader;
SET search_path TO app, public;
ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_member ON public.docs FOR SELECT USING (
    EXISTS (SELECT 1 FROM memberships m
        WHERE m.doc_id = docs.id
          AND m.user_id = current_setting('app.current_user_id', true)));
INSERT INTO public.docs VALUES ('d1');
INSERT INTO app.memberships VALUES ('d1', 'other_user');
INSERT INTO public.memberships VALUES ('d1', 'app_reader');
";
    conn.batch_execute(schema_sql)
        .expect("Failed to apply the resolved membership schema");

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
    conn.batch_execute("SET search_path TO public, app")
        .expect("Failed to set the loader path");
    let tuple_keys = execute_tuple_queries(&mut conn, outputs.tuple_queries());

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
        support::openfga::create_store(&mut service_client, "resolved-membership-parity").await;
    let model_id =
        support::openfga::write_authorization_model(&mut service_client, &store_id, &model).await;
    let client = service_client.into_client(&store_id, &model_id);
    let writes = tuple_keys
        .iter()
        .map(|tuple| support::openfga::make_tuple(&tuple.object, &tuple.relation, &tuple.subject))
        .collect();
    support::openfga::write_tuples(&client, writes).await;

    let expected = conn
        .transaction::<bool, diesel::result::Error, _>(|conn| {
            diesel::sql_query("SET LOCAL ROLE app_reader").execute(conn)?;
            diesel::sql_query("SELECT set_config('app.current_user_id', 'app_reader', true)")
                .execute(conn)?;
            let visible = docs::table
                .filter(docs::id.eq("d1"))
                .count()
                .get_result::<i64>(conn)?;
            Ok(visible == 1)
        })
        .expect("reading under row level security should not error");
    let actual =
        support::openfga::check_allowed(&client, "user:app_reader", "can_select", "docs:d1").await;

    assert!(!expected);
    assert_eq!(actual, expected);
}

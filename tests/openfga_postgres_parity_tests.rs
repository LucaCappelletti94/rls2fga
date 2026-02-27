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

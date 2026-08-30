#![cfg(not(target_os = "windows"))]
//! Every fixture applied to a real `PostgreSQL` 18, dumped with `pg_dump -s`, and
//! the dump translated again: the model must match the fixture's own byte for
//! byte, and the tuple SQL must return the same rows, so a dumped production
//! schema translates exactly as the handwritten spelling does. This is the
//! standing form of the harness that found the upstream parser gaps, so a
//! regression in any of them fails here.

use std::collections::BTreeSet;
use std::thread;
use std::time::Duration;

use diesel::connection::SimpleConnection;
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::sql_types::Text;
use testcontainers::{
    core::{CmdWaitFor, ExecCommand, IntoContainerPort, WaitFor},
    runners::AsyncRunner,
    ContainerAsync, GenericImage, ImageExt,
};

use rls2fga::generator::tuple_generator::TupleQuery;
use rls2fga::parser::sql_parser::{parse_schema, ParserDB};
use rls2fga::translator::TranslatorBuilder;
use rls2fga::types::ConfidenceLevel;

mod support;

const PG_USER: &str = "postgres";
const PG_PASSWORD: &str = "postgres";
const PG_DB: &str = "rls2fga";

/// Fixtures whose dump cannot parse yet, each waiting on a named sqlparser
/// gap. An entry whose dump starts parsing fails the run, which is the signal
/// to promote it into the round trip.
const DUMP_BLOCKED_ON_SQLPARSER: [(&str, &str); 2] = [
    (
        "current_user_equality",
        "a SERIAL key dumps as CREATE SEQUENCE options in an order sqlparser #2414 \
         refuses, and as ALTER SEQUENCE, which is not an ALTER target upstream at all",
    ),
    (
        "schema_objects",
        "the declared type dumps as ALTER TYPE ... OWNER TO, and OWNER TO is gated to \
         the table target upstream, the unfiled owner-to-uneven finding",
    ),
];
/// Roles fixture policies name in `TO` clauses, which must exist before
/// `CREATE POLICY` runs.
const FIXTURE_ROLES: [&str; 4] = ["auditor", "contractor", "editors", "app"];

/// Roles a fixture creates itself, which must be absent when it applies.
const CREATES_ROLES: [(&str, &str); 1] = [("schema_objects", "auditor")];

fn connect_with_retry(database_url: &str) -> PgConnection {
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

/// The model and tuple queries one schema translates to under the fixture's
/// own registry and declared session attributes.
fn artifacts(db: &ParserDB, fixture: &str) -> (String, Vec<TupleQuery>) {
    let outputs = TranslatorBuilder::new()
        .with_min_confidence(ConfidenceLevel::B)
        .with_registry(support::try_load_fixture_registry(fixture))
        .build()
        .translate(db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let tuples = outputs.tuple_queries().to_vec();
    (outputs.model(), tuples)
}

#[derive(QueryableByName, PartialEq, Eq, PartialOrd, Ord)]
struct TupleRow {
    #[diesel(sql_type = Text)]
    object: String,
    #[diesel(sql_type = Text)]
    relation: String,
    #[diesel(sql_type = Text)]
    subject: String,
}

/// Every `(object, relation, subject)` the queries return against the live
/// schema. Two spellings of one schema must return one set.
fn executed_rows(
    conn: &mut PgConnection,
    queries: &[TupleQuery],
) -> BTreeSet<(String, String, String)> {
    let mut keys = BTreeSet::new();
    for query in queries {
        // The generated SQL is the artifact under test, so it runs verbatim.
        let rows: Vec<TupleRow> =
            diesel::sql_query(&query.sql)
                .load(conn)
                .unwrap_or_else(|error| {
                    panic!("tuple SQL failed on PostgreSQL 18: {error}\n{}", query.sql)
                });
        keys.extend(
            rows.into_iter()
                .map(|row| (row.object, row.relation, row.subject)),
        );
    }
    keys
}

/// `pg_dump -s` of one database, run inside the server's own container so the
/// client version always matches the server's.
async fn dump_schema(container: &ContainerAsync<GenericImage>, database: &str) -> String {
    let mut result = container
        .exec(
            ExecCommand::new(["pg_dump", "--schema-only", "-U", PG_USER, database])
                .with_cmd_ready_condition(CmdWaitFor::exit()),
        )
        .await
        .expect("pg_dump should run inside the container");
    let stdout = result
        .stdout_to_vec()
        .await
        .expect("pg_dump output should be readable");
    String::from_utf8(stdout).expect("pg_dump emits UTF-8")
}

/// Drop the psql meta-commands a dump carries (`\restrict`, `\unrestrict`,
/// `\connect`), which are commands to psql rather than SQL.
fn strip_meta_commands(dump: &str) -> String {
    dump.lines()
        .filter(|line| !line.trim_start().starts_with('\\'))
        .collect::<Vec<_>>()
        .join("\n")
}

fn first_divergence(fixture_side: &str, dump_side: &str) -> String {
    for (index, (fixture_line, dump_line)) in
        fixture_side.lines().zip(dump_side.lines()).enumerate()
    {
        if fixture_line != dump_line {
            return format!(
                "line {}: fixture `{fixture_line}` vs dump `{dump_line}`",
                index + 1
            );
        }
    }
    format!(
        "one side continues past the other: fixture {} lines, dump {}",
        fixture_side.lines().count(),
        dump_side.lines().count()
    )
}

fn fixture_names() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir("tests/fixtures")
        .expect("fixtures directory should be readable")
        .filter_map(|entry| {
            let entry = entry.expect("fixture entry should be readable");
            entry
                .file_type()
                .expect("fixture entry type should be readable")
                .is_dir()
                .then(|| entry.file_name().to_string_lossy().into_owned())
        })
        .collect();
    names.sort();
    names
}

#[tokio::test]
#[ignore = "requires Docker and the postgres:18 container"]
async fn every_fixture_round_trips_through_pg_dump() {
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
    let admin_url = format!("postgres://{PG_USER}:{PG_PASSWORD}@127.0.0.1:{pg_port}/{PG_DB}");
    let mut admin = connect_with_retry(&admin_url);

    let mut failures = Vec::new();
    let mut round_tripped = 0usize;
    for fixture in fixture_names() {
        let fixture = fixture.as_str();
        // A fixture that creates a role itself must find it absent, and every
        // other fixture must find the shared roles present. Databases are
        // dropped after use, so the drop below never has dependents.
        for role in FIXTURE_ROLES {
            let owned_by_fixture = CREATES_ROLES
                .iter()
                .any(|(name, owned)| *name == fixture && *owned == role);
            let statement = if owned_by_fixture {
                format!("DROP ROLE IF EXISTS {role}")
            } else {
                format!(
                    "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = \
                     '{role}') THEN CREATE ROLE {role}; END IF; END $$"
                )
            };
            admin
                .batch_execute(&statement)
                .expect("Failed to prepare a fixture role");
        }
        let database = format!("rt_{fixture}");
        admin
            .batch_execute(&format!("CREATE DATABASE {database}"))
            .expect("Failed to create a fixture database");
        let fixture_url =
            format!("postgres://{PG_USER}:{PG_PASSWORD}@127.0.0.1:{pg_port}/{database}");
        let mut conn = connect_with_retry(&fixture_url);
        // The Supabase fixtures declare functions under `auth` without creating it,
        // exactly as their deployments find it already present.
        conn.batch_execute("CREATE SCHEMA IF NOT EXISTS auth")
            .expect("Failed to create the auth schema");

        if let Err(error) = conn.batch_execute(&support::read_fixture_sql(fixture)) {
            failures.push(format!(
                "{fixture}: failed to apply on PostgreSQL 18: {error}"
            ));
            continue;
        }

        let dump = format!(
            "CREATE ROLE {PG_USER};\n{}",
            strip_meta_commands(&dump_schema(&postgres, &database).await)
        );
        let parsed = parse_schema(&dump);
        let verdict = if let Some((_, reason)) = DUMP_BLOCKED_ON_SQLPARSER
            .iter()
            .find(|(name, _)| *name == fixture)
        {
            match parsed {
                Err(_) => None,
                Ok(_) => Some(format!(
                    "{fixture}: its dump now parses, so promote it into the round \
                     trip (was blocked: {reason})"
                )),
            }
        } else {
            match parsed {
                Err(error) => Some(format!("{fixture}: its dump does not parse: {error}")),
                Ok(dumped_db) => {
                    let fixture_db = support::parse_fixture_db(fixture);
                    let (fixture_model, fixture_tuples) = artifacts(&fixture_db, fixture);
                    let (dump_model, dump_tuples) = artifacts(&dumped_db, fixture);
                    if fixture_model != dump_model {
                        Some(format!(
                            "{fixture}: the dumped model diverges: {}",
                            first_divergence(&fixture_model, &dump_model)
                        ))
                    } else if executed_rows(&mut conn, &fixture_tuples)
                        != executed_rows(&mut conn, &dump_tuples)
                    {
                        Some(format!(
                            "{fixture}: the dumped tuple SQL returns different rows"
                        ))
                    } else {
                        round_tripped += 1;
                        None
                    }
                }
            }
        };
        failures.extend(verdict);
        drop(conn);
        admin
            .batch_execute(&format!("DROP DATABASE {database}"))
            .expect("Failed to drop a fixture database");
    }

    assert!(
        failures.is_empty(),
        "pg_dump round trip divergences:\n{}",
        failures.join("\n")
    );
    assert!(
        round_tripped >= 40,
        "only {round_tripped} fixtures round tripped, so the walk went vacuous"
    );
}

//! One runner for every `PostgreSQL` and `OpenFGA` parity case.
//!
//! A case declares data: a schema, a seed, the principals and the rows a write would
//! attempt. Which relations answer which statement, and how a row is named as an object,
//! come from the translation itself, so no case repeats that analysis.
//!
//! The comparison is the full cross product of principal, object and statement, in both
//! directions, so a case cannot check only the pairs its author thought of.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use diesel::connection::SimpleConnection;
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::sql_types::Jsonb;

use rls2fga::generator::model_generator::GeneratorSettings;
use rls2fga::translator::Translation;
use rls2fga::types::{
    ActionAnswer, ActionRelations, ActionStatement, ConfidenceLevel, RowNaming, RowVersion,
    ValueSource,
};

use super::openfga;

/// One caller, on both sides.
///
/// Nothing in the translation says which database role a subject is, which session values
/// it sets, or which roles it holds, so a case says.
pub(crate) struct Principal {
    /// Subject key, asked about as `user:<subject>`.
    pub(crate) subject: String,
    /// Role the reading transaction switches to.
    pub(crate) login_role: String,
    /// `set_config` values the policies read, applied local to the transaction.
    pub(crate) session: Vec<(String, String)>,
    /// Request context every check carries.
    pub(crate) context: serde_json::Value,
    /// `pg_role` memberships the caller holds, which no tuple query can know.
    pub(crate) pg_roles: Vec<String>,
}

impl Principal {
    /// A caller identified by one session setting, the ordinary shape.
    pub(crate) fn with_setting(subject: &str, login_role: &str, key: &str, value: &str) -> Self {
        Self {
            subject: subject.to_string(),
            login_role: login_role.to_string(),
            session: vec![(key.to_string(), value.to_string())],
            context: serde_json::json!({}),
            pg_roles: Vec::new(),
        }
    }

    /// A caller identified by its database role alone.
    pub(crate) fn as_role(subject: &str, login_role: &str) -> Self {
        Self {
            subject: subject.to_string(),
            login_role: login_role.to_string(),
            session: Vec::new(),
            context: serde_json::json!({}),
            pg_roles: Vec::new(),
        }
    }

    /// The same caller, holding `roles`.
    pub(crate) fn holding(mut self, roles: &[&str]) -> Self {
        self.pg_roles = roles.iter().map(|role| (*role).to_string()).collect();
        self
    }
}

/// What a write would attempt on one table.
///
/// A no-op `UPDATE` exercises `USING` and never `WITH CHECK`, so the new row is named. An
/// `INSERT` needs a row that does not collide with a seeded key.
#[derive(Default)]
pub(crate) struct Mutations {
    /// `SET` clause an `UPDATE` applies, such as `title = 'changed'`.
    pub(crate) update_set: Option<String>,
    /// Column list and values an `INSERT` attempts, such as `("id") VALUES ('new')`.
    pub(crate) insert: Option<String>,
}

/// One case, as data.
pub(crate) struct ParityCase {
    /// Store name, and the label failures carry.
    pub(crate) name: String,
    /// Statements run before the schema, for roles a policy names.
    pub(crate) prelude: Vec<String>,
    /// The schema under test.
    pub(crate) schema: String,
    /// Rows and grants applied after it.
    pub(crate) seed: Vec<String>,
    /// The callers to compare.
    pub(crate) principals: Vec<Principal>,
    /// Per table, keyed by the schema spelling, what a write would attempt.
    pub(crate) mutations: BTreeMap<String, Mutations>,
}

impl ParityCase {
    /// A case with no prelude and no writes.
    pub(crate) fn reading(
        name: &str,
        schema: &str,
        seed: &[&str],
        principals: Vec<Principal>,
    ) -> Self {
        Self {
            name: name.to_string(),
            prelude: Vec::new(),
            schema: schema.to_string(),
            seed: seed.iter().map(|sql| (*sql).to_string()).collect(),
            principals,
            mutations: BTreeMap::new(),
        }
    }

    /// The same case, with statements applied before the schema.
    pub(crate) fn after(mut self, prelude: &[&str]) -> Self {
        self.prelude = prelude.iter().map(|sql| (*sql).to_string()).collect();
        self
    }

    /// The same case, with what a write on `table` would attempt.
    pub(crate) fn writing(mut self, table: &str, mutations: Mutations) -> Self {
        self.mutations.insert(table.to_string(), mutations);
        self
    }
}

/// One disagreement, named so a failure says which pair it was.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Mismatch {
    /// The caller.
    pub(crate) subject: String,
    /// The object, as the model names it.
    pub(crate) object: String,
    /// The statement compared.
    pub(crate) statement: ActionStatement,
    /// What the database answered.
    pub(crate) postgres: bool,
    /// What the model answered.
    pub(crate) openfga: bool,
}

impl std::fmt::Display for Mismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "user:{} {:?} {}: postgres={}, openfga={}",
            self.subject, self.statement, self.object, self.postgres, self.openfga
        )
    }
}

/// The statements the runner compares, in the order a failure reports them.
const COMPARED: [ActionStatement; 4] = [
    ActionStatement::Select,
    ActionStatement::SelectForUpdate,
    ActionStatement::Update,
    ActionStatement::Delete,
];

#[derive(QueryableByName)]
struct JsonRow {
    #[diesel(sql_type = Jsonb)]
    row: serde_json::Value,
}

#[derive(QueryableByName)]
struct Counted {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    rows: i64,
}

/// One object of one table: how it is named, and the predicate that selects its row.
struct Object {
    name: String,
    table: String,
    predicate: String,
}

/// The key columns a table's objects are named from, or [`None`] where a column does not
/// name them.
fn key_columns(naming: &RowNaming) -> Option<Vec<&str>> {
    naming
        .key
        .parts()
        .iter()
        .map(|part| match part {
            ValueSource::Column(column) => Some(column.as_str()),
            _ => None,
        })
        .collect()
}

/// Every object the model names, read as the owner so row-level security does not filter
/// the enumeration.
fn objects(conn: &mut PgConnection, naming: &[RowNaming]) -> Vec<Object> {
    let mut out = Vec::new();
    for entry in naming {
        let Some(columns) = key_columns(entry) else {
            continue;
        };
        let table = entry.table.sql_name();
        let rows: Vec<JsonRow> =
            diesel::sql_query(format!("SELECT to_jsonb(t) AS row FROM {table} t"))
                .load(conn)
                .unwrap_or_else(|error| panic!("reading {table} as its owner: {error}"));
        for JsonRow { row } in rows {
            let Ok(Some(name)) = entry.render(&super::JsonRowValues(&row)) else {
                continue;
            };
            let mut predicate = String::new();
            for (at, column) in columns.iter().enumerate() {
                let value = row
                    .get(*column)
                    .and_then(super::scalar_text)
                    .unwrap_or_default();
                let joiner = if at == 0 { "" } else { " AND " };
                let _ = write!(
                    predicate,
                    "{joiner}\"{column}\"::text = '{}'",
                    value.replace('\'', "''")
                );
            }
            out.push(Object {
                name,
                table: table.clone(),
                predicate,
            });
        }
    }
    out
}

/// Switch to the caller's role and apply its session values, local to the transaction.
fn become_principal(conn: &mut PgConnection, principal: &Principal) -> QueryResult<()> {
    diesel::sql_query(format!("SET LOCAL ROLE {}", principal.login_role)).execute(conn)?;
    for (key, value) in &principal.session {
        diesel::sql_query("SELECT set_config($1, $2, true)")
            .bind::<diesel::sql_types::Text, _>(key)
            .bind::<diesel::sql_types::Text, _>(value)
            .execute(conn)?;
    }
    Ok(())
}

/// Whether the database lets `principal` reach `object` with `statement`.
///
/// Every write runs inside a savepoint and is rolled back, so one probe cannot decide the
/// next. [`None`] where the case declared no row for the write to attempt.
fn postgres_allows(
    conn: &mut PgConnection,
    case: &ParityCase,
    principal: &Principal,
    object: &Object,
    statement: ActionStatement,
) -> Option<bool> {
    let table = &object.table;
    let predicate = &object.predicate;
    let sql = match statement {
        ActionStatement::Select => {
            format!("SELECT count(*) AS rows FROM {table} WHERE {predicate}")
        }
        ActionStatement::SelectForUpdate => format!(
            "SELECT count(*) AS rows FROM (SELECT 1 FROM {table} WHERE {predicate} FOR UPDATE) s"
        ),
        ActionStatement::Update => {
            let set = case
                .mutations
                .values()
                .find_map(|mutations| mutations.update_set.as_deref())?;
            format!("WITH changed AS (UPDATE {table} SET {set} WHERE {predicate} RETURNING 1) SELECT count(*) AS rows FROM changed")
        }
        ActionStatement::Delete => format!(
            "WITH removed AS (DELETE FROM {table} WHERE {predicate} RETURNING 1) SELECT count(*) AS rows FROM removed"
        ),
        _ => return None,
    };

    let answered = conn.transaction::<bool, diesel::result::Error, _>(|conn| {
        become_principal(conn, principal)?;
        let counted: Counted = diesel::sql_query(&sql).get_result(conn)?;
        Ok(counted.rows == 1)
    });
    match answered {
        Ok(granted) => Some(granted),
        // A write `WITH CHECK` refuses raises, and that is a denial, as is a locking read
        // the caller lacks the `UPDATE` privilege for. A plain read never raises under
        // row-level security, so an error there is a case that granted no privilege or
        // named no column, and reporting it as a denial would hide the mistake.
        Err(error) if statement == ActionStatement::Select => panic!(
            "{}: reading {table} as {} raised, which row-level security never does: {error}",
            case.name, principal.login_role
        ),
        Err(_) => Some(false),
    }
}

/// Whether the model grants `principal` the statement on `object`.
async fn openfga_allows(
    client: &openfga::Client,
    answers: &[ActionRelations],
    principal: &Principal,
    object: &Object,
    statement: ActionStatement,
) -> Option<bool> {
    let type_name = object.name.split_once(':')?.0;
    let entry = answers
        .iter()
        .find(|entry| entry.type_name == *type_name && entry.statement == statement)?;
    match &entry.answer {
        ActionAnswer::Unrestricted => Some(true),
        ActionAnswer::Denied => Some(false),
        ActionAnswer::Judged(judgements) => {
            for judgement in judgements {
                // The tuples state facts about rows the database holds, so a judgement
                // about the row a write would produce has nothing to read. Answering it
                // needs that row's records, which is not this runner's job yet.
                if judgement.version == RowVersion::Resulting {
                    return None;
                }
                let granted = openfga::check_allowed_with_context(
                    client,
                    &format!("user:{}", principal.subject),
                    judgement.relation.as_str(),
                    &object.name,
                    principal.context.clone(),
                )
                .await;
                if !granted {
                    return Some(false);
                }
            }
            Some(true)
        }
        // A new answer the model learns to give is not one this compares.
        _ => None,
    }
}

/// Apply the case, translate it, load the tuples, and compare every pair.
///
/// `doctor` sees the translation's own statement answers before they are used, which is
/// how a test plants a divergence the runner has to find.
pub(crate) async fn run_with(
    case: &ParityCase,
    doctor: impl FnOnce(Vec<ActionRelations>) -> Vec<ActionRelations>,
) -> Vec<Mismatch> {
    let postgres = super::containers::start_postgres().await;
    let pg_port = postgres.get_host_port_ipv4(5432).await.unwrap();
    let pg_url = format!(
        "postgres://{}:{}@127.0.0.1:{pg_port}/{}",
        super::containers::PG_USER,
        super::containers::PG_PASSWORD,
        super::containers::PG_DB
    );
    let mut conn = super::containers::connect_postgres_with_retry(&pg_url);

    for sql in &case.prelude {
        conn.batch_execute(sql)
            .unwrap_or_else(|error| panic!("{}: prelude {sql}: {error}", case.name));
    }
    conn.batch_execute(&case.schema)
        .unwrap_or_else(|error| panic!("{}: schema: {error}", case.name));
    for sql in &case.seed {
        conn.batch_execute(sql)
            .unwrap_or_else(|error| panic!("{}: seed {sql}: {error}", case.name));
    }

    let (classified, db, registry) = super::classify_sql(&case.schema, None);
    let planned = Translation::plan(
        classified,
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .expect("translation should plan");
    let disclosed: Vec<String> = planned
        .notes()
        .iter()
        .filter(|note| note.severity().diverges_from_database())
        .map(ToString::to_string)
        .collect();
    assert!(
        disclosed.is_empty(),
        "{}: the translation already says it diverges here, so agreement is the wrong \
         question. Outside the exactly supported class the property is disclosure, not \
         equality:\n{}",
        case.name,
        disclosed.join("\n")
    );
    let answers = doctor(planned.action_relations().to_vec());
    let naming = planned.row_naming().to_vec();
    let outputs = planned.outputs_accepting_gaps();
    let model = outputs.json_model();

    let objects = objects(&mut conn, &naming);
    let tuples = super::execute_tuple_queries_for_parity(&mut conn, outputs.tuple_queries());

    let openfga_container = super::containers::start_openfga().await;
    let grpc_port = openfga_container.get_host_port_ipv4(8081).await.unwrap();
    let mut service = openfga::connect(grpc_port).await;
    let store_id = openfga::create_store(&mut service, &case.name).await;
    let model_id = openfga::write_authorization_model(&mut service, &store_id, &model).await;
    let client = service.into_client(&store_id, &model_id);

    let mut writes: Vec<_> = tuples
        .iter()
        .map(|(object, relation, subject)| openfga::make_tuple(object, relation, subject))
        .collect();
    for principal in &case.principals {
        for role in &principal.pg_roles {
            writes.push(openfga::make_tuple(
                &format!("pg_role:{role}"),
                "usage",
                &format!("user:{}", principal.subject),
            ));
        }
    }
    openfga::write_tuples(&client, writes).await;

    let mut mismatches = Vec::new();
    for principal in &case.principals {
        for object in &objects {
            for statement in COMPARED {
                let Some(postgres) = postgres_allows(&mut conn, case, principal, object, statement)
                else {
                    continue;
                };
                let Some(openfga) =
                    openfga_allows(&client, &answers, principal, object, statement).await
                else {
                    continue;
                };
                if postgres != openfga {
                    mismatches.push(Mismatch {
                        subject: principal.subject.clone(),
                        object: object.name.clone(),
                        statement,
                        postgres,
                        openfga,
                    });
                }
            }
        }
    }
    mismatches
}

/// Apply the case and compare every pair, taking the translation's answers as they are.
pub(crate) async fn run(case: &ParityCase) -> Vec<Mismatch> {
    run_with(case, |answers| answers).await
}

/// Fail with every disagreement named.
pub(crate) fn assert_agrees(case: &ParityCase, mismatches: &[Mismatch]) {
    assert!(
        mismatches.is_empty(),
        "{}: PostgreSQL and OpenFGA disagree:\n{}",
        case.name,
        mismatches
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    );
}

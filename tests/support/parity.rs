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
    /// Whether every check carries the database's clock as `request_time`.
    pub(crate) carries_request_time: bool,
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
            carries_request_time: false,
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
            carries_request_time: false,
        }
    }

    /// The same caller, whose checks carry the database's clock.
    ///
    /// A condition against the request clock needs it, and reading it from the same
    /// database the rows came from is what keeps the two sides asking about one instant.
    pub(crate) fn with_clock(mut self) -> Self {
        self.carries_request_time = true;
        self
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
    /// Accessor metadata the deployment declares, as a fixture's
    /// `function_registry.json` holds it.
    pub(crate) registry_json: Option<String>,
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
            registry_json: None,
        }
    }

    /// The same case, with statements applied before the schema.
    pub(crate) fn after(mut self, prelude: &[&str]) -> Self {
        self.prelude = prelude.iter().map(|sql| (*sql).to_string()).collect();
        self
    }

    /// The same case, reading its schema and registry from a fixture directory.
    pub(crate) fn from_fixture(
        name: &str,
        fixture: &str,
        seed: &[&str],
        principals: Vec<Principal>,
    ) -> Self {
        let mut case = Self::reading(name, &super::read_fixture_sql(fixture), seed, principals);
        case.registry_json =
            std::fs::read_to_string(super::fixture_dir(fixture).join("function_registry.json"))
                .ok();
        case
    }

    /// The same case, with the accessor metadata its deployment declares.
    pub(crate) fn with_registry(mut self, registry_json: &str) -> Self {
        self.registry_json = Some(registry_json.to_string());
        self
    }

    /// The same case, with what a write on `table` would attempt.
    pub(crate) fn writing(mut self, table: &str, mutations: Mutations) -> Self {
        self.mutations.insert(table.to_string(), mutations);
        self
    }
}

/// One compared pair and both answers.
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

impl Mismatch {
    /// Whether the two sides answered differently.
    pub(crate) fn disagrees(&self) -> bool {
        self.postgres != self.openfga
    }
}

/// Everything one case observed.
#[derive(Debug)]
pub(crate) struct Run {
    /// Every compared pair, in the order the runner walked them.
    pub(crate) observations: Vec<Mismatch>,
}

impl Run {
    /// The pairs the two sides answered differently about.
    pub(crate) fn mismatches(&self) -> Vec<&Mismatch> {
        self.observations
            .iter()
            .filter(|observation| observation.disagrees())
            .collect()
    }

    /// What the database answered for one pair, absent where the runner did not compare it.
    pub(crate) fn postgres_answered(
        &self,
        subject: &str,
        object: &str,
        statement: ActionStatement,
    ) -> Option<bool> {
        self.observations
            .iter()
            .find(|observation| {
                observation.subject == subject
                    && observation.object == object
                    && observation.statement == statement
            })
            .map(|observation| observation.postgres)
    }

    /// How many pairs were compared, which is what stops a case passing vacuously.
    pub(crate) fn compared(&self) -> usize {
        self.observations.len()
    }
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
struct Instant {
    #[diesel(sql_type = diesel::sql_types::Text)]
    instant: String,
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

#[derive(QueryableByName)]
struct Granted {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    granted: bool,
}

/// Whether `role` holds `privilege` on `table`.
///
/// A table privilege is not row-level security and the model says nothing about it, so a
/// pair the caller cannot reach at all is not one to compare. Asked of `PostgreSQL` rather
/// than inferred from an error, so a missing privilege on a table a *policy* reads still
/// raises and is reported.
fn holds_privilege(conn: &mut PgConnection, role: &str, table: &str, privilege: &str) -> bool {
    let answered: Granted = diesel::sql_query("SELECT has_table_privilege($1, $2, $3) AS granted")
        .bind::<diesel::sql_types::Text, _>(role)
        .bind::<diesel::sql_types::Text, _>(table)
        .bind::<diesel::sql_types::Text, _>(privilege)
        .get_result(conn)
        .unwrap_or_else(|error| panic!("asking whether {role} may {privilege} {table}: {error}"));
    answered.granted
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
    let privilege = match statement {
        ActionStatement::Select => "SELECT",
        ActionStatement::SelectForUpdate | ActionStatement::Update => "UPDATE",
        ActionStatement::Delete => "DELETE",
        _ => return None,
    };
    if !holds_privilege(conn, &principal.login_role, table, privilege) {
        return None;
    }
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
    context: &serde_json::Value,
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
                    context.clone(),
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
/// Which property a case is asserting.
///
/// The notes come from the translator under test, so they cannot be the pass condition.
/// They can say which of two properties applies, which is a question about the notes
/// themselves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Class {
    /// Inside the exactly supported class: the two sides must agree, note or no note.
    Exact,
    /// Outside it: the translation must say so, and the model may only be narrower.
    Disclosed,
}

pub(crate) async fn run_with(
    case: &ParityCase,
    expectation: Class,
    doctor: impl FnOnce(Vec<ActionRelations>) -> Vec<ActionRelations>,
) -> Run {
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

    let (classified, db, registry) =
        super::classify_sql(&case.schema, case.registry_json.as_deref());
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
    match expectation {
        Class::Exact => assert!(
            disclosed.is_empty(),
            "{}: the translation already says it diverges here, so agreement is the wrong \
             question. Outside the exactly supported class the property is disclosure, not \
             equality:\n{}",
            case.name,
            disclosed.join("\n")
        ),
        Class::Disclosed => assert!(
            !disclosed.is_empty(),
            "{}: nothing is disclosed, so this case is inside the exactly supported class \
             and equality is the property to assert",
            case.name
        ),
    }
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

    let clock: Instant =
        diesel::sql_query("SELECT to_char(now(), 'YYYY-MM-DD\"T\"HH24:MI:SSOF:00') AS instant")
            .get_result(&mut conn)
            .expect("reading now() should succeed");

    let mut observations = Vec::new();
    for principal in &case.principals {
        for object in &objects {
            for statement in COMPARED {
                let Some(postgres) = postgres_allows(&mut conn, case, principal, object, statement)
                else {
                    continue;
                };
                let mut context = principal.context.clone();
                if principal.carries_request_time {
                    if let Some(object) = context.as_object_mut() {
                        object.insert(
                            "request_time".to_string(),
                            serde_json::Value::String(clock.instant.clone()),
                        );
                    }
                }
                let Some(openfga) =
                    openfga_allows(&client, &answers, principal, &context, object, statement).await
                else {
                    continue;
                };
                observations.push(Mismatch {
                    subject: principal.subject.clone(),
                    object: object.name.clone(),
                    statement,
                    postgres,
                    openfga,
                });
            }
        }
    }
    Run { observations }
}

/// Apply the case and compare every pair, taking the translation's answers as they are.
pub(crate) async fn run(case: &ParityCase) -> Run {
    run_with(case, Class::Exact, |answers| answers).await
}

/// Apply a case the translation says it diverges on, and answer with what both sides said.
///
/// Refuses a case that discloses nothing, since that one belongs to [`run`].
pub(crate) async fn run_disclosing(case: &ParityCase) -> Run {
    run_with(case, Class::Disclosed, |answers| answers).await
}

/// Fail if the model grants anything the database denies.
///
/// The property for a disclosed case: a clause the threshold dropped can only make the
/// model narrower, so an over-grant is a defect however loudly it was disclosed.
pub(crate) fn assert_no_over_grant(case: &ParityCase, run: &Run) {
    let over: Vec<_> = run
        .observations
        .iter()
        .filter(|observation| observation.openfga && !observation.postgres)
        .map(ToString::to_string)
        .collect();
    assert!(
        over.is_empty(),
        "{}: the model grants what the database denies:\n{}",
        case.name,
        over.join("\n")
    );
    assert!(
        run.compared() > 0,
        "{}: nothing was compared, so narrowness means nothing",
        case.name
    );
}

/// Fail with every disagreement named, and refuse a case that compared nothing.
pub(crate) fn assert_agrees(case: &ParityCase, run: &Run) {
    let mismatches = run.mismatches();
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
    assert!(
        run.compared() > 0,
        "{}: nothing was compared, so agreeing means nothing",
        case.name
    );
}

/// Fail unless the database answered `expected` for one pair.
///
/// What a hand-written case pinned with its own `assert!(!expected)`: that the schema
/// really denies the row, so agreement is not two sides being wrong together.
pub(crate) fn assert_postgres(
    case: &ParityCase,
    run: &Run,
    subject: &str,
    object: &str,
    statement: ActionStatement,
    expected: bool,
) {
    let answered = run.postgres_answered(subject, object, statement);
    assert_eq!(
        answered,
        Some(expected),
        "{}: PostgreSQL on {subject} {statement:?} {object}",
        case.name
    );
}

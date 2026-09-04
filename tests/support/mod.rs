#![allow(dead_code)]

#[cfg(all(not(target_os = "windows"), feature = "client"))]
pub(crate) mod openfga;

#[cfg(all(not(target_os = "windows"), feature = "client"))]
pub(crate) mod parity;

#[cfg(not(target_os = "windows"))]
pub(crate) mod containers;

pub(crate) mod footgun;

use std::borrow::Cow;
use std::path::PathBuf;

use rls2fga::classifier::function_registry::{FunctionRegistry, SessionAttribute};
use rls2fga::classifier::patterns::ClassifiedPolicy;
use rls2fga::classifier::policy_classifier;
use rls2fga::parser::sql_parser::{self, ParserDB};
use rls2fga::types::{ColumnKind, RowCell, RowList, RowValues};

/// `serde_json` view of one row, adapting it to the crate's row interface.
pub(crate) struct JsonRowValues<'a>(pub(crate) &'a serde_json::Value);

/// Text of a JSON scalar the way `PostgreSQL` renders it in `||` and `->>`.
pub(crate) fn scalar_text(value: &serde_json::Value) -> Option<Cow<'_, str>> {
    match value {
        serde_json::Value::String(text) => Some(Cow::Borrowed(text.as_str())),
        serde_json::Value::Number(number) => Some(Cow::Owned(number.to_string())),
        serde_json::Value::Bool(flag) => Some(Cow::Borrowed(if *flag { "true" } else { "false" })),
        // A JSON null has no text, and neither does an object or an array, which
        // `||` would refuse anyway.
        _ => None,
    }
}

fn parse_bytea(text: &str) -> Option<Vec<u8>> {
    let hex = text.strip_prefix("\\x")?;
    let (pairs, remainder) = hex.as_bytes().as_chunks::<2>();
    let mut out = Vec::with_capacity(pairs.len());
    for [high, low] in pairs {
        out.push((hex_nibble(*high)? << 4) | hex_nibble(*low)?);
    }
    remainder.is_empty().then_some(out)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn scalar_cell(value: &serde_json::Value, kind: ColumnKind) -> RowCell<'_> {
    match (value, kind) {
        (serde_json::Value::Null, _) => RowCell::Null,
        (serde_json::Value::String(text), ColumnKind::Text) => {
            RowCell::Text(Cow::Borrowed(text.as_str()))
        }
        (serde_json::Value::String(text), ColumnKind::Uuid) => {
            RowCell::Uuid(Cow::Borrowed(text.as_str()))
        }
        (serde_json::Value::String(text), ColumnKind::Date) => {
            RowCell::Date(Cow::Borrowed(text.as_str()))
        }
        (serde_json::Value::String(text), ColumnKind::Time) => {
            RowCell::Time(Cow::Borrowed(text.as_str()))
        }
        (serde_json::Value::String(text), ColumnKind::Timestamp) => {
            RowCell::Timestamp(Cow::Borrowed(text.as_str()))
        }
        (serde_json::Value::String(text), ColumnKind::TimestampTz) => {
            RowCell::TimestampTz(Cow::Borrowed(text.as_str()))
        }
        (serde_json::Value::String(text), ColumnKind::Bytea) => parse_bytea(text)
            .map_or(RowCell::Undecodable, |bytes| {
                RowCell::Bytea(Cow::Owned(bytes))
            }),
        (serde_json::Value::Number(number), ColumnKind::Integer) => {
            RowCell::Integer(Cow::Owned(number.to_string()))
        }
        (serde_json::Value::Number(number), ColumnKind::Decimal) => {
            RowCell::Decimal(Cow::Owned(number.to_string()))
        }
        (serde_json::Value::Bool(flag), ColumnKind::Bool) => RowCell::Bool(*flag),
        _ => RowCell::Undecodable,
    }
}

impl RowValues for JsonRowValues<'_> {
    fn cell(&self, column: &str, kind: ColumnKind) -> RowCell<'_> {
        self.0
            .get(column)
            .map_or(RowCell::Absent, |value| scalar_cell(value, kind))
    }

    fn list(&self, column: &str, kind: ColumnKind) -> RowList<'_> {
        match self.0.get(column) {
            Some(serde_json::Value::Null) => RowList::Null,
            Some(serde_json::Value::Array(values)) => RowList::Values(
                values
                    .iter()
                    .map(|value| scalar_cell(value, kind))
                    .collect(),
            ),
            Some(_) => RowList::Undecodable,
            None => RowList::Absent,
        }
    }

    fn json_text(&self, column: &str, path: &[String]) -> RowCell<'_> {
        let Some(mut current) = self.0.get(column) else {
            return RowCell::Absent;
        };
        for step in path {
            let Some(next) = current.get(step) else {
                return RowCell::Null;
            };
            current = next;
        }
        match scalar_text(current) {
            Some(text) => RowCell::Text(text),
            None if current.is_null() => RowCell::Null,
            None => RowCell::Undecodable,
        }
    }
}

pub(crate) fn fixture_dir(fixture: &str) -> PathBuf {
    PathBuf::from("tests/fixtures").join(fixture)
}

pub(crate) fn read_fixture_sql(fixture: &str) -> String {
    let path = fixture_dir(fixture).join("input.sql");
    std::fs::read_to_string(path).expect("fixture SQL should be readable")
}

pub(crate) fn parse_fixture_db(fixture: &str) -> ParserDB {
    sql_parser::parse_schema(&read_fixture_sql(fixture)).expect("fixture SQL should parse")
}

pub(crate) fn read_fixture_registry_json(fixture: &str) -> String {
    let path = fixture_dir(fixture).join("function_registry.json");
    std::fs::read_to_string(path).expect("fixture registry should be readable")
}

pub(crate) fn load_fixture_registry(fixture: &str) -> FunctionRegistry {
    let mut registry = FunctionRegistry::new();
    registry
        .load_from_json(&read_fixture_registry_json(fixture))
        .expect("fixture registry should parse");
    registry
}

pub(crate) fn load_fixture_db_and_registry(fixture: &str) -> (ParserDB, FunctionRegistry) {
    (parse_fixture_db(fixture), load_fixture_registry(fixture))
}

pub(crate) fn load_fixture_classified(
    fixture: &str,
) -> (Vec<ClassifiedPolicy>, ParserDB, FunctionRegistry) {
    let (db, registry) = load_fixture_db_and_registry(fixture);
    let classified = policy_classifier::classify_policies(&db, &registry);
    (classified, db, registry)
}

pub(crate) fn try_load_fixture_registry(fixture: &str) -> FunctionRegistry {
    let path = fixture_dir(fixture).join("function_registry.json");
    let mut registry = FunctionRegistry::new();
    if let Ok(json) = std::fs::read_to_string(path) {
        registry
            .load_from_json(&json)
            .expect("fixture registry should parse");
    }
    registry.declare_session_attributes(fixture_session_attributes(fixture));
    registry
}

/// The request-scoped values a fixture's deployment declares, none when it declares none.
pub(crate) fn fixture_session_attributes(fixture: &str) -> Vec<SessionAttribute> {
    let path = fixture_dir(fixture).join("session_attributes.json");
    let Ok(json) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    serde_json::from_str(&json).expect("fixture session attributes should parse")
}

pub(crate) fn classify_sql(
    sql: &str,
    registry_json: Option<&str>,
) -> (Vec<ClassifiedPolicy>, ParserDB, FunctionRegistry) {
    let db = sql_parser::parse_schema(sql).expect("schema should parse");
    let mut registry = FunctionRegistry::new();
    if let Some(json) = registry_json {
        registry
            .load_from_json(json)
            .expect("registry json should parse");
    }
    let classified = policy_classifier::classify_policies(&db, &registry);
    (classified, db, registry)
}

/// Classify SQL with both the accessor metadata and the session attributes a deployment
/// declares.
///
/// The two existing helpers each take one of them, and a fixture may declare both.
pub(crate) fn classify_with(
    sql: &str,
    registry_json: Option<&str>,
    attributes_json: Option<&str>,
) -> (Vec<ClassifiedPolicy>, ParserDB, FunctionRegistry) {
    let db = sql_parser::parse_schema(sql).expect("schema should parse");
    let mut registry = FunctionRegistry::new();
    if let Some(json) = registry_json {
        registry
            .load_from_json(json)
            .expect("registry json should parse");
    }
    if let Some(json) = attributes_json {
        let attributes: Vec<SessionAttribute> =
            serde_json::from_str(json).expect("session attributes should parse");
        registry.declare_session_attributes(attributes);
    }
    let classified = policy_classifier::classify_policies(&db, &registry);
    (classified, db, registry)
}

/// Classify SQL with declared session attributes and no function registry.
pub(crate) fn classify_sql_with_session_attributes(
    sql: &str,
    attributes_json: &str,
) -> (Vec<ClassifiedPolicy>, ParserDB, FunctionRegistry) {
    let db = sql_parser::parse_schema(sql).expect("schema should parse");
    let mut registry = FunctionRegistry::new();
    let attributes: Vec<SessionAttribute> =
        serde_json::from_str(attributes_json).expect("session attributes should parse");
    registry.declare_session_attributes(attributes);
    let classified = policy_classifier::classify_policies(&db, &registry);
    (classified, db, registry)
}

/// Classify SQL with an empty function registry, for the common case where no registry
/// metadata is needed.
pub(crate) fn classify_sql_no_registry(
    sql: &str,
) -> (Vec<ClassifiedPolicy>, ParserDB, FunctionRegistry) {
    classify_sql(sql, None)
}

pub(crate) fn try_load_fixture_classified(
    fixture: &str,
) -> (Vec<ClassifiedPolicy>, ParserDB, FunctionRegistry) {
    let db = parse_fixture_db(fixture);
    let registry = try_load_fixture_registry(fixture);
    let classified = policy_classifier::classify_policies(&db, &registry);
    (classified, db, registry)
}

/// One loaded fact, carrying the condition and context where its query yields them.
///
/// `TupleQuery::condition` says which shape a query produces, so the loader knows how many
/// columns to read without parsing the SQL. Dropping the two extra columns makes the
/// service refuse the write with `condition is missing`.
#[cfg(all(not(target_os = "windows"), feature = "client"))]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct LoadedTuple {
    pub(crate) object: String,
    pub(crate) relation: String,
    pub(crate) subject: String,
    /// The condition the relation names, and the context the row supplies as JSON text.
    pub(crate) condition: Option<(String, String)>,
}

/// Run every tuple query and collect what it loaded, sorted and deduplicated.
///
/// Beside the per-case loaders, for the generic parity runner.
#[cfg(all(not(target_os = "windows"), feature = "client"))]
pub(crate) fn execute_tuple_queries_for_parity(
    conn: &mut diesel::pg::PgConnection,
    queries: &[rls2fga::generator::tuple_generator::TupleQuery],
) -> Vec<LoadedTuple> {
    use diesel::prelude::*;
    use diesel::sql_types::{Jsonb, Text};

    #[derive(diesel::QueryableByName)]
    struct Plain {
        #[diesel(sql_type = Text)]
        object: String,
        #[diesel(sql_type = Text)]
        relation: String,
        #[diesel(sql_type = Text)]
        subject: String,
    }

    #[derive(diesel::QueryableByName)]
    struct Conditional {
        #[diesel(sql_type = Text)]
        object: String,
        #[diesel(sql_type = Text)]
        relation: String,
        #[diesel(sql_type = Text)]
        subject: String,
        #[diesel(sql_type = Text)]
        condition: String,
        #[diesel(sql_type = Jsonb)]
        context: serde_json::Value,
    }

    let mut keys = std::collections::BTreeSet::new();
    for query in queries {
        if query.condition.is_some() {
            let rows: Vec<Conditional> =
                diesel::sql_query(&query.sql)
                    .load(conn)
                    .unwrap_or_else(|error| {
                        panic!(
                            "tuple SQL failed: {}\n{}\nError: {error}",
                            query.comment, query.sql
                        )
                    });
            for row in rows {
                keys.insert(LoadedTuple {
                    object: row.object,
                    relation: row.relation,
                    subject: row.subject,
                    condition: Some((row.condition, row.context.to_string())),
                });
            }
        } else {
            let rows: Vec<Plain> =
                diesel::sql_query(&query.sql)
                    .load(conn)
                    .unwrap_or_else(|error| {
                        panic!(
                            "tuple SQL failed: {}\n{}\nError: {error}",
                            query.comment, query.sql
                        )
                    });
            for row in rows {
                keys.insert(LoadedTuple {
                    object: row.object,
                    relation: row.relation,
                    subject: row.subject,
                    condition: None,
                });
            }
        }
    }
    keys.into_iter().collect()
}

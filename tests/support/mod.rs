#![allow(dead_code)]

#[cfg(all(not(target_os = "windows"), feature = "client"))]
pub(crate) mod openfga;

pub(crate) mod footgun;

use std::borrow::Cow;
use std::path::PathBuf;

use rls2fga::classifier::function_registry::{FunctionRegistry, SessionAttribute};
use rls2fga::classifier::patterns::ClassifiedPolicy;
use rls2fga::classifier::policy_classifier;
use rls2fga::generator::records::RowValues;
use rls2fga::parser::sql_parser::{self, ParserDB};

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

impl RowValues for JsonRowValues<'_> {
    fn text(&self, column: &str) -> Option<Cow<'_, str>> {
        self.0.get(column).and_then(scalar_text)
    }

    fn boolean(&self, column: &str) -> Option<bool> {
        self.0.get(column).and_then(serde_json::Value::as_bool)
    }

    fn list(&self, column: &str) -> Option<Vec<Option<Cow<'_, str>>>> {
        Some(
            self.0
                .get(column)?
                .as_array()?
                .iter()
                .map(scalar_text)
                .collect(),
        )
    }

    fn json_text(&self, column: &str, path: &[String]) -> Option<Cow<'_, str>> {
        let mut current = self.0.get(column)?;
        for step in path {
            current = current.get(step)?;
        }
        scalar_text(current)
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

/// Classify SQL with an empty function registry — convenience wrapper for
/// the common case where no registry metadata is needed.
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

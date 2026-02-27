#![allow(dead_code)]

pub(crate) mod openfga;

use std::path::PathBuf;

use rls2fga::classifier::function_registry::FunctionRegistry;
use rls2fga::classifier::patterns::ClassifiedPolicy;
use rls2fga::classifier::policy_classifier;
use rls2fga::parser::sql_parser::{self, ParserDB};

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
    registry
}

pub(crate) fn try_load_fixture_classified(
    fixture: &str,
) -> (Vec<ClassifiedPolicy>, ParserDB, FunctionRegistry) {
    let db = parse_fixture_db(fixture);
    let registry = try_load_fixture_registry(fixture);
    let classified = policy_classifier::classify_policies(&db, &registry);
    (classified, db, registry)
}

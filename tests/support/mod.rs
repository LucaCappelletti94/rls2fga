#![allow(dead_code)]

#[cfg(all(not(target_os = "windows"), feature = "client"))]
pub(crate) mod openfga;

pub(crate) mod footgun;

use std::borrow::Cow;
use std::path::PathBuf;

use rls2fga::classifier::function_registry::{FunctionRegistry, SessionAttribute};
use rls2fga::classifier::patterns::ClassifiedPolicy;
use rls2fga::classifier::policy_classifier;
use rls2fga::parser::names::unquote_identifier;
use rls2fga::parser::sql_parser::{self, DatabaseLike, ParserDB, TableLike};
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

pub(crate) fn qualify_table_declarations(sql: &str, tables: &[&str]) -> String {
    let mut qualified = sql.to_string();
    for table in tables {
        let spaced = format!("CREATE TABLE {table} (");
        let compact = format!("CREATE TABLE {table}(");
        assert_eq!(
            qualified.matches(&spaced).count() + qualified.matches(&compact).count(),
            1,
            "expected one declaration for {table}"
        );
        let (declaration, replacement) = if qualified.contains(&spaced) {
            (spaced, format!("CREATE TABLE public.{table} ("))
        } else {
            (compact, format!("CREATE TABLE public.{table}("))
        };
        qualified = qualified.replacen(&declaration, &replacement, 1);
    }
    qualified
}

fn qualify_all_table_declarations(sql: &str) -> String {
    let db = sql_parser::parse_schema(sql).expect("fixture SQL should parse");
    let tables = sql
        .lines()
        .filter_map(|line| {
            let declaration = line.trim_start().strip_prefix("CREATE TABLE ")?;
            let target_end = declaration
                .find(|character: char| character.is_whitespace() || character == '(')
                .unwrap_or(declaration.len());
            declaration[target_end..]
                .trim_start()
                .starts_with('(')
                .then_some(&declaration[..target_end])
        })
        .filter(|table| !has_unquoted_dot(table))
        .filter(|table| {
            let stored_name = if table.starts_with('"') {
                unquote_identifier(table)
            } else {
                Cow::Owned(table.to_ascii_lowercase())
            };
            db.tables().any(|declared| {
                declared.stored_table_schema().is_none()
                    && declared.stored_table_name() == stored_name
            })
        })
        .collect::<Vec<_>>();
    qualify_table_declarations(sql, &tables)
}

fn has_unquoted_dot(name: &str) -> bool {
    let mut characters = name.chars().peekable();
    let mut quoted = false;
    while let Some(character) = characters.next() {
        if character == '"' {
            if quoted && characters.peek() == Some(&'"') {
                characters.next();
            } else {
                quoted = !quoted;
            }
        } else if character == '.' && !quoted {
            return true;
        }
    }
    assert!(!quoted, "the table name must close its quote");
    false
}

pub(crate) fn classify_qualified_sql(
    sql: &str,
    registry_json: Option<&str>,
) -> (Vec<ClassifiedPolicy>, ParserDB, FunctionRegistry) {
    classify_sql(&qualify_all_table_declarations(sql), registry_json)
}

pub(crate) fn classify_qualified_sql_with_session_attributes(
    sql: &str,
    attributes_json: &str,
) -> (Vec<ClassifiedPolicy>, ParserDB, FunctionRegistry) {
    classify_sql_with_session_attributes(&qualify_all_table_declarations(sql), attributes_json)
}

pub(crate) fn load_qualified_fixture_classified(
    fixture: &str,
) -> (Vec<ClassifiedPolicy>, ParserDB, FunctionRegistry) {
    let sql = qualify_all_table_declarations(&read_fixture_sql(fixture));
    let db = sql_parser::parse_schema(&sql).expect("fixture SQL should parse");
    let registry = load_fixture_registry(fixture);
    let classified = policy_classifier::classify_policies(&db, &registry);
    (classified, db, registry)
}

pub(crate) fn try_load_qualified_fixture_classified(
    fixture: &str,
) -> (Vec<ClassifiedPolicy>, ParserDB, FunctionRegistry) {
    let sql = qualify_all_table_declarations(&read_fixture_sql(fixture));
    let db = sql_parser::parse_schema(&sql).expect("fixture SQL should parse");
    let registry = try_load_fixture_registry(fixture);
    let classified = policy_classifier::classify_policies(&db, &registry);
    (classified, db, registry)
}

pub(crate) fn parse_fixture_db(fixture: &str) -> ParserDB {
    sql_parser::parse_schema(&read_fixture_sql(fixture)).expect("fixture SQL should parse")
}

pub(crate) fn parse_qualified_fixture_db(fixture: &str) -> ParserDB {
    sql_parser::parse_schema(&qualify_all_table_declarations(&read_fixture_sql(fixture)))
        .expect("fixture SQL should parse")
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

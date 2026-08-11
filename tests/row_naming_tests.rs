//! What the emitted model calls a row of a table.
//!
//! The assertions come from the request recorded in `plans/row-naming.md`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::borrow::Cow;

use rls2fga::classifier::patterns::ConfidenceLevel;
use rls2fga::generator::records::{records_from_row, RecordDerivation, RowValues, ValueSource};
use rls2fga::generator::row_naming::RowNaming;
use rls2fga::parser::sql_parser::{parse_schema, ParserDB};
use rls2fga::translator::{Translation, TranslatorBuilder};

const CALLER: &str = "current_setting('app.user_id', true)";

fn translate(db: &ParserDB) -> Translation<'_, ParserDB> {
    TranslatorBuilder::new()
        .with_min_confidence(ConfidenceLevel::B)
        .with_current_user_setting_keys(["app.user_id"])
        .build()
        .translate(db)
}

fn naming(sql: &str) -> Vec<RowNaming> {
    let db: ParserDB = parse_schema(sql).expect("the schema should parse");
    let mut entries = translate(&db).row_naming();
    entries.sort_by(|left, right| left.table.cmp(&right.table));
    entries
}

fn entry<'a>(entries: &'a [RowNaming], table: &str) -> &'a RowNaming {
    entries
        .iter()
        .find(|entry| entry.table == table)
        .unwrap_or_else(|| {
            panic!(
                "no entry for {table}, got {:?}",
                entries
                    .iter()
                    .map(|entry| entry.table.clone())
                    .collect::<Vec<_>>()
            )
        })
}

/// One row, so a key can be rendered against it.
struct Row(Vec<(String, String)>);

impl RowValues for Row {
    fn text(&self, column: &str) -> Option<Cow<'_, str>> {
        self.0
            .iter()
            .find(|(name, _)| name == column)
            .map(|(_, value)| Cow::Borrowed(value.as_str()))
    }
}

fn row(pairs: &[(&str, &str)]) -> Row {
    Row(pairs
        .iter()
        .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
        .collect())
}

/// Assertion 1: one entry per named table, and the type it reports is the type its own
/// relations are defined on.
#[test]
fn a_named_table_reports_the_type_its_relations_live_on() {
    let sql = "CREATE TABLE docs(id INTEGER PRIMARY KEY, owner TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (owner = current_setting('app.user_id', true));
";
    let db: ParserDB = parse_schema(sql).expect("the schema should parse");
    let planned = translate(&db);
    let entries = planned.row_naming();
    assert_eq!(
        entries.len(),
        1,
        "one entry per named table, got {entries:?}"
    );

    let docs = &entries[0];
    assert_eq!(docs.table, "docs");
    assert_eq!(docs.key.parts(), [ValueSource::column("id")].as_slice());
    assert!(
        planned
            .relations()
            .iter()
            .any(|entry| entry.type_name.as_str() == docs.type_name
                && entry.relation == "can_select"),
        "the type it reports is the one carrying that table's actions"
    );
}

/// Assertion 2: the name the key renders is the name the tuple SQL writes, which is what
/// makes the entry answerable against the loaded store.
#[test]
fn the_rendered_name_is_the_one_the_records_carry() {
    let sql = "CREATE TABLE docs(id INTEGER PRIMARY KEY, owner TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (owner = current_setting('app.user_id', true));
";
    let db: ParserDB = parse_schema(sql).expect("the schema should parse");
    let planned = translate(&db);
    let entries = planned.row_naming();
    let docs = entry(&entries, "docs");
    let subject = row(&[("id", "a|b"), ("owner", "alice")]);

    let rendered = docs
        .key
        .render(docs.type_name.as_str(), &subject)
        .expect("the row is nameable")
        .expect("the name fits");

    let shape = planned
        .relations()
        .into_iter()
        .flat_map(|entry| entry.shapes)
        .find(|shape| {
            matches!(
                &shape.derivation,
                RecordDerivation::FromRow { table, template, .. }
                    if table == "docs" && template.object_type == docs.type_name
            )
        })
        .expect("the ownership shape names a docs object from a docs row");
    let records = records_from_row(&shape, &subject).expect("the row names itself");
    assert!(
        records.iter().any(|record| record.object == rendered),
        "the entry renders the object the records carry, got {rendered} against {records:?}"
    );
}

/// Assertion 3: two tables whose names canonicalise alike are told apart, and each entry
/// names its own.
#[test]
fn two_tables_that_canonicalise_alike_report_different_types() {
    let entries = naming(
        "CREATE SCHEMA a;
CREATE SCHEMA b;
CREATE TABLE a.users(id INTEGER PRIMARY KEY, owner TEXT);
CREATE TABLE b.users(id INTEGER PRIMARY KEY, owner TEXT);
ALTER TABLE a.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE b.users ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON a.users FOR SELECT USING (owner = current_setting('app.user_id', true));
CREATE POLICY q ON b.users FOR SELECT USING (owner = current_setting('app.user_id', true));
",
    );
    let first = entry(&entries, "a.users");
    let second = entry(&entries, "b.users");
    assert_ne!(
        first.type_name, second.type_name,
        "one type name for two tables names the wrong rows"
    );
    assert_eq!(first.type_name, "users");
    assert_eq!(second.type_name, "users_ba5dba17");
}

/// Assertion 4: a table whose whole key is a foreign key is named by its own type, not by
/// the parent a shape describes from its rows.
#[test]
fn a_table_keyed_by_its_foreign_key_names_itself() {
    let entries = naming(
        "CREATE TABLE docs(id INTEGER PRIMARY KEY, owner TEXT);
CREATE TABLE doc_acl(doc_id INTEGER PRIMARY KEY REFERENCES docs(id), grantee TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE doc_acl ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (
  owner = current_setting('app.user_id', true)
  OR EXISTS (SELECT 1 FROM doc_acl a WHERE a.doc_id = docs.id
             AND a.grantee = current_setting('app.user_id', true)));
CREATE POLICY q ON doc_acl FOR SELECT USING (grantee = current_setting('app.user_id', true));
",
    );
    assert_eq!(entry(&entries, "doc_acl").type_name, "doc_acl");
    assert_eq!(entry(&entries, "docs").type_name, "docs");
}

/// Assertion 5: a table the model grants nobody still has to be nameable, since naming
/// the row is how a consumer is told no.
#[test]
fn a_table_that_grants_nobody_is_still_named() {
    let entries = naming(
        "CREATE TABLE docs(id INTEGER PRIMARY KEY, owner TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (owner LIKE '%x%');
",
    );
    assert_eq!(entry(&entries, "docs").type_name, "docs");
}

/// Assertion 6: a row the model cannot name has no entry rather than an empty one. The
/// loss is not silent: the translation already reports it as unhandled.
#[test]
fn a_table_whose_rows_cannot_be_named_has_no_entry() {
    let sql = "CREATE TABLE docs(id INTEGER, owner TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (owner = current_setting('app.user_id', true));
";
    let db: ParserDB = parse_schema(sql).expect("the schema should parse");
    let planned = translate(&db);
    assert!(
        planned.row_naming().is_empty(),
        "a table with no key names no row, got {:?}",
        planned.row_naming()
    );
    assert!(
        planned.unhandled().count() > 0,
        "and the translation says so rather than leaving the absence to be noticed"
    );
}

/// A table reached only as a parent is named too: a consumer watching its rows has to
/// name them, and the model already carries a type for it.
#[test]
fn a_table_reached_only_as_a_parent_is_named() {
    let entries = naming(&format!(
        "CREATE TABLE projects(id INTEGER PRIMARY KEY, owner TEXT);
CREATE TABLE docs(id INTEGER PRIMARY KEY, project_id INTEGER REFERENCES projects(id));
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (
  EXISTS (SELECT 1 FROM projects p WHERE p.id = docs.project_id AND p.owner = {CALLER}));
"
    ));
    assert_eq!(entry(&entries, "projects").type_name, "projects");
    assert_eq!(entry(&entries, "docs").type_name, "docs");
}

/// A parent reached through a membership table is named after the table the foreign key
/// references, not after the membership table the rows were read from.
#[test]
fn a_parent_reached_through_a_membership_table_names_the_parent() {
    let entries = naming(&format!(
        "CREATE TABLE projects(id TEXT PRIMARY KEY);
CREATE TABLE docs(id TEXT PRIMARY KEY, project_id TEXT REFERENCES projects(id));
CREATE TABLE project_members(id TEXT PRIMARY KEY, project_id TEXT REFERENCES projects(id), user_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (
  project_id IN (SELECT project_id FROM project_members WHERE user_id = {CALLER}));
"
    ));
    assert_eq!(entry(&entries, "projects").type_name, "projects");
    assert!(
        entries.iter().all(|entry| entry.table != "project_members"),
        "the membership table carries no type of its own here, got {entries:?}"
    );
}

/// A parent reached through an undeclared foreign key is a type derived from a column's
/// name, and no table's rows are named by it. The child is still named.
#[test]
fn a_parent_named_from_a_column_rather_than_a_table_has_no_entry() {
    let entries = naming(&format!(
        "CREATE TABLE docs(id TEXT PRIMARY KEY);
CREATE TABLE doc_members(id TEXT PRIMARY KEY, doc_id TEXT, user_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (
  EXISTS (SELECT 1 FROM doc_members m WHERE m.doc_id = docs.id AND m.user_id = {CALLER}));
"
    ));
    assert_eq!(entry(&entries, "docs").type_name, "docs");
    assert!(
        entries
            .iter()
            .all(|entry| entry.table != "doc_members" && entry.type_name.as_str() != "doc"),
        "a type named after a column names no table's rows, got {entries:?}"
    );
}

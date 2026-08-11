//! Which relations answer an action, and which row version each judges.
//!
//! The assertions come from the request recorded in `plans/action-relations.md`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use rls2fga::classifier::function_registry::{SessionAttribute, SessionAttributeKind};
use rls2fga::classifier::patterns::ConfidenceLevel;
use rls2fga::generator::action_relations::{
    ActionAnswer, ActionRelations, ActionStatement, RowVersion,
};
use rls2fga::parser::sql_parser::{parse_schema, ParserDB};
use rls2fga::translator::{Translation, TranslatorBuilder};
use support::footgun::relation_definition;

/// One permissive policy giving one condition, which is what every connetto table
/// writes. `PostgreSQL` applies that condition to the existing row and to the result.
const ONE_CONDITION: &str = "
CREATE TABLE notes(id INTEGER PRIMARY KEY, owner TEXT, body TEXT);
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY notes_p ON notes USING (
  owner = current_setting('app.user_id', true)
  OR owner = ANY(string_to_array(current_setting('app.subjects', true), ',')));
";

/// The same table with the two clauses spelled out separately.
const TWO_CONDITIONS: &str = "
CREATE TABLE notes(id INTEGER PRIMARY KEY, owner TEXT, body TEXT);
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY notes_s ON notes FOR SELECT USING (
  owner = current_setting('app.user_id', true)
  OR owner = ANY(string_to_array(current_setting('app.subjects', true), ',')));
CREATE POLICY notes_u ON notes FOR UPDATE
  USING (owner = current_setting('app.user_id', true))
  WITH CHECK (owner = ANY(string_to_array(current_setting('app.subjects', true), ',')));
";

/// Reads alone, so every writing action denies while the table is still restricted.
const READS_ONLY: &str = "
CREATE TABLE notes(id INTEGER PRIMARY KEY, owner TEXT);
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY notes_s ON notes FOR SELECT USING (owner = current_setting('app.user_id', true));
";

/// Three rules that differ from each other, so an upsert asks more than an insert and
/// reading back an inserted row asks more than writing it.
const INSERT_AND_UPDATE: &str = "
CREATE TABLE notes(id INTEGER PRIMARY KEY, owner TEXT, editor TEXT, author TEXT);
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY notes_s ON notes FOR SELECT USING (owner = current_setting('app.user_id', true));
CREATE POLICY notes_i ON notes FOR INSERT WITH CHECK (author = current_setting('app.user_id', true));
CREATE POLICY notes_u ON notes FOR UPDATE USING (editor = current_setting('app.user_id', true));
";

/// A parent the model reaches only through a membership table, and which the database
/// itself restricts not at all.
const UNRESTRICTED_PARENT: &str = "
CREATE TABLE projects(id INTEGER PRIMARY KEY);
CREATE TABLE docs(id INTEGER PRIMARY KEY, project_id INTEGER REFERENCES projects(id));
CREATE TABLE project_members(project_id INTEGER REFERENCES projects(id), user_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY d ON docs USING (project_id IN (
  SELECT project_id FROM project_members WHERE user_id = current_setting('app.user_id', true)));
";

const EVERY_SCHEMA: [(&str, &str); 5] = [
    ("one condition", ONE_CONDITION),
    ("two conditions", TWO_CONDITIONS),
    ("reads only", READS_ONLY),
    ("insert and update", INSERT_AND_UPDATE),
    ("unrestricted parent", UNRESTRICTED_PARENT),
];

const EVERY_STATEMENT: [ActionStatement; 8] = [
    ActionStatement::Select,
    ActionStatement::Insert,
    ActionStatement::Update,
    ActionStatement::Delete,
    ActionStatement::SelectForUpdate,
    ActionStatement::InsertOnConflictUpdate,
    ActionStatement::InsertReturning,
    ActionStatement::UpdateWithoutWhere,
];

fn translate(db: &ParserDB) -> Translation<'_, ParserDB> {
    TranslatorBuilder::new()
        .with_min_confidence(ConfidenceLevel::B)
        .with_session_attributes([
            SessionAttribute::setting("app.user_id", SessionAttributeKind::CallerId),
            SessionAttribute::setting("app.subjects", SessionAttributeKind::SetAttribute),
        ])
        .build()
        .translate(db)
}

fn report(sql: &str) -> Vec<ActionRelations> {
    let db: ParserDB = parse_schema(sql).expect("schema should parse");
    translate(&db).action_relations()
}

fn dsl(sql: &str) -> String {
    let db: ParserDB = parse_schema(sql).expect("schema should parse");
    translate(&db).outputs_accepting_gaps().model()
}

fn entry<'a>(
    entries: &'a [ActionRelations],
    type_name: &str,
    statement: ActionStatement,
) -> &'a ActionRelations {
    entries
        .iter()
        .find(|entry| entry.type_name == *type_name && entry.statement == statement)
        .unwrap_or_else(|| panic!("no {statement:?} entry for {type_name}, got {entries:#?}"))
}

/// The judgements of one entry as `(relation, version)`, refusing any other answer.
fn judges(entry: &ActionRelations) -> Vec<(String, RowVersion)> {
    match &entry.answer {
        ActionAnswer::Judged(judges) => judges
            .iter()
            .map(|judge| (judge.relation.as_str().to_string(), judge.version))
            .collect(),
        other => panic!("{:?} is judged by nothing: {other:?}", entry.statement),
    }
}

fn judged(pairs: &[(&str, RowVersion)]) -> Vec<(String, RowVersion)> {
    pairs
        .iter()
        .map(|(relation, version)| ((*relation).to_string(), *version))
        .collect()
}

/// Every relation an entry names, whatever answer carries it.
fn named_relations(entry: &ActionRelations) -> Vec<String> {
    match &entry.answer {
        ActionAnswer::Judged(judges) => judges
            .iter()
            .map(|judge| judge.relation.as_str().to_string())
            .collect(),
        ActionAnswer::NotSeparable { relation } => vec![relation.as_str().to_string()],
        _ => Vec::new(),
    }
}

/// The property whose absence is the defect: a consumer can ask everything the report
/// names, whatever shape the policy was spelled in.
#[test]
fn every_relation_the_report_names_is_defined_in_the_emitted_model() {
    let mut named = 0usize;
    for (label, sql) in EVERY_SCHEMA {
        let model = dsl(sql);
        for entry in report(sql) {
            for relation in named_relations(&entry) {
                named += 1;
                assert!(
                    relation_definition(&model, entry.type_name.as_str(), &relation).is_some(),
                    "{label}: {} names {relation} on {}, which the model does not define:\n{model}",
                    format_args!("{:?}", entry.statement),
                    entry.type_name.as_str()
                );
            }
        }
    }
    assert!(
        named >= 40,
        "the corpus named only {named} relations, so the check above proves little"
    );
}

/// `PostgreSQL` applies a lone `USING` clause to the result as well, so the one
/// relation answers both versions.
#[test]
fn one_condition_names_its_relation_for_both_versions() {
    let entries = report(ONE_CONDITION);
    assert_eq!(
        judges(entry(&entries, "notes", ActionStatement::Update)),
        judged(&[
            ("can_update", RowVersion::Existing),
            ("can_update", RowVersion::Resulting),
        ])
    );
}

#[test]
fn two_clauses_name_the_using_half_for_the_row_and_the_check_half_for_the_result() {
    let entries = report(TWO_CONDITIONS);
    assert_eq!(
        judges(entry(&entries, "notes", ActionStatement::Update)),
        judged(&[
            ("can_update_using", RowVersion::Existing),
            ("can_update_check", RowVersion::Resulting),
        ])
    );
}

#[test]
fn a_read_judges_the_row_an_insert_the_result_and_a_delete_the_row() {
    let entries = report(ONE_CONDITION);
    for (statement, expected) in [
        (
            ActionStatement::Select,
            judged(&[("can_select", RowVersion::Existing)]),
        ),
        (
            ActionStatement::Insert,
            judged(&[("can_insert", RowVersion::Resulting)]),
        ),
        (
            ActionStatement::Delete,
            judged(&[("can_delete", RowVersion::Existing)]),
        ),
    ] {
        assert_eq!(judges(entry(&entries, "notes", statement)), expected);
    }
}

/// A locking read is filtered by the `SELECT` policies and by the `UPDATE` policies'
/// `USING` clause, and the relation named for it carries only the second.
#[test]
fn a_locking_read_names_the_read_gate_beside_the_update_half() {
    let entries = report(ONE_CONDITION);
    assert_eq!(
        judges(entry(&entries, "notes", ActionStatement::SelectForUpdate)),
        judged(&[
            ("can_select", RowVersion::Existing),
            ("can_select_for_update", RowVersion::Existing),
        ])
    );
}

/// `can_upsert` fuses an insert judging the result with an update judging both
/// versions, so the report names its halves rather than the fusion.
#[test]
fn an_upsert_names_the_insert_and_the_update_halves() {
    let entries = report(INSERT_AND_UPDATE);
    assert_eq!(
        judges(entry(
            &entries,
            "notes",
            ActionStatement::InsertOnConflictUpdate
        )),
        judged(&[
            ("can_insert", RowVersion::Resulting),
            ("can_update", RowVersion::Existing),
            ("can_update", RowVersion::Resulting),
        ])
    );
    assert!(
        relation_definition(&dsl(INSERT_AND_UPDATE), "notes", "can_upsert").is_some(),
        "the schema is pointless unless the model defines the fusion it decomposes"
    );
}

/// The returned row is the new one, and reading it needs the read gate the model
/// already folded into `can_insert_returning`. That relation is dropped wherever it
/// would repeat `can_insert`, and absent wherever nothing admits an insert, so the
/// plain insert answers in both.
#[test]
fn an_insert_that_returns_rows_judges_the_result_through_the_read_gated_relation() {
    assert_eq!(
        judges(entry(
            &report(INSERT_AND_UPDATE),
            "notes",
            ActionStatement::InsertReturning
        )),
        judged(&[("can_insert_returning", RowVersion::Resulting)])
    );
    assert!(
        relation_definition(&dsl(INSERT_AND_UPDATE), "notes", "can_insert_returning").is_some(),
        "the schema is pointless unless the model defines the read-gated insert"
    );
    assert_eq!(
        judges(entry(
            &report(READS_ONLY),
            "notes",
            ActionStatement::InsertReturning
        )),
        judged(&[("can_insert", RowVersion::Resulting)]),
        "with nothing admitting an insert the model defines no read-gated insert, and \
         the plain denial is what answers"
    );
}

#[test]
fn a_blind_update_of_one_condition_names_its_relation_for_both_versions() {
    assert_eq!(
        judges(entry(
            &report(ONE_CONDITION),
            "notes",
            ActionStatement::UpdateWithoutWhere
        )),
        judged(&[
            ("can_update_without_reading", RowVersion::Existing),
            ("can_update_without_reading", RowVersion::Resulting),
        ])
    );
}

/// The fused relation is `USING and WITH CHECK` in one, and nothing carries the
/// `USING` half without the read gate a blind update does not need.
#[test]
fn a_blind_update_of_two_clauses_has_no_single_version_answer() {
    let entries = report(TWO_CONDITIONS);
    let entry = entry(&entries, "notes", ActionStatement::UpdateWithoutWhere);
    match &entry.answer {
        ActionAnswer::NotSeparable { relation } => {
            assert_eq!(relation.as_str(), "can_update_without_reading");
        }
        other => panic!("a fused relation cannot be judged per version, got {other:?}"),
    }
}

/// So a consumer can ask and be told no, rather than not knowing what to ask.
#[test]
fn an_action_granting_nobody_still_gets_an_entry() {
    let entries = report(READS_ONLY);
    assert_eq!(
        judges(entry(&entries, "notes", ActionStatement::Update)),
        judged(&[
            ("can_update", RowVersion::Existing),
            ("can_update", RowVersion::Resulting),
        ])
    );
    assert_eq!(
        relation_definition(&dsl(READS_ONLY), "notes", "can_update").as_deref(),
        Some("no_access"),
        "the entry is only worth having because the answer it names is a denial"
    );
}

/// The database restricts nothing on it, and saying that is not the same as saying
/// nothing.
#[test]
fn a_table_the_database_does_not_restrict_reports_every_action_unrestricted() {
    let entries = report(UNRESTRICTED_PARENT);
    for statement in EVERY_STATEMENT {
        assert_eq!(
            entry(&entries, "projects", statement).answer,
            ActionAnswer::Unrestricted
        );
    }
    assert!(
        matches!(
            entry(&entries, "docs", ActionStatement::Select).answer,
            ActionAnswer::Judged(_)
        ),
        "and the guarded table beside it is still judged"
    );
}

#[test]
fn every_type_the_model_names_rows_of_answers_every_statement() {
    for (label, sql) in EVERY_SCHEMA {
        let db: ParserDB = parse_schema(sql).expect("schema should parse");
        let planned = translate(&db);
        let entries = planned.action_relations();
        for naming in planned.row_naming() {
            let statements: Vec<ActionStatement> = entries
                .iter()
                .filter(|entry| entry.type_name.as_str() == naming.type_name)
                .map(|entry| entry.statement)
                .collect();
            assert_eq!(
                statements,
                EVERY_STATEMENT.to_vec(),
                "{label}: {} is named as a row but answers {statements:?}",
                naming.type_name
            );
        }
    }
}

/// A type nothing keys on a row is not something a consumer asks about.
#[test]
fn a_type_that_is_no_table_has_no_entry() {
    let entries = report(UNRESTRICTED_PARENT);
    for type_name in ["user", "project_members"] {
        assert!(
            !entries
                .iter()
                .any(|entry| entry.type_name.as_str() == type_name),
            "{type_name} has no rows the model answers for, yet it has an entry"
        );
    }
}

/// The statement joins the notes, which name a SQL command and not a statement shape.
#[test]
fn every_statement_names_the_command_it_answers() {
    let commands: Vec<&str> = EVERY_STATEMENT
        .iter()
        .map(ActionStatement::command)
        .collect();
    assert_eq!(
        commands,
        ["SELECT", "INSERT", "UPDATE", "DELETE", "SELECT", "INSERT", "INSERT", "UPDATE"]
    );
}

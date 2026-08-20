//! A row of the generated tuple SQL becomes the record it stands for.
//!
//! Turning a result row into a fact is the one step a consumer had to invent, and
//! inventing it wrong loads tuples that are silently wrong in whichever direction
//! the guess fell. Everything here drives the public surface a second crate uses.

use rls2fga::classifier::patterns::ConfidenceLevel;
use rls2fga::generator::model_generator::GeneratorSettings;
use rls2fga::generator::records::{
    records_from_row, ColumnKind, Record, RecordDerivation, RowCell, RowList, RowValues,
};
use rls2fga::generator::tuple_generator::{TupleCondition, TupleRow, TupleRowError};
use rls2fga::generator::well_known::deny_relation;
use rls2fga::parser::sql_parser::{parse_schema, ParserDB};
use rls2fga::translator::{Outputs, Translation, TranslatorBuilder};

mod support;

const OWNERSHIP: &str = "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE docs (id TEXT PRIMARY KEY, owner_id TEXT);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING (owner_id = auth_current_user_id());
";

const ACCESSOR_REGISTRY: &str =
    r#"{"auth_current_user_id": {"kind": "current_user_accessor", "returns": "text"}}"#;

/// One row, so a description can be evaluated against it.
struct Row(Vec<(String, String)>);

impl RowValues for Row {
    fn cell(&self, column: &str, kind: ColumnKind) -> RowCell<'_> {
        let Some((_, value)) = self.0.iter().find(|(name, _)| name == column) else {
            return RowCell::Absent;
        };
        match kind {
            ColumnKind::Text => RowCell::Text(value.as_str().into()),
            ColumnKind::Integer => RowCell::Integer(value.as_str().into()),
            ColumnKind::Decimal => RowCell::Decimal(value.as_str().into()),
            ColumnKind::Date => RowCell::Date(value.as_str().into()),
            ColumnKind::Time => RowCell::Time(value.as_str().into()),
            ColumnKind::Timestamp => RowCell::Timestamp(value.as_str().into()),
            ColumnKind::TimestampTz => RowCell::TimestampTz(value.as_str().into()),
            ColumnKind::Uuid => RowCell::Uuid(value.as_str().into()),
            _ => RowCell::Undecodable,
        }
    }

    fn list(&self, _column: &str, _kind: ColumnKind) -> RowList<'_> {
        RowList::Absent
    }

    fn json_text(&self, _column: &str, _path: &[String]) -> RowCell<'_> {
        RowCell::Absent
    }
}

fn row(pairs: &[(&str, &str)]) -> Row {
    Row(pairs
        .iter()
        .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
        .collect())
}

fn ownership_db() -> ParserDB {
    parse_schema(OWNERSHIP).expect("the schema should parse")
}

fn ownership_outputs(db: &ParserDB) -> Outputs<'_, ParserDB> {
    TranslatorBuilder::new()
        .with_min_confidence(ConfidenceLevel::B)
        .with_registry_json(ACCESSOR_REGISTRY)
        .expect("the registry should parse")
        .build()
        .translate(db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
}

/// The record every other case here varies one column of.
fn owner_row<'a>() -> TupleRow<'a> {
    TupleRow {
        object: "docs:d1",
        relation: "owner",
        subject: "user:u1",
        condition: None,
    }
}

#[test]
fn a_row_of_the_tuple_sql_becomes_the_fact_it_spells() {
    let db = ownership_db();
    let outputs = ownership_outputs(&db);

    let record = outputs
        .record_from_tuple_row(owner_row())
        .expect("the model defines owner on docs");

    assert_eq!(record.object, "docs:d1");
    assert_eq!(record.relation, "owner");
    assert_eq!(record.subject, "user:u1");
    assert_eq!(record.context, None);
}

#[test]
fn a_relation_the_model_does_not_define_is_refused() {
    let db = ownership_db();
    let outputs = ownership_outputs(&db);

    assert_eq!(
        outputs.record_from_tuple_row(TupleRow {
            relation: "editor",
            ..owner_row()
        }),
        Err(TupleRowError::UnknownRelation {
            type_name: "docs".to_string(),
            relation: "editor".to_string(),
        })
    );
}

#[test]
fn a_computed_relation_takes_no_tuples() {
    let db = ownership_db();
    let outputs = ownership_outputs(&db);

    assert_eq!(
        outputs.record_from_tuple_row(TupleRow {
            relation: "can_select",
            ..owner_row()
        }),
        Err(TupleRowError::RelationTakesNoTuples {
            type_name: "docs".to_string(),
            relation: "can_select".to_string(),
        }),
        "can_select is computed from owner, so a tuple on it is a mistake the server also refuses"
    );
}

/// The relation every uncovered command denies with takes no tuple either.
///
/// `no_access` is a direct relation nothing populates, so the denial rests on nobody
/// writing it. One hand-written row turns `can_insert`, `can_update` and `can_delete`
/// from a denial into a grant, and this reader is the surface that has to say no.
#[test]
fn a_row_naming_the_denial_relation_is_refused() {
    let db = ownership_db();
    let outputs = ownership_outputs(&db);
    let denial = deny_relation();

    let forged = TupleRow {
        relation: denial.as_str(),
        ..owner_row()
    };
    assert!(
        outputs.record_from_tuple_row(forged).is_err(),
        "a row naming the relation the model denies with must be refused, not read back"
    );

    // The companion half, so refusing everything does not pass: a relation that does
    // grant still reads back.
    assert!(
        outputs.record_from_tuple_row(owner_row()).is_ok(),
        "a relation that grants has to keep reading back"
    );
}

#[test]
fn a_type_the_model_does_not_define_is_refused() {
    let db = ownership_db();
    let outputs = ownership_outputs(&db);

    assert_eq!(
        outputs.record_from_tuple_row(TupleRow {
            object: "invoices:i1",
            ..owner_row()
        }),
        Err(TupleRowError::UnknownType("invoices".to_string()))
    );
}

#[test]
fn a_name_that_is_not_a_typed_name_is_refused() {
    let db = ownership_db();
    let outputs = ownership_outputs(&db);

    assert_eq!(
        outputs.record_from_tuple_row(TupleRow {
            object: "docs",
            ..owner_row()
        }),
        Err(TupleRowError::MalformedObject("docs".to_string()))
    );
    assert_eq!(
        outputs.record_from_tuple_row(TupleRow {
            subject: "u1",
            ..owner_row()
        }),
        Err(TupleRowError::MalformedSubject("u1".to_string()))
    );
}

#[test]
fn a_condition_on_a_relation_that_names_none_is_refused() {
    let db = ownership_db();
    let outputs = ownership_outputs(&db);

    assert_eq!(
        outputs.record_from_tuple_row(TupleRow {
            condition: Some(TupleCondition {
                name: "tenant_matches",
                context: r#"{"tenant_id":"t1"}"#,
            }),
            ..owner_row()
        }),
        Err(TupleRowError::ConditionMismatch {
            type_name: "docs".to_string(),
            relation: "owner".to_string(),
            named: Some("tenant_matches".to_string()),
        }),
        "owner grants outright, so a tuple claiming a condition would grant less than the model says"
    );
}

#[test]
fn a_gated_record_names_the_condition_its_tuple_has_to_carry() {
    let (classified, db, registry) = support::try_load_fixture_classified("tenant_setting");
    let outputs = Translation::plan(
        classified,
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .expect("translation should plan")
    .outputs_accepting_gaps();

    let queries = outputs.tuple_queries();
    let query = queries
        .iter()
        .find(|query| query.condition.is_some())
        .expect("the tenant gate writes conditional tuples");
    let description = query
        .description
        .as_ref()
        .expect("every emitted query describes its records");
    assert!(
        matches!(description.derivation, RecordDerivation::FromRow { .. }),
        "the row carries its own side of the comparison"
    );

    let records = records_from_row(
        description,
        &row(&[
            ("id", "11111111-1111-1111-1111-111111111111"),
            ("tenant_id", "22222222-2222-2222-2222-222222222222"),
        ]),
    )
    .expect("the row decides its records");
    let [record] = records.as_slice() else {
        panic!("one row of documents carries one gate tuple, got {records:?}");
    };
    let context = record
        .context
        .as_ref()
        .expect("a gated record carries the row's side of the comparison");

    assert_eq!(
        context.condition,
        *query
            .condition
            .as_ref()
            .expect("the query is the conditional one"),
        "the record names the condition its own query writes"
    );
}

#[test]
fn every_record_a_row_yields_survives_the_trip_through_its_own_sql_row() {
    let (classified, db, registry) = support::try_load_fixture_classified("tenant_setting");
    let outputs = Translation::plan(
        classified,
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .expect("translation should plan")
    .outputs_accepting_gaps();

    let mut checked = 0usize;
    for query in outputs.tuple_queries() {
        let Some(description) = query.description.as_ref() else {
            continue;
        };
        if !description.is_pure() {
            continue;
        }
        let records = records_from_row(
            description,
            &row(&[
                ("id", "11111111-1111-1111-1111-111111111111"),
                ("tenant_id", "22222222-2222-2222-2222-222222222222"),
            ]),
        )
        .expect("a pure description answers from the row");
        for record in records {
            let context_json = record
                .context
                .as_ref()
                .map(|context| {
                    let body = context
                        .values
                        .iter()
                        .map(|(key, value)| format!(r#""{key}":"{value}""#))
                        .collect::<Vec<_>>()
                        .join(",");
                    format!("{{{body}}}")
                })
                .unwrap_or_default();
            let back: Record = outputs
                .record_from_tuple_row(TupleRow {
                    object: &record.object,
                    relation: record.relation.as_str(),
                    subject: &record.subject,
                    condition: record.context.as_ref().map(|context| TupleCondition {
                        name: context.condition.as_str(),
                        context: context_json.as_str(),
                    }),
                })
                .expect("a record's own columns describe a record");
            assert_eq!(
                back, record,
                "the trip through the SQL row changed the fact"
            );
            checked += 1;
        }
    }
    assert!(checked > 0, "the fixture yields records to check");
}

#[test]
fn a_conditional_tuple_needs_a_condition_and_a_readable_context() {
    let (classified, db, registry) = support::try_load_fixture_classified("tenant_setting");
    let outputs = Translation::plan(
        classified,
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .expect("translation should plan")
    .outputs_accepting_gaps();

    let queries = outputs.tuple_queries();
    let query = queries
        .iter()
        .find(|query| query.condition.is_some())
        .expect("the tenant gate writes conditional tuples");
    let condition = query.condition.as_deref().expect("the conditional query");
    let RecordDerivation::FromRow { template, .. } = &query
        .description
        .as_ref()
        .expect("the query describes its records")
        .derivation
    else {
        panic!("the gate is decided by the row");
    };
    let object = "documents:11111111-1111-1111-1111-111111111111".to_string();
    let relation = template.relation.as_str();

    assert_eq!(
        outputs.record_from_tuple_row(TupleRow {
            object: &object,
            relation,
            subject: "user:*",
            condition: Some(TupleCondition {
                name: condition,
                context: "{}",
            }),
        }),
        Err(TupleRowError::MalformedContext("{}".to_string())),
        "a conditional tuple whose context reads no value is not one the model emits"
    );

    assert_eq!(
        outputs.record_from_tuple_row(TupleRow {
            object: &object,
            relation,
            subject: "user:*",
            condition: None,
        }),
        Err(TupleRowError::ConditionMismatch {
            type_name: "documents".to_string(),
            relation: relation.to_string(),
            named: None,
        }),
        "the gate grants nobody without the comparison, so an unconditional tuple grants everyone"
    );
}

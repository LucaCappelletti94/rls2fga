//! Reaching the outputs, and what stops it.
use core::fmt::Write;

use rls2fga::generator::model_bounds::ModelBound;
use rls2fga::generator::well_known::WellKnownTypes;
use rls2fga::translator::PlanningError;

use rls2fga::generator::tuple_generator::format_tuples;
use rls2fga::parser::sql_parser::{parse_schema, ParserDB};
use rls2fga::translator::{Translator, TranslatorBuilder};
use rls2fga::types::ConfidenceLevel;
use rls2fga::types::{NoteSeverity, TranslationNote};

fn db_of(sql: &str) -> ParserDB {
    parse_schema(sql).expect("schema should parse")
}

fn translator(min_confidence: ConfidenceLevel) -> Translator {
    TranslatorBuilder::new()
        .with_min_confidence(min_confidence)
        .build()
}

/// A schema every clause of which translates.
const CLEAN: &str = "CREATE TABLE users(id UUID PRIMARY KEY);\n\
                     CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID NOT NULL REFERENCES users(id));\n\
                     ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
                     CREATE POLICY docs_all ON docs FOR ALL USING (owner_id = current_user) \
                     WITH CHECK (owner_id = current_user);\n";

/// A bit test this crate has no translation for.
const REFUSED: &str = "CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT, bits INT);\n\
                       ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
                       CREATE POLICY docs_sel ON docs FOR SELECT USING ((bits & 2) = 2);\n";

/// A RESTRICTIVE barrier the caller's own threshold drops, beside a grant that
/// survives. `P6BooleanFlag` is confidence B by design, so requesting A drops the
/// barrier and nothing else.
const RESTRICTIVE_BELOW_THRESHOLD: &str =
    "CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT, is_public BOOLEAN);\n\
     ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
     CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);\n\
     CREATE POLICY docs_bar ON docs AS RESTRICTIVE FOR SELECT USING (is_public);\n";

/// An expression nobody classified means the model denies what the database grants, so
/// the outputs are refused until the caller has seen it.
#[test]
fn an_unhandled_expression_refuses_the_outputs() {
    let db = db_of(REFUSED);
    let error = translator(ConfidenceLevel::D)
        .translate(&db)
        .expect("translation should plan")
        .outputs()
        .expect_err("an unclassified expression must refuse");

    assert_eq!(error.notes().len(), 1, "got {:?}", error.notes());
    assert_eq!(error.notes()[0].severity(), NoteSeverity::Unhandled);
    assert!(
        error
            .to_string()
            .contains("denies what the database grants"),
        "the refusal has to say what it costs, got: {error}"
    );
}

/// Accepting the gaps is the same outputs, one visible line later.
#[test]
fn accepting_the_gaps_yields_the_same_outputs() {
    let db = db_of(REFUSED);
    let accepted = translator(ConfidenceLevel::D)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();

    assert!(
        accepted.model().contains("define can_select: no_access"),
        "the narrower model is still a model:\n{}",
        accepted.model()
    );

    // The refusal names the unhandled notes only, while the accepted outputs carry
    // every note, so nothing is lost by taking the other door.
    let refused = translator(ConfidenceLevel::D)
        .translate(&db)
        .expect("translation should plan")
        .outputs()
        .expect_err("still refused");
    assert!(
        refused
            .notes()
            .iter()
            .all(|note| accepted.notes().contains(note)),
        "every refused note is among the accepted ones: {:?} vs {:?}",
        refused.notes(),
        accepted.notes()
    );
    assert!(
        accepted.notes().len() > refused.notes().len(),
        "and the accepted side keeps the notes that are not gaps"
    );
}

/// A schema that fully translates hands the outputs over without ceremony.
#[test]
fn a_translation_with_nothing_unhandled_answers() {
    let db = db_of(CLEAN);
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs()
        .expect("nothing went unhandled");

    assert!(outputs.model().contains("type docs"));
}

/// The payoff of typing the notes. A clause the caller's own threshold dropped is their
/// choice, not a limitation of this crate, so it must not refuse: the same schema that
/// refuses at `D` has to answer at `B`.
#[test]
fn a_clause_the_callers_threshold_dropped_does_not_refuse() {
    let db = db_of(REFUSED);
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs()
        .expect("the caller's own threshold is not a gap in the translation");

    assert!(
        outputs
            .notes()
            .iter()
            .any(|note| note.severity() == NoteSeverity::BelowThreshold),
        "the loss is still reported: {:?}",
        outputs.notes()
    );
    assert!(
        outputs
            .report()
            .contains("fell below the confidence threshold"),
        "and the report still names it:\n{}",
        outputs.report()
    );
}

/// The same payoff, for the mode it never covered. A RESTRICTIVE clause the caller's
/// own threshold dropped is the same caller choice as a permissive one and must not
/// refuse either. It used to: the stand-in denial was filed as an expression nobody
/// classified, which is the one severity that blocks the outputs, so raising the bar
/// made the crate refuse to answer at all. The stand-in still denies, so the model is
/// unchanged, and the loss is now reported as what it is.
#[test]
fn a_restrictive_clause_the_callers_threshold_dropped_does_not_refuse() {
    let db = db_of(RESTRICTIVE_BELOW_THRESHOLD);
    let outputs = translator(ConfidenceLevel::A)
        .translate(&db)
        .expect("translation should plan")
        .outputs()
        .expect("the caller's own threshold is not a gap in the translation");

    let dropped: Vec<&TranslationNote> = outputs
        .notes()
        .iter()
        .filter(|note| matches!(note, TranslationNote::ClauseBelowThreshold { .. }))
        .collect();
    assert_eq!(
        dropped.len(),
        1,
        "the barrier's loss is reported once: {:?}",
        outputs.notes()
    );
    assert!(
        matches!(
            dropped[0],
            TranslationNote::ClauseBelowThreshold { mode, policy, .. }
                if mode == "RESTRICTIVE" && policy == "docs_bar"
        ),
        "and it names the barrier and its mode: {:?}",
        dropped[0]
    );
    assert!(
        !outputs
            .notes()
            .iter()
            .any(|note| matches!(note, TranslationNote::ExpressionRefused { .. })),
        "a clause the crate could read is not an expression nobody classified: {:?}",
        outputs.notes()
    );
    assert!(
        outputs
            .model()
            .contains("define can_select: owner and no_access"),
        "the barrier still denies, so the emitted model is unchanged:\n{}",
        outputs.model()
    );
}

/// One plan, three outputs. Asking for each of them twice must not change any of them,
/// which is what says the plan is held rather than rebuilt per call.
#[test]
fn every_output_renders_from_one_plan() {
    let db = db_of(CLEAN);
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs()
        .expect("nothing went unhandled");

    assert_eq!(outputs.model(), outputs.model());
    assert_eq!(
        format_tuples(outputs.tuple_queries()),
        format_tuples(outputs.tuple_queries())
    );
    assert_eq!(
        serde_json::to_string(&outputs.json_model()).expect("serializes"),
        serde_json::to_string(&outputs.json_model()).expect("serializes")
    );
}

#[test]
fn translation_note_table_serializes_as_string() {
    use rls2fga::types::TableId;
    let note = TranslationNote::NoPermissivePolicy {
        table: TableId::from_stored(Some("public".to_string()), "docs".to_string()),
        commands: vec!["SELECT".to_string()],
    };
    let json = serde_json::to_string(&note).expect("note serializes");
    assert_eq!(
        json,
        r#"{"NoPermissivePolicy":{"table":"public.docs","commands":["SELECT"]}}"#
    );
}

#[test]
fn translation_note_roundtrips_from_baseline_string_table_json() {
    use rls2fga::types::TranslationNote;
    let baseline = r#"{"NoPermissivePolicy":{"table":"public.docs","commands":["SELECT"]}}"#;
    let result: Result<TranslationNote, _> = serde_json::from_str(baseline);
    assert!(result.is_ok(), "baseline note JSON refused: {result:?}");
    let TranslationNote::NoPermissivePolicy { table, commands } = result.unwrap() else {
        panic!("wrong variant");
    };
    assert_eq!(table.schema(), Some("public"));
    assert_eq!(table.name(), "docs");
    assert_eq!(commands, vec!["SELECT".to_string()]);
}

#[test]
fn translation_note_roundtrips_quoted_table_parts() {
    use rls2fga::types::TranslationNote;
    let baseline =
        r#"{"NoPermissivePolicy":{"table":"\"my.schema\".\"ta\"\"ble\"","commands":["SELECT"]}}"#;
    let note: TranslationNote = serde_json::from_str(baseline).expect("note deserializes");
    let TranslationNote::NoPermissivePolicy { table, .. } = &note else {
        panic!("wrong variant");
    };
    assert_eq!(table.schema(), Some("my.schema"));
    assert_eq!(table.name(), "ta\"ble");
    assert_eq!(
        serde_json::to_string(&note).expect("note serializes"),
        baseline
    );
}

#[test]
fn relation_name_deserialization_rejects_invalid_strings() {
    use rls2fga::types::RelationName;
    let result: Result<RelationName, _> = serde_json::from_str(r#""not valid""#);
    assert!(
        result.is_err(),
        "invalid relation name accepted: {result:?}"
    );
}

/// One table guarded by the clock, so its read earns a condition.
const TEMPORAL: &str = "CREATE TABLE docs(id UUID PRIMARY KEY, expires_at TIMESTAMPTZ);\n\
                       ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
                       CREATE POLICY docs_sel ON docs FOR SELECT USING (expires_at > now());\n";

/// `count` tables, each guarded by a temporal clause with its own offset, so every
/// guard is a distinct condition.
fn schema_with_temporal_guards(count: usize) -> String {
    let mut sql = String::new();
    for index in 0..count {
        writeln!(
            sql,
            "CREATE TABLE t{index:02}(id UUID PRIMARY KEY, expires_at TIMESTAMPTZ);\n\
             ALTER TABLE t{index:02} ENABLE ROW LEVEL SECURITY;\n\
             CREATE POLICY t{index:02}_sel ON t{index:02} FOR SELECT \
             USING (expires_at > now() - interval '{offset} days');\n",
            offset = index + 1,
        )
        .expect("schema writes");
    }
    sql
}

/// `OpenFGA` refuses a model declaring more than 25 conditions, and a model the
/// service would refuse must not leave the translator.
#[test]
fn twenty_six_conditions_refuse_the_translation() {
    let db = db_of(&schema_with_temporal_guards(26));
    let error = TranslatorBuilder::new()
        .build()
        .translate(&db)
        .expect_err("26 distinct conditions cross the bound");
    let PlanningError::ModelBoundExceeded {
        bound,
        measured,
        limit,
        ref item,
    } = error
    else {
        panic!("the crossed bound must name itself: {error:?}");
    };
    assert!(matches!(bound, ModelBound::Conditions), "got {bound:?}");
    assert_eq!(measured, 26);
    assert_eq!(limit, 25);
    assert!(
        !item.is_empty(),
        "the item must name the condition it counts"
    );
    let message = error.to_string();
    assert!(
        message.contains("25") && message.contains("26"),
        "the message must name the limit and the count, got {message}"
    );
}

/// Sitting exactly on the bound is within it.
#[test]
fn twenty_five_conditions_still_translate() {
    let db = db_of(&schema_with_temporal_guards(25));
    let outputs = TranslatorBuilder::new()
        .build()
        .translate(&db)
        .expect("25 conditions sit exactly on the bound")
        .outputs_accepting_gaps();
    assert_eq!(
        outputs
            .json_model()
            .conditions
            .as_ref()
            .map_or(0, std::collections::BTreeMap::len),
        25,
        "the model must declare exactly the 25 distinct guards"
    );
}

/// The request-time parameter a deployment configures names the request side of
/// every temporal condition, so one past fifty characters crosses a bound the
/// write would refuse.
#[test]
fn a_request_time_parameter_over_fifty_characters_refuses_the_translation() {
    let db = db_of(TEMPORAL);
    let error = TranslatorBuilder::new()
        .with_request_time_parameter("t".repeat(55))
        .expect("fifty five letters are a valid identifier")
        .build()
        .translate(&db)
        .expect_err("the parameter name crosses its bound");
    let PlanningError::ModelBoundExceeded {
        bound,
        measured,
        limit,
        ..
    } = error
    else {
        panic!("the crossed bound must name itself: {error:?}");
    };
    assert!(
        matches!(bound, ModelBound::ConditionParameterKey),
        "got {bound:?}"
    );
    assert_eq!(measured, 55);
    assert_eq!(limit, 50);
}

/// A configured well-known type name is length-checked only where the written
/// model is checked, since the constructor takes what the deployment spells.
#[test]
fn a_configured_type_name_past_two_hundred_fifty_four_refuses_the_translation() {
    let well_known = WellKnownTypes::new(
        "u".repeat(255),
        "team",
        "pg_role",
        "pg_role_scope",
        "nobody",
    )
    .expect("the name is otherwise valid");
    let db = db_of(CLEAN);
    let error = TranslatorBuilder::new()
        .with_well_known_types(well_known)
        .build()
        .translate(&db)
        .expect_err("the type name crosses its bound");
    let PlanningError::ModelBoundExceeded {
        bound,
        measured,
        limit,
        item,
    } = error
    else {
        panic!("the crossed bound must name itself: {error:?}");
    };
    assert!(matches!(bound, ModelBound::TypeName), "got {bound:?}");
    assert_eq!(measured, 255);
    assert_eq!(limit, 254);
    assert_eq!(item, "u".repeat(255));
}

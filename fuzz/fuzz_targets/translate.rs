#![no_main]

use std::borrow::Cow;
use std::hint::black_box;

use libfuzzer_sys::fuzz_target;
use rls2fga::classifier::oracle::{consult_oracle, OracleAnswer, PolicyOracle, RefusedExpr};
use rls2fga::classifier::patterns::{
    ClassifiedExpr, ConfidenceLevel, ConstantBool, PatternClass,
};
use rls2fga::generator::model_generator::GeneratorSettings;
use rls2fga::generator::records::{records_from_row, RowValues};
use rls2fga::generator::tuple_generator::format_tuples;
use rls2fga::parser::sql_parser::parse_schema;
use rls2fga::translator::{Translation, TranslatorBuilder};

/// Answers out of the refused text alone, so one input always draws one answer and a
/// crash replays. Spreads across all three states, since each reaches the pipeline
/// differently: a bail leaves the refusal standing, a denial substitutes a constant
/// false, and a classification faces `min_confidence` like any other.
struct TextOracle;

impl PolicyOracle for TextOracle {
    fn classify(&self, refused: &RefusedExpr<'_>) -> OracleAnswer {
        let len = refused.sql_text().len();
        match len % 3 {
            0 => OracleAnswer::Bailed,
            1 => OracleAnswer::Denied,
            _ => OracleAnswer::Classified(Box::new(ClassifiedExpr {
                pattern: PatternClass::P10ConstantBool(ConstantBool {
                    value: len.is_multiple_of(2),
                }),
                confidence: ConfidenceLevel::B,
            })),
        }
    }
}

/// One row's values, answered from the input so every column is decided by the same
/// bytes the schema came from. Each accessor withholds a value on some columns, which
/// is what drives the `NULL` and absent-column branches.
struct FuzzRow<'a>(&'a str);

impl FuzzRow<'_> {
    fn mix(&self, column: &str) -> usize {
        column.len().wrapping_add(self.0.len())
    }
}

impl RowValues for FuzzRow<'_> {
    fn text(&self, column: &str) -> Option<Cow<'_, str>> {
        (!self.mix(column).is_multiple_of(4)).then_some(Cow::Borrowed(self.0))
    }

    fn boolean(&self, column: &str) -> Option<bool> {
        let mixed = self.mix(column);
        (!mixed.is_multiple_of(5)).then(|| mixed.is_multiple_of(2))
    }

    fn list(&self, column: &str) -> Option<Vec<Option<Cow<'_, str>>>> {
        (!self.mix(column).is_multiple_of(6))
            .then(|| vec![Some(Cow::Borrowed(self.0)), None, Some(Cow::Borrowed(""))])
    }

    fn json_text(&self, column: &str, path: &[String]) -> Option<Cow<'_, str>> {
        (!self.mix(column).wrapping_add(path.len()).is_multiple_of(7))
            .then_some(Cow::Borrowed(self.0))
    }
}

/// Render every output, and walk the records every shape describes.
fn exercise(translation: Translation<'_>, sql: &str) {
    let unhandled = translation.unhandled().count();
    // The refusing door answers exactly when nothing went unhandled.
    assert_eq!(
        translation.clone().outputs().is_err(),
        unhandled > 0,
        "outputs() and unhandled() disagree"
    );

    let shapes = translation.relations();
    let outputs = translation.outputs_accepting_gaps();
    black_box(outputs.model());
    black_box(outputs.json_model());
    black_box(outputs.notes().len());
    black_box(outputs.confidence_summary().len());

    let queries = outputs.tuple_queries();
    let row = FuzzRow(sql);
    for query in &queries {
        if let Some(description) = query.description.as_ref() {
            black_box(records_from_row(description, &row).is_ok());
            black_box(description.is_pure());
            black_box(description.row_table());
        }
    }
    for entry in &shapes {
        black_box(entry.from_one_row);
        for shape in &entry.shapes {
            black_box(records_from_row(shape, &row).is_ok());
            black_box(shape.is_pure());
            black_box(shape.row_table());
        }
    }
    black_box(format_tuples(&queries));
    black_box(outputs.report());
}

/// Without a registry no function is ever an accessor, so the whole role-threshold
/// pattern and the relations it scaffolds are unreachable at any runtime. Naming the
/// same functions the fixtures use puts those paths behind a token the dictionary
/// carries rather than behind nothing at all.
const REGISTRY: &str = r#"{
  "get_owner_role": {
    "kind": "role_threshold",
    "user_param_index": 0,
    "resource_param_index": 1,
    "role_levels": {"viewer": 2, "editor": 3, "admin": 4},
    "grant_table": "owner_grants",
    "grant_grantee_col": "grantee_owner_id",
    "grant_resource_col": "granted_owner_id",
    "grant_role_col": "role_id",
    "team_membership_table": "team_members",
    "team_membership_user_col": "user_id",
    "team_membership_team_col": "team_id"
  },
  "auth_current_user_id": {"kind": "current_user_accessor", "returns": "text"},
  "auth_role": {"kind": "role_accessor", "returns": "text"}
}"#;

fn translator_at(level: ConfidenceLevel) -> rls2fga::translator::Translator {
    TranslatorBuilder::new()
        .with_min_confidence(level)
        .with_registry_json(REGISTRY)
        .expect("the harness registry is a fixed literal")
        .build()
}

/// Drive the full translation pipeline on one SQL input.
///
/// The property under test is that no input, however malformed, may panic or abort.
/// Parse errors are an expected outcome for random bytes and are not failures.
fn translate(sql: &str) {
    let Ok(db) = parse_schema(sql) else {
        return;
    };

    // Every confidence threshold, since the level gates which policies reach model,
    // tuple, and report generation.
    for level in [
        ConfidenceLevel::A,
        ConfidenceLevel::B,
        ConfidenceLevel::C,
        ConfidenceLevel::D,
    ] {
        exercise(translator_at(level).translate(&db), sql);
    }

    // An oracle's answers reach the generators only through `Translation::plan`, and at
    // one level rather than four because it doubles the work per input.
    let translator = translator_at(ConfidenceLevel::B);
    let mut policies = translator.classify(&db);
    black_box(consult_oracle(&mut policies, &TextOracle).len());
    exercise(
        Translation::plan(
            policies,
            &db,
            translator.registry(),
            translator.min_confidence(),
            &GeneratorSettings::default(),
        ),
        sql,
    );
}

// `&str` rather than `&[u8]`: a mutation that breaks UTF-8 becomes SQL truncated at the
// bad byte instead of a discarded run.
fuzz_target!(|sql: &str| {
    translate(sql);
});

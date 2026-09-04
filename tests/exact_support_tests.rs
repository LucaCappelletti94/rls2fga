//! The exact-support grammar, checked without a database.
//!
//! A generator that emitted shapes the translation refuses would measure the refusal path
//! rather than the translation, and every case it produced would pass for the wrong reason.
//! These tests are what keeps the grammar honest before any container starts.

mod support;

use support::exact_support::{every_case, Accessor, KeyType, DECLARED_KEY, PRECONDITIONS};

use rls2fga::generator::model_generator::GeneratorSettings;
use rls2fga::translator::Translation;
use rls2fga::types::{ActionAnswer, ActionStatement, ConfidenceLevel, NoteSeverity};

/// Plan one generated schema at the threshold the parity runner uses.
fn plan(schema: &str) -> Translation {
    let (classified, db, registry) =
        support::classify_sql_with_session_attributes(schema, DECLARED_KEY);
    Translation::plan(
        classified,
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .expect("a case the grammar admits has to plan")
}

#[test]
fn the_exact_support_grammar_generates_only_translatable_policies() {
    for case in every_case() {
        let planned = plan(&case.schema);
        let unhandled: Vec<String> = planned
            .notes()
            .iter()
            .filter(|note| note.severity() == NoteSeverity::Unhandled)
            .map(ToString::to_string)
            .collect();
        assert!(
            unhandled.is_empty(),
            "{}: the grammar admits a shape nobody classified, so a case drawn from it \
             would measure the refusal path:\n{}",
            case.name,
            unhandled.join("\n")
        );
    }
}

#[test]
fn the_exact_support_grammar_admits_nothing_the_translation_calls_divergent() {
    for case in every_case() {
        let planned = plan(&case.schema);
        let diverging: Vec<String> = planned
            .notes()
            .iter()
            .filter(|note| note.severity().diverges_from_database())
            .map(ToString::to_string)
            .collect();
        // The grammar decides membership, so this is a claim about the translation: a shape
        // whose answer one row settles has nothing to disclose.
        assert!(
            diverging.is_empty(),
            "{}: the translation says it diverges on a shape the grammar admits:\n{}",
            case.name,
            diverging.join("\n")
        );
    }
}

#[test]
fn every_generated_case_reaches_a_judged_read() {
    for case in every_case() {
        let planned = plan(&case.schema);
        let answer = planned
            .action_relations()
            .iter()
            .find(|entry| {
                entry.type_name.as_str() == "guarded" && entry.statement == ActionStatement::Select
            })
            .map(|entry| &entry.answer);
        // Neither denied nor unrestricted: a case that granted everything or nothing would
        // agree with the database on the rows it happened to seed and prove nothing.
        assert!(
            matches!(answer, Some(ActionAnswer::Judged(_))),
            "{}: the read is {answer:?}, so no row is judged",
            case.name
        );
    }
}

#[test]
fn the_grammar_covers_every_axis_value_it_declares() {
    let cases = every_case();
    assert_eq!(
        cases.len(),
        KeyType::ALL.len() * Accessor::ALL.len() * 2,
        "the enumeration has to cover the axes whole, or a point goes unmeasured"
    );
    for key in KeyType::ALL {
        for accessor in Accessor::ALL {
            assert!(
                cases.iter().any(|case| case.name.contains(match key {
                    KeyType::Text => "text",
                    KeyType::Integer => "int",
                    KeyType::Uuid => "uuid",
                }) && case.accessor == accessor),
                "no case pairs {key:?} with {accessor:?}"
            );
        }
    }
    assert_eq!(
        PRECONDITIONS, 6,
        "the documented preconditions are the class"
    );
}

#[test]
fn an_unset_caller_raises_only_where_the_spelling_says_so() {
    // PostgreSQL's rule, and the reason the parity runner needs told which caller raises.
    assert!(Accessor::BareSetting.raises_when_unset());
    assert!(Accessor::DeclaredFunction.raises_when_unset());
    assert!(!Accessor::MissingOkSetting.raises_when_unset());
}

#[test]
fn an_undeclared_request_key_falls_outside_the_class() {
    // Precondition 6 is a real boundary, not paperwork: without the declaration the same
    // schema refuses, and refusing is right, since nothing says which key carries the
    // caller. A grammar that admitted it would be measuring the refusal path.
    let case = every_case()
        .into_iter()
        .next()
        .expect("the grammar admits at least one case");
    let (classified, db, registry) = support::classify_sql(&case.schema, None);
    let planned = Translation::plan(
        classified,
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .expect("it still plans");
    let answer = planned
        .action_relations()
        .iter()
        .find(|entry| entry.statement == ActionStatement::Select)
        .map(|entry| &entry.answer);
    assert!(
        matches!(answer, Some(ActionAnswer::Denied)),
        "an undeclared key has to be refused rather than guessed, the read is {answer:?}"
    );
    // How the refusal is spelled depends on the threshold, `Unhandled` below it and
    // `BelowThreshold` at it, so the property is that it falls closed and says so.
    assert!(
        planned
            .notes()
            .iter()
            .any(|note| note.severity().diverges_from_database()),
        "falling closed on an undeclared key has to be disclosed, not silent"
    );
}

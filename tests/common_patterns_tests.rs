use rls2fga::classifier::function_registry::FunctionRegistry;
use rls2fga::classifier::patterns::*;
use rls2fga::classifier::policy_classifier;
use rls2fga::generator::model_generator::GeneratorSettings;
use rls2fga::generator::tuple_generator;
use rls2fga::parser::function_analyzer::FunctionSemantic;
use rls2fga::parser::sql_parser;
/// Tests for the most common real-world RLS patterns.
///
/// Each test verifies that the translator correctly classifies and generates
/// output for patterns commonly found in production `PostgreSQL` deployments.
use rls2fga::translator::Translation;

mod support;

fn classify_fixture(
    fixture: &str,
    registry_setup: impl FnOnce(&mut FunctionRegistry),
) -> (
    Vec<ClassifiedPolicy>,
    sql_parser::ParserDB,
    FunctionRegistry,
) {
    let db = support::parse_fixture_db(fixture);
    let mut registry = FunctionRegistry::new();
    registry_setup(&mut registry);
    let classified = policy_classifier::classify_policies(&db, &registry);
    (classified, db, registry)
}

fn classify_fixture_with_json_registry(
    fixture: &str,
) -> (
    Vec<ClassifiedPolicy>,
    sql_parser::ParserDB,
    FunctionRegistry,
) {
    support::load_fixture_classified(fixture)
}

#[test]
fn tenant_isolation_is_classified() {
    let (classified, _db, _reg) = classify_fixture("tenant_isolation", |reg| {
        reg.register_if_absent(
            "current_tenant_id",
            &FunctionSemantic::CurrentUserAccessor {
                returns: "uuid".to_string(),
            },
        );
    });

    assert_eq!(
        classified.len(),
        1,
        "Should find the tenant isolation policy"
    );
    let cp = &classified[0];
    let classification = cp
        .using_classification
        .as_ref()
        .expect("Should have USING classification");

    match &classification.pattern {
        PatternClass::P3DirectOwnership(DirectOwnership { column }) => {
            assert_eq!(column, "tenant_id");
            assert_eq!(classification.confidence, ConfidenceLevel::A);
        }
        other => {
            panic!("Expected P3 with tenant_id, got: {other:?}");
        }
    }
}

#[test]
fn compound_or_owner_or_public() {
    let (classified, db, registry) = classify_fixture("compound_or", |reg| {
        reg.register_if_absent(
            "auth_current_user_id",
            &FunctionSemantic::CurrentUserAccessor {
                returns: "uuid".to_string(),
            },
        );
    });

    assert_eq!(classified.len(), 1, "Should find one compound policy");
    let cp = &classified[0];
    let classification = cp
        .using_classification
        .as_ref()
        .expect("Should have USING classification");

    match &classification.pattern {
        PatternClass::P8Composite(Composite { op, parts }) => {
            assert_eq!(*op, BoolOp::Or, "Should be an OR composite");
            assert_eq!(parts.len(), 2, "Should have two sub-patterns");

            let has_p3 = parts.iter().any(|p| {
                matches!(
                    p.pattern,
                    PatternClass::P3DirectOwnership(DirectOwnership { .. })
                )
            });
            let has_p6 = parts
                .iter()
                .any(|p| matches!(p.pattern, PatternClass::P6BooleanFlag(BooleanFlag { .. })));
            assert!(has_p3, "Should contain P3 (ownership)");
            assert!(has_p6, "Should contain P6 (boolean flag)");
        }
        other => {
            panic!("Expected P8 composite, got: {other:?}");
        }
    }

    // Verify model contains the composite relation
    let model = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .expect("translation should plan")
    .outputs_accepting_gaps();
    assert!(
        model.model().contains("owner or public_viewer"),
        "Model should contain 'owner or public_viewer', got:\n{}",
        model.model()
    );

    // Verify tuple generation
    let tuples = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .expect("translation should plan")
    .outputs_accepting_gaps()
    .tuple_queries();
    assert!(!tuples.is_empty(), "Should generate tuple queries");
}

#[test]
fn supabase_auth_uid_pattern() {
    let sql = std::fs::read_to_string("tests/fixtures/supabase_auth/input.sql").unwrap();
    let db = sql_parser::parse_schema(&sql).expect("Supabase auth schema should parse");

    let mut registry = FunctionRegistry::new();
    registry.register_if_absent(
        "auth.uid",
        &FunctionSemantic::CurrentUserAccessor {
            returns: "uuid".to_string(),
        },
    );

    let classified = policy_classifier::classify_policies(&db, &registry);

    assert_eq!(classified.len(), 2, "expected both Supabase policies");
    for cp in &classified {
        let classification = cp
            .using_classification
            .as_ref()
            .or(cp.with_check_classification.as_ref())
            .expect("expected Supabase policy classification");
        assert!(
            matches!(
                classification.pattern,
                PatternClass::P3DirectOwnership(DirectOwnership { ref column }) if column == "user_id"
            ),
            "auth.uid() should classify as direct ownership, got: {:?}",
            classification.pattern
        );
    }
}

#[test]
fn in_subquery_membership() {
    let (classified, _db, _reg) = classify_fixture("in_subquery_membership", |reg| {
        reg.register_if_absent(
            "auth_current_user_id",
            &FunctionSemantic::CurrentUserAccessor {
                returns: "uuid".to_string(),
            },
        );
    });

    assert_eq!(classified.len(), 1, "Should find one IN-subquery policy");
    let cp = &classified[0];
    let classification = cp
        .using_classification
        .as_ref()
        .expect("Should have USING classification");

    match &classification.pattern {
        PatternClass::P4ExistsMembership(ExistsMembership { join_table, .. }) => {
            assert_eq!(join_table, "team_members");
            assert_eq!(classification.confidence, ConfidenceLevel::A);
        }
        other => {
            panic!("Expected P4 with team_members, got: {other:?}");
        }
    }
}

#[test]
fn fixture_wrapped_membership_predicate_translates_without_alias_leak() {
    let (classified, db, registry) =
        classify_fixture("membership_wrapped_function_safe", |_reg| {});

    assert_eq!(
        classified.len(),
        1,
        "Should find one wrapped-membership policy"
    );
    let cp = &classified[0];
    let classification = cp
        .using_classification
        .as_ref()
        .expect("Should have USING classification");
    assert!(
        matches!(
            &classification.pattern,
            PatternClass::P4ExistsMembership(ExistsMembership {
                join_table,
                fk_column,
                user_column,
                ..
            }) if join_table == "doc_members" && fk_column == "doc_id" && user_column == "user_id"
        ),
        "wrapped membership policy should classify as P4, got: {:?}",
        classification.pattern
    );

    let tuples = tuple_generator::format_tuples(
        &Translation::plan(
            classified.clone(),
            &db,
            &registry,
            ConfidenceLevel::D,
            &GeneratorSettings::default(),
        )
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .tuple_queries(),
    );
    let tuples_lower = tuples.to_ascii_lowercase();
    assert!(
        tuples_lower.contains("lower(role) = 'admin'"),
        "tuple SQL should preserve wrapped extra predicate, got:\n{tuples}"
    );
    assert!(
        !tuples_lower.contains("dm."),
        "tuple SQL should not leak membership alias, got:\n{tuples}"
    );
}

#[test]
fn fixture_wrapped_outer_table_membership_predicate_fails_closed_with_unknown_reason() {
    let (classified, _db, _registry) =
        classify_fixture("membership_wrapped_function_unsafe", |_reg| {});

    assert_eq!(
        classified.len(),
        1,
        "Should find one wrapped-membership policy"
    );
    let cp = &classified[0];
    let classification = cp
        .using_classification
        .as_ref()
        .expect("Should have USING classification");

    match &classification.pattern {
        PatternClass::Unknown(UnclassifiedExpr { reason, .. }) => {
            assert!(
                reason.contains("Ambiguous membership pattern"),
                "unsafe wrapped predicate should fail closed with unknown reason, got: {reason}"
            );
        }
        other => {
            panic!("Expected fail-closed Unknown for unsafe wrapped predicate, got: {other:?}")
        }
    }
}

#[test]
fn current_user_keyword_equality() {
    let (classified, _db, _reg) = classify_fixture("current_user_equality", |_reg| {});

    assert_eq!(classified.len(), 1, "Should find one current_user policy");
    let cp = &classified[0];
    let classification = cp
        .using_classification
        .as_ref()
        .expect("Should have USING classification");

    match &classification.pattern {
        PatternClass::P3DirectOwnership(DirectOwnership { column }) => {
            assert_eq!(column, "manager");
            assert_eq!(classification.confidence, ConfidenceLevel::A);
        }
        other => {
            panic!("Expected P3 with column 'manager', got: {other:?}");
        }
    }
}

#[test]
fn multi_policy_table_classification() {
    let (classified, db, registry) = classify_fixture("multi_policy_table", |reg| {
        reg.register_if_absent(
            "auth_current_user_id",
            &FunctionSemantic::CurrentUserAccessor {
                returns: "uuid".to_string(),
            },
        );
    });

    assert_eq!(classified.len(), 3, "Should find all three policies");

    // Check the published_visible policy (status = 'published') → P9
    let published = classified
        .iter()
        .find(|c| c.name() == "published_visible")
        .expect("Should find published_visible policy");
    let pub_class = published.using_classification.as_ref().unwrap();

    match &pub_class.pattern {
        PatternClass::P9AttributeCondition(AttributeCondition {
            column,
            predicate: Some(_),
            ..
        }) => {
            assert_eq!(column, "status");
            // A literal constant is row data, so it grades with the boolean flag.
            assert_eq!(pub_class.confidence, ConfidenceLevel::B);
        }
        other => {
            panic!("Expected P9 with a literal predicate for status, got: {other:?}");
        }
    }

    // Check the author_sees_own policy (author_id = auth()) → P3
    let author = classified
        .iter()
        .find(|c| c.name() == "author_sees_own")
        .expect("Should find author_sees_own policy");
    let author_class = author.using_classification.as_ref().unwrap();
    assert!(
        matches!(
            author_class.pattern,
            PatternClass::P3DirectOwnership(DirectOwnership { .. })
        ),
        "author_id = auth() should be P3, got: {:?}",
        author_class.pattern,
    );

    // Check that the model generates something reasonable
    let model = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::D,
        &GeneratorSettings::default(),
    )
    .expect("translation should plan")
    .outputs_accepting_gaps();
    assert!(
        !model.model().is_empty(),
        "Should generate a non-empty model"
    );
}

#[test]
fn role_in_list_classification() {
    let (classified, db, registry) = classify_fixture_with_json_registry("role_in_list");

    assert_eq!(classified.len(), 1, "Should find one role IN-list policy");
    let cp = &classified[0];
    let classification = cp
        .using_classification
        .as_ref()
        .expect("Should have USING classification");

    match &classification.pattern {
        PatternClass::P2RoleNameInList(RoleNameInList {
            function_name,
            role_names,
            ..
        }) => {
            assert_eq!(function_name, "get_owner_role");
            assert_eq!(role_names.len(), 3, "Should have 3 integer values");
            assert!(
                role_names.contains(&"2".to_string())
                    && role_names.contains(&"3".to_string())
                    && role_names.contains(&"4".to_string()),
                "Should contain 2, 3, 4 as string representations"
            );
        }
        other => {
            panic!("Expected P2 with 3 integer values, got: {other:?}");
        }
    }

    // Verify model generation produces role threshold output
    let model = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::D,
        &GeneratorSettings::default(),
    )
    .expect("translation should plan")
    .outputs_accepting_gaps();
    assert!(
        !model.model().is_empty(),
        "Should generate a non-empty model"
    );
}

#[test]
fn pipeline_summary_all_common_patterns() {
    let patterns = [
        ("simple_ownership", "P3: Direct ownership"),
        ("membership_check", "P4: EXISTS membership"),
        ("public_flag", "P6: Boolean flag"),
        ("compound_or", "P8: Compound OR (owner OR public)"),
    ];

    eprintln!("\n=== Common RLS Pattern Pipeline Summary ===\n");

    for (fixture, description) in patterns {
        let sql = std::fs::read_to_string(format!("tests/fixtures/{fixture}/input.sql")).unwrap();
        let db = sql_parser::parse_schema(&sql).unwrap();
        let mut registry = FunctionRegistry::new();
        registry.register_if_absent(
            "auth_current_user_id",
            &FunctionSemantic::CurrentUserAccessor {
                returns: "uuid".to_string(),
            },
        );

        let classified = policy_classifier::classify_policies(&db, &registry);
        let model = Translation::plan(
            classified.clone(),
            &db,
            &registry,
            ConfidenceLevel::D,
            &GeneratorSettings::default(),
        )
        .expect("translation should plan")
        .outputs_accepting_gaps();
        let tuples = Translation::plan(
            classified.clone(),
            &db,
            &registry,
            ConfidenceLevel::D,
            &GeneratorSettings::default(),
        )
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .tuple_queries();

        let all_a = classified.iter().all(|cp| {
            cp.using_classification
                .as_ref()
                .is_none_or(|c| c.confidence >= ConfidenceLevel::B)
                && cp
                    .with_check_classification
                    .as_ref()
                    .is_none_or(|c| c.confidence >= ConfidenceLevel::B)
        });

        eprintln!(
            "{description}: {} policies, {} tuples, all>=B: {all_a}, notes: {}",
            classified.len(),
            tuples.len(),
            model.notes().len(),
        );

        if !model.notes().is_empty() {
            for note in model.notes() {
                eprintln!(
                    "  note [{}] {}: {}",
                    note.severity(),
                    note.subject(),
                    note.message()
                );
            }
        }
    }
}

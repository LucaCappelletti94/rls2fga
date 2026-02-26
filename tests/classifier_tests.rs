use rls2fga::classifier::function_registry::FunctionRegistry;
use rls2fga::classifier::patterns::*;
use rls2fga::classifier::policy_classifier;
use rls2fga::parser::function_analyzer::FunctionSemantic;

mod support;

fn load_emi_fixture() -> (rls2fga::parser::sql_parser::ParserDB, FunctionRegistry) {
    support::load_fixture_db_and_registry("earth_metabolome")
}

#[test]
fn classify_emi_policies_as_p1() {
    let (db, registry) = load_emi_fixture();
    let classified = policy_classifier::classify_policies(&db, &registry);

    assert_eq!(classified.len(), 4);

    for cp in &classified {
        let classification = cp
            .using_classification
            .as_ref()
            .or(cp.with_check_classification.as_ref())
            .expect("Should have at least one classification");

        assert!(
            matches!(
                classification.pattern,
                PatternClass::P1NumericThreshold { .. }
            ),
            "Policy '{}' should be P1, got {:?}",
            cp.name(),
            classification.pattern,
        );

        assert_eq!(
            classification.confidence,
            ConfidenceLevel::A,
            "Policy '{}' should be Level A",
            cp.name(),
        );
    }
}

#[test]
fn classify_emi_select_threshold() {
    let (db, registry) = load_emi_fixture();
    let classified = policy_classifier::classify_policies(&db, &registry);

    let select = classified
        .iter()
        .find(|c| c.name() == "ownables_select_policy")
        .unwrap();
    if let Some(ClassifiedExpr {
        pattern: PatternClass::P1NumericThreshold { threshold, .. },
        ..
    }) = &select.using_classification
    {
        assert_eq!(*threshold, 2);
    } else {
        panic!("Expected P1 with threshold 2");
    }
}

#[test]
fn classify_emi_delete_threshold() {
    let (db, registry) = load_emi_fixture();
    let classified = policy_classifier::classify_policies(&db, &registry);

    let delete = classified
        .iter()
        .find(|c| c.name() == "ownables_delete_policy")
        .unwrap();
    if let Some(ClassifiedExpr {
        pattern: PatternClass::P1NumericThreshold { threshold, .. },
        ..
    }) = &delete.using_classification
    {
        assert_eq!(*threshold, 4);
    } else {
        panic!("Expected P1 with threshold 4");
    }
}

#[test]
fn classify_simple_ownership_as_p3() {
    let db = support::parse_fixture_db("simple_ownership");

    let mut registry = FunctionRegistry::new();
    // Register auth_current_user_id from the parsed functions
    registry.register_if_absent(
        "auth_current_user_id",
        &FunctionSemantic::CurrentUserAccessor {
            returns: "uuid".to_string(),
        },
    );

    let classified = policy_classifier::classify_policies(&db, &registry);

    for cp in &classified {
        let classification = cp
            .using_classification
            .as_ref()
            .expect("Should have USING classification");

        assert!(
            matches!(
                classification.pattern,
                PatternClass::P3DirectOwnership { .. }
            ),
            "Expected P3, got {:?}",
            classification.pattern,
        );
        assert_eq!(classification.confidence, ConfidenceLevel::A);
    }
}

#[test]
fn classify_public_flag_as_p6_heuristic_gives_confidence_b() {
    // Without explicit registration the heuristic match is capped at B so that
    // wildcard public-access grants always surface for manual review.
    let db = support::parse_fixture_db("public_flag");
    let registry = FunctionRegistry::new();

    let classified = policy_classifier::classify_policies(&db, &registry);
    assert_eq!(classified.len(), 1);

    let cp = &classified[0];
    let classification = cp.using_classification.as_ref().unwrap();
    assert!(
        matches!(classification.pattern, PatternClass::P6BooleanFlag { .. }),
        "Expected P6, got {:?}",
        classification.pattern,
    );
    assert_eq!(
        classification.confidence,
        ConfidenceLevel::B,
        "Unregistered public-flag column should produce confidence B, not A"
    );
}

#[test]
fn classify_public_flag_registered_column_gives_confidence_a() {
    let db = support::parse_fixture_db("public_flag");
    let mut registry = FunctionRegistry::new();
    registry.register_public_flag_column("is_public");

    let classified = policy_classifier::classify_policies(&db, &registry);
    assert_eq!(classified.len(), 1);

    let cp = &classified[0];
    let classification = cp.using_classification.as_ref().unwrap();
    assert!(
        matches!(classification.pattern, PatternClass::P6BooleanFlag { .. }),
        "Expected P6, got {:?}",
        classification.pattern,
    );
    assert_eq!(
        classification.confidence,
        ConfidenceLevel::A,
        "Explicitly registered public-flag column should produce confidence A"
    );
}

#[test]
fn classify_abac_status_as_p7() {
    let (db, registry) = support::load_fixture_db_and_registry("abac_status");

    let classified = policy_classifier::classify_policies(&db, &registry);
    assert_eq!(classified.len(), 1);

    let cp = &classified[0];
    let classification = cp.using_classification.as_ref().unwrap();
    assert!(
        matches!(classification.pattern, PatternClass::P7AbacAnd { .. }),
        "Expected P7, got {:?}",
        classification.pattern,
    );
    assert_eq!(classification.confidence, ConfidenceLevel::C);
}

#[test]
fn classify_tenant_isolation_without_registry_via_function_body_inference() {
    let db = support::parse_fixture_db("tenant_isolation");
    let registry = FunctionRegistry::new();

    let classified = policy_classifier::classify_policies(&db, &registry);
    assert_eq!(classified.len(), 1);

    let cp = &classified[0];
    let classification = cp
        .using_classification
        .as_ref()
        .expect("tenant policy should have USING classification");
    match &classification.pattern {
        PatternClass::P3DirectOwnership { column } => {
            assert_eq!(column, "tenant_id");
            assert_eq!(classification.confidence, ConfidenceLevel::A);
        }
        other => panic!("expected inferred P3 for tenant isolation, got: {other:?}"),
    }
}

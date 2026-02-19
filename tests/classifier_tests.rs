use rls2fga::classifier::function_registry::FunctionRegistry;
use rls2fga::classifier::patterns::*;
use rls2fga::classifier::policy_classifier;
use rls2fga::parser::function_analyzer::FunctionSemantic;
use rls2fga::parser::sql_parser;

fn load_emi_fixture() -> (sql_parser::ParserDB, FunctionRegistry) {
    let sql = std::fs::read_to_string("tests/fixtures/earth_metabolome/input.sql").unwrap();
    let db = sql_parser::parse_schema(&sql).unwrap();

    let reg_json =
        std::fs::read_to_string("tests/fixtures/earth_metabolome/function_registry.json").unwrap();
    let mut registry = FunctionRegistry::new();
    registry.load_from_json(&reg_json).unwrap();

    (db, registry)
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
    let sql = std::fs::read_to_string("tests/fixtures/simple_ownership/input.sql").unwrap();
    let db = sql_parser::parse_schema(&sql).unwrap();

    let mut registry = FunctionRegistry::new();
    // Register auth_current_user_id from the parsed functions
    registry.register_if_absent(
        "auth_current_user_id".to_string(),
        FunctionSemantic::CurrentUserAccessor {
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
fn classify_public_flag_as_p6() {
    let sql = std::fs::read_to_string("tests/fixtures/public_flag/input.sql").unwrap();
    let db = sql_parser::parse_schema(&sql).unwrap();
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
    assert_eq!(classification.confidence, ConfidenceLevel::A);
}

#[test]
fn classify_abac_status_as_p7() {
    let sql = std::fs::read_to_string("tests/fixtures/abac_status/input.sql").unwrap();
    let db = sql_parser::parse_schema(&sql).unwrap();

    let reg_json =
        std::fs::read_to_string("tests/fixtures/abac_status/function_registry.json").unwrap();
    let mut registry = FunctionRegistry::new();
    registry.load_from_json(&reg_json).unwrap();

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

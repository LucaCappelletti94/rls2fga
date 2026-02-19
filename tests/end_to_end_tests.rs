use rls2fga::classifier::function_registry::FunctionRegistry;
use rls2fga::classifier::patterns::ConfidenceLevel;
use rls2fga::classifier::policy_classifier;
use rls2fga::generator::model_generator;
use rls2fga::generator::tuple_generator;
use rls2fga::parser::sql_parser;

/// Full pipeline end-to-end test for the EMI schema.
/// This is the primary acceptance test.
#[test]
fn end_to_end_earth_metabolome() {
    // Stage 1-2: Parse
    let sql = std::fs::read_to_string("tests/fixtures/earth_metabolome/input.sql").unwrap();
    let db = sql_parser::parse_schema(&sql).unwrap();

    // Stage 3: Load function registry
    let reg_json =
        std::fs::read_to_string("tests/fixtures/earth_metabolome/function_registry.json").unwrap();
    let mut registry = FunctionRegistry::new();
    registry.load_from_json(&reg_json).unwrap();

    // Stage 4: Classify
    let classified = policy_classifier::classify_policies(&db, &registry);
    assert_eq!(classified.len(), 4, "Should classify all 4 policies");

    // Stage 5: Generate model
    let model = model_generator::generate_model(&classified, &db, &registry, &ConfidenceLevel::B);
    insta::assert_snapshot!("emi_model", model.dsl.trim());

    // Stage 6: Generate tuples
    let tuples = tuple_generator::generate_tuple_queries(&classified, &db, &registry);
    insta::assert_snapshot!("emi_tuples", tuple_generator::format_tuples(&tuples));

    // Verify no TODOs for Level A/B output
    assert!(model.todos.is_empty(), "EMI schema should produce no TODOs");
}

/// Pipeline test: all EMI policies should be Level A confidence.
#[test]
fn end_to_end_emi_all_level_a() {
    let sql = std::fs::read_to_string("tests/fixtures/earth_metabolome/input.sql").unwrap();
    let db = sql_parser::parse_schema(&sql).unwrap();

    let reg_json =
        std::fs::read_to_string("tests/fixtures/earth_metabolome/function_registry.json").unwrap();
    let mut registry = FunctionRegistry::new();
    registry.load_from_json(&reg_json).unwrap();

    let classified = policy_classifier::classify_policies(&db, &registry);

    for cp in &classified {
        for c in [&cp.using_classification, &cp.with_check_classification]
            .into_iter()
            .flatten()
        {
            assert_eq!(
                c.confidence,
                ConfidenceLevel::A,
                "Policy '{}' should be Level A, got Level {}",
                cp.name(),
                c.confidence,
            );
        }
    }
}

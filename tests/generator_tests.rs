use rls2fga::classifier::function_registry::FunctionRegistry;
use rls2fga::classifier::patterns::ConfidenceLevel;
use rls2fga::classifier::policy_classifier;
use rls2fga::generator::json_model;
use rls2fga::generator::model_generator;
use rls2fga::generator::tuple_generator;
use rls2fga::parser::function_analyzer::FunctionSemantic;
use rls2fga::parser::sql_parser;

fn load_emi() -> (
    Vec<rls2fga::classifier::patterns::ClassifiedPolicy>,
    sql_parser::ParserDB,
    FunctionRegistry,
) {
    let sql = std::fs::read_to_string("tests/fixtures/earth_metabolome/input.sql").unwrap();
    let db = sql_parser::parse_schema(&sql).unwrap();

    let reg_json =
        std::fs::read_to_string("tests/fixtures/earth_metabolome/function_registry.json").unwrap();
    let mut registry = FunctionRegistry::new();
    registry.load_from_json(&reg_json).unwrap();

    let classified = policy_classifier::classify_policies(&db, &registry);
    (classified, db, registry)
}

#[test]
fn generate_emi_model() {
    let (classified, db, registry) = load_emi();
    let model = model_generator::generate_model(&classified, &db, &registry, &ConfidenceLevel::B);
    insta::assert_snapshot!(model.dsl.trim());
}

#[test]
fn generate_emi_tuples() {
    let (classified, db, registry) = load_emi();
    let tuples = tuple_generator::generate_tuple_queries(&classified, &db, &registry);
    insta::assert_snapshot!(tuple_generator::format_tuples(&tuples));
}

#[test]
fn generate_emi_json_model() {
    let (classified, db, registry) = load_emi();
    let model = json_model::generate_json_model(&classified, &db, &registry, &ConfidenceLevel::B);
    insta::assert_json_snapshot!(model);
}

#[test]
fn generate_simple_ownership_model() {
    let sql = std::fs::read_to_string("tests/fixtures/simple_ownership/input.sql").unwrap();
    let db = sql_parser::parse_schema(&sql).unwrap();

    let mut registry = FunctionRegistry::new();
    registry.register_if_absent(
        "auth_current_user_id".to_string(),
        FunctionSemantic::CurrentUserAccessor {
            returns: "uuid".to_string(),
        },
    );

    let classified = policy_classifier::classify_policies(&db, &registry);
    let model = model_generator::generate_model(&classified, &db, &registry, &ConfidenceLevel::B);
    insta::assert_snapshot!(model.dsl.trim());
}

#[test]
fn generate_public_flag_model() {
    let sql = std::fs::read_to_string("tests/fixtures/public_flag/input.sql").unwrap();
    let db = sql_parser::parse_schema(&sql).unwrap();
    let registry = FunctionRegistry::new();

    let classified = policy_classifier::classify_policies(&db, &registry);
    let model = model_generator::generate_model(&classified, &db, &registry, &ConfidenceLevel::B);
    insta::assert_snapshot!(model.dsl.trim());
}

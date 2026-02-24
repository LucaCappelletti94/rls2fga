use rls2fga::classifier::function_registry::FunctionRegistry;
use rls2fga::classifier::patterns::ConfidenceLevel;
use rls2fga::classifier::policy_classifier;
use rls2fga::generator::json_model;
use rls2fga::generator::model_generator;
use rls2fga::generator::tuple_generator;
use rls2fga::parser::function_analyzer::FunctionSemantic;

mod support;

fn load_emi() -> (
    Vec<rls2fga::classifier::patterns::ClassifiedPolicy>,
    rls2fga::parser::sql_parser::ParserDB,
    FunctionRegistry,
) {
    let (db, registry) = support::load_fixture_db_and_registry("earth_metabolome");

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
    let tuples =
        tuple_generator::generate_tuple_queries(&classified, &db, &registry, &ConfidenceLevel::B);
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
    let db = support::parse_fixture_db("simple_ownership");

    let mut registry = FunctionRegistry::new();
    registry.register_if_absent(
        "auth_current_user_id",
        &FunctionSemantic::CurrentUserAccessor {
            returns: "uuid".to_string(),
        },
    );

    let classified = policy_classifier::classify_policies(&db, &registry);
    let model = model_generator::generate_model(&classified, &db, &registry, &ConfidenceLevel::B);
    insta::assert_snapshot!(model.dsl.trim());
}

#[test]
fn generate_public_flag_model() {
    let db = support::parse_fixture_db("public_flag");
    let registry = FunctionRegistry::new();

    let classified = policy_classifier::classify_policies(&db, &registry);
    let model = model_generator::generate_model(&classified, &db, &registry, &ConfidenceLevel::B);
    insta::assert_snapshot!(model.dsl.trim());
}

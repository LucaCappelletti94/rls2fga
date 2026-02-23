use rls2fga::classifier::function_registry::FunctionRegistry;
use rls2fga::classifier::patterns::ConfidenceLevel;
use rls2fga::classifier::policy_classifier;
use rls2fga::generator::model_generator;
use rls2fga::generator::tuple_generator;
use rls2fga::output::formatter;
use rls2fga::parser::sql_parser;

fn unique_temp_dir(prefix: &str) -> std::path::PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("{prefix}_{nanos}"));
    std::fs::create_dir_all(&dir).expect("should create temp dir");
    dir
}

#[test]
fn formatter_uses_same_tuple_format_as_tuple_generator_helper() {
    let sql = std::fs::read_to_string("tests/fixtures/earth_metabolome/input.sql").unwrap();
    let db = sql_parser::parse_schema(&sql).unwrap();
    let reg_json =
        std::fs::read_to_string("tests/fixtures/earth_metabolome/function_registry.json").unwrap();
    let mut registry = FunctionRegistry::new();
    registry.load_from_json(&reg_json).unwrap();

    let classified = policy_classifier::classify_policies(&db, &registry);
    let model = model_generator::generate_model(&classified, &db, &registry, &ConfidenceLevel::D);
    let tuples = tuple_generator::generate_tuple_queries(&classified, &db, &registry);
    let expected = tuple_generator::format_tuples(&tuples);

    let out_dir = unique_temp_dir("rls2fga_formatter");
    formatter::write_output(&out_dir, "emi", &model, &tuples, &classified).unwrap();
    let written = std::fs::read_to_string(out_dir.join("emi_tuples.sql")).unwrap();

    assert_eq!(
        written, expected,
        "output formatter should match tuple_generator::format_tuples exactly"
    );
}

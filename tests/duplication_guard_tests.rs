use std::fs;

fn read(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("failed to read {path}: {e}"))
}

#[test]
fn confidence_filtering_has_single_source_of_truth() {
    let files = [
        "src/generator/model_generator.rs",
        "src/generator/json_model.rs",
        "src/classifier/patterns.rs",
    ];

    let definitions = files
        .iter()
        .map(|path| read(path).matches("fn filter_policies_for_output(").count())
        .sum::<usize>();

    assert_eq!(
        definitions, 1,
        "expected a single confidence filtering implementation, found {definitions}"
    );
}

#[test]
fn pk_column_resolution_has_single_source_of_truth() {
    let files = [
        "src/generator/db_lookup.rs",
        "src/generator/model_generator.rs",
        "src/generator/tuple_generator.rs",
    ];

    let definitions = files
        .iter()
        .map(|path| read(path).matches("fn resolve_pk_column(").count())
        .sum::<usize>();

    assert_eq!(
        definitions, 1,
        "expected a single PK-resolution implementation, found {definitions}"
    );
}

#[test]
fn function_arg_extraction_has_single_source_of_truth() {
    let files = [
        "src/classifier/ast_args.rs",
        "src/classifier/recognizers.rs",
        "src/generator/model_generator.rs",
    ];

    let expr_defs = files
        .iter()
        .map(|path| read(path).matches("fn function_arg_expr(").count())
        .sum::<usize>();

    assert_eq!(
        expr_defs, 1,
        "expected a single function_arg_expr implementation, found {expr_defs}"
    );
}

#[test]
fn missing_object_identifier_todo_message_is_centralized() {
    let source = read("src/generator/model_generator.rs");
    let count = source
        .matches("table needs a primary key or `id` column for stable object IDs.")
        .count();
    assert_eq!(
        count, 1,
        "expected missing-object-id TODO SQL to be centralized in one helper, found {count}"
    );
}

#[test]
fn p5_inheritance_analysis_has_single_source_of_truth() {
    let source = read("src/classifier/recognizers.rs");
    let definitions = source.matches("fn analyze_p5_parent_inheritance(").count();
    assert_eq!(
        definitions, 1,
        "expected a single P5 inheritance analysis helper, found {definitions}"
    );
}

#[test]
fn bool_equality_extraction_has_single_source_of_truth() {
    let source = read("src/classifier/recognizers.rs");
    let definitions = source
        .matches("fn extract_boolean_column_equality(")
        .count();
    assert_eq!(
        definitions, 1,
        "expected a single boolean equality extractor helper, found {definitions}"
    );
}

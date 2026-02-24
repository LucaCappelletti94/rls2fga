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

use std::fs;
use std::path::Path;

/// Read a module's source. Accepts either a single `.rs` file or a directory
/// module, in which case every `.rs` file directly inside it is concatenated.
fn read_module(path: &str) -> String {
    let p = Path::new(path);
    if p.is_dir() {
        let mut entries: Vec<_> = fs::read_dir(p)
            .unwrap_or_else(|e| panic!("failed to read dir {path}: {e}"))
            .map(|e| e.expect("dir entry").path())
            .collect();
        entries.sort();
        let mut out = String::new();
        for entry in entries {
            if entry.extension().and_then(|s| s.to_str()) == Some("rs") {
                out.push_str(
                    &fs::read_to_string(&entry)
                        .unwrap_or_else(|e| panic!("failed to read {}: {e}", entry.display())),
                );
                out.push('\n');
            }
        }
        out
    } else {
        fs::read_to_string(p).unwrap_or_else(|e| panic!("failed to read {path}: {e}"))
    }
}

fn definition_count(modules: &[&str], needle: &str) -> usize {
    modules
        .iter()
        .map(|path| read_module(path).matches(needle).count())
        .sum()
}

#[test]
fn confidence_filtering_has_single_source_of_truth() {
    let modules = [
        "src/generator/model_generator",
        "src/generator/json_model.rs",
        "src/classifier/patterns.rs",
    ];

    let definitions = definition_count(&modules, "fn filter_policies_for_output(");

    assert_eq!(
        definitions, 1,
        "expected a single confidence filtering implementation, found {definitions}"
    );
}

#[test]
fn pk_column_resolution_has_single_source_of_truth() {
    let modules = [
        "src/generator/db_lookup.rs",
        "src/generator/model_generator",
        "src/generator/tuple_generator.rs",
    ];

    let definitions = definition_count(&modules, "fn resolve_pk_column(");

    assert_eq!(
        definitions, 1,
        "expected a single PK-resolution implementation, found {definitions}"
    );
}

#[test]
fn function_arg_extraction_has_single_source_of_truth() {
    let modules = [
        "src/parser/expr.rs",
        "src/classifier/recognizers",
        "src/generator/model_generator",
    ];

    let expr_defs = definition_count(&modules, "fn function_arg_expr(");

    assert_eq!(
        expr_defs, 1,
        "expected a single function_arg_expr implementation, found {expr_defs}"
    );
}

#[test]
fn missing_object_identifier_todo_message_is_centralized() {
    let source = read_module("src/generator/model_generator");
    let count = source
        .matches("table needs a single-column primary key or a NOT NULL UNIQUE `id` column")
        .count();
    assert_eq!(
        count, 1,
        "expected missing-object-id TODO SQL to be centralized in one helper, found {count}"
    );
}

#[test]
fn p5_inheritance_analysis_has_single_source_of_truth() {
    let source = read_module("src/classifier/recognizers");
    let definitions = source.matches("fn analyze_p5_parent_inheritance(").count();
    assert_eq!(
        definitions, 1,
        "expected a single P5 inheritance analysis helper, found {definitions}"
    );
}

#[test]
fn bool_equality_extraction_has_single_source_of_truth() {
    let source = read_module("src/classifier/recognizers");
    let definitions = source
        .matches("fn extract_boolean_column_equality(")
        .count();
    assert_eq!(
        definitions, 1,
        "expected a single boolean equality extractor helper, found {definitions}"
    );
}

#[test]
fn role_in_list_extraction_has_single_source_of_truth() {
    let source = read_module("src/classifier/recognizers");
    let definitions = source
        .matches("fn extract_role_names_from_in_list(")
        .count();
    assert_eq!(
        definitions, 1,
        "expected one shared IN-list role extraction helper, found {definitions}"
    );
}

#[test]
fn token_pair_matching_has_single_source_of_truth() {
    let source = read_module("src/parser/names.rs");
    let definitions = source.matches("fn has_token_pair(").count();
    assert_eq!(
        definitions, 1,
        "expected one shared token-pair helper in names.rs, found {definitions}"
    );
}

#[test]
fn relation_name_clamping_has_single_source_of_truth() {
    let modules = [
        "src/parser/names.rs",
        "src/generator/model_generator",
        "src/generator/role_relations.rs",
        "src/generator/tuple_generator.rs",
    ];

    let definitions = definition_count(&modules, "fn clamp_relation_name(");

    assert_eq!(
        definitions, 1,
        "every generated relation name must pass through one clamp, found {definitions}"
    );
}

#[test]
fn identifier_equality_has_single_source_of_truth() {
    let modules = [
        "src/parser/names.rs",
        "src/classifier/recognizers",
        "src/generator/model_generator",
    ];

    let definitions = definition_count(&modules, "fn same_identifier(");

    assert_eq!(
        definitions, 1,
        "expected one shared identifier-equality helper, found {definitions}"
    );
}

#[test]
fn relation_reference_walking_has_single_source_of_truth() {
    let modules = [
        "src/parser/expr.rs",
        "src/classifier/patterns.rs",
        "src/classifier/recognizers",
        "src/generator/model_generator",
    ];

    let walkers = definition_count(&modules, "visit_relations(");

    assert_eq!(
        walkers, 1,
        "walking an expression for the relations it reads belongs in one helper, found {walkers}"
    );
}

#[test]
fn action_relations_and_their_commands_are_paired_once() {
    let modules = ["src/generator/model_generator", "src/output/report.rs"];

    let tables = definition_count(&modules, "const ACTION_RELATION_COMMANDS");
    assert_eq!(
        tables, 1,
        "one table maps an action relation to its SQL command, found {tables}"
    );

    let strays = definition_count(&modules, "\"can_select\" => ");
    assert_eq!(
        strays, 0,
        "mapping a relation to a command by match duplicates that table, found {strays}"
    );
}

#[test]
fn reserved_relation_subjects_have_a_single_source_of_truth() {
    let modules = [
        "src/generator/model_generator",
        "src/generator/json_model.rs",
    ];

    let definitions = definition_count(&modules, "fn reserved_relation_subjects(");
    assert_eq!(
        definitions, 1,
        "one place decides which relation names the generator keeps, found {definitions}"
    );
}

#[test]
fn well_known_names_have_a_single_source_of_truth() {
    let modules = [
        "src/generator/ir.rs",
        "src/generator/json_model.rs",
        "src/generator/tuple_generator.rs",
        "src/generator/model_generator/mod.rs",
        "src/generator/model_generator/dsl.rs",
        "src/generator/model_generator/role_threshold.rs",
    ];

    for name in [
        "user",
        "team",
        "pg_role",
        "no_access",
        "public_viewer",
        "member",
        "owner_user",
        "owner_team",
        "can_select",
        "can_insert",
        "can_update",
        "can_delete",
        "can_update_using",
        "can_update_check",
        "can_insert_returning",
    ] {
        let literals = definition_count(&modules, &format!("\"{name}\""));
        assert_eq!(
            literals, 0,
            "'{name}' must come from generator::well_known, found {literals} literals"
        );
    }
}

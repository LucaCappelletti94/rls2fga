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

/// Count definitions of `name`, whether or not it carries a generic parameter list.
fn fn_definitions(modules: &[&str], name: &str) -> usize {
    definition_count(modules, &format!("fn {name}("))
        + definition_count(modules, &format!("fn {name}<"))
}

#[test]
fn confidence_filtering_has_single_source_of_truth() {
    let modules = [
        "src/generator/model_generator",
        "src/generator/json_model.rs",
        "src/classifier/patterns.rs",
    ];

    let definitions = fn_definitions(&modules, "filter_policies_for_output");

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
        "src/generator/relations.rs",
    ];

    let definitions = fn_definitions(&modules, "resolve_pk_columns");

    assert_eq!(
        definitions, 1,
        "expected a single PK-resolution implementation, found {definitions}"
    );

    // The single-column answer is derived from the list rather than resolved again.
    // A second resolution here is how a caller ends up naming a row one way while the
    // rest of the crate names it another.
    let single = fn_definitions(&modules, "single_pk_column");

    assert_eq!(
        single, 1,
        "expected a single narrowing helper, found {single}"
    );
}

#[test]
fn function_arg_extraction_has_single_source_of_truth() {
    let modules = [
        "src/parser/expr.rs",
        "src/classifier/recognizers",
        "src/generator/model_generator",
    ];

    let expr_defs = fn_definitions(&modules, "function_arg_expr");

    assert_eq!(
        expr_defs, 1,
        "expected a single function_arg_expr implementation, found {expr_defs}"
    );
}

/// Note prose lives in one module and is rendered from the typed cause, so a note
/// cannot say one thing while its kind says another, and no construction site can
/// grow a second wording for the same gap.
#[test]
fn translation_note_prose_lives_only_in_the_notes_module() {
    let notes = read_module("src/generator/notes.rs");
    let centralized = notes
        .matches("table needs a single-column primary key or a NOT NULL UNIQUE `id` column")
        .count();
    assert_eq!(
        centralized, 1,
        "expected the missing-object-id advice once in notes.rs, found {centralized}"
    );

    for module in [
        "src/generator/model_generator",
        "src/generator/tuple_generator.rs",
        "src/output/report.rs",
    ] {
        let stray = read_module(module).matches("-- TODO [Level").count();
        assert_eq!(
            stray, 0,
            "{module} must carry no note prose, found {stray} skipped-tuple comments"
        );
    }
}

#[test]
fn p5_inheritance_analysis_has_single_source_of_truth() {
    let definitions = fn_definitions(
        &["src/classifier/recognizers"],
        "analyze_p5_parent_inheritance",
    );
    assert_eq!(
        definitions, 1,
        "expected a single P5 inheritance analysis helper, found {definitions}"
    );
}

/// The name a `<thing>_id` column gives the entity it references is decided once.
///
/// The model generator reaches it through `parent_type_from_fk_column` rather than
/// stripping the suffix itself, so a change to the rule cannot move a parent type while
/// leaving an ownership relation on the old spelling.
///
/// `is_self_parent_bridge` in the tuple generator deliberately stays outside this: it
/// compares a column name against a table name in lowercase, and canonicalizing either
/// side would fold every non-ASCII name onto `resource`. That is pinned by
/// `two_unrelated_non_ascii_names_do_not_bridge`.
#[test]
fn the_name_an_id_column_references_has_a_single_source_of_truth() {
    let definitions = fn_definitions(&["src/parser/names.rs"], "parent_type_from_fk_column");
    assert_eq!(
        definitions, 1,
        "expected one 'fn parent_type_from_fk_column', found {definitions}"
    );

    let stray = read_module("src/generator/model_generator")
        .matches(r#"strip_suffix("_id")"#)
        .count();
    assert_eq!(
        stray, 0,
        "the model generator must reach the rule through parent_type_from_fk_column, \
         found {stray} hand-rolled strips"
    );
}

/// `FROM ONLY` keeps an inheritance parent's child rows out of its object-minting
/// queries, and which reads carry it is one rule: a second `ONLY` spelling site could
/// scope a foreign-table read, which denies rows `PostgreSQL` grants, or miss an
/// owner-table read, which merges child rows into parent objects.
#[test]
fn the_from_only_scope_has_a_single_source_of_truth() {
    let definitions = fn_definitions(
        &["src/generator/tuple_generator.rs"],
        "owner_table_reference",
    );
    assert_eq!(
        definitions, 1,
        "expected one 'fn owner_table_reference', found {definitions}"
    );

    let spellings = read_module("src/generator/tuple_generator.rs")
        .matches("\"ONLY {")
        .count();
    assert_eq!(
        spellings, 1,
        "the ONLY prefix must be rendered by owner_table_reference alone, \
         found {spellings} spellings"
    );
}

/// Three spellings reach P4 membership: `EXISTS`, `col IN (SELECT ...)`, and the caller on
/// the left. The last two are one rewrite into the first, so all three land on one
/// analyzer. A second analyzer, or a second reader of the projection, would let one
/// spelling keep a refusal another dropped.
#[test]
fn membership_analysis_has_a_single_source_of_truth() {
    let modules = ["src/classifier/recognizers"];

    for name in [
        "analyze_membership_select",
        "membership_subquery_operands",
        "membership_exists_from_in_subquery",
        // Every spelling reads its subquery through one of these two extractors, so the
        // refusals below cannot be dropped by one spelling and kept by another.
        "exists_subquery_select",
        "select_result_shaping_clause",
        "exists_emptying_limit_clause",
        "from_item_is_sampled",
        "query_binds_its_own_names",
        "query_locks_its_rows",
        "query_level_refusal",
    ] {
        let definitions = fn_definitions(&modules, name);
        assert_eq!(
            definitions, 1,
            "expected one 'fn {name}', found {definitions}"
        );
    }

    // Each clause by which a subquery stops being the plain set of rows in the table it
    // names is read in exactly one place. A second reader would let one spelling keep a
    // refusal another spelling dropped.
    let source = read_module("src/classifier/recognizers");
    for clause in [
        "limit_clause.is_some()",
        "fetch.is_some()",
        "having.is_some()",
        "qualify.is_some()",
        "Distinct::On",
        "sample: Some(_)",
        "with.is_some()",
        "locks.is_empty()",
    ] {
        let readers = source.matches(clause).count();
        assert_eq!(
            readers, 1,
            "'{clause}' decides a refusal in one place, found {readers}"
        );
    }

    // The projected column of an `IN` subquery is a correlation, not a hint. Reading it
    // anywhere but the rewrite is how it used to reach the pattern without facing the
    // conflict check, which dropped a second correlation and granted the table whole.
    let membership = read_module("src/classifier/recognizers/subquery.rs");
    let projection_readers = membership.matches("select.projection").count();
    assert_eq!(
        projection_readers, 1,
        "the projection is read only by the rewrite, found {projection_readers} readers"
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

    let definitions = fn_definitions(&modules, "clamp_relation_name");

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

    let definitions = fn_definitions(&modules, "same_identifier");

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

    let update_needs = definition_count(
        &modules,
        "ActionTarget::UpdateUsing, ActionTarget::UpdateCheck",
    );
    assert_eq!(
        update_needs, 1,
        "one place says which clause targets a command needs, found {update_needs}"
    );
}

#[test]
fn reserved_relation_subjects_have_a_single_source_of_truth() {
    let modules = [
        "src/generator/model_generator",
        "src/generator/json_model.rs",
    ];

    let definitions = fn_definitions(&modules, "reserved_relation_subjects");
    assert_eq!(
        definitions, 1,
        "one place decides which relation names the generator keeps, found {definitions}"
    );
}

#[test]
fn generator_owned_relation_names_have_a_single_source_of_truth() {
    let modules = ["src/generator/model_generator"];

    let definitions = fn_definitions(&modules, "generator_defines");
    assert_eq!(
        definitions, 1,
        "one place decides which relation names a translated name may not take, found {definitions}"
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
        "can_upsert",
        "can_select_for_update",
    ] {
        let literals = definition_count(&modules, &format!("\"{name}\""));
        assert_eq!(
            literals, 0,
            "'{name}' must come from generator::well_known, found {literals} literals"
        );
    }
}

#[test]
fn identifier_folding_has_a_single_source_of_truth() {
    let modules = [
        "src/parser",
        "src/classifier",
        "src/classifier/recognizers",
        "src/generator",
        "src/generator/model_generator",
    ];

    // Only the sqlparser side is ours. A declared identifier folds through
    // `ColumnLike::stored_column_name`, `TableLike::stored_table_name` and
    // `TableLike::stored_table_schema`.
    let definitions = fn_definitions(&modules, "stored_identifier");
    assert_eq!(
        definitions, 1,
        "one place folds an identifier to the name PostgreSQL stores, found {definitions}"
    );

    // A quote flag read means a site is re-pairing a value with its flag by
    // hand, which is the mistake the stored-name accessors exist to prevent.
    for accessor in [
        "column_name_is_quoted(",
        "table_name_is_quoted(",
        "table_schema_is_quoted(",
    ] {
        let uses = definition_count(&modules, accessor);
        assert_eq!(
            uses, 0,
            "'{accessor}' means a hand-rolled fold, use the stored-name accessor, found {uses}"
        );
    }
}

#[test]
fn blaming_an_unrecognized_clause_has_a_single_source_of_truth() {
    let modules = [
        "src/parser",
        "src/classifier",
        "src/classifier/recognizers",
        "src/generator",
        "src/generator/model_generator",
    ];

    for needle in [
        "fn called_function_names(",
        "fn unrecognized_operators(",
        "fn describe_unrecognized_function(",
        // A constructor is told apart from a call in one place, and described in one
        // place. A second copy would let the two disagree about what can be registered.
        "fn takes_a_subquery(",
        "fn subquery_set_constructors(",
        "fn describe_set_constructor(",
        // One recognizer decides which array spellings name the caller, and one reads a
        // jsonb key chain. A second copy would let the classifier and the renderer
        // disagree about what the clause says.
        "fn array_membership_column(",
        "fn jsonb_text_path(",
        "fn quote_sql_string_literal(",
    ] {
        let definitions = definition_count(&modules, needle);
        assert_eq!(
            definitions, 1,
            "expected one '{needle}', found {definitions}"
        );
    }

    // The operator reads these, so a second spelling would drift from the first.
    for fragment in [
        "not in registry and body not available",
        "did not match any recognized translation pattern",
        "is registered as Unknown",
        "is SQL syntax rather than a function call",
    ] {
        let uses = definition_count(&modules, fragment);
        assert_eq!(
            uses, 1,
            "'{fragment}' must come from describe_unrecognized_function alone, found {uses}"
        );
    }

    // Array membership and jsonb ownership are exact only because one place expands the
    // array and one place renders the key chain. A second renderer would drift from the
    // semantics both were verified against.
    for needle in ["UNNEST(", "fn render_jsonb_path("] {
        let uses = definition_count(&modules, needle);
        assert_eq!(uses, 1, "'{needle}' must have one source, found {uses}");
    }
}

/// One place decides that a parenthesis carries no meaning, and one place splits a
/// conjunction. A second peel would let one analyzer see through `pg_dump`'s
/// parentheses while another still refuses them.
#[test]
fn parenthesis_peeling_has_a_single_source_of_truth() {
    let modules = [
        "src/parser",
        "src/classifier",
        "src/classifier/recognizers",
        "src/generator",
        "src/generator/model_generator",
    ];

    for needle in [
        "fn unparenthesize(",
        "fn unwrap_cast_or_nested(",
        "fn flatten_and_predicates<",
    ] {
        let definitions = definition_count(&modules, needle);
        assert_eq!(
            definitions, 1,
            "expected one '{needle}', found {definitions}"
        );
    }

    // An extra membership predicate joins a conjunction of NULL guards, so every place
    // that splices one has to parenthesise it: a disjunction would otherwise break out
    // of the AND. Counting sites would break the moment a second one is added
    // correctly, so this asserts the property instead.
    let wrapped = definition_count(&modules, "AND ({e})");
    let bare = definition_count(&modules, "AND {e}");
    assert!(
        wrapped > 0,
        "the extra membership predicate must be spliced somewhere"
    );
    assert_eq!(
        bare, 0,
        "every splice of an extra predicate must parenthesise it, found {bare} that do not"
    );
}

/// The evaluator answers from one row, so it must not be able to reach a database.
///
/// This is structural on purpose. Calling the function can never show a handle to be
/// absent, only that this particular call did not use one, so the property is stated as
/// the module never naming a database type and never importing its way to one. The
/// `no_std` gate row covers it transitively, since a handle needs the standard library,
/// but that build says nothing about which module broke the rule.
#[test]
fn the_row_evaluator_holds_no_database_handle() {
    let source = read_module("src/generator/records.rs");

    for forbidden in [
        "ParserDB",
        "DatabaseLike",
        "diesel",
        "PgConnection",
        "Connection",
        "sql_query",
        "execute",
    ] {
        assert!(
            !source.contains(forbidden),
            "the row evaluator must not name `{forbidden}`"
        );
    }

    // Its imports stay inside a cone that cannot reach a database. Listing the paths
    // rather than whole lines keeps this robust to formatting, and widening the cone
    // has to be a deliberate edit here.
    // `generator::identity` is the encoding choke point. It reads no schema and takes
    // no database, and the evaluator has to spell a name exactly as the SQL does, so
    // sharing that one module is what keeps the two from drifting. `well_known` is the
    // single source for the names both sides spell, the typed wildcard among them.
    let allowed = [
        "crate::no_std_prelude",
        "crate::classifier::patterns",
        "crate::generator::identity",
        "crate::generator::well_known",
    ];
    for line in source
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("use crate::"))
    {
        let path = line
            .trim_start_matches("use ")
            .trim_end_matches(';')
            .to_string();
        assert!(
            allowed.iter().any(|prefix| path.starts_with(prefix)),
            "the row evaluator imports `{path}`, which is outside its pure cone"
        );
    }
}

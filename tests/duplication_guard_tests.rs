//! One rule, one spelling. Each guard states a property of the whole crate and names the
//! files exempt from it, rather than naming the files it searches.
//!
//! That direction matters. A guard listing the modules it reads goes quiet the moment a
//! file is added outside the list, and six modules had drifted outside every list,
//! `describe.rs` among them, which is how a second identifier escaper lived there
//! unnoticed. Searching everything and exempting deliberately fails towards noticing.

use std::fs;
use std::path::{Path, PathBuf};

/// Read a single module's source, test code included.
///
/// For the two guards that are about one file rather than about the crate.
fn read_module(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("failed to read {path}: {e}"))
}

/// Every `.rs` file under `src` carrying production code, as `(path, source)`.
///
/// Test code is cut at the `#[cfg(test)] mod tests` boundary and a whole `tests.rs` is
/// skipped, since a test spells a name on purpose and a helper it defines is not a second
/// implementation. A `#[cfg(test)]` item before that boundary is production-shaped and
/// stays counted.
fn src_modules() -> Vec<(String, String)> {
    fn walk(dir: &Path, into: &mut Vec<PathBuf>) {
        let mut entries: Vec<PathBuf> = fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("failed to read dir {}: {e}", dir.display()))
            .map(|entry| entry.expect("dir entry").path())
            .collect();
        entries.sort();
        for entry in entries {
            if entry.is_dir() {
                walk(&entry, into);
            } else if entry.extension().and_then(|ext| ext.to_str()) == Some("rs") {
                into.push(entry);
            }
        }
    }

    let mut paths = Vec::new();
    walk(Path::new("src"), &mut paths);

    paths
        .into_iter()
        .filter(|path| path.file_name().and_then(|name| name.to_str()) != Some("tests.rs"))
        .map(|path| {
            let source = fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
            let lines: Vec<&str> = source.lines().collect();
            let cut = lines
                .iter()
                .enumerate()
                .find(|(index, line)| {
                    line.trim() == "#[cfg(test)]"
                        && lines
                            .get(index + 1)
                            .is_some_and(|next| next.trim().starts_with("mod tests"))
                })
                .map_or(lines.len(), |(index, _)| index);
            (path.display().to_string(), lines[..cut].join("\n"))
        })
        .collect()
}

/// Count `needle` across every production module.
fn count_all(needle: &str) -> usize {
    count_excluding(&[], needle)
}

/// Count `needle` across every production module except `exempt`.
///
/// An exempt path that names no module is a failure rather than a silent widening, so a
/// rename says so instead of surfacing as a confusing count.
fn count_excluding(exempt: &[&str], needle: &str) -> usize {
    let modules = src_modules();
    for path in exempt {
        assert!(
            modules.iter().any(|(name, _)| name == path),
            "exempt path `{path}` names no module under src"
        );
    }
    modules
        .iter()
        .filter(|(path, _)| !exempt.contains(&path.as_str()))
        .map(|(_, source)| source.matches(needle).count())
        .sum()
}

/// Count definitions of `name`, whether or not it carries a generic parameter list.
fn fn_definitions(name: &str) -> usize {
    count_all(&format!("fn {name}(")) + count_all(&format!("fn {name}<"))
}

/// The walk itself, since every guard below is vacuous if it returns nothing.
///
/// The named files are the six that had drifted outside every guard's list. Pinning them
/// keeps the fix from being undone by a scoping mistake nobody notices.
#[test]
fn the_walk_reaches_every_source_file() {
    let modules = src_modules();

    assert!(
        modules.len() > 30,
        "the walk found only {} modules, so the guards below prove nothing",
        modules.len()
    );

    // Aggregate rather than per file. A new module has to cost nothing here, or the
    // inversion trades a guard that goes quiet for one that cries wolf, and an empty
    // file is the smallest new module there is.
    let total: usize = modules.iter().map(|(_, source)| source.len()).sum();
    assert!(
        total > 500_000,
        "the walk read only {total} bytes, so the guards below prove little"
    );

    for expected in [
        "src/lib.rs",
        "src/term.rs",
        "src/translator.rs",
        "src/output/report.rs",
        "src/generator/describe.rs",
        "src/generator/row_naming.rs",
        "src/generator/identity.rs",
        "src/generator/well_known.rs",
        "src/classifier/oracle.rs",
    ] {
        assert!(
            modules.iter().any(|(path, _)| path == expected),
            "{expected} is outside the walk, so no guard sees it"
        );
    }

    // The two test files are skipped, so a name a test spells is not a second spelling.
    assert!(
        !modules.iter().any(|(path, _)| path.ends_with("tests.rs")),
        "a whole test file reached the walk"
    );
}

#[test]
fn confidence_filtering_has_single_source_of_truth() {
    let definitions = fn_definitions("filter_policies_for_output");

    assert_eq!(
        definitions, 1,
        "expected a single confidence filtering implementation, found {definitions}"
    );
}

#[test]
fn pk_column_resolution_has_single_source_of_truth() {
    let definitions = fn_definitions("resolve_pk_columns");

    assert_eq!(
        definitions, 1,
        "expected a single PK-resolution implementation, found {definitions}"
    );

    // The single-column answer is derived from the list rather than resolved again.
    // A second resolution here is how a caller ends up naming a row one way while the
    // rest of the crate names it another.
    let single = fn_definitions("single_pk_column");

    assert_eq!(
        single, 1,
        "expected a single narrowing helper, found {single}"
    );
}

#[test]
fn function_arg_extraction_has_single_source_of_truth() {
    let expr_defs = fn_definitions("function_arg_expr");

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
    let centralized =
        count_all("table needs a single-column primary key or a NOT NULL UNIQUE `id` column");
    assert_eq!(
        centralized, 1,
        "expected the missing-object-id advice once, found {centralized}"
    );

    // Exempt: `notes.rs` is where the prose belongs.
    //
    // Two shapes, because one literal is what let a second wording through. The report
    // rendered `REVIEW: attribute condition on '...'` for the same gap `notes.rs` already
    // phrased twice, and this guard named the report's own file while looking only for the
    // comment marker. A guard aimed at a concept and spelled as one string is blind to a
    // synonym, so the report now renders notes rather than writing them, and both the
    // marker and the standing-out prefix are refused everywhere else.
    for wording in ["-- TODO [Level", "REVIEW:"] {
        let stray = count_excluding(&["src/generator/notes.rs"], wording);
        assert_eq!(
            stray, 0,
            "note prose belongs to notes.rs, found {stray} of '{wording}' elsewhere"
        );
    }
}

/// Every pattern the classifier can produce has a row in the README's table.
///
/// The README is the crate's rustdoc landing page through `include_str!`, so it is the only
/// place a consumer learns which shapes translate. Five patterns had been added without
/// rows, and the prose still claimed a count that was wrong for the rows it did have, so
/// the count is gone and the rows are checked instead. The variant names come from the enum
/// definition, which cannot drift from itself.
#[test]
fn every_pattern_has_a_readme_row() {
    let patterns = read_module("src/classifier/patterns.rs");
    let body = patterns
        .split_once("pub enum PatternClass {")
        .expect("PatternClass is declared")
        .1
        .split_once("\n}")
        .expect("the declaration closes")
        .0;

    // Each variant now carries a named payload, so it reads `P4ExistsMembership(Payload),`
    // rather than opening a brace.
    let variants: Vec<&str> = body
        .lines()
        .map(str::trim)
        .filter_map(|line| line.strip_prefix("P"))
        .filter_map(|line| line.split_once('('))
        .map(|(name, _)| name)
        .collect();

    assert!(
        variants.len() > 15,
        "only {} variants parsed out of the enum, so this proves nothing: {variants:?}",
        variants.len()
    );

    let readme = read_module("README.md");
    for variant in variants {
        // `P4ExistsMembership` is documented as row `P4` naming `ExistsMembership`, which
        // is the split the table's first two columns already make.
        let (number, name) = variant.split_at(
            variant
                .find(|ch: char| ch.is_ascii_alphabetic())
                .expect("a variant carries a name after its number"),
        );
        let row = format!("| P{number} | `{name}` |");
        assert!(
            readme.contains(&row),
            "README has no row `{row}` for PatternClass::P{number}{name}"
        );
    }
}

/// Every pattern's fields are declared once, by its payload struct.
///
/// `PatternClass` used to declare nineteen inline record types, which is why extracting an
/// arm needed up to eleven arguments and why an argument struct would have restated the same
/// field names beside the enum. Tuple variants make that impossible: a field can only be
/// added to the payload, so the recognizer that builds it and the emitter that reads it
/// cannot disagree about what the pattern holds.
#[test]
fn a_pattern_declares_its_fields_in_one_place() {
    let patterns = read_module("src/classifier/patterns.rs");
    let body = patterns
        .split_once("pub enum PatternClass {")
        .expect("PatternClass is declared")
        .1
        .split_once("\n}")
        .expect("the declaration closes")
        .0;

    let inline: Vec<&str> = body
        .lines()
        .map(str::trim)
        .filter(|line| line.ends_with('{'))
        .collect();
    assert!(
        inline.is_empty(),
        "a variant declaring its fields inline puts them in two places once a handler takes \
         them as arguments, found {inline:?}"
    );
}

/// Taking a table's plan out of the map and putting it back is one bracket.
///
/// The plan has to leave the map while a table is built, because minting a parent or holder type
/// needs the map mutably at the same time and nothing can hold both. Writing into the map for the
/// table currently being built is therefore discarded by the put-back, which is on the trap list
/// twice. `with_table_plan` owns both halves, so a second `remove` or `insert` on that map is the
/// shape that reintroduces the defect.
#[test]
fn a_table_plan_leaves_and_re_enters_the_map_in_one_place() {
    let source = read_module("src/generator/model_generator/mod.rs");

    let brackets = source.matches("fn with_table_plan<").count();
    assert_eq!(
        brackets, 1,
        "one bracket owns the pairing, found {brackets}"
    );

    for call in ["all_types.remove(", "all_types.insert("] {
        let uses = source.matches(call).count();
        assert_eq!(
            uses, 1,
            "'{call}' belongs to with_table_plan alone, found {uses}"
        );
    }
}

#[test]
fn p5_inheritance_analysis_has_single_source_of_truth() {
    let definitions = fn_definitions("analyze_p5_parent_inheritance");
    assert_eq!(
        definitions, 1,
        "expected a single P5 inheritance analysis helper, found {definitions}"
    );
}

/// The name a `<thing>_id` column gives the entity it references is decided once.
///
/// Every caller reaches it through `parent_type_from_fk_column` rather than stripping the
/// suffix itself, so a change to the rule cannot move a parent type while leaving an
/// ownership relation on the old spelling.
#[test]
fn the_name_an_id_column_references_has_a_single_source_of_truth() {
    let definitions = fn_definitions("parent_type_from_fk_column");
    assert_eq!(
        definitions, 1,
        "expected one 'fn parent_type_from_fk_column', found {definitions}"
    );

    // Exempt: `names.rs` holds the rule itself.
    let stray = count_excluding(&["src/parser/names.rs"], r#"strip_suffix("_id")"#);
    assert_eq!(
        stray, 0,
        "the suffix rule is reached through parent_type_from_fk_column, \
         found {stray} hand-rolled strips"
    );
}

/// `FROM ONLY` keeps an inheritance parent's child rows out of its object-minting
/// queries, and which reads carry it is one rule: a second `ONLY` spelling site could
/// scope a foreign-table read, which denies rows `PostgreSQL` grants, or miss an
/// owner-table read, which merges child rows into parent objects.
#[test]
fn the_from_only_scope_has_a_single_source_of_truth() {
    let definitions = fn_definitions("owner_table_reference");
    assert_eq!(
        definitions, 1,
        "expected one 'fn owner_table_reference', found {definitions}"
    );

    let spellings = count_all("\"ONLY {");
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
        let definitions = fn_definitions(name);
        assert_eq!(
            definitions, 1,
            "expected one 'fn {name}', found {definitions}"
        );
    }

    // Each clause by which a subquery stops being the plain set of rows in the table it
    // names is read in exactly one place. A second reader would let one spelling keep a
    // refusal another spelling dropped.
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
        let readers = count_all(clause);
        assert_eq!(
            readers, 1,
            "'{clause}' decides a refusal in one place, found {readers}"
        );
    }

    // The projected column of an `IN` subquery is a correlation, not a hint. Reading it
    // anywhere but the rewrite is how it used to reach the pattern without facing the
    // conflict check, which dropped a second correlation and granted the table whole.
    //
    // Scoped to one file on purpose, unlike the guards above: reading a projection is an
    // ordinary thing to do, and this says the membership analyzer does it once, not that
    // the crate does.
    let membership = read_module("src/classifier/recognizers/subquery.rs");
    let projection_readers = membership.matches("select.projection").count();
    assert_eq!(
        projection_readers, 1,
        "the projection is read only by the rewrite, found {projection_readers} readers"
    );
}

#[test]
fn bool_equality_extraction_has_single_source_of_truth() {
    let definitions = fn_definitions("extract_boolean_column_equality");
    assert_eq!(
        definitions, 1,
        "expected a single boolean equality extractor helper, found {definitions}"
    );
}

#[test]
fn role_in_list_extraction_has_single_source_of_truth() {
    let definitions = fn_definitions("extract_role_names_from_in_list");
    assert_eq!(
        definitions, 1,
        "expected one shared IN-list role extraction helper, found {definitions}"
    );
}

#[test]
fn token_pair_matching_has_single_source_of_truth() {
    let definitions = fn_definitions("has_token_pair");
    assert_eq!(
        definitions, 1,
        "expected one shared token-pair helper, found {definitions}"
    );
}

#[test]
fn relation_reference_walking_has_single_source_of_truth() {
    let walkers = count_all("visit_relations(");

    assert_eq!(
        walkers, 1,
        "walking an expression for the relations it reads belongs in one helper, found {walkers}"
    );
}

#[test]
fn action_relations_and_their_commands_are_paired_once() {
    let tables = count_all("fn action_relation_commands(");
    assert_eq!(
        tables, 1,
        "one table maps an action relation to its SQL command, found {tables}"
    );

    let strays = count_all("\"can_select\" => ");
    assert_eq!(
        strays, 0,
        "mapping a relation to a command by match duplicates that table, found {strays}"
    );

    let update_needs = count_all("ActionTarget::UpdateUsing, ActionTarget::UpdateCheck");
    assert_eq!(
        update_needs, 1,
        "one place says which clause targets a command needs, found {update_needs}"
    );
}

#[test]
fn reserved_relation_subjects_have_a_single_source_of_truth() {
    let definitions = fn_definitions("reserved_relation_subjects");
    assert_eq!(
        definitions, 1,
        "one place decides which relation names the generator keeps, found {definitions}"
    );
}

#[test]
fn generator_owned_relation_names_have_a_single_source_of_truth() {
    let definitions = fn_definitions("generator_defines");
    assert_eq!(
        definitions, 1,
        "one place decides which relation names a translated name may not take, found {definitions}"
    );
}

#[test]
fn well_known_names_have_a_single_source_of_truth() {
    // Exempt, and each for its own reason. `well_known.rs` owns the names.
    // `db_lookup.rs` names the SQL tables a principal conventionally lives in, which are
    // table names rather than model type names and deliberately stay out of well_known.
    // `names.rs` matches the word `user` inside a column name such as `user_id`.
    let exempt = [
        "src/generator/well_known.rs",
        "src/generator/db_lookup.rs",
        "src/parser/names.rs",
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
        let literals = count_excluding(&exempt, &format!("\"{name}\""));
        assert_eq!(
            literals, 0,
            "'{name}' must come from generator::well_known, found {literals} literals"
        );
    }
}

#[test]
fn blaming_an_unrecognized_clause_has_a_single_source_of_truth() {
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
        let definitions = count_all(needle);
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
        let uses = count_all(fragment);
        assert_eq!(
            uses, 1,
            "'{fragment}' must come from describe_unrecognized_function alone, found {uses}"
        );
    }

    // Array membership and jsonb ownership are exact only because one place expands the
    // array and one place renders the key chain. A second renderer would drift from the
    // semantics both were verified against.
    for needle in ["UNNEST(", "fn render_jsonb_path("] {
        let uses = count_all(needle);
        assert_eq!(uses, 1, "'{needle}' must have one source, found {uses}");
    }
}

/// One place turns an identifier into SQL text. A second escaper lets one site double an
/// interior quote while another does not, and `"a"b"` is not the column `a"b`: `PostgreSQL`
/// refuses to parse it, and a name chosen to close the quote rather than break it turns a
/// generated condition into a predicate of someone else's choosing.
#[test]
fn quoting_an_identifier_for_sql_has_a_single_source_of_truth() {
    for needle in ["fn quote_sql_identifier(", "fn bound_eq("] {
        let definitions = count_all(needle);
        assert_eq!(
            definitions, 1,
            "expected one '{needle}', found {definitions}"
        );
    }

    // Wrapping a name in quotes by hand is the bypass, since it skips the doubling.
    //
    // Exempt: `tuple_generator.rs` holds the escaper itself, and `quoted_for_lookup` in
    // `identifiers.rs` shares the doubling expression while deliberately not being SQL
    // text. It builds a key `lookup_table` resolves, leaving a bare lowercase name
    // unquoted, so it must not become SQL and must not be replaced by the escaper.
    let hand_quoted = count_excluding(
        &[
            "src/generator/tuple_generator.rs",
            "src/parser/identifiers.rs",
        ],
        r#"\"{"#,
    );
    assert_eq!(
        hand_quoted, 0,
        "an identifier becomes SQL through quote_sql_identifier, found {hand_quoted} by hand"
    );

    let lookup_keys = fn_definitions("quoted_for_lookup");
    assert_eq!(
        lookup_keys, 1,
        "one lookup-key speller, found {lookup_keys}"
    );
}

/// One place decides that a parenthesis carries no meaning, and one place splits a
/// conjunction. A second peel would let one analyzer see through `pg_dump`'s
/// parentheses while another still refuses them.
#[test]
fn parenthesis_peeling_has_a_single_source_of_truth() {
    for needle in [
        "fn unparenthesize(",
        "fn unwrap_cast_or_nested(",
        "fn flatten_and_predicates<",
    ] {
        let definitions = count_all(needle);
        assert_eq!(
            definitions, 1,
            "expected one '{needle}', found {definitions}"
        );
    }

    // An extra membership predicate joins a conjunction of NULL guards, so every place
    // that splices one has to parenthesise it: a disjunction would otherwise break out
    // of the AND. Counting sites would break the moment a second one is added
    // correctly, so this asserts the property instead.
    let wrapped = count_all("AND ({e})");
    let bare = count_all("AND {e}");
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
///
/// Scoped to one file, and the only guard here that is: it is a statement about one
/// module's imports rather than about a rule the crate keeps in one place.
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
    // `parser::identifiers` holds the name kinds. It reads no schema and takes no
    // database either, and a record's relation is a relation name, so sharing it is what
    // stops a column name being written into a fact.
    let allowed = [
        "crate::no_std_prelude",
        "crate::classifier::patterns",
        "crate::generator::identity",
        "crate::generator::well_known",
        "crate::parser::identifiers",
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

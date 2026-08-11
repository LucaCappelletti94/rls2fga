//! Regression tests for inputs where the generated model or tuple SQL diverged
//! from `PostgreSQL` RLS semantics.
//!
//! The names the model assigns, and the collisions it has to survive.

use rls2fga::classifier::patterns::ConfidenceLevel;
use rls2fga::generator::tuple_generator::format_tuples;

mod support;

use support::footgun::{
    db_of, relation_definition, relation_definitions, translator, tuples_reading_from, type_names,
};

const COLLIDING_SCHEMAS: &str = r"
CREATE SCHEMA app;
CREATE TABLE app.docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE app.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY app_docs_sel ON app.docs FOR SELECT USING (owner_id = current_user);
CREATE TABLE public.docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY public_docs_sel ON public.docs FOR SELECT USING (owner_id = current_user);
";

/// `app.docs` and `public.docs` both canonicalize to `docs`, so the second type
/// is renamed. Emitting its rows as `docs:<id>` would grant a `public.docs` owner
/// access to the `app.docs` row with the same key.
#[test]
fn disambiguated_type_receives_tuples_under_its_own_type_name() {
    let db = db_of(COLLIDING_SCHEMAS);
    let translator = translator(ConfidenceLevel::A);
    let dsl = translator.translate(&db).outputs_accepting_gaps().model();

    let renamed = type_names(&dsl)
        .into_iter()
        .find(|name| name != "docs" && name.starts_with("docs"))
        .expect("collision should produce a renamed second type");

    let tuples = translator
        .translate(&db)
        .outputs_accepting_gaps()
        .tuple_queries();
    assert_eq!(
        tuples.len(),
        2,
        "each colliding table needs its own ownership query, got: {tuples:#?}"
    );

    for (from_clause, expected_type) in [
        (r#"FROM "app"."docs""#, "docs"),
        (r#"FROM "public"."docs""#, renamed.as_str()),
    ] {
        let matching = tuples_reading_from(&tuples, from_clause);
        let [sql] = matching.as_slice() else {
            panic!("expected exactly one query reading {from_clause}, got: {matching:#?}");
        };
        assert!(
            sql.contains(&format!("'{expected_type}:'")),
            "query reading {from_clause} must emit '{expected_type}:' objects, got:\n{sql}"
        );
    }
}

/// A type without tuples can never be satisfied, so its policy is never enforced.
#[test]
fn disambiguated_type_is_not_left_without_tuples() {
    let db = db_of(COLLIDING_SCHEMAS);
    let translator = translator(ConfidenceLevel::A);
    let dsl = translator.translate(&db).outputs_accepting_gaps().model();
    let tuples = translator
        .translate(&db)
        .outputs_accepting_gaps()
        .tuple_queries();
    let rendered = format_tuples(&tuples);

    for type_name in type_names(&dsl) {
        if type_name == "user" {
            continue;
        }
        assert!(
            rendered.contains(&format!("'{type_name}:'")),
            "type '{type_name}' has no tuple query, so its relations can never be populated:\n{rendered}"
        );
    }
}

/// The generator refers to its own structural relations by name, so a table
/// named after one must not take it on a type that also needs it. Holding
/// `no_access` turns every denied action into a granted parent link.
#[test]
fn a_table_named_after_a_structural_relation_does_not_take_it() {
    for reserved in [
        "no_access",
        "public_viewer",
        "member",
        "owner_user",
        "owner_team",
    ] {
        let db = db_of(&format!(
            "
CREATE TABLE {reserved}(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE {reserved} ENABLE ROW LEVEL SECURITY;
CREATE POLICY parent_sel ON {reserved} FOR SELECT USING (owner_id = current_user);
CREATE TABLE tasks(id UUID PRIMARY KEY, parent_id UUID REFERENCES {reserved}(id));
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
CREATE POLICY tasks_sel ON tasks FOR SELECT USING (
  EXISTS (SELECT 1 FROM {reserved} p
          WHERE p.id = tasks.parent_id AND p.owner_id = current_user));
"
        ));
        let dsl = translator(ConfidenceLevel::A)
            .translate(&db)
            .outputs_accepting_gaps()
            .model();

        assert_ne!(
            relation_definition(&dsl, "tasks", reserved).as_deref(),
            Some(format!("[{reserved}]").as_str()),
            "the parent link took the structural relation '{reserved}':\n{dsl}"
        );
    }
}

/// The generator assembles an action from relations it names, so a column whose
/// relation would take one of those names leaves it defined twice and pointing at
/// itself.
#[test]
fn a_column_named_after_an_action_relation_does_not_take_it() {
    for reserved in [
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
        let db = db_of(&format!(
            "
CREATE TABLE docs(id UUID PRIMARY KEY, {reserved}_id UUID, editor_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING ({reserved}_id = current_user);
CREATE POLICY docs_ins ON docs FOR INSERT WITH CHECK (editor_id = current_user);
CREATE POLICY docs_upd ON docs FOR UPDATE USING ({reserved}_id = current_user)
  WITH CHECK (editor_id = current_user);
"
        ));
        let dsl = translator(ConfidenceLevel::B)
            .translate(&db)
            .outputs_accepting_gaps()
            .model();

        let defined = relation_definitions(&dsl, "docs");
        let mut names: Vec<&str> = defined.iter().map(|(name, _)| name.as_str()).collect();
        let declared = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(
            declared,
            names.len(),
            "a column named '{reserved}_id' took the action relation:\n{dsl}"
        );
        for (name, body) in &defined {
            assert!(
                !body.split_whitespace().any(|token| token == name),
                "'{name}' is defined as itself:\n{dsl}"
            );
        }
    }
}

/// Two policies on one table may spell its name differently. Grouping them by that
/// spelling builds the table twice, and the second group's actions overwrite the
/// first, so a RESTRICTIVE barrier can disappear.
#[test]
fn policies_compose_however_each_one_spells_the_table() {
    let schema = |restrictive_on: &str| {
        format!(
            "CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, reviewer_id UUID);\n\
             ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
             CREATE POLICY docs_owner ON docs FOR SELECT USING (owner_id = current_user);\n\
             CREATE POLICY docs_reviewed ON {restrictive_on} AS RESTRICTIVE FOR SELECT\n\
               USING (reviewer_id = current_user);\n"
        )
    };
    let read_of = |restrictive_on: &str| {
        let dsl = translator(ConfidenceLevel::A)
            .translate(&db_of(&schema(restrictive_on)))
            .outputs_accepting_gaps()
            .model();
        relation_definition(&dsl, "docs", "can_select")
    };

    assert_eq!(
        read_of("docs").as_deref(),
        Some("owner and reviewer"),
        "the bare spelling must keep the barrier, or this comparison proves nothing"
    );
    assert_eq!(
        read_of("\"docs\"").as_deref(),
        Some("owner and reviewer"),
        "quoting the table in the RESTRICTIVE policy must not drop it"
    );
}

/// `PostgreSQL` resolves an unqualified table reference through the search path, so a
/// policy may name a table in another schema without qualifying it. Leaving it
/// unresolved drops the policy and denies what RLS grants.
#[test]
fn a_policy_naming_its_table_without_the_schema_still_translates() {
    let db = db_of(
        r"
CREATE SCHEMA app;
SET search_path TO app;
CREATE TABLE app.docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE app.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
",
    );
    let translator = translator(ConfidenceLevel::A);
    let dsl = translator.translate(&db).outputs_accepting_gaps().model();

    assert_eq!(
        relation_definition(&dsl, "docs", "can_select").as_deref(),
        Some("owner"),
        "the policy names the table the search path resolves:\n{dsl}"
    );
    assert!(
        !tuples_reading_from(
            &translator
                .translate(&db)
                .outputs_accepting_gaps()
                .tuple_queries(),
            r#""docs""#
        )
        .is_empty(),
        "the ownership relation needs its rows"
    );
}

/// Two schemas may hold a table of the same name, and the search path decides which one
/// an unqualified policy means: the first entry holding it wins, which is what
/// `PostgreSQL` does. Guessing the other one binds the policy to the wrong rows.
#[test]
fn a_policy_naming_a_table_two_schemas_hold_follows_the_search_path() {
    let db = db_of(
        r"
CREATE SCHEMA aaa;
CREATE TABLE aaa.docs(id UUID PRIMARY KEY, owner_id UUID);
CREATE TABLE public.docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE aaa.docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;
SET search_path TO aaa, public;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
",
    );
    let model = translator(ConfidenceLevel::A)
        .translate(&db)
        .outputs_accepting_gaps();
    let dsl = model.model();

    let reads: Vec<(String, Option<String>)> = type_names(&dsl)
        .into_iter()
        .filter(|name| name != "user")
        .map(|name| {
            let definition = relation_definition(&dsl, &name, "can_select");
            (name, definition)
        })
        .collect();

    assert_eq!(
        reads
            .iter()
            .filter(|(_, definition)| definition.as_deref() == Some("owner"))
            .count(),
        1,
        "exactly one of the two tables carries the policy:\n{dsl}"
    );
    assert_eq!(
        reads
            .iter()
            .filter(|(_, definition)| definition.as_deref() == Some("no_access"))
            .count(),
        1,
        "the table the path does not select must read nothing:\n{dsl}"
    );

    // The policy resolves to `aaa.docs`, and a table carrying a policy claims the
    // canonical type name, so the untouched `public.docs` is the renamed one.
    assert_eq!(
        relation_definition(&dsl, "docs", "can_select").as_deref(),
        Some("owner"),
        "the first path entry holding the name wins:\n{dsl}"
    );
}

/// A policy may name its table without the schema. Matching that spelling against the
/// schema qualified name as text tells the operator RLS denies a command that its own
/// policy grants.
#[test]
fn a_filtered_policy_named_without_its_schema_is_reported_as_filtered() {
    let db = db_of(
        r"
CREATE SCHEMA app;
SET search_path TO app;
CREATE TABLE app.docs(id UUID PRIMARY KEY, tenant TEXT);
ALTER TABLE app.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (tenant = current_setting('app.tenant'));
",
    );
    let model = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();

    assert!(
        model.notes().iter().any(|note| {
            note.message()
                .contains("fell below the confidence threshold")
                && note.message().contains("SELECT")
        }),
        "the dropped SELECT policy must be reported as dropped, got {:#?}",
        model.notes()
    );
    assert!(
        !model.notes().iter().any(|note| {
            note.message().contains("No permissive policy") && note.message().contains("SELECT")
        }),
        "a policy PostgreSQL applies must not be reported as absent, got {:#?}",
        model.notes()
    );
}

/// A table that only appears as a deny-all must not take the canonical name from
/// a table with real policies: enabling RLS on an unrelated empty table would
/// otherwise rename a type whose tuples are already loaded.
#[test]
fn deny_only_table_does_not_take_the_name_of_a_table_with_policies() {
    let db = db_of(
        r"
CREATE SCHEMA aaa;
CREATE SCHEMA zzz;
CREATE TABLE aaa.docs(id UUID PRIMARY KEY);
ALTER TABLE aaa.docs ENABLE ROW LEVEL SECURITY;
CREATE TABLE zzz.docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE zzz.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY zzz_sel ON zzz.docs FOR SELECT USING (owner_id = current_user);
",
    );
    let translator = translator(ConfidenceLevel::A);
    let dsl = translator.translate(&db).outputs_accepting_gaps().model();

    assert_eq!(
        relation_definition(&dsl, "docs", "can_select").as_deref(),
        Some("owner"),
        "the table with policies keeps the canonical name:\n{dsl}"
    );
    let renamed = type_names(&dsl)
        .into_iter()
        .find(|name| name != "docs" && name.starts_with("docs"))
        .expect("the deny-all table should be the renamed one");
    assert_eq!(
        relation_definition(&dsl, &renamed, "can_select").as_deref(),
        Some("no_access"),
        "the deny-all table is the one that gets renamed:\n{dsl}"
    );
}

/// Canonicalizing a quoted role can map it onto a different existing role, which
/// changes who the policy admits.
#[test]
fn pg_role_identifier_rewrite_is_reported() {
    let db = db_of(
        r#"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT TO "billing admin" USING (owner_id = current_user);
"#,
    );
    let model = translator(ConfidenceLevel::A)
        .translate(&db)
        .outputs_accepting_gaps();

    assert!(
        model
            .notes()
            .iter()
            .any(|note| note.message().contains("billing admin")
                && note.message().contains("billing_admin")),
        "the role-name rewrite must name both the original and the OpenFGA identifier, got: {:#?}",
        model.notes()
    );
}

/// Each ownership column is a distinct relationship. Collapsing two of them into
/// one relation unions their subjects, so a policy that only admits `owner_id`
/// starts admitting everyone named by the other column.
#[test]
fn distinct_ownership_columns_get_distinct_relations() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, editor_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_upd ON docs FOR UPDATE USING (editor_id = current_user);
",
    );
    let translator = translator(ConfidenceLevel::A);
    let dsl = translator.translate(&db).outputs_accepting_gaps().model();

    let select =
        relation_definition(&dsl, "docs", "can_select").expect("docs should define can_select");
    let update =
        relation_definition(&dsl, "docs", "can_update").expect("docs should define can_update");
    assert_ne!(
        select, update,
        "SELECT admits owner_id and UPDATE admits editor_id, so they cannot share a relation:\n{dsl}"
    );

    // Every ownership query must populate the relation its own column feeds.
    for query in translator
        .translate(&db)
        .outputs_accepting_gaps()
        .tuple_queries()
    {
        // An action body may carry a trailing read gate.
        let leading = |body: &str| {
            body.split(" and ")
                .next()
                .unwrap_or(body)
                .trim()
                .to_string()
        };
        let column = if query.sql.contains(r#"|| "owner_id""#) {
            leading(&select)
        } else if query.sql.contains(r#"|| "editor_id""#) {
            leading(&update)
        } else {
            continue;
        };
        assert!(
            query.sql.contains(&format!("'{column}' AS relation")),
            "this query feeds the wrong relation, expected '{column}':\n{}",
            query.sql
        );
    }
}

/// `min_confidence` selects how much of a schema is translated. It must not
/// change what the types are called, or tuples loaded from one run stop matching
/// a model generated by another.
#[test]
fn type_names_do_not_depend_on_the_confidence_threshold() {
    let sql = r"
CREATE SCHEMA aaa;
CREATE SCHEMA zzz;
CREATE TABLE aaa.docs(id UUID PRIMARY KEY, tenant TEXT);
ALTER TABLE aaa.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY aaa_sel ON aaa.docs FOR SELECT USING (tenant = current_setting('app.tenant'));
CREATE TABLE zzz.docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE zzz.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY zzz_sel ON zzz.docs FOR SELECT USING (owner_id = current_user);
";
    let db = db_of(sql);
    let at_b = type_names(
        &translator(ConfidenceLevel::B)
            .translate(&db)
            .outputs_accepting_gaps()
            .model(),
    );
    let at_d = type_names(
        &translator(ConfidenceLevel::D)
            .translate(&db)
            .outputs_accepting_gaps()
            .model(),
    );

    assert_eq!(
        at_b, at_d,
        "the same schema must yield the same type names at every threshold"
    );
}

/// `OpenFGA` caps relation names at 50 characters and type names at 254. A longer
/// name is rejected when the model is written, which makes the whole artifact
/// unusable rather than just that relation.
#[test]
fn generated_names_respect_openfga_length_limits() {
    let long_column = "c".repeat(60);
    let long_table = "t".repeat(60);
    let long_parent = "p".repeat(60);
    let db = db_of(&format!(
        "CREATE TABLE {long_parent}(id UUID PRIMARY KEY, owner_id UUID);\n\
         ALTER TABLE {long_parent} ENABLE ROW LEVEL SECURITY;\n\
         CREATE POLICY parent_sel ON {long_parent} FOR SELECT USING (owner_id = current_user);\n\
         CREATE TABLE {long_table}(\n\
           id UUID PRIMARY KEY,\n\
           {long_column}_id UUID,\n\
           parent_ref UUID REFERENCES {long_parent}(id)\n\
         );\n\
         ALTER TABLE {long_table} ENABLE ROW LEVEL SECURITY;\n\
         CREATE POLICY own_sel ON {long_table} FOR SELECT USING ({long_column}_id = current_user);\n\
         CREATE POLICY inherit_upd ON {long_table} FOR UPDATE TO some_long_reporting_role USING (\n\
           EXISTS (SELECT 1 FROM {long_parent} p\n\
                   WHERE p.id = {long_table}.parent_ref AND p.owner_id = current_user));\n"
    ));
    let dsl = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps()
        .model();

    let mut relations = 0;
    let mut seen_types: Vec<&str> = Vec::new();
    for line in dsl.lines() {
        let trimmed = line.trim();
        if let Some(name) = trimmed.strip_prefix("type ") {
            let name = name.trim();
            assert!(
                name.chars().count() <= 254,
                "type '{name}' is {} characters, over the 254 limit",
                name.chars().count()
            );
            assert!(
                !seen_types.contains(&name),
                "type '{name}' is defined twice, which OpenFGA rejects:\n{dsl}"
            );
            seen_types.push(name);
        } else if let Some(rest) = trimmed.strip_prefix("define ") {
            let relation = rest.split_once(':').map_or(rest, |(name, _)| name).trim();
            relations += 1;
            assert!(
                relation.chars().count() <= 50,
                "relation '{relation}' is {} characters, over the 50 limit:\n{dsl}",
                relation.chars().count()
            );
        }
    }
    assert!(relations > 5, "expected a populated model, got:\n{dsl}");
}

/// Two schemas holding a table of the same name must not collapse into one type.
///
/// Collapsing them would let a policy on one answer for rows of the other, which is the
/// over-grant an earlier session traced to grouping policies by their raw spelling. The
/// `schema_search_path` fixture carries the shape: `app.docs` guarded by a policy that
/// names its table bare, `archive.docs` guarded by one that names it in full, and only
/// the search path says which `docs` the bare one means.
#[test]
fn two_schemas_holding_one_table_name_get_two_types() {
    let db = db_of(
        &std::fs::read_to_string("tests/fixtures/schema_search_path/input.sql")
            .expect("the fixture is readable"),
    );
    let dsl = translator(ConfidenceLevel::A)
        .translate(&db)
        .outputs_accepting_gaps()
        .model();

    let guarded: Vec<String> = type_names(&dsl)
        .into_iter()
        .filter(|name| {
            relation_definition(&dsl, name, "can_select").as_deref() == Some("owner_login")
        })
        .collect();

    assert_eq!(
        guarded.len(),
        2,
        "each table keeps its own read rule, so two types carry it:\n{dsl}"
    );

    // The renaming has to be reported, or an operator loading tuples under the canonical
    // name feeds them to whichever table won it.
    let renamed = guarded
        .iter()
        .find(|name| *name != "docs")
        .expect("one of the two is renamed");
    assert!(
        translator(ConfidenceLevel::A)
            .translate(&db)
            .outputs_accepting_gaps()
            .notes()
            .iter()
            .any(|note| note.message().contains(renamed.as_str())
                && note.message().contains("collision")),
        "the collision must be named, got {:#?}",
        translator(ConfidenceLevel::A)
            .translate(&db)
            .outputs_accepting_gaps()
            .notes()
    );
}

/// A dump carries roles, grants, sequences, indexes, views, enums, domains, generated
/// columns, comments, an owner and a composite key. None of that is a policy, and the
/// translator has to walk past all of it and still read the policies that are there.
#[test]
fn the_furniture_of_a_real_schema_does_not_disturb_the_policies() {
    let db = db_of(
        &std::fs::read_to_string("tests/fixtures/schema_objects/input.sql")
            .expect("the fixture is readable"),
    );
    let outputs = translator(ConfidenceLevel::C)
        .translate(&db)
        .outputs_accepting_gaps();
    let dsl = outputs.model();

    assert_eq!(
        relation_definition(&dsl, "docs", "can_select")
            .as_deref()
            .map(|d| d.contains("owner_login")),
        Some(true),
        "the ownership policy still reads its column:\n{dsl}"
    );

    // The owner the table was handed is exempt from every policy on it, and saying so is
    // the only way an operator learns the model is narrower than the database.
    assert!(
        outputs
            .notes()
            .iter()
            .any(|note| note.message().contains("auditor") && note.message().contains("exempt")),
        "the exempt owner must be named, got {:#?}",
        outputs.notes()
    );

    // A key over two columns leaves no single-column object identifier, so the table it
    // keys cannot take one from somewhere else.
    assert!(
        type_names(&dsl).iter().any(|name| name == "doc_links"),
        "the composite-key table is still translated:\n{dsl}"
    );
}

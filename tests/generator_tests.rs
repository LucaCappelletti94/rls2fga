use rls2fga::classifier::function_registry::FunctionRegistry;
use rls2fga::classifier::patterns::ConfidenceLevel;
use rls2fga::classifier::policy_classifier;
use rls2fga::generator::model_generator::GeneratorSettings;
use rls2fga::generator::tuple_generator;
use rls2fga::parser::function_analyzer::FunctionSemantic;
use rls2fga::parser::sql_parser;
use rls2fga::translator::Translation;

mod support;

fn load_emi() -> (
    Vec<rls2fga::classifier::patterns::ClassifiedPolicy>,
    sql_parser::ParserDB,
    FunctionRegistry,
) {
    support::load_fixture_classified("earth_metabolome")
}

/// The right-hand side of `define <relation>:` inside `type <type_name>`.
fn relation_body(dsl: &str, type_name: &str, relation: &str) -> Option<String> {
    let mut in_type = false;
    for line in dsl.lines() {
        let trimmed = line.trim();
        if let Some(name) = trimmed.strip_prefix("type ") {
            in_type = name.trim() == type_name;
            continue;
        }
        if in_type {
            if let Some(rest) = trimmed.strip_prefix(&format!("define {relation}:")) {
                return Some(rest.trim().to_string());
            }
        }
    }
    None
}

#[test]
fn generate_emi_model() {
    let (classified, db, registry) = load_emi();
    let model = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps();
    insta::assert_snapshot!(model.model().trim());
}

#[test]
fn generate_emi_tuples() {
    let (classified, db, registry) = load_emi();
    let tuples = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps()
    .tuple_queries();
    insta::assert_snapshot!(tuple_generator::format_tuples(&tuples));
}

#[test]
fn generate_emi_json_model() {
    let (classified, db, registry) = load_emi();
    let model = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps()
    .json_model();
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
    let model = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps();
    insta::assert_snapshot!(model.model().trim());
}

#[test]
fn generate_public_flag_model() {
    let db = support::parse_fixture_db("public_flag");
    let registry = FunctionRegistry::new();

    let classified = policy_classifier::classify_policies(&db, &registry);
    let model = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps();
    insta::assert_snapshot!(model.model().trim());
}

// ── P2: role name IN-list ────────────────────────────────────────────────────

#[test]
fn generate_role_in_list_model_and_tuples() {
    let (db, registry) = support::load_fixture_db_and_registry("role_in_list");
    let classified = policy_classifier::classify_policies(&db, &registry);

    let model = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps();
    insta::assert_snapshot!("generate_role_in_list_model", model.model().trim());

    let tuples = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps()
    .tuple_queries();
    insta::assert_snapshot!(
        "generate_role_in_list_tuples",
        tuple_generator::format_tuples(&tuples)
    );
}

// ── P4: EXISTS membership ────────────────────────────────────────────────────

#[test]
fn generate_membership_check_model_and_tuples() {
    let db = support::parse_fixture_db("membership_check");
    let registry = FunctionRegistry::new();

    let classified = policy_classifier::classify_policies(&db, &registry);

    let model = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps();
    insta::assert_snapshot!("generate_membership_check_model", model.model().trim());

    let tuples = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps()
    .tuple_queries();
    insta::assert_snapshot!(
        "generate_membership_check_tuples",
        tuple_generator::format_tuples(&tuples)
    );
}

// ── P5: parent inheritance ───────────────────────────────────────────────────

#[test]
fn generate_parent_inheritance_model_and_tuples() {
    let db = support::parse_fixture_db("parent_inheritance");
    let registry = FunctionRegistry::new();
    let classified = policy_classifier::classify_policies(&db, &registry);

    let model = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps();
    insta::assert_snapshot!("generate_parent_inheritance_model", model.model().trim());

    let tuples = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps()
    .tuple_queries();
    insta::assert_snapshot!(
        "generate_parent_inheritance_tuples",
        tuple_generator::format_tuples(&tuples)
    );
}

// ── P6: boolean flag tuples (model snapshot already exists) ─────────────────

#[test]
fn generate_public_flag_tuples() {
    let db = support::parse_fixture_db("public_flag");
    let registry = FunctionRegistry::new();

    let classified = policy_classifier::classify_policies(&db, &registry);
    let tuples = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps()
    .tuple_queries();
    insta::assert_snapshot!(tuple_generator::format_tuples(&tuples));
}

// ── P7: ABAC AND (relationship + attribute) ──────────────────────────────────

#[test]
fn generate_abac_status_model_and_tuples() {
    let (db, registry) = support::load_fixture_db_and_registry("abac_status");
    let classified = policy_classifier::classify_policies(&db, &registry);

    let model = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::C,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps();
    insta::assert_snapshot!("generate_abac_status_model", model.model().trim());

    let tuples = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::C,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps()
    .tuple_queries();
    insta::assert_snapshot!(
        "generate_abac_status_tuples",
        tuple_generator::format_tuples(&tuples)
    );
}

// ── P8: composite OR (P3 + P6) ───────────────────────────────────────────────

#[test]
fn generate_compound_or_model_and_tuples() {
    let db = support::parse_fixture_db("compound_or");
    let registry = FunctionRegistry::new();

    let classified = policy_classifier::classify_policies(&db, &registry);

    let model = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps();
    insta::assert_snapshot!("generate_compound_or_model", model.model().trim());

    let tuples = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps()
    .tuple_queries();
    insta::assert_snapshot!(
        "generate_compound_or_tuples",
        tuple_generator::format_tuples(&tuples)
    );
}

// ── P10: constant TRUE / FALSE ───────────────────────────────────────────────

#[test]
fn schema_collision_tables_get_disambiguated_type_names() {
    // Two schema-qualified tables that canonicalize to the same base name must receive
    // distinct OpenFGA type names.  The generator should append a stable hex suffix to
    // the colliding entry and emit a TranslationNote describing the collision.
    let sql = r"
CREATE SCHEMA app;
CREATE SCHEMA auth;
CREATE TABLE app.users (id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE app.users ENABLE ROW LEVEL SECURITY;
CREATE POLICY app_users_select ON app.users FOR SELECT USING (owner_id = current_user);

CREATE TABLE auth.users (id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE auth.users ENABLE ROW LEVEL SECURITY;
CREATE POLICY auth_users_select ON auth.users FOR SELECT USING (owner_id = current_user);
";
    let db = sql_parser::parse_schema(sql).expect("schema should parse");
    let registry = FunctionRegistry::new();
    let classified = policy_classifier::classify_policies(&db, &registry);
    let model = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps();

    // Both tables must have a type in the DSL — they should NOT be merged.
    let type_count = model.model().matches("type users").count()
        + model
            .model()
            .split('\n')
            .filter(|l| l.trim().starts_with("type "))
            .count();
    assert!(
        type_count > 1,
        "Two tables canonicalizing to 'users' must produce at least two resource types;\n\nDSL:\n{}",
        model.model()
    );
    // A TODO item should flag the collision.
    assert!(
        model
            .notes()
            .iter()
            .any(|t| t.message().contains("collision")),
        "Expected a TODO item describing the type-name collision"
    );
}

#[test]
fn generate_constant_bool_model_and_tuples() {
    let db = support::parse_fixture_db("constant_bool");
    let registry = FunctionRegistry::new();
    let classified = policy_classifier::classify_policies(&db, &registry);

    let model = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps();
    insta::assert_snapshot!("generate_constant_bool_model", model.model().trim());

    let tuples = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps()
    .tuple_queries();
    insta::assert_snapshot!(
        "generate_constant_bool_tuples",
        tuple_generator::format_tuples(&tuples)
    );
}

// ── Gap 1: pg_has_role / RoleAccessor → a walked pg_role scope ───────────────

/// The relation holds `[pg_role]` subjects, so pointing an action straight at it admits a
/// `pg_role:` object and never a `user:`. The action has to walk it to the role's members,
/// which is also what makes `pg_role#member` exist for the operator to load into.
#[test]
fn pg_has_role_walks_the_scope_to_the_roles_members() {
    let sql = r"
CREATE TABLE docs (id UUID PRIMARY KEY, title TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON docs FOR SELECT
    USING (pg_has_role(current_user, 'editor', 'MEMBER'));
";
    let (classified, db, registry) = support::classify_sql(sql, None);

    let model = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps();
    assert_eq!(
        relation_body(&model.model(), "docs", "can_select").as_deref(),
        Some("member from scope_docs_select_14425117"),
        "pg_has_role admits every member of the role, so the grant walks the scope:\n{}",
        model.model()
    );
    assert!(
        model.model().contains("define member: [user]"),
        "the walked relation has to exist for the operator to load memberships into:\n{}",
        model.model()
    );
    insta::assert_snapshot!("pg_has_role_model", model.model().trim());

    let tuples = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps()
    .tuple_queries();
    insta::assert_snapshot!(
        "pg_has_role_tuples",
        tuple_generator::format_tuples(&tuples)
    );
}

/// The accessor spelling reaches the same gate, so it needs the same walk.
#[test]
fn role_accessor_walks_the_scope_to_the_roles_members() {
    let sql = r"
CREATE TABLE docs (id UUID PRIMARY KEY, title TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON docs FOR SELECT
    USING (auth.role() = 'authenticated');
";
    let registry_json = r#"{
  "auth.role": {"kind": "role_accessor"}
}"#;
    let (classified, db, registry) = support::classify_sql(sql, Some(registry_json));

    let model = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps();
    assert_eq!(
        relation_body(&model.model(), "docs", "can_select").as_deref(),
        Some("member from scope_docs_select_14425117"),
        "the role accessor admits every member of the role:\n{}",
        model.model()
    );
    insta::assert_snapshot!("role_accessor_model", model.model().trim());

    let tuples = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps()
    .tuple_queries();
    insta::assert_snapshot!(
        "role_accessor_tuples",
        tuple_generator::format_tuples(&tuples)
    );
}

/// The privilege decides which members the policy admits, so it decides which relation the
/// gate walks. Probed on `postgres:18`: a member granted without inheritance has `MEMBER`
/// and not `USAGE`, one granted with `SET FALSE` has `MEMBER` and not `SET`, and only an
/// administrator has any `WITH ADMIN OPTION` form, whichever kind precedes it.
#[test]
fn each_pg_has_role_privilege_walks_its_own_relation() {
    let mut complaints = Vec::new();
    for (privilege, relation) in [
        ("MEMBER", "member"),
        ("USAGE", "usage"),
        ("SET", "set_role"),
        // All three admin spellings are one answer: PostgreSQL ignores the kind once the
        // admin option is asked about.
        ("MEMBER WITH ADMIN OPTION", "admin_option"),
        ("USAGE WITH ADMIN OPTION", "admin_option"),
        ("SET WITH ADMIN OPTION", "admin_option"),
        // Case and surrounding space do not change the answer in PostgreSQL either.
        ("usage", "usage"),
        (" MEMBER ", "member"),
        ("member with admin option", "admin_option"),
    ] {
        let sql = format!(
            r"
CREATE TABLE docs (id TEXT PRIMARY KEY);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON docs FOR SELECT
    USING (pg_has_role(current_user, 'editor', '{privilege}'));
"
        );
        let (classified, db, registry) = support::classify_sql(&sql, None);
        let dsl = Translation::plan(
            classified,
            &db,
            &registry,
            ConfidenceLevel::B,
            &GeneratorSettings::default(),
        )
        .outputs_accepting_gaps()
        .model();

        let expected = format!("{relation} from scope_docs_select_14425117");
        if relation_body(&dsl, "docs", "can_select").as_deref() != Some(expected.as_str()) {
            complaints.push(format!(
                "'{privilege}' should walk `{expected}`, got `{:?}`",
                relation_body(&dsl, "docs", "can_select")
            ));
        }
        if relation_body(&dsl, "pg_role", relation).as_deref() != Some("[user]") {
            complaints.push(format!(
                "'{privilege}' needs pg_role#{relation} for the operator to load into:\n{dsl}"
            ));
        }
    }
    assert!(complaints.is_empty(), "{}", complaints.join("\n"));
}

/// Two policies naming different privileges of one role is the shape that forces a relation
/// per privilege: sharing one would make the operator's single set of facts mean both.
#[test]
fn two_privileges_of_one_role_get_their_own_relations() {
    let sql = r"
CREATE TABLE docs (id TEXT PRIMARY KEY);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_read ON docs FOR SELECT
    USING (pg_has_role(current_user, 'editor', 'USAGE'));
CREATE POLICY docs_admin ON docs FOR DELETE
    USING (pg_has_role(current_user, 'editor', 'MEMBER WITH ADMIN OPTION'));
";
    let (classified, db, registry) = support::classify_sql(sql, None);
    let dsl = Translation::plan(
        classified,
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps()
    .model();

    assert_eq!(
        relation_body(&dsl, "docs", "can_select").as_deref(),
        Some("usage from scope_docs_read_06abf03b"),
        "the read policy asked about inheriting members:\n{dsl}"
    );
    assert_eq!(
        relation_body(&dsl, "docs", "can_delete").as_deref(),
        Some("admin_option from scope_docs_admin_e9b28a46 and can_select"),
        "the delete policy asked about the role's administrators:\n{dsl}"
    );
    for relation in ["usage", "admin_option"] {
        assert_eq!(
            relation_body(&dsl, "pg_role", relation).as_deref(),
            Some("[user]"),
            "each privilege needs its own set of facts:\n{dsl}"
        );
    }
    assert_eq!(
        relation_body(&dsl, "pg_role", "member"),
        None,
        "no policy asked about plain membership, so nothing may offer to hold it:\n{dsl}"
    );
}

/// A privilege the crate cannot read is not plain membership. `PostgreSQL` answers false for
/// an unrecognised string, so falling closed is faithful, and a privilege that is not a
/// literal cannot be known at all.
#[test]
fn a_pg_has_role_privilege_the_crate_cannot_read_falls_closed() {
    for privilege in ["'MEMBER WITH GRANT OPTION'", "'nonsense'", "some_column"] {
        let sql = format!(
            r"
CREATE TABLE docs (id TEXT PRIMARY KEY, some_column TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON docs FOR SELECT
    USING (pg_has_role(current_user, 'editor', {privilege}));
"
        );
        let (classified, db, registry) = support::classify_sql(&sql, None);
        let dsl = Translation::plan(
            classified,
            &db,
            &registry,
            ConfidenceLevel::B,
            &GeneratorSettings::default(),
        )
        .outputs_accepting_gaps()
        .model();
        assert_eq!(
            relation_body(&dsl, "docs", "can_select").as_deref(),
            Some("no_access"),
            "{privilege} names no privilege the crate can act on:\n{dsl}"
        );
    }
}

// ── P9: standalone attribute condition ──────────────────────────────────────

#[test]
fn generate_attribute_guard_model_and_tuples() {
    let db = support::parse_fixture_db("attribute_guard");
    let registry = FunctionRegistry::new();
    let classified = policy_classifier::classify_policies(&db, &registry);

    let model = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::C,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps();
    insta::assert_snapshot!("generate_attribute_guard_model", model.model().trim());

    let tuples = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::C,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps()
    .tuple_queries();
    insta::assert_snapshot!(
        "generate_attribute_guard_tuples",
        tuple_generator::format_tuples(&tuples)
    );
}

// ── Request-time conditions ──────────────────────────────────────────────────

/// The only fixture carrying conditions, so it is the only mechanical check on the
/// condition block and on the context column the tuple SQL builds beside it.
#[test]
fn generate_shared_policy_name_model_and_tuples() {
    let db = support::parse_fixture_db("shared_policy_name");
    let registry = FunctionRegistry::new();
    let classified = policy_classifier::classify_policies(&db, &registry);

    let model = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps();
    insta::assert_snapshot!("generate_shared_policy_name_model", model.model().trim());

    let tuples = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps()
    .tuple_queries();
    insta::assert_snapshot!(
        "generate_shared_policy_name_tuples",
        tuple_generator::format_tuples(&tuples)
    );
}

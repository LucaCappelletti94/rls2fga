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

// ── Gap 1: pg_has_role / RoleAccessor → scope relation (not deny) ───────────

#[test]
fn pg_has_role_generates_scope_relation_not_deny() {
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
    // Other commands lack a policy and are legitimately denied; only can_select
    // must not degrade to a deny.
    assert!(
        model.model().contains("define can_select: scope_"),
        "pg_has_role should drive can_select from a scope relation, not a deny; DSL:\n{}",
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

#[test]
fn role_accessor_generates_scope_relation() {
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
    assert!(
        model.model().contains("define can_select: scope_"),
        "role accessor should drive can_select from a scope relation, not a deny; DSL:\n{}",
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

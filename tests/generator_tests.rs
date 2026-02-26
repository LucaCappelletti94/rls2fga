use rls2fga::classifier::function_registry::FunctionRegistry;
use rls2fga::classifier::patterns::ConfidenceLevel;
use rls2fga::classifier::policy_classifier;
use rls2fga::generator::json_model;
use rls2fga::generator::model_generator;
use rls2fga::generator::tuple_generator;
use rls2fga::parser::function_analyzer::FunctionSemantic;
use rls2fga::parser::sql_parser;

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
    let model = model_generator::generate_model(&classified, &db, &registry, ConfidenceLevel::B);
    insta::assert_snapshot!(model.dsl.trim());
}

#[test]
fn generate_emi_tuples() {
    let (classified, db, registry) = load_emi();
    let tuples =
        tuple_generator::generate_tuple_queries(&classified, &db, &registry, ConfidenceLevel::B);
    insta::assert_snapshot!(tuple_generator::format_tuples(&tuples));
}

#[test]
fn generate_emi_json_model() {
    let (classified, db, registry) = load_emi();
    let model = json_model::generate_json_model(&classified, &db, &registry, ConfidenceLevel::B);
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
    let model = model_generator::generate_model(&classified, &db, &registry, ConfidenceLevel::B);
    insta::assert_snapshot!(model.dsl.trim());
}

#[test]
fn generate_public_flag_model() {
    let db = support::parse_fixture_db("public_flag");
    let registry = FunctionRegistry::new();

    let classified = policy_classifier::classify_policies(&db, &registry);
    let model = model_generator::generate_model(&classified, &db, &registry, ConfidenceLevel::B);
    insta::assert_snapshot!(model.dsl.trim());
}

// ── P2: role name IN-list ────────────────────────────────────────────────────

#[test]
fn generate_role_in_list_model_and_tuples() {
    let (db, registry) = support::load_fixture_db_and_registry("role_in_list");
    let classified = policy_classifier::classify_policies(&db, &registry);

    let model = model_generator::generate_model(&classified, &db, &registry, ConfidenceLevel::B);
    insta::assert_snapshot!("generate_role_in_list_model", model.dsl.trim());

    let tuples =
        tuple_generator::generate_tuple_queries(&classified, &db, &registry, ConfidenceLevel::B);
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

    let model = model_generator::generate_model(&classified, &db, &registry, ConfidenceLevel::B);
    insta::assert_snapshot!("generate_membership_check_model", model.dsl.trim());

    let tuples =
        tuple_generator::generate_tuple_queries(&classified, &db, &registry, ConfidenceLevel::B);
    insta::assert_snapshot!(
        "generate_membership_check_tuples",
        tuple_generator::format_tuples(&tuples)
    );
}

// ── P5: parent inheritance ───────────────────────────────────────────────────

#[test]
fn generate_parent_inheritance_model_and_tuples() {
    let sql = r"
CREATE TABLE users (id UUID PRIMARY KEY);
CREATE TABLE projects (
  id UUID PRIMARY KEY,
  owner_id UUID REFERENCES users(id)
);
CREATE TABLE tasks (
  id UUID PRIMARY KEY,
  project_id UUID NOT NULL REFERENCES projects(id)
);
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
CREATE POLICY projects_owner ON projects FOR SELECT TO PUBLIC
  USING (owner_id = current_user);
CREATE POLICY tasks_inherit_project ON tasks FOR SELECT TO PUBLIC USING (
  EXISTS (
    SELECT 1
    FROM projects p
    WHERE p.id = tasks.project_id
      AND p.owner_id = current_user
  )
);
";
    let db = sql_parser::parse_schema(sql).expect("schema should parse");
    let registry = FunctionRegistry::new();
    let classified = policy_classifier::classify_policies(&db, &registry);

    let model = model_generator::generate_model(&classified, &db, &registry, ConfidenceLevel::B);
    insta::assert_snapshot!("generate_parent_inheritance_model", model.dsl.trim());

    let tuples =
        tuple_generator::generate_tuple_queries(&classified, &db, &registry, ConfidenceLevel::B);
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
    let tuples =
        tuple_generator::generate_tuple_queries(&classified, &db, &registry, ConfidenceLevel::B);
    insta::assert_snapshot!(tuple_generator::format_tuples(&tuples));
}

// ── P7: ABAC AND (relationship + attribute) ──────────────────────────────────

#[test]
fn generate_abac_status_model_and_tuples() {
    let (db, registry) = support::load_fixture_db_and_registry("abac_status");
    let classified = policy_classifier::classify_policies(&db, &registry);

    let model = model_generator::generate_model(&classified, &db, &registry, ConfidenceLevel::C);
    insta::assert_snapshot!("generate_abac_status_model", model.dsl.trim());

    let tuples =
        tuple_generator::generate_tuple_queries(&classified, &db, &registry, ConfidenceLevel::C);
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

    let model = model_generator::generate_model(&classified, &db, &registry, ConfidenceLevel::B);
    insta::assert_snapshot!("generate_compound_or_model", model.dsl.trim());

    let tuples =
        tuple_generator::generate_tuple_queries(&classified, &db, &registry, ConfidenceLevel::B);
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
    // the colliding entry and emit a TodoItem describing the collision.
    let sql = r"
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
    let model = model_generator::generate_model(&classified, &db, &registry, ConfidenceLevel::B);

    // Both tables must have a type in the DSL — they should NOT be merged.
    let type_count = model.dsl.matches("type users").count()
        + model
            .dsl
            .split('\n')
            .filter(|l| l.trim().starts_with("type "))
            .count();
    assert!(
        type_count > 1,
        "Two tables canonicalizing to 'users' must produce at least two resource types;\n\nDSL:\n{}",
        model.dsl
    );
    // A TODO item should flag the collision.
    assert!(
        model.todos.iter().any(|t| t.message.contains("collision")),
        "Expected a TODO item describing the type-name collision"
    );
}

#[test]
fn generate_constant_bool_model_and_tuples() {
    let sql = r"
CREATE TABLE docs (id UUID PRIMARY KEY);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_true ON docs AS PERMISSIVE FOR SELECT TO PUBLIC USING (TRUE);
CREATE POLICY p_false ON docs AS RESTRICTIVE FOR SELECT TO PUBLIC USING (FALSE);
";
    let db = sql_parser::parse_schema(sql).expect("schema should parse");
    let registry = FunctionRegistry::new();
    let classified = policy_classifier::classify_policies(&db, &registry);

    let model = model_generator::generate_model(&classified, &db, &registry, ConfidenceLevel::B);
    insta::assert_snapshot!("generate_constant_bool_model", model.dsl.trim());

    let tuples =
        tuple_generator::generate_tuple_queries(&classified, &db, &registry, ConfidenceLevel::B);
    insta::assert_snapshot!(
        "generate_constant_bool_tuples",
        tuple_generator::format_tuples(&tuples)
    );
}

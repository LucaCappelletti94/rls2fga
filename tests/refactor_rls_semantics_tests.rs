use rls2fga::classifier::function_registry::FunctionRegistry;
use rls2fga::classifier::patterns::ConfidenceLevel;
use rls2fga::classifier::policy_classifier;
use rls2fga::generator::json_model;
use rls2fga::generator::model_generator;
use rls2fga::generator::tuple_generator;
use rls2fga::parser::sql_parser;

fn classify_sql(
    sql: &str,
    registry_json: Option<&str>,
) -> (
    Vec<rls2fga::classifier::patterns::ClassifiedPolicy>,
    sql_parser::ParserDB,
    FunctionRegistry,
) {
    let db = sql_parser::parse_schema(sql).expect("schema should parse");
    let mut registry = FunctionRegistry::new();
    if let Some(json) = registry_json {
        registry
            .load_from_json(json)
            .expect("registry json should parse");
    }
    let classified = policy_classifier::classify_policies(&db, &registry);
    (classified, db, registry)
}

#[test]
fn multi_policy_table_combines_patterns_for_select() {
    let sql = std::fs::read_to_string("tests/fixtures/multi_policy_table/input.sql").unwrap();
    let reg_json = r#"{
      "auth_current_user_id": {"kind":"current_user_accessor","returns":"uuid"}
    }"#;

    let (classified, db, registry) = classify_sql(&sql, Some(reg_json));
    let model = model_generator::generate_model(&classified, &db, &registry, &ConfidenceLevel::D);

    assert!(
        model
            .dsl
            .contains("define can_select: owner or public_viewer")
            || model
                .dsl
                .contains("define can_select: public_viewer or owner"),
        "expected composed select permission, got:\n{}",
        model.dsl
    );
}

#[test]
fn restrictive_policy_is_anded_with_permissive() {
    let sql = r#"
CREATE TABLE users (id UUID PRIMARY KEY);
CREATE TABLE docs (
  id UUID PRIMARY KEY,
  owner_id UUID REFERENCES users(id),
  is_public BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE FUNCTION auth_current_user_id() RETURNS UUID
  LANGUAGE sql STABLE
  AS 'SELECT current_setting(''app.current_user_id'')::uuid';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_owner ON docs AS PERMISSIVE FOR SELECT TO PUBLIC
  USING (owner_id = auth_current_user_id());
CREATE POLICY p_public ON docs AS RESTRICTIVE FOR SELECT TO PUBLIC
  USING (is_public = TRUE);
"#;
    let reg_json = r#"{
      "auth_current_user_id": {"kind":"current_user_accessor","returns":"uuid"}
    }"#;

    let (classified, db, registry) = classify_sql(sql, Some(reg_json));
    let model = model_generator::generate_model(&classified, &db, &registry, &ConfidenceLevel::D);

    assert!(
        model
            .dsl
            .contains("define can_select: owner and public_viewer")
            || model
                .dsl
                .contains("define can_select: public_viewer and owner"),
        "restrictive policy should intersect with permissive policy, got:\n{}",
        model.dsl
    );
}

#[test]
fn update_using_and_with_check_are_split() {
    let sql = r#"
CREATE TABLE users (id UUID PRIMARY KEY);
CREATE TABLE teams (id UUID PRIMARY KEY);
CREATE TABLE team_members (
  team_id UUID NOT NULL REFERENCES teams(id),
  user_id UUID NOT NULL REFERENCES users(id)
);
CREATE TABLE docs (
  id UUID PRIMARY KEY,
  owner_id UUID NOT NULL
);
CREATE TABLE owner_grants (
  grantee_owner_id UUID NOT NULL,
  granted_owner_id UUID NOT NULL,
  role_id INTEGER NOT NULL
);
CREATE FUNCTION auth_current_user_id() RETURNS UUID
  LANGUAGE sql STABLE
  AS 'SELECT current_setting(''app.current_user_id'')::uuid';
CREATE FUNCTION get_owner_role(user_uuid UUID, target_owner_id UUID) RETURNS INTEGER
  LANGUAGE sql STABLE
  AS 'SELECT 0';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_update ON docs FOR UPDATE TO PUBLIC
  USING (get_owner_role(auth_current_user_id(), owner_id) >= 2)
  WITH CHECK (get_owner_role(auth_current_user_id(), owner_id) >= 3);
"#;
    let reg_json =
        std::fs::read_to_string("tests/fixtures/earth_metabolome/function_registry.json").unwrap();

    let (classified, db, registry) = classify_sql(sql, Some(&reg_json));
    let model = model_generator::generate_model(&classified, &db, &registry, &ConfidenceLevel::D);

    assert!(
        model.dsl.contains("define can_update_using:"),
        "expected separate UPDATE visibility relation, got:\n{}",
        model.dsl
    );
    assert!(
        model.dsl.contains("define can_update_check:"),
        "expected separate UPDATE check relation, got:\n{}",
        model.dsl
    );
    assert!(
        model
            .dsl
            .contains("define can_update: can_update_using and can_update_check"),
        "expected combined UPDATE relation, got:\n{}",
        model.dsl
    );
}

#[test]
fn p4_membership_uses_actual_fk_column_from_subquery() {
    let sql = r#"
CREATE TABLE users (id UUID PRIMARY KEY);
CREATE TABLE projects (id UUID PRIMARY KEY);
CREATE TABLE project_members (
  project_id UUID NOT NULL REFERENCES projects(id),
  user_id UUID NOT NULL REFERENCES users(id),
  role TEXT NOT NULL
);
CREATE FUNCTION auth_current_user_id() RETURNS UUID
  LANGUAGE sql STABLE
  AS 'SELECT current_setting(''app.current_user_id'')::uuid';
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON projects FOR UPDATE TO PUBLIC USING (
  EXISTS (
    SELECT 1 FROM project_members
    WHERE project_id = projects.id
      AND user_id = auth_current_user_id()
      AND role = 'admin'
  )
);
"#;
    let reg_json = r#"{
      "auth_current_user_id": {"kind":"current_user_accessor","returns":"uuid"}
    }"#;

    let (classified, db, registry) = classify_sql(sql, Some(reg_json));
    let model = model_generator::generate_model(&classified, &db, &registry, &ConfidenceLevel::D);
    let tuples = tuple_generator::format_tuples(&tuple_generator::generate_tuple_queries(
        &classified,
        &db,
        &registry,
    ));

    assert!(
        model.dsl.contains("define project: [project]") || model.dsl.contains("define projects:"),
        "expected parent relation based on project_id, got:\n{}",
        model.dsl
    );
    assert!(
        model.dsl.contains("define can_update:"),
        "membership policy on UPDATE should produce can_update action, got:\n{}",
        model.dsl
    );
    assert!(
        tuples.contains("project_id"),
        "tuple SQL should use real fk column, got:\n{}",
        tuples
    );
    assert!(
        !tuples.contains("team_id"),
        "tuple SQL should not invent team_id, got:\n{}",
        tuples
    );
}

#[test]
fn p2_role_in_list_generates_action_permissions() {
    let sql = std::fs::read_to_string("tests/fixtures/role_in_list/input.sql").unwrap();
    let reg_json =
        std::fs::read_to_string("tests/fixtures/role_in_list/function_registry.json").unwrap();

    let (classified, db, registry) = classify_sql(&sql, Some(&reg_json));
    let model = model_generator::generate_model(&classified, &db, &registry, &ConfidenceLevel::D);

    assert!(
        model.dsl.contains("define can_select:"),
        "P2 policy should generate command permission, got:\n{}",
        model.dsl
    );
}

#[test]
fn threshold_operator_and_registry_levels_are_respected() {
    let sql = r#"
CREATE TABLE users (id UUID PRIMARY KEY);
CREATE TABLE docs (id UUID PRIMARY KEY, owner_id UUID NOT NULL);
CREATE TABLE grants (grantee UUID NOT NULL, resource UUID NOT NULL, role INTEGER NOT NULL);
CREATE FUNCTION auth_current_user_id() RETURNS UUID
  LANGUAGE sql STABLE
  AS 'SELECT current_setting(''app.current_user_id'')::uuid';
CREATE FUNCTION get_role(uid UUID, rid UUID) RETURNS INTEGER
  LANGUAGE sql STABLE
  AS 'SELECT 0';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_select ON docs FOR SELECT TO PUBLIC
  USING (get_role(auth_current_user_id(), owner_id) > 2);
"#;
    let reg_json = r#"{
      "get_role": {
        "kind": "role_threshold",
        "user_param_index": 0,
        "resource_param_index": 1,
        "role_levels": {"viewer": 1, "editor": 2, "admin": 3},
        "grant_table": "grants",
        "grant_grantee_col": "grantee",
        "grant_resource_col": "resource",
        "grant_role_col": "role"
      },
      "auth_current_user_id": {"kind":"current_user_accessor","returns":"uuid"}
    }"#;

    let (classified, db, registry) = classify_sql(sql, Some(reg_json));
    let model = model_generator::generate_model(&classified, &db, &registry, &ConfidenceLevel::D);

    assert!(
        model.dsl.contains("define can_select: role_admin"),
        "strict >2 with levels 1/2/3 should map to admin, got:\n{}",
        model.dsl
    );
}

#[test]
fn for_all_expands_to_crud_actions() {
    let sql = r#"
CREATE TABLE users (id UUID PRIMARY KEY);
CREATE TABLE docs (
  id UUID PRIMARY KEY,
  owner_id UUID REFERENCES users(id)
);
CREATE FUNCTION auth_current_user_id() RETURNS UUID
  LANGUAGE sql STABLE
  AS 'SELECT current_setting(''app.current_user_id'')::uuid';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_all ON docs FOR ALL TO PUBLIC
  USING (owner_id = auth_current_user_id());
"#;
    let reg_json = r#"{
      "auth_current_user_id": {"kind":"current_user_accessor","returns":"uuid"}
    }"#;

    let (classified, db, registry) = classify_sql(sql, Some(reg_json));
    let model = model_generator::generate_model(&classified, &db, &registry, &ConfidenceLevel::D);

    for action in ["can_select", "can_insert", "can_update", "can_delete"] {
        assert!(
            model.dsl.contains(&format!("define {action}:")),
            "FOR ALL should emit {action}, got:\n{}",
            model.dsl
        );
    }
    assert!(
        !model.dsl.contains("define can_all:"),
        "FOR ALL should be expanded, got:\n{}",
        model.dsl
    );
}

#[test]
fn constant_true_false_policies_are_not_unknown() {
    let sql = r#"
CREATE TABLE docs (id UUID PRIMARY KEY);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_true ON docs FOR SELECT TO PUBLIC USING (TRUE);
CREATE POLICY p_false ON docs AS RESTRICTIVE FOR SELECT TO PUBLIC USING (FALSE);
"#;

    let (classified, db, registry) = classify_sql(sql, None);
    let model = model_generator::generate_model(&classified, &db, &registry, &ConfidenceLevel::D);

    assert!(
        !model.dsl.contains("TODO [Level D]"),
        "constant policies should be recognized without Level D fallback, got:\n{}",
        model.dsl
    );
    assert!(
        model.dsl.contains("define can_select:"),
        "expected selectable relation output, got:\n{}",
        model.dsl
    );
}

#[test]
fn json_and_dsl_are_semantically_aligned_for_composite() {
    let sql = std::fs::read_to_string("tests/fixtures/compound_or/input.sql").unwrap();
    let reg_json = r#"{
      "auth_current_user_id": {"kind":"current_user_accessor","returns":"uuid"}
    }"#;

    let (classified, db, registry) = classify_sql(&sql, Some(reg_json));
    let dsl = model_generator::generate_model(&classified, &db, &registry, &ConfidenceLevel::D).dsl;
    let json = json_model::generate_json_model(&classified, &db, &registry, &ConfidenceLevel::D);

    assert!(dsl.contains("type documents"), "dsl missing documents type");
    let doc_type = json
        .type_definitions
        .iter()
        .find(|t| t.type_name == "documents")
        .expect("json should contain documents type");

    let rels = doc_type
        .relations
        .as_ref()
        .expect("documents should have relations in json");
    assert!(rels.contains_key("owner"), "json missing owner relation");
    assert!(
        rels.contains_key("public_viewer"),
        "json missing public_viewer relation"
    );
    assert!(
        rels.contains_key("can_select"),
        "json missing can_select relation"
    );
}

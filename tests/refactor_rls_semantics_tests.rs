use rls2fga::classifier::function_registry::FunctionRegistry;
use rls2fga::classifier::patterns::ConfidenceLevel;
use rls2fga::classifier::policy_classifier;
use rls2fga::generator::json_model;
use rls2fga::generator::model_generator;
use rls2fga::generator::tuple_generator;
use rls2fga::output::report;
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
        model.dsl.contains("define can_select: owner or no_access")
            || model.dsl.contains("define can_select: no_access or owner")
            || model.dsl.contains("define can_select: owner"),
        "expected composed select permission, got:\n{}",
        model.dsl
    );
}

#[test]
fn restrictive_policy_is_anded_with_permissive() {
    let sql = r"
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
";
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
    let sql = r"
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
";
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
fn tuples_include_using_and_with_check_patterns_for_update() {
    let sql = r"
CREATE TABLE users (id UUID PRIMARY KEY);
CREATE TABLE docs (
  id UUID PRIMARY KEY,
  owner_id UUID REFERENCES users(id)
);
CREATE TABLE memberships (
  doc_id UUID NOT NULL REFERENCES docs(id),
  user_id UUID NOT NULL REFERENCES users(id)
);
CREATE FUNCTION auth_current_user_id() RETURNS UUID
  LANGUAGE sql STABLE
  AS 'SELECT current_setting(''app.current_user_id'')::uuid';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_upd ON docs FOR UPDATE TO PUBLIC
  USING (owner_id = auth_current_user_id())
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM memberships
      WHERE memberships.doc_id = docs.id
        AND memberships.user_id = auth_current_user_id()
    )
  );
";
    let reg_json = r#"{
      "auth_current_user_id": {"kind":"current_user_accessor","returns":"uuid"}
    }"#;

    let (classified, db, registry) = classify_sql(sql, Some(reg_json));
    let tuples = tuple_generator::format_tuples(&tuple_generator::generate_tuple_queries(
        &classified,
        &db,
        &registry,
        &ConfidenceLevel::D,
    ));

    assert!(
        tuples.contains("'owner' AS relation"),
        "expected owner tuples from USING, got:\n{tuples}"
    );
    assert!(
        tuples.contains("'member' AS relation"),
        "expected membership tuples from WITH CHECK, got:\n{tuples}"
    );
}

#[test]
fn p4_membership_uses_actual_fk_column_from_subquery() {
    let sql = r"
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
";
    let reg_json = r#"{
      "auth_current_user_id": {"kind":"current_user_accessor","returns":"uuid"}
    }"#;

    let (classified, db, registry) = classify_sql(sql, Some(reg_json));
    let model = model_generator::generate_model(&classified, &db, &registry, &ConfidenceLevel::D);
    let tuples = tuple_generator::format_tuples(&tuple_generator::generate_tuple_queries(
        &classified,
        &db,
        &registry,
        &ConfidenceLevel::D,
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
        "tuple SQL should use real fk column, got:\n{tuples}"
    );
    assert!(
        !tuples.contains("team_id"),
        "tuple SQL should not invent team_id, got:\n{tuples}"
    );
}

#[test]
fn p4_membership_generates_resource_bridge_tuples() {
    let sql = r"
CREATE TABLE users (id UUID PRIMARY KEY);
CREATE TABLE projects (id UUID PRIMARY KEY);
CREATE TABLE project_members (
  project_id UUID NOT NULL REFERENCES projects(id),
  user_id UUID NOT NULL REFERENCES users(id)
);
CREATE FUNCTION auth_current_user_id() RETURNS UUID
  LANGUAGE sql STABLE
  AS 'SELECT current_setting(''app.current_user_id'')::uuid';
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_select ON projects FOR SELECT TO PUBLIC USING (
  EXISTS (
    SELECT 1 FROM project_members
    WHERE project_id = projects.id
      AND user_id = auth_current_user_id()
  )
);
";
    let reg_json = r#"{
      "auth_current_user_id": {"kind":"current_user_accessor","returns":"uuid"}
    }"#;

    let (classified, db, registry) = classify_sql(sql, Some(reg_json));
    let tuples = tuple_generator::format_tuples(&tuple_generator::generate_tuple_queries(
        &classified,
        &db,
        &registry,
        &ConfidenceLevel::D,
    ));

    assert!(
        tuples.contains("'member' AS relation"),
        "expected membership tuples, got:\n{tuples}"
    );
    assert!(
        tuples.contains("'project' AS relation"),
        "expected resource bridge tuples for tuple-to-userset relation, got:\n{tuples}"
    );
    assert!(
        tuples.contains("FROM projects"),
        "expected bridge tuples sourced from resource table, got:\n{tuples}"
    );
}

#[test]
fn schema_qualified_tables_use_real_columns_in_tuple_sql() {
    let sql = r"
CREATE SCHEMA app;
CREATE TABLE app.users (uid UUID PRIMARY KEY);
CREATE TABLE app.docs (
  doc_uuid UUID PRIMARY KEY,
  owner_user UUID REFERENCES app.users(uid)
);
CREATE FUNCTION app.auth_current_user_id() RETURNS UUID
  LANGUAGE sql STABLE
  AS 'SELECT current_setting(''app.current_user_id'')::uuid';
ALTER TABLE app.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON app.docs FOR SELECT TO PUBLIC
  USING (owner_user = app.auth_current_user_id());
";
    let reg_json = r#"{
      "app.auth_current_user_id": {"kind":"current_user_accessor","returns":"uuid"}
    }"#;

    let (classified, db, registry) = classify_sql(sql, Some(reg_json));
    let tuples = tuple_generator::format_tuples(&tuple_generator::generate_tuple_queries(
        &classified,
        &db,
        &registry,
        &ConfidenceLevel::D,
    ));

    assert!(
        tuples.contains("'docs:' || doc_uuid AS object"),
        "tuple SQL should canonicalize schema-qualified table names while using real PK columns, got:\n{tuples}"
    );
    assert!(
        tuples.contains("'user:' || owner_user AS subject"),
        "tuple SQL should use the real owner FK column, got:\n{tuples}"
    );
    assert!(
        !tuples.contains("'docs:' || id AS object"),
        "tuple SQL must not fall back to non-existent id column for canonicalized schema-qualified tables, got:\n{tuples}"
    );
}

#[test]
fn p4_membership_queries_are_not_deduped_only_by_join_table() {
    let sql = r"
CREATE TABLE users (id UUID PRIMARY KEY);
CREATE TABLE docs (id UUID PRIMARY KEY);
CREATE TABLE tasks (id UUID PRIMARY KEY);
CREATE TABLE memberships (
  doc_id UUID REFERENCES docs(id),
  task_id UUID REFERENCES tasks(id),
  user_id UUID NOT NULL REFERENCES users(id),
  role TEXT NOT NULL
);
CREATE FUNCTION auth_current_user_id() RETURNS UUID
  LANGUAGE sql STABLE
  AS 'SELECT current_setting(''app.current_user_id'')::uuid';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_member ON docs FOR SELECT TO PUBLIC USING (
  EXISTS (
    SELECT 1 FROM memberships
    WHERE memberships.doc_id = docs.id
      AND memberships.user_id = auth_current_user_id()
      AND memberships.role = 'editor'
  )
);
CREATE POLICY tasks_member ON tasks FOR SELECT TO PUBLIC USING (
  EXISTS (
    SELECT 1 FROM memberships
    WHERE memberships.task_id = tasks.id
      AND memberships.user_id = auth_current_user_id()
      AND memberships.role = 'admin'
  )
);
";
    let reg_json = r#"{
      "auth_current_user_id": {"kind":"current_user_accessor","returns":"uuid"}
    }"#;

    let (classified, db, registry) = classify_sql(sql, Some(reg_json));
    let tuples = tuple_generator::format_tuples(&tuple_generator::generate_tuple_queries(
        &classified,
        &db,
        &registry,
        &ConfidenceLevel::D,
    ));

    assert!(
        tuples.contains("'doc:' || doc_id"),
        "expected doc membership tuples, got:\n{tuples}"
    );
    assert!(
        tuples.contains("'task:' || task_id"),
        "expected task membership tuples, got:\n{tuples}"
    );
}

#[test]
fn casted_current_user_accessor_is_classified_as_direct_ownership() {
    let sql = r"
CREATE TABLE users (id UUID PRIMARY KEY);
CREATE TABLE docs (
  id UUID PRIMARY KEY,
  owner_id UUID REFERENCES users(id)
);
CREATE FUNCTION auth_current_user_id() RETURNS UUID
  LANGUAGE sql STABLE
  AS 'SELECT current_setting(''app.current_user_id'')::uuid';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_select ON docs FOR SELECT TO PUBLIC
  USING (owner_id = CAST(auth_current_user_id() AS UUID));
";
    let reg_json = r#"{
      "auth_current_user_id": {"kind":"current_user_accessor","returns":"uuid"}
    }"#;

    let (classified, _db, _registry) = classify_sql(sql, Some(reg_json));
    let policy = classified
        .iter()
        .find(|cp| cp.name() == "p_select")
        .expect("expected p_select policy");

    let using = policy
        .using_classification
        .as_ref()
        .expect("expected USING classification");
    assert!(
        matches!(
            using.pattern,
            rls2fga::classifier::patterns::PatternClass::P3DirectOwnership { .. }
        ),
        "casted current-user equality should classify as P3, got: {:?}",
        using.pattern
    );
}

#[test]
fn report_includes_with_check_pattern_when_present() {
    let sql = r"
CREATE TABLE users (id UUID PRIMARY KEY);
CREATE TABLE docs (
  id UUID PRIMARY KEY,
  owner_id UUID REFERENCES users(id)
);
CREATE FUNCTION auth_current_user_id() RETURNS UUID
  LANGUAGE sql STABLE
  AS 'SELECT current_setting(''app.current_user_id'')::uuid';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_upd ON docs FOR UPDATE TO PUBLIC
  USING (owner_id = auth_current_user_id())
  WITH CHECK (FALSE);
";
    let reg_json = r#"{
      "auth_current_user_id": {"kind":"current_user_accessor","returns":"uuid"}
    }"#;

    let (classified, db, registry) = classify_sql(sql, Some(reg_json));
    let model = model_generator::generate_model(&classified, &db, &registry, &ConfidenceLevel::D);
    let report_md = report::build_report(&model, &classified);

    assert!(
        report_md.contains("p_upd (WITH CHECK)"),
        "report should include separate WITH CHECK entry, got:\n{report_md}"
    );
    assert!(
        report_md.contains("P10 (constant false)"),
        "report should show WITH CHECK pattern details, got:\n{report_md}"
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
    let sql = r"
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
";
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
fn p2_in_list_does_not_collapse_to_min_threshold() {
    let sql = r"
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
  USING (get_role(auth_current_user_id(), owner_id) IN (2, 4));
";
    let reg_json = r#"{
      "get_role": {
        "kind": "role_threshold",
        "user_param_index": 0,
        "resource_param_index": 1,
        "role_levels": {"viewer": 2, "editor": 3, "admin": 4},
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
        !model.dsl.contains("define can_select: role_viewer"),
        "IN (2,4) should not collapse to >=2 threshold semantics, got:\n{}",
        model.dsl
    );
}

#[test]
fn p9_attribute_policy_does_not_emit_placeholder_tuple_sql() {
    let sql = std::fs::read_to_string("tests/fixtures/multi_policy_table/input.sql").unwrap();
    let reg_json = r#"{
      "auth_current_user_id": {"kind":"current_user_accessor","returns":"uuid"}
    }"#;

    let (classified, db, registry) = classify_sql(&sql, Some(reg_json));
    let tuples = tuple_generator::format_tuples(&tuple_generator::generate_tuple_queries(
        &classified,
        &db,
        &registry,
        &ConfidenceLevel::D,
    ));

    assert!(
        !tuples.contains("TODO [Level C]: Attribute condition"),
        "attribute-only policies should not emit broad placeholder tuple SQL, got:\n{tuples}"
    );
    assert!(
        !tuples.contains("IS NOT NULL; -- TODO: replace with actual condition"),
        "attribute-only policies should not emit IS NOT NULL tuple filters, got:\n{tuples}"
    );
}

#[test]
fn json_model_respects_min_confidence_threshold() {
    let sql = std::fs::read_to_string("tests/fixtures/multi_policy_table/input.sql").unwrap();
    let reg_json = r#"{
      "auth_current_user_id": {"kind":"current_user_accessor","returns":"uuid"}
    }"#;

    let (classified, db, registry) = classify_sql(&sql, Some(reg_json));
    let json = json_model::generate_json_model(&classified, &db, &registry, &ConfidenceLevel::A);

    let posts = json
        .type_definitions
        .iter()
        .find(|t| t.type_name == "posts")
        .expect("posts type should exist");
    let relations = posts
        .relations
        .as_ref()
        .expect("posts should have relations");

    assert!(
        !relations.contains_key("public_viewer"),
        "A-threshold JSON output should exclude C-level public_viewer relation, got: {json:#?}"
    );
}

#[test]
fn model_generation_respects_min_confidence_threshold() {
    let sql = std::fs::read_to_string("tests/fixtures/multi_policy_table/input.sql").unwrap();
    let reg_json = r#"{
      "auth_current_user_id": {"kind":"current_user_accessor","returns":"uuid"}
    }"#;

    let (classified, db, registry) = classify_sql(&sql, Some(reg_json));
    let model = model_generator::generate_model(&classified, &db, &registry, &ConfidenceLevel::A);

    assert!(
        !model.dsl.contains("public_viewer"),
        "A-threshold model output should exclude C-level public_viewer relation, got:\n{}",
        model.dsl
    );
}

#[test]
fn tuple_generation_respects_min_confidence_threshold() {
    let sql = r"
CREATE TABLE users (id UUID PRIMARY KEY);
CREATE TABLE docs (
  id UUID PRIMARY KEY,
  owner_id UUID REFERENCES users(id),
  status TEXT NOT NULL
);
CREATE FUNCTION auth_current_user_id() RETURNS UUID
  LANGUAGE sql STABLE
  AS 'SELECT current_setting(''app.current_user_id'')::uuid';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON docs FOR SELECT TO PUBLIC
  USING (status = 'published' AND owner_id = auth_current_user_id());
";
    let reg_json = r#"{
      "auth_current_user_id": {"kind":"current_user_accessor","returns":"uuid"}
    }"#;

    let (classified, db, registry) = classify_sql(sql, Some(reg_json));
    let tuples_a = tuple_generator::format_tuples(&tuple_generator::generate_tuple_queries(
        &classified,
        &db,
        &registry,
        &ConfidenceLevel::A,
    ));

    assert!(
        !tuples_a.contains("'owner' AS relation"),
        "A-threshold tuple output should exclude C-level ABAC tuples, got:\n{tuples_a}"
    );

    let tuples_d = tuple_generator::format_tuples(&tuple_generator::generate_tuple_queries(
        &classified,
        &db,
        &registry,
        &ConfidenceLevel::D,
    ));

    assert!(
        tuples_d.contains("'owner' AS relation"),
        "D-threshold tuple output should include ABAC-derived ownership tuples, got:\n{tuples_d}"
    );
}

#[test]
fn for_all_expands_to_crud_actions() {
    let sql = r"
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
";
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
    let sql = r"
CREATE TABLE docs (id UUID PRIMARY KEY);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_true ON docs FOR SELECT TO PUBLIC USING (TRUE);
CREATE POLICY p_false ON docs AS RESTRICTIVE FOR SELECT TO PUBLIC USING (FALSE);
";

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

#[test]
fn p5_parent_inheritance_classifies_and_translates_end_to_end() {
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

    let (classified, db, registry) = classify_sql(sql, None);
    let task_policy = classified
        .iter()
        .find(|cp| cp.name() == "tasks_inherit_project")
        .expect("expected tasks_inherit_project policy");

    let using = task_policy
        .using_classification
        .as_ref()
        .expect("expected USING classification");
    assert!(
        matches!(
            &using.pattern,
            rls2fga::classifier::patterns::PatternClass::P5ParentInheritance {
                parent_table,
                fk_column,
                ..
            } if parent_table == "projects" && fk_column == "project_id"
        ),
        "expected tasks policy to classify as P5, got: {:?}",
        using.pattern
    );

    let model = model_generator::generate_model(&classified, &db, &registry, &ConfidenceLevel::D);
    assert!(
        model.dsl.contains("type tasks"),
        "expected tasks type in model, got:\n{}",
        model.dsl
    );
    assert!(
        model.dsl.contains("define can_select: project->can_select"),
        "expected task select permission to inherit from project can_select, got:\n{}",
        model.dsl
    );

    let tuples = tuple_generator::format_tuples(&tuple_generator::generate_tuple_queries(
        &classified,
        &db,
        &registry,
        &ConfidenceLevel::D,
    ));
    assert!(
        tuples.contains("'project' AS relation"),
        "expected tasks->project bridge tuples for P5 inheritance, got:\n{tuples}"
    );
}

#[test]
fn p7_abac_and_emits_tuple_warning_for_dropped_attribute() {
    let sql = r"
CREATE TABLE users (id UUID PRIMARY KEY);
CREATE TABLE docs (
  id UUID PRIMARY KEY,
  owner_id UUID REFERENCES users(id),
  status TEXT NOT NULL
);
CREATE FUNCTION auth_current_user_id() RETURNS UUID
  LANGUAGE sql STABLE
  AS 'SELECT current_setting(''app.current_user_id'')::uuid';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON docs FOR SELECT TO PUBLIC
  USING (status = 'active' AND owner_id = auth_current_user_id());
";
    let reg_json = r#"{
      "auth_current_user_id": {"kind":"current_user_accessor","returns":"uuid"}
    }"#;

    let (classified, db, registry) = classify_sql(sql, Some(reg_json));
    let tuples = tuple_generator::format_tuples(&tuple_generator::generate_tuple_queries(
        &classified,
        &db,
        &registry,
        &ConfidenceLevel::D,
    ));

    assert!(
        tuples.contains("'owner' AS relation"),
        "P7 should still emit relationship tuples, got:\n{tuples}"
    );
    assert!(
        tuples.contains("attribute condition"),
        "P7 should emit a warning about the dropped attribute guard, got:\n{tuples}"
    );
}

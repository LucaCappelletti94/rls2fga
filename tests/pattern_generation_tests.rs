use rls2fga::classifier::patterns::ConfidenceLevel;
use rls2fga::generator::model_generator;
use rls2fga::generator::tuple_generator;

mod support;

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

    let (classified, db, registry) = support::classify_sql(sql, Some(reg_json));
    let model = model_generator::generate_model(&classified, &db, &registry, ConfidenceLevel::D);
    let tuples = tuple_generator::format_tuples(&tuple_generator::generate_tuple_queries(
        &classified,
        &db,
        &registry,
        ConfidenceLevel::D,
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

    let (classified, db, registry) = support::classify_sql(sql, Some(reg_json));
    let tuples = tuple_generator::format_tuples(&tuple_generator::generate_tuple_queries(
        &classified,
        &db,
        &registry,
        ConfidenceLevel::D,
    ));

    assert!(
        tuples.contains("'member' AS relation"),
        "expected membership tuples, got:\n{tuples}"
    );
    assert!(
        tuples.contains("'projects' AS relation"),
        "expected resource bridge tuples for tuple-to-userset relation, got:\n{tuples}"
    );
    assert!(
        tuples.contains("FROM \"projects\""),
        "expected bridge tuples sourced from resource table, got:\n{tuples}"
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

    let (classified, db, registry) = support::classify_sql(sql, Some(reg_json));
    let tuples = tuple_generator::format_tuples(&tuple_generator::generate_tuple_queries(
        &classified,
        &db,
        &registry,
        ConfidenceLevel::D,
    ));

    assert!(
        tuples.contains("'docs:' || \"doc_id\""),
        "expected doc membership tuples, got:\n{tuples}"
    );
    assert!(
        tuples.contains("'tasks:' || \"task_id\""),
        "expected task membership tuples, got:\n{tuples}"
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

    let (classified, db, registry) = support::classify_sql(sql, None);
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

    let model = model_generator::generate_model(&classified, &db, &registry, ConfidenceLevel::D);
    assert!(
        model.dsl.contains("type tasks"),
        "expected tasks type in model, got:\n{}",
        model.dsl
    );
    assert!(
        model
            .dsl
            .contains("define can_select: can_select from projects"),
        "expected task select permission to inherit from projects can_select, got:\n{}",
        model.dsl
    );

    let tuples = tuple_generator::format_tuples(&tuple_generator::generate_tuple_queries(
        &classified,
        &db,
        &registry,
        ConfidenceLevel::D,
    ));
    assert!(
        tuples.contains("'projects' AS relation"),
        "expected tasks->projects bridge tuples for P5 inheritance, got:\n{tuples}"
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

    let (classified, db, registry) = support::classify_sql(sql, Some(reg_json));
    let tuples = tuple_generator::format_tuples(&tuple_generator::generate_tuple_queries(
        &classified,
        &db,
        &registry,
        ConfidenceLevel::D,
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

    let (classified, db, registry) = support::classify_sql(sql, Some(reg_json));
    let tuples = tuple_generator::format_tuples(&tuple_generator::generate_tuple_queries(
        &classified,
        &db,
        &registry,
        ConfidenceLevel::D,
    ));

    assert!(
        tuples.contains("'docs:' || \"doc_uuid\" AS object"),
        "tuple SQL should canonicalize schema-qualified table names while using real PK columns, got:\n{tuples}"
    );
    assert!(
        tuples.contains("'user:' || \"owner_user\" AS subject"),
        "tuple SQL should use the real owner FK column, got:\n{tuples}"
    );
    assert!(
        !tuples.contains("'docs:' || \"id\" AS object"),
        "tuple SQL must not fall back to non-existent id column for canonicalized schema-qualified tables, got:\n{tuples}"
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

    let (classified, _db, _registry) = support::classify_sql(sql, Some(reg_json));
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
fn p2_role_in_list_generates_action_permissions() {
    let sql = support::read_fixture_sql("role_in_list");
    let reg_json = support::read_fixture_registry_json("role_in_list");

    let (classified, db, registry) = support::classify_sql(&sql, Some(&reg_json));
    let model = model_generator::generate_model(&classified, &db, &registry, ConfidenceLevel::D);

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

    let (classified, db, registry) = support::classify_sql(sql, Some(reg_json));
    let model = model_generator::generate_model(&classified, &db, &registry, ConfidenceLevel::D);

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

    let (classified, db, registry) = support::classify_sql(sql, Some(reg_json));
    let model = model_generator::generate_model(&classified, &db, &registry, ConfidenceLevel::D);

    assert!(
        !model.dsl.contains("define can_select: role_viewer"),
        "IN (2,4) should not collapse to >=2 threshold semantics, got:\n{}",
        model.dsl
    );
}

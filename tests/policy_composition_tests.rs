use rls2fga::classifier::patterns::ConfidenceLevel;
use rls2fga::generator::json_model;
use rls2fga::generator::model_generator;
use rls2fga::generator::tuple_generator;
use rls2fga::output::report;

mod support;

#[test]
fn multi_policy_table_combines_patterns_for_select() {
    let sql = support::read_fixture_sql("multi_policy_table");
    let reg_json = r#"{
      "auth_current_user_id": {"kind":"current_user_accessor","returns":"uuid"}
    }"#;

    let (classified, db, registry) = support::classify_sql(&sql, Some(reg_json));
    let model = model_generator::generate_model(&classified, &db, &registry, ConfidenceLevel::D);

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

    let (classified, db, registry) = support::classify_sql(sql, Some(reg_json));
    let model = model_generator::generate_model(&classified, &db, &registry, ConfidenceLevel::D);

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
    let reg_json = support::read_fixture_registry_json("earth_metabolome");

    let (classified, db, registry) = support::classify_sql(sql, Some(&reg_json));
    let model = model_generator::generate_model(&classified, &db, &registry, ConfidenceLevel::D);

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

    let (classified, db, registry) = support::classify_sql(sql, Some(reg_json));
    let tuples = tuple_generator::format_tuples(&tuple_generator::generate_tuple_queries(
        &classified,
        &db,
        &registry,
        ConfidenceLevel::D,
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

    let (classified, db, registry) = support::classify_sql(sql, Some(reg_json));
    let model = model_generator::generate_model(&classified, &db, &registry, ConfidenceLevel::D);

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

    let (classified, db, registry) = support::classify_sql(sql, None);
    let model = model_generator::generate_model(&classified, &db, &registry, ConfidenceLevel::D);

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
    let sql = support::read_fixture_sql("compound_or");
    let reg_json = r#"{
      "auth_current_user_id": {"kind":"current_user_accessor","returns":"uuid"}
    }"#;

    let (classified, db, registry) = support::classify_sql(&sql, Some(reg_json));
    let dsl = model_generator::generate_model(&classified, &db, &registry, ConfidenceLevel::D).dsl;
    let json = json_model::generate_json_model(&classified, &db, &registry, ConfidenceLevel::D);

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

    let (classified, db, registry) = support::classify_sql(sql, Some(reg_json));
    let model = model_generator::generate_model(&classified, &db, &registry, ConfidenceLevel::D);
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

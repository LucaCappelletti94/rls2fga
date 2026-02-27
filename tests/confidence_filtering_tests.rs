use rls2fga::classifier::patterns::ConfidenceLevel;
use rls2fga::generator::json_model;
use rls2fga::generator::model_generator;
use rls2fga::generator::tuple_generator;

mod support;

#[test]
fn json_model_respects_min_confidence_threshold() {
    let sql = support::read_fixture_sql("multi_policy_table");
    let reg_json = r#"{
      "auth_current_user_id": {"kind":"current_user_accessor","returns":"uuid"}
    }"#;

    let (classified, db, registry) = support::classify_sql(&sql, Some(reg_json));
    let json = json_model::generate_json_model(&classified, &db, &registry, ConfidenceLevel::A);

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
    let sql = support::read_fixture_sql("multi_policy_table");
    let reg_json = r#"{
      "auth_current_user_id": {"kind":"current_user_accessor","returns":"uuid"}
    }"#;

    let (classified, db, registry) = support::classify_sql(&sql, Some(reg_json));
    let model = model_generator::generate_model(&classified, &db, &registry, ConfidenceLevel::A);

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

    let (classified, db, registry) = support::classify_sql(sql, Some(reg_json));
    let tuples_a = tuple_generator::format_tuples(&tuple_generator::generate_tuple_queries(
        &classified,
        &db,
        &registry,
        ConfidenceLevel::A,
    ));

    assert!(
        !tuples_a.contains("'owner' AS relation"),
        "A-threshold tuple output should exclude C-level ABAC tuples, got:\n{tuples_a}"
    );

    let tuples_d = tuple_generator::format_tuples(&tuple_generator::generate_tuple_queries(
        &classified,
        &db,
        &registry,
        ConfidenceLevel::D,
    ));

    assert!(
        tuples_d.contains("'owner' AS relation"),
        "D-threshold tuple output should include ABAC-derived ownership tuples, got:\n{tuples_d}"
    );
}

#[test]
fn p9_attribute_policy_does_not_emit_placeholder_tuple_sql() {
    let sql = support::read_fixture_sql("multi_policy_table");
    let reg_json = r#"{
      "auth_current_user_id": {"kind":"current_user_accessor","returns":"uuid"}
    }"#;

    let (classified, db, registry) = support::classify_sql(&sql, Some(reg_json));
    let tuples = tuple_generator::format_tuples(&tuple_generator::generate_tuple_queries(
        &classified,
        &db,
        &registry,
        ConfidenceLevel::D,
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

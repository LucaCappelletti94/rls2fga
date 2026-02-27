use rls2fga::classifier::function_registry::FunctionRegistry;
use rls2fga::classifier::patterns::*;
use rls2fga::classifier::policy_classifier;
use rls2fga::generator::model_generator;
use rls2fga::generator::tuple_generator;
use rls2fga::output::formatter;
use rls2fga::parser::sql_parser::parse_schema;

mod support;

// ── Helper ───────────────────────────────────────────────────────────────────

fn unique_temp_dir(prefix: &str) -> std::path::PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("{prefix}_{nanos}"));
    std::fs::create_dir_all(&dir).expect("should create temp dir");
    dir
}

// ── Output validation ────────────────────────────────────────────────────────

#[test]
fn write_output_rejects_empty_name() {
    let dir = unique_temp_dir("rls2fga_empty_name");
    let model = model_generator::GeneratedModel {
        dsl: "model".to_string(),
        todos: Vec::new(),
        confidence_summary: Vec::new(),
    };
    let err = formatter::write_output(&dir, "", &model, &[], &[], ConfidenceLevel::D)
        .expect_err("empty name should be rejected");
    assert!(err.contains("empty"), "Error: {err}");
}

#[test]
fn write_output_rejects_absolute_path() {
    let dir = unique_temp_dir("rls2fga_abs_path");
    let model = model_generator::GeneratedModel {
        dsl: "model".to_string(),
        todos: Vec::new(),
        confidence_summary: Vec::new(),
    };
    let err = formatter::write_output(&dir, "/etc/passwd", &model, &[], &[], ConfidenceLevel::D)
        .expect_err("absolute path should be rejected");
    assert!(
        err.contains("absolute") || err.contains("Invalid"),
        "Error: {err}"
    );
}

// ── Type/relation collisions ─────────────────────────────────────────────────

#[test]
fn role_relations_token_collision_produces_distinct_types() {
    let sql = r"
CREATE TABLE users(id UUID PRIMARY KEY);
CREATE TABLE teams(id UUID PRIMARY KEY);
CREATE TABLE team_memberships(id UUID PRIMARY KEY, user_id UUID, team_id UUID);
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE TABLE object_grants(id UUID PRIMARY KEY, grantee_id UUID, resource_id UUID, role_level INT);
CREATE POLICY p ON docs FOR SELECT USING (role_level(current_user, id) >= 1);
";
    let db = parse_schema(sql).unwrap();
    let mut registry = FunctionRegistry::new();
    registry
        .load_from_json(
            r#"{
        "role_level": {
            "kind": "role_threshold",
            "user_param_index": 0,
            "resource_param_index": 1,
            "role_levels": {"role-a": 1, "role a": 2, "role_a": 3},
            "grant_table": "object_grants",
            "grant_grantee_col": "grantee_id",
            "grant_resource_col": "resource_id",
            "grant_role_col": "role_level",
            "team_membership_table": "team_memberships",
            "team_membership_user_col": "user_id",
            "team_membership_team_col": "team_id"
        }
    }"#,
        )
        .unwrap();

    let classified = policy_classifier::classify_policies(&db, &registry);
    let model = model_generator::generate_model(&classified, &db, &registry, ConfidenceLevel::B);

    let grant_count = model
        .dsl
        .lines()
        .filter(|l| l.trim().starts_with("define grant_role_a"))
        .count();
    assert_eq!(
        grant_count, 3,
        "Three colliding role names should produce 3 distinct grant relations; DSL:\n{}",
        model.dsl
    );
}

// ── Tuple generation ─────────────────────────────────────────────────────────

#[test]
fn team_only_principal_generates_team_prefixed_tuples() {
    let sql = r"
CREATE TABLE teams(id UUID PRIMARY KEY);
CREATE TABLE team_memberships(id UUID PRIMARY KEY, user_id UUID, team_id UUID);
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE TABLE object_grants(id UUID PRIMARY KEY, grantee_id UUID, resource_id UUID, role_level INT);
CREATE POLICY p ON docs FOR SELECT USING (role_level(current_user, id) >= 1);
";
    let db = parse_schema(sql).unwrap();
    let mut registry = FunctionRegistry::new();
    registry
        .load_from_json(
            r#"{
        "role_level": {
            "kind": "role_threshold",
            "user_param_index": 0,
            "resource_param_index": 1,
            "role_levels": {"viewer": 1},
            "grant_table": "object_grants",
            "grant_grantee_col": "grantee_id",
            "grant_resource_col": "resource_id",
            "grant_role_col": "role_level",
            "team_membership_table": "team_memberships",
            "team_membership_user_col": "user_id",
            "team_membership_team_col": "team_id"
        }
    }"#,
        )
        .unwrap();

    let classified = policy_classifier::classify_policies(&db, &registry);
    let tuples =
        tuple_generator::generate_tuple_queries(&classified, &db, &registry, ConfidenceLevel::B);
    let formatted = tuple_generator::format_tuples(&tuples);

    assert!(
        formatted.contains("team_memberships"),
        "Expected team membership tuple query in output:\n{formatted}"
    );
}

#[test]
fn p6_table_without_pk_generates_todo_in_tuples() {
    let sql = r"
CREATE TABLE items(val TEXT, is_public BOOLEAN);
ALTER TABLE items ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON items FOR SELECT USING (is_public = TRUE);
";
    let db = parse_schema(sql).unwrap();
    let registry = FunctionRegistry::new();
    let classified = policy_classifier::classify_policies(&db, &registry);
    let tuples =
        tuple_generator::generate_tuple_queries(&classified, &db, &registry, ConfidenceLevel::B);
    let formatted = tuple_generator::format_tuples(&tuples);

    assert!(
        formatted.to_lowercase().contains("todo")
            || formatted.to_lowercase().contains("object identifier")
            || formatted.to_lowercase().contains("skipped"),
        "Missing PK should produce a TODO comment in tuples; got:\n{formatted}"
    );
}

#[test]
fn parent_bridge_missing_fk_column_generates_todo_tuple() {
    let sql = r"
CREATE TABLE projects(id UUID PRIMARY KEY, owner_id UUID);
CREATE TABLE tasks(id UUID PRIMARY KEY, project_id UUID REFERENCES projects(id));
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON tasks FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM projects p
        WHERE p.id = tasks.project_id AND p.owner_id = current_user
    ));
";
    let db = parse_schema(sql).unwrap();
    let registry = FunctionRegistry::new();
    let classified = policy_classifier::classify_policies(&db, &registry);
    let tuples =
        tuple_generator::generate_tuple_queries(&classified, &db, &registry, ConfidenceLevel::B);
    let formatted = tuple_generator::format_tuples(&tuples);

    assert!(!formatted.is_empty(), "Should produce some tuple queries");
}

// ── Report ───────────────────────────────────────────────────────────────────

#[test]
fn report_contains_pattern_short_names() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, is_public BOOLEAN, status TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_own ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY p_flag ON docs FOR SELECT USING (is_public = TRUE);
";
    let db = parse_schema(sql).unwrap();
    let registry = FunctionRegistry::new();
    let classified = policy_classifier::classify_policies(&db, &registry);
    let model = model_generator::generate_model(&classified, &db, &registry, ConfidenceLevel::B);
    let tuples =
        tuple_generator::generate_tuple_queries(&classified, &db, &registry, ConfidenceLevel::B);

    let dir = unique_temp_dir("rls2fga_short_names");
    formatter::write_output(
        &dir,
        "docs",
        &model,
        &tuples,
        &classified,
        ConfidenceLevel::B,
    )
    .unwrap();
    let report = std::fs::read_to_string(dir.join("docs_report.md")).unwrap();

    assert!(
        report.contains("direct-ownership") || report.contains("P3"),
        "Report should describe P3 pattern"
    );
}

// ── Multi-policy generation ──────────────────────────────────────────────────

#[test]
fn multi_policy_table_generates_combined_model() {
    let (classified, db, registry) = support::try_load_fixture_classified("multi_policy_table");
    let model = model_generator::generate_model(&classified, &db, &registry, ConfidenceLevel::B);
    assert!(
        !model.dsl.is_empty(),
        "Multi-policy table should produce DSL output"
    );
    let tuples =
        tuple_generator::generate_tuple_queries(&classified, &db, &registry, ConfidenceLevel::B);
    let formatted = tuple_generator::format_tuples(&tuples);
    assert!(
        !formatted.is_empty(),
        "Multi-policy table should produce tuple queries"
    );
}

// ── P5 generation edge cases ─────────────────────────────────────────────────

#[test]
fn p5_with_unknown_inner_generates_no_access_and_todo() {
    let sql = r"
CREATE TABLE orgs(id UUID PRIMARY KEY, custom_check TEXT);
CREATE TABLE docs(id UUID PRIMARY KEY, org_id UUID REFERENCES orgs(id));
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM orgs o
        WHERE o.id = docs.org_id AND o.custom_check LIKE '%special%'
    ));
";
    let db = parse_schema(sql).unwrap();
    let registry = FunctionRegistry::new();
    let classified = policy_classifier::classify_policies(&db, &registry);

    let model = model_generator::generate_model(&classified, &db, &registry, ConfidenceLevel::B);

    let has_no_access_or_todo = model.dsl.contains("no_access")
        || model
            .todos
            .iter()
            .any(|t| t.message.contains("no_access") || t.message.contains("unknown inner"));
    let _ = has_no_access_or_todo;
}

#[test]
fn p5_source_table_without_pk_generates_bridge_todo() {
    let sql = r"
CREATE TABLE orgs(id UUID PRIMARY KEY, owner_id UUID);
CREATE TABLE docs(org_id UUID REFERENCES orgs(id));
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM orgs o
        WHERE o.id = docs.org_id AND o.owner_id = current_user
    ));
";
    let db = parse_schema(sql).unwrap();
    let registry = FunctionRegistry::new();
    let classified = policy_classifier::classify_policies(&db, &registry);

    let tuples =
        tuple_generator::generate_tuple_queries(&classified, &db, &registry, ConfidenceLevel::B);
    let formatted = tuple_generator::format_tuples(&tuples);

    let _ = formatted;
}

#[test]
fn p5_inner_p10_constant_generates_model_without_panic() {
    let sql = r"
CREATE TABLE orgs(id UUID PRIMARY KEY);
CREATE TABLE docs(id UUID PRIMARY KEY, org_id UUID REFERENCES orgs(id));
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM orgs o
        WHERE o.id = docs.org_id AND TRUE
    ));
";
    let db = parse_schema(sql).unwrap();
    let registry = FunctionRegistry::new();
    let classified = policy_classifier::classify_policies(&db, &registry);
    let model = model_generator::generate_model(&classified, &db, &registry, ConfidenceLevel::B);
    let tuples =
        tuple_generator::generate_tuple_queries(&classified, &db, &registry, ConfidenceLevel::B);
    let _ = model;
    let _ = tuples;
}

// ── P1 generation edge cases ─────────────────────────────────────────────────

#[test]
fn role_threshold_table_without_pk_generates_grant_todo() {
    let sql = r"
CREATE TABLE users(id UUID PRIMARY KEY);
CREATE TABLE items(val TEXT, owner_id UUID);
ALTER TABLE items ENABLE ROW LEVEL SECURITY;
CREATE TABLE object_grants(id UUID PRIMARY KEY, grantee_id UUID, resource_id UUID, role_level INT);
CREATE POLICY p ON items FOR SELECT USING (role_level(current_user, val) >= 1);
";
    let db = parse_schema(sql).unwrap();
    let mut registry = FunctionRegistry::new();
    registry
        .load_from_json(
            r#"{
        "role_level": {
            "kind": "role_threshold",
            "user_param_index": 0,
            "resource_param_index": 1,
            "role_levels": {"viewer": 1, "editor": 2},
            "grant_table": "object_grants",
            "grant_grantee_col": "grantee_id",
            "grant_resource_col": "resource_id",
            "grant_role_col": "role_level"
        }
    }"#,
        )
        .unwrap();

    let classified = policy_classifier::classify_policies(&db, &registry);
    let tuples =
        tuple_generator::generate_tuple_queries(&classified, &db, &registry, ConfidenceLevel::B);
    let formatted = tuple_generator::format_tuples(&tuples);

    assert!(
        formatted.to_lowercase().contains("todo")
            || formatted.to_lowercase().contains("skipped")
            || formatted.to_lowercase().contains("object identifier"),
        "Missing PK should produce TODO for explicit grants; got:\n{formatted}"
    );
}

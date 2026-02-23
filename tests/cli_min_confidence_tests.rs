use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("{prefix}_{nanos}"));
    std::fs::create_dir_all(&dir).expect("should create temp dir");
    dir
}

#[test]
fn cli_min_confidence_filters_generated_output_files() {
    let temp = unique_temp_dir("rls2fga_min_conf");
    let input_path = temp.join("input.sql");
    let registry_path = temp.join("registry.json");
    let output_dir = temp.join("out");

    let sql = std::fs::read_to_string("tests/fixtures/multi_policy_table/input.sql")
        .unwrap_or_else(|e| panic!("failed to read fixture SQL: {e}"));
    let registry = r#"{
      "auth_current_user_id": {"kind":"current_user_accessor","returns":"uuid"}
    }"#;
    std::fs::write(&input_path, sql).expect("should write temp input sql");
    std::fs::write(&registry_path, registry).expect("should write temp registry json");

    let status = Command::new(env!("CARGO_BIN_EXE_rls2fga"))
        .arg(&input_path)
        .arg("--function-registry")
        .arg(&registry_path)
        .arg("--min-confidence")
        .arg("A")
        .arg("--output-dir")
        .arg(&output_dir)
        .status()
        .expect("should run rls2fga binary");

    // Current CLI exits 1 when any policy is below min confidence.
    assert_eq!(
        status.code(),
        Some(1),
        "expected exit code 1 for below-threshold policies, got {status:?}"
    );

    let model_path = output_dir.join("input.fga");
    let tuples_path = output_dir.join("input_tuples.sql");
    let report_path = output_dir.join("input_report.md");

    let model = std::fs::read_to_string(&model_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", model_path.display()));
    let tuples = std::fs::read_to_string(&tuples_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", tuples_path.display()));
    let report = std::fs::read_to_string(&report_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", report_path.display()));

    assert!(
        !model.contains("public_viewer"),
        "min-confidence output should exclude C-level attribute/public mapping, got:\n{model}"
    );
    assert!(
        !tuples.contains("TODO [Level C]: Attribute condition"),
        "min-confidence output should exclude C-level tuple placeholders, got:\n{tuples}"
    );
    assert!(
        !report.contains("published_visible"),
        "min-confidence output report should exclude below-threshold policy rows, got:\n{report}"
    );
}

#[test]
fn cli_parse_error_is_not_double_prefixed() {
    let temp = unique_temp_dir("rls2fga_parse_err");
    let input_path = temp.join("invalid.sql");
    std::fs::write(&input_path, "not sql").expect("should write invalid sql file");

    let output = Command::new(env!("CARGO_BIN_EXE_rls2fga"))
        .arg(&input_path)
        .output()
        .expect("should run rls2fga binary");

    assert_eq!(
        output.status.code(),
        Some(2),
        "expected parse failure exit code 2, got {:?}",
        output.status
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("SQL parse error: SQL parse error:"),
        "parse error message should not duplicate prefix, got:\n{stderr}"
    );
    assert!(
        stderr.contains("SQL parse error:"),
        "parse error message should keep a single prefix, got:\n{stderr}"
    );
}

#[test]
fn cli_can_infer_current_user_accessor_from_function_body_without_registry() {
    let temp = unique_temp_dir("rls2fga_infer_fn");
    let input_path = temp.join("input.sql");
    let output_dir = temp.join("out");

    let sql = r"
CREATE TABLE users (id UUID PRIMARY KEY);
CREATE TABLE docs (
  id UUID PRIMARY KEY,
  tenant_id UUID REFERENCES users(id)
);
CREATE FUNCTION current_tenant_id() RETURNS UUID
  LANGUAGE sql STABLE
  AS 'SELECT current_setting(''app.current_user_id'')::uuid';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_select ON docs FOR SELECT TO PUBLIC
  USING (tenant_id = current_tenant_id());
";
    std::fs::write(&input_path, sql).expect("should write temp input sql");

    let status = Command::new(env!("CARGO_BIN_EXE_rls2fga"))
        .arg(&input_path)
        .arg("--min-confidence")
        .arg("A")
        .arg("--output-dir")
        .arg(&output_dir)
        .status()
        .expect("should run rls2fga binary");

    assert_eq!(
        status.code(),
        Some(0),
        "expected successful run when function body can be inferred, got {status:?}"
    );

    let model_path = output_dir.join("input.fga");
    let model = std::fs::read_to_string(&model_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", model_path.display()));

    assert!(
        model.contains("type docs"),
        "expected docs type in output model, got:\n{model}"
    );
    assert!(
        model.contains("define can_select: owner"),
        "expected inferred ownership policy translation, got:\n{model}"
    );
}

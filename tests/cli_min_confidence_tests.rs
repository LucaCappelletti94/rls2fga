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

#[test]
fn cli_schema_dir_missing_reports_error() {
    let temp = unique_temp_dir("rls2fga_schema_dir_missing");
    let missing_dir = temp.join("does_not_exist");

    let output = Command::new(env!("CARGO_BIN_EXE_rls2fga"))
        .arg("--schema-dir")
        .arg(&missing_dir)
        .output()
        .expect("should run rls2fga binary");

    assert_eq!(
        output.status.code(),
        Some(2),
        "expected schema-dir read failure exit code 2, got {:?}",
        output.status
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Error reading schema directory:"),
        "missing schema dir should report a directory read error, got:\n{stderr}"
    );
}

#[test]
fn cli_schema_dir_without_sql_files_reports_no_input() {
    let empty_schema_dir = unique_temp_dir("rls2fga_schema_dir_empty");

    let output = Command::new(env!("CARGO_BIN_EXE_rls2fga"))
        .arg("--schema-dir")
        .arg(&empty_schema_dir)
        .output()
        .expect("should run rls2fga binary");

    assert_eq!(
        output.status.code(),
        Some(2),
        "expected empty schema-dir exit code 2, got {:?}",
        output.status
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("No input SQL files provided"),
        "empty schema dir should report missing input SQL files, got:\n{stderr}"
    );
}

#[test]
fn cli_missing_input_file_reports_error() {
    let temp = unique_temp_dir("rls2fga_missing_input");
    let missing_input = temp.join("missing.sql");

    let output = Command::new(env!("CARGO_BIN_EXE_rls2fga"))
        .arg(&missing_input)
        .output()
        .expect("should run rls2fga binary");

    assert_eq!(
        output.status.code(),
        Some(2),
        "expected missing input file exit code 2, got {:?}",
        output.status
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Error reading"),
        "missing input file should report read failure, got:\n{stderr}"
    );
}

#[test]
fn cli_missing_function_registry_file_reports_error() {
    let temp = unique_temp_dir("rls2fga_registry_missing");
    let input_path = temp.join("input.sql");
    let missing_registry = temp.join("registry.json");
    let output_dir = temp.join("out");

    let sql = "CREATE TABLE docs (id UUID PRIMARY KEY);";
    std::fs::write(&input_path, sql).expect("should write temp input sql");

    let output = Command::new(env!("CARGO_BIN_EXE_rls2fga"))
        .arg(&input_path)
        .arg("--function-registry")
        .arg(&missing_registry)
        .arg("--output-dir")
        .arg(&output_dir)
        .output()
        .expect("should run rls2fga binary");

    assert_eq!(
        output.status.code(),
        Some(2),
        "expected missing function-registry file exit code 2, got {:?}",
        output.status
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Error reading function registry:"),
        "missing function registry should report read failure, got:\n{stderr}"
    );
}

#[test]
fn cli_invalid_function_registry_json_reports_error() {
    let temp = unique_temp_dir("rls2fga_registry_invalid");
    let input_path = temp.join("input.sql");
    let registry_path = temp.join("registry.json");
    let output_dir = temp.join("out");

    let sql = "CREATE TABLE docs (id UUID PRIMARY KEY);";
    std::fs::write(&input_path, sql).expect("should write temp input sql");
    std::fs::write(&registry_path, "{ not valid json").expect("should write invalid registry");

    let output = Command::new(env!("CARGO_BIN_EXE_rls2fga"))
        .arg(&input_path)
        .arg("--function-registry")
        .arg(&registry_path)
        .arg("--output-dir")
        .arg(&output_dir)
        .output()
        .expect("should run rls2fga binary");

    assert_eq!(
        output.status.code(),
        Some(2),
        "expected invalid function-registry json exit code 2, got {:?}",
        output.status
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Error parsing function registry:"),
        "invalid function registry should report parse failure, got:\n{stderr}"
    );
}

#[test]
fn cli_output_dir_file_path_reports_write_error() {
    let temp = unique_temp_dir("rls2fga_output_dir_file");
    let input_path = temp.join("input.sql");
    let output_dir_marker = temp.join("not_a_directory");
    std::fs::write(&output_dir_marker, "marker file").expect("should create marker file");

    let sql = "CREATE TABLE docs (id UUID PRIMARY KEY);";
    std::fs::write(&input_path, sql).expect("should write temp input sql");

    let output = Command::new(env!("CARGO_BIN_EXE_rls2fga"))
        .arg(&input_path)
        .arg("--output-dir")
        .arg(&output_dir_marker)
        .output()
        .expect("should run rls2fga binary");

    assert_eq!(
        output.status.code(),
        Some(2),
        "expected write-output failure exit code 2, got {:?}",
        output.status
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Error writing output: Failed to create output directory:"),
        "file path output-dir should report create_dir_all failure, got:\n{stderr}"
    );
}

#[test]
fn cli_verbose_emits_parse_and_policy_diagnostics() {
    let temp = unique_temp_dir("rls2fga_verbose_output");
    let input_path = temp.join("input.sql");
    let output_dir = temp.join("out");

    let sql = std::fs::read_to_string("tests/fixtures/public_flag/input.sql")
        .unwrap_or_else(|e| panic!("failed to read fixture SQL: {e}"));
    std::fs::write(&input_path, sql).expect("should write temp input sql");

    let output = Command::new(env!("CARGO_BIN_EXE_rls2fga"))
        .arg(&input_path)
        .arg("--verbose")
        .arg("--min-confidence")
        .arg("C")
        .arg("--output-dir")
        .arg(&output_dir)
        .output()
        .expect("should run rls2fga binary");

    assert_eq!(
        output.status.code(),
        Some(0),
        "expected successful verbose run, got {:?}",
        output.status
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Parsed "),
        "verbose mode should emit parse summary, got:\n{stderr}"
    );
    assert!(
        stderr.contains("Policy '"),
        "verbose mode should emit per-policy diagnostics, got:\n{stderr}"
    );
}

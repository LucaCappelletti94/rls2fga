use std::path::{Component, Path};

use crate::classifier::patterns::{filter_policies_for_output, ClassifiedPolicy, ConfidenceLevel};
use crate::generator::model_generator::GeneratedModel;
use crate::generator::tuple_generator::{self, TupleQuery};
use crate::output::report;

/// Write all output files to the specified directory.
pub fn write_output(
    output_dir: &Path,
    name: &str,
    model: &GeneratedModel,
    tuples: &[TupleQuery],
    policies: &[ClassifiedPolicy],
    min_confidence: ConfidenceLevel,
) -> Result<(), String> {
    validate_output_name(name)?;

    std::fs::create_dir_all(output_dir)
        .map_err(|e| format!("Failed to create output directory: {e}"))?;

    // Write .fga model file
    let fga_path = output_dir.join(format!("{name}.fga"));
    std::fs::write(&fga_path, &model.dsl)
        .map_err(|e| format!("Failed to write {}: {e}", fga_path.display()))?;

    // Write _tuples.sql
    let tuples_path = output_dir.join(format!("{name}_tuples.sql"));
    let tuples_content = tuple_generator::format_tuples(tuples);
    std::fs::write(&tuples_path, &tuples_content)
        .map_err(|e| format!("Failed to write {}: {e}", tuples_path.display()))?;

    // Write _report.md
    let report_path = output_dir.join(format!("{name}_report.md"));
    let filtered = filter_policies_for_output(policies, min_confidence);
    let report_content = report::build_report(model, &filtered);
    std::fs::write(&report_path, &report_content)
        .map_err(|e| format!("Failed to write {}: {e}", report_path.display()))?;

    Ok(())
}

/// Windows reserved device names that must not be used as output names.
const WINDOWS_RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

fn validate_output_name(name: &str) -> Result<(), String> {
    if name.trim().is_empty() {
        return Err("Output name must not be empty".to_string());
    }
    // Reject names containing null bytes or other control characters.
    if name.chars().any(char::is_control) {
        return Err(format!(
            "Invalid output name '{name}': control characters are not allowed"
        ));
    }
    // Reject a bare dot (current directory reference).
    if name == "." || name == ".." {
        return Err(format!(
            "Invalid output name '{name}': '.' and '..' are not allowed"
        ));
    }
    // Reject colons (Windows drive separator; also problematic on macOS).
    if name.contains(':') {
        return Err(format!(
            "Invalid output name '{name}': colons are not allowed"
        ));
    }
    // Reject Windows reserved device names (case-insensitive).
    let upper = name.to_uppercase();
    if WINDOWS_RESERVED.contains(&upper.as_str()) {
        return Err(format!(
            "Invalid output name '{name}': Windows reserved device name"
        ));
    }
    let candidate = Path::new(name);
    if candidate.is_absolute() {
        return Err(format!(
            "Invalid output name '{name}': absolute paths are not allowed"
        ));
    }
    if candidate.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err(format!(
            "Invalid output name '{name}': traversal segments are not allowed"
        ));
    }
    if name.contains('/') || name.contains('\\') {
        return Err(format!(
            "Invalid output name '{name}': path separators are not allowed"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generator::model_generator::TodoItem;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_path(prefix: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be monotonic")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}_{nanos}"))
    }

    fn empty_model() -> GeneratedModel {
        GeneratedModel {
            dsl: "model".to_string(),
            todos: vec![TodoItem {
                level: ConfidenceLevel::C,
                policy_name: "p".to_string(),
                message: "todo".to_string(),
            }],
            confidence_summary: Vec::new(),
        }
    }

    #[test]
    fn write_output_reports_directory_creation_errors() {
        let path = unique_path("rls2fga_formatter_file");
        std::fs::write(&path, "not a directory").expect("should create marker file");

        let err = write_output(
            &path,
            "output",
            &empty_model(),
            &[],
            &[],
            ConfidenceLevel::D,
        )
        .expect_err("directory creation should fail");
        assert!(err.contains("Failed to create output directory"));
    }

    #[test]
    fn write_output_rejects_unsafe_name_paths() {
        let dir = unique_path("rls2fga_formatter_dir");
        std::fs::create_dir_all(&dir).expect("should create temp directory");

        let err = write_output(
            &dir,
            "nested/output",
            &empty_model(),
            &[],
            &[],
            ConfidenceLevel::D,
        )
        .expect_err("unsafe output name should fail validation");
        assert!(err.contains("Invalid output name"));

        let err = write_output(
            &dir,
            "../escape",
            &empty_model(),
            &[],
            &[],
            ConfidenceLevel::D,
        )
        .expect_err("path traversal should fail validation");
        assert!(err.contains("Invalid output name"));
    }

    #[test]
    fn write_output_writes_all_artifacts_on_success() {
        let dir = unique_path("rls2fga_formatter_ok");
        let tuples = vec![TupleQuery {
            comment: "-- tuple".to_string(),
            sql: "SELECT 1;".to_string(),
        }];

        write_output(
            &dir,
            "docs",
            &empty_model(),
            &tuples,
            &[],
            ConfidenceLevel::D,
        )
        .expect("write_output should succeed");

        let fga = std::fs::read_to_string(dir.join("docs.fga")).expect("fga file should exist");
        let tuple_sql =
            std::fs::read_to_string(dir.join("docs_tuples.sql")).expect("tuple file should exist");
        let report =
            std::fs::read_to_string(dir.join("docs_report.md")).expect("report should exist");

        assert_eq!(fga, "model");
        assert!(tuple_sql.contains("SELECT 1;"));
        assert!(report.contains("# rls2fga Translation Report"));
    }

    #[test]
    fn validate_output_name_rejects_dot_and_dotdot() {
        assert!(
            validate_output_name(".").is_err(),
            "bare dot should be rejected"
        );
        assert!(
            validate_output_name("..").is_err(),
            "dotdot should be rejected"
        );
    }

    #[test]
    fn validate_output_name_rejects_control_characters() {
        let with_null = "name\x00suffix";
        assert!(
            validate_output_name(with_null).is_err(),
            "null byte should be rejected"
        );
        let with_newline = "name\nsuffix";
        assert!(
            validate_output_name(with_newline).is_err(),
            "newline should be rejected"
        );
    }

    #[test]
    fn validate_output_name_rejects_colons() {
        assert!(
            validate_output_name("C:name").is_err(),
            "colon should be rejected"
        );
    }

    #[test]
    fn validate_output_name_rejects_windows_reserved_names() {
        for reserved in &["CON", "con", "NUL", "nul", "COM1", "LPT9"] {
            assert!(
                validate_output_name(reserved).is_err(),
                "Windows reserved name '{reserved}' should be rejected"
            );
        }
    }

    #[test]
    fn validate_output_name_accepts_normal_names() {
        assert!(validate_output_name("my_output").is_ok());
        assert!(validate_output_name("schema-v1").is_ok());
        assert!(validate_output_name("report_2024").is_ok());
    }
}

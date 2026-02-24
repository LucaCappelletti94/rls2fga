use std::path::{Component, Path};

use crate::classifier::patterns::ClassifiedPolicy;
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
    let report_content = report::build_report(model, policies);
    std::fs::write(&report_path, &report_content)
        .map_err(|e| format!("Failed to write {}: {e}", report_path.display()))?;

    Ok(())
}

fn validate_output_name(name: &str) -> Result<(), String> {
    if name.trim().is_empty() {
        return Err("Output name must not be empty".to_string());
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
                level: crate::classifier::patterns::ConfidenceLevel::C,
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

        let err = write_output(&path, "output", &empty_model(), &[], &[])
            .expect_err("directory creation should fail");
        assert!(err.contains("Failed to create output directory"));
    }

    #[test]
    fn write_output_rejects_unsafe_name_paths() {
        let dir = unique_path("rls2fga_formatter_dir");
        std::fs::create_dir_all(&dir).expect("should create temp directory");

        let err = write_output(&dir, "nested/output", &empty_model(), &[], &[])
            .expect_err("unsafe output name should fail validation");
        assert!(err.contains("Invalid output name"));

        let err = write_output(&dir, "../escape", &empty_model(), &[], &[])
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

        write_output(&dir, "docs", &empty_model(), &tuples, &[])
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
}

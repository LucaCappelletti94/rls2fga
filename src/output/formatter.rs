use std::path::Path;

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
    fn write_output_reports_write_errors_for_invalid_name_path() {
        let dir = unique_path("rls2fga_formatter_dir");
        std::fs::create_dir_all(&dir).expect("should create temp directory");

        let err = write_output(&dir, "nested/output", &empty_model(), &[], &[])
            .expect_err("writing nested name without parent directory should fail");
        assert!(err.contains("Failed to write"));
        assert!(err.contains("nested/output.fga"));
    }
}

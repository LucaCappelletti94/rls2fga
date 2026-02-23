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

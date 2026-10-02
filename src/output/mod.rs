/// Writes the generated model, tuple queries, and report to disk.
#[cfg(feature = "std")]
pub mod formatter;
/// Builds a Markdown confidence-summary report from classified policies.
pub mod report;

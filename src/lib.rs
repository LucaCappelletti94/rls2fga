//! Translate `PostgreSQL` Row-Level Security policies into `OpenFGA` authorization models.
#![warn(missing_docs)]

/// RLS expression classification: pattern matching, function registry, and confidence scoring.
pub mod classifier;
/// `OpenFGA` model generation from classified policies (DSL, JSON, and tuple SQL).
pub mod generator;
/// File output and markdown report generation.
pub mod output;
/// SQL schema parsing and function body analysis.
pub mod parser;

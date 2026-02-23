//! CLI entry point for `rls2fga`.

use std::path::PathBuf;
use std::process;

use clap::Parser;
use rls2fga::classifier::function_registry::FunctionRegistry;
use rls2fga::classifier::patterns::{ClassifiedPolicy, ConfidenceLevel};
use rls2fga::classifier::policy_classifier;
use rls2fga::generator::model_generator;
use rls2fga::generator::tuple_generator;
use rls2fga::output::formatter;
use rls2fga::parser::sql_parser;

use sql_traits::prelude::DatabaseLike;

#[derive(Parser)]
#[command(
    name = "rls2fga",
    about = "Translate PostgreSQL RLS policies into OpenFGA authorization models"
)]
struct Cli {
    /// Input SQL files
    #[arg(required_unless_present_any = ["schema_dir", "db_url"])]
    input: Vec<PathBuf>,

    /// Process all .sql files in directory
    #[arg(long)]
    schema_dir: Option<PathBuf>,

    /// Introspect live `PostgreSQL` database
    #[arg(long)]
    db_url: Option<String>,

    /// Pre-built JSON function registry
    #[arg(long)]
    function_registry: Option<PathBuf>,

    /// Output directory
    #[arg(long, default_value = "rls2fga-output")]
    output_dir: PathBuf,

    /// Minimum confidence level to include in output
    #[arg(long, default_value = "B")]
    min_confidence: ConfidenceLevel,

    /// Print verbose diagnostics
    #[arg(long)]
    verbose: bool,
}

fn main() {
    let cli = Cli::parse();

    // Collect input files
    let mut sql_files = cli.input.clone();
    if let Some(dir) = &cli.schema_dir {
        match std::fs::read_dir(dir) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().is_some_and(|e| e == "sql") {
                        sql_files.push(path);
                    }
                }
            }
            Err(e) => {
                eprintln!("Error reading schema directory: {e}");
                process::exit(2);
            }
        }
    }

    if sql_files.is_empty() {
        eprintln!("No input SQL files provided");
        process::exit(2);
    }

    // Read and concatenate all SQL
    let mut combined_sql = String::new();
    for path in &sql_files {
        match std::fs::read_to_string(path) {
            Ok(content) => {
                combined_sql.push_str(&content);
                combined_sql.push('\n');
            }
            Err(e) => {
                eprintln!("Error reading {}: {e}", path.display());
                process::exit(2);
            }
        }
    }

    // Stage 1-2: Parse schema
    let db = match sql_parser::parse_schema(&combined_sql) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("SQL parse error: {e}");
            process::exit(2);
        }
    };

    if cli.verbose {
        eprintln!(
            "Parsed {} tables, {} functions, {} policies",
            db.number_of_tables(),
            db.functions().count(),
            db.policies().count()
        );
    }

    // Stage 3: Load/merge function registry
    let mut registry = FunctionRegistry::new();
    if let Some(reg_path) = &cli.function_registry {
        match std::fs::read_to_string(reg_path) {
            Ok(content) => match registry.load_from_json(&content) {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("Error parsing function registry: {e}");
                    process::exit(2);
                }
            },
            Err(e) => {
                eprintln!("Error reading function registry: {e}",);
                process::exit(2);
            }
        }
    }
    // Infer semantics for in-schema functions when possible (without overriding explicit registry).
    registry.enrich_from_schema(&db);

    // Stage 4: Classify policies
    let classified = policy_classifier::classify_policies(&db, &registry);
    let output_classified = filter_policies_for_output(&classified, cli.min_confidence);

    if cli.verbose {
        for cp in &classified {
            eprintln!(
                "Policy '{}' on '{}': {:?}",
                cp.name(),
                cp.table_name(),
                cp.using_classification
                    .as_ref()
                    .map(|c| (&c.pattern, &c.confidence))
            );
        }
    }

    // Stage 5: Generate model
    let model =
        model_generator::generate_model(&output_classified, &db, &registry, &cli.min_confidence);

    // Stage 6: Generate tuple queries
    let tuples = tuple_generator::generate_tuple_queries(&output_classified, &db, &registry);

    // Stage 7: Write output
    // Derive name from first input file
    let name = sql_files
        .first()
        .and_then(|p| p.file_stem())
        .and_then(|s| s.to_str())
        .unwrap_or("output");

    if let Err(e) =
        formatter::write_output(&cli.output_dir, name, &model, &tuples, &output_classified)
    {
        eprintln!("Error writing output: {e}");
        process::exit(2);
    }

    // Exit code based on confidence
    let has_below_min = classified.iter().any(|cp| {
        let below_using = cp
            .using_classification
            .as_ref()
            .is_some_and(|c| c.confidence < cli.min_confidence);
        let below_check = cp
            .with_check_classification
            .as_ref()
            .is_some_and(|c| c.confidence < cli.min_confidence);
        below_using || below_check
    });

    if has_below_min {
        process::exit(1);
    }
}

fn filter_policies_for_output(
    policies: &[ClassifiedPolicy],
    min_confidence: ConfidenceLevel,
) -> Vec<ClassifiedPolicy> {
    policies
        .iter()
        .filter_map(|cp| {
            let mut filtered = cp.clone();
            filtered.using_classification = cp
                .using_classification
                .as_ref()
                .filter(|c| c.confidence >= min_confidence)
                .cloned();
            filtered.with_check_classification = cp
                .with_check_classification
                .as_ref()
                .filter(|c| c.confidence >= min_confidence)
                .cloned();

            if filtered.using_classification.is_some()
                || filtered.with_check_classification.is_some()
            {
                Some(filtered)
            } else {
                None
            }
        })
        .collect()
}

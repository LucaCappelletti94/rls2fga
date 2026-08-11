//! The schema catalog reaches the public surface as a `DatabaseLike`.
//!
//! rls2fga reads a catalog only through the traits, so demanding the one instantiation
//! `parse_schema` returns would refuse a caller holding any other, a different dialect
//! or a catalog read from a live server rather than parsed from DDL. The proof is a body
//! the compiler checks against the bound alone: every public entry point that takes a
//! catalog is called here through `DB`, so a concrete catalog reappearing anywhere on
//! the surface fails to build.

use rls2fga::classifier::function_registry::FunctionRegistry;
use rls2fga::classifier::patterns::{
    ConfidenceLevel, DirectOwnership, PatternClass, PolicyCommand,
};
use rls2fga::classifier::policy_classifier::{
    classify_expr, classify_policies, classify_policies_with_effective_registry,
    classify_policies_with_effective_registry_and_settings, classify_policies_with_registry,
};
use rls2fga::generator::model_generator::GeneratorSettings;
use rls2fga::generator::relations::RelationShapes;
use rls2fga::generator::tuple_generator::format_tuples;
use rls2fga::parser::function_analyzer::AccessorInferenceSettings;
use rls2fga::parser::sql_parser::{parse_schema, DatabaseLike, PolicyLike};
use rls2fga::translator::{Translation, TranslatorBuilder};

const SCHEMA: &str = "
CREATE TABLE users (id UUID PRIMARY KEY);
CREATE TABLE docs (id UUID PRIMARY KEY, owner_id UUID);
CREATE FUNCTION auth_current_user_id() RETURNS UUID LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')::uuid';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING (owner_id = auth_current_user_id());
";

const ACCESSOR_REGISTRY: &str =
    r#"{"auth_current_user_id": {"kind": "current_user_accessor", "returns": "uuid"}}"#;

fn unique_temp_dir(prefix: &str) -> std::path::PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the clock is after the epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("{prefix}_{nanos}"));
    std::fs::create_dir_all(&dir).expect("the temp dir is creatable");
    dir
}

/// What the generic pass produced, so the assertions can see it answered rather than
/// compiled vacuously.
struct Driven {
    classified: usize,
    enriched_accessor: bool,
    expr_pattern: PatternClass,
    model: String,
    json_types: Vec<String>,
    tuples: String,
    report: String,
    relations: Vec<RelationShapes>,
    notes: usize,
    unhandled: usize,
    confidence: Vec<(String, ConfidenceLevel)>,
    written: String,
}

/// Every public entry point that takes a catalog, called through `DB`.
fn drive<DB: DatabaseLike>(db: &DB) -> Driven {
    let mut registry = FunctionRegistry::new();
    registry
        .load_from_json(ACCESSOR_REGISTRY)
        .expect("the registry parses");

    let settings = AccessorInferenceSettings::default();
    let generator = GeneratorSettings::default();

    // The four free classifiers, plus the two registry enrichers.
    let classified = classify_policies(db, &registry);
    assert_eq!(
        classify_policies_with_registry(db, &registry).len(),
        classified.len()
    );
    let (with_effective, _) = classify_policies_with_effective_registry(db, &registry);
    assert_eq!(with_effective.len(), classified.len());
    let (with_settings, effective) =
        classify_policies_with_effective_registry_and_settings(db, &registry, &settings);
    assert_eq!(with_settings.len(), classified.len());

    let mut enriched = FunctionRegistry::new();
    enriched.enrich_from_schema(db);
    let mut enriched_with_settings = FunctionRegistry::new();
    enriched_with_settings.enrich_from_schema_with_settings(db, &settings);
    let enriched_accessor = enriched.is_current_user_accessor("auth_current_user_id")
        && enriched_with_settings.is_current_user_accessor("auth_current_user_id");

    // One expression, classified on its own, which is how an oracle reaches the
    // pattern tree without going through the whole schema.
    let policy = db.policies().next().expect("the schema declares a policy");
    let expr = policy
        .using_expression(db)
        .expect("the policy stores a USING clause")
        .clone();
    let expr_pattern = classify_expr(&expr, db, &registry, "docs", PolicyCommand::Select).pattern;

    // The facade, then the plan built from answers somebody else classified.
    let translator = TranslatorBuilder::new()
        .with_registry(registry.clone())
        .with_min_confidence(ConfidenceLevel::B)
        .build();
    assert_eq!(translator.classify(db).len(), classified.len());
    let (facade_classified, _) = translator.classify_with_effective_registry(db);
    assert_eq!(facade_classified.len(), classified.len());

    let translation = translator.translate(db);
    let notes = translation.notes().len();
    let unhandled = translation.unhandled().count();
    let relations = translation.relations();
    let outputs = translation.outputs().expect("nothing goes unhandled");

    let model = outputs.model();
    let json_types = outputs
        .json_model()
        .type_definitions
        .iter()
        .map(|definition| definition.type_name.clone())
        .collect();
    let tuples = format_tuples(&outputs.tuple_queries());
    let report = outputs.report();
    assert_eq!(outputs.notes().len(), notes);
    let confidence = outputs.confidence_summary().to_vec();

    let dir = unique_temp_dir("rls2fga_generic_catalog");
    outputs.write(&dir, "docs").expect("the write succeeds");
    let written = std::fs::read_to_string(dir.join("docs.fga")).expect("the model is written");

    // The plan door, reached with the answers the free classifier gave.
    let replanned = Translation::plan(
        classified.clone(),
        db,
        &effective,
        ConfidenceLevel::B,
        &generator,
    );
    assert_eq!(replanned.relations().len(), relations.len());
    assert!(!replanned.outputs_accepting_gaps().model().is_empty());

    Driven {
        classified: classified.len(),
        enriched_accessor,
        expr_pattern,
        model,
        json_types,
        tuples,
        report,
        relations,
        notes,
        unhandled,
        confidence,
        written,
    }
}

/// The generic pass translates, rather than compiling against a surface it never
/// exercises.
#[test]
fn a_catalog_known_only_as_database_like_drives_the_whole_surface() {
    let db = parse_schema(SCHEMA).expect("the schema parses");
    let driven = drive(&db);

    assert_eq!(driven.classified, 1);
    assert!(
        driven.enriched_accessor,
        "schema enrichment must recognise the accessor, saw it refused"
    );
    assert!(
        matches!(&driven.expr_pattern, PatternClass::P3DirectOwnership(DirectOwnership { column }) if column == "owner_id"),
        "classifying the clause on its own must reach direct ownership, saw {:?}",
        driven.expr_pattern
    );
    assert!(
        driven.model.contains("type docs") && driven.model.contains("can_select"),
        "the DSL must carry the policied table and its read action, saw:\n{}",
        driven.model
    );
    assert!(
        driven.json_types.iter().any(|name| name == "docs"),
        "the JSON model must declare the policied type, saw {:?}",
        driven.json_types
    );
    assert!(
        driven.tuples.contains("owner_id"),
        "the tuple SQL must read the ownership column, saw:\n{}",
        driven.tuples
    );
    assert!(
        driven.report.contains("docs_owner"),
        "the report must name the policy, saw:\n{}",
        driven.report
    );
    assert!(
        driven
            .relations
            .iter()
            .any(|shapes| shapes.relation == "can_select"),
        "the relation report must reach the read action, saw {:?}",
        driven
            .relations
            .iter()
            .map(|shapes| shapes.relation.clone())
            .collect::<Vec<_>>()
    );
    assert_eq!(driven.unhandled, 0);
    assert_eq!(
        driven.confidence,
        vec![("docs_owner".to_string(), ConfidenceLevel::A)]
    );
    assert_eq!(driven.written, driven.model);
    assert!(driven.notes >= driven.unhandled);
}

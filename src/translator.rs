#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
#[cfg(feature = "std")]
use std::path::Path;

use crate::classifier::function_registry::FunctionRegistry;
use crate::classifier::patterns::{ClassifiedPolicy, ConfidenceLevel};
use crate::classifier::policy_classifier::classify_policies_with_effective_registry_and_settings;
use crate::generator::json_model::{generate_json_model, AuthorizationModel};
use crate::generator::model_generator::{generate_model, GeneratedModel};
use crate::generator::tuple_generator::{generate_tuple_queries, TupleQuery};
#[cfg(feature = "std")]
use crate::output::formatter::write_output;
use crate::parser::function_analyzer::AccessorInferenceSettings;
use crate::parser::sql_parser::ParserDB;

/// Builder for a [`Translator`].
#[derive(Debug, Clone)]
pub struct TranslatorBuilder {
    registry: FunctionRegistry,
    settings: AccessorInferenceSettings,
    min_confidence: ConfidenceLevel,
}

impl TranslatorBuilder {
    /// Create a new translator builder with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the base function registry.
    #[must_use]
    pub fn with_registry(mut self, registry: FunctionRegistry) -> Self {
        self.registry = registry;
        self
    }

    /// Merge function semantics from JSON into the base registry.
    pub fn with_registry_json(mut self, json: &str) -> Result<Self, String> {
        self.registry.load_from_json(json)?;
        Ok(self)
    }

    /// Replace allowed `current_setting` keys used for automatic accessor inference.
    #[must_use]
    pub fn with_current_user_setting_keys<I, S>(mut self, keys: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.settings = AccessorInferenceSettings::from_keys(keys);
        self
    }

    /// Set the output confidence threshold used by model/tuple/report generation.
    #[must_use]
    pub fn with_min_confidence(mut self, min_confidence: ConfidenceLevel) -> Self {
        self.min_confidence = min_confidence;
        self
    }

    /// Build the translator.
    pub fn build(self) -> Translator {
        Translator {
            registry: self.registry,
            settings: self.settings,
            min_confidence: self.min_confidence,
        }
    }
}

impl Default for TranslatorBuilder {
    fn default() -> Self {
        Self {
            registry: FunctionRegistry::new(),
            settings: AccessorInferenceSettings::default(),
            min_confidence: ConfidenceLevel::B,
        }
    }
}

/// High-level classification and translation facade.
#[derive(Debug, Clone)]
pub struct Translator {
    registry: FunctionRegistry,
    settings: AccessorInferenceSettings,
    min_confidence: ConfidenceLevel,
}

impl Translator {
    /// Classify policies using the configured settings.
    pub fn classify(&self, db: &ParserDB) -> Vec<ClassifiedPolicy> {
        self.classify_with_effective_registry(db).0
    }

    /// Classify policies and return the effective registry after schema enrichment.
    pub fn classify_with_effective_registry(
        &self,
        db: &ParserDB,
    ) -> (Vec<ClassifiedPolicy>, FunctionRegistry) {
        classify_policies_with_effective_registry_and_settings(db, &self.registry, &self.settings)
    }

    /// Generate an `OpenFGA` DSL model from the configured pipeline.
    pub fn generate_model(&self, db: &ParserDB) -> GeneratedModel {
        let (classified, effective_registry) = self.classify_with_effective_registry(db);
        generate_model(&classified, db, &effective_registry, self.min_confidence)
    }

    /// Generate an `OpenFGA` JSON authorization model from the configured pipeline.
    pub fn generate_json_model(&self, db: &ParserDB) -> AuthorizationModel {
        let (classified, effective_registry) = self.classify_with_effective_registry(db);
        generate_json_model(&classified, db, &effective_registry, self.min_confidence)
    }

    /// Generate tuple SQL queries from the configured pipeline.
    pub fn generate_tuple_queries(&self, db: &ParserDB) -> Vec<TupleQuery> {
        let (classified, effective_registry) = self.classify_with_effective_registry(db);
        generate_tuple_queries(&classified, db, &effective_registry, self.min_confidence)
    }

    #[cfg(feature = "std")]
    /// Run classification + generation and write artifacts to disk.
    pub fn write_output(&self, db: &ParserDB, output_dir: &Path, name: &str) -> Result<(), String> {
        let (classified, effective_registry) = self.classify_with_effective_registry(db);
        let model = generate_model(&classified, db, &effective_registry, self.min_confidence);
        let tuples =
            generate_tuple_queries(&classified, db, &effective_registry, self.min_confidence);
        write_output(
            output_dir,
            name,
            &model,
            &tuples,
            &classified,
            self.min_confidence,
        )
    }

    /// Read-only access to the configured base registry.
    pub fn registry(&self) -> &FunctionRegistry {
        &self.registry
    }

    /// Read-only access to accessor inference settings.
    pub fn settings(&self) -> &AccessorInferenceSettings {
        &self.settings
    }

    /// Configured minimum confidence for output generation.
    pub fn min_confidence(&self) -> ConfidenceLevel {
        self.min_confidence
    }
}

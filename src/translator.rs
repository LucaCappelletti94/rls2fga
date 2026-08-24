#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
#[cfg(feature = "std")]
use std::path::Path;

use crate::classifier::function_registry::{FunctionRegistry, RegistryLoadError, SessionAttribute};
use crate::classifier::patterns::{ClassifiedPolicy, ConfidenceLevel};
use crate::classifier::policy_classifier::classify_policies_with_effective_registry_and_settings;
use crate::generator::action_relations::{action_relations, ActionRelations};
use crate::generator::json_model::{json_model_from_plan, AuthorizationModel};
use crate::generator::model_generator::{
    build_filtered_schema_plan, render_dsl_from_plan, GeneratorSettings, SchemaPlan,
};
use crate::generator::notes::{NoteSeverity, TranslationNote};
use crate::generator::records::Record;
use crate::generator::relations::{relation_shapes, RelationShapes};
use crate::generator::row_naming::{row_naming, RowNaming};
use crate::generator::tuple_generator::{
    generate_tuple_queries_from_plan, record_from_tuple_row, TupleQuery, TupleRow, TupleRowError,
};
use crate::generator::unrestricted::{unrestricted_tables, UnrestrictedTable};
use crate::generator::well_known::WellKnownTypes;
#[cfg(feature = "std")]
use crate::output::formatter::{write_output, WriteError};
use crate::output::report::build_report;
use crate::parser::function_analyzer::AccessorInferenceSettings;
use crate::parser::sql_parser::{DatabaseLike, ParserDB};

pub use crate::generator::model_generator::PlanningError;

/// Builder for a [`Translator`].
#[derive(Debug, Clone)]
pub struct TranslatorBuilder {
    registry: FunctionRegistry,
    settings: AccessorInferenceSettings,
    min_confidence: ConfidenceLevel,
    generator: GeneratorSettings,
}

impl TranslatorBuilder {
    /// Create a new translator builder with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Name the condition parameter a caller supplies for a guard against statement
    /// time, which every check context then has to use. Defaults to `request_time`.
    #[must_use]
    pub fn with_request_time_parameter(mut self, name: impl Into<String>) -> Self {
        self.generator.request_time_parameter = name.into();
        self
    }

    /// Replace the type names the generator reserves for its own vocabulary.
    #[must_use]
    pub fn with_well_known_types(mut self, names: WellKnownTypes) -> Self {
        self.generator.well_known = names;
        self
    }

    /// Replace the base function registry.
    #[must_use]
    pub fn with_registry(mut self, registry: FunctionRegistry) -> Self {
        self.registry = registry;
        self
    }

    /// Merge function semantics from JSON into the base registry.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryLoadError`] when the JSON is not a registry payload.
    pub fn with_registry_json(mut self, json: &str) -> Result<Self, RegistryLoadError> {
        self.registry.load_from_json(json)?;
        Ok(self)
    }

    /// Replace the `current_setting` keys this builder names as holding the caller's
    /// identity. A key the base registry already names is kept.
    ///
    /// A call reading one names the caller wherever it appears: inline in a policy, or
    /// as the whole body of a function the policy calls.
    #[must_use]
    pub fn with_current_user_setting_keys<I, S>(mut self, keys: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.settings = AccessorInferenceSettings::from_keys(keys);
        self
    }

    /// Declare the request-scoped values a policy may read, of any kind.
    ///
    /// A source is a `current_setting` key, optionally with a field path taken out of
    /// the value at that key. Declaring one is a contract with the caller: the condition
    /// parameter it names has to be supplied in every check context.
    #[must_use]
    pub fn with_session_attributes<I>(mut self, attributes: I) -> Self
    where
        I: IntoIterator<Item = SessionAttribute>,
    {
        self.settings = AccessorInferenceSettings::from_attributes(
            self.settings
                .session_attributes()
                .iter()
                .cloned()
                .chain(attributes),
        );
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
            generator: self.generator,
        }
    }
}

impl Default for TranslatorBuilder {
    fn default() -> Self {
        Self {
            registry: FunctionRegistry::new(),
            settings: AccessorInferenceSettings::default(),
            generator: GeneratorSettings::default(),
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
    generator: GeneratorSettings,
}

impl Translator {
    /// Classify policies using the configured settings.
    pub fn classify<DB: DatabaseLike>(&self, db: &DB) -> Vec<ClassifiedPolicy> {
        self.classify_with_effective_registry(db).0
    }

    /// Classify policies and return the effective registry after schema enrichment.
    pub fn classify_with_effective_registry<DB: DatabaseLike>(
        &self,
        db: &DB,
    ) -> (Vec<ClassifiedPolicy>, FunctionRegistry) {
        classify_policies_with_effective_registry_and_settings(db, &self.registry, &self.settings)
    }

    /// Plan a translation of `db`.
    ///
    /// The plan is built once here and each output is rendered from it on demand, so a
    /// caller wanting the model, the JSON and the tuples classifies once rather than
    /// three times.
    pub fn translate<'a, DB: DatabaseLike>(
        &self,
        db: &'a DB,
    ) -> Result<Translation<'a, DB>, PlanningError> {
        let (classified, effective_registry) = self.classify_with_effective_registry(db);
        Translation::plan(
            classified,
            db,
            &effective_registry,
            self.min_confidence,
            &self.generator,
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

/// A planned translation of one schema.
///
/// Holding the plan is what makes the outputs cheap, and it is also what makes them
/// refusable: an expression nobody classified leaves the model denying what the
/// database grants, and that has to be seen rather than discovered later.
#[derive(Debug, Clone)]
pub struct Translation<'a, DB: DatabaseLike = ParserDB> {
    db: &'a DB,
    plan: SchemaPlan,
    policies: Vec<ClassifiedPolicy>,
    min_confidence: ConfidenceLevel,
}

impl<'a, DB: DatabaseLike> Translation<'a, DB> {
    /// Plan a translation from policies already classified, which is how an oracle's
    /// answers reach the generators.
    pub fn plan(
        policies: Vec<ClassifiedPolicy>,
        db: &'a DB,
        registry: &FunctionRegistry,
        min_confidence: ConfidenceLevel,
        settings: &GeneratorSettings,
    ) -> Result<Self, PlanningError> {
        let plan = build_filtered_schema_plan(&policies, db, registry, min_confidence, settings)?;
        Ok(Self {
            db,
            plan,
            policies,
            min_confidence,
        })
    }

    /// Everything the translation has to say about itself.
    #[must_use]
    pub fn notes(&self) -> &[TranslationNote] {
        &self.plan.notes
    }

    /// The expressions nobody classified. These are the only notes that make the model
    /// narrower than the database through a limitation of this crate rather than a
    /// choice the caller made.
    pub fn unhandled(&self) -> impl Iterator<Item = &TranslationNote> {
        self.notes()
            .iter()
            .filter(|note| note.severity() == NoteSeverity::Unhandled)
    }

    /// Every relation the emitted model declares, with the shapes whose records fill
    /// it and whether one row decides them.
    ///
    /// Reads the plan the translation already holds, so the answers follow the
    /// settings this translation was planned with.
    #[must_use]
    pub fn relations(&self) -> Vec<RelationShapes> {
        relation_shapes(&self.plan, self.db)
    }

    /// How rows of each table the model names are named as objects, which is what a
    /// consumer asking the authorization service about one changed row has to spell.
    ///
    /// Beside [`Translation::relations`] and read with it: the relations say what a type
    /// grants, this says which table's rows that type is. A partition is named after its
    /// root, so a row of one is asked about under the root's type.
    #[must_use]
    pub fn row_naming(&self) -> Vec<RowNaming> {
        row_naming(&self.plan, self.db)
    }

    /// Which relations answer each action the model covers, and which version of the
    /// row each of them judges.
    ///
    /// Read with [`Translation::relations`] and [`Translation::row_naming`]: those say
    /// what a type grants and how its rows are named, this says what to ask about one.
    /// Which relations exist depends on how a policy spelled its clauses, so deriving
    /// this from the emitted model is the case analysis it exists to remove.
    #[must_use]
    pub fn action_relations(&self) -> Vec<ActionRelations> {
        action_relations(&self.plan, self.db)
    }

    /// Every table the database restricts nothing on: row-level security is off on it, and
    /// off on every table it is a partition or an `INHERITS` child of, since a read through
    /// one of those applies that table's policies to these rows.
    ///
    /// Read beside [`Translation::action_relations`], and read positively: a table here
    /// shows every row to everybody, so a question about one of its rows is granted with
    /// nothing asked. A table absent from both this and the action report is one nothing
    /// covered, which says nothing about what the database allows.
    ///
    /// Reported by table because the emitted model defines no type for such a table.
    #[must_use]
    pub fn unrestricted_tables(&self) -> Vec<UnrestrictedTable> {
        unrestricted_tables(self.db)
    }

    /// The outputs, refused while any expression went unhandled.
    ///
    /// # Errors
    ///
    /// Returns the unhandled expressions, which is what a caller has to look at before
    /// trusting a model that denies what the database grants.
    pub fn outputs(self) -> Result<Outputs<'a, DB>, UnhandledExpressions> {
        let unhandled: Vec<TranslationNote> = self.unhandled().cloned().collect();
        if unhandled.is_empty() {
            Ok(Outputs(self))
        } else {
            Err(UnhandledExpressions { notes: unhandled })
        }
    }

    /// The outputs, gaps and all.
    ///
    /// Say this deliberately. For every expression [`Translation::unhandled`] names,
    /// the model denies what the database grants.
    #[must_use]
    pub fn outputs_accepting_gaps(self) -> Outputs<'a, DB> {
        Outputs(self)
    }
}

/// The outputs of a translation.
///
/// Reachable only through [`Translation::outputs`], which refuses while anything went
/// unhandled, or [`Translation::outputs_accepting_gaps`], which is one visible line
/// saying the caller took the narrower model on purpose.
#[derive(Debug, Clone)]
pub struct Outputs<'a, DB: DatabaseLike = ParserDB>(Translation<'a, DB>);

impl<'a, DB: DatabaseLike> Outputs<'a, DB> {
    /// The translation these outputs were rendered from, for the analysis
    /// surface ([`Translation::relations`], [`Translation::row_naming`],
    /// [`Translation::action_relations`], [`Translation::unrestricted_tables`])
    /// without cloning before [`Translation::outputs`] consumes it.
    #[must_use]
    pub fn translation(&self) -> &Translation<'a, DB> {
        &self.0
    }

    /// The `OpenFGA` DSL model.
    #[must_use]
    pub fn model(&self) -> String {
        render_dsl_from_plan(&self.0.plan)
    }

    /// The `OpenFGA` JSON authorization model.
    #[must_use]
    pub fn json_model(&self) -> AuthorizationModel {
        json_model_from_plan(&self.0.plan)
    }

    /// SQL that populates the relationship tuples.
    #[must_use]
    pub fn tuple_queries(&self) -> Vec<TupleQuery> {
        generate_tuple_queries_from_plan(&self.0.plan, self.0.db)
    }

    /// Read one row a [`Outputs::tuple_queries`] query returned back as the record
    /// it spells.
    ///
    /// The relation is looked up rather than taken, so a row naming something the
    /// model does not define is refused instead of loaded.
    ///
    /// # Errors
    ///
    /// Returns [`TupleRowError`] for a row this model has no such fact in.
    pub fn record_from_tuple_row(&self, row: TupleRow<'_>) -> Result<Record, TupleRowError> {
        record_from_tuple_row(&self.0.plan, row)
    }

    /// Everything the translation has to say about itself.
    #[must_use]
    pub fn notes(&self) -> &[TranslationNote] {
        self.0.notes()
    }

    /// Per-policy confidence levels.
    #[must_use]
    pub fn confidence_summary(&self) -> &[(String, ConfidenceLevel)] {
        &self.0.plan.confidence_summary
    }

    /// The markdown report, which is the only place a clause dropped by the threshold
    /// is visible.
    #[must_use]
    pub fn report(&self) -> String {
        build_report(self.notes(), &self.0.policies, self.0.min_confidence)
    }

    /// Write the model, the tuple SQL and the report into `output_dir`.
    ///
    /// # Errors
    ///
    /// Returns [`WriteError`] when the name is unusable as a filename or a write fails.
    #[cfg(feature = "std")]
    pub fn write(&self, output_dir: &Path, name: &str) -> Result<(), WriteError> {
        write_output(
            output_dir,
            name,
            &self.model(),
            &self.tuple_queries(),
            &self.report(),
        )
    }
}

/// Expressions nobody classified, which is what stops [`Translation::outputs`]
/// answering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnhandledExpressions {
    notes: Vec<TranslationNote>,
}

impl UnhandledExpressions {
    /// The notes naming each expression and why it was refused.
    #[must_use]
    pub fn notes(&self) -> &[TranslationNote] {
        &self.notes
    }
}

impl core::fmt::Display for UnhandledExpressions {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{} expression(s) went unhandled, so the model denies what the database grants",
            self.notes.len()
        )?;
        for note in &self.notes {
            write!(f, "\n  {}: {note}", note.subject())?;
        }
        Ok(())
    }
}

impl core::error::Error for UnhandledExpressions {}

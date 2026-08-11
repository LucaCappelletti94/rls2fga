#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use alloc::collections::{BTreeMap, BTreeSet};
use core::fmt::Write;

use crate::classifier::function_registry::{FunctionRegistry, SessionAttribute};
use crate::classifier::patterns::*;
use crate::classifier::recognizers::is_constantly_false;
use crate::generator::db_lookup::{
    composite_primary_key_columns, resolve_pk_columns, single_pk_column, table_has_column,
};
use crate::generator::identity::MAX_OBJECT_NAME_CHARS;
use crate::generator::ir::{PrincipalInfo, TupleSource};
use crate::generator::notes::{SkippedTuples, TranslationNote};
use crate::generator::relations::RequestComparison;
use crate::generator::role_relations::{sorted_role_relation_names, RoleRelationName};
use crate::generator::tuple_generator::{resolve_bridge_columns, UnboundedColumns};
use crate::generator::well_known::{
    can_delete_relation, can_insert_relation, can_insert_returning_relation,
    can_select_for_update_relation, can_select_relation, can_update_check_relation,
    can_update_relation, can_update_using_relation, can_update_without_reading_relation,
    can_upsert_relation, deny_relation, member_relation, owner_team_relation, owner_user_relation,
    public_relation, PG_ROLE_TYPE, REQUEST_TIME_PARAMETER, STRING_PARAMETER_TYPE, TEAM_TYPE,
    TIMESTAMP_PARAMETER_TYPE, USER_TYPE,
};
use crate::parser::expr::extract_column_name;
use crate::parser::expr::function_arg_expr;
use crate::parser::function_analyzer::FunctionSemantic;
use crate::parser::identifiers::{ColumnName, RelationName, TableId, TypeName};
use crate::parser::names::{
    canonical_fga_type_name, clamp_relation_name, conditional_gate_relation_name,
    gate_condition_name, is_owner_like_column_name, lookup_table,
    membership_read_scope_relation_name, normalize_identifier, normalize_relation_name,
    parent_type_from_fk_column, policy_scope_relation_name, role_limited_relation_name,
    same_identifier, stable_hex_suffix, yielded_relation_name, MAX_RELATION_RENAME_ATTEMPTS,
};
use crate::parser::sql_parser::{
    ColumnLike, DatabaseLike, ForeignKeyLike, PolicyLike, RoleLike, TableLike,
};
use sqlparser::ast::{Expr, Function, FunctionArguments};

/// Which relation a command reads, and how a policy's clauses reach it.
mod actions;
/// `OpenFGA` DSL text rendering from the schema plan.
mod dsl;
/// Emission for the patterns that reach through another row.
mod emit_membership;
/// Emission for the patterns one column of the row decides.
mod emit_ownership;
/// Emission for the patterns the request completes rather than the row.
mod emit_requests;
/// Emission for the patterns a role decides.
mod emit_roles;
/// Which statements `PostgreSQL` refuses to plan because the policies loop.
mod recursion;
/// Role-threshold resource-column inference and tuple-source population.
mod role_threshold;
/// Whole-plan passes that run once every table is translated.
mod simplify;

use actions::{
    action_relation_commands, action_relations, clauses_lost_to_the_threshold,
    commands_a_permissive_policy_covers, commands_fed_by, compose_action,
    define_blanket_update_relations, define_locking_read_relations, define_upsert_relations,
    derived_action_relations, dropped_attribute_guards, fill_uncovered_actions_with_deny,
    for_each_policy_target_expr, mark_narrowed, narrowed_by, policies_missing_a_clause,
    push_action_expr, scoped_policy_expr, targets_a_policy_feeds, ActionTarget, ModeBuckets,
    INHERITED_RELATION_PREFIX,
};
use dsl::render_dsl;
use emit_membership::{
    emit_abac_and, emit_composite, emit_exists_membership, emit_parent_inheritance,
    emit_uncorrelated_membership,
};
use emit_ownership::{
    emit_attribute_condition, emit_boolean_flag, emit_constant_bool, emit_row_ownership,
    emit_unclassified,
};
use emit_requests::{
    conditional_gate_expr, emit_membership_in_caller_set, emit_request_gate, RequestSide,
    RowParameterSource,
};
use emit_roles::{
    emit_numeric_threshold, emit_role_name_in_list, register_pg_role_scope, RoleScopeSpec,
};
use recursion::PolicyReadRecursion;
use role_threshold::{infer_role_threshold_resource_columns, populate_role_threshold_sources};
use simplify::{
    drop_implied_insert_readback, grants_nothing, inline_synthetic_rule_aliases,
    prune_unreferenced_relations, reach_userset, requires_read_access,
    simplify_redundant_select_gates,
};

/// `OpenFGA` authorization model schema version.
pub(crate) const OPENFGA_SCHEMA_VERSION: &str = "1.1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DirectSubject {
    Type(String),
    Wildcard(String),
    /// A wildcard every tuple of which carries a condition, so the grant holds only
    /// while the condition evaluates true at check time.
    ConditionalWildcard {
        type_name: String,
        condition: String,
    },
}

/// A condition the model declares and a relation reference names.
///
/// One `CEL` expression over parameters that arrive from two places: the tuple
/// carries what the row knows, the request carries what only it knows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConditionSpec {
    pub expression: String,
    /// Parameter name to its `OpenFGA` type, sorted so emission is stable.
    pub parameters: BTreeMap<String, ConditionParameter>,
    /// The parameter each tuple supplies, and where its value comes from.
    pub row_parameter: RowParameter,
}

/// A condition parameter's type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ConditionParameter {
    /// One value, named as the API names it.
    Scalar(&'static str),
    /// A list of values of the named element type.
    ListOf(&'static str),
}

/// What a tuple puts in the context under the parameter the request cannot supply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RowParameter {
    /// Read from this column of the row.
    Column {
        /// The condition parameter the value fills.
        parameter: String,
        /// The column the value comes from.
        column: ColumnName,
    },
    /// A constant the policy named, so every row of the table carries the same one.
    Literal {
        /// The condition parameter the value fills.
        parameter: String,
        /// The constant.
        value: String,
    },
}

impl RowParameter {
    /// The parameter this tuple side fills.
    pub(crate) fn parameter(&self) -> &str {
        match self {
            Self::Column { parameter, .. } | Self::Literal { parameter, .. } => parameter,
        }
    }

    /// The column a row reads it from, `None` for a constant.
    pub(crate) fn column(&self) -> Option<&ColumnName> {
        match self {
            Self::Column { column, .. } => Some(column),
            Self::Literal { .. } => None,
        }
    }
}

/// Structural identity of a subject list, stable against `Debug` formatting.
fn subject_key(subjects: &[DirectSubject]) -> String {
    subjects
        .iter()
        .map(|subject| match subject {
            DirectSubject::Type(name) => format!("t:{name}"),
            DirectSubject::Wildcard(name) => format!("w:{name}"),
            DirectSubject::ConditionalWildcard {
                type_name,
                condition,
            } => format!("wc:{type_name}:{condition}"),
        })
        .collect::<Vec<_>>()
        .join(",")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UsersetExpr {
    Computed(RelationName),
    TupleToUserset {
        tupleset: RelationName,
        computed: RelationName,
    },
    Union(Vec<UsersetExpr>),
    Intersection(Vec<UsersetExpr>),
    /// `base` minus `subtract`, the only way to negate a userset in `OpenFGA`.
    Exclusion {
        base: Box<UsersetExpr>,
        subtract: Box<UsersetExpr>,
    },
}

/// Structural identity of a userset expression, stable against `Debug` formatting.
fn userset_key(expr: &UsersetExpr) -> String {
    match expr {
        UsersetExpr::Computed(name) => format!("c:{name}"),
        UsersetExpr::TupleToUserset { tupleset, computed } => format!("t:{tupleset}:{computed}"),
        UsersetExpr::Union(children) => format!("u({})", child_keys(children)),
        UsersetExpr::Intersection(children) => format!("i({})", child_keys(children)),
        UsersetExpr::Exclusion { base, subtract } => {
            format!("x({},{})", userset_key(base), userset_key(subtract))
        }
    }
}

fn child_keys(children: &[UsersetExpr]) -> String {
    children
        .iter()
        .map(userset_key)
        .collect::<Vec<_>>()
        .join(",")
}

#[derive(Debug, Clone, Default)]
pub(crate) struct TypePlan {
    pub type_name: TypeName,
    pub direct_relations: BTreeMap<RelationName, Vec<DirectSubject>>,
    pub computed_relations: BTreeMap<RelationName, UsersetExpr>,
    /// Table-level tuple sources not tied to a specific relation (e.g. policy
    /// scope tuples).
    pub table_tuple_sources: Vec<TupleSource>,
    /// Ownership column → its relation. Sharing one would union distinct principals.
    ownership_relations: BTreeMap<String, RelationName>,
    /// Conditions this type's own relation references name, keyed by condition name.
    /// They live here rather than threaded through translation so a condition stays
    /// beside the relation that needs it.
    pub conditions: BTreeMap<String, ConditionSpec>,
    /// The table has `INHERITS` children, so queries minting this type's objects read
    /// `FROM ONLY`: the key does not span child rows, and a shared value would merge
    /// two rows into one object.
    pub reads_only_its_own_rows: bool,
    /// Action relations whose emitted rule came out narrower, or wider, than the
    /// database because a clause `PostgreSQL` evaluates was lost. Read where
    /// decidability is answered, so a consumer answering reads from the recipe
    /// delegates instead of guessing. An entry naming a relation this plan never
    /// defines is inert.
    pub narrowed_relations: BTreeSet<RelationName>,
    /// Table whose rows this type names, in the schema's own spelling, absent for a
    /// type nothing keys on a row (`user`, a team, a holder). Written where the type
    /// name is bound to the table, so nothing has to re-derive the association from
    /// the shapes, where two tables can key a row alike.
    pub source_table: Option<String>,
}

/// Subjects the generator's own structural relations hold, or `None` when the
/// name is free. These relations are referenced by name, so any other caller
/// asking for one is renamed regardless of translation order.
fn reserved_relation_subjects(relation: &RelationName) -> Option<Vec<DirectSubject>> {
    if *relation == deny_relation()
        || *relation == member_relation()
        || *relation == owner_user_relation()
    {
        Some(vec![DirectSubject::Type(USER_TYPE.to_string())])
    } else if *relation == public_relation() {
        Some(vec![DirectSubject::Wildcard(USER_TYPE.to_string())])
    } else if *relation == owner_team_relation() {
        Some(vec![DirectSubject::Type(TEAM_TYPE.to_string())])
    } else {
        None
    }
}

/// Whether the generator defines `relation` itself once the actions are assembled,
/// so a translated name taking it would be defined twice.
fn generator_defines(relation: &RelationName) -> bool {
    action_relations()
        .chain(derived_action_relations())
        .any(|reserved| reserved == *relation)
}

impl TypePlan {
    fn new(type_name: impl Into<String>) -> Self {
        Self {
            type_name: TypeName::from_resolved(type_name),
            ..Self::default()
        }
    }

    /// Record which table's rows this type names, keeping the first spelling bound to
    /// it: a parent reached from a child is bound before the parent's own group is
    /// built, and both name one table.
    fn names_rows_of(&mut self, table: &str) {
        if self.source_table.is_none() {
            self.source_table = Some(table.to_string());
        }
    }

    /// Relation carrying the subjects of an ownership source, named after
    /// `name_source` (`owner_id` → `owner`) and disambiguated on collision.
    ///
    /// `memo_key` namespaces the reuse: a jsonb path and a column spelled alike must
    /// not share a relation, or their two tuple sources union their principals.
    fn ownership_relation(&mut self, memo_key: &str, name_source: &str) -> RelationName {
        if let Some(existing) = self.ownership_relations.get(memo_key) {
            return existing.clone();
        }

        let base = parent_type_from_fk_column(name_source);
        let taken = |name: &str, plan: &Self| {
            let name = RelationName::from_resolved(name);
            reserved_relation_subjects(&name).is_some()
                || generator_defines(&name)
                || plan.direct_relations.contains_key(&name)
                || plan.computed_relations.contains_key(&name)
        };
        let relation = RelationName::from_resolved(clamp_relation_name(if taken(&base, self) {
            let fallback = format!("owner_{}", canonical_fga_type_name(name_source));
            if taken(&fallback, self) {
                format!("{fallback}_{}", stable_hex_suffix(memo_key))
            } else {
                fallback
            }
        } else {
            base
        }));

        self.ownership_relations
            .insert(memo_key.to_string(), relation.clone());
        relation
    }

    /// Register a directly-assignable relation, returning the name actually used.
    fn ensure_direct(
        &mut self,
        relation: impl Into<String>,
        subjects: Vec<DirectSubject>,
    ) -> RelationName {
        let base = clamp_relation_name(relation.into());
        let key = subject_key(&subjects);
        let mut relation = RelationName::from_resolved(base.clone());
        // A name already held must yield rather than emit a second `define` or inherit
        // subjects it does not accept. The yielded name can be held too, since it is derived
        // from the value while whatever holds it may come from the schema, so keep looking:
        // the two maps are separate, and inserting blind would declare one name twice.
        for attempt in 0..MAX_RELATION_RENAME_ATTEMPTS {
            let held = self.computed_relations.contains_key(&relation)
                || self
                    .direct_relations
                    .get(&relation)
                    .is_some_and(|held| *held != subjects)
                || reserved_relation_subjects(&relation).is_some_and(|held| held != subjects)
                || generator_defines(&relation);
            if !held {
                break;
            }
            relation = yielded_relation_name(&base, &key, attempt);
        }
        self.direct_relations
            .entry(relation.clone())
            .or_insert(subjects);
        relation
    }

    fn ensure_computed(&mut self, relation: impl Into<String>, expr: UsersetExpr) -> RelationName {
        let base = clamp_relation_name(relation.into());
        let key = userset_key(&expr);
        let mut relation = RelationName::from_resolved(base.clone());
        // One name, one rule, or a caller deriving the name reads the wrong definition.
        for attempt in 0..MAX_RELATION_RENAME_ATTEMPTS {
            let held = self.direct_relations.contains_key(&relation)
                || self
                    .computed_relations
                    .get(&relation)
                    .is_some_and(|held| *held != expr)
                || generator_defines(&relation);
            if !held {
                break;
            }
            relation = yielded_relation_name(&base, &key, attempt);
        }
        self.computed_relations
            .entry(relation.clone())
            .or_insert(expr);
        relation
    }

    fn set_computed(&mut self, relation: impl Into<String>, expr: UsersetExpr) -> RelationName {
        let mut relation = RelationName::from_resolved(clamp_relation_name(relation.into()));
        // A name a direct relation already holds yields, exactly as `ensure_direct` and
        // `ensure_computed` do. Overwriting a computed rule is this function's whole
        // job, so only the direct case is a clash.
        if self.direct_relations.contains_key(&relation) {
            let key = userset_key(&expr);
            relation = RelationName::from_resolved(clamp_relation_name(format!(
                "{relation}_{}",
                stable_hex_suffix(key.as_str())
            )));
        }
        self.computed_relations.insert(relation.clone(), expr);
        relation
    }

    fn add_source(&mut self, source: TupleSource) {
        self.table_tuple_sources.push(source);
    }
}

/// Choices a deployment makes about the emitted model.
///
/// One struct rather than a growing parameter list, so the next setting costs a field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratorSettings {
    /// Condition parameter the caller supplies for a guard against statement time. It
    /// is the name every check context must use, so a deployment with its own
    /// convention sets it here.
    pub request_time_parameter: String,
}

impl Default for GeneratorSettings {
    fn default() -> Self {
        Self {
            request_time_parameter: REQUEST_TIME_PARAMETER.to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SchemaPlan {
    pub types: Vec<TypePlan>,
    pub notes: Vec<TranslationNote>,
    pub confidence_summary: Vec<(String, ConfidenceLevel)>,
    /// Conditions any relation reference names, keyed by name.
    pub conditions: BTreeMap<String, ConditionSpec>,
}

/// Pre-computed per-`(table, function_name)` resource column hints for P1/P2
/// patterns.  Populated once per `build_schema_plan` call by walking the raw
/// policy `Expr` AST before pattern translation begins.
#[derive(Debug, Clone, Default)]
pub(crate) struct RoleThresholdResourceHints {
    /// `(table, function_name)` → resource column name (unambiguous cases).
    pub columns: BTreeMap<(String, String), ColumnName>,
    /// `(table, function_name)` pairs where multiple distinct resource columns
    /// were observed; these cannot be resolved to a single tuple join column.
    pub conflicts: BTreeSet<(String, String)>,
}

/// Render the DSL text for a plan.
pub(crate) fn render_dsl_from_plan(plan: &SchemaPlan) -> String {
    render_dsl(&plan.types, &plan.conditions)
}

pub(crate) fn build_filtered_schema_plan<DB: DatabaseLike>(
    policies: &[ClassifiedPolicy],
    db: &DB,
    registry: &FunctionRegistry,
    min_confidence: ConfidenceLevel,
    settings: &GeneratorSettings,
) -> SchemaPlan {
    let filtered = filter_policies_for_output(policies, min_confidence);
    build_schema_plan(&filtered, db, registry, settings)
}

pub(crate) fn build_schema_plan<DB: DatabaseLike>(
    policies: &[ClassifiedPolicy],
    db: &DB,
    registry: &FunctionRegistry,
    settings: &GeneratorSettings,
) -> SchemaPlan {
    build_plan_typing(policies, db, registry, settings, TypeScope::WithPolicies)
}

/// Which tables earn a type, which is the schema's row-level security everywhere except
/// on the term route, where a subscription filter guards a table that needs no policy.
#[derive(Debug, Clone, Copy)]
pub(crate) enum TypeScope<'a> {
    WithPolicies,
    AndAlso(&'a str),
}

/// Every classified policy under the key its table resolves to, plus a seeded entry for each
/// row-level-security table no policy named.
///
/// Keyed by the schema's own spelling, since two policies may quote the table differently and
/// one table must be built once. `group_keys` memoizes the resolution, which walks the tables,
/// and every policy on one table repeats it.
fn group_policies_by_table<'a, DB: DatabaseLike>(
    policies: &'a [ClassifiedPolicy],
    db: &DB,
    group_keys: &mut BTreeMap<String, String>,
) -> BTreeMap<String, Vec<&'a ClassifiedPolicy>> {
    let mut by_table: BTreeMap<String, Vec<&ClassifiedPolicy>> = BTreeMap::new();
    for cp in policies {
        let key = table_group_key(db, cp.table_name().to_string(), group_keys);
        by_table.entry(key).or_default().push(cp);
    }

    // An RLS-enabled table with no policy denies every row, so seed it and let
    // the deny fill downstream cover its commands.
    let covered: BTreeSet<TableId> = by_table
        .keys()
        .filter_map(|name| lookup_table(db, name))
        .map(table_identity)
        .collect();
    for table in db.tables() {
        // A table whose RLS state cannot be read must still be deny-filled: a table
        // absent from the model reads as unconstrained.
        if table.has_row_level_security(db) == Ok(false) || covered.contains(&table_identity(table))
        {
            continue;
        }
        by_table.entry(qualified_table_name(table)).or_default();
    }
    by_table
}

/// The schema's own permissive policies, under the same key the classifications use.
///
/// The filtered set cannot say whether a policy exists at all. Splitting the two keys would
/// tell the operator RLS denies a command its own policy grants.
fn declared_permissive_policies<'a, DB: DatabaseLike>(
    db: &'a DB,
    group_keys: &mut BTreeMap<String, String>,
) -> BTreeMap<String, Vec<&'a DB::Policy>> {
    let mut declared: BTreeMap<String, Vec<&DB::Policy>> = BTreeMap::new();
    for policy in db.policies() {
        if derive_policy_mode(policy) != PolicyMode::Permissive {
            continue;
        }
        let key = table_group_key(db, policy.target_table_name().to_string(), group_keys);
        declared.entry(key).or_default().push(policy);
    }
    declared
}

/// Parent identity to the spellings of its `INHERITS` children.
///
/// One pass, since `inheritors` walks every table per call. Partitions are not in this edge: a
/// partitioned root holds no rows of its own and its key spans every partition, so its plain
/// read is exact.
fn inheritance_children<DB: DatabaseLike>(db: &DB) -> BTreeMap<TableId, Vec<String>> {
    let mut children: BTreeMap<TableId, Vec<String>> = BTreeMap::new();
    for table in db.tables() {
        // A table iterated out of `db` is in `db`, so an unreadable parent list is
        // an empty one.
        for parent in table.inherits_from(db).into_iter().flatten() {
            children
                .entry(table_identity(parent))
                .or_default()
                .push(qualified_table_name(table));
        }
    }
    children
}

/// Run `build` against one table's plan, taken out of `all_types` and put back after.
///
/// The plan has to leave the map for the duration: `translate_pattern` mints parent and holder
/// types, so it needs `&mut all_types` at the same time, and nothing can hold both that and a
/// borrow of one entry. Bracketing the pair is what stops it being half-written. Writing into
/// `all_types` for the table currently being built is discarded by the put-back, which is on the
/// trap list twice, and the closure's two arguments say which of the two to reach for.
fn with_table_plan<R>(
    all_types: &mut BTreeMap<String, TypePlan>,
    type_name: &str,
    build: impl FnOnce(&mut TypePlan, &mut BTreeMap<String, TypePlan>) -> R,
) -> R {
    let mut plan = all_types
        .remove(type_name)
        .unwrap_or_else(|| TypePlan::new(type_name));
    let out = build(&mut plan, all_types);
    all_types.insert(type_name.to_string(), plan);
    out
}

pub(crate) fn build_plan_typing<DB: DatabaseLike>(
    policies: &[ClassifiedPolicy],
    db: &DB,
    registry: &FunctionRegistry,
    settings: &GeneratorSettings,
    scope: TypeScope<'_>,
) -> SchemaPlan {
    // Pre-compute resource column hints for P1/P2 role-threshold patterns.
    // This walks the raw policy Expr AST once up-front so that
    // pattern_to_expr_for_target can use the resolved column during translation.
    let role_threshold_resource_hints = infer_role_threshold_resource_columns(policies, registry);

    let mut all_types: BTreeMap<String, TypePlan> = BTreeMap::new();
    let mut notes = Vec::new();
    let mut confidence_summary = Vec::new();

    for function in registry.owner_bound_accessors() {
        notes.push(TranslationNote::OwnerBoundFunction {
            function: function.to_string(),
        });
    }

    let mut group_keys: BTreeMap<String, String> = BTreeMap::new();
    let by_table = group_policies_by_table(policies, db, &mut group_keys);

    report_row_level_security_bypasses(db, &mut notes);

    let declared_permissive = declared_permissive_policies(db, &mut group_keys);

    let table_types = TableTypes::assign(db, scope, &mut notes);
    let recursion = PolicyReadRecursion::detect(db, &table_types);
    // Resolved once for the whole plan, like the recursion graph above it: asking per
    // table went through `lookup_table`, which walks every table.
    let bounds = UnboundedColumns::resolve(db);
    // Answered once per membership table rather than once per clause naming it.
    let mut readability: BTreeMap<String, JoinTableReadability> = BTreeMap::new();
    let readability = &mut readability;

    let inheritance_children = inheritance_children(db);

    // Types a policy may have narrowed that no name resolved to. Applied after the
    // loop, since a bearer may be built after the group that named it.
    let mut unresolved_losses: BTreeMap<String, BTreeSet<RelationName>> = BTreeMap::new();

    for (source_table_name, table_policies) in by_table {
        // Only RLS-enabled tables that resolve against the schema get a type. A name
        // the schema cannot resolve carries the policy nowhere, so say so.
        let Some(canonical_table_name) = table_types.get(db, &source_table_name) else {
            if lookup_table(db, &source_table_name).is_none() {
                let bearers = types_bearing_name(db, &source_table_name, &table_types);
                for cp in &table_policies {
                    notes.push(TranslationNote::UnresolvedPolicyTable {
                        policy: cp.name().to_string(),
                        named: source_table_name.clone(),
                    });
                    let lost: BTreeSet<RelationName> = narrowed_by(&targets_a_policy_feeds(cp));
                    for bearer in &bearers {
                        unresolved_losses
                            .entry(bearer.clone())
                            .or_default()
                            .extend(lost.iter().cloned());
                    }
                }
            }
            continue;
        };
        let canonical_table_name = canonical_table_name.to_string();

        with_table_plan(
            &mut all_types,
            &canonical_table_name,
            |table_plan, other_types| {
                table_plan.names_rows_of(&source_table_name);

                // Once per table: `by_table` holds each table exactly once.
                let children = lookup_table(db, &source_table_name)
                    .map(table_identity)
                    .and_then(|identity| inheritance_children.get(&identity))
                    .cloned()
                    .unwrap_or_default();
                if !children.is_empty() {
                    table_plan.reads_only_its_own_rows = true;
                    let mut children = children;
                    children.sort();
                    notes.push(TranslationNote::InheritanceParentReadsOwnRowsOnly {
                        table: source_table_name.clone(),
                        children,
                    });
                }

                // A clause reading a table whose policies loop cannot be planned, so PostgreSQL
                // raises rather than filtering and every command that clause feeds must deny.
                let recursive_targets = recursion.blocked_targets(&canonical_table_name);

                // Whether a row of this table can be named at all, which decides whether any tuple
                // source can be emitted for it. Resolved once here rather than per policy.
                let object_identifier = resolve_pk_columns(&source_table_name, db);

                // UPDATE and DELETE name the row they change. INSERT does not.
                let has_row_scoped_write_policy = table_policies.iter().any(|cp| {
                    cp.mode() == PolicyMode::Permissive
                        && matches!(
                            cp.command(),
                            PolicyCommand::Update | PolicyCommand::Delete | PolicyCommand::All
                        )
                });

                // Every clause PostgreSQL evaluates that the model does not carry leaves the
                // relations it fed diverged from the database. Collected before anything is
                // translated, so a partial drop scars exactly like a total one rather than
                // resting on `no_access` happening to have no feeding sources. The note and
                // the scar are built from the same targets, so the two cannot disagree.
                let mut update_check_was_filtered = false;
                for cp in &table_policies {
                    for (clause, confidence, targets) in clauses_lost_to_the_threshold(cp) {
                        // A target the read loop already blocks is denied by PostgreSQL too, so
                        // the model is not narrower there and nothing may claim a divergence.
                        let targets: Vec<ActionTarget> = targets
                            .into_iter()
                            .filter(|target| !recursive_targets.contains_key(target))
                            .collect();
                        if targets.is_empty() {
                            continue;
                        }
                        if cp.mode() == PolicyMode::Permissive
                            && targets.contains(&ActionTarget::UpdateCheck)
                        {
                            update_check_was_filtered = true;
                        }
                        mark_narrowed(table_plan, &targets);
                        notes.push(TranslationNote::ClauseBelowThreshold {
                            table: source_table_name.clone(),
                            policy: cp.name().to_string(),
                            mode: cp.mode().to_string(),
                            clause: clause.to_string(),
                            confidence,
                            commands: commands_fed_by(&targets),
                            relations: narrowed_by(&targets).into_iter().collect(),
                        });
                    }
                }

                let mut build = TableBuild {
                    source_table: &source_table_name,
                    plan: table_plan,
                    other_types,
                    notes: &mut notes,
                    readability,
                    confidence_summary: &mut confidence_summary,
                    db,
                    registry,
                    settings,
                    table_types: &table_types,
                    hints: &role_threshold_resource_hints,
                };
                let action_buckets = build.translate_policies(
                    table_policies,
                    &recursive_targets,
                    object_identifier.as_ref(),
                );

                // A grant whose facts cannot be written is a permission nothing can satisfy, so
                // each one above fell closed. Read the losses back off the skips they recorded,
                // rather than collecting them a second time, so the note and the loader's script
                scar_unfillable_grants(
                    build.plan,
                    build.notes,
                    &source_table_name,
                    &canonical_table_name,
                    &bounds,
                    db,
                );
                note_request_contracts(build.plan, build.notes, settings);

                let blocked_commands = build.set_action_relations(
                    &action_buckets,
                    &recursive_targets,
                    update_check_was_filtered,
                );

                // An undefined action relation reads as "the consumer decides", which is
                // how RLS coverage gaps become open access.
                let declared_here: &[&DB::Policy] = declared_permissive
                    .get(&source_table_name)
                    .map_or(&[], Vec::as_slice);
                fill_and_report_coverage(
                    build.plan,
                    build.notes,
                    &source_table_name,
                    declared_here,
                    &blocked_commands,
                    has_row_scoped_write_policy,
                    db,
                );
            },
        );
    }

    // A policy whose table did not resolve may have been the one granting any table
    // bearing that name, and a dump does not record which, so each carries the loss.
    for (type_name, relations) in unresolved_losses {
        if let Some(plan) = all_types.get_mut(&type_name) {
            plan.narrowed_relations.extend(relations);
        }
    }

    all_types
        .entry(USER_TYPE.to_string())
        .or_insert_with(|| TypePlan::new(USER_TYPE));

    simplify_redundant_select_gates(&mut all_types);
    inline_synthetic_rule_aliases(&mut all_types);
    drop_implied_insert_readback(&mut all_types);
    define_upsert_relations(&mut all_types);
    define_locking_read_relations(&mut all_types);
    define_blanket_update_relations(&mut all_types);
    prune_unreferenced_relations(&mut all_types);

    let types = ordered_types(all_types);
    let conditions = surviving_conditions(&types);

    SchemaPlan {
        types,
        notes,
        confidence_summary,
        conditions,
    }
}

/// One table's build in progress.
///
/// The stages share the plan under construction, the map of the other types, the accumulators and
/// the read-only context. Threading those as arguments is what made the widest stage need fifteen
/// of them, so they live here and each stage takes only what varies.
struct TableBuild<'a, DB: DatabaseLike> {
    /// Table as the schema spells it.
    source_table: &'a str,
    /// The plan being built, out of the map for the duration.
    plan: &'a mut TypePlan,
    /// Every other type, which minting a parent or a holder reaches.
    other_types: &'a mut BTreeMap<String, TypePlan>,
    /// Everything the translation has to say.
    notes: &'a mut Vec<TranslationNote>,
    /// Which membership tables a caller can read, answered once each.
    readability: &'a mut BTreeMap<String, JoinTableReadability>,
    /// Per-clause grades, for the report.
    confidence_summary: &'a mut Vec<(String, ConfidenceLevel)>,
    /// The schema.
    db: &'a DB,
    /// Function semantics.
    registry: &'a FunctionRegistry,
    /// Caller-chosen names the emitted conditions respect.
    settings: &'a GeneratorSettings,
    /// Which table each type name belongs to.
    table_types: &'a TableTypes,
    /// Resource columns inferred for the role-threshold patterns.
    hints: &'a RoleThresholdResourceHints,
}

impl<DB: DatabaseLike> TableBuild<'_, DB> {
    /// Translate every clause of this table's policies into the buckets each action collects.
    ///
    /// The widest stage of the build, and the reason this is a value rather than a function: as
    /// free arguments it would take fifteen.
    fn translate_policies(
        &mut self,
        table_policies: Vec<&ClassifiedPolicy>,
        recursive_targets: &BTreeMap<ActionTarget, &[String]>,
        object_identifier: Option<&Vec<ColumnName>>,
    ) -> BTreeMap<ActionTarget, ModeBuckets> {
        let mut action_buckets: BTreeMap<ActionTarget, ModeBuckets> = BTreeMap::new();

        for cp in table_policies {
            self.translate_one_policy(
                cp,
                recursive_targets,
                object_identifier,
                &mut action_buckets,
            );
        }
        action_buckets
    }

    /// Translate one policy's clauses into the buckets its targets collect.
    ///
    /// One policy at a time, because a policy is the unit `PostgreSQL` combines: its mode decides
    /// whether a role scope narrows the grant or merely binds it, and its clauses are reported once
    /// per policy however many phases they cover.
    fn translate_one_policy(
        &mut self,
        cp: &ClassifiedPolicy,
        recursive_targets: &BTreeMap<ActionTarget, &[String]>,
        object_identifier: Option<&Vec<ColumnName>>,
        action_buckets: &mut BTreeMap<ActionTarget, ModeBuckets>,
    ) {
        // A policy the schema gives no clause constrains nothing, so it must not
        // mint a scope relation or ask for tuples either.
        if cp.using.is_none() && cp.with_check.is_none() {
            return;
        }
        // The threshold emptied this one, so it contributes no expression and must
        // not mint a scope relation, a note or a summary entry either. What it cost
        // is already recorded above.
        if cp.mode() == PolicyMode::Permissive
            && cp.using_classification.is_none()
            && cp.with_check_classification.is_none()
        {
            return;
        }
        // A clause PostgreSQL refuses to store never came out of a database, so
        // nothing downstream may read it as one. The INSERT spelling would
        // otherwise mint a grant through the USING-to-check mirror.
        if let Some(rule) =
            clause_illegal_for_command(cp.command(), cp.using.is_some(), cp.with_check.is_some())
        {
            self.notes.push(TranslationNote::PolicyClauseIllegal {
                policy: cp.name().to_string(),
                rule: rule.to_string(),
            });
            return;
        }
        // Nor may a policy every target of which is blocked: the loop denies each of
        // them, so a scope relation minted here would ask for tuples nothing reads.
        let mut reached = BTreeSet::new();
        for_each_policy_target_expr(cp, |target, _| {
            reached.insert(target);
        });
        if !reached.is_empty()
            && reached
                .iter()
                .all(|target| recursive_targets.contains_key(target))
        {
            return;
        }
        // PostgreSQL resolves these spellings to the DDL-running role when the
        // policy is created, so a schema file cannot know who they bind. Fall
        // closed per mode: a permissive grant is dropped, and a barrier binds
        // everyone by keeping its scope empty, named roles beside the spelling
        // included, since a barrier that also binds the DDL runner cannot be
        // narrowed to the names alone.
        let scope_unknowable = !cp.ddl_time_roles().is_empty();
        if scope_unknowable {
            self.notes.push(TranslationNote::PolicyBoundToDdlTimeRole {
                policy: cp.name().to_string(),
                spellings: cp.ddl_time_roles().to_vec(),
            });
            if cp.mode() == PolicyMode::Permissive {
                mark_narrowed(self.plan, &targets_a_policy_feeds(cp));
                return;
            }
        }
        if let Some(ref c) = cp.using_classification {
            self.confidence_summary
                .push((cp.name().to_string(), c.confidence));
        }
        if let Some(ref c) = cp.with_check_classification {
            self.confidence_summary
                .push((format!("{} (WITH CHECK)", cp.name()), c.confidence));
        }

        let scoped_roles: &[String] = if scope_unknowable {
            &[]
        } else {
            cp.scoped_roles()
        };
        // A barrier is folded as `(base and rule) or (base but not member from scope)`, so
        // an unfillable scope excuses everyone from it. Binding everyone instead denies
        // more than RLS does, which is the direction a missing input has to take. The
        // permissive side needs no such case: it intersects with the scope, so an empty
        // one already falls closed.
        let barrier_cannot_bind = !scoped_roles.is_empty()
            && cp.mode() == PolicyMode::Restrictive
            && object_identifier.is_none();
        if barrier_cannot_bind {
            self.notes
                .push(TranslationNote::RestrictiveBarrierBindsEveryone {
                    policy: cp.name().to_string(),
                    roles: scoped_roles.to_vec(),
                });
        }
        let scope_relation = if scoped_roles.is_empty() || barrier_cannot_bind {
            None
        } else {
            let relation = policy_scope_relation_name(cp.name());
            // An unfillable scope mints nothing, and the rule it would have narrowed
            // denies for want of the same row identity, so there is no grant left to
            // narrow. Naming it anyway would ask the operator to load memberships
            // nothing reads.
            let filled = register_pg_role_scope(
                self.plan,
                &mut *self.other_types,
                self.notes,
                self.source_table,
                cp.name(),
                self.db,
                RoleScopeSpec {
                    scope_relation: &relation,
                    walked: &RolePrivilege::Usage.relation_name(),
                    role_names: scoped_roles,
                    scope_note: TranslationNote::PolicyRoleScope {
                        policy: cp.name().to_string(),
                        roles: scoped_roles.to_vec(),
                        relation: relation.clone(),
                    },
                    missing_object_what: "policy scope tuples",
                },
            );
            filled.then_some(relation)
        };

        // A policy covering several phases is translated once per phase, so the
        // same clause reports the same item repeatedly. Keep one per policy.
        let notes_before = self.notes.len();
        for_each_policy_target_expr(cp, |target, classified| {
            if recursive_targets.contains_key(&target) {
                // Nothing here can be planned, so translating it leaves dead relations.
                return;
            }
            let expr = translate_pattern(
                &classified.pattern,
                &PatternCtx {
                    policy_name: cp.name(),
                    registry: self.registry,
                    hints: self.hints,
                    db: self.db,
                    table_types: self.table_types,
                    source_table: self.source_table,
                    settings: self.settings,
                },
                self.plan,
                &mut *self.other_types,
                self.notes,
                self.readability,
            );
            // A restrictive clause is a barrier, so a dropped conjunct must still deny.
            let guards = dropped_attribute_guards(&classified.pattern);
            let expr = if cp.mode() == PolicyMode::Restrictive && !guards.is_empty() {
                // The denial supersedes any runtime-enforcement note for the guard.
                for guard in guards {
                    let superseded = TranslationNote::AttributeNeedsRuntimeEnforcement {
                        policy: cp.name().to_string(),
                        attribute: guard.to_string(),
                    };
                    self.notes.retain(|note| *note != superseded);
                }
                self.notes
                    .push(TranslationNote::RestrictiveAttributeRefused {
                        policy: cp.name().to_string(),
                    });
                UsersetExpr::Intersection(vec![expr, deny_expr(self.plan)])
            } else {
                // A permissive conjunct handed to the application is enforced
                // nowhere in this model, so the rule grants rows the database
                // refuses. The one drift that widens rather than narrows.
                if !guards.is_empty() {
                    mark_narrowed(self.plan, &[target]);
                }
                expr
            };
            push_action_expr(
                action_buckets,
                target,
                cp.name(),
                cp.mode(),
                expr,
                scope_relation.as_ref(),
            );
        });
        dedup_notes_added_since(self.notes, notes_before);
    }

    /// Compose each action's rule from its buckets and assign the relations it answers for.
    ///
    /// The densest decision in the build. A per-row `UPDATE` or `DELETE` names the row it changes,
    /// so `PostgreSQL` applies the `SELECT` policies too and these relations intersect the read. A
    /// blanket `UPDATE` names no row and reads nothing, so it gets its own relation instead. A
    /// command whose targets a policy loop blocks is denied here rather than deny-filled, and a
    /// dropped permissive check must not come back as the `USING` it was refused beside.
    ///
    /// Returns the commands a loop denied, which the coverage report must not blame on a missing
    /// policy.
    fn set_action_relations(
        &mut self,
        action_buckets: &BTreeMap<ActionTarget, ModeBuckets>,
        recursive_targets: &BTreeMap<ActionTarget, &[String]>,
        update_check_was_filtered: bool,
    ) -> BTreeSet<&'static str> {
        let mut select_expr = compose_action(self.plan, action_buckets.get(&ActionTarget::Select));
        let mut insert_expr = compose_action(self.plan, action_buckets.get(&ActionTarget::Insert));
        let mut update_using_expr =
            compose_action(self.plan, action_buckets.get(&ActionTarget::UpdateUsing));
        // Composed only where an existing row can pass, since a WITH CHECK admits
        // the new row alone and never stands in for the missing USING.
        let mut update_check_expr = update_using_expr
            .is_some()
            .then(|| compose_action(self.plan, action_buckets.get(&ActionTarget::UpdateCheck)));
        let mut delete_expr = compose_action(self.plan, action_buckets.get(&ActionTarget::Delete));

        // Skipping the blocked targets above left their buckets empty, so the deny fill
        // below already answers for them. The UPDATE pair is the exception: a check the
        // fill never sees would fall back to mirroring the USING, which grants.
        if recursive_targets.contains_key(&ActionTarget::UpdateUsing)
            || recursive_targets.contains_key(&ActionTarget::UpdateCheck)
        {
            update_using_expr = None;
            update_check_expr = None;
        }

        // One note per loop, naming the commands it denies. A command denies as soon as
        // one of its targets is blocked, and its own coverage gap is then the loop rather
        // than a missing or dropped policy.
        let mut denied_by_loop: BTreeMap<&[String], Vec<&'static str>> = BTreeMap::new();
        for (_, command, targets) in action_relation_commands() {
            if let Some(cycle) = targets
                .iter()
                .find_map(|target| recursive_targets.get(target))
            {
                denied_by_loop.entry(cycle).or_default().push(command);
            }
        }
        let blocked_commands: BTreeSet<&'static str> =
            denied_by_loop.values().flatten().copied().collect();
        for (cycle, commands) in denied_by_loop {
            self.notes.push(TranslationNote::PolicyReadRecursion {
                table: self.source_table.to_string(),
                commands: commands.into_iter().map(ToString::to_string).collect(),
                cycle: cycle.to_vec(),
            });
        }

        if let Some(expr) = select_expr.take() {
            self.plan.set_computed(can_select_relation(), expr);
        }
        if let Some(expr) = insert_expr.take() {
            self.plan.set_computed(
                can_insert_returning_relation(),
                requires_read_access(expr.clone()),
            );
            self.plan.set_computed(can_insert_relation(), expr);
        }
        // PostgreSQL applies the SELECT policies to any row a statement reads, and
        // naming the row to change reads it.
        if let Some(expr) = delete_expr.take() {
            self.plan
                .set_computed(can_delete_relation(), requires_read_access(expr));
        }

        if let Some(using_expr) = update_using_expr.take() {
            // A permissive check the threshold dropped must not come back as the USING.
            // `for_each_policy_target_expr` suppresses the mirror per policy, but this
            // fallback would resurrect exactly the clause that was refused. With no
            // surviving check arm the check half denies, while `can_update_using` keeps
            // the surviving USING so a locking read stays precise.
            let check_expr = update_check_expr.take().flatten().unwrap_or_else(|| {
                if update_check_was_filtered {
                    deny_expr(self.plan)
                } else {
                    using_expr.clone()
                }
            });
            // An update that names no row reads nothing, so `PostgreSQL` applies the
            // UPDATE policies to it and not the SELECT policies. Check this relation
            // only for `UPDATE t SET c = ...` with no WHERE: pick it for a statement
            // that does name rows and the grant is wider than the database's.
            let blanket = if using_expr == check_expr {
                using_expr.clone()
            } else {
                UsersetExpr::Intersection(vec![using_expr.clone(), check_expr.clone()])
            };
            self.plan
                .set_computed(can_update_without_reading_relation(), blanket);
            if using_expr == check_expr {
                self.plan
                    .set_computed(can_update_relation(), requires_read_access(using_expr));
            } else {
                self.plan.set_computed(
                    can_update_using_relation(),
                    requires_read_access(using_expr),
                );
                self.plan
                    .set_computed(can_update_check_relation(), check_expr);
                self.plan.set_computed(
                    can_update_relation(),
                    UsersetExpr::Intersection(vec![
                        UsersetExpr::Computed(can_update_using_relation()),
                        UsersetExpr::Computed(can_update_check_relation()),
                    ]),
                );
            }
        }
        blocked_commands
    }
}

/// Fill what no surviving policy covers with a denial, and report which is which.
///
/// A command denied because every policy covering it fell below the bar gets a different line
/// from one no policy covers at all: the first says the model came out narrower than the database,
/// the second says the database denies it too. The schema is asked, since the filtered set cannot
/// tell them apart.
fn fill_and_report_coverage<DB: DatabaseLike>(
    plan: &mut TypePlan,
    notes: &mut Vec<TranslationNote>,
    source_table: &str,
    declared_here: &[&DB::Policy],
    blocked_commands: &BTreeSet<&'static str>,
    has_row_scoped_write_policy: bool,
    db: &DB,
) {
    let uncovered: Vec<&'static str> = fill_uncovered_actions_with_deny(plan)
        .into_iter()
        .filter(|command| !blocked_commands.contains(command))
        .collect();
    if !uncovered.is_empty() {
        let covered_by_schema = commands_a_permissive_policy_covers(declared_here, db);
        let (dropped, unpolicied): (Vec<&str>, Vec<&str>) = uncovered
            .into_iter()
            .partition(|command| covered_by_schema.contains(command));
        if !unpolicied.is_empty() {
            notes.push(TranslationNote::NoPermissivePolicy {
                table: source_table.to_string(),
                commands: unpolicied.iter().map(|c| (*c).to_string()).collect(),
            });
        }
        if !dropped.is_empty() {
            notes.push(TranslationNote::CoveringPoliciesBelowThreshold {
                table: source_table.to_string(),
                commands: dropped.iter().map(|c| (*c).to_string()).collect(),
            });
        }
    }

    for (policy_name, commands, clause) in policies_missing_a_clause(declared_here, db) {
        notes.push(TranslationNote::PolicyClauseAbsent {
            policy: policy_name,
            commands,
            clause: clause.to_string(),
        });
    }

    // Denying this silently would hide a schema mistake.
    if has_row_scoped_write_policy
        && plan
            .computed_relations
            .get(&can_select_relation())
            .is_some_and(|expr| grants_nothing(expr, plan, &mut BTreeSet::new()))
    {
        notes.push(TranslationNote::ReadsDeniedSoWritesCannotName {
            table: source_table.to_string(),
        });
    }
}

/// The losses a table carries when a tuple cannot name what a grant needs.
///
/// Three readings of the same source list, kept apart because they are different losses: no row
/// identity at all, a bridge whose column the schema does not have, and a key whose rendered name
/// can reach the length cap.
fn scar_unfillable_grants<DB: DatabaseLike>(
    plan: &TypePlan,
    notes: &mut Vec<TranslationNote>,
    source_table: &str,
    type_name: &str,
    bounds: &UnboundedColumns,
    db: &DB,
) {
    // cannot describe different losses. Nothing here is minted for a target the read
    // loop blocks: PostgreSQL raises there rather than granting, so the policy loop
    // never translated it and no skip exists to read.
    let unfillable: BTreeSet<String> = plan
        .table_tuple_sources
        .iter()
        .filter_map(|source| match source {
            TupleSource::Skipped {
                reason: SkippedTuples::NoObjectIdentifier { what, .. },
            } => Some(what.clone()),
            TupleSource::Skipped {
                reason: SkippedTuples::NoBridge { parent_type, .. },
            } => Some(format!("bridge tuples to '{parent_type}'")),
            _ => None,
        })
        .collect();
    if !unfillable.is_empty() {
        notes.push(TranslationNote::RowsCannotBeNamed {
            table: source_table.to_string(),
            reason: missing_object_identifier_reason(source_table, db),
            sources: unfillable.into_iter().collect(),
        });
    }
    // The same reading, for a bridge whose column the schema does not have: the row
    // is nameable, so it is a different loss and says so.
    let unbridged: BTreeSet<(String, ColumnName)> = plan
        .table_tuple_sources
        .iter()
        .filter_map(|source| match source {
            TupleSource::Skipped {
                reason:
                    SkippedTuples::BridgeColumnMissing {
                        parent_type,
                        fk_col,
                        ..
                    },
            } => Some((parent_type.clone(), fk_col.clone())),
            _ => None,
        })
        .collect();
    for (parent_type, column) in unbridged {
        notes.push(TranslationNote::BridgeColumnMissing {
            table: source_table.to_string(),
            parent_type,
            column,
        });
    }

    // Where the guard is on, the operator is told the exact number. Gated the same
    // way the guard is, on whether the key's declared type can reach the cap, so a
    // `uuid` or integer key stays silent instead of putting a line on every table.
    if let Some(budget) = row_identifier_budget(source_table, type_name, bounds, db) {
        notes.push(TranslationNote::RowIdentifierBudget {
            table: source_table.to_string(),
            budget,
        });
    }
}

/// Every request-scoped gate is a contract with the caller, and the model has nowhere to carry
/// it.
///
/// Read back off the sources the arms recorded, so the note and the emitted conditions cannot name
/// different parameters.
fn note_request_contracts(
    plan: &TypePlan,
    notes: &mut Vec<TranslationNote>,
    settings: &GeneratorSettings,
) {
    // Every request-scoped gate is a contract with the caller, and the model itself
    // has nowhere to carry it. Read the parameters back off the sources the arms
    // recorded, so the note and the emitted conditions cannot name different ones.
    let mut contracts: BTreeSet<(String, Option<String>, Option<String>)> = BTreeSet::new();
    for source in &plan.table_tuple_sources {
        match source {
            // One arm for both, because a set carried against a row column and one
            // carried against a membership row state the same contract.
            TupleSource::SessionAttributeGate {
                request_parameter,
                setting_key,
                separator,
                ..
            }
            | TupleSource::SessionAttributeMembershipGate {
                request_parameter,
                setting_key,
                separator,
                ..
            } => {
                contracts.insert((
                    request_parameter.clone(),
                    Some(setting_key.clone()),
                    separator.clone(),
                ));
            }
            // The clock has had the same contract since it was built and never
            // announced it either.
            TupleSource::ConditionalAttributeGate { .. } => {
                contracts.insert((settings.request_time_parameter.clone(), None, None));
            }
            _ => {}
        }
    }
    for (parameter, setting_key, separator) in contracts {
        notes.push(TranslationNote::CallerSuppliesConditionParameter {
            parameter,
            setting_key,
            separator,
        });
    }
}

/// The plans in emission order, `user` first and the rest by name.
fn ordered_types(mut all_types: BTreeMap<String, TypePlan>) -> Vec<TypePlan> {
    let mut type_names: Vec<String> = all_types.keys().cloned().collect();
    type_names.sort();
    if let Some(pos) = type_names.iter().position(|n| n == USER_TYPE) {
        let user = type_names.remove(pos);
        type_names.insert(0, user);
    }
    type_names
        .into_iter()
        .filter_map(|name| all_types.remove(&name))
        .collect()
}

/// Only the conditions a surviving reference still names.
///
/// A policy dropped by confidence filtering cannot leave a condition behind.
fn surviving_conditions(types: &[TypePlan]) -> BTreeMap<String, ConditionSpec> {
    let named: BTreeSet<&str> = types
        .iter()
        .flat_map(|plan| plan.direct_relations.values())
        .flatten()
        .filter_map(|subject| match subject {
            DirectSubject::ConditionalWildcard { condition, .. } => Some(condition.as_str()),
            DirectSubject::Type(_) | DirectSubject::Wildcard(_) => None,
        })
        .collect();
    types
        .iter()
        .flat_map(|plan| plan.conditions.iter())
        .filter(|(name, _)| named.contains(name.as_str()))
        .map(|(name, spec)| (name.clone(), spec.clone()))
        .collect()
}

/// Report the principals row level security does not reach.
///
/// The model keeps describing the rules that do apply. Modelling a bypass as a
/// permission would be the largest widening available here, and it misfires the moment
/// a service account stops running as the exempt principal.
///
/// The table's owner is the third mechanism, named where the schema assigns one and
/// generic where it does not, since an unreadable answer must not invent a role.
fn report_row_level_security_bypasses<DB: DatabaseLike>(db: &DB, notes: &mut Vec<TranslationNote>) {
    for role in db.roles() {
        if role.can_bypass_rls() {
            notes.push(TranslationNote::RoleBypassesPolicies {
                role: role.name().to_string(),
            });
        }
    }
    for table in db.tables() {
        // Fail closed on an unreadable answer in the direction that reports rather than
        // hides: only a definite yes means the owner is subject to the policies.
        if table.has_row_level_security(db) == Ok(true)
            && table.has_forced_row_level_security(db) != Ok(true)
        {
            notes.push(TranslationNote::TableOwnerBypassesPolicies {
                table: qualified_table_name(table),
                // An unreadable answer is not a name, so the note stays generic.
                owner: table.owner(db).ok().flatten().map(str::to_string),
            });
        }
    }
}

/// The type standing for everyone listed in `member_table`.
///
/// One per member source, so two policies reading the same table share a holder and two
/// reading different ones cannot pool their members. Disambiguated against the table
/// types, which are all assigned before any policy is translated, so a schema that
/// happens to declare a table by this name keeps it.
fn holder_type_name(member_table: &str, table_types: &TableTypes) -> String {
    let base = canonical_fga_type_name(&format!("{member_table}_holder"));
    if table_types.claims(&base) {
        return format!("{base}_{}", stable_hex_suffix(member_table));
    }
    base
}

/// Every `(type, relation)` a permission can consult. Anything unresolved counts as
/// reachable, since dropping a needed query would narrow the model.
pub(crate) fn grantable_relations(types: &[TypePlan]) -> BTreeSet<(String, RelationName)> {
    let by_name: BTreeMap<&str, &TypePlan> = types
        .iter()
        .map(|plan| (plan.type_name.as_str(), plan))
        .collect();
    let mut reached: BTreeSet<(String, RelationName)> = BTreeSet::new();
    for plan in types {
        for action in action_relations().chain(derived_action_relations()) {
            let Some(expr) = plan.computed_relations.get(&action) else {
                continue;
            };
            if grants_nothing(expr, plan, &mut BTreeSet::new()) {
                continue;
            }
            reach_userset(expr, plan, &by_name, &mut reached);
        }
    }
    reached
}

/// Every type whose table may be the one an unresolvable name denotes. `PostgreSQL`
/// picked one through the search path and a dump does not record it, so each of them
/// may be the table that lost the clause. A qualified name resolving to nothing bears
/// on no table at all, which is what `same_identifier` answers for it.
fn types_bearing_name<DB: DatabaseLike>(
    db: &DB,
    named: &str,
    table_types: &TableTypes,
) -> Vec<String> {
    db.tables()
        .filter(|table| same_identifier(named, table.table_name()))
        .filter_map(|table| table_types.by_identity.get(&table_identity(table)).cloned())
        .collect()
}

/// How much of a membership table a querying user may read.
#[derive(Clone)]
enum JoinTableReadability {
    /// No row level security, so every membership row counts.
    Open,
    /// Row level security with at least one policy that can grant reads. `roles` is
    /// non-empty when every such policy is role scoped, so reads also require one of
    /// those roles.
    Guarded { roles: Vec<String> },
    /// Row level security with nothing granting reads, so no row is visible.
    Unreadable,
}

/// Readability of one membership table, computed once per plan per table.
///
/// The uncached walk reads every policy the schema declares to find the table's own, and it
/// runs once per clause naming that table, so a schema whose tables all join one membership
/// table pays it quadratically. Memoized on the spelling, which `lookup_table` resolves.
fn join_table_readability<DB: DatabaseLike>(
    join_table: &str,
    db: &DB,
    memo: &mut BTreeMap<String, JoinTableReadability>,
) -> JoinTableReadability {
    memo.entry(join_table.to_string())
        .or_insert_with(|| read_join_table_readability(join_table, db))
        .clone()
}

fn read_join_table_readability<DB: DatabaseLike>(
    join_table: &str,
    db: &DB,
) -> JoinTableReadability {
    let Some(table) = lookup_table(db, join_table) else {
        return JoinTableReadability::Open;
    };
    // Only a table positively known to have RLS off is open.
    if table.has_row_level_security(db) == Ok(false) {
        return JoinTableReadability::Open;
    }

    // A clause that admits no row grants nobody, whichever side of the algebra it sits on:
    // PostgreSQL reads the table as (permissive OR ...) AND restrictive AND ..., so every
    // permissive one being empty leaves nothing, and any restrictive one being empty removes
    // whatever they admit. Only provable emptiness counts, since denying on a clause the
    // crate merely failed to read would refuse what RLS allows.
    //
    // One pass, and at most one clause read per policy: this runs once per dependent clause
    // and the accessors consult the schema, so a second walk here is quadratic in the tables
    // that join one membership table.
    let mut roles = BTreeSet::new();
    let mut grants_read = false;
    let mut grants_read_unscoped = false;
    for policy in table.policies(db).into_iter().flatten() {
        if !matches!(
            PolicyCommand::from(policy.command()),
            PolicyCommand::Select | PolicyCommand::All
        ) {
            continue;
        }
        let Some(using) = policy.using_expression(db) else {
            continue;
        };
        let admits_nothing = is_constantly_false(using);

        if derive_policy_mode(policy) == PolicyMode::Restrictive {
            // A barrier bound to roles closes the table for those roles alone, which the
            // three answers here cannot express, so it is left as a disclosed widening.
            if admits_nothing && derive_scoped_roles(policy, db).is_empty() {
                return JoinTableReadability::Unreadable;
            }
            continue;
        }
        if admits_nothing {
            continue;
        }

        grants_read = true;
        let scoped = derive_scoped_roles(policy, db);
        if scoped.is_empty() {
            grants_read_unscoped = true;
        } else {
            roles.extend(scoped);
        }
    }

    match (grants_read, grants_read_unscoped) {
        (false, _) => JoinTableReadability::Unreadable,
        (true, true) => JoinTableReadability::Guarded { roles: Vec::new() },
        (true, false) => JoinTableReadability::Guarded {
            roles: roles.into_iter().collect(),
        },
    }
}

/// Schema-qualified stored name, in the spelling `lookup_table` resolves.
fn qualified_table_name<T: TableLike>(table: &T) -> String {
    table_identity(table).to_string()
}

/// Key grouping every spelling of one table together, memoized in `cache` because
/// resolving a spelling walks the tables. Both groupings call this, so the filtered
/// classifications and the schema's own policies cannot land under different keys.
fn table_group_key<DB: DatabaseLike>(
    db: &DB,
    named: String,
    cache: &mut BTreeMap<String, String>,
) -> String {
    if let Some(key) = cache.get(&named) {
        return key.clone();
    }
    let key = match lookup_table(db, &named) {
        Some(table) => qualified_table_name(table),
        None => named.clone(),
    };
    cache.insert(named, key.clone());
    key
}

/// Identity that matches two table references however the policy spelled them.
fn table_identity<T: TableLike>(table: &T) -> TableId {
    TableId::from_stored(
        table.stored_table_schema().map(Into::into),
        table.stored_table_name().into(),
    )
}

/// Final `OpenFGA` type name of every table that gets one, assigned in one pass so a
/// parent reference resolves to the same type as the table's own policies.
struct TypeOwner {
    identity: TableId,
    /// Spelling used in the schema, for the collision message.
    spelling: String,
}

#[derive(Default)]
struct TableTypes {
    by_identity: BTreeMap<TableId, String>,
    owners: BTreeMap<String, TypeOwner>,
}

impl TableTypes {
    /// Whether a table already holds this type name, so a synthetic type must not.
    fn claims(&self, type_name: &str) -> bool {
        self.owners.contains_key(type_name)
    }

    /// The schema's own spelling of the table holding this type, for a note to name.
    fn spelling<'a>(&'a self, type_name: &'a str) -> &'a str {
        self.owners
            .get(type_name)
            .map_or(type_name, |owner| owner.spelling.as_str())
    }
}

impl TableTypes {
    /// One type name per table the plan constrains, collisions suffixed with a hash of
    /// the qualified name.
    ///
    /// Derived from the schema alone, never from which policies survived filtering,
    /// so names do not move with the confidence threshold. Tables carrying policies
    /// claim their canonical name first.
    fn assign<DB: DatabaseLike>(
        db: &DB,
        scope: TypeScope<'_>,
        notes: &mut Vec<TranslationNote>,
    ) -> Self {
        let mut types = Self::default();
        let mut policied: BTreeSet<TableId> = BTreeSet::new();
        for policy in db.policies() {
            if let Some(table) = lookup_table(db, &policy.target_table_name().to_string()) {
                policied.insert(table_identity(table));
            }
        }
        // A subscription filter guards a table that carries no policy, so its type
        // cannot wait for row-level security to be switched on.
        let forced = match scope {
            TypeScope::WithPolicies => None,
            TypeScope::AndAlso(table) => lookup_table(db, table).map(table_identity),
        };

        let mut names: Vec<(bool, String)> = db
            .tables()
            .filter(|table| {
                table.has_row_level_security(db) != Ok(false)
                    || forced.as_ref() == Some(&table_identity(table))
            })
            .map(|table| {
                (
                    !policied.contains(&table_identity(table)),
                    qualified_table_name(table),
                )
            })
            .collect();
        names.sort();

        for (_, name) in &names {
            let Some(table) = lookup_table(db, name) else {
                continue;
            };
            let identity = table_identity(table);
            if types.by_identity.contains_key(&identity) {
                continue;
            }

            let base = canonical_fga_type_name(name);
            let assigned = match types.owners.get(&base) {
                Some(prior) => {
                    let disambiguated = format!("{base}_{}", stable_hex_suffix(name));
                    notes.push(TranslationNote::TypeNameCollision {
                        spelling: name.clone(),
                        prior: prior.spelling.clone(),
                        canonical: base.clone(),
                        renamed: disambiguated.clone(),
                    });
                    disambiguated
                }
                None => base,
            };
            types.owners.insert(
                assigned.clone(),
                TypeOwner {
                    identity: identity.clone(),
                    spelling: name.clone(),
                },
            );
            types.by_identity.insert(identity, assigned);
        }

        types
    }

    /// Type of `table`, or `None` when it has no type (unresolvable or RLS off).
    fn get<DB: DatabaseLike>(&self, db: &DB, table: &str) -> Option<&str> {
        let identity = table_identity(lookup_table(db, table)?);
        self.by_identity.get(&identity).map(String::as_str)
    }

    /// Type of `table`, deriving one when it has none: a parent without RLS still
    /// needs a type for the child to point at. The derived name steps aside when
    /// another table already owns it, so the child cannot inherit that table's
    /// permissions.
    fn resolve<DB: DatabaseLike>(&self, db: &DB, table: &str) -> String {
        let identity = lookup_table(db, table).map(table_identity);
        if let Some(assigned) = identity.as_ref().and_then(|id| self.by_identity.get(id)) {
            return assigned.clone();
        }
        let base = canonical_fga_type_name(table);
        match self.owners.get(&base) {
            Some(owner) if Some(&owner.identity) != identity.as_ref() => {
                format!("{base}_{}", stable_hex_suffix(table))
            }
            _ => base,
        }
    }
}

/// Drop notes added since `start` that repeat an earlier one. A policy covering
/// several phases is translated once per phase, so the same clause reports the same
/// note each time.
fn dedup_notes_added_since(notes: &mut Vec<TranslationNote>, start: usize) {
    let mut seen: Vec<TranslationNote> = Vec::new();
    let mut index = start;
    while index < notes.len() {
        let Some(note) = notes.get(index) else { break };
        if seen.contains(note) {
            notes.remove(index);
        } else {
            seen.push(note.clone());
            index += 1;
        }
    }
}

fn deny_expr(table_plan: &mut TypePlan) -> UsersetExpr {
    table_plan.ensure_direct(
        deny_relation(),
        vec![DirectSubject::Type(USER_TYPE.to_string())],
    );
    UsersetExpr::Computed(deny_relation())
}

fn public_expr(table_plan: &mut TypePlan) -> UsersetExpr {
    table_plan.ensure_direct(
        public_relation(),
        vec![DirectSubject::Wildcard(USER_TYPE.to_string())],
    );
    UsersetExpr::Computed(public_relation())
}

fn combine_exprs(
    mut exprs: Vec<UsersetExpr>,
    wrapper: fn(Vec<UsersetExpr>) -> UsersetExpr,
) -> Option<UsersetExpr> {
    match exprs.len() {
        0 => None,
        1 => exprs.pop(),
        _ => Some(wrapper(exprs)),
    }
}

fn combine_union(exprs: Vec<UsersetExpr>) -> Option<UsersetExpr> {
    combine_exprs(exprs, UsersetExpr::Union)
}

fn combine_intersection(exprs: Vec<UsersetExpr>) -> Option<UsersetExpr> {
    combine_exprs(exprs, UsersetExpr::Intersection)
}

/// Translate a pattern against a table whose rows a tuple can name, which is what the
/// pattern arms assume. Use [`pattern_to_expr_without_row_identity`] for the other case.
#[cfg(test)]
fn pattern_to_expr(
    pattern: &PatternClass,
    policy_name: &str,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<String, TypePlan>,
    registry: &FunctionRegistry,
    notes: &mut Vec<TranslationNote>,
) -> UsersetExpr {
    pattern_to_expr_against(
        "CREATE TABLE projects(id UUID PRIMARY KEY);
CREATE TABLE test_table(id UUID PRIMARY KEY, project_id UUID REFERENCES projects(id));",
        pattern,
        policy_name,
        table_plan,
        all_types,
        registry,
        notes,
    )
}

/// Translate a pattern against a table no schema declares, so nothing names its rows.
#[cfg(test)]
fn pattern_to_expr_without_row_identity(
    pattern: &PatternClass,
    policy_name: &str,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<String, TypePlan>,
    registry: &FunctionRegistry,
    notes: &mut Vec<TranslationNote>,
) -> UsersetExpr {
    pattern_to_expr_against(
        "",
        pattern,
        policy_name,
        table_plan,
        all_types,
        registry,
        notes,
    )
}

#[cfg(test)]
fn pattern_to_expr_against(
    schema: &str,
    pattern: &PatternClass,
    policy_name: &str,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<String, TypePlan>,
    registry: &FunctionRegistry,
    notes: &mut Vec<TranslationNote>,
) -> UsersetExpr {
    let db = crate::parser::sql_parser::parse_schema(schema).expect("schema should parse");
    translate_pattern(
        pattern,
        &PatternCtx {
            policy_name,
            registry,
            hints: &RoleThresholdResourceHints::default(),
            db: &db,
            table_types: &TableTypes::default(),
            source_table: "test_table",
            settings: &GeneratorSettings::default(),
        },
        table_plan,
        all_types,
        notes,
        &mut BTreeMap::new(),
    )
}

/// Everything a pattern arm reads and nobody mutates.
///
/// Passed by reference and re-targeted through [`PatternCtx::for_table`], which is what a
/// parent-rule recursion needs. A context holding the mutable state could not do that: the
/// recursion swaps the plan it writes to while keeping the map that plan came out of, so
/// those four stay explicit parameters.
struct PatternCtx<'a, DB: DatabaseLike> {
    /// Policy the clause belongs to, named in every note the arms raise.
    policy_name: &'a str,
    /// Function semantics, for the arms that resolve a call.
    registry: &'a FunctionRegistry,
    /// Resource columns inferred for the role-threshold patterns.
    hints: &'a RoleThresholdResourceHints,
    /// The schema.
    db: &'a DB,
    /// Which table each type name belongs to.
    table_types: &'a TableTypes,
    /// Table the clause guards, which a parent recursion re-targets.
    source_table: &'a str,
    /// Caller-chosen names the emitted conditions have to respect.
    settings: &'a GeneratorSettings,
}

impl<'a, DB: DatabaseLike> PatternCtx<'a, DB> {
    /// The same context reading a different table, which is what a parent rule is
    /// translated against.
    fn for_table(&self, source_table: &'a str) -> Self {
        Self {
            policy_name: self.policy_name,
            registry: self.registry,
            hints: self.hints,
            db: self.db,
            table_types: self.table_types,
            source_table,
            settings: self.settings,
        }
    }
}

/// Build the userset expression for one classified pattern.
///
/// The result does not depend on which command the policy covers: inheritance
/// always reads the parent's SELECT relation, and the caller files the expression
/// under the right action.
fn translate_pattern<DB: DatabaseLike>(
    pattern: &PatternClass,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<String, TypePlan>,
    notes: &mut Vec<TranslationNote>,
    readability: &mut BTreeMap<String, JoinTableReadability>,
) -> UsersetExpr {
    let source_table = ctx.source_table;
    match pattern {
        PatternClass::P1NumericThreshold(numeric_threshold) => {
            emit_numeric_threshold(numeric_threshold, ctx, table_plan, all_types, notes)
        }
        PatternClass::P2RoleNameInList(role_name_in_list) => {
            emit_role_name_in_list(role_name_in_list, ctx, table_plan, all_types, notes)
        }
        PatternClass::P3DirectOwnership(DirectOwnership { column }) => emit_row_ownership(
            column.as_str(),
            column.as_str(),
            "ownership tuples",
            ctx,
            table_plan,
            |pk_cols, relation| TupleSource::DirectOwnership {
                table: source_table.to_string(),
                pk_cols,
                owner_col: column.clone(),
                relation,
            },
        ),
        PatternClass::P11ArrayMembership(ArrayMembership { column }) => emit_row_ownership(
            column.as_str(),
            column.as_str(),
            "array membership tuples",
            ctx,
            table_plan,
            |pk_cols, relation| TupleSource::ArrayMembership {
                table: source_table.to_string(),
                pk_cols,
                array_col: column.clone(),
                relation,
            },
        ),
        PatternClass::P12JsonbFieldOwnership(JsonbFieldOwnership { column, path }) => {
            emit_row_ownership(
                &format!("jsonb:{column}:{}", path.join(".")),
                &path.join("_"),
                "jsonb field ownership tuples",
                ctx,
                table_plan,
                |pk_cols, relation| TupleSource::JsonbFieldOwnership {
                    table: source_table.to_string(),
                    pk_cols,
                    column: column.clone(),
                    path: path.clone(),
                    relation,
                },
            )
        }
        PatternClass::P13UncorrelatedMembership(uncorrelated_membership) => {
            emit_uncorrelated_membership(
                uncorrelated_membership,
                ctx,
                table_plan,
                all_types,
                notes,
                readability,
            )
        }
        PatternClass::P18MembershipInCallerSet(membership_in_caller_set) => {
            emit_membership_in_caller_set(
                membership_in_caller_set,
                ctx,
                table_plan,
                notes,
                readability,
            )
        }
        PatternClass::P4ExistsMembership(exists_membership) => emit_exists_membership(
            exists_membership,
            ctx,
            table_plan,
            all_types,
            notes,
            readability,
        ),
        PatternClass::P5ParentInheritance(parent_inheritance) => emit_parent_inheritance(
            parent_inheritance,
            ctx,
            table_plan,
            all_types,
            notes,
            readability,
        ),
        PatternClass::P6BooleanFlag(boolean_flag) => {
            emit_boolean_flag(boolean_flag, ctx, table_plan)
        }
        PatternClass::P7AbacAnd(abac_and) => {
            emit_abac_and(abac_and, ctx, table_plan, all_types, notes, readability)
        }
        PatternClass::P8Composite(composite) => {
            emit_composite(composite, ctx, table_plan, all_types, notes, readability)
        }
        PatternClass::P9AttributeCondition(attribute_condition) => {
            emit_attribute_condition(attribute_condition, ctx, table_plan, notes)
        }
        PatternClass::P10ConstantBool(constant_bool) => {
            emit_constant_bool(constant_bool, ctx, table_plan)
        }
        PatternClass::P14RowValueInCallerSet(RowValueInCallerSet {
            column,
            source,
            separator,
        }) => emit_request_gate(
            RequestSide {
                source,
                comparison: RequestComparison::CallerSetHolds,
                separator: separator.as_deref(),
            },
            RowParameterSource::Column(column),
            ctx,
            table_plan,
        ),
        PatternClass::P15RowValueEqualsCallerScalar(RowValueEqualsCallerScalar {
            column,
            source,
        }) => emit_request_gate(
            RequestSide {
                source,
                comparison: RequestComparison::CallerValueEquals,
                separator: None,
            },
            RowParameterSource::Column(column),
            ctx,
            table_plan,
        ),
        PatternClass::P16ConstantInCallerSet(ConstantInCallerSet {
            value,
            source,
            separator,
        }) => emit_request_gate(
            RequestSide {
                source,
                comparison: RequestComparison::CallerSetHolds,
                separator: separator.as_deref(),
            },
            RowParameterSource::Constant(value),
            ctx,
            table_plan,
        ),
        PatternClass::P17CallerScalarEqualsConstant(CallerScalarEqualsConstant {
            value,
            source,
        }) => emit_request_gate(
            RequestSide {
                source,
                comparison: RequestComparison::CallerValueEquals,
                separator: None,
            },
            RowParameterSource::Constant(value),
            ctx,
            table_plan,
        ),
        PatternClass::Unknown(unclassified) => {
            emit_unclassified(unclassified, ctx, table_plan, notes)
        }
    }
}

/// Characters this table's key may render before the guard leaves the row out, or
/// `None` where the key's declared type cannot reach the cap.
///
/// The budget covers the whole `type:id` string, so it shrinks as the type name
/// grows and two tables of the same schema can have different numbers.
fn row_identifier_budget<DB: DatabaseLike>(
    source_table: &str,
    type_name: &str,
    bounds: &UnboundedColumns,
    db: &DB,
) -> Option<usize> {
    let key = resolve_pk_columns(source_table, db)?;
    if !bounds.any_unbounded(source_table, &key, db) {
        return None;
    }
    MAX_OBJECT_NAME_CHARS.checked_sub(type_name.chars().count() + 1)
}

/// Explain why `source_table` has no usable `OpenFGA` object identifier.
fn missing_object_identifier_reason<DB: DatabaseLike>(source_table: &str, db: &DB) -> String {
    if let Some(columns) = composite_primary_key_columns(source_table, db) {
        return format!(
            "composite primary key ({}) leaves no single-column object identifier",
            columns.join(", ")
        );
    }
    if table_has_column(db, source_table, "id") {
        return "no primary key, and 'id' is nullable or not uniquely constrained, so it does \
                not identify a row"
            .to_string();
    }
    "missing object identifier column".to_string()
}

/// Record that a tuple query cannot be emitted, because no single column names a row.
///
/// The grant it would have filled falls closed at the call site, and one note per table
/// is derived from the skips recorded here so the two cannot describe different losses.
fn skip_source_without_row_identity<DB: DatabaseLike>(
    table_plan: &mut TypePlan,
    source_table: &str,
    what: &str,
    db: &DB,
) {
    table_plan.add_source(TupleSource::Skipped {
        reason: SkippedTuples::NoObjectIdentifier {
            table: source_table.to_string(),
            what: what.to_string(),
            reason: missing_object_identifier_reason(source_table, db),
        },
    });
}

/// Whether the bridge linking a row of `source_table` to its parent can be written,
/// recording the loss when it cannot.
///
/// Asked here rather than left to the renderer, which has only a comment to carry the
/// answer: a bridge nobody writes leaves the grant above it satisfiable by no one, and
/// the caller falls closed on `false`.
fn bridge_is_buildable<DB: DatabaseLike>(
    table_plan: &mut TypePlan,
    source_table: &str,
    fk_col: &ColumnName,
    parent_type: &str,
    db: &DB,
) -> bool {
    if resolve_bridge_columns(source_table, fk_col, db).is_some() {
        return true;
    }
    let reason = if resolve_pk_columns(source_table, db).is_none() {
        SkippedTuples::NoBridge {
            table: source_table.to_string(),
            parent_type: parent_type.to_string(),
            reason: missing_object_identifier_reason(source_table, db),
        }
    } else {
        SkippedTuples::BridgeColumnMissing {
            table: source_table.to_string(),
            parent_type: parent_type.to_string(),
            fk_col: fk_col.clone(),
        }
    };
    table_plan.add_source(TupleSource::Skipped { reason });
    false
}

fn ensure_member_type(all_types: &mut BTreeMap<String, TypePlan>, type_name: &str) {
    let entry = all_types
        .entry(type_name.to_string())
        .or_insert_with(|| TypePlan::new(type_name));
    entry.ensure_direct(
        member_relation(),
        vec![DirectSubject::Type(USER_TYPE.to_string())],
    );
}

/// Give `pg_role` a relation holding one kind of role membership, for an operator to load.
fn ensure_pg_role_relation(all_types: &mut BTreeMap<String, TypePlan>, relation: &RelationName) {
    all_types
        .entry(PG_ROLE_TYPE.to_string())
        .or_insert_with(|| TypePlan::new(PG_ROLE_TYPE))
        .ensure_direct(
            relation.clone(),
            vec![DirectSubject::Type(USER_TYPE.to_string())],
        );
}

/// Bind a parent type to the table whose rows it names, in the spelling the plan groups
/// tables under, so an entry the loop writes and one a parent reference writes agree.
fn bind_row_source<DB: DatabaseLike>(
    all_types: &mut BTreeMap<String, TypePlan>,
    type_name: &str,
    table: &str,
    db: &DB,
) {
    let Some(spelling) = lookup_table(db, table).map(qualified_table_name) else {
        return;
    };
    if let Some(plan) = all_types.get_mut(type_name) {
        plan.names_rows_of(&spelling);
    }
}

fn resolve_owner_column<DB: DatabaseLike>(table: &str, db: &DB) -> Option<ColumnName> {
    let table_info = lookup_table(db, table)?;
    for col in table_info.columns(db).into_iter().flatten() {
        let name = col.stored_column_name();
        if is_owner_like_column_name(&name) {
            return Some(ColumnName::from_stored(name));
        }
    }
    for fk in table_info.foreign_keys(db).into_iter().flatten() {
        let Ok(ref_table) = fk.referenced_table(db) else {
            continue;
        };
        let normalized_ref = normalize_relation_name(ref_table.table_name());
        if normalized_ref == "users" || normalized_ref == "owners" {
            if let Some(col_name) = fk
                .host_columns(db)
                .into_iter()
                .flatten()
                .next()
                .map(|col| ColumnName::from_stored(col.stored_column_name()))
            {
                return Some(col_name);
            }
        }
    }
    None
}

/// Returns the name of the table that `fk_column` in `table` references, or
/// `None` if no matching FK constraint is found in the schema.
fn referenced_table_for_fk_col<'db, DB: DatabaseLike>(
    db: &'db DB,
    table: &str,
    fk_column: &ColumnName,
) -> Option<&'db str> {
    let table_info = lookup_table(db, table)?;
    for fk in table_info.foreign_keys(db).into_iter().flatten() {
        let uses_col = fk
            .host_columns(db)
            .into_iter()
            .flatten()
            .any(|c| *fk_column == c.stored_column_name().into_owned());
        if uses_col {
            return fk.referenced_table(db).ok().map(TableLike::table_name);
        }
    }
    None
}

fn resolve_principal_info<DB: DatabaseLike>(
    db: &DB,
    configured_table: Option<&str>,
    configured_pk_col: Option<&ColumnName>,
    fallback_candidates: &[&str],
) -> Option<PrincipalInfo> {
    if let Some(table) = configured_table {
        let pk_col = if let Some(pk_col) = configured_pk_col {
            if !table_has_column(db, table, pk_col.as_str()) {
                return None;
            }
            pk_col.clone()
        } else {
            single_pk_column(table, db)?
        };
        return Some(PrincipalInfo {
            table: table.to_string(),
            pk_col,
        });
    }

    for &candidate in fallback_candidates {
        if lookup_table(db, candidate).is_none() {
            continue;
        }
        if let Some(pk_col) = single_pk_column(candidate, db) {
            return Some(PrincipalInfo {
                table: candidate.to_string(),
                pk_col,
            });
        }
    }

    None
}

#[cfg(test)]
mod tests;

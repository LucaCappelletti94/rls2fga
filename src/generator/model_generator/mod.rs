#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use alloc::collections::{BTreeMap, BTreeSet};
use core::fmt::Write;

use crate::classifier::function_registry::FunctionRegistry;
use crate::classifier::patterns::*;
use crate::classifier::recognizers::is_constantly_false;
use crate::generator::db_lookup::{
    composite_primary_key_columns, resolve_pk_column, table_has_column,
};
use crate::generator::ir::{PrincipalInfo, TupleSource};
use crate::generator::notes::{SkippedTuples, TranslationNote};
use crate::generator::role_relations::{sorted_role_relation_names, RoleRelationName};
use crate::generator::well_known::{
    CAN_DELETE_RELATION, CAN_INSERT_RELATION, CAN_INSERT_RETURNING_RELATION,
    CAN_SELECT_FOR_UPDATE_RELATION, CAN_SELECT_RELATION, CAN_UPDATE_CHECK_RELATION,
    CAN_UPDATE_RELATION, CAN_UPDATE_USING_RELATION, CAN_UPDATE_WITHOUT_READING_RELATION,
    CAN_UPSERT_RELATION, DENY_RELATION, MEMBER_RELATION, OWNER_TEAM_RELATION, OWNER_USER_RELATION,
    PG_ROLE_TYPE, PUBLIC_RELATION, REQUEST_TIME_PARAMETER, TEAM_TYPE, TIMESTAMP_PARAMETER_TYPE,
    USER_TYPE,
};
use crate::parser::expr::extract_column_name;
use crate::parser::expr::function_arg_expr;
use crate::parser::function_analyzer::FunctionSemantic;
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

/// `OpenFGA` DSL text rendering from the schema plan.
mod dsl;
/// Which statements `PostgreSQL` refuses to plan because the policies loop.
mod recursion;
/// Role-threshold resource-column inference and tuple-source population.
mod role_threshold;

use dsl::render_dsl;
use recursion::PolicyReadRecursion;
use role_threshold::{infer_role_threshold_resource_columns, populate_role_threshold_sources};

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
    /// Parameter name to its `OpenFGA` type name, sorted so emission is stable.
    pub parameters: BTreeMap<String, String>,
    /// The parameter each tuple supplies from its own row, and the column it reads.
    pub row_parameter: (String, String),
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
    Computed(String),
    TupleToUserset {
        tupleset: String,
        computed: String,
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
    pub type_name: String,
    pub direct_relations: BTreeMap<String, Vec<DirectSubject>>,
    pub computed_relations: BTreeMap<String, UsersetExpr>,
    /// Table-level tuple sources not tied to a specific relation (e.g. policy
    /// scope tuples).
    pub table_tuple_sources: Vec<TupleSource>,
    /// Ownership column → its relation. Sharing one would union distinct principals.
    ownership_relations: BTreeMap<String, String>,
    /// Conditions this type's own relation references name, keyed by condition name.
    /// They live here rather than threaded through translation so a condition stays
    /// beside the relation that needs it.
    pub conditions: BTreeMap<String, ConditionSpec>,
}

/// Subjects the generator's own structural relations hold, or `None` when the
/// name is free. These relations are referenced by name, so any other caller
/// asking for one is renamed regardless of translation order.
fn reserved_relation_subjects(relation: &str) -> Option<Vec<DirectSubject>> {
    let user = || vec![DirectSubject::Type(USER_TYPE.to_string())];
    match relation {
        DENY_RELATION | MEMBER_RELATION | OWNER_USER_RELATION => Some(user()),
        PUBLIC_RELATION => Some(vec![DirectSubject::Wildcard(USER_TYPE.to_string())]),
        OWNER_TEAM_RELATION => Some(vec![DirectSubject::Type(TEAM_TYPE.to_string())]),
        _ => None,
    }
}

/// Whether the generator defines `relation` itself once the actions are assembled,
/// so a translated name taking it would be defined twice.
fn generator_defines(relation: &str) -> bool {
    action_relations()
        .chain(DERIVED_ACTION_RELATIONS)
        .any(|reserved| reserved == relation)
}

impl TypePlan {
    fn new(type_name: impl Into<String>) -> Self {
        Self {
            type_name: type_name.into(),
            ..Self::default()
        }
    }

    /// Relation carrying the subjects of an ownership source, named after
    /// `name_source` (`owner_id` → `owner`) and disambiguated on collision.
    ///
    /// `memo_key` namespaces the reuse: a jsonb path and a column spelled alike must
    /// not share a relation, or their two tuple sources union their principals.
    fn ownership_relation(&mut self, memo_key: &str, name_source: &str) -> String {
        if let Some(existing) = self.ownership_relations.get(memo_key) {
            return existing.clone();
        }

        let base = parent_type_from_fk_column(name_source);
        let taken = |name: &str, plan: &Self| {
            reserved_relation_subjects(name).is_some()
                || generator_defines(name)
                || plan.direct_relations.contains_key(name)
                || plan.computed_relations.contains_key(name)
        };
        let relation = clamp_relation_name(if taken(&base, self) {
            let fallback = format!("owner_{}", canonical_fga_type_name(name_source));
            if taken(&fallback, self) {
                format!("{fallback}_{}", stable_hex_suffix(memo_key))
            } else {
                fallback
            }
        } else {
            base
        });

        self.ownership_relations
            .insert(memo_key.to_string(), relation.clone());
        relation
    }

    /// Register a directly-assignable relation, returning the name actually used.
    fn ensure_direct(
        &mut self,
        relation: impl Into<String>,
        subjects: Vec<DirectSubject>,
    ) -> String {
        let base = clamp_relation_name(relation.into());
        let key = subject_key(&subjects);
        let mut relation = base.clone();
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

    fn ensure_computed(&mut self, relation: impl Into<String>, expr: UsersetExpr) -> String {
        let base = clamp_relation_name(relation.into());
        let key = userset_key(&expr);
        let mut relation = base.clone();
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

    fn set_computed(&mut self, relation: impl Into<String>, expr: UsersetExpr) -> String {
        let mut relation = clamp_relation_name(relation.into());
        // A name a direct relation already holds yields, exactly as `ensure_direct` and
        // `ensure_computed` do. Overwriting a computed rule is this function's whole
        // job, so only the direct case is a clash.
        if self.direct_relations.contains_key(&relation) {
            let key = userset_key(&expr);
            relation =
                clamp_relation_name(format!("{relation}_{}", stable_hex_suffix(key.as_str())));
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum ActionTarget {
    Select,
    Insert,
    UpdateUsing,
    UpdateCheck,
    Delete,
}

#[derive(Debug, Clone, Default)]
struct ModeBuckets {
    permissive: Vec<UsersetExpr>,
    restrictive: Vec<UsersetExpr>,
    /// Barriers that bind only the members of a role.
    role_limited: Vec<RoleLimitedRule>,
}

/// A RESTRICTIVE rule and the relation holding the roles it binds.
#[derive(Debug, Clone)]
struct RoleLimitedRule {
    policy: String,
    rule: UsersetExpr,
    scope_relation: String,
}

/// Pre-computed per-`(table, function_name)` resource column hints for P1/P2
/// patterns.  Populated once per `build_schema_plan` call by walking the raw
/// policy `Expr` AST before pattern translation begins.
#[derive(Debug, Clone, Default)]
pub(crate) struct RoleThresholdResourceHints {
    /// `(table, function_name)` → resource column name (unambiguous cases).
    pub columns: BTreeMap<(String, String), String>,
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
    // Pre-compute resource column hints for P1/P2 role-threshold patterns.
    // This walks the raw policy Expr AST once up-front so that
    // pattern_to_expr_for_target can use the resolved column during translation.
    let role_threshold_resource_hints = infer_role_threshold_resource_columns(policies, registry);

    let mut all_types: BTreeMap<String, TypePlan> = BTreeMap::new();
    let mut notes = Vec::new();
    let mut confidence_summary = Vec::new();
    let mut has_role_scopes = false;

    for function in registry.owner_bound_accessors() {
        notes.push(TranslationNote::OwnerBoundFunction {
            function: function.to_string(),
        });
    }

    // Keyed by the schema's own spelling, since two policies may quote the table
    // differently and one table must be built once. `group_keys` memoizes the
    // resolution, which walks the tables, and every policy on one table repeats it.
    let mut group_keys: BTreeMap<String, String> = BTreeMap::new();
    let mut by_table: BTreeMap<String, Vec<&ClassifiedPolicy>> = BTreeMap::new();
    for cp in policies {
        let key = table_group_key(db, cp.table_name().to_string(), &mut group_keys);
        by_table.entry(key).or_default().push(cp);
    }

    // An RLS-enabled table with no policy denies every row, so seed it and let
    // the deny fill below cover its commands.
    let covered: BTreeSet<(Option<String>, String)> = by_table
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

    report_row_level_security_bypasses(db, &mut notes);

    // The schema's own permissive policies under the same key, since the filtered
    // set cannot say whether a policy exists at all. Splitting the two keys would
    // tell the operator RLS denies a command its own policy grants.
    let mut declared_permissive: BTreeMap<String, Vec<&DB::Policy>> = BTreeMap::new();
    for policy in db.policies() {
        if derive_policy_mode(policy) != PolicyMode::Permissive {
            continue;
        }
        let key = table_group_key(db, policy.target_table_name().to_string(), &mut group_keys);
        declared_permissive.entry(key).or_default().push(policy);
    }

    let table_types = TableTypes::assign(db, &mut notes);
    let recursion = PolicyReadRecursion::detect(db, &table_types);
    // Answered once per membership table rather than once per clause naming it.
    let mut readability: BTreeMap<String, JoinTableReadability> = BTreeMap::new();
    let readability = &mut readability;

    for (source_table_name, table_policies) in by_table {
        // Only RLS-enabled tables that resolve against the schema get a type. A name
        // the schema cannot resolve carries the policy nowhere, so say so.
        let Some(canonical_table_name) = table_types.get(db, &source_table_name) else {
            if lookup_table(db, &source_table_name).is_none() {
                for cp in &table_policies {
                    notes.push(TranslationNote::UnresolvedPolicyTable {
                        policy: cp.name().to_string(),
                        named: source_table_name.clone(),
                    });
                }
            }
            continue;
        };
        let canonical_table_name = canonical_table_name.to_string();

        let mut table_plan = all_types
            .remove(&canonical_table_name)
            .unwrap_or_else(|| TypePlan::new(&canonical_table_name));

        // A clause reading a table whose policies loop cannot be planned, so PostgreSQL
        // raises rather than filtering and every command that clause feeds must deny.
        let recursive_targets = recursion.blocked_targets(&canonical_table_name);

        // Whether a row of this table can be named at all, which decides whether any tuple
        // source can be emitted for it. Resolved once here rather than per policy.
        let object_identifier = resolve_pk_column(&source_table_name, db);

        // UPDATE and DELETE name the row they change. INSERT does not.
        let has_row_scoped_write_policy = table_policies.iter().any(|cp| {
            cp.mode() == PolicyMode::Permissive
                && matches!(
                    cp.command(),
                    PolicyCommand::Update | PolicyCommand::Delete | PolicyCommand::All
                )
        });

        let mut action_buckets: BTreeMap<ActionTarget, ModeBuckets> = BTreeMap::new();

        for cp in table_policies {
            // A policy the schema gives no clause constrains nothing, so it must not
            // mint a scope relation or ask for tuples either.
            if cp.using.is_none() && cp.with_check.is_none() {
                continue;
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
                continue;
            }
            if let Some(ref c) = cp.using_classification {
                confidence_summary.push((cp.name().to_string(), c.confidence));
            }
            if let Some(ref c) = cp.with_check_classification {
                confidence_summary.push((format!("{} (WITH CHECK)", cp.name()), c.confidence));
            }

            let scoped_roles = cp.scoped_roles();
            // A barrier is folded as `(base and rule) or (base but not member from scope)`, so
            // an unfillable scope excuses everyone from it. Binding everyone instead denies
            // more than RLS does, which is the direction a missing input has to take. The
            // permissive side needs no such case: it intersects with the scope, so an empty
            // one already falls closed.
            let barrier_cannot_bind = !scoped_roles.is_empty()
                && cp.mode() == PolicyMode::Restrictive
                && object_identifier.is_none();
            if barrier_cannot_bind {
                notes.push(TranslationNote::RestrictiveBarrierBindsEveryone {
                    policy: cp.name().to_string(),
                    roles: scoped_roles.to_vec(),
                });
            }
            let scope_relation = if scoped_roles.is_empty() || barrier_cannot_bind {
                None
            } else {
                has_role_scopes = true;
                let relation = policy_scope_relation_name(cp.name());
                register_pg_role_scope(
                    &mut table_plan,
                    &mut all_types,
                    &source_table_name,
                    &relation,
                    scoped_roles,
                    cp.name(),
                    TranslationNote::PolicyRoleScope {
                        policy: cp.name().to_string(),
                        roles: scoped_roles.to_vec(),
                        relation: relation.clone(),
                    },
                    db,
                    &mut notes,
                    "policy scope tuples",
                );
                Some(relation)
            };

            // A policy covering several phases is translated once per phase, so the
            // same clause reports the same item repeatedly. Keep one per policy.
            let notes_before = notes.len();
            for_each_policy_target_expr(cp, |target, classified| {
                if recursive_targets.contains_key(&target) {
                    // Nothing here can be planned, so translating it leaves dead relations.
                    return;
                }
                let expr = translate_pattern(
                    &classified.pattern,
                    cp.name(),
                    &mut table_plan,
                    &mut all_types,
                    registry,
                    &mut notes,
                    &role_threshold_resource_hints,
                    db,
                    &table_types,
                    &source_table_name,
                    settings,
                    readability,
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
                        notes.retain(|note| *note != superseded);
                    }
                    notes.push(TranslationNote::RestrictiveAttributeRefused {
                        policy: cp.name().to_string(),
                    });
                    UsersetExpr::Intersection(vec![expr, deny_expr(&mut table_plan)])
                } else {
                    expr
                };
                push_action_expr(
                    &mut action_buckets,
                    target,
                    cp.name(),
                    cp.mode(),
                    expr,
                    scope_relation.as_deref(),
                );
            });
            dedup_notes_added_since(&mut notes, notes_before);
        }

        let mut select_expr =
            compose_action(&mut table_plan, action_buckets.get(&ActionTarget::Select));
        let mut insert_expr =
            compose_action(&mut table_plan, action_buckets.get(&ActionTarget::Insert));
        let mut update_using_expr = compose_action(
            &mut table_plan,
            action_buckets.get(&ActionTarget::UpdateUsing),
        );
        // Composed only where an existing row can pass, since a WITH CHECK admits
        // the new row alone and never stands in for the missing USING.
        let mut update_check_expr = update_using_expr.is_some().then(|| {
            compose_action(
                &mut table_plan,
                action_buckets.get(&ActionTarget::UpdateCheck),
            )
        });
        let mut delete_expr =
            compose_action(&mut table_plan, action_buckets.get(&ActionTarget::Delete));

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
        for (_, command, targets) in ACTION_RELATION_COMMANDS {
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
            notes.push(TranslationNote::PolicyReadRecursion {
                table: source_table_name.clone(),
                commands: commands.into_iter().map(ToString::to_string).collect(),
                cycle: cycle.to_vec(),
            });
        }

        if let Some(expr) = select_expr.take() {
            table_plan.set_computed(CAN_SELECT_RELATION, expr);
        }
        if let Some(expr) = insert_expr.take() {
            table_plan.set_computed(
                CAN_INSERT_RETURNING_RELATION,
                requires_read_access(expr.clone()),
            );
            table_plan.set_computed(CAN_INSERT_RELATION, expr);
        }
        // PostgreSQL applies the SELECT policies to any row a statement reads, and
        // naming the row to change reads it.
        if let Some(expr) = delete_expr.take() {
            table_plan.set_computed(CAN_DELETE_RELATION, requires_read_access(expr));
        }

        if let Some(using_expr) = update_using_expr.take() {
            let check_expr = update_check_expr
                .take()
                .flatten()
                .unwrap_or_else(|| using_expr.clone());
            // An update that names no row reads nothing, so `PostgreSQL` applies the
            // UPDATE policies to it and not the SELECT policies. Check this relation
            // only for `UPDATE t SET c = ...` with no WHERE: pick it for a statement
            // that does name rows and the grant is wider than the database's.
            let blanket = if using_expr == check_expr {
                using_expr.clone()
            } else {
                UsersetExpr::Intersection(vec![using_expr.clone(), check_expr.clone()])
            };
            table_plan.set_computed(CAN_UPDATE_WITHOUT_READING_RELATION, blanket);
            if using_expr == check_expr {
                table_plan.set_computed(CAN_UPDATE_RELATION, requires_read_access(using_expr));
            } else {
                table_plan
                    .set_computed(CAN_UPDATE_USING_RELATION, requires_read_access(using_expr));
                table_plan.set_computed(CAN_UPDATE_CHECK_RELATION, check_expr);
                table_plan.set_computed(
                    CAN_UPDATE_RELATION,
                    UsersetExpr::Intersection(vec![
                        UsersetExpr::Computed(CAN_UPDATE_USING_RELATION.to_string()),
                        UsersetExpr::Computed(CAN_UPDATE_CHECK_RELATION.to_string()),
                    ]),
                );
            }
        }

        // An undefined action relation reads as "the consumer decides", which is
        // how RLS coverage gaps become open access.
        let declared_here: &[&DB::Policy] = declared_permissive
            .get(&source_table_name)
            .map_or(&[], Vec::as_slice);
        let uncovered: Vec<&'static str> = fill_uncovered_actions_with_deny(&mut table_plan)
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
                    table: source_table_name.clone(),
                    commands: unpolicied.iter().map(|c| (*c).to_string()).collect(),
                });
            }
            if !dropped.is_empty() {
                notes.push(TranslationNote::CoveringPoliciesBelowThreshold {
                    table: source_table_name.clone(),
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
            && table_plan
                .computed_relations
                .get(CAN_SELECT_RELATION)
                .is_some_and(|expr| grants_nothing(expr, &table_plan, &mut BTreeSet::new()))
        {
            notes.push(TranslationNote::ReadsDeniedSoWritesCannotName {
                table: source_table_name.clone(),
            });
        }

        all_types.insert(canonical_table_name, table_plan);
    }

    if has_role_scopes {
        ensure_pg_role_type(&mut all_types);
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

    let mut type_names: Vec<String> = all_types.keys().cloned().collect();
    type_names.sort();
    if let Some(pos) = type_names.iter().position(|n| n == USER_TYPE) {
        let user = type_names.remove(pos);
        type_names.insert(0, user);
    }

    let types: Vec<TypePlan> = type_names
        .into_iter()
        .filter_map(|name| all_types.remove(&name))
        .collect();

    // Only the conditions a surviving reference still names are declared, so a policy
    // dropped by confidence filtering cannot leave a condition behind.
    let named: BTreeSet<&str> = types
        .iter()
        .flat_map(|plan| plan.direct_relations.values())
        .flatten()
        .filter_map(|subject| match subject {
            DirectSubject::ConditionalWildcard { condition, .. } => Some(condition.as_str()),
            DirectSubject::Type(_) | DirectSubject::Wildcard(_) => None,
        })
        .collect();
    let conditions: BTreeMap<String, ConditionSpec> = types
        .iter()
        .flat_map(|plan| plan.conditions.iter())
        .filter(|(name, _)| named.contains(name.as_str()))
        .map(|(name, spec)| (name.clone(), spec.clone()))
        .collect();

    SchemaPlan {
        types,
        notes,
        confidence_summary,
        conditions,
    }
}

/// The rule a `can_select` gate wraps, if this expression is such a gate.
fn select_gate_rule(expr: &UsersetExpr) -> Option<&UsersetExpr> {
    let UsersetExpr::Intersection(children) = expr else {
        return None;
    };
    let [rule, UsersetExpr::Computed(gate)] = children.as_slice() else {
        return None;
    };
    (gate == CAN_SELECT_RELATION).then_some(rule)
}

/// Whether `rule` can only hold where `visible` holds. Unrecognized shapes keep the
/// gate.
fn rule_implies(
    rule: &UsersetExpr,
    visible: &UsersetExpr,
    relations: &BTreeMap<String, UsersetExpr>,
    seen: &mut BTreeSet<String>,
) -> bool {
    if userset_key(rule) == userset_key(visible) {
        return true;
    }
    match visible {
        // Any branch that admits the rule admits it for the whole union.
        UsersetExpr::Union(branches) => branches
            .iter()
            .any(|branch| rule_implies(rule, branch, relations, seen)),
        // Every conjunct has to admit it.
        UsersetExpr::Intersection(children) => children
            .iter()
            .all(|child| rule_implies(rule, child, relations, seen)),
        // A named relation stands for its own definition. Levels of a role
        // hierarchy chain through here, and `seen` keeps a cycle from looping.
        UsersetExpr::Computed(name) => {
            seen.insert(name.clone())
                && relations
                    .get(name)
                    .is_some_and(|expr| rule_implies(rule, expr, relations, seen))
        }
        // An exclusion can remove the rule's own members, so it admits nothing.
        UsersetExpr::TupleToUserset { .. } | UsersetExpr::Exclusion { .. } => false,
    }
}

/// Require the row to be readable, which every per-row change does.
fn requires_read_access(expr: UsersetExpr) -> UsersetExpr {
    UsersetExpr::Intersection(vec![
        expr,
        UsersetExpr::Computed(CAN_SELECT_RELATION.to_string()),
    ])
}

/// Report the principals row level security does not reach.
///
/// The model keeps describing the rules that do apply. Modelling a bypass as a
/// permission would be the largest widening available here, and it misfires the moment
/// a service account stops running as the exempt principal.
///
/// The table's owner is the third mechanism and is not reported by name: the upstream
/// parser discards `ALTER TABLE ... OWNER TO`, so only the absence of `FORCE` is
/// visible. See `docs/upstream/`.
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

/// Drop a `can_select` gate the rule already implies.
fn simplify_redundant_select_gates(all_types: &mut BTreeMap<String, TypePlan>) {
    for plan in all_types.values_mut() {
        let relations = plan.computed_relations.clone();
        let Some(visible) = relations.get(CAN_SELECT_RELATION) else {
            continue;
        };
        for (relation, expr) in &mut plan.computed_relations {
            if relation == CAN_SELECT_RELATION {
                continue;
            }
            let Some(rule) = select_gate_rule(expr) else {
                continue;
            };
            if rule_implies(rule, visible, &relations, &mut BTreeSet::new()) {
                *expr = rule.clone();
            }
        }
    }
}

/// Drop the readback relation where it repeats `can_insert`, since a relation
/// that adds no requirement is noise.
fn drop_implied_insert_readback(all_types: &mut BTreeMap<String, TypePlan>) {
    for plan in all_types.values_mut() {
        let repeats = plan
            .computed_relations
            .get(CAN_INSERT_RETURNING_RELATION)
            .zip(plan.computed_relations.get(CAN_INSERT_RELATION))
            .is_some_and(|(readback, insert)| readback == insert);
        if repeats {
            plan.computed_relations
                .remove(CAN_INSERT_RETURNING_RELATION);
        }
    }
}

/// Inline a synthesized rule relation that is just another name for one relation on
/// the same type. Only generated holders are disposable.
fn inline_synthetic_rule_aliases(all_types: &mut BTreeMap<String, TypePlan>) {
    let mut aliases: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    for (type_name, plan) in all_types.iter() {
        for (relation, expr) in &plan.computed_relations {
            if !relation.starts_with(INHERITED_RELATION_PREFIX) {
                continue;
            }
            let UsersetExpr::Computed(target) = expr else {
                continue;
            };
            if plan.direct_relations.contains_key(target)
                || plan.computed_relations.contains_key(target)
            {
                aliases
                    .entry(type_name.clone())
                    .or_default()
                    .insert(relation.clone(), target.clone());
            }
        }
    }
    if aliases.is_empty() {
        return;
    }

    for plan in all_types.values_mut() {
        let TypePlan {
            type_name,
            direct_relations,
            computed_relations,
            ..
        } = plan;
        if let Some(dropped) = aliases.get(type_name.as_str()) {
            computed_relations.retain(|relation, _| !dropped.contains_key(relation));
        }
        let own = aliases.get(type_name.as_str());
        for expr in computed_relations.values_mut() {
            repoint_inlined_aliases(expr, direct_relations, own, &aliases);
        }
    }
}

/// Point every reference to an inlined alias at the relation it named.
fn repoint_inlined_aliases(
    expr: &mut UsersetExpr,
    direct_relations: &BTreeMap<String, Vec<DirectSubject>>,
    own: Option<&BTreeMap<String, String>>,
    aliases: &BTreeMap<String, BTreeMap<String, String>>,
) {
    match expr {
        UsersetExpr::Computed(name) => {
            if let Some(replacement) = own.and_then(|dropped| dropped.get(name.as_str())) {
                *name = replacement.clone();
            }
        }
        UsersetExpr::TupleToUserset { tupleset, computed } => {
            // The walked relation is evaluated on the types the tupleset admits.
            let replacement = direct_relations
                .get(tupleset.as_str())
                .into_iter()
                .flatten()
                .filter_map(|subject| match subject {
                    DirectSubject::Type(name) => aliases.get(name.as_str()),
                    DirectSubject::Wildcard(_) | DirectSubject::ConditionalWildcard { .. } => None,
                })
                .find_map(|dropped| dropped.get(computed.as_str()));
            if let Some(replacement) = replacement {
                *computed = replacement.clone();
            }
        }
        UsersetExpr::Union(children) | UsersetExpr::Intersection(children) => {
            for child in children {
                repoint_inlined_aliases(child, direct_relations, own, aliases);
            }
        }
        UsersetExpr::Exclusion { base, subtract } => {
            repoint_inlined_aliases(base, direct_relations, own, aliases);
            repoint_inlined_aliases(subtract, direct_relations, own, aliases);
        }
    }
}

/// Every `(type, relation)` a permission can consult. Anything unresolved counts as
/// reachable, since dropping a needed query would narrow the model.
pub(crate) fn grantable_relations(types: &[TypePlan]) -> BTreeSet<(String, String)> {
    let by_name: BTreeMap<&str, &TypePlan> = types
        .iter()
        .map(|plan| (plan.type_name.as_str(), plan))
        .collect();
    let mut reached: BTreeSet<(String, String)> = BTreeSet::new();
    for plan in types {
        for action in action_relations().chain(DERIVED_ACTION_RELATIONS) {
            let Some(expr) = plan.computed_relations.get(action) else {
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

/// Every `(type, relation)` some definition names, a denying one included.
///
/// Deliberately not [`grantable_relations`], which stops at a permission that grants
/// nothing. A relation only a denial names still has to stay declared, or the model
/// carries a reference to something it does not define.
fn referenced_relations(types: &[TypePlan]) -> BTreeSet<(String, String)> {
    let by_name: BTreeMap<&str, &TypePlan> = types
        .iter()
        .map(|plan| (plan.type_name.as_str(), plan))
        .collect();
    let mut reached: BTreeSet<(String, String)> = BTreeSet::new();
    for plan in types {
        for action in action_relations().chain(DERIVED_ACTION_RELATIONS) {
            if let Some(expr) = plan.computed_relations.get(action) {
                reach_userset(expr, plan, &by_name, &mut reached);
            }
        }
    }
    reached
}

/// Drop relations no permission names. They are declared, no tuple query feeds them,
/// and nothing can consult them, so the model advertises access it can never grant.
///
/// An operator hand-writing their own facts for such a relation will no longer find it
/// in the model, which is the point: it never did anything.
fn prune_unreferenced_relations(all_types: &mut BTreeMap<String, TypePlan>) {
    let types: Vec<TypePlan> = all_types.values().cloned().collect();
    let referenced = referenced_relations(&types);
    for plan in all_types.values_mut() {
        let owner = plan.type_name.clone();
        plan.direct_relations
            .retain(|name, _| referenced.contains(&(owner.clone(), name.clone())));
        plan.computed_relations.retain(|name, _| {
            generator_defines(name) || referenced.contains(&(owner.clone(), name.clone()))
        });
    }
}

/// Whether an expression can never grant. Only certainty is reported.
fn grants_nothing(expr: &UsersetExpr, plan: &TypePlan, seen: &mut BTreeSet<String>) -> bool {
    match expr {
        UsersetExpr::Computed(name) if name == DENY_RELATION => true,
        UsersetExpr::Computed(name) => {
            seen.insert(name.clone())
                && plan
                    .computed_relations
                    .get(name)
                    .is_some_and(|expr| grants_nothing(expr, plan, seen))
        }
        // One conjunct that never holds denies the whole intersection.
        UsersetExpr::Intersection(children) => children
            .iter()
            .any(|child| grants_nothing(child, plan, seen)),
        UsersetExpr::Union(children) => children
            .iter()
            .all(|child| grants_nothing(child, plan, seen)),
        // Subtracting from nothing still grants nothing, and how much a subtraction
        // removes is unknowable here.
        UsersetExpr::Exclusion { base, .. } => grants_nothing(base, plan, seen),
        UsersetExpr::TupleToUserset { .. } => false,
    }
}

fn reach_userset(
    expr: &UsersetExpr,
    plan: &TypePlan,
    by_name: &BTreeMap<&str, &TypePlan>,
    reached: &mut BTreeSet<(String, String)>,
) {
    match expr {
        UsersetExpr::Computed(name) => {
            if !reached.insert((plan.type_name.clone(), name.clone())) {
                return;
            }
            if let Some(inner) = plan.computed_relations.get(name) {
                reach_userset(inner, plan, by_name, reached);
            }
        }
        UsersetExpr::TupleToUserset { tupleset, computed } => {
            reached.insert((plan.type_name.clone(), tupleset.clone()));
            // The walked relation is evaluated on every type the tupleset admits.
            for target in plan
                .direct_relations
                .get(tupleset)
                .into_iter()
                .flatten()
                .filter_map(|subject| match subject {
                    DirectSubject::Type(name) => by_name.get(name.as_str()),
                    DirectSubject::Wildcard(_) | DirectSubject::ConditionalWildcard { .. } => None,
                })
            {
                if !reached.insert((target.type_name.clone(), computed.clone())) {
                    continue;
                }
                if let Some(inner) = target.computed_relations.get(computed) {
                    reach_userset(inner, target, by_name, reached);
                }
            }
        }
        UsersetExpr::Union(children) | UsersetExpr::Intersection(children) => {
            for child in children {
                reach_userset(child, plan, by_name, reached);
            }
        }
        // Both sides are consulted, so both keep their tuples.
        UsersetExpr::Exclusion { base, subtract } => {
            reach_userset(base, plan, by_name, reached);
            reach_userset(subtract, plan, by_name, reached);
        }
    }
}

fn scoped_policy_expr(expr: UsersetExpr, scope_relation: &str) -> UsersetExpr {
    UsersetExpr::Intersection(vec![
        expr,
        UsersetExpr::TupleToUserset {
            tupleset: scope_relation.to_string(),
            computed: MEMBER_RELATION.to_string(),
        },
    ])
}

fn using_targets(command: PolicyCommand) -> Vec<ActionTarget> {
    match command {
        PolicyCommand::Select => vec![ActionTarget::Select],
        PolicyCommand::Insert => vec![],
        PolicyCommand::Update => vec![ActionTarget::UpdateUsing],
        PolicyCommand::Delete => vec![ActionTarget::Delete],
        PolicyCommand::All => vec![
            ActionTarget::Select,
            ActionTarget::UpdateUsing,
            ActionTarget::Delete,
        ],
    }
}

fn with_check_targets(command: PolicyCommand) -> Vec<ActionTarget> {
    match command {
        PolicyCommand::Insert => vec![ActionTarget::Insert],
        PolicyCommand::Update => vec![ActionTarget::UpdateCheck],
        PolicyCommand::Select | PolicyCommand::Delete => vec![],
        PolicyCommand::All => vec![ActionTarget::Insert, ActionTarget::UpdateCheck],
    }
}

fn policy_uses_using_for_missing_with_check(command: PolicyCommand) -> bool {
    matches!(
        command,
        PolicyCommand::All | PolicyCommand::Update | PolicyCommand::Insert
    )
}

/// Stand-in expression for a RESTRICTIVE clause dropped by confidence filtering:
/// `PostgreSQL` ANDs it onto the permissive union, so it must deny.
fn dropped_restrictive_expr(cp: &ClassifiedPolicy, clause_sql: Option<String>) -> ClassifiedExpr {
    ClassifiedExpr {
        pattern: PatternClass::Unknown {
            sql_text: clause_sql.unwrap_or_default(),
            reason: format!(
                "RESTRICTIVE policy '{}' could not be translated at the requested confidence \
                 level; PostgreSQL ANDs it onto every other policy, so the command is denied \
                 rather than left unconstrained",
                cp.name()
            ),
        },
        confidence: ConfidenceLevel::D,
    }
}

/// Attribute guards this pattern discards, which widens whatever it guards.
fn dropped_attribute_guards(pattern: &PatternClass) -> Vec<&str> {
    match pattern {
        PatternClass::P7AbacAnd { attribute_part, .. } => vec![attribute_part.as_str()],
        PatternClass::P8Composite { parts, .. } => parts
            .iter()
            .flat_map(|part| dropped_attribute_guards(&part.pattern))
            .collect(),
        _ => Vec::new(),
    }
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

fn for_each_policy_target_expr<F>(cp: &ClassifiedPolicy, mut f: F)
where
    F: FnMut(ActionTarget, &ClassifiedExpr),
{
    let restrictive = cp.mode() == PolicyMode::Restrictive;

    let dropped_using = (restrictive && cp.using_was_filtered)
        .then(|| dropped_restrictive_expr(cp, cp.using.as_ref().map(ToString::to_string)));
    if let Some(using) = cp.using_classification.as_ref().or(dropped_using.as_ref()) {
        for target in using_targets(cp.command()) {
            f(target, using);
        }
    }

    // Mirror USING → WITH CHECK only when the SQL had no WITH CHECK at all. A filtered
    // one falls closed instead.
    let dropped_with_check = (restrictive && cp.with_check_was_filtered)
        .then(|| dropped_restrictive_expr(cp, cp.with_check.as_ref().map(ToString::to_string)));
    let with_check_pattern = cp
        .with_check_classification
        .as_ref()
        .or(dropped_with_check.as_ref())
        .or_else(|| {
            if !cp.with_check_was_filtered && policy_uses_using_for_missing_with_check(cp.command())
            {
                cp.using_classification.as_ref()
            } else {
                None
            }
        });

    if let Some(with_check) = with_check_pattern {
        for target in with_check_targets(cp.command()) {
            f(target, with_check);
        }
    }
}

/// Route one translated clause into its bucket.
///
/// A role scope narrows a PERMISSIVE grant, since the other permissive policies
/// still stand for everyone else. A RESTRICTIVE barrier instead binds only the
/// roles it names, which `compose_action` can express only once the base is known.
fn push_action_expr(
    action_buckets: &mut BTreeMap<ActionTarget, ModeBuckets>,
    target: ActionTarget,
    policy_name: &str,
    mode: PolicyMode,
    expr: UsersetExpr,
    scope_relation: Option<&str>,
) {
    let bucket = action_buckets.entry(target).or_default();
    match (mode, scope_relation) {
        (PolicyMode::Permissive, Some(scope)) => {
            bucket.permissive.push(scoped_policy_expr(expr, scope));
        }
        (PolicyMode::Permissive, None) => bucket.permissive.push(expr),
        (PolicyMode::Restrictive, Some(scope)) => bucket.role_limited.push(RoleLimitedRule {
            policy: policy_name.to_string(),
            rule: expr,
            scope_relation: scope.to_string(),
        }),
        (PolicyMode::Restrictive, None) => bucket.restrictive.push(expr),
    }
}

#[allow(clippy::too_many_arguments)]
fn register_pg_role_scope<DB: DatabaseLike>(
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<String, TypePlan>,
    source_table: &str,
    scope_relation: &str,
    role_names: &[String],
    policy_name: &str,
    scope_note: TranslationNote,
    db: &DB,
    notes: &mut Vec<TranslationNote>,
    missing_object_what: &str,
) {
    ensure_pg_role_type(all_types);

    table_plan.ensure_direct(
        scope_relation.to_string(),
        vec![DirectSubject::Type(PG_ROLE_TYPE.to_string())],
    );
    notes.push(scope_note);

    if let Some(pk_col) = resolve_pk_column(source_table, db) {
        for role in role_names {
            let pg_role = canonical_fga_type_name(role);
            // A quoted role can rewrite onto a different existing role, which
            // changes who the policy admits.
            if normalize_identifier(role) != pg_role {
                notes.push(TranslationNote::RoleNameRewritten {
                    policy: policy_name.to_string(),
                    role: role.clone(),
                    pg_role: pg_role.clone(),
                });
            }
            table_plan.add_source(TupleSource::PolicyScope {
                table: source_table.to_string(),
                pk_col: pk_col.clone(),
                scope_relation: scope_relation.to_string(),
                pg_role,
            });
        }
    } else {
        add_missing_object_identifier_note(table_plan, source_table, missing_object_what, db);
    }
}

fn compose_action(table_plan: &mut TypePlan, bucket: Option<&ModeBuckets>) -> Option<UsersetExpr> {
    let bucket = bucket?;

    let permissive = combine_union(bucket.permissive.clone());
    let restrictive = combine_intersection(bucket.restrictive.clone());

    let Some(permissive) = permissive else {
        // Barriers alone grant nobody anything, whichever roles they bind.
        return (restrictive.is_some() || !bucket.role_limited.is_empty())
            .then(|| deny_expr(table_plan));
    };

    let mut expr = match restrictive {
        Some(restrictive) => UsersetExpr::Intersection(vec![permissive, restrictive]),
        None => permissive,
    };

    // Members of the bound roles have to satisfy the barrier, everyone else is
    // untouched by it. Each barrier wraps the previous result, so a second one costs
    // one more relation rather than doubling the tree.
    for limited in &bucket.role_limited {
        let bound = UsersetExpr::Intersection(vec![expr.clone(), limited.rule.clone()]);
        let unbound = UsersetExpr::Exclusion {
            base: Box::new(expr),
            subtract: Box::new(UsersetExpr::TupleToUserset {
                tupleset: limited.scope_relation.clone(),
                computed: MEMBER_RELATION.to_string(),
            }),
        };
        let name = table_plan.ensure_computed(
            role_limited_relation_name(&limited.policy),
            UsersetExpr::Union(vec![bound, unbound]),
        );
        expr = UsersetExpr::Computed(name);
    }

    Some(expr)
}

/// Quote `part` for a table-lookup key unless it is a bare lowercase identifier.
/// `lookup_table` tries both spellings, so this form resolves either way.
fn quoted_for_lookup(part: &str) -> String {
    let is_bare = !part.is_empty()
        && !part.starts_with(|ch: char| ch.is_ascii_digit())
        && part
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_');
    if is_bare {
        part.to_string()
    } else {
        format!("\"{}\"", part.replace('"', "\"\""))
    }
}

/// Schema-qualified stored name, in the spelling `lookup_table` resolves.
fn qualified_table_name<T: TableLike>(table: &T) -> String {
    let relation = quoted_for_lookup(&table.stored_table_name());
    match table.stored_table_schema() {
        Some(schema) => format!("{}.{relation}", quoted_for_lookup(&schema)),
        None => relation,
    }
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
fn table_identity<T: TableLike>(table: &T) -> (Option<String>, String) {
    (
        table.table_schema().map(ToString::to_string),
        table.table_name().to_string(),
    )
}

/// Final `OpenFGA` type name of every table that gets one, assigned in one pass so a
/// parent reference resolves to the same type as the table's own policies.
struct TypeOwner {
    identity: (Option<String>, String),
    /// Spelling used in the schema, for the collision message.
    spelling: String,
}

#[derive(Default)]
struct TableTypes {
    by_identity: BTreeMap<(Option<String>, String), String>,
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
    /// One type name per RLS-enabled table, collisions suffixed with a hash of the
    /// qualified name.
    ///
    /// Derived from the schema alone, never from which policies survived filtering,
    /// so names do not move with the confidence threshold. Tables carrying policies
    /// claim their canonical name first.
    fn assign<DB: DatabaseLike>(db: &DB, notes: &mut Vec<TranslationNote>) -> Self {
        let mut types = Self::default();
        let mut policied: BTreeSet<(Option<String>, String)> = BTreeSet::new();
        for policy in db.policies() {
            if let Some(table) = lookup_table(db, &policy.target_table_name().to_string()) {
                policied.insert(table_identity(table));
            }
        }

        let mut names: Vec<(bool, String)> = db
            .tables()
            .filter(|table| table.has_row_level_security(db) != Ok(false))
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

/// Prefix for relations synthesized to hold a parent-side rule.
const INHERITED_RELATION_PREFIX: &str = "inherited_";

/// Action relations, the SQL command each answers for, and the clause targets a
/// policy has to reach before any row passes that command.
const ACTION_RELATION_COMMANDS: [(&str, &str, &[ActionTarget]); 4] = [
    (CAN_SELECT_RELATION, "SELECT", &[ActionTarget::Select]),
    (CAN_INSERT_RELATION, "INSERT", &[ActionTarget::Insert]),
    (
        CAN_UPDATE_RELATION,
        "UPDATE",
        &[ActionTarget::UpdateUsing, ActionTarget::UpdateCheck],
    ),
    (CAN_DELETE_RELATION, "DELETE", &[ActionTarget::Delete]),
];

/// The action relations alone, in command order.
fn action_relations() -> impl Iterator<Item = &'static str> {
    ACTION_RELATION_COMMANDS
        .into_iter()
        .map(|(relation, _, _)| relation)
}

/// Relations a statement shape needs rather than a bare SQL command name.
const DERIVED_ACTION_RELATIONS: [&str; 6] = [
    CAN_UPDATE_USING_RELATION,
    CAN_UPDATE_CHECK_RELATION,
    CAN_UPDATE_WITHOUT_READING_RELATION,
    CAN_INSERT_RETURNING_RELATION,
    CAN_UPSERT_RELATION,
    CAN_SELECT_FOR_UPDATE_RELATION,
];

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

/// Action targets a policy's stored clauses reach, which is the routing
/// `for_each_policy_target_expr` performs once those clauses are classified.
fn policy_clause_targets<P: PolicyLike>(policy: &P, db: &P::DB) -> BTreeSet<ActionTarget> {
    recursion::declared_clause_targets(policy, db)
        .into_iter()
        .filter(|(clause, _)| clause.is_some())
        .flat_map(|(_, targets)| targets)
        .collect()
}

/// Commands the schema's permissive policies on one table cover, whatever their
/// confidence. The filtered policy set cannot answer this, and the answer decides
/// whether a denied command is a coverage gap in `PostgreSQL` or in the translation.
fn commands_a_permissive_policy_covers<P: PolicyLike>(
    declared: &[&P],
    db: &P::DB,
) -> BTreeSet<&'static str> {
    let mut commands = BTreeSet::new();
    for policy in declared {
        let reached = policy_clause_targets(*policy, db);
        commands.extend(
            ACTION_RELATION_COMMANDS
                .into_iter()
                .filter(|(_, _, needed)| needed.iter().all(|target| reached.contains(target)))
                .map(|(_, command, _)| command),
        );
    }
    commands
}

/// Permissive policies that name a command without storing the clause it reads,
/// as `(policy, commands, clause)`. `PostgreSQL` finds no qual for those, so the
/// policy admits nothing and the schema reads as if it covered them.
fn policies_missing_a_clause<P: PolicyLike>(
    declared: &[&P],
    db: &P::DB,
) -> Vec<(String, String, &'static str)> {
    let mut missing = Vec::new();
    for policy in declared {
        if policy.using_expression(db).is_some() {
            continue;
        }
        let command = PolicyCommand::from(policy.command());
        let checks: BTreeSet<ActionTarget> = with_check_targets(command).into_iter().collect();
        let applies: BTreeSet<ActionTarget> = using_targets(command)
            .into_iter()
            .chain(checks.iter().copied())
            .collect();

        let mut needs_using = Vec::new();
        let mut needs_check = Vec::new();
        for (_, named, targets) in ACTION_RELATION_COMMANDS {
            if !targets.iter().any(|target| applies.contains(target)) {
                continue;
            }
            // A command every one of whose targets a WITH CHECK feeds, which is the
            // INSERT, survives a missing USING.
            if targets.iter().all(|target| checks.contains(target)) {
                needs_check.push(named);
            } else {
                needs_using.push(named);
            }
        }

        if !needs_using.is_empty() {
            missing.push((policy.name().to_string(), needs_using.join(", "), "USING"));
        }
        if !needs_check.is_empty() && policy.check_expression(db).is_none() {
            missing.push((
                policy.name().to_string(),
                needs_check.join(", "),
                "WITH CHECK",
            ));
        }
    }
    missing
}

/// Deny every action relation no policy produced, returning the denied commands.
fn fill_uncovered_actions_with_deny(table_plan: &mut TypePlan) -> Vec<&'static str> {
    let missing: Vec<(&'static str, &'static str)> = ACTION_RELATION_COMMANDS
        .into_iter()
        .filter(|(relation, _, _)| !table_plan.computed_relations.contains_key(*relation))
        .map(|(relation, command, _)| (relation, command))
        .collect();
    if missing.is_empty() {
        return Vec::new();
    }
    let deny = deny_expr(table_plan);
    for (relation, _) in &missing {
        table_plan.set_computed(*relation, deny.clone());
    }
    missing.into_iter().map(|(_, command)| command).collect()
}

/// Answer for `INSERT ... ON CONFLICT ... DO UPDATE`, which updates the conflicting
/// row and so needs the UPDATE policies too. Runs once the actions are final, and
/// is left out wherever it would add no requirement to `can_insert`.
fn define_upsert_relations(all_types: &mut BTreeMap<String, TypePlan>) {
    for plan in all_types.values_mut() {
        let Some(insert) = plan.computed_relations.get(CAN_INSERT_RELATION) else {
            continue;
        };
        let adds_nothing = grants_nothing(insert, plan, &mut BTreeSet::new())
            || plan
                .computed_relations
                .get(CAN_UPDATE_RELATION)
                .is_some_and(|update| update == insert);
        if adds_nothing {
            continue;
        }
        plan.set_computed(
            CAN_UPSERT_RELATION,
            UsersetExpr::Intersection(vec![
                UsersetExpr::Computed(CAN_INSERT_RELATION.to_string()),
                UsersetExpr::Computed(CAN_UPDATE_RELATION.to_string()),
            ]),
        );
    }
}

/// Answer for a locking read, which `PostgreSQL` filters by the `UPDATE` policies'
/// `USING` clause as well as the `SELECT` policies. That is the `USING` half where
/// the two `UPDATE` clauses differ, and `can_update` itself where they agree or
/// where nothing admits an update. Runs once the actions are final.
fn define_locking_read_relations(all_types: &mut BTreeMap<String, TypePlan>) {
    for plan in all_types.values_mut() {
        if !plan.computed_relations.contains_key(CAN_UPDATE_RELATION) {
            continue;
        }
        let answers = if plan
            .computed_relations
            .contains_key(CAN_UPDATE_USING_RELATION)
        {
            CAN_UPDATE_USING_RELATION
        } else {
            CAN_UPDATE_RELATION
        };
        plan.set_computed(
            CAN_SELECT_FOR_UPDATE_RELATION,
            UsersetExpr::Computed(answers.to_string()),
        );
    }
}

/// Every type carries `can_update_without_reading`, because an action relation nobody
/// defined reads as "the consumer decides". Where no rule admits an update it points at
/// `can_update`, which is already the denial.
fn define_blanket_update_relations(all_types: &mut BTreeMap<String, TypePlan>) {
    for plan in all_types.values_mut() {
        if plan
            .computed_relations
            .contains_key(CAN_UPDATE_WITHOUT_READING_RELATION)
            || !plan.computed_relations.contains_key(CAN_UPDATE_RELATION)
        {
            continue;
        }
        plan.set_computed(
            CAN_UPDATE_WITHOUT_READING_RELATION,
            UsersetExpr::Computed(CAN_UPDATE_RELATION.to_string()),
        );
    }
}

/// Handle `P2RoleNameInList` when the function is *not* a `RoleThreshold` (e.g.
/// `pg_has_role()` or Supabase `auth.role()`).  Creates scope-style direct
/// relations per role name and emits `PolicyScope` tuple sources, mirroring the
/// pattern used for policy-level `TO` role scoping.
#[allow(clippy::too_many_arguments)]
fn handle_p2_role_gate<DB: DatabaseLike>(
    role_names: &[String],
    privilege: RolePrivilege,
    policy_name: &str,
    source_table: &str,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<String, TypePlan>,
    db: &DB,
    notes: &mut Vec<TranslationNote>,
) -> UsersetExpr {
    if role_names.is_empty() {
        return deny_expr(table_plan);
    }

    let scope_relation = policy_scope_relation_name(policy_name);
    let held_by = privilege.relation_name();
    register_pg_role_scope(
        table_plan,
        all_types,
        source_table,
        &scope_relation,
        role_names,
        policy_name,
        TranslationNote::RoleGateScope {
            policy: policy_name.to_string(),
            roles: role_names.to_vec(),
            relation: scope_relation.clone(),
            held_by: held_by.to_string(),
        },
        db,
        notes,
        "role gate tuples",
    );
    // Each kind of membership admits a different set, so each gets its own relation for the
    // operator to load. Sharing one would make those facts mean whichever policy was read.
    ensure_pg_role_relation(all_types, held_by);

    // The scope relation holds `[pg_role]` subjects, so a `user:` subject can never satisfy
    // it directly. Walking it to the role's holders is what admits them, and it is what
    // makes the relation survive the pruner.
    UsersetExpr::TupleToUserset {
        tupleset: scope_relation,
        computed: held_by.to_string(),
    }
}

fn deny_expr(table_plan: &mut TypePlan) -> UsersetExpr {
    table_plan.ensure_direct(
        DENY_RELATION,
        vec![DirectSubject::Type(USER_TYPE.to_string())],
    );
    UsersetExpr::Computed(DENY_RELATION.to_string())
}

fn public_expr(table_plan: &mut TypePlan) -> UsersetExpr {
    table_plan.ensure_direct(
        PUBLIC_RELATION,
        vec![DirectSubject::Wildcard(USER_TYPE.to_string())],
    );
    UsersetExpr::Computed(PUBLIC_RELATION.to_string())
}

/// Mint the relation, the condition and the tuple source a request-time guard needs.
///
/// Returns `None` when the row cannot be identified or the column's type has no
/// condition parameter type, so the caller falls back to closing the policy.
fn conditional_gate_expr<DB: DatabaseLike>(
    request: &AttributeRequestPredicate,
    policy_name: &str,
    source_table: &str,
    table_plan: &mut TypePlan,
    db: &DB,
    request_time_parameter: &str,
) -> Option<UsersetExpr> {
    let pk_col = resolve_pk_column(source_table, db)?;
    let parameter_type = condition_parameter_type(source_table, &request.column, db)?;

    let condition = gate_condition_name(&table_plan.type_name, policy_name);
    // A column named like the request's parameter yields, since two parameters cannot
    // share one name.
    let request_parameter = request_time_parameter.to_string();
    let mut row_parameter = normalize_relation_name(&request.column);
    if row_parameter == request_parameter {
        row_parameter = format!("{row_parameter}_{}", stable_hex_suffix(&request.column));
    }
    let operator = condition_operator(request.operator);

    table_plan.conditions.insert(
        condition.clone(),
        ConditionSpec {
            expression: format!("{row_parameter} {operator} {request_parameter}"),
            parameters: [
                (row_parameter.clone(), parameter_type.to_string()),
                (request_parameter, TIMESTAMP_PARAMETER_TYPE.to_string()),
            ]
            .into_iter()
            .collect(),
            row_parameter: (row_parameter.clone(), request.column.clone()),
        },
    );

    let relation = table_plan.ensure_direct(
        conditional_gate_relation_name(policy_name),
        vec![DirectSubject::ConditionalWildcard {
            type_name: USER_TYPE.to_string(),
            condition: condition.clone(),
        }],
    );
    table_plan.add_source(TupleSource::ConditionalAttributeGate {
        table: source_table.to_string(),
        pk_col,
        relation: relation.clone(),
        condition,
        row_parameter,
        column: request.column.clone(),
    });
    Some(UsersetExpr::Computed(relation))
}

/// `CEL` spelling of the comparison, which matches SQL for the operators reaching here.
fn condition_operator(operator: AttributeOperator) -> &'static str {
    match operator {
        AttributeOperator::Eq => "==",
        AttributeOperator::NotEq => "!=",
        AttributeOperator::Gt => ">",
        AttributeOperator::GtEq => ">=",
        AttributeOperator::Lt => "<",
        AttributeOperator::LtEq => "<=",
    }
}

/// The condition parameter type for a column, or `None` when the schema does not say
/// or the type has no `OpenFGA` counterpart.
fn condition_parameter_type<DB: DatabaseLike>(
    table: &str,
    column: &str,
    db: &DB,
) -> Option<&'static str> {
    let meta = lookup_table(db, table)?;
    let declared = meta
        .columns(db)
        .into_iter()
        .flatten()
        .find(|candidate| same_identifier(&candidate.stored_column_name(), column))?;
    let data_type = declared.data_type(db).to_lowercase();
    // A tuple's context must be RFC 3339, which only a zoned column renders: a date
    // carries no time part and a zoneless timestamp no offset, and `OpenFGA` v1.11.6
    // refuses both at load while accepting the model that named them.
    matches!(
        data_type.as_str(),
        "timestamptz" | "timestamp with time zone"
    )
    .then_some(TIMESTAMP_PARAMETER_TYPE)
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

/// Translate a pattern with schema-independent defaults.
#[cfg(test)]
fn pattern_to_expr(
    pattern: &PatternClass,
    policy_name: &str,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<String, TypePlan>,
    registry: &FunctionRegistry,
    notes: &mut Vec<TranslationNote>,
) -> UsersetExpr {
    let db = crate::parser::sql_parser::parse_schema("").expect("empty schema should parse");
    translate_pattern(
        pattern,
        policy_name,
        table_plan,
        all_types,
        registry,
        notes,
        &RoleThresholdResourceHints::default(),
        &db,
        &TableTypes::default(),
        "test_table",
        &GeneratorSettings::default(),
        &mut BTreeMap::new(),
    )
}

/// Build the userset expression for one classified pattern.
///
/// The result does not depend on which command the policy covers: inheritance
/// always reads the parent's SELECT relation, and the caller files the expression
/// under the right action.
#[allow(clippy::too_many_arguments)]
fn translate_pattern<DB: DatabaseLike>(
    pattern: &PatternClass,
    policy_name: &str,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<String, TypePlan>,
    registry: &FunctionRegistry,
    notes: &mut Vec<TranslationNote>,
    hints: &RoleThresholdResourceHints,
    db: &DB,
    table_types: &TableTypes,
    source_table: &str,
    settings: &GeneratorSettings,
    readability: &mut BTreeMap<String, JoinTableReadability>,
) -> UsersetExpr {
    match pattern {
        PatternClass::P1NumericThreshold {
            function_name,
            operator,
            threshold,
            ..
        } => {
            let Some(prepared) = prepare_role_threshold_translation(
                function_name,
                "Role-threshold",
                policy_name,
                source_table,
                table_plan,
                all_types,
                registry,
                hints,
                db,
                notes,
            ) else {
                return deny_expr(table_plan);
            };

            let min_level = match operator {
                ThresholdOperator::Gte => *threshold,
                ThresholdOperator::Gt => threshold.saturating_add(1),
            };

            if let Some(role_relation) = role_for_level(&prepared.sorted_roles, min_level) {
                UsersetExpr::Computed(role_relation)
            } else {
                deny_expr(table_plan)
            }
        }
        PatternClass::P2RoleNameInList {
            function_name,
            role_names,
            privilege,
        } => {
            let Some(prepared) = prepare_role_threshold_translation(
                function_name,
                "Role-list",
                policy_name,
                source_table,
                table_plan,
                all_types,
                registry,
                hints,
                db,
                notes,
            ) else {
                // Non-RoleThreshold function (e.g. pg_has_role, auth.role()) ,
                // fall back to scope-style direct relations per role name.
                return handle_p2_role_gate(
                    role_names,
                    *privilege,
                    policy_name,
                    source_table,
                    table_plan,
                    all_types,
                    db,
                    notes,
                );
            };

            // Matched by name, not by level, so `viewer=1` and `guest=1` stay
            // distinct. A numeric item means every role at that level.
            let mut selected_names: BTreeSet<String> = BTreeSet::new();
            for role in role_names {
                if let Ok(level) = role.parse::<i32>() {
                    // Numeric string → expand to all role names at this level.
                    for r in &prepared.sorted_roles {
                        if r.level == level {
                            selected_names.insert(r.original_name.to_lowercase());
                        }
                    }
                    continue;
                }
                // Role name string → insert directly (case-insensitive).
                selected_names.insert(role.to_lowercase());
            }

            if selected_names.is_empty() {
                return deny_expr(table_plan);
            }

            if let Some(expr) = exact_roles_expr(
                &prepared.sorted_roles,
                &selected_names,
                prepared.has_team_support,
            ) {
                expr
            } else {
                deny_expr(table_plan)
            }
        }
        PatternClass::P3DirectOwnership { column } => {
            let relation = table_plan.ownership_relation(column, column);
            table_plan.ensure_direct(
                relation.clone(),
                vec![DirectSubject::Type(USER_TYPE.to_string())],
            );
            if let Some(pk_col) = resolve_pk_column(source_table, db) {
                table_plan.add_source(TupleSource::DirectOwnership {
                    table: source_table.to_string(),
                    pk_col,
                    owner_col: column.clone(),
                    relation: relation.clone(),
                });
            } else {
                add_missing_object_identifier_note(
                    table_plan,
                    source_table,
                    "ownership tuples",
                    db,
                );
            }
            UsersetExpr::Computed(relation)
        }
        PatternClass::P11ArrayMembership { column } => {
            let relation = table_plan.ownership_relation(column, column);
            table_plan.ensure_direct(
                relation.clone(),
                vec![DirectSubject::Type(USER_TYPE.to_string())],
            );
            if let Some(pk_col) = resolve_pk_column(source_table, db) {
                table_plan.add_source(TupleSource::ArrayMembership {
                    table: source_table.to_string(),
                    pk_col,
                    array_col: column.clone(),
                    relation: relation.clone(),
                });
            } else {
                add_missing_object_identifier_note(
                    table_plan,
                    source_table,
                    "array membership tuples",
                    db,
                );
            }
            UsersetExpr::Computed(relation)
        }
        PatternClass::P12JsonbFieldOwnership { column, path } => {
            let field = path.join("_");
            let relation = table_plan
                .ownership_relation(&format!("jsonb:{column}:{}", path.join(".")), &field);
            table_plan.ensure_direct(
                relation.clone(),
                vec![DirectSubject::Type(USER_TYPE.to_string())],
            );
            if let Some(pk_col) = resolve_pk_column(source_table, db) {
                table_plan.add_source(TupleSource::JsonbFieldOwnership {
                    table: source_table.to_string(),
                    pk_col,
                    column: column.clone(),
                    path: path.clone(),
                    relation: relation.clone(),
                });
            } else {
                add_missing_object_identifier_note(
                    table_plan,
                    source_table,
                    "jsonb field ownership tuples",
                    db,
                );
            }
            UsersetExpr::Computed(relation)
        }
        PatternClass::P13UncorrelatedMembership {
            member_table,
            user_column,
            extra_predicate_sql,
        } => {
            // Reading the member table is still reading it as the caller, so its own
            // RLS decides which membership rows count, exactly as for P4.
            match join_table_readability(member_table, db, readability) {
                JoinTableReadability::Unreadable => {
                    notes.push(TranslationNote::MembershipTableGrantsNoReads {
                        policy: policy_name.to_string(),
                        join_table: member_table.clone(),
                    });
                    return deny_expr(table_plan);
                }
                JoinTableReadability::Guarded { .. } => {
                    notes.push(TranslationNote::MembershipTableGuarded {
                        policy: policy_name.to_string(),
                        join_table: member_table.clone(),
                    });
                }
                JoinTableReadability::Open => {}
            }
            if let Some(extra) = extra_predicate_sql {
                notes.push(TranslationNote::MembershipExtraPredicate {
                    policy: policy_name.to_string(),
                    predicate: extra.clone(),
                });
            }

            // One holder per member source, never per table and never per policy: two
            // policies reading the same table may share, and two reading different
            // ones must not pool their members.
            let holder_type = holder_type_name(member_table, table_types);
            ensure_member_type(all_types, &holder_type);
            // Named after the type it points at, as the parent link is.
            let holder_relation = table_plan.ensure_direct(
                clamp_relation_name(holder_type.clone()),
                vec![DirectSubject::Type(holder_type.clone())],
            );
            table_plan.add_source(TupleSource::HolderMembers {
                holder_type: holder_type.clone(),
                member_table: member_table.clone(),
                user_col: user_column.clone(),
                extra_predicate_sql: extra_predicate_sql.clone(),
            });
            if let Some(holder_plan) = all_types.get_mut(&holder_type) {
                holder_plan.add_source(TupleSource::HolderMembers {
                    holder_type: holder_type.clone(),
                    member_table: member_table.clone(),
                    user_col: user_column.clone(),
                    extra_predicate_sql: extra_predicate_sql.clone(),
                });
            }
            if let Some(pk_col) = resolve_pk_column(source_table, db) {
                table_plan.add_source(TupleSource::HolderBridge {
                    table: source_table.to_string(),
                    pk_col,
                    relation: holder_relation.clone(),
                    holder_type,
                });
            } else {
                add_missing_object_identifier_note(
                    table_plan,
                    source_table,
                    "membership holder tuples",
                    db,
                );
            }
            UsersetExpr::TupleToUserset {
                tupleset: holder_relation,
                computed: MEMBER_RELATION.to_string(),
            }
        }
        PatternClass::P4ExistsMembership {
            join_table,
            fk_column,
            user_column,
            extra_predicate_sql,
            ..
        } => {
            // The subquery reads `join_table` as the user, so its own RLS decides which
            // membership rows count.
            let read_scope_roles = match join_table_readability(join_table, db, readability) {
                JoinTableReadability::Unreadable => {
                    notes.push(TranslationNote::MembershipTableGrantsNoReads {
                        policy: policy_name.to_string(),
                        join_table: join_table.clone(),
                    });
                    return deny_expr(table_plan);
                }
                JoinTableReadability::Guarded { roles } => {
                    notes.push(TranslationNote::MembershipTableGuarded {
                        policy: policy_name.to_string(),
                        join_table: join_table.clone(),
                    });
                    roles
                }
                JoinTableReadability::Open => Vec::new(),
            };

            // Prefer the table that fk_column actually references (e.g. "teams"
            // for team_members.team_id → teams.id).  Fall back to the FK-column
            // name heuristic when no FK constraint metadata is available
            // (e.g. "doc_id" → "doc" for an undeclared reference).
            let parent_type = referenced_table_for_fk_col(db, join_table, fk_column).map_or_else(
                || parent_type_from_fk_column(fk_column),
                |referenced| table_types.resolve(db, referenced),
            );

            // The relation is named after the parent type, but relation names have a
            // tighter length limit, so use the name the plan actually registered.
            let parent_relation = table_plan.ensure_direct(
                parent_type.clone(),
                vec![DirectSubject::Type(parent_type.clone())],
            );
            // The plan for `source_table` is held here, not in `all_types`, so a
            // self-referential membership has to register `member` on it directly or
            // the re-insert at the end of the loop drops it.
            if parent_type == table_plan.type_name {
                table_plan.ensure_direct(
                    MEMBER_RELATION,
                    vec![DirectSubject::Type(USER_TYPE.to_string())],
                );
            } else {
                ensure_member_type(all_types, &parent_type);
            }

            if let Some(extra) = extra_predicate_sql {
                notes.push(TranslationNote::MembershipExtraPredicate {
                    policy: policy_name.to_string(),
                    predicate: extra.clone(),
                });
            }

            // Membership rows: add to table_plan first (for correct ordering in IR renderer),
            // then also to the parent type's plan for semantic correctness (deduplicated).
            let membership_source = TupleSource::ExistsMembership {
                join_table: join_table.clone(),
                fk_col: fk_column.clone(),
                user_col: user_column.clone(),
                parent_type: parent_type.clone(),
                extra_predicate_sql: extra_predicate_sql.clone(),
            };
            table_plan.add_source(membership_source.clone());
            if let Some(parent_plan) = all_types.get_mut(&parent_type) {
                parent_plan.add_source(membership_source);
            }

            // Bridge rows link each source-table row to its parent.
            // The pk_col is resolved at render time via resolve_bridge_columns;
            // we emit a Todo here only if the table has no identifiable PK at all.
            if resolve_pk_column(source_table, db).is_some() {
                table_plan.add_source(TupleSource::ParentBridge {
                    table: source_table.to_string(),
                    fk_col: fk_column.clone(),
                    parent_type: parent_type.clone(),
                    relation: parent_relation.clone(),
                });
            } else {
                add_missing_bridge_note(table_plan, source_table, &parent_type, db);
            }

            let membership = UsersetExpr::TupleToUserset {
                tupleset: parent_relation,
                computed: MEMBER_RELATION.to_string(),
            };
            if read_scope_roles.is_empty() {
                return membership;
            }

            // Only those roles can read the membership rows, so only they inherit
            // the grant.
            let scope_relation = membership_read_scope_relation_name(join_table);
            register_pg_role_scope(
                table_plan,
                all_types,
                source_table,
                &scope_relation,
                &read_scope_roles,
                policy_name,
                TranslationNote::MembershipReadScope {
                    policy: policy_name.to_string(),
                    join_table: join_table.clone(),
                    roles: read_scope_roles.clone(),
                    relation: scope_relation.clone(),
                },
                db,
                notes,
                "membership read scope tuples",
            );
            scoped_policy_expr(membership, &scope_relation)
        }
        PatternClass::P5ParentInheritance {
            parent_table,
            fk_column,
            inner_pattern,
        } => {
            if let PatternClass::Unknown { reason, .. } = &inner_pattern.pattern {
                notes.push(TranslationNote::ParentRuleUnknown {
                    policy: policy_name.to_string(),
                    parent_table: parent_table.clone(),
                    reason: reason.clone(),
                });
                return deny_expr(table_plan);
            }

            let parent_type = table_types.resolve(db, parent_table);

            // The relation is named after the parent type, but relation names have a
            // tighter length limit, so use the name the plan actually registered.
            let parent_relation = table_plan.ensure_direct(
                parent_type.clone(),
                vec![DirectSubject::Type(parent_type.clone())],
            );
            // The inner rule has to land on the parent's plan. When the parent is the
            // table being built, that plan is `table_plan`, held here rather than in
            // `all_types`, so writing it there would be dropped by the re-insert at
            // the end of the table loop.
            let inherits_from_self = parent_type == table_plan.type_name;
            let inner_expr = if inherits_from_self {
                translate_pattern(
                    &inner_pattern.pattern,
                    policy_name,
                    table_plan,
                    all_types,
                    registry,
                    notes,
                    hints,
                    db,
                    table_types,
                    parent_table,
                    settings,
                    readability,
                )
            } else {
                let parent_plan = all_types
                    .entry(parent_type.clone())
                    .or_insert_with(|| TypePlan::new(&parent_type));
                let mut parent_plan_owned =
                    core::mem::replace(parent_plan, TypePlan::new(&parent_type));
                let expr = translate_pattern(
                    &inner_pattern.pattern,
                    policy_name,
                    &mut parent_plan_owned,
                    all_types,
                    registry,
                    notes,
                    hints,
                    db,
                    table_types,
                    parent_table,
                    settings,
                    readability,
                );
                *all_types
                    .entry(parent_type.clone())
                    .or_insert_with(|| TypePlan::new(&parent_type)) = parent_plan_owned;
                expr
            };

            // The policy requires this specific parent-side rule. Pointing at the
            // parent's `can_select` instead would import every other permissive
            // policy the parent has.
            let rule_is_denial =
                matches!(&inner_expr, UsersetExpr::Computed(name) if name == DENY_RELATION);
            // A row the parent hides cannot satisfy the rule, self references included.
            // Gating narrows the rule, so an unreadable RLS state gates.
            let gate_on_parent = !rule_is_denial
                && lookup_table(db, parent_table)
                    .is_some_and(|table| table.has_row_level_security(db) != Ok(false));
            let rule_expr = if gate_on_parent {
                UsersetExpr::Intersection(vec![
                    inner_expr,
                    UsersetExpr::Computed(CAN_SELECT_RELATION.to_string()),
                ])
            } else {
                inner_expr
            };
            let inherited = match rule_expr {
                UsersetExpr::Computed(name) => name,
                expr => {
                    // Named after the rule, so children share it and a policy rename
                    // leaves the parent alone.
                    let name = clamp_relation_name(format!(
                        "{INHERITED_RELATION_PREFIX}{}",
                        stable_hex_suffix(userset_key(&expr).as_str())
                    ));
                    if inherits_from_self {
                        table_plan.ensure_computed(name, expr)
                    } else {
                        all_types
                            .entry(parent_type.clone())
                            .or_insert_with(|| TypePlan::new(&parent_type))
                            .ensure_computed(name, expr)
                    }
                }
            };

            if rule_is_denial {
                notes.push(TranslationNote::ParentRuleUntranslated {
                    policy: policy_name.to_string(),
                    parent_table: parent_table.clone(),
                });
            }

            if resolve_pk_column(source_table, db).is_some() {
                table_plan.add_source(TupleSource::ParentBridge {
                    table: source_table.to_string(),
                    fk_col: fk_column.clone(),
                    parent_type: parent_type.clone(),
                    relation: parent_relation.clone(),
                });
            } else {
                add_missing_bridge_note(table_plan, source_table, &parent_type, db);
            }

            UsersetExpr::TupleToUserset {
                tupleset: parent_relation,
                computed: inherited,
            }
        }
        PatternClass::P6BooleanFlag { column } => {
            if let Some(pk_col) = resolve_pk_column(source_table, db) {
                table_plan.add_source(TupleSource::PublicFlag {
                    table: source_table.to_string(),
                    pk_col,
                    flag_col: column.clone(),
                });
            } else {
                add_missing_object_identifier_note(
                    table_plan,
                    source_table,
                    "public-flag tuples",
                    db,
                );
            }
            public_expr(table_plan)
        }
        PatternClass::P7AbacAnd {
            relationship_part,
            attribute_part,
        } => {
            notes.push(TranslationNote::AttributeNeedsRuntimeEnforcement {
                policy: policy_name.to_string(),
                attribute: attribute_part.clone(),
            });
            // Recurse first so relationship sources appear before the attribute Todo
            // in table_tuple_sources (matching old generate_tuple_queries ordering).
            let result = translate_pattern(
                &relationship_part.pattern,
                policy_name,
                table_plan,
                all_types,
                registry,
                notes,
                hints,
                db,
                table_types,
                source_table,
                settings,
                readability,
            );
            table_plan.add_source(TupleSource::Skipped {
                reason: SkippedTuples::AttributeRuntimeEnforcement {
                    table: source_table.to_string(),
                    attribute: attribute_part.clone(),
                },
            });
            result
        }
        PatternClass::P8Composite { op, parts } => {
            let mut child_exprs = Vec::new();
            for part in parts {
                child_exprs.push(translate_pattern(
                    &part.pattern,
                    policy_name,
                    table_plan,
                    all_types,
                    registry,
                    notes,
                    hints,
                    db,
                    table_types,
                    source_table,
                    settings,
                    readability,
                ));
            }
            match op {
                BoolOp::Or => combine_union(child_exprs).unwrap_or_else(|| deny_expr(table_plan)),
                BoolOp::And => {
                    combine_intersection(child_exprs).unwrap_or_else(|| deny_expr(table_plan))
                }
            }
        }
        PatternClass::P9AttributeCondition {
            column,
            predicate,
            request_predicate,
            ..
        } => {
            // A value only the request knows cannot be decided by a tuple, so the
            // guard becomes a condition the service evaluates per check, and the tuple
            // carries the row's own value as its context.
            if let Some(request) = request_predicate {
                if let Some(expr) = conditional_gate_expr(
                    request,
                    policy_name,
                    source_table,
                    table_plan,
                    db,
                    &settings.request_time_parameter,
                ) {
                    return expr;
                }
            }
            // A literal constant is decided by the row, so the guard generalises the
            // boolean flag: emit the wildcard and let the tuple query qualify rows.
            // The wildcard is only correct because the compared value is a literal.
            // A caller-derived one would grant everyone access to rows scoped to one
            // caller, so it arrives here as `None` and keeps falling closed.
            if let Some(predicate) = predicate {
                if let Some(pk_col) = resolve_pk_column(source_table, db) {
                    table_plan.add_source(TupleSource::AttributeGate {
                        table: source_table.to_string(),
                        pk_col,
                        predicate: predicate.clone(),
                    });
                } else {
                    add_missing_object_identifier_note(
                        table_plan,
                        source_table,
                        "attribute-gate tuples",
                        db,
                    );
                }
                return public_expr(table_plan);
            }
            notes.push(TranslationNote::StandaloneAttributePolicy {
                policy: policy_name.to_string(),
                column: column.clone(),
            });
            table_plan.add_source(TupleSource::Skipped {
                reason: SkippedTuples::StandaloneAttribute {
                    table: source_table.to_string(),
                    column: column.clone(),
                },
            });
            deny_expr(table_plan)
        }
        PatternClass::P10ConstantBool { value } => {
            if *value {
                if let Some(pk_col) = resolve_pk_column(source_table, db) {
                    table_plan.add_source(TupleSource::ConstantTrue {
                        table: source_table.to_string(),
                        pk_col,
                    });
                } else {
                    add_missing_object_identifier_note(
                        table_plan,
                        source_table,
                        "constant-TRUE tuples",
                        db,
                    );
                }
                public_expr(table_plan)
            } else {
                deny_expr(table_plan)
            }
        }
        PatternClass::Unknown { reason, .. } => {
            notes.push(TranslationNote::ExpressionRefused {
                policy: policy_name.to_string(),
                reason: reason.clone(),
            });
            table_plan.add_source(TupleSource::Skipped {
                reason: SkippedTuples::UnclassifiedExpression {
                    table: source_table.to_string(),
                    reason: reason.clone(),
                },
            });
            deny_expr(table_plan)
        }
    }
}

#[derive(Debug, Clone)]
struct RoleThresholdPrepared {
    sorted_roles: Vec<RoleRelationName>,
    has_team_support: bool,
}

#[allow(clippy::too_many_arguments)]
fn prepare_role_threshold_translation<DB: DatabaseLike>(
    function_name: &str,
    function_kind_label: &str,
    policy_name: &str,
    source_table: &str,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<String, TypePlan>,
    registry: &FunctionRegistry,
    hints: &RoleThresholdResourceHints,
    db: &DB,
    notes: &mut Vec<TranslationNote>,
) -> Option<RoleThresholdPrepared> {
    let Some(FunctionSemantic::RoleThreshold {
        role_levels,
        team_membership_table,
        ..
    }) = registry.get(function_name)
    else {
        notes.push(TranslationNote::FunctionMissingMetadata {
            policy: policy_name.to_string(),
            function_kind: function_kind_label.to_string(),
            function: function_name.to_string(),
        });
        return None;
    };

    let has_team_support = team_membership_table.is_some();
    let sorted_roles =
        ensure_role_threshold_scaffold(table_plan, all_types, role_levels, has_team_support);
    populate_role_threshold_sources(
        function_name,
        source_table,
        db,
        registry,
        hints,
        table_plan,
        all_types,
    );

    Some(RoleThresholdPrepared {
        sorted_roles,
        has_team_support,
    })
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

fn add_missing_object_identifier_note<DB: DatabaseLike>(
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

fn add_missing_bridge_note<DB: DatabaseLike>(
    table_plan: &mut TypePlan,
    source_table: &str,
    parent_type: &str,
    db: &DB,
) {
    table_plan.add_source(TupleSource::Skipped {
        reason: SkippedTuples::NoBridge {
            table: source_table.to_string(),
            parent_type: parent_type.to_string(),
            reason: missing_object_identifier_reason(source_table, db),
        },
    });
}

fn ensure_member_type(all_types: &mut BTreeMap<String, TypePlan>, type_name: &str) {
    let entry = all_types
        .entry(type_name.to_string())
        .or_insert_with(|| TypePlan::new(type_name));
    entry.ensure_direct(
        MEMBER_RELATION,
        vec![DirectSubject::Type(USER_TYPE.to_string())],
    );
}

fn ensure_pg_role_type(all_types: &mut BTreeMap<String, TypePlan>) {
    ensure_member_type(all_types, PG_ROLE_TYPE);
}

/// Give `pg_role` a relation holding one kind of role membership, for an operator to load.
fn ensure_pg_role_relation(all_types: &mut BTreeMap<String, TypePlan>, relation: &str) {
    all_types
        .entry(PG_ROLE_TYPE.to_string())
        .or_insert_with(|| TypePlan::new(PG_ROLE_TYPE))
        .ensure_direct(relation, vec![DirectSubject::Type(USER_TYPE.to_string())]);
}

fn ensure_role_threshold_scaffold(
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<String, TypePlan>,
    role_levels: &BTreeMap<String, i32>,
    has_team_support: bool,
) -> Vec<RoleRelationName> {
    let sorted_roles = sorted_role_relation_names(role_levels);

    table_plan.ensure_direct(
        OWNER_USER_RELATION,
        vec![DirectSubject::Type(USER_TYPE.to_string())],
    );

    if has_team_support {
        table_plan.ensure_direct(
            OWNER_TEAM_RELATION,
            vec![DirectSubject::Type(TEAM_TYPE.to_string())],
        );
        ensure_member_type(all_types, TEAM_TYPE);
    }

    let grant_subjects = if has_team_support {
        vec![
            DirectSubject::Type(USER_TYPE.to_string()),
            DirectSubject::Type(TEAM_TYPE.to_string()),
        ]
    } else {
        vec![DirectSubject::Type(USER_TYPE.to_string())]
    };

    for role in &sorted_roles {
        table_plan.ensure_direct(role.grant_relation(), grant_subjects.clone());
    }

    let mut descending = sorted_roles.clone();
    descending.reverse();

    for (idx, role) in descending.iter().enumerate() {
        let mut children = Vec::new();

        if idx == 0 {
            children.push(UsersetExpr::Computed(OWNER_USER_RELATION.to_string()));
            if has_team_support {
                children.push(UsersetExpr::TupleToUserset {
                    tupleset: OWNER_TEAM_RELATION.to_string(),
                    computed: MEMBER_RELATION.to_string(),
                });
            }
        } else if let Some(prev) = descending.get(idx - 1) {
            children.push(UsersetExpr::Computed(prev.role_relation()));
        }

        let grant_name = role.grant_relation();
        children.push(UsersetExpr::Computed(grant_name.clone()));
        if has_team_support {
            children.push(UsersetExpr::TupleToUserset {
                tupleset: grant_name,
                computed: MEMBER_RELATION.to_string(),
            });
        }

        if let Some(expr) = combine_union(children) {
            table_plan.ensure_computed(role.role_relation(), expr);
        }
    }

    sorted_roles
}

fn role_for_level(sorted_roles: &[RoleRelationName], min_level: i32) -> Option<String> {
    sorted_roles
        .iter()
        .find(|role| role.level >= min_level)
        .map(RoleRelationName::role_relation)
}

/// Userset for a P2 role-name-in-list policy.
///
/// Keyed on the listed role names, so a same-level role with a different name
/// (`guest=1` beside `viewer=1`) is not admitted.
fn exact_roles_expr(
    sorted_roles: &[RoleRelationName],
    selected_names: &BTreeSet<String>,
    has_team_support: bool,
) -> Option<UsersetExpr> {
    let mut children = Vec::new();

    for role in sorted_roles {
        if selected_names.contains(&role.original_name.to_lowercase()) {
            let grant_name = role.grant_relation();
            children.push(UsersetExpr::Computed(grant_name.clone()));
            if has_team_support {
                children.push(UsersetExpr::TupleToUserset {
                    tupleset: grant_name,
                    computed: MEMBER_RELATION.to_string(),
                });
            }
        }
    }

    // Include owner_user / owner_team when the highest-level role is selected.
    let max_level = sorted_roles.iter().map(|role| role.level).max();
    if let Some(max) = max_level {
        let max_is_selected = sorted_roles
            .iter()
            .any(|r| r.level == max && selected_names.contains(&r.original_name.to_lowercase()));
        if max_is_selected {
            children.push(UsersetExpr::Computed(OWNER_USER_RELATION.to_string()));
            if has_team_support {
                children.push(UsersetExpr::TupleToUserset {
                    tupleset: OWNER_TEAM_RELATION.to_string(),
                    computed: MEMBER_RELATION.to_string(),
                });
            }
        }
    }

    combine_union(children)
}

fn resolve_owner_column<DB: DatabaseLike>(table: &str, db: &DB) -> Option<String> {
    let table_info = lookup_table(db, table)?;
    for col in table_info.columns(db).into_iter().flatten() {
        let name = col.stored_column_name();
        if is_owner_like_column_name(&name) {
            return Some(name.into_owned());
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
                .map(|col| col.stored_column_name().into_owned())
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
    fk_column: &str,
) -> Option<&'db str> {
    let table_info = lookup_table(db, table)?;
    for fk in table_info.foreign_keys(db).into_iter().flatten() {
        let uses_col = fk
            .host_columns(db)
            .into_iter()
            .flatten()
            .any(|c| c.stored_column_name() == fk_column);
        if uses_col {
            return fk.referenced_table(db).ok().map(TableLike::table_name);
        }
    }
    None
}

fn resolve_principal_info<DB: DatabaseLike>(
    db: &DB,
    configured_table: Option<&str>,
    configured_pk_col: Option<&str>,
    fallback_candidates: &[&str],
) -> Option<PrincipalInfo> {
    if let Some(table) = configured_table {
        let pk_col = if let Some(pk_col) = configured_pk_col {
            if !table_has_column(db, table, pk_col) {
                return None;
            }
            pk_col.to_string()
        } else {
            resolve_pk_column(table, db)?
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
        if let Some(pk_col) = resolve_pk_column(candidate, db) {
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

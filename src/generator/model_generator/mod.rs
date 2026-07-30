#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use alloc::collections::{BTreeMap, BTreeSet};
use core::fmt::Write;

use crate::classifier::function_registry::FunctionRegistry;
use crate::classifier::patterns::*;
use crate::generator::db_lookup::{
    composite_primary_key_columns, resolve_pk_column, table_has_column,
};
use crate::generator::ir::{PrincipalInfo, TupleSource};
use crate::generator::role_relations::{sorted_role_relation_names, RoleRelationName};
use crate::generator::well_known::{
    CAN_DELETE_RELATION, CAN_INSERT_RELATION, CAN_INSERT_RETURNING_RELATION,
    CAN_SELECT_FOR_UPDATE_RELATION, CAN_SELECT_RELATION, CAN_UPDATE_CHECK_RELATION,
    CAN_UPDATE_RELATION, CAN_UPDATE_USING_RELATION, CAN_UPSERT_RELATION, DENY_RELATION,
    MEMBER_RELATION, OWNER_TEAM_RELATION, OWNER_USER_RELATION, PG_ROLE_TYPE, PUBLIC_RELATION,
    TEAM_TYPE, USER_TYPE,
};
use crate::parser::expr::extract_column_name;
use crate::parser::expr::function_arg_expr;
use crate::parser::expr::reads_relation;
use crate::parser::function_analyzer::FunctionSemantic;
use crate::parser::names::{
    canonical_fga_type_name, clamp_relation_name, is_owner_like_column_name, lookup_table,
    membership_read_scope_relation_name, normalize_identifier, normalize_relation_name,
    parent_type_from_fk_column, policy_scope_relation_name, role_limited_relation_name,
    stable_hex_suffix,
};
use crate::parser::sql_parser::{ColumnLike, DatabaseLike, ForeignKeyLike, ParserDB, TableLike};
use sqlparser::ast::{Expr, Function, FunctionArguments};

/// `OpenFGA` DSL text rendering from the schema plan.
mod dsl;
/// Role-threshold resource-column inference and tuple-source population.
mod role_threshold;

use dsl::render_dsl;
use role_threshold::{infer_role_threshold_resource_columns, populate_role_threshold_sources};

/// `OpenFGA` authorization model schema version.
pub(crate) const OPENFGA_SCHEMA_VERSION: &str = "1.1";

/// Generated ``OpenFGA`` model output.
#[derive(Debug, Clone)]
pub struct GeneratedModel {
    /// The complete `OpenFGA` DSL text.
    pub dsl: String,
    /// Action items for policies that need manual review.
    pub todos: Vec<TodoItem>,
    /// Per-policy confidence levels for the report.
    pub confidence_summary: Vec<(String, ConfidenceLevel)>,
}

/// An action item generated when a policy cannot be fully translated.
#[derive(Debug, Clone)]
pub struct TodoItem {
    /// Confidence level that triggered this item.
    pub level: ConfidenceLevel,
    /// Name of the policy that needs attention.
    pub policy_name: String,
    /// Human-readable description of what needs manual review.
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DirectSubject {
    Type(String),
    Wildcard(String),
}

/// Structural identity of a subject list, stable against `Debug` formatting.
fn subject_key(subjects: &[DirectSubject]) -> String {
    subjects
        .iter()
        .map(|subject| match subject {
            DirectSubject::Type(name) => format!("t:{name}"),
            DirectSubject::Wildcard(name) => format!("w:{name}"),
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

        let base = canonical_fga_type_name(name_source.strip_suffix("_id").unwrap_or(name_source));
        let taken = |name: &str, plan: &Self| {
            reserved_relation_subjects(name).is_some()
                || generator_defines(name)
                || plan.direct_relations.contains_key(name)
                || plan.computed_relations.contains_key(name)
        };
        let relation = clamp_relation_name(if base.is_empty() || taken(&base, self) {
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
        let mut relation = clamp_relation_name(relation.into());
        // A name already held must yield rather than emit a second `define` or inherit
        // subjects it does not accept.
        let conflicts = self.computed_relations.contains_key(&relation)
            || self
                .direct_relations
                .get(&relation)
                .is_some_and(|held| *held != subjects)
            || reserved_relation_subjects(&relation).is_some_and(|held| held != subjects)
            || generator_defines(&relation);
        if conflicts {
            let key = subject_key(&subjects);
            relation =
                clamp_relation_name(format!("{relation}_{}", stable_hex_suffix(key.as_str())));
        }
        self.direct_relations
            .entry(relation.clone())
            .or_insert(subjects);
        relation
    }

    fn ensure_computed(&mut self, relation: impl Into<String>, expr: UsersetExpr) -> String {
        let mut relation = clamp_relation_name(relation.into());
        // One name, one rule, or a caller deriving the name reads the wrong definition.
        let conflicts = self.direct_relations.contains_key(&relation)
            || self
                .computed_relations
                .get(&relation)
                .is_some_and(|held| *held != expr)
            || generator_defines(&relation);
        if conflicts {
            let key = userset_key(&expr);
            relation =
                clamp_relation_name(format!("{relation}_{}", stable_hex_suffix(key.as_str())));
        }
        self.computed_relations
            .entry(relation.clone())
            .or_insert(expr);
        relation
    }

    fn set_computed(&mut self, relation: impl Into<String>, expr: UsersetExpr) -> String {
        let relation = clamp_relation_name(relation.into());
        // Guard: if this relation was already registered as direct, that is a programming error.
        debug_assert!(
            !self.direct_relations.contains_key(&relation),
            "relation '{relation}' already registered as direct; cannot overwrite as computed"
        );
        self.computed_relations.insert(relation.clone(), expr);
        relation
    }

    fn add_source(&mut self, source: TupleSource) {
        self.table_tuple_sources.push(source);
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SchemaPlan {
    pub types: Vec<TypePlan>,
    pub todos: Vec<TodoItem>,
    pub confidence_summary: Vec<(String, ConfidenceLevel)>,
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

/// Generate an ``OpenFGA`` model from classified policies.
pub fn generate_model(
    policies: &[ClassifiedPolicy],
    db: &ParserDB,
    registry: &FunctionRegistry,
    min_confidence: ConfidenceLevel,
) -> GeneratedModel {
    let plan = build_filtered_schema_plan(policies, db, registry, min_confidence);
    let dsl = render_dsl(&plan.types);

    GeneratedModel {
        dsl,
        todos: plan.todos,
        confidence_summary: plan.confidence_summary,
    }
}

pub(crate) fn build_filtered_schema_plan(
    policies: &[ClassifiedPolicy],
    db: &ParserDB,
    registry: &FunctionRegistry,
    min_confidence: ConfidenceLevel,
) -> SchemaPlan {
    let filtered = filter_policies_for_output(policies, min_confidence);
    build_schema_plan(&filtered, db, registry)
}

pub(crate) fn build_schema_plan(
    policies: &[ClassifiedPolicy],
    db: &ParserDB,
    registry: &FunctionRegistry,
) -> SchemaPlan {
    // Pre-compute resource column hints for P1/P2 role-threshold patterns.
    // This walks the raw policy Expr AST once up-front so that
    // pattern_to_expr_for_target can use the resolved column during translation.
    let role_threshold_resource_hints = infer_role_threshold_resource_columns(policies, registry);

    let mut all_types: BTreeMap<String, TypePlan> = BTreeMap::new();
    let mut todos = Vec::new();
    let mut confidence_summary = Vec::new();
    let mut has_role_scopes = false;

    for function in registry.owner_bound_accessors() {
        todos.push(TodoItem {
            level: ConfidenceLevel::C,
            policy_name: function.to_string(),
            message: format!(
                "Function '{function}' runs as its owner, so current_user inside it is the \
                 owner's name for every caller and identifies nobody; policies calling it are \
                 dropped"
            ),
        });
    }

    // Keyed by the schema's own spelling, since two policies may quote the table
    // differently and one table must be built once. `group_keys` memoizes the
    // resolution, which walks the tables, and every policy on one table repeats it.
    let mut group_keys: BTreeMap<String, String> = BTreeMap::new();
    let mut by_table: BTreeMap<String, Vec<&ClassifiedPolicy>> = BTreeMap::new();
    for cp in policies {
        let key = table_group_key(db, cp.table_name(), &mut group_keys);
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
        if !table.has_row_level_security(db) || covered.contains(&table_identity(table)) {
            continue;
        }
        by_table.entry(qualified_table_name(table)).or_default();
    }

    // The schema's own permissive policies under the same key, since the filtered
    // set cannot say whether a policy exists at all. Splitting the two keys would
    // tell the operator RLS denies a command its own policy grants.
    let mut declared_permissive: BTreeMap<String, Vec<&<ParserDB as DatabaseLike>::Policy>> =
        BTreeMap::new();
    for policy in db.policies() {
        if derive_policy_mode(policy) != PolicyMode::Permissive {
            continue;
        }
        let key = table_group_key(db, policy.table_name.to_string(), &mut group_keys);
        declared_permissive.entry(key).or_default().push(policy);
    }

    let table_types = TableTypes::assign(db, &mut todos);

    for (source_table_name, table_policies) in by_table {
        // Only RLS-enabled tables that resolve against the schema get a type. A name
        // the schema cannot resolve carries the policy nowhere, so say so.
        let Some(canonical_table_name) = table_types.get(db, &source_table_name) else {
            if lookup_table(db, &source_table_name).is_none() {
                for cp in &table_policies {
                    todos.push(TodoItem {
                        level: ConfidenceLevel::C,
                        policy_name: cp.name().to_string(),
                        message: format!(
                            "Policy '{}' names '{source_table_name}', which does not resolve to \
                             one table in the schema, so qualify it with a schema to have the \
                             policy translated",
                            cp.name()
                        ),
                    });
                }
            }
            continue;
        };
        let canonical_table_name = canonical_table_name.to_string();

        let mut table_plan = all_types
            .remove(&canonical_table_name)
            .unwrap_or_else(|| TypePlan::new(&canonical_table_name));

        // A SELECT policy reading its own table makes PostgreSQL fail every read of it.
        let mut recursive_select: Option<String> = None;

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
            if cp.policy.using.is_none() && cp.policy.with_check.is_none() {
                continue;
            }
            if let Some(ref c) = cp.using_classification {
                confidence_summary.push((cp.name().to_string(), c.confidence));
            }
            if let Some(ref c) = cp.with_check_classification {
                confidence_summary.push((format!("{} (WITH CHECK)", cp.name()), c.confidence));
            }

            let scoped_roles = cp.scoped_roles();
            let scope_relation = if scoped_roles.is_empty() {
                None
            } else {
                has_role_scopes = true;
                let relation = policy_scope_relation_name(cp.name());
                register_pg_role_scope(
                    &mut table_plan,
                    &mut all_types,
                    &source_table_name,
                    &relation,
                    &scoped_roles,
                    cp.name(),
                    format!(
                        "Policy role scope TO ({}) mapped to relation '{relation}'; ensure pg_role memberships are loaded",
                        scoped_roles.join(", ")
                    ),
                    db,
                    &mut todos,
                    "policy scope tuples",
                );
                Some(relation)
            };

            // Judged before classification: a filtered clause still poisons reads.
            let recurses = policy_recurses_on_reads(cp, db, &table_types, &canonical_table_name);
            if recurses {
                recursive_select = Some(cp.name().to_string());
            }

            // A policy covering several phases is translated once per phase, so the
            // same clause reports the same item repeatedly. Keep one per policy.
            let todos_before = todos.len();
            for_each_policy_target_expr(cp, |target, classified| {
                if recurses && target == ActionTarget::Select {
                    // Nothing here can be evaluated, so translating it leaves dead relations.
                    return;
                }
                let expr = translate_pattern(
                    &classified.pattern,
                    cp.name(),
                    &mut table_plan,
                    &mut all_types,
                    registry,
                    &mut todos,
                    &role_threshold_resource_hints,
                    db,
                    &table_types,
                    &source_table_name,
                );
                // A restrictive clause is a barrier, so a dropped conjunct must still deny.
                let guards = dropped_attribute_guards(&classified.pattern);
                let expr = if cp.mode() == PolicyMode::Restrictive && !guards.is_empty() {
                    // The denial supersedes any runtime-enforcement note for the guard.
                    for guard in guards {
                        let note = attribute_runtime_note(guard);
                        todos.retain(|todo| todo.policy_name != cp.name() || todo.message != note);
                    }
                    todos.push(TodoItem {
                        level: ConfidenceLevel::C,
                        policy_name: cp.name().to_string(),
                        message: format!(
                            "RESTRICTIVE policy '{}' guards on an attribute the model cannot \
                             express, so the command is denied",
                            cp.name()
                        ),
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
            dedup_todos_added_since(&mut todos, todos_before);
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

        if let Some(policy_name) = recursive_select {
            select_expr = Some(deny_expr(&mut table_plan));
            todos.push(TodoItem {
                level: ConfidenceLevel::C,
                policy_name: policy_name.clone(),
                message: format!(
                    "SELECT policy '{policy_name}' reads '{source_table_name}', the table it \
                     guards, so PostgreSQL raises infinite recursion on every read. Reads are \
                     denied to match."
                ),
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
        let declared_here: &[&<ParserDB as DatabaseLike>::Policy] = declared_permissive
            .get(&source_table_name)
            .map_or(&[], Vec::as_slice);
        let uncovered = fill_uncovered_actions_with_deny(&mut table_plan);
        if !uncovered.is_empty() {
            let covered_by_schema = commands_a_permissive_policy_covers(declared_here);
            let (dropped, unpolicied): (Vec<&str>, Vec<&str>) = uncovered
                .into_iter()
                .partition(|command| covered_by_schema.contains(command));
            if !unpolicied.is_empty() {
                todos.push(TodoItem {
                    level: ConfidenceLevel::C,
                    policy_name: source_table_name.clone(),
                    message: format!(
                        "No permissive policy on '{source_table_name}' covers {}; RLS denies \
                         {those} outright and the model mirrors that with no_access",
                        unpolicied.join(", "),
                        those = if unpolicied.len() == 1 { "it" } else { "them" }
                    ),
                });
            }
            if !dropped.is_empty() {
                todos.push(TodoItem {
                    level: ConfidenceLevel::C,
                    policy_name: source_table_name.clone(),
                    message: format!(
                        "Every permissive policy on '{source_table_name}' covering {} fell below \
                         the confidence threshold, so the model denies what RLS grants",
                        dropped.join(", ")
                    ),
                });
            }
        }

        for (policy_name, commands, clause) in policies_missing_a_clause(declared_here) {
            let message = format!(
                "Policy '{policy_name}' names {commands} without a {clause} clause, so \
                 PostgreSQL admits no row through it"
            );
            todos.push(TodoItem {
                level: ConfidenceLevel::C,
                policy_name,
                message,
            });
        }

        // Denying this silently would hide a schema mistake.
        if has_row_scoped_write_policy
            && table_plan
                .computed_relations
                .get(CAN_SELECT_RELATION)
                .is_some_and(|expr| grants_nothing(expr, &table_plan, &mut BTreeSet::new()))
        {
            todos.push(TodoItem {
                level: ConfidenceLevel::C,
                policy_name: source_table_name.clone(),
                message: format!(
                    "Reads of '{source_table_name}' are denied, so UPDATE and DELETE cannot \
                     name a row either. Add a SELECT policy the model can translate."
                ),
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

    let mut type_names: Vec<String> = all_types.keys().cloned().collect();
    type_names.sort();
    if let Some(pos) = type_names.iter().position(|n| n == USER_TYPE) {
        let user = type_names.remove(pos);
        type_names.insert(0, user);
    }

    let types = type_names
        .into_iter()
        .filter_map(|name| all_types.remove(&name))
        .collect();

    SchemaPlan {
        types,
        todos,
        confidence_summary,
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
                    DirectSubject::Wildcard(_) => None,
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
                    DirectSubject::Wildcard(_) => None,
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

fn using_targets(command: &PolicyCommand) -> Vec<ActionTarget> {
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

fn with_check_targets(command: &PolicyCommand) -> Vec<ActionTarget> {
    match command {
        PolicyCommand::Insert => vec![ActionTarget::Insert],
        PolicyCommand::Update => vec![ActionTarget::UpdateCheck],
        PolicyCommand::Select | PolicyCommand::Delete => vec![],
        PolicyCommand::All => vec![ActionTarget::Insert, ActionTarget::UpdateCheck],
    }
}

fn policy_uses_using_for_missing_with_check(command: &PolicyCommand) -> bool {
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

/// Note that a hybrid leaves its attribute half to the caller.
fn attribute_runtime_note(attribute: &str) -> String {
    format!("Attribute condition '{attribute}' still requires runtime enforcement")
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

/// Whether reading `type_name` would expand this policy again, which `PostgreSQL`
/// rejects as infinite recursion.
fn policy_recurses_on_reads(
    cp: &ClassifiedPolicy,
    db: &ParserDB,
    table_types: &TableTypes,
    type_name: &str,
) -> bool {
    if !matches!(cp.command(), PolicyCommand::Select | PolicyCommand::All) {
        return false;
    }
    // Only the read side matters: a WITH CHECK clause guards new rows.
    cp.policy
        .using
        .as_ref()
        .is_some_and(|using| expr_reads_table(using, db, table_types, type_name))
}

/// Whether any relation the expression reads resolves to `type_name`.
fn expr_reads_table(expr: &Expr, db: &ParserDB, table_types: &TableTypes, type_name: &str) -> bool {
    reads_relation(expr, |name| table_types.resolve(db, name) == type_name)
}

/// How much of a membership table a querying user may read.
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

fn join_table_readability(join_table: &str, db: &ParserDB) -> JoinTableReadability {
    let Some(table) = lookup_table(db, join_table) else {
        return JoinTableReadability::Open;
    };
    if !table.has_row_level_security(db) {
        return JoinTableReadability::Open;
    }

    let mut roles = BTreeSet::new();
    let mut grants_read = false;
    for policy in table.policies(db).filter(|p| policy_grants_select(p)) {
        grants_read = true;
        let scoped = derive_scoped_roles(policy);
        if scoped.is_empty() {
            return JoinTableReadability::Guarded { roles: Vec::new() };
        }
        roles.extend(scoped);
    }

    if grants_read {
        JoinTableReadability::Guarded {
            roles: roles.into_iter().collect(),
        }
    } else {
        JoinTableReadability::Unreadable
    }
}

fn for_each_policy_target_expr<F>(cp: &ClassifiedPolicy, mut f: F)
where
    F: FnMut(ActionTarget, &ClassifiedExpr),
{
    let restrictive = cp.mode() == PolicyMode::Restrictive;

    let dropped_using = (restrictive && cp.using_was_filtered)
        .then(|| dropped_restrictive_expr(cp, cp.policy.using.as_ref().map(ToString::to_string)));
    if let Some(using) = cp.using_classification.as_ref().or(dropped_using.as_ref()) {
        for target in using_targets(&cp.command()) {
            f(target, using);
        }
    }

    // Mirror USING → WITH CHECK only when the SQL had no WITH CHECK at all. A filtered
    // one falls closed instead.
    let dropped_with_check = (restrictive && cp.with_check_was_filtered).then(|| {
        dropped_restrictive_expr(cp, cp.policy.with_check.as_ref().map(ToString::to_string))
    });
    let with_check_pattern = cp
        .with_check_classification
        .as_ref()
        .or(dropped_with_check.as_ref())
        .or_else(|| {
            if !cp.with_check_was_filtered
                && policy_uses_using_for_missing_with_check(&cp.command())
            {
                cp.using_classification.as_ref()
            } else {
                None
            }
        });

    if let Some(with_check) = with_check_pattern {
        for target in with_check_targets(&cp.command()) {
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
fn register_pg_role_scope(
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<String, TypePlan>,
    source_table: &str,
    scope_relation: &str,
    role_names: &[String],
    policy_name: &str,
    todo_message: String,
    db: &ParserDB,
    todos: &mut Vec<TodoItem>,
    missing_object_what: &str,
) {
    ensure_pg_role_type(all_types);

    table_plan.ensure_direct(
        scope_relation.to_string(),
        vec![DirectSubject::Type(PG_ROLE_TYPE.to_string())],
    );
    todos.push(TodoItem {
        level: ConfidenceLevel::C,
        policy_name: policy_name.to_string(),
        message: todo_message,
    });

    if let Some(pk_col) = resolve_pk_column(source_table, db) {
        for role in role_names {
            let pg_role = canonical_fga_type_name(role);
            // A quoted role can rewrite onto a different existing role, which
            // changes who the policy admits.
            if normalize_identifier(role) != pg_role {
                todos.push(TodoItem {
                    level: ConfidenceLevel::C,
                    policy_name: policy_name.to_string(),
                    message: format!(
                        "PostgreSQL role '{role}' is not a valid OpenFGA identifier and was \
                         rewritten to 'pg_role:{pg_role}'; confirm no other role maps to the \
                         same identifier"
                    ),
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
        add_missing_object_identifier_todo(table_plan, source_table, missing_object_what, db);
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
fn qualified_table_name(table: &<ParserDB as DatabaseLike>::Table) -> String {
    let relation = quoted_for_lookup(&table.stored_table_name());
    match table.stored_table_schema() {
        Some(schema) => format!("{}.{relation}", quoted_for_lookup(&schema)),
        None => relation,
    }
}

/// Key grouping every spelling of one table together, memoized in `cache` because
/// resolving a spelling walks the tables. Both groupings call this, so the filtered
/// classifications and the schema's own policies cannot land under different keys.
fn table_group_key(db: &ParserDB, named: String, cache: &mut BTreeMap<String, String>) -> String {
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
fn table_identity(table: &<ParserDB as DatabaseLike>::Table) -> (Option<String>, String) {
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
    /// One type name per RLS-enabled table, collisions suffixed with a hash of the
    /// qualified name.
    ///
    /// Derived from the schema alone, never from which policies survived filtering,
    /// so names do not move with the confidence threshold. Tables carrying policies
    /// claim their canonical name first.
    fn assign(db: &ParserDB, todos: &mut Vec<TodoItem>) -> Self {
        let mut types = Self::default();
        let mut policied: BTreeSet<(Option<String>, String)> = BTreeSet::new();
        for policy in db.policies() {
            if let Some(table) = lookup_table(db, &policy.table_name.to_string()) {
                policied.insert(table_identity(table));
            }
        }

        let mut names: Vec<(bool, String)> = db
            .tables()
            .filter(|table| table.has_row_level_security(db))
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
                    todos.push(TodoItem {
                        level: ConfidenceLevel::C,
                        policy_name: name.clone(),
                        message: format!(
                            "Type name collision: '{name}' and '{}' both canonicalize to \
                             '{base}'. Renamed to '{disambiguated}'. Update your OpenFGA model \
                             references accordingly.",
                            prior.spelling
                        ),
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
    fn get(&self, db: &ParserDB, table: &str) -> Option<&str> {
        let identity = table_identity(lookup_table(db, table)?);
        self.by_identity.get(&identity).map(String::as_str)
    }

    /// Type of `table`, deriving one when it has none: a parent without RLS still
    /// needs a type for the child to point at. The derived name steps aside when
    /// another table already owns it, so the child cannot inherit that table's
    /// permissions.
    fn resolve(&self, db: &ParserDB, table: &str) -> String {
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
const DERIVED_ACTION_RELATIONS: [&str; 5] = [
    CAN_UPDATE_USING_RELATION,
    CAN_UPDATE_CHECK_RELATION,
    CAN_INSERT_RETURNING_RELATION,
    CAN_UPSERT_RELATION,
    CAN_SELECT_FOR_UPDATE_RELATION,
];

/// Drop items added since `start` that repeat an earlier one, comparing level,
/// policy and message. Scoped to one policy so two same-named policies on
/// different tables keep their own entries.
fn dedup_todos_added_since(todos: &mut Vec<TodoItem>, start: usize) {
    let mut seen: Vec<(ConfidenceLevel, String, String)> = Vec::new();
    let mut index = start;
    while index < todos.len() {
        let Some(todo) = todos.get(index) else { break };
        let key = (todo.level, todo.policy_name.clone(), todo.message.clone());
        if seen.contains(&key) {
            todos.remove(index);
        } else {
            seen.push(key);
            index += 1;
        }
    }
}

/// Action targets a policy's stored clauses reach, which is the routing
/// `for_each_policy_target_expr` performs once those clauses are classified.
fn policy_clause_targets(policy: &sqlparser::ast::CreatePolicy) -> BTreeSet<ActionTarget> {
    let command = derive_policy_command(policy.command.as_ref());
    let mut targets = BTreeSet::new();
    if policy.using.is_some() {
        targets.extend(using_targets(&command));
    }
    if policy.with_check.is_some()
        || (policy.using.is_some() && policy_uses_using_for_missing_with_check(&command))
    {
        targets.extend(with_check_targets(&command));
    }
    targets
}

/// Commands the schema's permissive policies on one table cover, whatever their
/// confidence. The filtered policy set cannot answer this, and the answer decides
/// whether a denied command is a coverage gap in `PostgreSQL` or in the translation.
fn commands_a_permissive_policy_covers(
    declared: &[&<ParserDB as DatabaseLike>::Policy],
) -> BTreeSet<&'static str> {
    let mut commands = BTreeSet::new();
    for policy in declared {
        let reached = policy_clause_targets(policy);
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
fn policies_missing_a_clause(
    declared: &[&<ParserDB as DatabaseLike>::Policy],
) -> Vec<(String, String, &'static str)> {
    let mut missing = Vec::new();
    for policy in declared {
        if policy.using.is_some() {
            continue;
        }
        let command = derive_policy_command(policy.command.as_ref());
        let checks: BTreeSet<ActionTarget> = with_check_targets(&command).into_iter().collect();
        let applies: BTreeSet<ActionTarget> = using_targets(&command)
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
            missing.push((policy.name.value.clone(), needs_using.join(", "), "USING"));
        }
        if !needs_check.is_empty() && policy.with_check.is_none() {
            missing.push((
                policy.name.value.clone(),
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

/// Handle `P2RoleNameInList` when the function is *not* a `RoleThreshold` (e.g.
/// `pg_has_role()` or Supabase `auth.role()`).  Creates scope-style direct
/// relations per role name and emits `PolicyScope` tuple sources, mirroring the
/// pattern used for policy-level `TO` role scoping.
#[allow(clippy::too_many_arguments)]
fn handle_p2_role_gate(
    role_names: &[String],
    policy_name: &str,
    source_table: &str,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<String, TypePlan>,
    db: &ParserDB,
    todos: &mut Vec<TodoItem>,
) -> UsersetExpr {
    if role_names.is_empty() {
        return deny_expr(table_plan);
    }

    let scope_relation = policy_scope_relation_name(policy_name);
    register_pg_role_scope(
        table_plan,
        all_types,
        source_table,
        &scope_relation,
        role_names,
        policy_name,
        format!(
            "Role gate ({}) mapped to relation '{scope_relation}'; \
             ensure pg_role memberships are loaded",
            role_names.join(", ")
        ),
        db,
        todos,
        "role gate tuples",
    );

    UsersetExpr::Computed(scope_relation)
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
    todos: &mut Vec<TodoItem>,
) -> UsersetExpr {
    let db = crate::parser::sql_parser::parse_schema("").expect("empty schema should parse");
    translate_pattern(
        pattern,
        policy_name,
        table_plan,
        all_types,
        registry,
        todos,
        &RoleThresholdResourceHints::default(),
        &db,
        &TableTypes::default(),
        "test_table",
    )
}

/// Build the userset expression for one classified pattern.
///
/// The result does not depend on which command the policy covers: inheritance
/// always reads the parent's SELECT relation, and the caller files the expression
/// under the right action.
#[allow(clippy::too_many_arguments)]
fn translate_pattern(
    pattern: &PatternClass,
    policy_name: &str,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<String, TypePlan>,
    registry: &FunctionRegistry,
    todos: &mut Vec<TodoItem>,
    hints: &RoleThresholdResourceHints,
    db: &ParserDB,
    table_types: &TableTypes,
    source_table: &str,
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
                todos,
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
                todos,
            ) else {
                // Non-RoleThreshold function (e.g. pg_has_role, auth.role()) ,
                // fall back to scope-style direct relations per role name.
                return handle_p2_role_gate(
                    role_names,
                    policy_name,
                    source_table,
                    table_plan,
                    all_types,
                    db,
                    todos,
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
                add_missing_object_identifier_todo(
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
                add_missing_object_identifier_todo(
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
                add_missing_object_identifier_todo(
                    table_plan,
                    source_table,
                    "jsonb field ownership tuples",
                    db,
                );
            }
            UsersetExpr::Computed(relation)
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
            let read_scope_roles = match join_table_readability(join_table, db) {
                JoinTableReadability::Unreadable => {
                    todos.push(TodoItem {
                        level: ConfidenceLevel::C,
                        policy_name: policy_name.to_string(),
                        message: format!(
                            "Membership table '{join_table}' grants no reads, so no membership \
                             row is visible and the command is denied"
                        ),
                    });
                    return deny_expr(table_plan);
                }
                JoinTableReadability::Guarded { roles } => {
                    todos.push(TodoItem {
                        level: ConfidenceLevel::C,
                        policy_name: policy_name.to_string(),
                        message: format!(
                            "Row level security on membership table '{join_table}' decides which \
                             membership rows a user sees, which no relation can express. Load \
                             tuples only for the rows it exposes."
                        ),
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
                todos.push(TodoItem {
                    level: ConfidenceLevel::C,
                    policy_name: policy_name.to_string(),
                    message: format!(
                        "Membership policy carries extra predicate '{extra}' that must be preserved in tuple SQL"
                    ),
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
                add_missing_bridge_todo(table_plan, source_table, &parent_type, db);
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
                format!(
                    "Reading membership table '{join_table}' needs PostgreSQL role ({}), mapped to relation '{scope_relation}'; ensure pg_role memberships are loaded",
                    read_scope_roles.join(", ")
                ),
                db,
                todos,
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
                todos.push(TodoItem {
                    level: ConfidenceLevel::D,
                    policy_name: policy_name.to_string(),
                    message: format!(
                        "Parent inheritance from '{parent_table}' has unknown inner rule ({reason}); mapped to no_access"
                    ),
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
                    todos,
                    hints,
                    db,
                    table_types,
                    parent_table,
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
                    todos,
                    hints,
                    db,
                    table_types,
                    parent_table,
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
            let gate_on_parent = !rule_is_denial
                && lookup_table(db, parent_table)
                    .is_some_and(|table| table.has_row_level_security(db));
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
                todos.push(TodoItem {
                    level: ConfidenceLevel::C,
                    policy_name: policy_name.to_string(),
                    message: format!(
                        "Parent inheritance from '{parent_table}' could not translate the \
                         parent-side rule, so the command is denied"
                    ),
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
                add_missing_bridge_todo(table_plan, source_table, &parent_type, db);
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
                add_missing_object_identifier_todo(
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
            todos.push(TodoItem {
                level: ConfidenceLevel::C,
                policy_name: policy_name.to_string(),
                message: attribute_runtime_note(attribute_part),
            });
            // Recurse first so relationship sources appear before the attribute Todo
            // in table_tuple_sources (matching old generate_tuple_queries ordering).
            let result = translate_pattern(
                &relationship_part.pattern,
                policy_name,
                table_plan,
                all_types,
                registry,
                todos,
                hints,
                db,
                table_types,
                source_table,
            );
            table_plan.add_source(TupleSource::Todo {
                level: ConfidenceLevel::C,
                comment: format!(
                    "-- TODO [Level C]: attribute condition '{attribute_part}' on {source_table} requires runtime enforcement"
                ),
                sql: format!(
                    "-- No tuple can express the attribute filter '{attribute_part}', so application logic must enforce it."
                ),
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
                    todos,
                    hints,
                    db,
                    table_types,
                    source_table,
                ));
            }
            match op {
                BoolOp::Or => combine_union(child_exprs).unwrap_or_else(|| deny_expr(table_plan)),
                BoolOp::And => {
                    combine_intersection(child_exprs).unwrap_or_else(|| deny_expr(table_plan))
                }
            }
        }
        PatternClass::P9AttributeCondition { column, .. } => {
            todos.push(TodoItem {
                level: ConfidenceLevel::C,
                policy_name: policy_name.to_string(),
                message: format!(
                    "Standalone attribute policy on '{column}' mapped to no_access for safety"
                ),
            });
            table_plan.add_source(TupleSource::Todo {
                level: ConfidenceLevel::D,
                comment: format!(
                    "-- TODO [Level D]: skipped tuple generation for {source_table} (unsupported pattern P9)"
                ),
                sql: format!(
                    "-- Tuple query not emitted; attribute condition on '{column}' requires runtime filtering; no static tuple mapping."
                ),
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
                    add_missing_object_identifier_todo(
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
            todos.push(TodoItem {
                level: ConfidenceLevel::D,
                policy_name: policy_name.to_string(),
                message: format!(
                    "Expression could not be safely translated ({reason}); mapped to no_access"
                ),
            });
            table_plan.add_source(TupleSource::Todo {
                level: ConfidenceLevel::D,
                comment: format!(
                    "-- TODO [Level D]: skipped tuple generation for {source_table} (unsupported pattern Unknown)"
                ),
                sql: format!(
                    "-- Tuple query not emitted; classifier could not translate expression: {reason}."
                ),
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
fn prepare_role_threshold_translation(
    function_name: &str,
    function_kind_label: &str,
    policy_name: &str,
    source_table: &str,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<String, TypePlan>,
    registry: &FunctionRegistry,
    hints: &RoleThresholdResourceHints,
    db: &ParserDB,
    todos: &mut Vec<TodoItem>,
) -> Option<RoleThresholdPrepared> {
    let Some(FunctionSemantic::RoleThreshold {
        role_levels,
        team_membership_table,
        ..
    }) = registry.get(function_name)
    else {
        todos.push(TodoItem {
            level: ConfidenceLevel::D,
            policy_name: policy_name.to_string(),
            message: format!(
                "{function_kind_label} function '{function_name}' missing semantic metadata"
            ),
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
fn missing_object_identifier_reason(source_table: &str, db: &ParserDB) -> String {
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

const MISSING_OBJECT_IDENTIFIER_SQL: &str =
    "-- Tuple query not emitted; table needs a single-column primary key or a NOT NULL UNIQUE `id` column for stable object IDs.";

fn add_missing_object_identifier_todo(
    table_plan: &mut TypePlan,
    source_table: &str,
    what: &str,
    db: &ParserDB,
) {
    let reason = missing_object_identifier_reason(source_table, db);
    table_plan.add_source(TupleSource::Todo {
        level: ConfidenceLevel::D,
        comment: format!("-- TODO [Level D]: skipped {what} for {source_table} ({reason})"),
        sql: MISSING_OBJECT_IDENTIFIER_SQL.to_string(),
    });
}

fn add_missing_bridge_todo(
    table_plan: &mut TypePlan,
    source_table: &str,
    parent_type: &str,
    db: &ParserDB,
) {
    let reason = missing_object_identifier_reason(source_table, db);
    table_plan.add_source(TupleSource::Todo {
        level: ConfidenceLevel::D,
        comment: format!(
            "-- TODO [Level D]: skipped {source_table} to {parent_type} bridge ({reason})"
        ),
        sql: "-- Bridge tuple not emitted; review schema/FK mapping.".to_string(),
    });
}

fn add_explicit_grants_todo(
    table_plan: &mut TypePlan,
    source_table: &str,
    reason: &str,
    sql: &str,
) {
    table_plan.add_source(TupleSource::Todo {
        level: ConfidenceLevel::D,
        comment: format!(
            "-- TODO [Level D]: skipped explicit grants for {source_table} ({reason})"
        ),
        sql: sql.to_string(),
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

fn resolve_owner_column(table: &str, db: &ParserDB) -> Option<String> {
    let table_info = lookup_table(db, table)?;
    for col in table_info.columns(db) {
        let name = col.stored_column_name();
        if is_owner_like_column_name(&name) {
            return Some(name.into_owned());
        }
    }
    for fk in table_info.foreign_keys(db) {
        let ref_table = fk.referenced_table(db);
        let ref_name = ref_table.table_name();
        let normalized_ref = normalize_relation_name(ref_name);
        if normalized_ref == "users" || normalized_ref == "owners" {
            if let Some(col_name) = fk
                .host_columns(db)
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
fn referenced_table_for_fk_col<'db>(
    db: &'db ParserDB,
    table: &str,
    fk_column: &str,
) -> Option<&'db str> {
    let table_info = lookup_table(db, table)?;
    for fk in table_info.foreign_keys(db) {
        let uses_col = fk
            .host_columns(db)
            .any(|c| c.stored_column_name() == fk_column);
        if uses_col {
            return Some(fk.referenced_table(db).table_name());
        }
    }
    None
}

fn resolve_principal_info(
    db: &ParserDB,
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

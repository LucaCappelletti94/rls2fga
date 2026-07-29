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
use crate::parser::expr::extract_column_name;
use crate::parser::expr::function_arg_expr;
use crate::parser::function_analyzer::FunctionSemantic;
use crate::parser::names::{
    canonical_fga_type_name, clamp_relation_name, is_owner_like_column_name, lookup_table,
    normalize_identifier, normalize_relation_name, parent_type_from_fk_column,
    policy_scope_relation_name, stable_hex_suffix,
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
    TupleToUserset { tupleset: String, computed: String },
    Union(Vec<UsersetExpr>),
    Intersection(Vec<UsersetExpr>),
}

/// Structural identity of a userset expression, stable against `Debug` formatting.
/// Relation names are canonicalized, so the delimiters cannot appear inside one.
fn userset_key(expr: &UsersetExpr) -> String {
    match expr {
        UsersetExpr::Computed(name) => format!("c:{name}"),
        UsersetExpr::TupleToUserset { tupleset, computed } => format!("t:{tupleset}:{computed}"),
        UsersetExpr::Union(children) => format!("u({})", child_keys(children)),
        UsersetExpr::Intersection(children) => format!("i({})", child_keys(children)),
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
    /// Ownership column → the relation carrying its subjects. One relation per
    /// column: sharing one would union two different sets of principals.
    ownership_relations: BTreeMap<String, String>,
}

/// Relation names the generator reserves for its own structural relations, so a
/// column-derived name never lands on one regardless of translation order.
const RESERVED_RELATIONS: [&str; 5] = [
    "no_access",
    "public_viewer",
    "member",
    "owner_user",
    "owner_team",
];

impl TypePlan {
    fn new(type_name: impl Into<String>) -> Self {
        Self {
            type_name: type_name.into(),
            ..Self::default()
        }
    }

    /// Relation that carries the subjects of ownership column `column`.
    ///
    /// Derived from the column so the model reads naturally (`owner_id` → `owner`,
    /// `editor_id` → `editor`), and disambiguated when two columns would land on
    /// the same name or on a name the generator already uses.
    fn ownership_relation(&mut self, column: &str) -> String {
        if let Some(existing) = self.ownership_relations.get(column) {
            return existing.clone();
        }

        let base = canonical_fga_type_name(column.strip_suffix("_id").unwrap_or(column));
        let taken = |name: &str, plan: &Self| {
            RESERVED_RELATIONS.contains(&name)
                || ACTION_RELATIONS.contains(&name)
                || plan.direct_relations.contains_key(name)
                || plan.computed_relations.contains_key(name)
        };
        let relation = clamp_relation_name(if base.is_empty() || taken(&base, self) {
            let fallback = format!("owner_{}", canonical_fga_type_name(column));
            if taken(&fallback, self) {
                format!("{fallback}_{}", stable_hex_suffix(column))
            } else {
                fallback
            }
        } else {
            base
        });

        self.ownership_relations
            .insert(column.to_string(), relation.clone());
        relation
    }

    /// Register a directly-assignable relation, returning the name actually used.
    fn ensure_direct(
        &mut self,
        relation: impl Into<String>,
        subjects: Vec<DirectSubject>,
    ) -> String {
        let mut relation = clamp_relation_name(relation.into());
        // A relation admits exactly one subject list and cannot also be computed, so
        // a name already spoken for has to yield rather than emit a second `define`
        // or quietly inherit subjects it does not accept.
        let conflicts = self.computed_relations.contains_key(&relation)
            || self
                .direct_relations
                .get(&relation)
                .is_some_and(|held| *held != subjects);
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
        // One name, one rule: a name another rule holds has to yield, or callers that
        // derive it from the rule would silently read someone else's definition.
        let conflicts = self.direct_relations.contains_key(&relation)
            || self
                .computed_relations
                .get(&relation)
                .is_some_and(|held| *held != expr);
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

    // Group policies by source table
    let mut by_table: BTreeMap<String, Vec<&ClassifiedPolicy>> = BTreeMap::new();
    for cp in policies {
        by_table.entry(cp.table_name()).or_default().push(cp);
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

    let table_types = TableTypes::assign(db, &mut todos);

    for (source_table_name, table_policies) in by_table {
        // Only RLS-enabled tables that resolve against the schema get a type.
        let Some(canonical_table_name) = table_types.get(db, &source_table_name) else {
            continue;
        };
        let canonical_table_name = canonical_table_name.to_string();

        let mut table_plan = all_types
            .remove(&canonical_table_name)
            .unwrap_or_else(|| TypePlan::new(&canonical_table_name));

        // A SELECT policy that reads its own table needs itself to expand, which
        // PostgreSQL answers with `infinite recursion detected in policy for
        // relation`. Every read of the table fails, whatever the other policies say.
        let mut recursive_select: Option<String> = None;

        let mut action_buckets: BTreeMap<ActionTarget, ModeBuckets> = BTreeMap::new();

        for cp in table_policies {
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

            // The recursion is a property of the SQL, so it is judged before any
            // classification: a clause dropped by filtering still poisons reads.
            let recurses = policy_recurses_on_reads(cp, db, &table_types, &canonical_table_name);
            if recurses {
                recursive_select = Some(cp.name().to_string());
            }

            // A policy covering several phases is translated once per phase, so the
            // same clause reports the same item repeatedly. Keep one per policy.
            let todos_before = todos.len();
            for_each_policy_target_expr(cp, |target, classified| {
                if recurses && target == ActionTarget::Select {
                    // Nothing this clause names can ever be evaluated, so translating
                    // it would only leave relations no permission reaches.
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
                let expr = if let Some(scope_relation) = scope_relation.as_deref() {
                    scoped_policy_expr(expr, scope_relation)
                } else {
                    expr
                };
                // A permissive hybrid may hand its attribute half to the application,
                // but a restrictive clause is a barrier: dropping a conjunct there
                // admits rows PostgreSQL refuses, so the barrier keeps denying.
                let guards = dropped_attribute_guards(&classified.pattern);
                let expr = if cp.mode() == PolicyMode::Restrictive && !guards.is_empty() {
                    // The command is denied, so asking for runtime enforcement of the
                    // same guard would contradict the outcome.
                    for guard in guards {
                        let note = attribute_runtime_note(guard);
                        todos.retain(|todo| todo.policy_name != cp.name() || todo.message != note);
                    }
                    todos.push(TodoItem {
                        level: ConfidenceLevel::C,
                        policy_name: cp.name().to_string(),
                        message: format!(
                            "RESTRICTIVE policy '{}' guards on an attribute the model cannot \
                             express, so the command is denied rather than left unconstrained",
                            cp.name()
                        ),
                    });
                    UsersetExpr::Intersection(vec![expr, deny_expr(&mut table_plan)])
                } else {
                    expr
                };
                push_action_expr(&mut action_buckets, target, cp.mode(), expr);
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
        let mut update_check_expr = compose_action(
            &mut table_plan,
            action_buckets.get(&ActionTarget::UpdateCheck),
        );
        let mut delete_expr =
            compose_action(&mut table_plan, action_buckets.get(&ActionTarget::Delete));

        if let Some(policy_name) = recursive_select {
            select_expr = Some(deny_expr(&mut table_plan));
            todos.push(TodoItem {
                level: ConfidenceLevel::C,
                policy_name: policy_name.clone(),
                message: format!(
                    "SELECT policy '{policy_name}' reads '{source_table_name}', the table it \
                     guards, so PostgreSQL raises infinite recursion and no read of the table \
                     succeeds. The model denies reads to match, and the policy needs rewriting."
                ),
            });
        }

        if let Some(expr) = select_expr.take() {
            table_plan.set_computed("can_select", expr);
        }
        if let Some(expr) = insert_expr.take() {
            table_plan.set_computed("can_insert", expr);
        }
        // Naming the row to change means reading a column of it, so PostgreSQL also
        // applies the table's SELECT policies. Verified on PostgreSQL 16. A blanket
        // statement that reads no column escapes that, but it identifies no object
        // and so has no counterpart in a per-object check.
        if let Some(expr) = delete_expr.take() {
            table_plan.set_computed("can_delete", requires_read_access(expr));
        }

        if let Some(using_expr) = update_using_expr
            .take()
            .or_else(|| update_check_expr.clone())
        {
            let check_expr = update_check_expr
                .take()
                .unwrap_or_else(|| using_expr.clone());
            if using_expr == check_expr {
                table_plan.set_computed("can_update", requires_read_access(using_expr));
            } else {
                table_plan.set_computed("can_update_using", requires_read_access(using_expr));
                table_plan.set_computed("can_update_check", check_expr);
                table_plan.set_computed(
                    "can_update",
                    UsersetExpr::Intersection(vec![
                        UsersetExpr::Computed("can_update_using".to_string()),
                        UsersetExpr::Computed("can_update_check".to_string()),
                    ]),
                );
            }
        }

        // An undefined action relation reads as "the consumer decides", which is
        // how RLS coverage gaps become open access.
        let uncovered = fill_uncovered_actions_with_deny(&mut table_plan);
        if !uncovered.is_empty() {
            todos.push(TodoItem {
                level: ConfidenceLevel::C,
                policy_name: source_table_name.clone(),
                message: format!(
                    "No permissive policy on '{source_table_name}' covers {}; RLS denies \
                     {those} outright and the model mirrors that with no_access",
                    uncovered.join(", "),
                    those = if uncovered.len() == 1 { "it" } else { "them" }
                ),
            });
        }

        all_types.insert(canonical_table_name, table_plan);
    }

    if has_role_scopes {
        ensure_pg_role_type(&mut all_types);
    }

    all_types
        .entry("user".to_string())
        .or_insert_with(|| TypePlan::new("user"));

    simplify_redundant_select_gates(&mut all_types);
    inline_synthetic_rule_aliases(&mut all_types);

    let mut type_names: Vec<String> = all_types.keys().cloned().collect();
    type_names.sort();
    if let Some(pos) = type_names.iter().position(|n| n == "user") {
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
    (gate == "can_select").then_some(rule)
}

/// Whether `rule` can only hold where `visible` holds, judged structurally against
/// the relations of one type. Only the cases that are certain are reported, so an
/// unrecognized shape keeps its gate.
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
        UsersetExpr::TupleToUserset { .. } => false,
    }
}

/// Require the row to be readable, which every per-row change does.
fn requires_read_access(expr: UsersetExpr) -> UsersetExpr {
    UsersetExpr::Intersection(vec![expr, UsersetExpr::Computed("can_select".to_string())])
}

/// Replace every `can_select` gate a rule already implies with the rule itself,
/// since the conjunct can never change the outcome there.
fn simplify_redundant_select_gates(all_types: &mut BTreeMap<String, TypePlan>) {
    for plan in all_types.values_mut() {
        let relations = plan.computed_relations.clone();
        let Some(visible) = relations.get("can_select") else {
            continue;
        };
        for (relation, expr) in &mut plan.computed_relations {
            if relation == "can_select" {
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

/// Remove a synthesized rule relation that ended up as nothing but another name for
/// one relation on the same type, pointing whatever walked it at the original. Only
/// generated rule holders are disposable, since every other name is either an entry
/// point or documents a phase.
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
    }
}

fn scoped_policy_expr(expr: UsersetExpr, scope_relation: &str) -> UsersetExpr {
    UsersetExpr::Intersection(vec![
        expr,
        UsersetExpr::TupleToUserset {
            tupleset: scope_relation.to_string(),
            computed: "member".to_string(),
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

/// Operator note that a hybrid leaves its attribute half to the caller.
fn attribute_runtime_note(attribute: &str) -> String {
    format!("Attribute condition '{attribute}' still requires runtime enforcement")
}

/// Attribute guards this pattern discards when translated, which widens whatever
/// the pattern guards.
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

/// Whether a `SELECT` on `type_name` would expand this policy again, which happens
/// when the policy guards reads of that type and its own expression reads it.
/// `PostgreSQL` answers such a read with `infinite recursion detected in policy for
/// relation`, whatever the rest of the expression turned out to be.
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

/// Whether any relation the expression reads resolves to `type_name`. Column
/// qualifiers are identifiers rather than relations, so they are not counted.
fn expr_reads_table(expr: &Expr, db: &ParserDB, table_types: &TableTypes, type_name: &str) -> bool {
    let mut reads = false;
    let _ = sqlparser::ast::visit_relations(expr, |name| {
        if table_types.resolve(db, &name.to_string()) == type_name {
            reads = true;
            return core::ops::ControlFlow::Break(());
        }
        core::ops::ControlFlow::Continue(())
    });
    reads
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

    // Mirror USING → WITH CHECK only when the policy genuinely has no WITH CHECK
    // expression (i.e. it was never present in the SQL, not filtered by confidence).
    // If `with_check_was_filtered` is true, the expression existed but was dropped
    // due to low confidence; fall closed rather than promoting a low-confidence
    // USING expression as a WITH CHECK substitute.
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

fn push_action_expr(
    action_buckets: &mut BTreeMap<ActionTarget, ModeBuckets>,
    target: ActionTarget,
    mode: PolicyMode,
    expr: UsersetExpr,
) {
    let bucket = action_buckets.entry(target).or_default();
    match mode {
        PolicyMode::Permissive => bucket.permissive.push(expr),
        PolicyMode::Restrictive => bucket.restrictive.push(expr),
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
        vec![DirectSubject::Type("pg_role".to_string())],
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

    match (permissive, restrictive) {
        (Some(p), Some(r)) => Some(UsersetExpr::Intersection(vec![p, r])),
        (Some(p), None) => Some(p),
        (None, Some(_)) => Some(deny_expr(table_plan)),
        (None, None) => None,
    }
}

/// Quote `part` for a table-lookup key unless it is a bare lowercase identifier.
///
/// Not the SQL quoter: `tuple_generator::quote_sql_identifier` always quotes.
///
/// The result is used both to derive the type name and to look the table back up,
/// and `lookup_table` tries the quoted spelling as well as the unquoted one, so
/// quoting is the form that resolves either way.
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

/// Schema-qualified name, matching the spelling used in `CREATE POLICY`.
fn qualified_table_name(table: &<ParserDB as DatabaseLike>::Table) -> String {
    let relation = quoted_for_lookup(table.table_name());
    match table.table_schema() {
        Some(schema) => format!("{}.{relation}", quoted_for_lookup(schema)),
        None => relation,
    }
}

/// Identity that matches two table references however the policy spelled them.
fn table_identity(table: &<ParserDB as DatabaseLike>::Table) -> (Option<String>, String) {
    (
        table.table_schema().map(ToString::to_string),
        table.table_name().to_string(),
    )
}

/// Final `OpenFGA` type name of every table that gets a type.
///
/// Names are assigned in one pass before translation so that a table referenced
/// as a parent resolves to the same type as when its own policies are processed.
/// Deriving the name on demand would point a child at whichever same-named table
/// happened to claim the canonical name first.
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

const ACTION_RELATIONS: [&str; 4] = ["can_select", "can_insert", "can_update", "can_delete"];

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

/// Deny every action relation no policy produced, returning the denied commands.
fn fill_uncovered_actions_with_deny(table_plan: &mut TypePlan) -> Vec<&'static str> {
    let missing: Vec<&'static str> = ACTION_RELATIONS
        .into_iter()
        .filter(|relation| !table_plan.computed_relations.contains_key(*relation))
        .collect();
    if missing.is_empty() {
        return Vec::new();
    }
    let deny = deny_expr(table_plan);
    for relation in &missing {
        table_plan.set_computed(*relation, deny.clone());
    }
    missing
        .into_iter()
        .map(|relation| match relation {
            "can_select" => "SELECT",
            "can_insert" => "INSERT",
            "can_update" => "UPDATE",
            _ => "DELETE",
        })
        .collect()
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
    table_plan.ensure_direct("no_access", vec![DirectSubject::Type("user".to_string())]);
    UsersetExpr::Computed("no_access".to_string())
}

fn public_expr(table_plan: &mut TypePlan) -> UsersetExpr {
    table_plan.ensure_direct(
        "public_viewer",
        vec![DirectSubject::Wildcard("user".to_string())],
    );
    UsersetExpr::Computed("public_viewer".to_string())
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
            let relation = table_plan.ownership_relation(column);
            table_plan.ensure_direct(
                relation.clone(),
                vec![DirectSubject::Type("user".to_string())],
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
        PatternClass::P4ExistsMembership {
            join_table,
            fk_column,
            user_column,
            extra_predicate_sql,
            ..
        } => {
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
                table_plan.ensure_direct("member", vec![DirectSubject::Type("user".to_string())]);
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

            UsersetExpr::TupleToUserset {
                tupleset: parent_relation,
                computed: "member".to_string(),
            }
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
                matches!(&inner_expr, UsersetExpr::Computed(name) if name == "no_access");
            // The subquery reads the parent as the querying user, so the parent's own
            // RLS filters it: a row the parent hides cannot satisfy the rule. Verified
            // on PostgreSQL 16. A parent without RLS is unfiltered. A table reading
            // itself is gated the same way, since the row it reads is a different row.
            let gate_on_parent = !rule_is_denial
                && lookup_table(db, parent_table)
                    .is_some_and(|table| table.has_row_level_security(db));
            let rule_expr = if gate_on_parent {
                UsersetExpr::Intersection(vec![
                    inner_expr,
                    UsersetExpr::Computed("can_select".to_string()),
                ])
            } else {
                inner_expr
            };
            let inherited = match rule_expr {
                UsersetExpr::Computed(name) => name,
                expr => {
                    // The rule belongs to the parent, so name it after the rule itself.
                    // Two children needing the same rule then share one relation, and
                    // renaming a policy leaves the parent's relations alone.
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
                    "-- TODO [Level C]: attribute condition '{attribute_part}' on {source_table} requires runtime enforcement; relationship tuples generated above"
                ),
                sql: format!(
                    "-- Tuple query not emitted; attribute filter '{attribute_part}' must be enforced by application logic."
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
    match composite_primary_key_columns(source_table, db) {
        Some(columns) => format!(
            "composite primary key ({}) leaves no single-column object identifier",
            columns.join(", ")
        ),
        None => "missing object identifier column".to_string(),
    }
}

const MISSING_OBJECT_IDENTIFIER_SQL: &str =
    "-- Tuple query not emitted; table needs a single-column primary key or `id` column for stable object IDs.";

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
    entry.ensure_direct("member", vec![DirectSubject::Type("user".to_string())]);
}

fn ensure_pg_role_type(all_types: &mut BTreeMap<String, TypePlan>) {
    ensure_member_type(all_types, "pg_role");
}

fn ensure_role_threshold_scaffold(
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<String, TypePlan>,
    role_levels: &BTreeMap<String, i32>,
    has_team_support: bool,
) -> Vec<RoleRelationName> {
    let sorted_roles = sorted_role_relation_names(role_levels);

    table_plan.ensure_direct("owner_user", vec![DirectSubject::Type("user".to_string())]);

    if has_team_support {
        table_plan.ensure_direct("owner_team", vec![DirectSubject::Type("team".to_string())]);
        ensure_member_type(all_types, "team");
    }

    let grant_subjects = if has_team_support {
        vec![
            DirectSubject::Type("user".to_string()),
            DirectSubject::Type("team".to_string()),
        ]
    } else {
        vec![DirectSubject::Type("user".to_string())]
    };

    for role in &sorted_roles {
        table_plan.ensure_direct(role.grant_relation(), grant_subjects.clone());
    }

    let mut descending = sorted_roles.clone();
    descending.reverse();

    for (idx, role) in descending.iter().enumerate() {
        let mut children = Vec::new();

        if idx == 0 {
            children.push(UsersetExpr::Computed("owner_user".to_string()));
            if has_team_support {
                children.push(UsersetExpr::TupleToUserset {
                    tupleset: "owner_team".to_string(),
                    computed: "member".to_string(),
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
                computed: "member".to_string(),
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
                    computed: "member".to_string(),
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
            children.push(UsersetExpr::Computed("owner_user".to_string()));
            if has_team_support {
                children.push(UsersetExpr::TupleToUserset {
                    tupleset: "owner_team".to_string(),
                    computed: "member".to_string(),
                });
            }
        }
    }

    combine_union(children)
}

fn resolve_owner_column(table: &str, db: &ParserDB) -> Option<String> {
    let table_info = lookup_table(db, table)?;
    for col in table_info.columns(db) {
        let name = col.column_name();
        if is_owner_like_column_name(name) {
            return Some(name.to_string());
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
                .map(|col| col.column_name().to_string())
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
        let uses_col = fk.host_columns(db).any(|c| c.column_name() == fk_column);
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

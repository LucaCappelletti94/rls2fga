use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write;

use crate::classifier::ast_args::function_arg_expr;
use crate::classifier::function_registry::FunctionRegistry;
use crate::classifier::patterns::*;
use crate::generator::db_lookup::{resolve_pk_column, table_has_column};
use crate::generator::ir::{PrincipalInfo, TupleSource};
use crate::generator::role_relations::{sorted_role_relation_names, RoleRelationName};
use crate::parser::expr::extract_column_name;
use crate::parser::function_analyzer::FunctionSemantic;
use crate::parser::names::{
    canonical_fga_type_name, is_owner_like_column_name, lookup_table, normalize_relation_name,
    parent_type_from_fk_column, policy_scope_relation_name, stable_hex_suffix,
};
use crate::parser::sql_parser::{ColumnLike, ForeignKeyLike, ParserDB, TableLike};
use sqlparser::ast::{Expr, Function, FunctionArguments, Query, SelectItem, SetExpr};

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UsersetExpr {
    Computed(String),
    TupleToUserset { tupleset: String, computed: String },
    Union(Vec<UsersetExpr>),
    Intersection(Vec<UsersetExpr>),
}

#[derive(Debug, Clone, Default)]
pub(crate) struct TypePlan {
    pub type_name: String,
    pub direct_relations: BTreeMap<String, Vec<DirectSubject>>,
    pub computed_relations: BTreeMap<String, UsersetExpr>,
    /// Tuple sources keyed by relation name.  A relation without an entry has
    /// no static SQL tuples.  Populated during pattern translation; consumed by
    /// [`crate::generator::tuple_generator`].
    // Populated in Step 3 of the IR migration; read in Step 4.
    #[allow(dead_code)]
    pub tuple_sources: BTreeMap<String, Vec<TupleSource>>,
    /// Table-level tuple sources not tied to a specific relation (e.g. policy
    /// scope tuples).
    pub table_tuple_sources: Vec<TupleSource>,
}

impl TypePlan {
    fn new(type_name: impl Into<String>) -> Self {
        Self {
            type_name: type_name.into(),
            direct_relations: BTreeMap::new(),
            computed_relations: BTreeMap::new(),
            tuple_sources: BTreeMap::new(),
            table_tuple_sources: Vec::new(),
        }
    }

    fn ensure_direct(&mut self, relation: impl Into<String>, subjects: Vec<DirectSubject>) {
        let relation = relation.into();
        // Guard: a relation cannot be both direct and computed — OpenFGA would reject duplicate `define` lines.
        debug_assert!(
            !self.computed_relations.contains_key(&relation),
            "relation '{relation}' already registered as computed; cannot also register as direct"
        );
        self.direct_relations.entry(relation).or_insert(subjects);
    }

    fn ensure_computed(&mut self, relation: impl Into<String>, expr: UsersetExpr) {
        let relation = relation.into();
        // Guard: a relation cannot be both direct and computed — OpenFGA would reject duplicate `define` lines.
        debug_assert!(
            !self.direct_relations.contains_key(&relation),
            "relation '{relation}' already registered as direct; cannot also register as computed"
        );
        self.computed_relations.entry(relation).or_insert(expr);
    }

    fn set_computed(&mut self, relation: impl Into<String>, expr: UsersetExpr) {
        let relation = relation.into();
        // Guard: if this relation was already registered as direct, that is a programming error.
        debug_assert!(
            !self.direct_relations.contains_key(&relation),
            "relation '{relation}' already registered as direct; cannot overwrite as computed"
        );
        self.computed_relations.insert(relation, expr);
    }

    fn has_relations(&self) -> bool {
        !self.direct_relations.is_empty() || !self.computed_relations.is_empty()
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    pub columns: HashMap<(String, String), String>,
    /// `(table, function_name)` pairs where multiple distinct resource columns
    /// were observed; these cannot be resolved to a single tuple join column.
    pub conflicts: BTreeSet<(String, String)>,
}

/// Resolved resource-join information for a single P1/P2 call site.
// Constructed in Step 3 once TupleSource population begins.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct RoleThresholdResourceJoin<'a> {
    /// The unambiguous resource column, if one could be inferred.
    pub column: Option<&'a str>,
    /// `true` when multiple conflicting columns were observed for this key.
    pub conflict: bool,
}

/// Generate an ``OpenFGA`` model from classified policies.
pub fn generate_model(
    policies: &[ClassifiedPolicy],
    db: &ParserDB,
    registry: &FunctionRegistry,
    min_confidence: ConfidenceLevel,
) -> GeneratedModel {
    let filtered = filter_policies_for_output(policies, min_confidence);
    let plan = build_schema_plan(&filtered, db, registry);
    let dsl = render_dsl(&plan.types);

    GeneratedModel {
        dsl,
        todos: plan.todos,
        confidence_summary: plan.confidence_summary,
    }
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

    // Track which source table first claimed each canonical OpenFGA type name so we can
    // detect and disambiguate collisions (e.g. `app.users` and `auth.users` both → `users`).
    let mut canonical_name_owners: BTreeMap<String, String> = BTreeMap::new();

    // Group policies by source table
    let mut by_table: BTreeMap<String, Vec<&ClassifiedPolicy>> = BTreeMap::new();
    for cp in policies {
        by_table.entry(cp.table_name()).or_default().push(cp);
    }

    for (source_table_name, table_policies) in by_table {
        let base_canonical = canonical_fga_type_name(&source_table_name);

        // Detect canonical-name collision: two distinct source tables mapping to the same
        // OpenFGA type identifier.  Disambiguate by appending a stable hex suffix of the
        // original qualified name so each table gets its own type.
        let canonical_table_name =
            if let Some(prior_owner) = canonical_name_owners.get(&base_canonical) {
                if prior_owner == &source_table_name {
                    base_canonical
                } else {
                    // Disambiguate: append a short stable hash of the qualified name.
                    let suffix = stable_hex_suffix(&source_table_name);
                    let disambiguated = format!("{base_canonical}_{suffix}");
                    todos.push(TodoItem {
                        level: ConfidenceLevel::C,
                        policy_name: source_table_name.clone(),
                        message: format!(
                            "Type name collision: '{source_table_name}' and '{prior_owner}' both \
                             canonicalize to '{base_canonical}'. Renamed to '{disambiguated}'. \
                             Update your OpenFGA model references accordingly."
                        ),
                    });
                    canonical_name_owners.insert(disambiguated.clone(), source_table_name.clone());
                    disambiguated
                }
            } else {
                canonical_name_owners.insert(base_canonical.clone(), source_table_name.clone());
                base_canonical
            };

        // Only generate resource types for RLS-enabled tables.
        let table_lookup = lookup_table(db, &source_table_name);
        let Some(table) = table_lookup else {
            continue;
        };
        if !table.has_row_level_security(db) {
            continue;
        }

        let mut table_plan = all_types
            .remove(&canonical_table_name)
            .unwrap_or_else(|| TypePlan::new(&canonical_table_name));

        let mut action_buckets: HashMap<ActionTarget, ModeBuckets> = HashMap::new();

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
                table_plan.ensure_direct(
                    relation.clone(),
                    vec![DirectSubject::Type("pg_role".to_string())],
                );
                todos.push(TodoItem {
                    level: ConfidenceLevel::C,
                    policy_name: cp.name().to_string(),
                    message: format!(
                        "Policy role scope TO ({}) mapped to relation '{relation}'; ensure pg_role memberships are loaded",
                        scoped_roles.join(", ")
                    ),
                });
                if let Some(pk_col) = resolve_pk_column(&source_table_name, db) {
                    for role in &scoped_roles {
                        let pg_role = canonical_fga_type_name(role);
                        table_plan.add_source(TupleSource::PolicyScope {
                            table: source_table_name.clone(),
                            pk_col: pk_col.clone(),
                            scope_relation: relation.clone(),
                            pg_role,
                        });
                    }
                } else {
                    add_missing_object_identifier_todo(
                        &mut table_plan,
                        &source_table_name,
                        "policy scope tuples",
                    );
                }
                Some(relation)
            };

            for_each_policy_target_expr(cp, |target, classified| {
                let expr = pattern_to_expr_for_target(
                    &classified.pattern,
                    cp.name(),
                    target,
                    &mut table_plan,
                    &mut all_types,
                    registry,
                    &mut todos,
                    &role_threshold_resource_hints,
                    db,
                    &source_table_name,
                );
                let expr = if let Some(scope_relation) = scope_relation.as_deref() {
                    scoped_policy_expr(expr, scope_relation)
                } else {
                    expr
                };
                push_action_expr(&mut action_buckets, target, cp.mode(), expr);
            });
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

        if let Some(expr) = select_expr.take() {
            table_plan.set_computed("can_select", expr);
        }
        if let Some(expr) = insert_expr.take() {
            table_plan.set_computed("can_insert", expr);
        }
        if let Some(expr) = delete_expr.take() {
            table_plan.set_computed("can_delete", expr);
        }

        if let Some(using_expr) = update_using_expr
            .take()
            .or_else(|| update_check_expr.clone())
        {
            let check_expr = update_check_expr
                .take()
                .unwrap_or_else(|| using_expr.clone());
            if using_expr == check_expr {
                table_plan.set_computed("can_update", using_expr);
            } else {
                table_plan.set_computed("can_update_using", using_expr);
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

        if !table_plan.has_relations() {
            todos.push(TodoItem {
                level: ConfidenceLevel::D,
                policy_name: source_table_name.clone(),
                message: format!(
                    "No translatable relations generated for table '{source_table_name}'"
                ),
            });
        }

        all_types.insert(canonical_table_name, table_plan);
    }

    rewrite_p5_update_phases(&mut all_types);

    if has_role_scopes {
        ensure_pg_role_type(&mut all_types);
    }

    all_types
        .entry("user".to_string())
        .or_insert_with(|| TypePlan::new("user"));

    let mut type_names: Vec<String> = all_types.keys().cloned().collect();
    type_names.sort();
    let pos = type_names
        .iter()
        .position(|n| n == "user")
        .expect("user type should always be present");
    let user = type_names.remove(pos);
    type_names.insert(0, user);

    let types = type_names
        .into_iter()
        .map(|name| {
            all_types
                .remove(&name)
                .expect("type name should exist in plan map")
        })
        .collect();

    SchemaPlan {
        types,
        todos,
        confidence_summary,
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

fn for_each_policy_target_expr<F>(cp: &ClassifiedPolicy, mut f: F)
where
    F: FnMut(ActionTarget, &ClassifiedExpr),
{
    if let Some(using) = cp.using_classification.as_ref() {
        for target in using_targets(&cp.command()) {
            f(target, using);
        }
    }

    // Mirror USING → WITH CHECK only when the policy genuinely has no WITH CHECK
    // expression (i.e. it was never present in the SQL, not filtered by confidence).
    // If `with_check_was_filtered` is true, the expression existed but was dropped
    // due to low confidence; fall closed rather than promoting a low-confidence
    // USING expression as a WITH CHECK substitute.
    let with_check_pattern = cp.with_check_classification.as_ref().or_else(|| {
        if !cp.with_check_was_filtered && policy_uses_using_for_missing_with_check(&cp.command()) {
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

fn action_relation_for_target(target: ActionTarget) -> &'static str {
    match target {
        ActionTarget::Select => "can_select",
        ActionTarget::Insert => "can_insert",
        ActionTarget::UpdateUsing | ActionTarget::UpdateCheck => "can_update",
        ActionTarget::Delete => "can_delete",
    }
}

fn push_action_expr(
    action_buckets: &mut HashMap<ActionTarget, ModeBuckets>,
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

fn combine_union(mut exprs: Vec<UsersetExpr>) -> Option<UsersetExpr> {
    if exprs.is_empty() {
        return None;
    }
    if exprs.len() == 1 {
        return exprs.pop();
    }
    Some(UsersetExpr::Union(exprs))
}

fn combine_intersection(mut exprs: Vec<UsersetExpr>) -> Option<UsersetExpr> {
    if exprs.is_empty() {
        return None;
    }
    if exprs.len() == 1 {
        return exprs.pop();
    }
    Some(UsersetExpr::Intersection(exprs))
}

fn rewrite_p5_update_phases(all_types: &mut BTreeMap<String, TypePlan>) {
    let relation_index: HashMap<String, BTreeSet<String>> = all_types
        .iter()
        .map(|(type_name, plan)| {
            let mut rels: BTreeSet<String> = plan.computed_relations.keys().cloned().collect();
            rels.extend(plan.direct_relations.keys().cloned());
            (type_name.clone(), rels)
        })
        .collect();

    for plan in all_types.values_mut() {
        for target_relation in ["can_update_using", "can_update_check"] {
            let Some(expr) = plan.computed_relations.get_mut(target_relation) else {
                continue;
            };
            rewrite_update_phase_expr(
                expr,
                target_relation,
                &plan.direct_relations,
                &relation_index,
            );
        }
    }
}

fn rewrite_update_phase_expr(
    expr: &mut UsersetExpr,
    target_relation: &str,
    direct_relations: &BTreeMap<String, Vec<DirectSubject>>,
    relation_index: &HashMap<String, BTreeSet<String>>,
) {
    match expr {
        UsersetExpr::TupleToUserset { tupleset, computed } => {
            if computed != "can_update" {
                return;
            }

            let Some(subjects) = direct_relations.get(tupleset) else {
                return;
            };
            let parent_types: Vec<&str> = subjects
                .iter()
                .filter_map(|s| match s {
                    DirectSubject::Type(t) => Some(t.as_str()),
                    DirectSubject::Wildcard(_) => None,
                })
                .collect();
            if parent_types.is_empty() {
                return;
            }

            if parent_types.iter().all(|parent_type| {
                relation_index
                    .get(*parent_type)
                    .is_some_and(|rels| rels.contains(target_relation))
            }) {
                *computed = target_relation.to_string();
            }
        }
        UsersetExpr::Union(children) | UsersetExpr::Intersection(children) => {
            for child in children {
                rewrite_update_phase_expr(child, target_relation, direct_relations, relation_index);
            }
        }
        UsersetExpr::Computed(_) => {}
    }
}

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
    pattern_to_expr_for_target(
        pattern,
        policy_name,
        ActionTarget::Select,
        table_plan,
        all_types,
        registry,
        todos,
        &RoleThresholdResourceHints::default(),
        &db,
        "test_table",
    )
}

#[allow(clippy::too_many_arguments)]
fn pattern_to_expr_for_target(
    pattern: &PatternClass,
    policy_name: &str,
    target: ActionTarget,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<String, TypePlan>,
    registry: &FunctionRegistry,
    todos: &mut Vec<TodoItem>,
    hints: &RoleThresholdResourceHints,
    db: &ParserDB,
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
                return deny_expr(table_plan);
            };

            // Collect the exact set of role names that the policy grants access to.
            //
            // Role names are matched by name (case-insensitive), not by integer
            // level, to avoid conflating two roles that happen to share the same
            // level (e.g. `viewer=1` and `guest=1`).
            //
            // Numeric items in the IN list (e.g. `IN (2, 4)`) are treated as
            // level values: all roles at the given level are included.
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
            table_plan.ensure_direct("owner", vec![DirectSubject::Type("user".to_string())]);
            if let Some(pk_col) = resolve_pk_column(source_table, db) {
                table_plan.add_source(TupleSource::DirectOwnership {
                    table: source_table.to_string(),
                    pk_col,
                    owner_col: column.clone(),
                });
            } else {
                add_missing_object_identifier_todo(table_plan, source_table, "ownership tuples");
            }
            UsersetExpr::Computed("owner".to_string())
        }
        PatternClass::P4ExistsMembership {
            join_table,
            fk_column,
            user_column,
            extra_predicate_sql,
        } => {
            // Prefer the table that fk_column actually references (e.g. "teams"
            // for team_members.team_id → teams.id).  Fall back to the FK-column
            // name heuristic when no FK constraint metadata is available
            // (e.g. "doc_id" → "doc" for an undeclared reference).
            let parent_type = referenced_table_for_fk_col(db, join_table, fk_column).map_or_else(
                || parent_type_from_fk_column(fk_column),
                canonical_fga_type_name,
            );

            table_plan.ensure_direct(
                parent_type.clone(),
                vec![DirectSubject::Type(parent_type.clone())],
            );
            ensure_member_type(all_types, &parent_type);

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
            all_types
                .get_mut(&parent_type)
                .expect("ensure_member_type should have created the parent type entry")
                .add_source(membership_source);

            // Bridge rows link each source-table row to its parent.
            // The pk_col is resolved at render time via resolve_bridge_columns;
            // we emit a Todo here only if the table has no identifiable PK at all.
            if resolve_pk_column(source_table, db).is_some() {
                table_plan.add_source(TupleSource::ParentBridge {
                    table: source_table.to_string(),
                    fk_col: fk_column.clone(),
                    parent_type: parent_type.clone(),
                });
            } else {
                add_missing_bridge_todo(table_plan, source_table, &parent_type);
            }

            UsersetExpr::TupleToUserset {
                tupleset: parent_type,
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

            let parent_relation = canonical_fga_type_name(parent_table);

            table_plan.ensure_direct(
                parent_relation.clone(),
                vec![DirectSubject::Type(parent_relation.clone())],
            );
            // Pre-populate the parent TypePlan with the relations derived from the
            // inner pattern.  This ensures the parent has the correct action relation
            // even if its own policies haven't been processed yet.
            let parent_plan = all_types
                .entry(parent_relation.clone())
                .or_insert_with(|| TypePlan::new(&parent_relation));
            // Temporarily take the parent plan out to call pattern_to_expr_for_target.
            // We'll re-insert it afterwards.
            let mut parent_plan_owned =
                std::mem::replace(parent_plan, TypePlan::new(&parent_relation));
            let inner_expr = pattern_to_expr_for_target(
                &inner_pattern.pattern,
                policy_name,
                target,
                &mut parent_plan_owned,
                all_types,
                registry,
                todos,
                hints,
                db,
                parent_table,
            );
            // Re-insert the (now populated) parent plan.
            *all_types
                .entry(parent_relation.clone())
                .or_insert_with(|| TypePlan::new(&parent_relation)) = parent_plan_owned;

            if matches!(inner_expr, UsersetExpr::Computed(ref name) if name == "no_access") {
                todos.push(TodoItem {
                    level: ConfidenceLevel::C,
                    policy_name: policy_name.to_string(),
                    message: format!(
                        "Parent inheritance from '{parent_table}' inner pattern could not be \
                         safely translated; '{parent_table}' may not expose '{}' \
                         (check parent table's RLS policies)",
                        action_relation_for_target(target)
                    ),
                });
            }

            if resolve_pk_column(source_table, db).is_some() {
                table_plan.add_source(TupleSource::ParentBridge {
                    table: source_table.to_string(),
                    fk_col: fk_column.clone(),
                    parent_type: parent_relation.clone(),
                });
            } else {
                add_missing_bridge_todo(table_plan, source_table, &parent_relation);
            }

            UsersetExpr::TupleToUserset {
                tupleset: parent_relation,
                computed: action_relation_for_target(target).to_string(),
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
                add_missing_object_identifier_todo(table_plan, source_table, "public-flag tuples");
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
                message: format!(
                    "Attribute condition '{attribute_part}' still requires runtime enforcement"
                ),
            });
            // Recurse first so relationship sources appear before the attribute Todo
            // in table_tuple_sources (matching old generate_tuple_queries ordering).
            let result = pattern_to_expr_for_target(
                &relationship_part.pattern,
                policy_name,
                target,
                table_plan,
                all_types,
                registry,
                todos,
                hints,
                db,
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
                child_exprs.push(pattern_to_expr_for_target(
                    &part.pattern,
                    policy_name,
                    target,
                    table_plan,
                    all_types,
                    registry,
                    todos,
                    hints,
                    db,
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

const MISSING_OBJECT_IDENTIFIER_SQL: &str =
    "-- Tuple query not emitted; table needs a primary key or `id` column for stable object IDs.";

fn add_missing_object_identifier_todo(table_plan: &mut TypePlan, source_table: &str, what: &str) {
    table_plan.add_source(TupleSource::Todo {
        level: ConfidenceLevel::D,
        comment: format!(
            "-- TODO [Level D]: skipped {what} for {source_table} (missing object identifier column)"
        ),
        sql: MISSING_OBJECT_IDENTIFIER_SQL.to_string(),
    });
}

fn add_missing_bridge_todo(table_plan: &mut TypePlan, source_table: &str, parent_type: &str) {
    table_plan.add_source(TupleSource::Todo {
        level: ConfidenceLevel::D,
        comment: format!(
            "-- TODO [Level D]: skipped {source_table} to {parent_type} bridge (missing object identifier column)"
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
    let entry = all_types
        .entry("pg_role".to_string())
        .or_insert_with(|| TypePlan::new("pg_role"));
    entry.ensure_direct("member", vec![DirectSubject::Type("user".to_string())]);
}

fn ensure_role_threshold_scaffold(
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<String, TypePlan>,
    role_levels: &HashMap<String, i32>,
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
        } else {
            children.push(UsersetExpr::Computed(descending[idx - 1].role_relation()));
        }

        let grant_name = role.grant_relation();
        children.push(UsersetExpr::Computed(grant_name.clone()));
        if has_team_support {
            children.push(UsersetExpr::TupleToUserset {
                tupleset: grant_name,
                computed: "member".to_string(),
            });
        }

        table_plan.ensure_computed(
            role.role_relation(),
            combine_union(children).expect("role relation should always have at least one source"),
        );
    }

    sorted_roles
}

fn role_for_level(sorted_roles: &[RoleRelationName], min_level: i32) -> Option<String> {
    sorted_roles
        .iter()
        .find(|role| role.level >= min_level)
        .map(RoleRelationName::role_relation)
}

/// Build the `OpenFGA` userset expression for a P2 role-name-in-list policy.
///
/// `selected_names` is the set of role **original names** (lowercased) that the
/// policy grants access to.  Roles that share an integer level but have a
/// *different* name are intentionally excluded — this prevents the conflation
/// bug where `viewer=1` and `guest=1` both grant access when only `'viewer'`
/// is listed in the SQL policy.
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

// ---------------------------------------------------------------------------
// Role-threshold resource column pre-pass
//
// These functions walk the raw policy Expr AST to infer which column name is
// passed as the "resource" argument in each P1/P2 role-threshold function
// call.  The result is threaded into pattern_to_expr_for_target so that the
// tuple-SQL renderer can emit the correct JOIN column without re-walking the
// AST a second time.
// ---------------------------------------------------------------------------

pub(crate) fn infer_role_threshold_resource_columns(
    policies: &[ClassifiedPolicy],
    registry: &FunctionRegistry,
) -> RoleThresholdResourceHints {
    let mut hints = RoleThresholdResourceHints::default();

    for cp in policies {
        collect_policy_resource_column(
            &cp.table_name(),
            cp.policy.using.as_ref(),
            cp.using_classification.as_ref(),
            registry,
            &mut hints.columns,
            &mut hints.conflicts,
        );
        collect_policy_resource_column(
            &cp.table_name(),
            cp.policy.with_check.as_ref(),
            cp.with_check_classification.as_ref(),
            registry,
            &mut hints.columns,
            &mut hints.conflicts,
        );
    }

    hints
}

fn collect_policy_resource_column(
    table: &str,
    policy_expr: Option<&Expr>,
    classified: Option<&ClassifiedExpr>,
    registry: &FunctionRegistry,
    out: &mut HashMap<(String, String), String>,
    conflicts: &mut BTreeSet<(String, String)>,
) {
    let Some(expr) = policy_expr else {
        return;
    };

    for (function_name, resource_param_index) in
        role_threshold_functions_and_resource_params(classified, registry)
    {
        let key = (table.to_string(), function_name);
        if conflicts.contains(&key) {
            continue;
        }

        let resource_cols =
            extract_resource_columns_for_function(expr, &key.1, resource_param_index);
        if resource_cols.is_empty() {
            continue;
        }
        if resource_cols.len() > 1 {
            out.remove(&key);
            conflicts.insert(key);
            continue;
        }
        let resource_col = resource_cols
            .into_iter()
            .next()
            .expect("non-empty resource column set should contain one value");

        if let Some(existing) = out.get(&key) {
            if existing != &resource_col {
                out.remove(&key);
                conflicts.insert(key);
            }
            continue;
        }

        out.insert(key, resource_col);
    }
}

fn role_threshold_functions_and_resource_params(
    classified: Option<&ClassifiedExpr>,
    registry: &FunctionRegistry,
) -> Vec<(String, usize)> {
    fn walk(
        classified: &ClassifiedExpr,
        registry: &FunctionRegistry,
        out: &mut BTreeSet<(String, usize)>,
    ) {
        match &classified.pattern {
            PatternClass::P1NumericThreshold { function_name, .. }
            | PatternClass::P2RoleNameInList { function_name, .. } => {
                let Some(FunctionSemantic::RoleThreshold {
                    resource_param_index,
                    ..
                }) = registry.get(function_name)
                else {
                    return;
                };
                out.insert((function_name.clone(), *resource_param_index));
            }
            PatternClass::P5ParentInheritance { inner_pattern, .. } => {
                walk(inner_pattern, registry, out);
            }
            PatternClass::P7AbacAnd {
                relationship_part, ..
            } => {
                walk(relationship_part, registry, out);
            }
            PatternClass::P8Composite { parts, .. } => {
                for part in parts {
                    walk(part, registry, out);
                }
            }
            PatternClass::P3DirectOwnership { .. }
            | PatternClass::P4ExistsMembership { .. }
            | PatternClass::P6BooleanFlag { .. }
            | PatternClass::P9AttributeCondition { .. }
            | PatternClass::P10ConstantBool { .. }
            | PatternClass::Unknown { .. } => {}
        }
    }

    let Some(classified) = classified else {
        return Vec::new();
    };

    let mut functions = BTreeSet::new();
    walk(classified, registry, &mut functions);
    functions.into_iter().collect()
}

fn extract_resource_columns_for_function(
    expr: &Expr,
    function_name: &str,
    resource_param_index: usize,
) -> BTreeSet<String> {
    let mut functions = Vec::new();
    collect_function_calls(expr, function_name, &mut functions);

    let mut columns = BTreeSet::new();
    for function in functions {
        let Some(arg_expr) = positional_function_arg(function, resource_param_index) else {
            continue;
        };
        let Some(column) = extract_column_name(arg_expr) else {
            continue;
        };
        columns.insert(column);
    }

    columns
}

fn collect_function_calls<'a>(expr: &'a Expr, function_name: &str, out: &mut Vec<&'a Function>) {
    match expr {
        Expr::Function(function)
            if normalize_relation_name(&function.name.to_string())
                == normalize_relation_name(function_name) =>
        {
            out.push(function);
        }
        Expr::Function(function) => {
            if let FunctionArguments::List(arg_list) = &function.args {
                for arg in &arg_list.args {
                    if let Some(expr) = function_arg_expr(arg) {
                        collect_function_calls(expr, function_name, out);
                    }
                }
            }
        }
        Expr::BinaryOp { left, right, .. }
        | Expr::IsDistinctFrom(left, right)
        | Expr::IsNotDistinctFrom(left, right)
        | Expr::AnyOp { left, right, .. }
        | Expr::AllOp { left, right, .. } => {
            collect_function_calls(left, function_name, out);
            collect_function_calls(right, function_name, out);
        }
        Expr::UnaryOp { expr, .. }
        | Expr::Cast { expr, .. }
        | Expr::InSubquery { expr, .. }
        | Expr::IsNull(expr)
        | Expr::IsNotNull(expr)
        | Expr::IsTrue(expr)
        | Expr::IsFalse(expr)
        | Expr::IsNotTrue(expr)
        | Expr::IsNotFalse(expr)
        | Expr::IsUnknown(expr)
        | Expr::IsNotUnknown(expr) => collect_function_calls(expr, function_name, out),
        Expr::Nested(inner) => collect_function_calls(inner, function_name, out),
        Expr::Exists { subquery, .. } | Expr::Subquery(subquery) => {
            collect_function_calls_in_query(subquery, function_name, out);
        }
        Expr::InList { expr, list, .. } => {
            collect_function_calls(expr, function_name, out);
            for item in list {
                collect_function_calls(item, function_name, out);
            }
        }
        Expr::InUnnest {
            expr, array_expr, ..
        } => {
            collect_function_calls(expr, function_name, out);
            collect_function_calls(array_expr, function_name, out);
        }
        Expr::Between {
            expr, low, high, ..
        } => {
            collect_function_calls(expr, function_name, out);
            collect_function_calls(low, function_name, out);
            collect_function_calls(high, function_name, out);
        }
        Expr::Case {
            operand,
            conditions,
            else_result,
            ..
        } => {
            if let Some(operand) = operand.as_deref() {
                collect_function_calls(operand, function_name, out);
            }
            for when in conditions {
                collect_function_calls(&when.condition, function_name, out);
                collect_function_calls(&when.result, function_name, out);
            }
            if let Some(else_expr) = else_result.as_deref() {
                collect_function_calls(else_expr, function_name, out);
            }
        }
        Expr::Like { expr, pattern, .. }
        | Expr::ILike { expr, pattern, .. }
        | Expr::SimilarTo { expr, pattern, .. }
        | Expr::RLike { expr, pattern, .. } => {
            collect_function_calls(expr, function_name, out);
            collect_function_calls(pattern, function_name, out);
        }
        Expr::Tuple(items) => {
            for item in items {
                collect_function_calls(item, function_name, out);
            }
        }
        _ => {}
    }
}

fn collect_function_calls_in_query<'a>(
    query: &'a Query,
    function_name: &str,
    out: &mut Vec<&'a Function>,
) {
    collect_function_calls_in_set_expr(query.body.as_ref(), function_name, out);
}

fn collect_function_calls_in_set_expr<'a>(
    set_expr: &'a SetExpr,
    function_name: &str,
    out: &mut Vec<&'a Function>,
) {
    match set_expr {
        SetExpr::Select(select) => {
            for item in &select.projection {
                match item {
                    SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. } => {
                        collect_function_calls(expr, function_name, out);
                    }
                    _ => {}
                }
            }
            if let Some(selection) = &select.selection {
                collect_function_calls(selection, function_name, out);
            }
            if let Some(having) = &select.having {
                collect_function_calls(having, function_name, out);
            }
        }
        SetExpr::SetOperation { left, right, .. } => {
            collect_function_calls_in_set_expr(left, function_name, out);
            collect_function_calls_in_set_expr(right, function_name, out);
        }
        SetExpr::Query(query) => collect_function_calls_in_query(query, function_name, out),
        _ => {}
    }
}

fn positional_function_arg(function: &Function, index: usize) -> Option<&Expr> {
    let FunctionArguments::List(arg_list) = &function.args else {
        return None;
    };
    let arg = arg_list.args.get(index)?;
    function_arg_expr(arg)
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

/// Populate `TupleSource` entries on `table_plan` (and `all_types` for team
/// membership) for the P1/P2 role-threshold patterns.  Called once per unique
/// `(source_table, function_name)` pair; the renderer deduplicates via
/// [`TupleSource::dedup_key`].
#[allow(clippy::too_many_arguments)]
fn populate_role_threshold_sources(
    function_name: &str,
    source_table: &str,
    db: &ParserDB,
    registry: &FunctionRegistry,
    hints: &RoleThresholdResourceHints,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<String, TypePlan>,
) {
    let Some(FunctionSemantic::RoleThreshold {
        grant_table,
        grant_grantee_col,
        grant_resource_col,
        grant_role_col,
        team_membership_table,
        team_membership_user_col,
        team_membership_team_col,
        user_table,
        user_pk_col,
        team_table,
        team_pk_col,
        role_levels,
        ..
    }) = registry.get(function_name)
    else {
        return; // error already emitted in the pattern arm
    };

    let has_team = team_membership_table.is_some();
    let owner_col = resolve_owner_column(source_table, db);
    let pk_col = resolve_pk_column(source_table, db);

    let user_principal = resolve_principal_info(
        db,
        user_table.as_deref(),
        user_pk_col.as_deref(),
        &["users", "user"],
    );
    let team_principal = if has_team {
        resolve_principal_info(
            db,
            team_table.as_deref(),
            team_pk_col.as_deref(),
            &["teams", "team"],
        )
    } else {
        None
    };

    // --- Ownership sources ---
    match (&owner_col, &pk_col) {
        (Some(oc), Some(pk)) => {
            if let Some(upi) = user_principal.clone() {
                table_plan.add_source(TupleSource::RoleOwnerUser {
                    table: source_table.to_string(),
                    pk_col: pk.clone(),
                    owner_col: oc.clone(),
                    user_table: upi.table,
                    user_pk_col: upi.pk_col,
                });
            } else {
                table_plan.add_source(TupleSource::Todo {
                    level: ConfidenceLevel::D,
                    comment: format!(
                        "-- TODO [Level D]: skipped user ownership tuples for {source_table} (unresolved user principal table)"
                    ),
                    sql: "-- User ownership tuples not emitted; add role_threshold.user_table metadata or users table.".to_string(),
                });
            }
            if has_team {
                if let Some(tpi) = team_principal.clone() {
                    table_plan.add_source(TupleSource::RoleOwnerTeam {
                        table: source_table.to_string(),
                        pk_col: pk.clone(),
                        owner_col: oc.clone(),
                        team_table: tpi.table,
                        team_pk_col: tpi.pk_col,
                    });
                } else {
                    table_plan.add_source(TupleSource::Todo {
                        level: ConfidenceLevel::D,
                        comment: format!(
                            "-- TODO [Level D]: skipped team ownership tuples for {source_table} (unresolved team principal table)"
                        ),
                        sql: "-- Team ownership tuples not emitted; add role_threshold.team_table metadata or teams table.".to_string(),
                    });
                }
            }
        }
        _ => {
            table_plan.add_source(TupleSource::Todo {
                level: ConfidenceLevel::D,
                comment: format!(
                    "-- TODO [Level D]: skipped ownership tuples for {source_table} (no owner-like column/FK found)"
                ),
                sql: "-- Ownership tuples not emitted; review owner mapping.".to_string(),
            });
        }
    }

    // --- Team membership ---
    // Add to table_plan first so the membership source appears in the correct position
    // in the IR renderer (between team-ownership and explicit-grants, matching the old
    // generate_tuple_queries ordering).  Also add to all_types["team"] for semantic
    // correctness; the renderer deduplicates via dedup_key so it is only emitted once.
    if let (Some(tm_table), Some(tm_user), Some(tm_team)) = (
        team_membership_table,
        team_membership_user_col,
        team_membership_team_col,
    ) {
        let membership_source = TupleSource::TeamMembership {
            membership_table: tm_table.clone(),
            team_col: tm_team.clone(),
            user_col: tm_user.clone(),
        };
        table_plan.add_source(membership_source.clone());
        all_types
            .entry("team".to_string())
            .or_insert_with(|| TypePlan::new("team"))
            .add_source(membership_source);
    }

    // --- Explicit grants ---
    let hint_key = (source_table.to_string(), function_name.to_string());
    if hints.conflicts.contains(&hint_key) {
        add_explicit_grants_todo(
            table_plan,
            source_table,
            "conflicting resource join columns inferred from policies",
            "-- Grant tuples not emitted; align resource arguments for role-threshold calls across policies.",
        );
        return;
    }

    let grant_join_col = hints
        .columns
        .get(&hint_key)
        .map(String::as_str)
        .or(owner_col.as_deref());

    let Some(grant_join_col) = grant_join_col else {
        add_explicit_grants_todo(
            table_plan,
            source_table,
            "missing resource join column",
            "-- Grant tuples not emitted; add function metadata or owner FK.",
        );
        return;
    };

    let Some(object_pk) = pk_col else {
        add_missing_object_identifier_todo(table_plan, source_table, "explicit grant tuples");
        return;
    };

    let sorted_roles = sorted_role_relation_names(role_levels);
    if sorted_roles.is_empty() {
        return;
    }

    // Deduplicate by integer level: two role names at the same level produce
    // duplicate WHEN arms in the generated CASE expression (second is unreachable).
    // Keep only the first occurrence of each level (sorted by (level, name)).
    let mut seen_levels = std::collections::HashSet::new();
    let role_cases: Vec<(i32, String, String)> = sorted_roles
        .iter()
        .filter(|role| seen_levels.insert(role.level))
        .map(|role| {
            (
                role.level,
                role.grant_relation(),
                role.original_name.clone(),
            )
        })
        .collect();

    table_plan.add_source(TupleSource::ExplicitGrants {
        table: source_table.to_string(),
        pk_col: object_pk,
        grant_join_col: grant_join_col.to_string(),
        grant_table: grant_table.clone(),
        grant_role_col: grant_role_col.clone(),
        grant_grantee_col: grant_grantee_col.clone(),
        grant_resource_col: grant_resource_col.clone(),
        role_cases,
        user_principal,
        team_principal,
    });
}

fn render_dsl(types: &[TypePlan]) -> String {
    let mut dsl = String::new();
    writeln!(dsl, "model").unwrap();
    writeln!(dsl, "  schema 1.1").unwrap();

    for t in types {
        writeln!(dsl).unwrap();
        writeln!(dsl, "type {}", t.type_name).unwrap();

        if t.direct_relations.is_empty() && t.computed_relations.is_empty() {
            continue;
        }

        writeln!(dsl, "  relations").unwrap();
        for (relation, subjects) in &t.direct_relations {
            writeln!(dsl, "    define {relation}: {}", format_subjects(subjects)).unwrap();
        }
        for (relation, expr) in &t.computed_relations {
            writeln!(dsl, "    define {relation}: {}", expr_to_dsl(expr, 0)).unwrap();
        }
    }

    dsl
}

fn format_subjects(subjects: &[DirectSubject]) -> String {
    let parts = subjects
        .iter()
        .map(|s| match s {
            DirectSubject::Type(t) => t.clone(),
            DirectSubject::Wildcard(t) => format!("{t}:*"),
        })
        .collect::<Vec<_>>();
    format!("[{}]", parts.join(", "))
}

fn expr_to_dsl(expr: &UsersetExpr, parent_precedence: u8) -> String {
    // 0 = top, 1 = OR, 2 = AND, 3 = atom
    match expr {
        UsersetExpr::Computed(name) => name.clone(),
        UsersetExpr::TupleToUserset { tupleset, computed } => {
            format!("{computed} from {tupleset}")
        }
        UsersetExpr::Union(children) => {
            let rendered = children
                .iter()
                .map(|c| expr_to_dsl(c, 1))
                .collect::<Vec<_>>()
                .join(" or ");
            if parent_precedence > 1 {
                format!("({rendered})")
            } else {
                rendered
            }
        }
        UsersetExpr::Intersection(children) => {
            let rendered = children
                .iter()
                .map(|c| expr_to_dsl(c, 2))
                .collect::<Vec<_>>()
                .join(" and ");
            if parent_precedence > 2 {
                format!("({rendered})")
            } else {
                rendered
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::sql_parser::{parse_schema, DatabaseLike};

    fn role_registry(role_levels: &str, include_team: bool) -> FunctionRegistry {
        let mut registry = FunctionRegistry::new();
        let team_fields = if include_team {
            r#",
    "team_membership_table": "team_memberships",
    "team_membership_user_col": "user_id",
    "team_membership_team_col": "team_id""#
        } else {
            ""
        };
        let json = format!(
            r#"{{
  "role_level": {{
    "kind": "role_threshold",
    "user_param_index": 0,
    "resource_param_index": 1,
    "role_levels": {role_levels},
    "grant_table": "object_grants",
    "grant_grantee_col": "grantee_id",
    "grant_resource_col": "resource_id",
    "grant_role_col": "role_level"{team_fields}
  }}
}}"#
        );
        registry
            .load_from_json(&json)
            .expect("registry json should parse");
        registry
    }

    fn docs_db_with_policy(policy_sql: &str) -> ParserDB {
        let sql = format!(
            "
CREATE TABLE docs(id uuid primary key, owner_id uuid, status text);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
{policy_sql}
"
        );
        parse_schema(&sql).expect("schema should parse")
    }

    fn classified_from_policy(
        policy: sqlparser::ast::CreatePolicy,
        using: Option<PatternClass>,
        with_check: Option<PatternClass>,
    ) -> ClassifiedPolicy {
        ClassifiedPolicy {
            policy,
            using_classification: using.map(|pattern| ClassifiedExpr {
                pattern,
                confidence: ConfidenceLevel::A,
            }),
            with_check_classification: with_check.map(|pattern| ClassifiedExpr {
                pattern,
                confidence: ConfidenceLevel::A,
            }),
            using_was_filtered: false,
            with_check_was_filtered: false,
        }
    }

    #[test]
    fn compose_action_with_only_restrictive_rules_maps_to_no_access() {
        let mut plan = TypePlan::new("docs");
        let bucket = ModeBuckets {
            permissive: Vec::new(),
            restrictive: vec![UsersetExpr::Computed("owner".to_string())],
        };

        let expr = compose_action(&mut plan, Some(&bucket)).expect("expected expression");
        assert_eq!(expr, UsersetExpr::Computed("no_access".to_string()));
        assert!(
            plan.direct_relations.contains_key("no_access"),
            "restrictive-only rules should synthesize no_access"
        );
    }

    #[test]
    fn pattern_to_expr_handles_missing_or_invalid_role_threshold_metadata() {
        let empty_registry = FunctionRegistry::new();
        let mut table_plan = TypePlan::new("docs");
        let mut all_types = BTreeMap::new();
        let mut todos = Vec::new();

        let p1 = PatternClass::P1NumericThreshold {
            function_name: "missing_fn".to_string(),
            operator: ThresholdOperator::Gte,
            threshold: 2,
            command: PolicyCommand::Select,
        };
        let p2 = PatternClass::P2RoleNameInList {
            function_name: "missing_fn".to_string(),
            role_names: vec!["viewer".to_string()],
        };

        let p1_expr = pattern_to_expr(
            &p1,
            "p1",
            &mut table_plan,
            &mut all_types,
            &empty_registry,
            &mut todos,
        );
        let p2_expr = pattern_to_expr(
            &p2,
            "p2",
            &mut table_plan,
            &mut all_types,
            &empty_registry,
            &mut todos,
        );

        assert_eq!(p1_expr, UsersetExpr::Computed("no_access".to_string()));
        assert_eq!(p2_expr, UsersetExpr::Computed("no_access".to_string()));
        assert_eq!(todos.len(), 2);
        assert!(todos[0].message.contains("missing semantic metadata"));
        assert!(todos[1].message.contains("missing semantic metadata"));
    }

    #[test]
    fn pattern_to_expr_handles_empty_role_selection_paths() {
        let registry = role_registry("{}", false);
        let mut table_plan = TypePlan::new("docs");
        let mut all_types = BTreeMap::new();
        let mut todos = Vec::new();

        let p2_non_numeric = PatternClass::P2RoleNameInList {
            function_name: "role_level".to_string(),
            role_names: vec!["viewer".to_string()],
        };
        let p2_numeric_without_levels = PatternClass::P2RoleNameInList {
            function_name: "role_level".to_string(),
            role_names: vec!["5".to_string()],
        };

        let first = pattern_to_expr(
            &p2_non_numeric,
            "p2_non_numeric",
            &mut table_plan,
            &mut all_types,
            &registry,
            &mut todos,
        );
        let second = pattern_to_expr(
            &p2_numeric_without_levels,
            "p2_numeric",
            &mut table_plan,
            &mut all_types,
            &registry,
            &mut todos,
        );

        assert_eq!(first, UsersetExpr::Computed("no_access".to_string()));
        assert_eq!(second, UsersetExpr::Computed("no_access".to_string()));
    }

    #[test]
    fn pattern_to_expr_covers_abac_composite_constant_and_unknown_branches() {
        let registry = FunctionRegistry::new();
        let mut table_plan = TypePlan::new("docs");
        let mut all_types = BTreeMap::new();
        let mut todos = Vec::new();

        let relationship = ClassifiedExpr {
            pattern: PatternClass::P3DirectOwnership {
                column: "owner_id".to_string(),
            },
            confidence: ConfidenceLevel::A,
        };
        let p7 = PatternClass::P7AbacAnd {
            relationship_part: Box::new(relationship.clone()),
            attribute_part: "status".to_string(),
        };
        let p8_or_empty = PatternClass::P8Composite {
            op: BoolOp::Or,
            parts: Vec::new(),
        };
        let p8_and_empty = PatternClass::P8Composite {
            op: BoolOp::And,
            parts: Vec::new(),
        };
        let p9 = PatternClass::P9AttributeCondition {
            column: "status".to_string(),
            value_description: "'published'".to_string(),
        };
        let p8_and_attr_true = PatternClass::P8Composite {
            op: BoolOp::And,
            parts: vec![
                ClassifiedExpr {
                    pattern: p9.clone(),
                    confidence: ConfidenceLevel::C,
                },
                ClassifiedExpr {
                    pattern: PatternClass::P10ConstantBool { value: true },
                    confidence: ConfidenceLevel::A,
                },
            ],
        };
        let p10_false = PatternClass::P10ConstantBool { value: false };
        let p5 = PatternClass::P5ParentInheritance {
            parent_table: "projects".to_string(),
            fk_column: "project_id".to_string(),
            inner_pattern: Box::new(relationship),
        };
        let unknown = PatternClass::Unknown {
            sql_text: "mystery()".to_string(),
            reason: "no recognizer".to_string(),
        };

        let p7_expr = pattern_to_expr(
            &p7,
            "p7",
            &mut table_plan,
            &mut all_types,
            &registry,
            &mut todos,
        );
        let p8_or_expr = pattern_to_expr(
            &p8_or_empty,
            "p8_or",
            &mut table_plan,
            &mut all_types,
            &registry,
            &mut todos,
        );
        let p8_and_expr = pattern_to_expr(
            &p8_and_empty,
            "p8_and",
            &mut table_plan,
            &mut all_types,
            &registry,
            &mut todos,
        );
        let p10_expr = pattern_to_expr(
            &p10_false,
            "p10",
            &mut table_plan,
            &mut all_types,
            &registry,
            &mut todos,
        );
        let p9_expr = pattern_to_expr(
            &p9,
            "p9",
            &mut table_plan,
            &mut all_types,
            &registry,
            &mut todos,
        );
        let p8_and_attr_true_expr = pattern_to_expr(
            &p8_and_attr_true,
            "p8_and_attr_true",
            &mut table_plan,
            &mut all_types,
            &registry,
            &mut todos,
        );
        let p5_expr = pattern_to_expr(
            &p5,
            "p5",
            &mut table_plan,
            &mut all_types,
            &registry,
            &mut todos,
        );
        let unknown_expr = pattern_to_expr(
            &unknown,
            "unknown",
            &mut table_plan,
            &mut all_types,
            &registry,
            &mut todos,
        );

        assert_eq!(p7_expr, UsersetExpr::Computed("owner".to_string()));
        assert_eq!(p8_or_expr, UsersetExpr::Computed("no_access".to_string()));
        assert_eq!(p8_and_expr, UsersetExpr::Computed("no_access".to_string()));
        assert_eq!(p10_expr, UsersetExpr::Computed("no_access".to_string()));
        assert_eq!(p9_expr, UsersetExpr::Computed("no_access".to_string()));
        assert!(
            matches!(
                &p8_and_attr_true_expr,
                UsersetExpr::Computed(name) if name == "no_access"
            ) || matches!(
                &p8_and_attr_true_expr,
                UsersetExpr::Intersection(children)
                    if children
                        .iter()
                        .any(|child| matches!(child, UsersetExpr::Computed(name) if name == "no_access"))
            ),
            "attribute + constant-true composite should remain deny-biased, got: {p8_and_attr_true_expr:?}"
        );
        assert_eq!(
            p5_expr,
            UsersetExpr::TupleToUserset {
                tupleset: "projects".to_string(),
                computed: "can_select".to_string(),
            }
        );
        assert_eq!(unknown_expr, UsersetExpr::Computed("no_access".to_string()));
        assert!(table_plan.direct_relations.contains_key("projects"));
        assert!(todos
            .iter()
            .any(|t| t.message.contains("still requires runtime enforcement")));
        assert!(todos
            .iter()
            .any(|t| t.message.contains("mapped to no_access for safety")));
        assert!(todos
            .iter()
            .any(|t| t.message.contains("could not be safely translated")));
    }

    #[test]
    fn build_schema_plan_adds_todos_for_non_public_to_and_empty_translation() {
        let db = docs_db_with_policy(
            "CREATE POLICY docs_select ON docs FOR SELECT TO app_user USING (TRUE);",
        );
        let policy = db.policies().next().expect("policy should exist").clone();
        let classified = classified_from_policy(
            policy,
            Some(PatternClass::Unknown {
                sql_text: "TRUE".to_string(),
                reason: "not supported".to_string(),
            }),
            None,
        );
        let registry = FunctionRegistry::new();
        let plan = build_schema_plan(&[classified], &db, &registry);

        assert!(plan
            .todos
            .iter()
            .any(|t| t.message.contains("Policy role scope TO")));
        assert!(plan.todos.iter().any(|t| t
            .message
            .contains("Expression could not be safely translated")));
        assert!(plan
            .todos
            .iter()
            .any(|t| t.message.contains("not supported")));
    }

    #[test]
    fn build_schema_plan_models_non_public_scope_via_pg_role() {
        let db = docs_db_with_policy(
            "CREATE POLICY docs_select ON docs FOR SELECT TO app_user USING (owner_id = current_user);",
        );
        let policy = db.policies().next().expect("policy should exist").clone();
        let scope_relation = policy_scope_relation_name("docs_select");
        let classified = classified_from_policy(
            policy,
            Some(PatternClass::P3DirectOwnership {
                column: "owner_id".to_string(),
            }),
            None,
        );
        let registry = FunctionRegistry::new();
        let plan = build_schema_plan(&[classified], &db, &registry);

        let docs = plan
            .types
            .iter()
            .find(|t| t.type_name == "docs")
            .expect("docs type should exist");
        assert!(docs.direct_relations.contains_key(&scope_relation));
        assert!(matches!(
            docs.computed_relations.get("can_select"),
            Some(UsersetExpr::Intersection(children))
                if children.iter().any(|c| matches!(c, UsersetExpr::Computed(name) if name == "owner"))
                    && children.iter().any(|c| matches!(
                        c,
                        UsersetExpr::TupleToUserset { tupleset, computed }
                            if tupleset == &scope_relation && computed == "member"
                    ))
        ));

        let pg_role = plan
            .types
            .iter()
            .find(|t| t.type_name == "pg_role")
            .expect("pg_role type should exist");
        assert!(matches!(
            pg_role.direct_relations.get("member"),
            Some(subjects) if subjects == &vec![DirectSubject::Type("user".to_string())]
        ));
    }

    #[test]
    fn build_schema_plan_mirrors_update_check_when_only_with_check_is_present() {
        let db = docs_db_with_policy(
            "CREATE POLICY docs_update ON docs FOR UPDATE WITH CHECK (owner_id = current_user);",
        );
        let policy = db.policies().next().expect("policy should exist").clone();
        let classified = classified_from_policy(
            policy,
            None,
            Some(PatternClass::P3DirectOwnership {
                column: "owner_id".to_string(),
            }),
        );
        let registry = FunctionRegistry::new();
        let plan = build_schema_plan(&[classified], &db, &registry);

        let docs = plan
            .types
            .iter()
            .find(|t| t.type_name == "docs")
            .expect("docs type should exist");
        assert!(
            docs.computed_relations.contains_key("can_update"),
            "update relation should be synthesized from WITH CHECK"
        );
    }

    #[test]
    fn exact_roles_expr_does_not_conflate_roles_at_same_level() {
        // `viewer=1` and `guest=1` share the same integer level.  Selecting only
        // `'viewer'` by name must NOT include `grant_guest`.
        let mut table_plan = TypePlan::new("docs");
        let mut all_types = BTreeMap::new();
        let role_levels = HashMap::from([
            ("viewer".to_string(), 1),
            ("guest".to_string(), 1),
            ("editor".to_string(), 2),
        ]);

        let sorted =
            ensure_role_threshold_scaffold(&mut table_plan, &mut all_types, &role_levels, false);

        // Select only "viewer" by name.
        let selected = BTreeSet::from(["viewer".to_string()]);
        let expr =
            exact_roles_expr(&sorted, &selected, false).expect("should produce an expression");

        // The expression must include grant_viewer.
        let contains_viewer = match &expr {
            UsersetExpr::Computed(n) => n == "grant_viewer",
            UsersetExpr::Union(children) => children
                .iter()
                .any(|c| matches!(c, UsersetExpr::Computed(n) if n == "grant_viewer")),
            _ => false,
        };
        assert!(contains_viewer, "grant_viewer must be included");

        // The expression must NOT include grant_guest.
        let contains_guest = match &expr {
            UsersetExpr::Computed(n) => n == "grant_guest",
            UsersetExpr::Union(children) => children
                .iter()
                .any(|c| matches!(c, UsersetExpr::Computed(n) if n == "grant_guest")),
            _ => false,
        };
        assert!(
            !contains_guest,
            "grant_guest must not be included when only 'viewer' was selected"
        );
    }

    #[test]
    fn ensure_role_threshold_scaffold_with_team_support_and_exact_roles_owner_inclusion() {
        let mut table_plan = TypePlan::new("docs");
        let mut all_types = BTreeMap::new();
        let role_levels = HashMap::from([
            ("viewer".to_string(), 1),
            ("editor".to_string(), 2),
            ("admin".to_string(), 3),
        ]);

        let sorted =
            ensure_role_threshold_scaffold(&mut table_plan, &mut all_types, &role_levels, true);
        assert!(table_plan.direct_relations.contains_key("owner_team"));
        assert!(table_plan.direct_relations.contains_key("grant_admin"));
        assert!(all_types.contains_key("team"));

        let selected = BTreeSet::from(["admin".to_string()]);
        let expr =
            exact_roles_expr(&sorted, &selected, true).expect("roles should produce expression");
        assert!(matches!(&expr, UsersetExpr::Union(children) if children
        .iter()
        .any(|c| matches!(c, UsersetExpr::Computed(name) if name == "owner_user"))
        && children.iter().any(|c| matches!(
            c,
            UsersetExpr::TupleToUserset { tupleset, computed }
                if tupleset == "owner_team" && computed == "member"
        ))));
    }

    #[test]
    fn ensure_role_threshold_scaffold_sanitizes_role_relation_names() {
        let mut table_plan = TypePlan::new("docs");
        let mut all_types = BTreeMap::new();
        let role_levels =
            HashMap::from([("read-write".to_string(), 1), ("Team Admin".to_string(), 2)]);

        ensure_role_threshold_scaffold(&mut table_plan, &mut all_types, &role_levels, false);

        assert!(
            table_plan.direct_relations.contains_key("grant_read_write"),
            "expected hyphenated role names to be canonicalized"
        );
        assert!(
            table_plan.direct_relations.contains_key("grant_team_admin"),
            "expected spaced/cased role names to be canonicalized"
        );
        assert!(
            table_plan
                .computed_relations
                .contains_key("role_read_write"),
            "expected computed role relation name to be canonicalized"
        );
    }

    #[test]
    fn ensure_role_threshold_scaffold_disambiguates_role_name_collisions() {
        let mut table_plan = TypePlan::new("docs");
        let mut all_types = BTreeMap::new();
        let role_levels = HashMap::from([("role-a".to_string(), 1), ("role a".to_string(), 2)]);

        ensure_role_threshold_scaffold(&mut table_plan, &mut all_types, &role_levels, false);

        let grant_relations: Vec<&String> = table_plan
            .direct_relations
            .keys()
            .filter(|name| name.starts_with("grant_role_a"))
            .collect();
        assert_eq!(
            grant_relations.len(),
            2,
            "canonical collisions must remain distinct relation identifiers"
        );
        assert_ne!(
            grant_relations[0], grant_relations[1],
            "colliding canonical names should be disambiguated"
        );
    }

    #[test]
    fn expr_to_dsl_adds_parentheses_when_required() {
        let union = UsersetExpr::Union(vec![
            UsersetExpr::Computed("a".to_string()),
            UsersetExpr::Computed("b".to_string()),
        ]);
        let intersection = UsersetExpr::Intersection(vec![
            UsersetExpr::Computed("x".to_string()),
            UsersetExpr::Computed("y".to_string()),
        ]);

        assert_eq!(expr_to_dsl(&union, 2), "(a or b)");
        assert_eq!(expr_to_dsl(&intersection, 3), "(x and y)");
    }

    #[test]
    fn combine_helpers_cover_empty_and_multi_intersection() {
        assert!(combine_union(Vec::new()).is_none());
        assert!(combine_intersection(Vec::new()).is_none());

        let inter = combine_intersection(vec![
            UsersetExpr::Computed("a".to_string()),
            UsersetExpr::Computed("b".to_string()),
        ])
        .expect("intersection should exist");
        assert!(matches!(inter, UsersetExpr::Intersection(children) if children.len() == 2));

        let mut plan = TypePlan::new("docs");
        let empty_bucket = ModeBuckets::default();
        assert!(compose_action(&mut plan, Some(&empty_bucket)).is_none());
    }

    #[test]
    fn build_schema_plan_skips_unknown_and_non_rls_tables() {
        let db = parse_schema(
            r"
CREATE TABLE docs(id uuid primary key, owner_id uuid);
CREATE TABLE rls_docs(id uuid primary key, owner_id uuid);
ALTER TABLE rls_docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON docs USING (owner_id = current_user);
CREATE POLICY rls_docs_select ON rls_docs USING (owner_id = current_user);
",
        )
        .expect("schema should parse");

        let mut policies = Vec::new();
        for policy in db.policies() {
            let classified = classified_from_policy(
                policy.clone(),
                Some(PatternClass::P3DirectOwnership {
                    column: "owner_id".to_string(),
                }),
                None,
            );
            if classified.name() == "docs_select" {
                let mut missing_table = classified.clone();
                missing_table.policy.table_name =
                    sqlparser::ast::ObjectName(vec![sqlparser::ast::ObjectNamePart::Identifier(
                        sqlparser::ast::Ident::new("ghost_docs"),
                    )]);
                policies.push(missing_table);
            }
            policies.push(classified);
        }

        let registry = FunctionRegistry::new();
        let plan = build_schema_plan(&policies, &db, &registry);
        assert!(
            plan.types.iter().any(|t| t.type_name == "rls_docs"),
            "RLS-enabled table should be translated"
        );
        assert!(
            !plan.types.iter().any(|t| t.type_name == "docs"),
            "non-RLS table should be skipped"
        );
    }

    #[test]
    fn build_schema_plan_adds_no_translatable_relations_todo() {
        let db = docs_db_with_policy(
            "CREATE POLICY docs_select ON docs FOR SELECT USING (owner_id = current_user);",
        );
        let policy = db.policies().next().expect("policy should exist").clone();
        let classified = classified_from_policy(policy, None, None);
        let registry = FunctionRegistry::new();

        let plan = build_schema_plan(&[classified], &db, &registry);
        assert!(plan
            .todos
            .iter()
            .any(|t| t.message.contains("No translatable relations generated")));
    }

    #[test]
    fn build_schema_plan_canonicalizes_schema_qualified_table_names() {
        let db = parse_schema(
            r"
CREATE TABLE app.docs(id uuid primary key, owner_id uuid);
ALTER TABLE app.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON app.docs FOR SELECT USING (owner_id = current_user);
",
        )
        .expect("schema should parse");

        let policy = db.policies().next().expect("policy should exist").clone();
        let classified = classified_from_policy(
            policy,
            Some(PatternClass::P3DirectOwnership {
                column: "owner_id".to_string(),
            }),
            None,
        );
        let registry = FunctionRegistry::new();
        let plan = build_schema_plan(&[classified], &db, &registry);

        assert!(
            plan.types.iter().any(|t| t.type_name == "docs"),
            "schema-qualified table name should canonicalize to relation name"
        );
        assert!(
            !plan.types.iter().any(|t| t.type_name == "app.docs"),
            "raw schema-qualified table name should not appear in output types"
        );
    }

    #[test]
    fn build_schema_plan_mirrors_update_using_when_with_check_absent() {
        let db = docs_db_with_policy(
            "CREATE POLICY docs_update ON docs FOR UPDATE USING (owner_id = current_user);",
        );
        let policy = db.policies().next().expect("policy should exist").clone();
        let classified = classified_from_policy(
            policy,
            Some(PatternClass::P3DirectOwnership {
                column: "owner_id".to_string(),
            }),
            None,
        );
        let registry = FunctionRegistry::new();
        let plan = build_schema_plan(&[classified], &db, &registry);

        let docs = plan
            .types
            .iter()
            .find(|t| t.type_name == "docs")
            .expect("docs type should exist");
        assert!(docs.computed_relations.contains_key("can_update"));
    }

    #[test]
    fn ensure_role_threshold_scaffold_sorts_ties_by_role_name() {
        let mut table_plan = TypePlan::new("docs");
        let mut all_types = BTreeMap::new();
        let role_levels = HashMap::from([
            ("beta".to_string(), 1),
            ("alpha".to_string(), 1),
            ("admin".to_string(), 2),
        ]);

        let sorted =
            ensure_role_threshold_scaffold(&mut table_plan, &mut all_types, &role_levels, false);
        let ordered: Vec<(String, i32)> = sorted
            .iter()
            .map(|role| (role.original_name.clone(), role.level))
            .collect();
        assert_eq!(
            ordered,
            vec![
                ("alpha".to_string(), 1),
                ("beta".to_string(), 1),
                ("admin".to_string(), 2),
            ]
        );
    }

    #[test]
    fn pattern_to_expr_handles_unreachable_thresholds_and_case_insensitive_role_names() {
        let registry = role_registry(r#"{"viewer": 1}"#, false);
        let mut table_plan = TypePlan::new("docs");
        let mut all_types = BTreeMap::new();
        let mut todos = Vec::new();

        let p1_unreachable = PatternClass::P1NumericThreshold {
            function_name: "role_level".to_string(),
            operator: ThresholdOperator::Gt,
            threshold: 10,
            command: PolicyCommand::Select,
        };
        let p2_mixed_case = PatternClass::P2RoleNameInList {
            function_name: "role_level".to_string(),
            role_names: vec!["VIEWER".to_string()],
        };

        let p1_expr = pattern_to_expr(
            &p1_unreachable,
            "p1_unreachable",
            &mut table_plan,
            &mut all_types,
            &registry,
            &mut todos,
        );
        let p2_expr = pattern_to_expr(
            &p2_mixed_case,
            "p2_case",
            &mut table_plan,
            &mut all_types,
            &registry,
            &mut todos,
        );

        assert_eq!(p1_expr, UsersetExpr::Computed("no_access".to_string()));
        assert!(
            matches!(p2_expr, UsersetExpr::Union(_) | UsersetExpr::Computed(_)),
            "case-insensitive role name matching should produce a translatable expression"
        );
    }

    #[test]
    fn role_registry_helper_covers_team_branch() {
        let registry = role_registry(r#"{"viewer": 1, "editor": 2}"#, true);
        assert!(matches!(
            registry.get("role_level"),
            Some(FunctionSemantic::RoleThreshold {
                team_membership_table: Some(_),
                team_membership_user_col: Some(_),
                team_membership_team_col: Some(_),
                ..
            })
        ));
    }

    #[test]
    fn action_target_helpers_cover_empty_arms() {
        assert!(using_targets(&PolicyCommand::Insert).is_empty());
        assert!(with_check_targets(&PolicyCommand::Select).is_empty());
        assert!(with_check_targets(&PolicyCommand::Delete).is_empty());
    }

    #[test]
    fn rewrite_p5_update_phases_promotes_phase_specific_parent_relations() {
        let mut all_types = BTreeMap::new();

        let mut parent = TypePlan::new("project");
        parent.set_computed(
            "can_update_using",
            UsersetExpr::Computed("owner".to_string()),
        );
        parent.set_computed(
            "can_update_check",
            UsersetExpr::Computed("editor".to_string()),
        );
        parent.set_computed(
            "can_update",
            UsersetExpr::Intersection(vec![
                UsersetExpr::Computed("can_update_using".to_string()),
                UsersetExpr::Computed("can_update_check".to_string()),
            ]),
        );
        all_types.insert("project".to_string(), parent);

        let mut child = TypePlan::new("task");
        child.ensure_direct("project", vec![DirectSubject::Type("project".to_string())]);
        child.set_computed(
            "can_update_using",
            UsersetExpr::TupleToUserset {
                tupleset: "project".to_string(),
                computed: "can_update".to_string(),
            },
        );
        child.set_computed(
            "can_update_check",
            UsersetExpr::TupleToUserset {
                tupleset: "project".to_string(),
                computed: "can_update".to_string(),
            },
        );
        all_types.insert("task".to_string(), child);

        rewrite_p5_update_phases(&mut all_types);

        let task = all_types.get("task").expect("task type should exist");
        assert!(matches!(
            task.computed_relations.get("can_update_using"),
            Some(UsersetExpr::TupleToUserset { computed, .. }) if computed == "can_update_using"
        ));
        assert!(matches!(
            task.computed_relations.get("can_update_check"),
            Some(UsersetExpr::TupleToUserset { computed, .. }) if computed == "can_update_check"
        ));
    }

    #[test]
    fn rewrite_p5_update_phases_keeps_can_update_when_parent_types_are_mixed() {
        let mut all_types = BTreeMap::new();

        let mut project = TypePlan::new("project");
        project.set_computed(
            "can_update_using",
            UsersetExpr::Computed("owner".to_string()),
        );
        all_types.insert("project".to_string(), project);

        let mut org = TypePlan::new("org");
        org.set_computed("can_update", UsersetExpr::Computed("admin".to_string()));
        all_types.insert("org".to_string(), org);

        let mut task = TypePlan::new("task");
        task.ensure_direct(
            "parent",
            vec![
                DirectSubject::Type("project".to_string()),
                DirectSubject::Type("org".to_string()),
            ],
        );
        task.set_computed(
            "can_update_using",
            UsersetExpr::TupleToUserset {
                tupleset: "parent".to_string(),
                computed: "can_update".to_string(),
            },
        );
        all_types.insert("task".to_string(), task);

        rewrite_p5_update_phases(&mut all_types);

        let task = all_types.get("task").expect("task type should exist");
        assert!(matches!(
            task.computed_relations.get("can_update_using"),
            Some(UsersetExpr::TupleToUserset { computed, .. }) if computed == "can_update"
        ));
    }

    #[test]
    fn confidence_filter_prevents_with_check_mirror_when_with_check_was_filtered() {
        // UPDATE policy: USING has high-confidence P3, WITH CHECK has low-confidence (would
        // normally be filtered).  After confidence filtering, with_check_was_filtered = true
        // → the USING→WITH CHECK mirror must NOT be applied.
        let db = docs_db_with_policy(
            "CREATE POLICY docs_upd ON docs FOR UPDATE \
             USING (owner_id = current_user) WITH CHECK (owner_id = current_user);",
        );
        let policy = db.policies().next().expect("policy should exist").clone();
        let p3 = PatternClass::P3DirectOwnership {
            column: "owner_id".to_string(),
        };
        // Construct a policy where WITH CHECK has low confidence (B) and USING has high (A).
        let mut classified = ClassifiedPolicy {
            policy,
            using_classification: Some(ClassifiedExpr {
                pattern: p3.clone(),
                confidence: ConfidenceLevel::A,
            }),
            with_check_classification: Some(ClassifiedExpr {
                pattern: p3.clone(),
                confidence: ConfidenceLevel::B,
            }),
            using_was_filtered: false,
            with_check_was_filtered: false,
        };
        // Filter at level A: WITH CHECK (B) gets filtered out → with_check_was_filtered = true.
        let filtered = filter_policies_for_output(&[classified.clone()], ConfidenceLevel::A);
        let filtered_cp = filtered.first().expect("USING should survive at A");
        assert!(
            filtered_cp.with_check_was_filtered,
            "with_check_was_filtered should be true after filtering"
        );
        assert!(
            filtered_cp.with_check_classification.is_none(),
            "with_check_classification should be None after filtering"
        );

        // Build a schema plan from the filtered policy.
        let registry = FunctionRegistry::new();
        let plan = build_schema_plan(std::slice::from_ref(filtered_cp), &db, &registry);
        let docs = plan
            .types
            .iter()
            .find(|t| t.type_name == "docs")
            .expect("docs type should exist");
        // USING survived → can_update_using should be defined.
        assert!(
            docs.computed_relations.contains_key("can_update"),
            "can_update relation should exist from USING expression"
        );
        // WITH CHECK was filtered, NOT mirrored → can_insert or can_update_check should NOT
        // exist (we don't mirror low-confidence USING into WITH CHECK slot).
        // For UPDATE the check target is can_update_check — it should be absent.
        assert!(
            !docs.computed_relations.contains_key("can_update_check"),
            "can_update_check must not be silently mirrored from USING when with_check was filtered; \
             relations present: {:?}",
            docs.computed_relations.keys().collect::<Vec<_>>()
        );
        // Now verify that when WITH CHECK is genuinely absent (not filtered), the mirror DOES apply.
        classified.with_check_classification = None; // never present
        classified.with_check_was_filtered = false;
        let plan2 = build_schema_plan(&[classified], &db, &registry);
        let docs2 = plan2
            .types
            .iter()
            .find(|t| t.type_name == "docs")
            .expect("docs type");
        assert!(
            docs2.computed_relations.contains_key("can_update"),
            "mirror should still apply when with_check was never present"
        );
    }
}

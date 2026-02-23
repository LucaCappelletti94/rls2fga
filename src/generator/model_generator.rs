use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write;

use sqlparser::ast::Owner;

use crate::classifier::function_registry::FunctionRegistry;
use crate::classifier::patterns::*;
use crate::parser::function_analyzer::FunctionSemantic;
use crate::parser::sql_parser::{DatabaseLike, ParserDB, TableLike};

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
}

impl TypePlan {
    fn new(type_name: impl Into<String>) -> Self {
        Self {
            type_name: type_name.into(),
            direct_relations: BTreeMap::new(),
            computed_relations: BTreeMap::new(),
        }
    }

    fn ensure_direct(&mut self, relation: impl Into<String>, subjects: Vec<DirectSubject>) {
        let relation = relation.into();
        self.direct_relations.entry(relation).or_insert(subjects);
    }

    fn ensure_computed(&mut self, relation: impl Into<String>, expr: UsersetExpr) {
        let relation = relation.into();
        self.computed_relations.entry(relation).or_insert(expr);
    }

    fn set_computed(&mut self, relation: impl Into<String>, expr: UsersetExpr) {
        self.computed_relations.insert(relation.into(), expr);
    }

    fn has_relations(&self) -> bool {
        !self.direct_relations.is_empty() || !self.computed_relations.is_empty()
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

/// Generate an ``OpenFGA`` model from classified policies.
pub fn generate_model(
    policies: &[ClassifiedPolicy],
    db: &ParserDB,
    registry: &FunctionRegistry,
    min_confidence: &ConfidenceLevel,
) -> GeneratedModel {
    let filtered = filter_policies_for_output(policies, *min_confidence);
    let plan = build_schema_plan(&filtered, db, registry);
    let dsl = render_dsl(&plan.types);

    GeneratedModel {
        dsl,
        todos: plan.todos,
        confidence_summary: plan.confidence_summary,
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

pub(crate) fn build_schema_plan(
    policies: &[ClassifiedPolicy],
    db: &ParserDB,
    registry: &FunctionRegistry,
) -> SchemaPlan {
    let mut all_types: BTreeMap<String, TypePlan> = BTreeMap::new();
    let mut todos = Vec::new();
    let mut confidence_summary = Vec::new();

    // Group policies by table
    let mut by_table: BTreeMap<String, Vec<&ClassifiedPolicy>> = BTreeMap::new();
    for cp in policies {
        by_table.entry(cp.table_name()).or_default().push(cp);
    }

    for (table_name, table_policies) in by_table {
        // Only generate resource types for RLS-enabled tables.
        let Some(table) = db.table(None, &table_name) else {
            continue;
        };
        if !table.has_row_level_security(db) {
            continue;
        }

        let mut table_plan = all_types
            .remove(&table_name)
            .unwrap_or_else(|| TypePlan::new(&table_name));

        let mut action_buckets: HashMap<ActionTarget, ModeBuckets> = HashMap::new();

        for cp in table_policies {
            if let Some(ref c) = cp.using_classification {
                confidence_summary.push((cp.name().to_string(), c.confidence));
            }
            if let Some(ref c) = cp.with_check_classification {
                confidence_summary.push((format!("{} (WITH CHECK)", cp.name()), c.confidence));
            }

            if let Some(to) = cp.policy.to.as_ref() {
                let only_public = to.len() == 1
                    && matches!(
                        &to[0],
                        Owner::Ident(i) if i.value.eq_ignore_ascii_case("public")
                    );
                if !only_public {
                    todos.push(TodoItem {
                        level: ConfidenceLevel::C,
                        policy_name: cp.name().to_string(),
                        message: format!(
                            "Policy role scope TO ({}) is not explicitly modeled in OpenFGA output",
                            to.iter()
                                .map(ToString::to_string)
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                    });
                }
            }

            let using_expr = cp.using_classification.as_ref().map(|c| {
                pattern_to_expr(
                    &c.pattern,
                    cp.name(),
                    &mut table_plan,
                    &mut all_types,
                    registry,
                    &mut todos,
                )
            });
            let mut with_check_expr = cp.with_check_classification.as_ref().map(|c| {
                pattern_to_expr(
                    &c.pattern,
                    cp.name(),
                    &mut table_plan,
                    &mut all_types,
                    registry,
                    &mut todos,
                )
            });

            // PostgreSQL behavior when WITH CHECK is absent for UPDATE/INSERT/ALL is often
            // interpreted as USING-equivalent gating for write paths.
            if with_check_expr.is_none()
                && matches!(
                    cp.command(),
                    PolicyCommand::All | PolicyCommand::Update | PolicyCommand::Insert
                )
            {
                with_check_expr.clone_from(&using_expr);
            }

            if let Some(expr) = using_expr.clone() {
                for target in using_targets(&cp.command()) {
                    push_action_expr(&mut action_buckets, target, cp.mode(), expr.clone());
                }
            }
            if let Some(expr) = with_check_expr.clone() {
                for target in with_check_targets(&cp.command()) {
                    push_action_expr(&mut action_buckets, target, cp.mode(), expr.clone());
                }
            }
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
                policy_name: table_name.clone(),
                message: format!("No translatable relations generated for table '{table_name}'"),
            });
        }

        all_types.insert(table_name.clone(), table_plan);
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
        (None, Some(_)) => {
            table_plan.ensure_direct("no_access", vec![DirectSubject::Type("user".to_string())]);
            Some(UsersetExpr::Computed("no_access".to_string()))
        }
        (None, None) => None,
    }
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

fn pattern_to_expr(
    pattern: &PatternClass,
    policy_name: &str,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<String, TypePlan>,
    registry: &FunctionRegistry,
    todos: &mut Vec<TodoItem>,
) -> UsersetExpr {
    match pattern {
        PatternClass::P1NumericThreshold {
            function_name,
            operator,
            threshold,
            ..
        } => {
            let Some(FunctionSemantic::RoleThreshold {
                role_levels,
                team_membership_table,
                ..
            }) = registry.get(function_name)
            else {
                table_plan
                    .ensure_direct("no_access", vec![DirectSubject::Type("user".to_string())]);
                todos.push(TodoItem {
                    level: ConfidenceLevel::D,
                    policy_name: policy_name.to_string(),
                    message: format!(
                        "Role-threshold function '{function_name}' missing semantic metadata"
                    ),
                });
                return UsersetExpr::Computed("no_access".to_string());
            };

            let sorted_roles = ensure_role_threshold_scaffold(
                table_plan,
                all_types,
                role_levels,
                team_membership_table.is_some(),
            );

            let min_level = match operator {
                ThresholdOperator::Gte => *threshold,
                ThresholdOperator::Gt => threshold.saturating_add(1),
            };

            if let Some(role_relation) = role_for_level(&sorted_roles, min_level) {
                UsersetExpr::Computed(role_relation)
            } else {
                table_plan
                    .ensure_direct("no_access", vec![DirectSubject::Type("user".to_string())]);
                UsersetExpr::Computed("no_access".to_string())
            }
        }
        PatternClass::P2RoleNameInList {
            function_name,
            role_names,
        } => {
            let Some(FunctionSemantic::RoleThreshold {
                role_levels,
                team_membership_table,
                ..
            }) = registry.get(function_name)
            else {
                table_plan
                    .ensure_direct("no_access", vec![DirectSubject::Type("user".to_string())]);
                todos.push(TodoItem {
                    level: ConfidenceLevel::D,
                    policy_name: policy_name.to_string(),
                    message: format!(
                        "Role-list function '{function_name}' missing semantic metadata"
                    ),
                });
                return UsersetExpr::Computed("no_access".to_string());
            };

            let sorted_roles = ensure_role_threshold_scaffold(
                table_plan,
                all_types,
                role_levels,
                team_membership_table.is_some(),
            );

            let mut selected_levels: BTreeSet<i32> = BTreeSet::new();
            for role in role_names {
                if let Ok(level) = role.parse::<i32>() {
                    selected_levels.insert(level);
                    continue;
                }
                if let Some(level) = role_levels
                    .iter()
                    .find_map(|(name, level)| name.eq_ignore_ascii_case(role).then_some(*level))
                {
                    selected_levels.insert(level);
                }
            }

            if selected_levels.is_empty() {
                table_plan
                    .ensure_direct("no_access", vec![DirectSubject::Type("user".to_string())]);
                return UsersetExpr::Computed("no_access".to_string());
            }

            if let Some(expr) = exact_roles_expr(
                &sorted_roles,
                &selected_levels,
                team_membership_table.is_some(),
            ) {
                expr
            } else {
                table_plan
                    .ensure_direct("no_access", vec![DirectSubject::Type("user".to_string())]);
                UsersetExpr::Computed("no_access".to_string())
            }
        }
        PatternClass::P3DirectOwnership { .. } => {
            table_plan.ensure_direct("owner", vec![DirectSubject::Type("user".to_string())]);
            UsersetExpr::Computed("owner".to_string())
        }
        PatternClass::P4ExistsMembership {
            fk_column,
            extra_predicate_sql,
            ..
        } => {
            let parent_type = fk_column
                .strip_suffix("_id")
                .unwrap_or(fk_column)
                .to_string();

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

            UsersetExpr::TupleToUserset {
                tupleset: parent_type,
                computed: "member".to_string(),
            }
        }
        PatternClass::P6BooleanFlag { .. } => {
            table_plan.ensure_direct(
                "public_viewer",
                vec![DirectSubject::Wildcard("user".to_string())],
            );
            UsersetExpr::Computed("public_viewer".to_string())
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
            pattern_to_expr(
                &relationship_part.pattern,
                policy_name,
                table_plan,
                all_types,
                registry,
                todos,
            )
        }
        PatternClass::P8Composite { op, parts } => {
            let mut child_exprs = Vec::new();
            for part in parts {
                child_exprs.push(pattern_to_expr(
                    &part.pattern,
                    policy_name,
                    table_plan,
                    all_types,
                    registry,
                    todos,
                ));
            }
            match op {
                BoolOp::Or => combine_union(child_exprs)
                    .unwrap_or_else(|| UsersetExpr::Computed("no_access".to_string())),
                BoolOp::And => combine_intersection(child_exprs)
                    .unwrap_or_else(|| UsersetExpr::Computed("no_access".to_string())),
            }
        }
        PatternClass::P9AttributeCondition { column, .. } => {
            todos.push(TodoItem {
                level: ConfidenceLevel::C,
                policy_name: policy_name.to_string(),
                message: format!(
                    "Standalone attribute policy on '{column}' mapped to placeholder public relation"
                ),
            });
            table_plan.ensure_direct(
                "public_viewer",
                vec![DirectSubject::Wildcard("user".to_string())],
            );
            UsersetExpr::Computed("public_viewer".to_string())
        }
        PatternClass::P10ConstantBool { value } => {
            if *value {
                table_plan.ensure_direct(
                    "public_viewer",
                    vec![DirectSubject::Wildcard("user".to_string())],
                );
                UsersetExpr::Computed("public_viewer".to_string())
            } else {
                table_plan
                    .ensure_direct("no_access", vec![DirectSubject::Type("user".to_string())]);
                UsersetExpr::Computed("no_access".to_string())
            }
        }
        PatternClass::P5ParentInheritance { .. } | PatternClass::Unknown { .. } => {
            table_plan.ensure_direct("no_access", vec![DirectSubject::Type("user".to_string())]);
            todos.push(TodoItem {
                level: ConfidenceLevel::D,
                policy_name: policy_name.to_string(),
                message: "Expression could not be safely translated; mapped to no_access"
                    .to_string(),
            });
            UsersetExpr::Computed("no_access".to_string())
        }
    }
}

fn ensure_member_type(all_types: &mut BTreeMap<String, TypePlan>, type_name: &str) {
    let entry = all_types
        .entry(type_name.to_string())
        .or_insert_with(|| TypePlan::new(type_name));
    entry.ensure_direct("member", vec![DirectSubject::Type("user".to_string())]);
}

fn ensure_role_threshold_scaffold(
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<String, TypePlan>,
    role_levels: &HashMap<String, i32>,
    has_team_support: bool,
) -> Vec<(String, i32)> {
    let mut sorted_roles: Vec<(String, i32)> = role_levels
        .iter()
        .map(|(name, level)| (name.clone(), *level))
        .collect();
    sorted_roles.sort_by(|(a_name, a_level), (b_name, b_level)| {
        a_level.cmp(b_level).then_with(|| a_name.cmp(b_name))
    });

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

    for (role_name, _) in &sorted_roles {
        table_plan.ensure_direct(format!("grant_{role_name}"), grant_subjects.clone());
    }

    let mut descending = sorted_roles.clone();
    descending.reverse();

    for (idx, (role_name, _)) in descending.iter().enumerate() {
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
            let higher_name = &descending[idx - 1].0;
            children.push(UsersetExpr::Computed(format!("role_{higher_name}")));
        }

        let grant_name = format!("grant_{role_name}");
        children.push(UsersetExpr::Computed(grant_name.clone()));
        if has_team_support {
            children.push(UsersetExpr::TupleToUserset {
                tupleset: grant_name,
                computed: "member".to_string(),
            });
        }

        table_plan.ensure_computed(
            format!("role_{role_name}"),
            combine_union(children).expect("role relation should always have at least one source"),
        );
    }

    sorted_roles
}

fn role_for_level(sorted_roles: &[(String, i32)], min_level: i32) -> Option<String> {
    sorted_roles
        .iter()
        .find(|(_, level)| *level >= min_level)
        .map(|(name, _)| format!("role_{name}"))
}

fn exact_roles_expr(
    sorted_roles: &[(String, i32)],
    selected_levels: &BTreeSet<i32>,
    has_team_support: bool,
) -> Option<UsersetExpr> {
    let mut children = Vec::new();

    for (role_name, role_level) in sorted_roles {
        if selected_levels.contains(role_level) {
            let grant_name = format!("grant_{role_name}");
            children.push(UsersetExpr::Computed(grant_name.clone()));
            if has_team_support {
                children.push(UsersetExpr::TupleToUserset {
                    tupleset: grant_name,
                    computed: "member".to_string(),
                });
            }
        }
    }

    if sorted_roles
        .iter()
        .map(|(_, level)| *level)
        .max()
        .is_some_and(|max| selected_levels.contains(&max))
    {
        children.push(UsersetExpr::Computed("owner_user".to_string()));
        if has_team_support {
            children.push(UsersetExpr::TupleToUserset {
                tupleset: "owner_team".to_string(),
                computed: "member".to_string(),
            });
        }
    }

    combine_union(children)
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
            format!("{tupleset}->{computed}")
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
        assert_eq!(p5_expr, UsersetExpr::Computed("no_access".to_string()));
        assert_eq!(unknown_expr, UsersetExpr::Computed("no_access".to_string()));
        assert!(todos
            .iter()
            .any(|t| t.message.contains("still requires runtime enforcement")));
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

        let selected = BTreeSet::from([3]);
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
        assert_eq!(
            sorted,
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
}

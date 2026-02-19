use std::collections::{BTreeMap, HashMap};
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
    _min_confidence: &ConfidenceLevel,
) -> GeneratedModel {
    let plan = build_schema_plan(policies, db, registry);
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
                with_check_expr = using_expr.clone();
            }

            for target in using_targets(&cp.command()) {
                if let Some(expr) = using_expr.clone() {
                    push_action_expr(&mut action_buckets, target, cp.mode(), expr);
                }
            }
            for target in with_check_targets(&cp.command()) {
                if let Some(expr) = with_check_expr.clone() {
                    push_action_expr(&mut action_buckets, target, cp.mode(), expr);
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

        // If only one UPDATE side exists, mirror it as PostgreSQL-compatible default.
        if update_using_expr.is_some() && update_check_expr.is_none() {
            update_check_expr = update_using_expr.clone();
        }
        if update_check_expr.is_some() && update_using_expr.is_none() {
            update_using_expr = update_check_expr.clone();
        }

        if let Some(expr) = select_expr.take() {
            table_plan.set_computed("can_select", expr);
        }
        if let Some(expr) = insert_expr.take() {
            table_plan.set_computed("can_insert", expr);
        }
        if let Some(expr) = delete_expr.take() {
            table_plan.set_computed("can_delete", expr);
        }

        match (update_using_expr.take(), update_check_expr.take()) {
            (Some(using_expr), Some(check_expr)) => {
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
            (Some(expr), None) | (None, Some(expr)) => {
                table_plan.set_computed("can_update", expr);
            }
            (None, None) => {}
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
        PolicyCommand::Select => vec![],
        PolicyCommand::Insert => vec![ActionTarget::Insert],
        PolicyCommand::Update => vec![ActionTarget::UpdateCheck],
        PolicyCommand::Delete => vec![],
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
    let Some(bucket) = bucket else {
        return None;
    };

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

            let mut selected_levels = Vec::new();
            for role in role_names {
                if let Ok(level) = role.parse::<i32>() {
                    selected_levels.push(level);
                    continue;
                }
                if let Some(level) = role_levels
                    .iter()
                    .find_map(|(name, level)| name.eq_ignore_ascii_case(role).then_some(*level))
                {
                    selected_levels.push(level);
                }
            }

            if selected_levels.is_empty() {
                table_plan
                    .ensure_direct("no_access", vec![DirectSubject::Type("user".to_string())]);
                return UsersetExpr::Computed("no_access".to_string());
            }

            let min_level = *selected_levels.iter().min().unwrap_or(&i32::MAX);
            if let Some(role_relation) = role_for_level(&sorted_roles, min_level) {
                UsersetExpr::Computed(role_relation)
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
        } else if let Some((higher_name, _)) = descending.get(idx - 1) {
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
            combine_union(children)
                .unwrap_or_else(|| UsersetExpr::Computed("no_access".to_string())),
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

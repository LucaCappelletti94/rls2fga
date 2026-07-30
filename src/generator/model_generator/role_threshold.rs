use super::*;

use crate::generator::db_lookup::{TEAM_PRINCIPAL_TABLES, USER_PRINCIPAL_TABLES};

// Infers which column each P1/P2 role-threshold call passes as its resource
// argument, so the tuple renderer knows the JOIN column without re-walking the AST.

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
    out: &mut BTreeMap<(String, String), String>,
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
        let Some(resource_col) = resource_cols.into_iter().next() else {
            continue;
        };

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
            | PatternClass::P11ArrayMembership { .. }
            | PatternClass::P12JsonbFieldOwnership { .. }
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

pub(super) fn extract_resource_columns_for_function(
    expr: &Expr,
    function_name: &str,
    resource_param_index: usize,
) -> BTreeSet<String> {
    use core::ops::ControlFlow;
    use sqlparser::ast::visit_expressions;

    let normalized = normalize_relation_name(function_name);
    let mut columns = BTreeSet::new();
    let _ = visit_expressions(expr, |e| {
        if let Expr::Function(f) = e {
            if crate::parser::names::normalized_function_name(f) == normalized {
                if let Some(arg) = positional_function_arg(f, resource_param_index) {
                    if let Some(col) = extract_column_name(arg) {
                        columns.insert(col);
                    }
                }
            }
        }
        ControlFlow::<()>::Continue(())
    });
    columns
}

pub(super) fn positional_function_arg(function: &Function, index: usize) -> Option<&Expr> {
    let FunctionArguments::List(arg_list) = &function.args else {
        return None;
    };
    let arg = arg_list.args.get(index)?;
    function_arg_expr(arg)
}
/// Populate `TupleSource` entries on `table_plan` (and `all_types` for team
/// membership) for the P1/P2 role-threshold patterns.  Called once per unique
/// `(source_table, function_name)` pair; the renderer deduplicates via
/// [`TupleSource::dedup_key`].
#[allow(clippy::too_many_arguments)]
pub(super) fn populate_role_threshold_sources(
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
        USER_PRINCIPAL_TABLES,
    );
    let team_principal = if has_team {
        resolve_principal_info(
            db,
            team_table.as_deref(),
            team_pk_col.as_deref(),
            TEAM_PRINCIPAL_TABLES,
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
    // generate_tuple_queries ordering).  Also add to the team type for semantic
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
            .entry(TEAM_TYPE.to_string())
            .or_insert_with(|| TypePlan::new(TEAM_TYPE))
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
        add_missing_object_identifier_todo(table_plan, source_table, "explicit grant tuples", db);
        return;
    };

    let sorted_roles = sorted_role_relation_names(role_levels);
    if sorted_roles.is_empty() {
        return;
    }

    // Deduplicate by integer level: two role names at the same level produce
    // duplicate WHEN arms in the generated CASE expression (second is unreachable).
    // Keep only the first occurrence of each level (sorted by (level, name)).
    let mut seen_levels = BTreeSet::new();
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

use crate::classifier::function_registry::FunctionRegistry;
use crate::classifier::patterns::*;
use crate::parser::expr::extract_column_name;
use crate::parser::function_analyzer::FunctionSemantic;
use crate::parser::names::{
    canonical_fga_type_name, is_owner_like_column_name, lookup_table, normalize_relation_name,
    parent_type_from_fk_column, policy_scope_relation_name, split_schema_and_relation,
};
use crate::parser::sql_parser::{ColumnLike, ForeignKeyLike, ParserDB, TableLike};
use sqlparser::ast::{
    Expr, Function, FunctionArg, FunctionArgExpr, FunctionArguments, Query, SelectItem, SetExpr,
};
use std::collections::{BTreeSet, HashMap};

/// A generated tuple query with its descriptive comment.
#[derive(Debug, Clone)]
pub struct TupleQuery {
    /// Human-readable SQL comment describing what this query populates.
    pub comment: String,
    /// SELECT statement that produces (object, relation, subject) triples.
    pub sql: String,
}

#[derive(Debug, Clone)]
struct PrincipalTable {
    table: String,
    pk_col: String,
}

#[derive(Debug, Clone, Default)]
struct RolePrincipalResolution {
    user: Option<PrincipalTable>,
    team: Option<PrincipalTable>,
}

#[derive(Debug, Clone, Default)]
struct RoleThresholdResourceHints {
    columns: HashMap<(String, String), String>,
    conflicts: BTreeSet<(String, String)>,
}

#[derive(Debug, Clone, Copy)]
struct RoleThresholdResourceJoin<'a> {
    column: Option<&'a str>,
    conflict: bool,
}

/// Format a list of tuple queries into a single SQL string.
pub fn format_tuples(tuples: &[TupleQuery]) -> String {
    let mut out = String::new();
    for query in tuples {
        out.push_str(&query.comment);
        out.push('\n');
        out.push_str(&query.sql);
        out.push_str("\n\n");
    }
    // Remove trailing newline to match snapshot expectations
    while out.ends_with('\n') {
        out.pop();
    }
    out
}

/// Generate tuple SQL queries from classified policies.
pub fn generate_tuple_queries(
    policies: &[ClassifiedPolicy],
    db: &ParserDB,
    registry: &FunctionRegistry,
) -> Vec<TupleQuery> {
    let mut queries = Vec::new();
    let role_threshold_resource_hints = infer_role_threshold_resource_columns(policies, registry);

    // Track which tuple types we've already generated to avoid duplicates
    let mut generated = std::collections::HashSet::new();

    for cp in policies {
        emit_policy_scope_tuples(cp, &cp.table_name(), db, &mut queries, &mut generated);
        for classified in cp.classifications() {
            generate_tuples_for_pattern(
                &classified.pattern,
                &cp.table_name(),
                db,
                registry,
                &role_threshold_resource_hints,
                &mut queries,
                &mut generated,
            );
        }
    }

    queries
}

fn emit_policy_scope_tuples(
    cp: &ClassifiedPolicy,
    table: &str,
    db: &ParserDB,
    queries: &mut Vec<TupleQuery>,
    generated: &mut std::collections::HashSet<String>,
) {
    let scoped_roles = cp.scoped_roles();
    if scoped_roles.is_empty() {
        return;
    }

    let table_type = canonical_fga_type_name(table);
    let object_col = find_object_column(table, db);
    let scope_relation = policy_scope_relation_name(cp.name());

    for role in scoped_roles {
        let role_id = canonical_fga_type_name(&role);
        let key = format!("scope:{table}:{scope_relation}:{role_id}");
        if !generated.insert(key) {
            continue;
        }
        queries.push(TupleQuery {
            comment: format!(
                "-- Policy scope: {table} rows require PostgreSQL role '{role}' via {scope_relation}"
            ),
            sql: format!(
                "SELECT '{table_type}:' || {object_col} AS object, '{scope_relation}' AS relation, 'pg_role:{role_id}' AS subject\nFROM {table}\nWHERE {object_col} IS NOT NULL;"
            ),
        });
    }
}

fn generate_tuples_for_pattern(
    pattern: &PatternClass,
    table: &str,
    db: &ParserDB,
    registry: &FunctionRegistry,
    role_threshold_resource_hints: &RoleThresholdResourceHints,
    queries: &mut Vec<TupleQuery>,
    generated: &mut std::collections::HashSet<String>,
) {
    let table_type = canonical_fga_type_name(table);

    match pattern {
        PatternClass::P1NumericThreshold { function_name, .. }
        | PatternClass::P2RoleNameInList { function_name, .. } => {
            let key = (table.to_string(), function_name.clone());
            let resource_join = RoleThresholdResourceJoin {
                column: role_threshold_resource_hints
                    .columns
                    .get(&key)
                    .map(String::as_str),
                conflict: role_threshold_resource_hints.conflicts.contains(&key),
            };

            generate_role_threshold_tuples_with_options(
                function_name,
                table,
                resource_join,
                db,
                registry,
                queries,
                generated,
            );
        }
        PatternClass::P3DirectOwnership { column } => {
            let key = format!("p3:{table}:{column}");
            if generated.insert(key) {
                let object_col = find_object_column(table, db);
                queries.push(TupleQuery {
                    comment: format!("-- User ownership ({column} references users)"),
                    sql: format!(
                        "SELECT '{table_type}:' || {object_col} AS object, 'owner' AS relation, 'user:' || {column} AS subject\nFROM {table}\nWHERE {column} IS NOT NULL;"
                    ),
                });
            }
        }
        PatternClass::P4ExistsMembership {
            join_table,
            fk_column,
            user_column,
            extra_predicate_sql,
        } => {
            let key = format!(
                "p4:{table}:{join_table}:{fk_column}:{user_column}:{}",
                extra_predicate_sql.as_deref().unwrap_or("")
            );
            if generated.insert(key) {
                let parent_type = parent_type_from_fk_column(fk_column);
                let where_clause = extra_predicate_sql
                    .as_ref()
                    .map(|e| format!("\nWHERE {e}"))
                    .unwrap_or_default();
                queries.push(TupleQuery {
                    comment: format!("-- {parent_type} membership from {join_table}"),
                    sql: format!(
                        "SELECT '{parent_type}:' || {fk_column} AS object, 'member' AS relation, 'user:' || {user_column} AS subject\nFROM {join_table}{where_clause};"
                    ),
                });
            }

            emit_bridge_tuple(table, fk_column, db, queries, generated, "p4_bridge");
        }
        PatternClass::P5ParentInheritance { fk_column, .. } => {
            emit_bridge_tuple(table, fk_column, db, queries, generated, "p5_bridge");
        }
        PatternClass::P6BooleanFlag { column } => {
            let key = format!("p6:{table}:{column}");
            if generated.insert(key) {
                let object_col = find_object_column(table, db);
                queries.push(TupleQuery {
                    comment: format!("-- Public access flag ({column})"),
                    sql: format!(
                        "SELECT '{table_type}:' || {object_col} AS object, 'public_viewer' AS relation, 'user:*' AS subject\nFROM {table}\nWHERE {column} = TRUE;"
                    ),
                });
            }
        }
        PatternClass::P8Composite { parts, .. } => {
            for part in parts {
                generate_tuples_for_pattern(
                    &part.pattern,
                    table,
                    db,
                    registry,
                    role_threshold_resource_hints,
                    queries,
                    generated,
                );
            }
        }
        PatternClass::P7AbacAnd {
            relationship_part, ..
        } => {
            generate_tuples_for_pattern(
                &relationship_part.pattern,
                table,
                db,
                registry,
                role_threshold_resource_hints,
                queries,
                generated,
            );
        }
        PatternClass::P10ConstantBool { value } => {
            let key = format!("p10:{table}:{value}");
            if generated.insert(key) && *value {
                let object_col = find_object_column(table, db);
                queries.push(TupleQuery {
                    comment: "-- Constant TRUE policy (all rows are visible)".to_string(),
                    sql: format!(
                        "SELECT '{table_type}:' || {object_col} AS object, 'public_viewer' AS relation, 'user:*' AS subject\nFROM {table};"
                    ),
                });
            }
        }
        _ => {}
    }
}

#[cfg(test)]
fn generate_role_threshold_tuples(
    function_name: &str,
    table: &str,
    resource_join_col: Option<&str>,
    db: &ParserDB,
    registry: &FunctionRegistry,
    queries: &mut Vec<TupleQuery>,
    generated: &mut std::collections::HashSet<String>,
) {
    generate_role_threshold_tuples_with_options(
        function_name,
        table,
        RoleThresholdResourceJoin {
            column: resource_join_col,
            conflict: false,
        },
        db,
        registry,
        queries,
        generated,
    );
}

fn generate_role_threshold_tuples_with_options(
    function_name: &str,
    table: &str,
    resource_join: RoleThresholdResourceJoin<'_>,
    db: &ParserDB,
    registry: &FunctionRegistry,
    queries: &mut Vec<TupleQuery>,
    generated: &mut std::collections::HashSet<String>,
) {
    let key = format!("role_threshold:{table}:{function_name}");
    if !generated.insert(key) {
        return;
    }

    let table_type = canonical_fga_type_name(table);

    if let Some(FunctionSemantic::RoleThreshold {
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
    {
        let principals = resolve_role_principals(
            db,
            user_table.as_deref(),
            user_pk_col.as_deref(),
            team_table.as_deref(),
            team_pk_col.as_deref(),
            team_membership_table.is_some(),
        );

        // Identify ownership and object columns.
        let owner_col = find_owner_column(table, db);
        let object_col = find_object_column(table, db);

        if let Some(owner_col) = owner_col.as_deref() {
            // 1. User ownership
            if let Some(user_principal) = principals.user.as_ref() {
                queries.push(TupleQuery {
                    comment: format!(
                        "-- User ownership ({owner_col} references {})",
                        user_principal.table
                    ),
                    sql: format!(
                        "SELECT '{table_type}:' || {object_col} AS object, 'owner_user' AS relation, 'user:' || {owner_col} AS subject\n\
                         FROM {table}\n\
                         WHERE {owner_col} IN (SELECT {} FROM {})\n\
                         AND {owner_col} IS NOT NULL;",
                        user_principal.pk_col, user_principal.table
                    ),
                });
            } else {
                queries.push(TupleQuery {
                    comment: format!(
                        "-- TODO [Level D]: skipped user ownership tuples for {table} (unresolved user principal table)"
                    ),
                    sql: "-- User ownership tuples not emitted; add role_threshold.user_table metadata or users table.".to_string(),
                });
            }

            // 2. Team ownership (if teams exist)
            if team_membership_table.is_some() {
                if let Some(team_principal) = principals.team.as_ref() {
                    queries.push(TupleQuery {
                        comment: format!(
                            "-- Team ownership ({owner_col} references {})",
                            team_principal.table
                        ),
                        sql: format!(
                            "SELECT '{table_type}:' || {object_col} AS object, 'owner_team' AS relation, 'team:' || {owner_col} AS subject\n\
                             FROM {table}\n\
                             WHERE {owner_col} IN (SELECT {} FROM {})\n\
                             AND {owner_col} IS NOT NULL;",
                            team_principal.pk_col, team_principal.table
                        ),
                    });
                } else {
                    queries.push(TupleQuery {
                        comment: format!(
                            "-- TODO [Level D]: skipped team ownership tuples for {table} (unresolved team principal table)"
                        ),
                        sql: "-- Team ownership tuples not emitted; add role_threshold.team_table metadata or teams table.".to_string(),
                    });
                }
            }
        } else {
            queries.push(TupleQuery {
                comment: format!(
                    "-- TODO [Level D]: skipped ownership tuples for {table} (no owner-like column/FK found)"
                ),
                sql: "-- Ownership tuples not emitted; review owner mapping.".to_string(),
            });
        }

        // 3. Team memberships
        if let (Some(tm_table), Some(tm_user), Some(tm_team)) = (
            team_membership_table,
            team_membership_user_col,
            team_membership_team_col,
        ) {
            let tm_key = format!("team_membership:{tm_table}");
            if generated.insert(tm_key) {
                queries.push(TupleQuery {
                    comment: "-- Team memberships".to_string(),
                    sql: format!(
                        "SELECT 'team:' || {tm_team} AS object, 'member' AS relation, 'user:' || {tm_user} AS subject\n\
                         FROM {tm_table};"
                    ),
                });
            }
        }

        // 4. Explicit grants
        let mut role_cases = Vec::new();
        let mut role_ids = Vec::new();
        let mut sorted_levels: Vec<(&String, &i32)> = role_levels.iter().collect();
        sorted_levels.sort_by_key(|(_, v)| *v);

        if sorted_levels.is_empty() {
            return;
        }

        if resource_join.conflict {
            queries.push(TupleQuery {
                comment: format!(
                    "-- TODO [Level D]: skipped explicit grants for {table} (conflicting resource join columns inferred from policies)"
                ),
                sql: "-- Grant tuples not emitted; align resource arguments for role-threshold calls across policies.".to_string(),
            });
            return;
        }

        let Some(grant_join_col) = resource_join.column.or(owner_col.as_deref()) else {
            queries.push(TupleQuery {
                comment: format!(
                    "-- TODO [Level D]: skipped explicit grants for {table} (missing resource join column)"
                ),
                sql: "-- Grant tuples not emitted; add function metadata or owner FK.".to_string(),
            });
            return;
        };

        for (role_name, role_id) in &sorted_levels {
            role_cases.push(format!("    WHEN {role_id} THEN 'grant_{role_name}'"));
            role_ids.push(role_id.to_string());
        }

        let case_expr = format!("CASE og.{grant_role_col}\n{}\n  END", role_cases.join("\n"));
        let mut subject_joins: Vec<String> = Vec::new();
        let subject_expr = match (principals.user.as_ref(), principals.team.as_ref()) {
            (Some(user_principal), Some(team_principal)) => {
                subject_joins.push(format!(
                    "LEFT JOIN {} u ON u.{} = og.{grant_grantee_col}",
                    user_principal.table, user_principal.pk_col
                ));
                subject_joins.push(format!(
                    "LEFT JOIN {} t ON t.{} = og.{grant_grantee_col}",
                    team_principal.table, team_principal.pk_col
                ));
                format!(
                    "CASE\n\
                     \x20   WHEN u.{} IS NOT NULL THEN 'user:' || og.{grant_grantee_col}\n\
                     \x20   WHEN t.{} IS NOT NULL THEN 'team:' || og.{grant_grantee_col}\n\
                     \x20   ELSE 'user:' || og.{grant_grantee_col}\n\
                     \x20 END",
                    user_principal.pk_col, team_principal.pk_col
                )
            }
            (Some(_) | None, None) => format!("'user:' || og.{grant_grantee_col}"),
            (None, Some(team_principal)) => {
                subject_joins.push(format!(
                    "LEFT JOIN {} t ON t.{} = og.{grant_grantee_col}",
                    team_principal.table, team_principal.pk_col
                ));
                format!(
                    "CASE\n\
                     \x20   WHEN t.{} IS NOT NULL THEN 'team:' || og.{grant_grantee_col}\n\
                     \x20   ELSE 'user:' || og.{grant_grantee_col}\n\
                     \x20 END",
                    team_principal.pk_col
                )
            }
        };

        let subject_join_sql = if subject_joins.is_empty() {
            String::new()
        } else {
            format!("{}\n", subject_joins.join("\n                 "))
        };

        queries.push(TupleQuery {
            comment: format!(
                "-- Explicit grants expanded to {table} rows ({}: {})",
                grant_role_col,
                sorted_levels
                    .iter()
                    .map(|(name, id)| format!("{id}={name}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            sql: format!(
                "SELECT\n\
                 \x20 '{table_type}:' || resource.{object_col} AS object,\n\
                 \x20 {case_expr} AS relation,\n\
                 \x20 {subject_expr} AS subject\n\
                 FROM {grant_table} og\n\
                 JOIN {table} resource ON resource.{grant_join_col} = og.{grant_resource_col}\n\
                 {subject_join_sql}\
                 WHERE og.{grant_role_col} IN ({});",
                role_ids.join(", ")
            ),
        });
    }
}

fn find_owner_column(table: &str, db: &ParserDB) -> Option<String> {
    if let Some(table_info) = lookup_table(db, table) {
        for col in table_info.columns(db) {
            let name = col.column_name();
            if is_owner_like_column_name(name) {
                return Some(name.to_string());
            }
        }
        // Check FK references to users/owners
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
    }
    None
}

fn resolve_object_column(table: &str, db: &ParserDB) -> Option<String> {
    let table_info = lookup_table(db, table)?;
    table_info
        .primary_key_column(db)
        .map(|c| c.column_name().to_string())
        .or_else(|| {
            table_info
                .columns(db)
                .find(|c| c.column_name() == "id")
                .map(|c| c.column_name().to_string())
        })
        .or_else(|| {
            table_info
                .columns(db)
                .next()
                .map(|c| c.column_name().to_string())
        })
}

fn find_object_column(table: &str, db: &ParserDB) -> String {
    resolve_object_column(table, db).unwrap_or_else(|| "id".to_string())
}

fn resolve_role_principals(
    db: &ParserDB,
    user_table: Option<&str>,
    user_pk_col: Option<&str>,
    team_table: Option<&str>,
    team_pk_col: Option<&str>,
    has_team_support: bool,
) -> RolePrincipalResolution {
    let user = resolve_principal_table(db, user_table, user_pk_col, &["users", "user"]);
    let team = if has_team_support {
        resolve_principal_table(db, team_table, team_pk_col, &["teams", "team"])
    } else {
        None
    };

    RolePrincipalResolution { user, team }
}

fn resolve_principal_table(
    db: &ParserDB,
    configured_table: Option<&str>,
    configured_pk_col: Option<&str>,
    fallback_table_candidates: &[&str],
) -> Option<PrincipalTable> {
    if let Some(table) = configured_table {
        let pk_col = if let Some(pk_col) = configured_pk_col {
            if !table_has_column(db, table, pk_col) {
                return None;
            }
            pk_col.to_string()
        } else {
            resolve_object_column(table, db)?
        };

        return Some(PrincipalTable {
            table: table.to_string(),
            pk_col,
        });
    }

    for table in fallback_table_candidates {
        if lookup_table(db, table).is_none() {
            continue;
        }
        if let Some(pk_col) = resolve_object_column(table, db) {
            return Some(PrincipalTable {
                table: (*table).to_string(),
                pk_col,
            });
        }
    }

    None
}

fn table_has_column(db: &ParserDB, table: &str, col: &str) -> bool {
    lookup_table(db, table)
        .is_some_and(|table_info| table_info.columns(db).any(|c| c.column_name() == col))
}

fn infer_role_threshold_resource_columns(
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

        let Some(resource_col) =
            extract_resource_column_for_function(expr, &key.1, resource_param_index)
        else {
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

fn extract_resource_column_for_function(
    expr: &Expr,
    function_name: &str,
    resource_param_index: usize,
) -> Option<String> {
    let function = find_function_call(expr, function_name)?;
    let arg_expr = positional_function_arg(function, resource_param_index)?;
    extract_column_name(arg_expr)
}

fn find_function_call<'a>(expr: &'a Expr, function_name: &str) -> Option<&'a Function> {
    match expr {
        Expr::Function(function)
            if normalize_relation_name(&function.name.to_string())
                == normalize_relation_name(function_name) =>
        {
            Some(function)
        }
        Expr::BinaryOp { left, right, .. } => find_function_call(left, function_name)
            .or_else(|| find_function_call(right, function_name)),
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
        | Expr::IsNotUnknown(expr) => find_function_call(expr, function_name),
        Expr::Nested(inner) => find_function_call(inner, function_name),
        Expr::Exists { subquery, .. } | Expr::Subquery(subquery) => {
            find_function_call_in_query(subquery, function_name)
        }
        Expr::InList { expr, list, .. } => find_function_call(expr, function_name).or_else(|| {
            list.iter()
                .find_map(|item| find_function_call(item, function_name))
        }),
        Expr::InUnnest {
            expr, array_expr, ..
        } => find_function_call(expr, function_name)
            .or_else(|| find_function_call(array_expr, function_name)),
        Expr::Between {
            expr, low, high, ..
        } => find_function_call(expr, function_name)
            .or_else(|| find_function_call(low, function_name))
            .or_else(|| find_function_call(high, function_name)),
        Expr::Case {
            operand,
            conditions,
            else_result,
            ..
        } => operand
            .as_deref()
            .and_then(|o| find_function_call(o, function_name))
            .or_else(|| {
                conditions.iter().find_map(|when| {
                    find_function_call(&when.condition, function_name)
                        .or_else(|| find_function_call(&when.result, function_name))
                })
            })
            .or_else(|| {
                else_result
                    .as_deref()
                    .and_then(|else_expr| find_function_call(else_expr, function_name))
            }),
        Expr::Like { expr, pattern, .. }
        | Expr::ILike { expr, pattern, .. }
        | Expr::SimilarTo { expr, pattern, .. }
        | Expr::RLike { expr, pattern, .. } => find_function_call(expr, function_name)
            .or_else(|| find_function_call(pattern, function_name)),
        Expr::IsDistinctFrom(left, right)
        | Expr::IsNotDistinctFrom(left, right)
        | Expr::AnyOp { left, right, .. }
        | Expr::AllOp { left, right, .. } => find_function_call(left, function_name)
            .or_else(|| find_function_call(right, function_name)),
        Expr::Tuple(items) => items
            .iter()
            .find_map(|item| find_function_call(item, function_name)),
        _ => None,
    }
}

fn find_function_call_in_query<'a>(query: &'a Query, function_name: &str) -> Option<&'a Function> {
    find_function_call_in_set_expr(query.body.as_ref(), function_name)
}

fn find_function_call_in_set_expr<'a>(
    set_expr: &'a SetExpr,
    function_name: &str,
) -> Option<&'a Function> {
    match set_expr {
        SetExpr::Select(select) => {
            for item in &select.projection {
                let found = match item {
                    SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. } => {
                        find_function_call(expr, function_name)
                    }
                    _ => None,
                };
                if found.is_some() {
                    return found;
                }
            }
            if let Some(selection) = &select.selection {
                return find_function_call(selection, function_name);
            }
            if let Some(having) = &select.having {
                return find_function_call(having, function_name);
            }
            None
        }
        SetExpr::SetOperation { left, right, .. } => {
            find_function_call_in_set_expr(left, function_name)
                .or_else(|| find_function_call_in_set_expr(right, function_name))
        }
        SetExpr::Query(query) => find_function_call_in_query(query, function_name),
        _ => None,
    }
}

fn positional_function_arg(function: &Function, index: usize) -> Option<&Expr> {
    let FunctionArguments::List(arg_list) = &function.args else {
        return None;
    };
    let arg = arg_list.args.get(index)?;

    match arg {
        FunctionArg::Unnamed(FunctionArgExpr::Expr(expr))
        | FunctionArg::Named {
            arg: FunctionArgExpr::Expr(expr),
            ..
        }
        | FunctionArg::ExprNamed {
            arg: FunctionArgExpr::Expr(expr),
            ..
        } => Some(expr),
        _ => None,
    }
}

fn resolve_bridge_columns(table: &str, fk_column: &str, db: &ParserDB) -> Option<(String, String)> {
    let table_info = lookup_table(db, table)?;
    let cols: Vec<String> = table_info
        .columns(db)
        .map(|c| c.column_name().to_string())
        .collect();

    let object_col = resolve_object_column(table, db)?;

    if cols.iter().any(|c| c == fk_column) {
        return Some((object_col, fk_column.to_string()));
    }

    if is_self_parent_bridge(table, fk_column) {
        return Some((object_col.clone(), object_col));
    }

    None
}

fn is_self_parent_bridge(table: &str, fk_column: &str) -> bool {
    let parent_type = fk_column.strip_suffix("_id").unwrap_or(fk_column);
    let relation = split_schema_and_relation(table)
        .map_or_else(|| table.to_string(), |(_, relation)| relation);
    let relation = relation.to_ascii_lowercase();
    let parent_type = parent_type.to_ascii_lowercase();
    singular_candidates(&relation)
        .iter()
        .any(|candidate| candidate == &parent_type)
}

fn singular_candidates(relation: &str) -> Vec<String> {
    let mut candidates = vec![relation.to_string()];

    if let Some(stem) = relation.strip_suffix("ies") {
        if !stem.is_empty() {
            candidates.push(format!("{stem}y"));
        }
    }
    if let Some(stem) = relation.strip_suffix("es") {
        if !stem.is_empty() {
            candidates.push(stem.to_string());
        }
    }
    if let Some(stem) = relation.strip_suffix('s') {
        if !stem.is_empty() {
            candidates.push(stem.to_string());
        }
    }

    candidates.sort();
    candidates.dedup();
    candidates
}

fn emit_bridge_tuple(
    table: &str,
    fk_column: &str,
    db: &ParserDB,
    queries: &mut Vec<TupleQuery>,
    generated: &mut std::collections::HashSet<String>,
    kind: &str,
) {
    let table_type = canonical_fga_type_name(table);
    let parent_type = parent_type_from_fk_column(fk_column);
    let bridge_key = format!("{kind}:{table}:{fk_column}:{parent_type}");
    if !generated.insert(bridge_key) {
        return;
    }
    let Some((object_col, parent_ref_col)) = resolve_bridge_columns(table, fk_column, db) else {
        queries.push(TupleQuery {
            comment: format!(
                "-- TODO [Level D]: skipped {table} to {parent_type} bridge (missing column '{fk_column}')"
            ),
            sql: "-- Bridge tuple not emitted; review schema/FK mapping.".to_string(),
        });
        return;
    };
    queries.push(TupleQuery {
        comment: format!("-- {table} to {parent_type} bridge for tuple-to-userset"),
        sql: format!(
            "SELECT '{table_type}:' || {object_col} AS object, '{parent_type}' AS relation, '{parent_type}:' || {parent_ref_col} AS subject\nFROM {table}\nWHERE {object_col} IS NOT NULL\nAND {parent_ref_col} IS NOT NULL;"
        ),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::sql_parser::{parse_schema, DatabaseLike};
    use sqlparser::dialect::PostgreSqlDialect;
    use sqlparser::parser::Parser;

    fn parse_expr(expr_sql: &str) -> Expr {
        Parser::new(&PostgreSqlDialect {})
            .try_with_sql(expr_sql)
            .expect("expression should parse")
            .parse_expr()
            .expect("expression should parse")
    }

    fn registry_with_role_threshold(team_support: bool) -> FunctionRegistry {
        let mut registry = FunctionRegistry::new();
        let team_fields = if team_support {
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
    "role_levels": {{"viewer": 1, "editor": 2}},
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

    fn db_with_resources() -> ParserDB {
        parse_schema(
            r"
CREATE TABLE users(id uuid primary key);
CREATE TABLE teams(id uuid primary key);
CREATE TABLE docs(id uuid primary key, owner_id uuid references users(id), project_id uuid);
CREATE TABLE doc_members(doc_id uuid, user_id uuid, role text);
CREATE TABLE object_grants(grantee_id uuid, resource_id uuid, role_level integer);
CREATE TABLE team_memberships(user_id uuid, team_id uuid);
CREATE TABLE project_links(resource_uuid uuid, project_uuid uuid);
",
        )
        .expect("schema should parse")
    }

    #[test]
    fn format_tuples_trims_trailing_newlines() {
        let tuples = vec![
            TupleQuery {
                comment: "-- one".to_string(),
                sql: "SELECT 1;".to_string(),
            },
            TupleQuery {
                comment: "-- two".to_string(),
                sql: "SELECT 2;".to_string(),
            },
        ];
        let formatted = format_tuples(&tuples);
        assert!(formatted.ends_with("SELECT 2;"));
        assert!(!formatted.ends_with('\n'));
    }

    #[test]
    fn generate_role_threshold_tuples_supports_team_membership_and_dedup() {
        let db = db_with_resources();
        let registry = registry_with_role_threshold(true);
        let mut queries = Vec::new();
        let mut generated = std::collections::HashSet::new();

        generate_role_threshold_tuples(
            "role_level",
            "docs",
            None,
            &db,
            &registry,
            &mut queries,
            &mut generated,
        );
        generate_role_threshold_tuples(
            "role_level",
            "docs",
            None,
            &db,
            &registry,
            &mut queries,
            &mut generated,
        );

        assert!(queries.iter().any(|q| q
            .comment
            .contains("User ownership (owner_id references users)")));
        assert!(queries.iter().any(|q| q
            .comment
            .contains("Team ownership (owner_id references teams)")));
        assert!(queries.iter().any(|q| q.comment == "-- Team memberships"));
        assert!(queries
            .iter()
            .any(|q| q.comment.contains("Explicit grants expanded to docs rows")));

        let team_membership_count = queries
            .iter()
            .filter(|q| q.comment == "-- Team memberships")
            .count();
        assert_eq!(
            team_membership_count, 1,
            "team membership tuples should be deduplicated"
        );
    }

    #[test]
    fn generate_role_threshold_tuples_ignores_unknown_function_semantics() {
        let db = db_with_resources();
        let registry = FunctionRegistry::new();
        let mut queries = Vec::new();
        let mut generated = std::collections::HashSet::new();

        generate_role_threshold_tuples(
            "unknown_role_fn",
            "docs",
            None,
            &db,
            &registry,
            &mut queries,
            &mut generated,
        );

        assert!(queries.is_empty());
    }

    #[test]
    fn find_owner_column_prefers_named_owner_then_fk_then_none() {
        let db = parse_schema(
            r"
CREATE TABLE users(id uuid primary key);
CREATE TABLE owners(id uuid primary key);
CREATE TABLE docs(id uuid primary key, owner_id uuid);
CREATE TABLE notes(id uuid primary key, owner_ref uuid references users(id));
CREATE TABLE posts(id uuid primary key, owner_ref uuid references owners(id));
",
        )
        .expect("schema should parse");

        assert_eq!(find_owner_column("docs", &db), Some("owner_id".to_string()));
        assert_eq!(
            find_owner_column("notes", &db),
            Some("owner_ref".to_string())
        );
        assert_eq!(
            find_owner_column("posts", &db),
            Some("owner_ref".to_string())
        );
        assert_eq!(find_owner_column("missing_table", &db), None);
    }

    #[test]
    fn generate_role_threshold_tuples_skips_team_memberships_when_columns_missing() {
        let db = db_with_resources();
        let mut registry = FunctionRegistry::new();
        registry
            .load_from_json(
                r#"{
  "role_level": {
    "kind": "role_threshold",
    "user_param_index": 0,
    "resource_param_index": 1,
    "role_levels": {"viewer": 1},
    "grant_table": "object_grants",
    "grant_grantee_col": "grantee_id",
    "grant_resource_col": "resource_id",
    "grant_role_col": "role_level",
    "team_membership_table": "team_memberships"
  }
}"#,
            )
            .expect("registry json should parse");

        let mut queries = Vec::new();
        let mut generated = std::collections::HashSet::new();
        generate_role_threshold_tuples(
            "role_level",
            "docs",
            None,
            &db,
            &registry,
            &mut queries,
            &mut generated,
        );

        assert!(!queries.iter().any(|q| q.comment == "-- Team memberships"));
    }

    #[test]
    fn resolve_bridge_columns_covers_safe_and_skip_paths() {
        let db = parse_schema(
            r"
CREATE TABLE docs(id uuid primary key, project_id uuid);
CREATE TABLE links(resource_uuid uuid, project_uuid uuid);
CREATE TABLE projects(id uuid primary key);
CREATE TABLE status(status uuid primary key);
CREATE TABLE events(label text, event_uuid uuid primary key, project_id uuid);
CREATE TABLE categories(id uuid primary key);
",
        )
        .expect("schema should parse");

        assert_eq!(resolve_bridge_columns("missing", "project_id", &db), None);
        assert_eq!(
            resolve_bridge_columns("docs", "project_id", &db),
            Some(("id".to_string(), "project_id".to_string()))
        );
        assert_eq!(
            resolve_bridge_columns("projects", "project_id", &db),
            Some(("id".to_string(), "id".to_string()))
        );
        assert_eq!(
            resolve_bridge_columns("status", "status_id", &db),
            Some(("status".to_string(), "status".to_string()))
        );
        assert_eq!(
            resolve_bridge_columns("events", "project_id", &db),
            Some(("event_uuid".to_string(), "project_id".to_string()))
        );
        assert_eq!(
            resolve_bridge_columns("categories", "category_id", &db),
            Some(("id".to_string(), "id".to_string()))
        );
        assert_eq!(resolve_bridge_columns("links", "project_id", &db), None);
    }

    #[test]
    fn emit_bridge_tuple_emits_todo_for_unsafe_missing_fk_column() {
        let db = parse_schema(
            r"
CREATE TABLE links(resource_uuid uuid, project_uuid uuid);
",
        )
        .expect("schema should parse");

        let mut queries = Vec::new();
        let mut generated = std::collections::HashSet::new();
        emit_bridge_tuple(
            "links",
            "project_id",
            &db,
            &mut queries,
            &mut generated,
            "p4_bridge",
        );

        assert!(
            queries.iter().any(|q| q
                .comment
                .contains("TODO [Level D]: skipped links to project bridge")),
            "expected TODO marker for skipped unsafe bridge, got: {queries:?}"
        );
    }

    #[test]
    fn emit_bridge_tuple_does_not_collapse_distinct_fk_columns() {
        let db = parse_schema(
            r"
CREATE TABLE tasks(
  id uuid primary key,
  source_project_id uuid,
  target_project_id uuid
);
",
        )
        .expect("schema should parse");

        let mut queries = Vec::new();
        let mut generated = std::collections::HashSet::new();
        emit_bridge_tuple(
            "tasks",
            "source_project_id",
            &db,
            &mut queries,
            &mut generated,
            "p5_bridge",
        );
        emit_bridge_tuple(
            "tasks",
            "target_project_id",
            &db,
            &mut queries,
            &mut generated,
            "p5_bridge",
        );

        let bridge_count = queries
            .iter()
            .filter(|q| q.comment.contains("bridge for tuple-to-userset"))
            .count();
        assert_eq!(
            bridge_count, 2,
            "distinct FK columns should each produce bridge tuples"
        );
    }

    #[test]
    fn generate_tuples_for_pattern_handles_p4_bridge_p7_p8_and_p10() {
        let db = db_with_resources();
        let registry = registry_with_role_threshold(false);
        let mut queries = Vec::new();
        let mut generated = std::collections::HashSet::new();
        let role_threshold_resource_hints = RoleThresholdResourceHints::default();

        let p4 = PatternClass::P4ExistsMembership {
            join_table: "doc_members".to_string(),
            fk_column: "project_id".to_string(),
            user_column: "user_id".to_string(),
            extra_predicate_sql: Some("doc_members.role = 'admin'".to_string()),
        };
        generate_tuples_for_pattern(
            &p4,
            "docs",
            &db,
            &registry,
            &role_threshold_resource_hints,
            &mut queries,
            &mut generated,
        );
        generate_tuples_for_pattern(
            &p4,
            "docs",
            &db,
            &registry,
            &role_threshold_resource_hints,
            &mut queries,
            &mut generated,
        );

        let p7 = PatternClass::P7AbacAnd {
            relationship_part: Box::new(ClassifiedExpr {
                pattern: PatternClass::P3DirectOwnership {
                    column: "owner_id".to_string(),
                },
                confidence: ConfidenceLevel::A,
            }),
            attribute_part: "status".to_string(),
        };
        generate_tuples_for_pattern(
            &p7,
            "docs",
            &db,
            &registry,
            &role_threshold_resource_hints,
            &mut queries,
            &mut generated,
        );

        let composite = PatternClass::P8Composite {
            op: BoolOp::Or,
            parts: vec![
                ClassifiedExpr {
                    pattern: PatternClass::P6BooleanFlag {
                        column: "is_public".to_string(),
                    },
                    confidence: ConfidenceLevel::A,
                },
                ClassifiedExpr {
                    pattern: PatternClass::P10ConstantBool { value: true },
                    confidence: ConfidenceLevel::A,
                },
                ClassifiedExpr {
                    pattern: PatternClass::P10ConstantBool { value: false },
                    confidence: ConfidenceLevel::A,
                },
            ],
        };
        generate_tuples_for_pattern(
            &composite,
            "docs",
            &db,
            &registry,
            &role_threshold_resource_hints,
            &mut queries,
            &mut generated,
        );

        assert!(queries
            .iter()
            .any(|q| q.comment.contains("-- project membership from doc_members")));
        assert!(queries
            .iter()
            .any(|q| q.comment.contains("bridge for tuple-to-userset")));
        assert!(queries.iter().any(|q| q
            .comment
            .contains("User ownership (owner_id references users)")));
        assert!(queries
            .iter()
            .any(|q| q.comment.contains("Constant TRUE policy")));

        let p4_membership_count = queries
            .iter()
            .filter(|q| q.comment.contains("-- project membership from doc_members"))
            .count();
        assert_eq!(
            p4_membership_count, 1,
            "P4 membership tuples should be deduplicated"
        );
    }

    #[test]
    fn generate_tuple_queries_reads_using_and_with_check() {
        let db = parse_schema(
            r"
CREATE TABLE docs(id uuid primary key, owner_id uuid);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_update ON docs FOR UPDATE
  USING (owner_id = current_user)
  WITH CHECK (owner_id = current_user);
",
        )
        .expect("schema should parse");

        let policy = db.policies().next().expect("policy should exist").clone();
        let classified = ClassifiedPolicy {
            policy,
            using_classification: Some(ClassifiedExpr {
                pattern: PatternClass::P3DirectOwnership {
                    column: "owner_id".to_string(),
                },
                confidence: ConfidenceLevel::A,
            }),
            with_check_classification: Some(ClassifiedExpr {
                pattern: PatternClass::P6BooleanFlag {
                    column: "is_public".to_string(),
                },
                confidence: ConfidenceLevel::A,
            }),
        };

        let queries = generate_tuple_queries(&[classified], &db, &FunctionRegistry::new());
        assert!(queries.iter().any(|q| q
            .comment
            .contains("User ownership (owner_id references users)")));
        assert!(queries
            .iter()
            .any(|q| q.comment.contains("Public access flag (is_public)")));
    }

    #[test]
    fn generate_tuple_queries_emit_policy_scope_tuples_for_non_public_roles() {
        let db = parse_schema(
            r"
CREATE TABLE docs(id uuid primary key, owner_id uuid);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON docs FOR SELECT TO app_user, auditors
  USING (owner_id = current_user);
",
        )
        .expect("schema should parse");

        let classified =
            crate::classifier::policy_classifier::classify_policies(&db, &FunctionRegistry::new());
        let queries = generate_tuple_queries(&classified, &db, &FunctionRegistry::new());
        let scope_relation = policy_scope_relation_name("docs_select");

        assert!(queries
            .iter()
            .any(|q| q.sql.contains(&format!("'{scope_relation}' AS relation"))));
        assert!(queries
            .iter()
            .any(|q| q.sql.contains("'pg_role:app_user' AS subject")));
        assert!(queries
            .iter()
            .any(|q| q.sql.contains("'pg_role:auditors' AS subject")));
    }

    #[test]
    fn generate_role_threshold_tuples_uses_policy_resource_column_for_grant_join() {
        let db = parse_schema(
            r"
CREATE TABLE users(id uuid primary key);
CREATE TABLE docs(id uuid primary key, owner_id uuid references users(id));
CREATE TABLE object_grants(grantee_id uuid, resource_id uuid, role_level integer);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON docs FOR SELECT
  USING (role_level(auth_current_user_id(), id) >= 2);
",
        )
        .expect("schema should parse");

        let mut registry = FunctionRegistry::new();
        registry
            .load_from_json(
                r#"{
  "role_level": {
    "kind": "role_threshold",
    "user_param_index": 0,
    "resource_param_index": 1,
    "role_levels": {"viewer": 1, "editor": 2},
    "grant_table": "object_grants",
    "grant_grantee_col": "grantee_id",
    "grant_resource_col": "resource_id",
    "grant_role_col": "role_level"
  },
  "auth_current_user_id": {
    "kind": "current_user_accessor",
    "returns": "uuid"
  }
}"#,
            )
            .expect("registry json should parse");

        let classified = crate::classifier::policy_classifier::classify_policies(&db, &registry);
        let queries = generate_tuple_queries(&classified, &db, &registry);

        let explicit_grants = queries
            .iter()
            .find(|q| q.comment.contains("Explicit grants expanded to docs rows"))
            .expect("expected explicit grants tuple query");

        assert!(
            explicit_grants
                .sql
                .contains("JOIN docs resource ON resource.id = og.resource_id"),
            "expected grants join to use policy resource column `id`, got:\n{}",
            explicit_grants.sql
        );
    }

    #[test]
    fn generate_role_threshold_tuples_extracts_resource_column_from_composite_classification() {
        let db = parse_schema(
            r"
CREATE TABLE users(id uuid primary key);
CREATE TABLE docs(id uuid primary key, owner_id uuid references users(id), is_public boolean);
CREATE TABLE object_grants(grantee_id uuid, resource_id uuid, role_level integer);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON docs FOR SELECT
  USING ((role_level(auth_current_user_id(), id) >= 2) AND is_public = TRUE);
",
        )
        .expect("schema should parse");

        let mut registry = FunctionRegistry::new();
        registry
            .load_from_json(
                r#"{
  "role_level": {
    "kind": "role_threshold",
    "user_param_index": 0,
    "resource_param_index": 1,
    "role_levels": {"viewer": 1, "editor": 2},
    "grant_table": "object_grants",
    "grant_grantee_col": "grantee_id",
    "grant_resource_col": "resource_id",
    "grant_role_col": "role_level"
  },
  "auth_current_user_id": {
    "kind": "current_user_accessor",
    "returns": "uuid"
  }
}"#,
            )
            .expect("registry json should parse");

        let classified = crate::classifier::policy_classifier::classify_policies(&db, &registry);
        let queries = generate_tuple_queries(&classified, &db, &registry);

        let explicit_grants = queries
            .iter()
            .find(|q| q.comment.contains("Explicit grants expanded to docs rows"))
            .expect("expected explicit grants tuple query");
        assert!(
            explicit_grants
                .sql
                .contains("JOIN docs resource ON resource.id = og.resource_id"),
            "expected composite policy extraction to preserve join on `id`, got:\n{}",
            explicit_grants.sql
        );
    }

    #[test]
    fn generate_role_threshold_tuples_emits_todo_when_resource_columns_conflict() {
        let db = parse_schema(
            r"
CREATE TABLE users(id uuid primary key);
CREATE TABLE docs(id uuid primary key, owner_id uuid references users(id), project_id uuid);
CREATE TABLE object_grants(grantee_id uuid, resource_id uuid, role_level integer);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select_id ON docs FOR SELECT
  USING (role_level(auth_current_user_id(), id) >= 2);
CREATE POLICY docs_select_project ON docs FOR SELECT
  USING (role_level(auth_current_user_id(), project_id) >= 2);
",
        )
        .expect("schema should parse");

        let mut registry = FunctionRegistry::new();
        registry
            .load_from_json(
                r#"{
  "role_level": {
    "kind": "role_threshold",
    "user_param_index": 0,
    "resource_param_index": 1,
    "role_levels": {"viewer": 1, "editor": 2},
    "grant_table": "object_grants",
    "grant_grantee_col": "grantee_id",
    "grant_resource_col": "resource_id",
    "grant_role_col": "role_level"
  },
  "auth_current_user_id": {
    "kind": "current_user_accessor",
    "returns": "uuid"
  }
}"#,
            )
            .expect("registry json should parse");

        let classified = crate::classifier::policy_classifier::classify_policies(&db, &registry);
        let queries = generate_tuple_queries(&classified, &db, &registry);

        assert!(
            queries
                .iter()
                .any(|q| q.comment.contains("conflicting resource join columns")),
            "expected conflict TODO when role threshold resource columns disagree"
        );
        assert!(
            !queries
                .iter()
                .any(|q| q.comment.contains("Explicit grants expanded to docs rows")),
            "explicit grants should be skipped when resource join column is ambiguous"
        );
    }

    #[test]
    fn generate_role_threshold_tuples_emit_todos_when_owner_and_join_columns_are_missing() {
        let db = parse_schema(
            r"
CREATE TABLE docs(doc_uuid uuid primary key, title text);
CREATE TABLE object_grants(grantee_id uuid, resource_id uuid, role_level integer);
",
        )
        .expect("schema should parse");

        let mut registry = FunctionRegistry::new();
        registry
            .load_from_json(
                r#"{
  "role_level": {
    "kind": "role_threshold",
    "user_param_index": 0,
    "resource_param_index": 1,
    "role_levels": {"viewer": 1},
    "grant_table": "object_grants",
    "grant_grantee_col": "grantee_id",
    "grant_resource_col": "resource_id",
    "grant_role_col": "role_level"
  }
}"#,
            )
            .expect("registry json should parse");

        let mut queries = Vec::new();
        let mut generated = std::collections::HashSet::new();
        generate_role_threshold_tuples(
            "role_level",
            "docs",
            None,
            &db,
            &registry,
            &mut queries,
            &mut generated,
        );

        assert!(queries.iter().any(|q| q
            .comment
            .contains("TODO [Level D]: skipped ownership tuples for docs")));
        assert!(queries.iter().any(|q| q
            .comment
            .contains("TODO [Level D]: skipped explicit grants for docs")));
    }

    #[test]
    fn generate_role_threshold_tuples_uses_configured_principal_tables() {
        let db = parse_schema(
            r"
CREATE TABLE accounts(account_id uuid primary key);
CREATE TABLE groups(group_id uuid primary key);
CREATE TABLE docs(id uuid primary key, owner_id uuid);
CREATE TABLE object_grants(grantee_id uuid, resource_id uuid, role_level integer);
CREATE TABLE team_memberships(user_id uuid, team_id uuid);
",
        )
        .expect("schema should parse");

        let mut registry = FunctionRegistry::new();
        registry
            .load_from_json(
                r#"{
  "role_level": {
    "kind": "role_threshold",
    "user_param_index": 0,
    "resource_param_index": 1,
    "role_levels": {"viewer": 1},
    "grant_table": "object_grants",
    "grant_grantee_col": "grantee_id",
    "grant_resource_col": "resource_id",
    "grant_role_col": "role_level",
    "team_membership_table": "team_memberships",
    "team_membership_user_col": "user_id",
    "team_membership_team_col": "team_id",
    "user_table": "accounts",
    "user_pk_col": "account_id",
    "team_table": "groups",
    "team_pk_col": "group_id"
  }
}"#,
            )
            .expect("registry json should parse");

        let mut queries = Vec::new();
        let mut generated = std::collections::HashSet::new();
        generate_role_threshold_tuples(
            "role_level",
            "docs",
            None,
            &db,
            &registry,
            &mut queries,
            &mut generated,
        );

        let user_ownership = queries
            .iter()
            .find(|q| q.comment.contains("User ownership"))
            .expect("expected user ownership query");
        assert!(user_ownership
            .sql
            .contains("SELECT account_id FROM accounts"));

        let team_ownership = queries
            .iter()
            .find(|q| q.comment.contains("Team ownership"))
            .expect("expected team ownership query");
        assert!(team_ownership.sql.contains("SELECT group_id FROM groups"));

        let grants = queries
            .iter()
            .find(|q| q.comment.contains("Explicit grants expanded to docs rows"))
            .expect("expected grant query");
        assert!(grants
            .sql
            .contains("LEFT JOIN accounts u ON u.account_id = og.grantee_id"));
        assert!(grants
            .sql
            .contains("LEFT JOIN groups t ON t.group_id = og.grantee_id"));
    }

    #[test]
    fn find_owner_column_returns_none_when_owner_columns_missing() {
        let db = parse_schema(
            r"
CREATE TABLE docs(doc_uuid uuid primary key, title text);
",
        )
        .expect("schema should parse");

        assert_eq!(
            find_owner_column("docs", &db),
            None,
            "expected no owner mapping when no owner-like columns are present"
        );
    }

    #[test]
    fn aliased_p4_membership_tuples_do_not_leak_correlated_or_current_user_predicates() {
        let db = parse_schema(
            r"
CREATE TABLE docs(id uuid primary key);
CREATE TABLE doc_members(doc_id uuid, user_id uuid, role text);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON docs FOR SELECT USING (
  EXISTS (
    SELECT 1
    FROM doc_members dm
    WHERE dm.doc_id = docs.id
      AND dm.user_id = current_user
      AND dm.role = 'admin'
  )
);
",
        )
        .expect("schema should parse");

        let registry = FunctionRegistry::new();
        let classified = crate::classifier::policy_classifier::classify_policies(&db, &registry);
        let queries = generate_tuple_queries(&classified, &db, &registry);

        let membership_query = queries
            .iter()
            .find(|q| q.comment.contains("-- doc membership from doc_members"))
            .expect("expected doc membership tuple query");

        assert!(
            membership_query.sql.contains("WHERE role = 'admin'"),
            "expected role filter to be preserved, got:\n{}",
            membership_query.sql
        );
        assert!(
            !membership_query.sql.contains("docs.id"),
            "correlated outer-table predicate must not leak into tuple SQL, got:\n{}",
            membership_query.sql
        );
        assert!(
            !membership_query.sql.contains("current_user"),
            "current_user predicate should be consumed as subject mapping, got:\n{}",
            membership_query.sql
        );
        assert!(
            !membership_query.sql.contains("dm."),
            "join-table alias should not leak into tuple SQL when FROM has no alias, got:\n{}",
            membership_query.sql
        );
    }

    #[test]
    fn extract_resource_column_for_function_walks_case_between_and_subquery_nodes() {
        let case_expr =
            parse_expr("CASE WHEN TRUE THEN role_level(auth_current_user_id(), doc_id) ELSE 0 END");
        assert_eq!(
            extract_resource_column_for_function(&case_expr, "role_level", 1).as_deref(),
            Some("doc_id")
        );

        let between_expr = parse_expr("role_level(auth_current_user_id(), id) BETWEEN 1 AND 5");
        assert_eq!(
            extract_resource_column_for_function(&between_expr, "role_level", 1).as_deref(),
            Some("id")
        );

        let in_subquery_expr =
            parse_expr("role_level(auth_current_user_id(), id) IN (SELECT doc_id FROM docs)");
        assert_eq!(
            extract_resource_column_for_function(&in_subquery_expr, "role_level", 1).as_deref(),
            Some("id")
        );

        let exists_expr = parse_expr(
            "EXISTS (
               SELECT 1
               FROM docs d
               WHERE role_level(auth_current_user_id(), d.id) >= 2
             )",
        );
        assert_eq!(
            extract_resource_column_for_function(&exists_expr, "role_level", 1).as_deref(),
            Some("id")
        );

        let having_expr = parse_expr(
            "EXISTS (
               SELECT count(*)
               FROM docs d
               GROUP BY d.id
               HAVING role_level(auth_current_user_id(), d.id) >= 2
             )",
        );
        assert_eq!(
            extract_resource_column_for_function(&having_expr, "role_level", 1).as_deref(),
            Some("id")
        );
    }

    #[test]
    fn canonical_table_name_is_used_for_tuple_object_prefixes() {
        let db = parse_schema(
            r"
CREATE TABLE app.docs(id uuid primary key, owner_id uuid);
ALTER TABLE app.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON app.docs USING (owner_id = current_user);
",
        )
        .expect("schema should parse");

        let classified =
            crate::classifier::policy_classifier::classify_policies(&db, &FunctionRegistry::new());
        let queries = generate_tuple_queries(&classified, &db, &FunctionRegistry::new());

        let ownership_query = queries
            .iter()
            .find(|q| q.comment.contains("User ownership"))
            .expect("expected ownership tuple query");
        assert!(ownership_query.sql.contains("'docs:' ||"));
        assert!(!ownership_query.sql.contains("'app.docs:' ||"));
    }
}

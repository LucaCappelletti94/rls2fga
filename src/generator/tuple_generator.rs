use crate::classifier::function_registry::FunctionRegistry;
use crate::classifier::patterns::*;
use crate::parser::function_analyzer::FunctionSemantic;
use crate::parser::sql_parser::{ColumnLike, DatabaseLike, ForeignKeyLike, ParserDB, TableLike};

/// A generated tuple query with its descriptive comment.
#[derive(Debug, Clone)]
pub struct TupleQuery {
    /// Human-readable SQL comment describing what this query populates.
    pub comment: String,
    /// SELECT statement that produces (object, relation, subject) triples.
    pub sql: String,
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

    // Track which tuple types we've already generated to avoid duplicates
    let mut generated = std::collections::HashSet::new();

    for cp in policies {
        let classification = cp
            .using_classification
            .as_ref()
            .or(cp.with_check_classification.as_ref());

        if let Some(classified) = classification {
            generate_tuples_for_pattern(
                &classified.pattern,
                &cp.table_name(),
                db,
                registry,
                &mut queries,
                &mut generated,
            );
        }
    }

    queries
}

fn generate_tuples_for_pattern(
    pattern: &PatternClass,
    table: &str,
    db: &ParserDB,
    registry: &FunctionRegistry,
    queries: &mut Vec<TupleQuery>,
    generated: &mut std::collections::HashSet<String>,
) {
    match pattern {
        PatternClass::P1NumericThreshold { function_name, .. }
        | PatternClass::P2RoleNameInList { function_name, .. } => {
            generate_role_threshold_tuples(function_name, table, db, registry, queries, generated);
        }
        PatternClass::P3DirectOwnership { column } => {
            let key = format!("p3:{table}:{column}");
            if generated.insert(key) {
                queries.push(TupleQuery {
                    comment: format!("-- User ownership ({column} references users)"),
                    sql: format!(
                        "SELECT '{table}:' || id AS object, 'owner' AS relation, 'user:' || {column} AS subject\nFROM {table}\nWHERE {column} IS NOT NULL;"
                    ),
                });
            }
        }
        PatternClass::P4ExistsMembership {
            join_table,
            fk_column,
            user_column,
        } => {
            let key = format!("p4:{join_table}");
            if generated.insert(key) {
                let parent_type = fk_column.strip_suffix("_id").unwrap_or(fk_column);
                queries.push(TupleQuery {
                    comment: format!("-- {parent_type} membership from {join_table}"),
                    sql: format!(
                        "SELECT '{parent_type}:' || {fk_column} AS object, 'member' AS relation, 'user:' || {user_column} AS subject\nFROM {join_table};"
                    ),
                });
            }
        }
        PatternClass::P6BooleanFlag { column } => {
            let key = format!("p6:{table}:{column}");
            if generated.insert(key) {
                queries.push(TupleQuery {
                    comment: format!("-- Public access flag ({column})"),
                    sql: format!(
                        "SELECT '{table}:' || id AS object, 'public_viewer' AS relation, 'user:*' AS subject\nFROM {table}\nWHERE {column} = TRUE;"
                    ),
                });
            }
        }
        PatternClass::P9AttributeCondition { column, .. } => {
            let key = format!("p9:{table}:{column}");
            if generated.insert(key) {
                queries.push(TupleQuery {
                    comment: format!(
                        "-- TODO [Level C]: Attribute condition ({column}) — adjust filter to match your policy"
                    ),
                    sql: format!(
                        "SELECT '{table}:' || id AS object, 'public_viewer' AS relation, 'user:*' AS subject\nFROM {table}\nWHERE {column} IS NOT NULL; -- TODO: replace with actual condition"
                    ),
                });
            }
        }
        PatternClass::P8Composite { parts, .. } => {
            for part in parts {
                generate_tuples_for_pattern(&part.pattern, table, db, registry, queries, generated);
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
                queries,
                generated,
            );
        }
        _ => {}
    }
}

fn generate_role_threshold_tuples(
    function_name: &str,
    table: &str,
    db: &ParserDB,
    registry: &FunctionRegistry,
    queries: &mut Vec<TupleQuery>,
    generated: &mut std::collections::HashSet<String>,
) {
    let key = format!("role_threshold:{table}:{function_name}");
    if !generated.insert(key) {
        return;
    }

    if let Some(FunctionSemantic::RoleThreshold {
        grant_table,
        grant_grantee_col,
        grant_resource_col,
        grant_role_col,
        team_membership_table,
        team_membership_user_col,
        team_membership_team_col,
        role_levels,
        ..
    }) = registry.get(function_name)
    {
        // Find the owner column on this table
        let owner_col = find_owner_column(table, db);

        // 1. User ownership
        queries.push(TupleQuery {
            comment: format!("-- User ownership ({owner_col} references users)"),
            sql: format!(
                "SELECT '{table}:' || id AS object, 'owner_user' AS relation, 'user:' || {owner_col} AS subject\n\
                 FROM {table}\n\
                 WHERE {owner_col} IN (SELECT id FROM users)\n\
                 AND {owner_col} IS NOT NULL;"
            ),
        });

        // 2. Team ownership (if teams exist)
        if team_membership_table.is_some() {
            queries.push(TupleQuery {
                comment: format!("-- Team ownership ({owner_col} references teams)"),
                sql: format!(
                    "SELECT '{table}:' || id AS object, 'owner_team' AS relation, 'team:' || {owner_col} AS subject\n\
                     FROM {table}\n\
                     WHERE {owner_col} IN (SELECT id FROM teams)\n\
                     AND {owner_col} IS NOT NULL;"
                ),
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

        for (role_name, role_id) in &sorted_levels {
            role_cases.push(format!("    WHEN {role_id} THEN 'grant_{role_name}'"));
            role_ids.push(role_id.to_string());
        }

        let case_expr = format!("CASE og.{grant_role_col}\n{}\n  END", role_cases.join("\n"));

        queries.push(TupleQuery {
            comment: format!(
                "-- Explicit grants ({}: {})",
                grant_role_col,
                sorted_levels
                    .iter()
                    .map(|(name, id)| format!("{id}={name}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            sql: format!(
                "SELECT\n\
                 \x20 '{table}:' || og.{grant_resource_col} AS object,\n\
                 \x20 {case_expr} AS relation,\n\
                 \x20 CASE\n\
                 \x20   WHEN u.id IS NOT NULL THEN 'user:' || og.{grant_grantee_col}\n\
                 \x20   ELSE 'team:' || og.{grant_grantee_col}\n\
                 \x20 END AS subject\n\
                 FROM {grant_table} og\n\
                 LEFT JOIN users u ON u.id = og.{grant_grantee_col}\n\
                 WHERE og.{grant_role_col} IN ({});",
                role_ids.join(", ")
            ),
        });
    }
}

fn find_owner_column(table: &str, db: &ParserDB) -> String {
    if let Some(table_info) = db.table(None, table) {
        for col in table_info.columns(db) {
            let name = col.column_name();
            if name == "owner_id" || name == "created_by" || name == "author_id" {
                return name.to_string();
            }
        }
        // Check FK references to users/owners
        for fk in table_info.foreign_keys(db) {
            let ref_table = fk.referenced_table(db);
            let ref_name = ref_table.table_name();
            if ref_name == "users" || ref_name == "owners" {
                if let Some(col) = fk.host_columns(db).next() {
                    return col.column_name().to_string();
                }
            }
        }
    }
    "owner_id".to_string()
}

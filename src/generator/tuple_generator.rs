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
        if let Some(classified) = cp.using_classification.as_ref() {
            generate_tuples_for_pattern(
                &classified.pattern,
                &cp.table_name(),
                db,
                registry,
                &mut queries,
                &mut generated,
            );
        }
        if let Some(classified) = cp.with_check_classification.as_ref() {
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
            extra_predicate_sql,
        } => {
            let key = format!(
                "p4:{table}:{join_table}:{fk_column}:{user_column}:{}",
                extra_predicate_sql.as_deref().unwrap_or("")
            );
            if generated.insert(key) {
                let parent_type = fk_column.strip_suffix("_id").unwrap_or(fk_column);
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

            let parent_type = fk_column.strip_suffix("_id").unwrap_or(fk_column);
            let bridge_key = format!("p4_bridge:{table}:{parent_type}");
            if generated.insert(bridge_key) {
                let (object_col, parent_ref_col) = pick_bridge_columns(table, fk_column, db);
                queries.push(TupleQuery {
                    comment: format!("-- {table} to {parent_type} bridge for tuple-to-userset"),
                    sql: format!(
                        "SELECT '{table}:' || {object_col} AS object, '{parent_type}' AS relation, '{parent_type}:' || {parent_ref_col} AS subject\nFROM {table}\nWHERE {object_col} IS NOT NULL\nAND {parent_ref_col} IS NOT NULL;"
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
        PatternClass::P10ConstantBool { value } => {
            let key = format!("p10:{table}:{value}");
            if generated.insert(key) && *value {
                queries.push(TupleQuery {
                    comment: "-- Constant TRUE policy (all rows are visible)".to_string(),
                    sql: format!(
                        "SELECT '{table}:' || id AS object, 'public_viewer' AS relation, 'user:*' AS subject\nFROM {table};"
                    ),
                });
            }
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
                 \x20 '{table}:' || resource.id AS object,\n\
                 \x20 {case_expr} AS relation,\n\
                 \x20 CASE\n\
                 \x20   WHEN u.id IS NOT NULL THEN 'user:' || og.{grant_grantee_col}\n\
                 \x20   ELSE 'team:' || og.{grant_grantee_col}\n\
                 \x20 END AS subject\n\
                 FROM {grant_table} og\n\
                 JOIN {table} resource ON resource.{owner_col} = og.{grant_resource_col}\n\
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
                if let Some(col_name) = fk
                    .host_columns(db)
                    .next()
                    .map(|col| col.column_name().to_string())
                {
                    return col_name;
                }
            }
        }
    }
    "owner_id".to_string()
}

fn pick_bridge_columns(table: &str, fk_column: &str, db: &ParserDB) -> (String, String) {
    let Some(table_info) = db.table(None, table) else {
        return ("id".to_string(), "id".to_string());
    };

    let cols: Vec<String> = table_info
        .columns(db)
        .map(|c| c.column_name().to_string())
        .collect();

    let object_col = cols
        .iter()
        .find(|c| c.as_str() == "id")
        .cloned()
        .or_else(|| cols.first().cloned())
        .unwrap_or_else(|| "id".to_string());

    let parent_ref_col = if cols.iter().any(|c| c == fk_column) {
        fk_column.to_string()
    } else {
        object_col.clone()
    };

    (object_col, parent_ref_col)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::sql_parser::{parse_schema, DatabaseLike};

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
            &db,
            &registry,
            &mut queries,
            &mut generated,
        );
        generate_role_threshold_tuples(
            "role_level",
            "docs",
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
            &db,
            &registry,
            &mut queries,
            &mut generated,
        );

        assert!(queries.is_empty());
    }

    #[test]
    fn find_owner_column_prefers_named_owner_then_fk_then_default() {
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

        assert_eq!(find_owner_column("docs", &db), "owner_id");
        assert_eq!(find_owner_column("notes", &db), "owner_ref");
        assert_eq!(find_owner_column("posts", &db), "owner_ref");
        assert_eq!(find_owner_column("missing_table", &db), "owner_id");
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
            &db,
            &registry,
            &mut queries,
            &mut generated,
        );

        assert!(!queries.iter().any(|q| q.comment == "-- Team memberships"));
    }

    #[test]
    fn pick_bridge_columns_covers_fallback_paths() {
        let db = parse_schema(
            r"
CREATE TABLE docs(id uuid primary key, project_id uuid);
CREATE TABLE links(resource_uuid uuid, project_uuid uuid);
",
        )
        .expect("schema should parse");

        assert_eq!(
            pick_bridge_columns("missing", "project_id", &db),
            ("id".to_string(), "id".to_string())
        );
        assert_eq!(
            pick_bridge_columns("docs", "project_id", &db),
            ("id".to_string(), "project_id".to_string())
        );
        assert_eq!(
            pick_bridge_columns("links", "project_id", &db),
            ("resource_uuid".to_string(), "resource_uuid".to_string())
        );
    }

    #[test]
    fn generate_tuples_for_pattern_handles_p4_bridge_p7_p8_and_p10() {
        let db = db_with_resources();
        let registry = registry_with_role_threshold(false);
        let mut queries = Vec::new();
        let mut generated = std::collections::HashSet::new();

        let p4 = PatternClass::P4ExistsMembership {
            join_table: "doc_members".to_string(),
            fk_column: "project_id".to_string(),
            user_column: "user_id".to_string(),
            extra_predicate_sql: Some("doc_members.role = 'admin'".to_string()),
        };
        generate_tuples_for_pattern(&p4, "docs", &db, &registry, &mut queries, &mut generated);
        generate_tuples_for_pattern(&p4, "docs", &db, &registry, &mut queries, &mut generated);

        let p7 = PatternClass::P7AbacAnd {
            relationship_part: Box::new(ClassifiedExpr {
                pattern: PatternClass::P3DirectOwnership {
                    column: "owner_id".to_string(),
                },
                confidence: ConfidenceLevel::A,
            }),
            attribute_part: "status".to_string(),
        };
        generate_tuples_for_pattern(&p7, "docs", &db, &registry, &mut queries, &mut generated);

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
}

use crate::classifier::function_registry::FunctionRegistry;
use crate::classifier::patterns::*;
use crate::generator::ir::TupleSource;
use crate::generator::model_generator::SchemaPlan;
use crate::parser::names::{
    canonical_fga_type_name, lookup_table, parent_type_from_fk_column,
    split_qualified_identifier_parts, split_schema_and_relation,
};
use crate::parser::sql_parser::{ColumnLike, ParserDB, TableLike};
use std::collections::HashSet;

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

/// Generate tuple SQL queries from a pre-built [`SchemaPlan`].
pub(crate) fn generate_tuple_queries_from_plan(
    plan: &SchemaPlan,
    db: &ParserDB,
) -> Vec<TupleQuery> {
    let mut queries = Vec::new();
    let mut generated: HashSet<String> = HashSet::new();

    for type_plan in &plan.types {
        for source in &type_plan.table_tuple_sources {
            let key = source.dedup_key();
            if !generated.insert(key) {
                continue;
            }
            if let Some(query) = render_tuple_source(source, db) {
                queries.push(query);
            }
        }
    }

    queries
}

/// Render a single [`TupleSource`] to a [`TupleQuery`].
///
/// Returns `None` only when the source has no renderable output (currently
/// unused; all variants produce at least a comment).
fn render_tuple_source(source: &TupleSource, db: &ParserDB) -> Option<TupleQuery> {
    match source {
        TupleSource::DirectOwnership {
            table,
            pk_col,
            owner_col,
        } => {
            let table_type = canonical_fga_type_name(table);
            let table_sql = quote_sql_identifier(table);
            let pk_col_sql = quote_sql_identifier(pk_col);
            let owner_col_sql = quote_sql_identifier(owner_col);
            Some(TupleQuery {
                comment: format!("-- User ownership ({owner_col} references users)"),
                sql: format!(
                    "SELECT '{table_type}:' || {pk_col_sql} AS object, 'owner' AS relation, \
                     'user:' || {owner_col_sql} AS subject\n\
                     FROM {table_sql}\n\
                     WHERE {owner_col_sql} IS NOT NULL;"
                ),
            })
        }

        TupleSource::RoleOwnerUser {
            table,
            pk_col,
            owner_col,
            user_table,
            user_pk_col,
        } => {
            let table_type = canonical_fga_type_name(table);
            let table_sql = quote_sql_identifier(table);
            let pk_col_sql = quote_sql_identifier(pk_col);
            let owner_col_sql = quote_sql_identifier(owner_col);
            let user_table_sql = quote_sql_identifier(user_table);
            let user_pk_col_sql = quote_sql_identifier(user_pk_col);
            Some(TupleQuery {
                comment: format!("-- User ownership ({owner_col} references {user_table})"),
                sql: format!(
                    "SELECT '{table_type}:' || {pk_col_sql} AS object, 'owner_user' AS relation, \
                     'user:' || {owner_col_sql} AS subject\n\
                     FROM {table_sql}\n\
                     WHERE {owner_col_sql} IN (SELECT {user_pk_col_sql} FROM {user_table_sql})\n\
                     AND {owner_col_sql} IS NOT NULL;"
                ),
            })
        }

        TupleSource::RoleOwnerTeam {
            table,
            pk_col,
            owner_col,
            team_table,
            team_pk_col,
        } => {
            let table_type = canonical_fga_type_name(table);
            let table_sql = quote_sql_identifier(table);
            let pk_col_sql = quote_sql_identifier(pk_col);
            let owner_col_sql = quote_sql_identifier(owner_col);
            let team_table_sql = quote_sql_identifier(team_table);
            let team_pk_col_sql = quote_sql_identifier(team_pk_col);
            Some(TupleQuery {
                comment: format!("-- Team ownership ({owner_col} references {team_table})"),
                sql: format!(
                    "SELECT '{table_type}:' || {pk_col_sql} AS object, 'owner_team' AS relation, \
                     'team:' || {owner_col_sql} AS subject\n\
                     FROM {table_sql}\n\
                     WHERE {owner_col_sql} IN (SELECT {team_pk_col_sql} FROM {team_table_sql})\n\
                     AND {owner_col_sql} IS NOT NULL;"
                ),
            })
        }

        TupleSource::ExplicitGrants {
            table,
            pk_col,
            grant_join_col,
            grant_table,
            grant_role_col,
            grant_grantee_col,
            grant_resource_col,
            role_cases,
            user_principal,
            team_principal,
        } => {
            if role_cases.is_empty() {
                return None;
            }
            let table_type = canonical_fga_type_name(table);
            let table_sql = quote_sql_identifier(table);
            let pk_col_sql = quote_sql_identifier(pk_col);
            let grant_join_col_sql = quote_sql_identifier(grant_join_col);
            let grant_table_sql = quote_sql_identifier(grant_table);
            let grant_role_col_sql = quote_sql_identifier(grant_role_col);
            let grant_grantee_col_sql = quote_sql_identifier(grant_grantee_col);
            let grant_resource_col_sql = quote_sql_identifier(grant_resource_col);

            let case_arms: Vec<String> = role_cases
                .iter()
                .map(|(level, grant_rel, _)| format!("    WHEN {level} THEN '{grant_rel}'"))
                .collect();

            let role_ids: Vec<String> = role_cases
                .iter()
                .map(|(level, _, _)| level.to_string())
                .collect();
            let comment_roles: Vec<String> = role_cases
                .iter()
                .map(|(level, _, original)| format!("{level}={original}"))
                .collect();

            let case_expr = format!(
                "CASE og.{grant_role_col_sql}\n{}\n  END",
                case_arms.join("\n")
            );

            let mut subject_joins: Vec<String> = Vec::new();
            let subject_expr = match (user_principal.as_ref(), team_principal.as_ref()) {
                (Some(up), Some(tp)) => {
                    let user_tbl_sql = quote_sql_identifier(&up.table);
                    let user_pk_sql = quote_sql_identifier(&up.pk_col);
                    let team_tbl_sql = quote_sql_identifier(&tp.table);
                    let team_pk_sql = quote_sql_identifier(&tp.pk_col);
                    subject_joins.push(format!(
                        "LEFT JOIN {user_tbl_sql} u ON u.{user_pk_sql} = og.{grant_grantee_col_sql}"
                    ));
                    subject_joins.push(format!(
                        "LEFT JOIN {team_tbl_sql} t ON t.{team_pk_sql} = og.{grant_grantee_col_sql}"
                    ));
                    format!(
                        "CASE\n\
                         \x20   WHEN u.{user_pk_sql} IS NOT NULL THEN 'user:' || og.{grant_grantee_col_sql}\n\
                         \x20   WHEN t.{team_pk_sql} IS NOT NULL THEN 'team:' || og.{grant_grantee_col_sql}\n\
                         \x20   ELSE 'user:' || og.{grant_grantee_col_sql}\n\
                         \x20 END"
                    )
                }
                (Some(_) | None, None) => {
                    format!("'user:' || og.{grant_grantee_col_sql}")
                }
                (None, Some(tp)) => {
                    let team_tbl_sql = quote_sql_identifier(&tp.table);
                    let team_pk_sql = quote_sql_identifier(&tp.pk_col);
                    subject_joins.push(format!(
                        "LEFT JOIN {team_tbl_sql} t ON t.{team_pk_sql} = og.{grant_grantee_col_sql}"
                    ));
                    format!(
                        "CASE\n\
                         \x20   WHEN t.{team_pk_sql} IS NOT NULL THEN 'team:' || og.{grant_grantee_col_sql}\n\
                         \x20   ELSE 'user:' || og.{grant_grantee_col_sql}\n\
                         \x20 END"
                    )
                }
            };

            let subject_join_sql = if subject_joins.is_empty() {
                String::new()
            } else {
                format!("{}\n", subject_joins.join("\n                 "))
            };

            Some(TupleQuery {
                comment: format!(
                    "-- Explicit grants expanded to {table} rows ({grant_role_col}: {})",
                    comment_roles.join(", ")
                ),
                sql: format!(
                    "SELECT\n\
                     \x20 '{table_type}:' || resource.{pk_col_sql} AS object,\n\
                     \x20 {case_expr} AS relation,\n\
                     \x20 {subject_expr} AS subject\n\
                     FROM {grant_table_sql} og\n\
                     JOIN {table_sql} resource ON resource.{grant_join_col_sql} = og.{grant_resource_col_sql}\n\
                     {subject_join_sql}\
                     WHERE og.{grant_role_col_sql} IN ({});",
                    role_ids.join(", ")
                ),
            })
        }

        TupleSource::TeamMembership {
            membership_table,
            team_col,
            user_col,
        } => {
            let membership_table_sql = quote_sql_identifier(membership_table);
            let team_col_sql = quote_sql_identifier(team_col);
            let user_col_sql = quote_sql_identifier(user_col);
            Some(TupleQuery {
                comment: "-- Team memberships".to_string(),
                sql: format!(
                    "SELECT 'team:' || {team_col_sql} AS object, 'member' AS relation, \
                     'user:' || {user_col_sql} AS subject\n\
                     FROM {membership_table_sql};"
                ),
            })
        }

        TupleSource::ExistsMembership {
            join_table,
            fk_col,
            user_col,
            extra_predicate_sql,
        } => {
            let parent_type = parent_type_from_fk_column(fk_col);
            let join_table_sql = quote_sql_identifier(join_table);
            let fk_col_sql = quote_sql_identifier(fk_col);
            let user_col_sql = quote_sql_identifier(user_col);
            let where_clause = extra_predicate_sql
                .as_ref()
                .map(|e| format!("\nWHERE {e}"))
                .unwrap_or_default();
            Some(TupleQuery {
                comment: format!("-- {parent_type} membership from {join_table}"),
                sql: format!(
                    "SELECT '{parent_type}:' || {fk_col_sql} AS object, 'member' AS relation, \
                     'user:' || {user_col_sql} AS subject\n\
                     FROM {join_table_sql}{where_clause};"
                ),
            })
        }

        TupleSource::ParentBridge {
            table,
            fk_col,
            parent_type,
        } => {
            let table_type = canonical_fga_type_name(table);
            let Some((object_col, parent_ref_col)) = resolve_bridge_columns(table, fk_col, db)
            else {
                return Some(TupleQuery {
                    comment: format!(
                        "-- TODO [Level D]: skipped {table} to {parent_type} bridge \
                         (missing column '{fk_col}')"
                    ),
                    sql: "-- Bridge tuple not emitted; review schema/FK mapping.".to_string(),
                });
            };
            let table_sql = quote_sql_identifier(table);
            let object_col_sql = quote_sql_identifier(&object_col);
            let parent_ref_col_sql = quote_sql_identifier(&parent_ref_col);
            Some(TupleQuery {
                comment: format!("-- {table} to {parent_type} bridge for tuple-to-userset"),
                sql: format!(
                    "SELECT '{table_type}:' || {object_col_sql} AS object, \
                     '{parent_type}' AS relation, \
                     '{parent_type}:' || {parent_ref_col_sql} AS subject\n\
                     FROM {table_sql}\n\
                     WHERE {object_col_sql} IS NOT NULL\n\
                     AND {parent_ref_col_sql} IS NOT NULL;"
                ),
            })
        }

        TupleSource::PublicFlag {
            table,
            pk_col,
            flag_col,
        } => {
            let table_type = canonical_fga_type_name(table);
            let table_sql = quote_sql_identifier(table);
            let pk_col_sql = quote_sql_identifier(pk_col);
            let flag_col_sql = quote_sql_identifier(flag_col);
            Some(TupleQuery {
                comment: format!("-- Public access flag ({flag_col})"),
                sql: format!(
                    "SELECT '{table_type}:' || {pk_col_sql} AS object, 'public_viewer' AS relation, \
                     'user:*' AS subject\n\
                     FROM {table_sql}\n\
                     WHERE {flag_col_sql} = TRUE;"
                ),
            })
        }

        TupleSource::ConstantTrue { table, pk_col } => {
            let table_type = canonical_fga_type_name(table);
            let table_sql = quote_sql_identifier(table);
            let pk_col_sql = quote_sql_identifier(pk_col);
            Some(TupleQuery {
                comment: "-- Constant TRUE policy (all rows are visible)".to_string(),
                sql: format!(
                    "SELECT '{table_type}:' || {pk_col_sql} AS object, 'public_viewer' AS relation, \
                     'user:*' AS subject\n\
                     FROM {table_sql}\n\
                     WHERE {pk_col_sql} IS NOT NULL;"
                ),
            })
        }

        TupleSource::PolicyScope {
            table,
            pk_col,
            scope_relation,
            pg_role,
        } => {
            let table_type = canonical_fga_type_name(table);
            let table_sql = quote_sql_identifier(table);
            let pk_col_sql = quote_sql_identifier(pk_col);
            Some(TupleQuery {
                comment: format!(
                    "-- Policy scope: {table} rows require PostgreSQL role '{pg_role}' \
                     via {scope_relation}"
                ),
                sql: format!(
                    "SELECT '{table_type}:' || {pk_col_sql} AS object, \
                     '{scope_relation}' AS relation, \
                     'pg_role:{pg_role}' AS subject\n\
                     FROM {table_sql}\n\
                     WHERE {pk_col_sql} IS NOT NULL;"
                ),
            })
        }

        TupleSource::Todo { comment, sql, .. } => Some(TupleQuery {
            comment: comment.clone(),
            sql: sql.clone(),
        }),
    }
}

/// Generate tuple SQL queries from classified policies.
pub fn generate_tuple_queries(
    policies: &[ClassifiedPolicy],
    db: &ParserDB,
    registry: &FunctionRegistry,
    min_confidence: &ConfidenceLevel,
) -> Vec<TupleQuery> {
    let filtered = filter_policies_for_output(policies, *min_confidence);
    let plan = crate::generator::model_generator::build_schema_plan(&filtered, db, registry);
    generate_tuple_queries_from_plan(&plan, db)
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

    // The FK column isn't a real column of this table, but the inferred parent
    // type matches the table's own name.  Emit the sentinel self-reference tuple
    // (`project:X  project  project:X`) that OpenFGA needs for tuple-to-userset
    // when the membership table FK points back to the same resource type.
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

fn quote_sql_identifier(identifier: &str) -> String {
    split_qualified_identifier_parts(identifier)
        .into_iter()
        .map(|part| quote_sql_identifier_part(&part))
        .collect::<Vec<_>>()
        .join(".")
}

fn quote_sql_identifier_part(part: &str) -> String {
    let trimmed = part.trim();
    if trimmed.is_empty() {
        return "\"\"".to_string();
    }
    // Strip pre-existing outer quotes and re-escape through the normal path.
    // This prevents pre-quoted strings from bypassing validation (e.g. a
    // function_registry.json entry containing `"foo" OR 1=1--`).
    let raw = if trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2 {
        trimmed[1..trimmed.len() - 1].replace("\"\"", "\"")
    } else {
        trimmed.to_string()
    };
    if !identifier_needs_quoting(&raw) {
        return raw;
    }
    format!("\"{}\"", raw.replace('"', "\"\""))
}

fn identifier_needs_quoting(ident: &str) -> bool {
    // Expanded list of PostgreSQL reserved and commonly-conflicting keywords.
    // Column or table names matching any of these must be double-quoted.
    const RESERVED: &[&str] = &[
        "all",
        "analyse",
        "analyze",
        "and",
        "any",
        "array",
        "as",
        "asc",
        "asymmetric",
        "authorization",
        "between",
        "binary",
        "both",
        "case",
        "cast",
        "check",
        "collate",
        "collation",
        "column",
        "concurrently",
        "constraint",
        "create",
        "cross",
        "current_catalog",
        "current_date",
        "current_role",
        "current_schema",
        "current_time",
        "current_timestamp",
        "current_user",
        "default",
        "deferrable",
        "desc",
        "distinct",
        "do",
        "else",
        "end",
        "except",
        "false",
        "fetch",
        "for",
        "foreign",
        "freeze",
        "from",
        "full",
        "grant",
        "group",
        "having",
        "ilike",
        "in",
        "initially",
        "inner",
        "intersect",
        "into",
        "is",
        "isnull",
        "join",
        "lateral",
        "leading",
        "left",
        "like",
        "limit",
        "localtime",
        "localtimestamp",
        "natural",
        "not",
        "notnull",
        "null",
        "offset",
        "on",
        "only",
        "or",
        "order",
        "outer",
        "overlaps",
        "placing",
        "primary",
        "references",
        "returning",
        "right",
        "role",
        "row",
        "select",
        "session_user",
        "similar",
        "some",
        "symmetric",
        "table",
        "tablesample",
        "then",
        "to",
        "trailing",
        "true",
        "union",
        "unique",
        "user",
        "using",
        "variadic",
        "verbose",
        "when",
        "where",
        "window",
        "with",
    ];

    if RESERVED.iter().any(|kw| ident.eq_ignore_ascii_case(kw)) {
        return true;
    }

    let mut chars = ident.chars();
    let Some(first) = chars.next() else {
        return true;
    };
    if !(first.is_ascii_lowercase() || first == '_') {
        return true;
    }
    chars.any(|ch| !(ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::names::policy_scope_relation_name;
    use crate::parser::sql_parser::{parse_schema, DatabaseLike};

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
        // Sentinel self-reference: fk_col not in table columns but parent type
        // matches table name → used for OpenFGA tuple-to-userset navigation.
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

        let queries = generate_tuple_queries(
            &[classified],
            &db,
            &FunctionRegistry::new(),
            &ConfidenceLevel::D,
        );
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
        let queries = generate_tuple_queries(
            &classified,
            &db,
            &FunctionRegistry::new(),
            &ConfidenceLevel::D,
        );
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
        let queries = generate_tuple_queries(&classified, &db, &registry, &ConfidenceLevel::D);

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
        let queries = generate_tuple_queries(&classified, &db, &registry, &ConfidenceLevel::D);

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
        let queries = generate_tuple_queries(&classified, &db, &registry, &ConfidenceLevel::D);

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
    fn generate_role_threshold_tuples_emits_todo_when_single_policy_has_conflicting_resource_columns(
    ) {
        let db = parse_schema(
            r"
CREATE TABLE users(id uuid primary key);
CREATE TABLE docs(id uuid primary key, owner_id uuid references users(id), project_id uuid);
CREATE TABLE object_grants(grantee_id uuid, resource_id uuid, role_level integer);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON docs FOR SELECT
  USING (
    (role_level(auth_current_user_id(), id) >= 2)
    OR (role_level(auth_current_user_id(), project_id) >= 2)
  );
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
        let queries = generate_tuple_queries(&classified, &db, &registry, &ConfidenceLevel::D);

        assert!(
            queries
                .iter()
                .any(|q| q.comment.contains("conflicting resource join columns")),
            "expected conflict TODO for mixed resource args in one policy expression"
        );
        assert!(
            !queries
                .iter()
                .any(|q| q.comment.contains("Explicit grants expanded to docs rows")),
            "explicit grants should be skipped when a single policy mixes resource join columns"
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
        let queries = generate_tuple_queries(&classified, &db, &registry, &ConfidenceLevel::D);

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
        let queries = generate_tuple_queries(
            &classified,
            &db,
            &FunctionRegistry::new(),
            &ConfidenceLevel::D,
        );

        let ownership_query = queries
            .iter()
            .find(|q| q.comment.contains("User ownership"))
            .expect("expected ownership tuple query");
        assert!(ownership_query.sql.contains("'docs:' ||"));
        assert!(!ownership_query.sql.contains("'app.docs:' ||"));
    }

    #[test]
    fn tuple_sql_quotes_identifiers_for_mixed_case_and_reserved_names() {
        let db = parse_schema(
            r#"
CREATE TABLE "Doc Items"(
  id uuid primary key,
  "OwnerID" uuid
);
ALTER TABLE "Doc Items" ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON "Doc Items" FOR SELECT
  USING ("OwnerID" = current_user);
"#,
        )
        .expect("schema should parse");

        let classified =
            crate::classifier::policy_classifier::classify_policies(&db, &FunctionRegistry::new());
        let queries = generate_tuple_queries(
            &classified,
            &db,
            &FunctionRegistry::new(),
            &ConfidenceLevel::D,
        );

        let ownership_query = queries
            .iter()
            .find(|q| q.comment.contains("User ownership"))
            .expect("expected ownership tuple query");

        assert!(
            ownership_query
                .sql
                .contains("'user:' || \"OwnerID\" AS subject"),
            "subject column should be quoted, got:\n{}",
            ownership_query.sql
        );
        assert!(
            ownership_query.sql.contains("FROM \"Doc Items\""),
            "table name should be quoted, got:\n{}",
            ownership_query.sql
        );
    }

    #[test]
    fn tuple_generation_fails_closed_when_object_identifier_column_is_missing() {
        let db = parse_schema(
            r"
CREATE TABLE docs(doc_uuid uuid, owner_id uuid);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON docs FOR SELECT
  USING (owner_id = current_user);
",
        )
        .expect("schema should parse");

        let registry = FunctionRegistry::new();
        let classified = crate::classifier::policy_classifier::classify_policies(&db, &registry);
        let queries = generate_tuple_queries(&classified, &db, &registry, &ConfidenceLevel::D);

        assert!(
            queries
                .iter()
                .any(|q| q.comment.contains("missing object identifier column")),
            "expected explicit TODO when object identifier column cannot be resolved"
        );
        assert!(
            !queries.iter().any(|q| q.comment.contains("User ownership")),
            "ownership tuples should not be emitted without a stable object identifier column"
        );
    }

    #[test]
    fn quote_sql_identifier_part_re_escapes_pre_quoted_identifiers() {
        // A pre-quoted identifier must be stripped and re-quoted through the
        // normal path rather than returned verbatim, preventing injection via
        // malformed entries (e.g. function_registry.json).
        assert_eq!(
            quote_sql_identifier_part("\"simple\""),
            "simple",
            "simple pre-quoted identifier should round-trip to unquoted form"
        );
        assert_eq!(
            quote_sql_identifier_part("\"mixed Case\""),
            "\"mixed Case\"",
            "pre-quoted identifier with spaces must be re-quoted"
        );
        // A pre-quoted identifier with inner doubled-quotes (SQL escaping):
        // strip outer quotes → unescape `""` → `"` → re-escape → `""` → re-quote.
        assert_eq!(
            quote_sql_identifier_part("\"with\"\"inner\"\"quotes\""),
            "\"with\"\"inner\"\"quotes\"",
            "inner doubled quotes should be unescaped then properly re-escaped"
        );
        // New keywords in the expanded list must be quoted.
        assert_eq!(quote_sql_identifier_part("null"), "\"null\"");
        assert_eq!(quote_sql_identifier_part("with"), "\"with\"");
        assert_eq!(quote_sql_identifier_part("join"), "\"join\"");
        assert_eq!(quote_sql_identifier_part("default"), "\"default\"");
        assert_eq!(quote_sql_identifier_part("case"), "\"case\"");
    }
}

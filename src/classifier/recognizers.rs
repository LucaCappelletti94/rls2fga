use sqlparser::ast::{BinaryOperator, Expr, Select, SelectItem, Value};

use crate::classifier::function_registry::FunctionRegistry;
use crate::classifier::patterns::*;
use crate::parser::sql_parser::{ColumnLike, DatabaseLike, ParserDB, TableLike};

/// Try to recognize P1: numeric role threshold `func(user, resource) >= N`.
pub fn recognize_p1(
    expr: &Expr,
    _db: &ParserDB,
    registry: &FunctionRegistry,
    command: &PolicyCommand,
) -> Option<ClassifiedExpr> {
    if let Expr::BinaryOp { left, op, right } = expr {
        let (func_expr, threshold_expr, operator) = match op {
            BinaryOperator::GtEq => (left.as_ref(), right.as_ref(), ThresholdOperator::Gte),
            BinaryOperator::Gt => (left.as_ref(), right.as_ref(), ThresholdOperator::Gt),
            _ => return None,
        };

        let func_name = extract_function_name(func_expr)?;
        if !registry.is_role_threshold(&func_name) {
            return None;
        }

        let threshold = extract_integer_value(threshold_expr)?;

        return Some(ClassifiedExpr {
            pattern: PatternClass::P1NumericThreshold {
                function_name: func_name,
                operator,
                threshold,
                command: command.clone(),
            },
            confidence: ConfidenceLevel::A,
        });
    }
    None
}

/// Try to recognize P2: role name IN-list `func(user, resource) IN ('viewer', ...)`.
pub fn recognize_p2(
    expr: &Expr,
    _db: &ParserDB,
    registry: &FunctionRegistry,
) -> Option<ClassifiedExpr> {
    if let Expr::InList {
        expr: inner_expr,
        list,
        negated,
    } = expr
    {
        if *negated {
            return None;
        }

        let func_name = extract_function_name(inner_expr)?;
        if !registry.is_role_threshold(&func_name) {
            return None;
        }

        let role_names: Vec<String> = list
            .iter()
            .filter_map(|e| {
                if let Expr::Value(v) = e {
                    match &v.value {
                        Value::SingleQuotedString(s) => return Some(s.clone()),
                        Value::Number(n, _) => return Some(n.clone()),
                        _ => {}
                    }
                }
                None
            })
            .collect();

        if role_names.is_empty() {
            return None;
        }

        return Some(ClassifiedExpr {
            pattern: PatternClass::P2RoleNameInList {
                function_name: func_name,
                role_names,
            },
            confidence: ConfidenceLevel::A,
        });
    }
    None
}

/// Try to recognize P3: direct ownership `owner_id = auth.user_id()`.
pub fn recognize_p3(
    expr: &Expr,
    _db: &ParserDB,
    registry: &FunctionRegistry,
) -> Option<ClassifiedExpr> {
    if let Expr::BinaryOp { left, op, right } = expr {
        if !matches!(op, BinaryOperator::Eq) {
            return None;
        }

        // Try column = function() or function() = column
        let (col_name, func_name) = if let (Some(col), Some(func)) =
            (extract_column_name(left), extract_function_name(right))
        {
            (col, func)
        } else if let (Some(func), Some(col)) =
            (extract_function_name(left), extract_column_name(right))
        {
            (col, func)
        } else {
            return None;
        };

        // Determine how we matched the function and assign confidence accordingly.
        let is_registry_confirmed = registry.is_current_user_accessor(&func_name);
        let func_lower = func_name.to_lowercase();
        let is_sql_keyword =
            func_lower == "current_user" || func_lower == "session_user" || func_lower == "user";

        if !is_registry_confirmed && !is_sql_keyword {
            // Heuristic function name check
            if !func_lower.contains("current_user")
                && !func_lower.contains("auth")
                && !func_lower.contains("user_id")
            {
                return None;
            }

            // Heuristic match: require column name to look ownership-related
            let col_lower = col_name.to_lowercase();
            if col_lower.contains("owner")
                || col_lower.contains("created_by")
                || col_lower.contains("user_id")
                || col_lower == "author_id"
            {
                return Some(ClassifiedExpr {
                    pattern: PatternClass::P3DirectOwnership { column: col_name },
                    confidence: ConfidenceLevel::A,
                });
            }

            // Heuristic function + non-standard column → confidence B
            return Some(ClassifiedExpr {
                pattern: PatternClass::P3DirectOwnership { column: col_name },
                confidence: ConfidenceLevel::B,
            });
        }

        // Registry-confirmed or SQL keyword: accept any column at confidence A
        return Some(ClassifiedExpr {
            pattern: PatternClass::P3DirectOwnership { column: col_name },
            confidence: ConfidenceLevel::A,
        });
    }
    None
}

/// Try to recognize P4: EXISTS membership check.
pub fn recognize_p4(
    expr: &Expr,
    db: &ParserDB,
    registry: &FunctionRegistry,
) -> Option<ClassifiedExpr> {
    if let Expr::Exists { subquery, negated } = expr {
        if *negated {
            return None;
        }

        let query = subquery.as_ref();
        let body = query.body.as_ref();

        if let sqlparser::ast::SetExpr::Select(select) = body {
            // Simple membership: one table, FK join + user filter
            if select.from.len() == 1 {
                let from = &select.from[0];
                let table_name = extract_table_name_from_table_factor(&from.relation)?;

                // Check if this table exists in schema via sql-traits
                if let Some(table) = db.table(None, &table_name) {
                    // Collect column names for analysis
                    let col_names: Vec<String> = table
                        .columns(db)
                        .map(|c| c.column_name().to_string())
                        .collect();

                    if let Some((fk_col, user_col, extra_predicate_sql)) =
                        extract_membership_columns(
                            select.as_ref(),
                            &table_name,
                            &col_names,
                            registry,
                        )
                    {
                        return Some(ClassifiedExpr {
                            pattern: PatternClass::P4ExistsMembership {
                                join_table: table_name,
                                fk_column: fk_col,
                                user_column: user_col,
                                extra_predicate_sql,
                            },
                            confidence: ConfidenceLevel::A,
                        });
                    }
                }
            }
        }
    }
    None
}

/// Try to recognize P4 via IN-subquery: `col IN (SELECT col FROM membership_table ...)`.
pub fn recognize_p4_in_subquery(
    expr: &Expr,
    db: &ParserDB,
    registry: &FunctionRegistry,
) -> Option<ClassifiedExpr> {
    if let Expr::InSubquery {
        expr: lhs,
        subquery,
        negated,
    } = expr
    {
        if *negated {
            return None;
        }

        // LHS should be a column reference (e.g. team_id)
        let lhs_col = extract_column_name(lhs)?;

        let query = subquery.as_ref();
        let body = query.body.as_ref();

        if let sqlparser::ast::SetExpr::Select(select) = body {
            if select.from.len() == 1 {
                let from = &select.from[0];
                let table_name = extract_table_name_from_table_factor(&from.relation)?;

                // Check if this table exists in schema
                if let Some(table) = db.table(None, &table_name) {
                    let col_names: Vec<String> = table
                        .columns(db)
                        .map(|c| c.column_name().to_string())
                        .collect();

                    let projected_col =
                        extract_projection_column(select.as_ref()).unwrap_or(lhs_col);
                    if let Some((_fk_col, user_col, extra_predicate_sql)) =
                        extract_membership_columns(
                            select.as_ref(),
                            &table_name,
                            &col_names,
                            registry,
                        )
                    {
                        return Some(ClassifiedExpr {
                            pattern: PatternClass::P4ExistsMembership {
                                join_table: table_name,
                                fk_column: projected_col,
                                user_column: user_col,
                                extra_predicate_sql,
                            },
                            confidence: ConfidenceLevel::A,
                        });
                    }
                }
            }
        }
    }
    None
}

/// Try to recognize P10: constant boolean policies (`TRUE` / `FALSE`).
pub fn recognize_p10_constant_bool(
    expr: &Expr,
    _db: &ParserDB,
    _registry: &FunctionRegistry,
) -> Option<ClassifiedExpr> {
    if let Expr::Value(v) = expr {
        if let Value::Boolean(b) = v.value {
            return Some(ClassifiedExpr {
                pattern: PatternClass::P10ConstantBool { value: b },
                confidence: ConfidenceLevel::A,
            });
        }
    }
    None
}

/// Try to recognize P6: boolean flag `is_public = TRUE` or bare boolean column.
pub fn recognize_p6(
    expr: &Expr,
    _db: &ParserDB,
    _registry: &FunctionRegistry,
) -> Option<ClassifiedExpr> {
    match expr {
        Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq,
            right,
        } => {
            // Check for `column = TRUE`
            let (col_name, is_true) = match (left.as_ref(), right.as_ref()) {
                (_, Expr::Value(v)) => {
                    let col = extract_column_name(left)?;
                    let is_t = matches!(v.value, Value::Boolean(true));
                    (col, is_t)
                }
                (Expr::Value(v), _) => {
                    let col = extract_column_name(right)?;
                    let is_t = matches!(v.value, Value::Boolean(true));
                    (col, is_t)
                }
                _ => return None,
            };

            if is_true
                && (col_name.contains("public")
                    || col_name.contains("published")
                    || col_name.contains("visible"))
            {
                return Some(ClassifiedExpr {
                    pattern: PatternClass::P6BooleanFlag { column: col_name },
                    confidence: ConfidenceLevel::A,
                });
            }
        }
        Expr::Identifier(ident) => {
            let col_name = ident.value.clone();
            if col_name.contains("public")
                || col_name.contains("published")
                || col_name.contains("visible")
            {
                return Some(ClassifiedExpr {
                    pattern: PatternClass::P6BooleanFlag { column: col_name },
                    confidence: ConfidenceLevel::A,
                });
            }
        }
        _ => {}
    }
    None
}

// ---- Helper functions ----

/// Extract a function name from an expression.
pub fn extract_function_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Function(func) => Some(func.name.to_string()),
        _ => None,
    }
}

/// Extract a simple column name from an expression.
pub fn extract_column_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Identifier(ident) => Some(ident.value.clone()),
        Expr::CompoundIdentifier(parts) => Some(parts.last()?.value.clone()),
        _ => None,
    }
}

/// Extract an integer value from an expression.
fn extract_integer_value(expr: &Expr) -> Option<i32> {
    if let Expr::Value(v) = expr {
        match &v.value {
            Value::Number(n, _) => n.parse().ok(),
            _ => None,
        }
    } else {
        None
    }
}

/// Extract a table name from a `TableFactor`.
fn extract_table_name_from_table_factor(tf: &sqlparser::ast::TableFactor) -> Option<String> {
    if let sqlparser::ast::TableFactor::Table { name, .. } = tf {
        Some(name.to_string())
    } else {
        None
    }
}

fn extract_projection_column(select: &Select) -> Option<String> {
    select.projection.first().and_then(|p| match p {
        SelectItem::UnnamedExpr(e) => extract_column_name(e),
        SelectItem::ExprWithAlias { expr, .. } => extract_column_name(expr),
        _ => None,
    })
}

fn extract_membership_columns(
    select: &Select,
    join_table: &str,
    join_cols: &[String],
    registry: &FunctionRegistry,
) -> Option<(String, String, Option<String>)> {
    let mut fk_col: Option<String> = None;
    let mut user_col: Option<String> = None;
    let mut extras: Vec<String> = Vec::new();

    if let Some(selection) = &select.selection {
        let mut predicates = Vec::new();
        flatten_and_predicates(selection, &mut predicates);

        for pred in predicates {
            if let Expr::BinaryOp {
                left,
                op: BinaryOperator::Eq,
                right,
            } = pred
            {
                let left_col = extract_qualified_column(left);
                let right_col = extract_qualified_column(right);

                // user_id = auth_current_user()
                if let Some((_, col)) = left_col.clone() {
                    if join_cols.contains(&col) && is_current_user_expr(right, registry) {
                        user_col = Some(col);
                        continue;
                    }
                }
                if let Some((_, col)) = right_col.clone() {
                    if join_cols.contains(&col) && is_current_user_expr(left, registry) {
                        user_col = Some(col);
                        continue;
                    }
                }

                // join_table_fk = outer_table_col
                if let (Some((left_qual, left_name)), Some((right_qual, right_name))) =
                    (left_col, right_col)
                {
                    let left_is_join = left_qual.as_deref().is_some_and(|q| q == join_table)
                        || (left_qual.is_none() && join_cols.contains(&left_name));
                    let right_is_join = right_qual.as_deref().is_some_and(|q| q == join_table)
                        || (right_qual.is_none() && join_cols.contains(&right_name));

                    if left_is_join && !right_is_join {
                        fk_col = Some(left_name);
                        continue;
                    }
                    if right_is_join && !left_is_join {
                        fk_col = Some(right_name);
                        continue;
                    }
                }
            }

            // Keep additional predicates for tuple filtering.
            extras.push(pred.to_string());
        }
    }

    if user_col.is_none() {
        user_col = join_cols
            .iter()
            .find(|c| c.contains("user_id") || c.contains("member_id"))
            .cloned();
    }

    if fk_col.is_none() {
        // Prefer any *_id other than the user column.
        fk_col = join_cols
            .iter()
            .find(|c| c.ends_with("_id") && Some(*c) != user_col.as_ref())
            .cloned();
    }

    let user_col = user_col?;
    let fk_col = fk_col?;

    let extra_predicate_sql = if extras.is_empty() {
        None
    } else {
        Some(extras.join(" AND "))
    };

    Some((fk_col, user_col, extra_predicate_sql))
}

fn flatten_and_predicates<'a>(expr: &'a Expr, out: &mut Vec<&'a Expr>) {
    if let Expr::BinaryOp {
        left,
        op: BinaryOperator::And,
        right,
    } = expr
    {
        flatten_and_predicates(left, out);
        flatten_and_predicates(right, out);
    } else {
        out.push(expr);
    }
}

fn extract_qualified_column(expr: &Expr) -> Option<(Option<String>, String)> {
    match expr {
        Expr::Identifier(id) => Some((None, id.value.clone())),
        Expr::CompoundIdentifier(parts) if parts.len() >= 2 => Some((
            Some(parts[parts.len() - 2].value.clone()),
            parts.last()?.value.clone(),
        )),
        _ => None,
    }
}

fn is_current_user_expr(expr: &Expr, registry: &FunctionRegistry) -> bool {
    match expr {
        Expr::Function(func) => {
            let name = func.name.to_string();
            registry.is_current_user_accessor(&name)
        }
        Expr::Cast { expr, .. } => is_current_user_expr(expr, registry),
        Expr::Nested(inner) => is_current_user_expr(inner, registry),
        _ => false,
    }
}

/// Check if an expression references a column that looks like an attribute
/// (not a user/owner reference).
pub fn is_attribute_check(expr: &Expr) -> Option<String> {
    if let Expr::BinaryOp { left, op, right } = expr {
        if matches!(
            op,
            BinaryOperator::Eq
                | BinaryOperator::NotEq
                | BinaryOperator::GtEq
                | BinaryOperator::LtEq
                | BinaryOperator::Gt
                | BinaryOperator::Lt
        ) {
            if let Some(col) = extract_column_name(left) {
                if is_literal_value(right) && !is_user_related_column(&col) {
                    return Some(col);
                }
            }
            if let Some(col) = extract_column_name(right) {
                if is_literal_value(left) && !is_user_related_column(&col) {
                    return Some(col);
                }
            }
        }
    }
    None
}

fn is_literal_value(expr: &Expr) -> bool {
    matches!(expr, Expr::Value(_))
}

fn is_user_related_column(col: &str) -> bool {
    let lower = col.to_lowercase();
    lower.contains("user_id")
        || lower.contains("owner_id")
        || lower.contains("created_by")
        || lower.contains("author_id")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::sql_parser::parse_schema;
    use sqlparser::ast::{SetExpr, Statement};
    use sqlparser::dialect::PostgreSqlDialect;
    use sqlparser::parser::Parser;

    fn parse_expr(expr_sql: &str) -> Expr {
        Parser::new(&PostgreSqlDialect {})
            .try_with_sql(expr_sql)
            .expect("expression should parse")
            .parse_expr()
            .expect("expression should parse")
    }

    fn parse_select(sql: &str) -> Select {
        let stmts = Parser::parse_sql(&PostgreSqlDialect {}, sql).expect("query should parse");
        let stmt = stmts.first().expect("expected one statement");
        let Statement::Query(query) = stmt else {
            panic!("expected query statement");
        };
        let SetExpr::Select(select) = query.body.as_ref() else {
            panic!("expected select body");
        };
        select.as_ref().clone()
    }

    fn db_with_docs_and_members() -> ParserDB {
        parse_schema(
            r"
CREATE TABLE docs (
  id UUID PRIMARY KEY,
  owner_id UUID,
  tenant_uuid UUID,
  is_public BOOLEAN,
  published BOOLEAN
);
CREATE TABLE doc_members (
  doc_id UUID,
  user_id UUID,
  member_id UUID,
  role TEXT
);
",
        )
        .expect("schema should parse")
    }

    fn registry_with_role_level() -> FunctionRegistry {
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
  "auth_current_user_id": {"kind":"current_user_accessor","returns":"uuid"}
}"#,
            )
            .expect("registry json should parse");
        registry
    }

    #[test]
    fn recognize_p1_supports_gt_and_rejects_unknown_functions() {
        let db = db_with_docs_and_members();
        let registry = registry_with_role_level();
        let expr = parse_expr("role_level(auth_current_user_id(), id) > 2");

        let classified =
            recognize_p1(&expr, &db, &registry, &PolicyCommand::Delete).expect("expected P1 match");
        assert!(matches!(
            &classified.pattern,
            PatternClass::P1NumericThreshold {
                function_name,
                operator: ThresholdOperator::Gt,
                threshold,
                command: PolicyCommand::Delete,
            } if function_name == "role_level" && *threshold == 2
        ));

        let unknown = parse_expr("unknown_role(auth_current_user_id(), id) >= 1");
        assert!(recognize_p1(&unknown, &db, &registry, &PolicyCommand::Select).is_none());
    }

    #[test]
    fn recognize_p2_handles_negation_and_literal_filtering() {
        let db = db_with_docs_and_members();
        let registry = registry_with_role_level();

        let negated = parse_expr("role_level(auth_current_user_id(), id) NOT IN ('viewer')");
        assert!(recognize_p2(&negated, &db, &registry).is_none());

        let non_threshold = parse_expr("unknown_role(auth_current_user_id(), id) IN ('viewer')");
        assert!(recognize_p2(&non_threshold, &db, &registry).is_none());

        let non_string_literals = parse_expr("role_level(auth_current_user_id(), id) IN (TRUE)");
        assert!(recognize_p2(&non_string_literals, &db, &registry).is_none());

        let ok = parse_expr("role_level(auth_current_user_id(), id) IN ('viewer', 2)");
        let classified = recognize_p2(&ok, &db, &registry).expect("expected P2 match");
        assert!(matches!(
            &classified.pattern,
            PatternClass::P2RoleNameInList {
                function_name,
                role_names,
            } if function_name == "role_level"
                && role_names == &vec!["viewer".to_string(), "2".to_string()]
        ));
    }

    #[test]
    fn recognize_p3_heuristics_cover_confidence_variants() {
        let db = db_with_docs_and_members();
        let registry = FunctionRegistry::new();

        let a = parse_expr("owner_id = auth_current_user_id()");
        let classified_a = recognize_p3(&a, &db, &registry).expect("expected heuristic match");
        assert_eq!(classified_a.confidence, ConfidenceLevel::A);

        let b = parse_expr("tenant_uuid = auth_current_user_id()");
        let classified_b = recognize_p3(&b, &db, &registry).expect("expected heuristic match");
        assert_eq!(classified_b.confidence, ConfidenceLevel::B);

        let none = parse_expr("tenant_uuid = actor_id()");
        assert!(
            recognize_p3(&none, &db, &registry).is_none(),
            "non-user-like function should not match ownership"
        );

        let not_eq = parse_expr("owner_id <> auth_current_user_id()");
        assert!(recognize_p3(&not_eq, &db, &registry).is_none());
    }

    #[test]
    fn recognize_p4_exists_supports_extra_predicates_and_negation() {
        let db = db_with_docs_and_members();
        let registry = registry_with_role_level();

        let negated = parse_expr(
            "NOT EXISTS (
               SELECT 1
               FROM doc_members
               WHERE doc_members.doc_id = docs.id
             )",
        );
        assert!(recognize_p4(&negated, &db, &registry).is_none());

        let exists_expr = parse_expr(
            "EXISTS (
               SELECT 1
               FROM doc_members
               WHERE doc_members.doc_id = docs.id
                 AND doc_members.user_id = auth_current_user_id()
                 AND doc_members.role = 'admin'
             )",
        );
        let classified = recognize_p4(&exists_expr, &db, &registry).expect("expected P4 match");
        assert!(matches!(
            &classified.pattern,
            PatternClass::P4ExistsMembership {
                join_table,
                fk_column,
                user_column,
                extra_predicate_sql,
            } if join_table == "doc_members"
                && fk_column == "doc_id"
                && user_column == "user_id"
                && extra_predicate_sql
                    .as_deref()
                    .is_some_and(|s| s.contains("doc_members.role = 'admin'"))
        ));
    }

    #[test]
    fn recognize_p4_in_subquery_handles_negation_and_projection_alias() {
        let db = db_with_docs_and_members();
        let registry = registry_with_role_level();

        let negated = parse_expr(
            "doc_id NOT IN (
               SELECT dm.doc_id
               FROM doc_members dm
               WHERE dm.user_id = auth_current_user_id()
             )",
        );
        assert!(recognize_p4_in_subquery(&negated, &db, &registry).is_none());

        let in_subquery = parse_expr(
            "doc_id IN (
               SELECT dm.doc_id AS projected_doc
               FROM doc_members dm
               WHERE dm.user_id = auth_current_user_id()
             )",
        );
        let classified =
            recognize_p4_in_subquery(&in_subquery, &db, &registry).expect("expected match");
        assert!(matches!(
            &classified.pattern,
            PatternClass::P4ExistsMembership {
                fk_column,
                user_column,
                ..
            } if fk_column == "doc_id" && user_column == "user_id"
        ));
    }

    #[test]
    fn recognize_p10_and_p6_cover_non_matching_variants() {
        let db = db_with_docs_and_members();
        let registry = FunctionRegistry::new();

        let p10_true = parse_expr("TRUE");
        assert!(recognize_p10_constant_bool(&p10_true, &db, &registry).is_some());

        let p10_not_bool = parse_expr("1");
        assert!(recognize_p10_constant_bool(&p10_not_bool, &db, &registry).is_none());

        let p6_false = parse_expr("FALSE = is_public");
        assert!(recognize_p6(&p6_false, &db, &registry).is_none());

        let p6_ident = parse_expr("published");
        assert!(recognize_p6(&p6_ident, &db, &registry).is_some());

        let p6_non_public = parse_expr("private_flag");
        assert!(recognize_p6(&p6_non_public, &db, &registry).is_none());
    }

    #[test]
    fn extractor_helpers_and_attribute_detection_work_for_edge_cases() {
        let fun = parse_expr("auth_current_user_id()");
        assert_eq!(
            extract_function_name(&fun).as_deref(),
            Some("auth_current_user_id")
        );

        let id_expr = parse_expr("owner_id");
        assert!(extract_function_name(&id_expr).is_none());

        let qualified = parse_expr("docs.owner_id");
        assert_eq!(extract_column_name(&qualified).as_deref(), Some("owner_id"));
        assert_eq!(
            extract_qualified_column(&qualified),
            Some((Some("docs".to_string()), "owner_id".to_string()))
        );

        let simple = parse_expr("owner_id");
        assert_eq!(
            extract_qualified_column(&simple),
            Some((None, "owner_id".to_string()))
        );

        let attr = parse_expr("priority >= 3");
        assert_eq!(is_attribute_check(&attr).as_deref(), Some("priority"));

        let user_attr = parse_expr("user_id = 'x'");
        assert!(is_attribute_check(&user_attr).is_none());

        let non_literal = parse_expr("status = other_status");
        assert!(is_attribute_check(&non_literal).is_none());
    }

    #[test]
    fn membership_column_extraction_falls_back_when_join_predicates_missing() {
        let select = parse_select(
            "SELECT dm.doc_id
             FROM doc_members dm
             WHERE dm.role = 'admin'",
        );
        let registry = registry_with_role_level();
        let cols = vec![
            "doc_id".to_string(),
            "member_id".to_string(),
            "role".to_string(),
        ];

        let extracted = extract_membership_columns(&select, "doc_members", &cols, &registry)
            .expect("fallback should infer membership columns");
        assert_eq!(extracted.0, "doc_id");
        assert_eq!(extracted.1, "member_id");
        assert!(extracted
            .2
            .as_deref()
            .is_some_and(|s| s.contains("dm.role = 'admin'")));
    }

    #[test]
    fn table_and_projection_extractors_cover_non_table_and_alias_paths() {
        let table_select = parse_select("SELECT dm.doc_id AS projected FROM doc_members dm");
        let from = &table_select.from[0];
        let table_name = extract_table_name_from_table_factor(&from.relation)
            .expect("table factor should resolve");
        assert_eq!(table_name, "doc_members");
        assert_eq!(
            extract_projection_column(&table_select).as_deref(),
            Some("doc_id")
        );

        let derived_select = parse_select("SELECT x.id FROM (SELECT 1 AS id) x WHERE x.id = 1");
        let derived_from = &derived_select.from[0];
        assert!(
            extract_table_name_from_table_factor(&derived_from.relation).is_none(),
            "derived table should not resolve to a table name"
        );
    }

    #[test]
    fn current_user_expr_detection_supports_cast_and_nested() {
        let registry = registry_with_role_level();
        let nested = parse_expr("(auth_current_user_id())");
        let casted = parse_expr("CAST(auth_current_user_id() AS UUID)");
        let other = parse_expr("owner_id");

        assert!(is_current_user_expr(&nested, &registry));
        assert!(is_current_user_expr(&casted, &registry));
        assert!(!is_current_user_expr(&other, &registry));
    }

    #[test]
    fn extract_projection_column_returns_none_for_wildcard() {
        let select = parse_select("SELECT * FROM doc_members");
        assert!(extract_projection_column(&select).is_none());
    }

    #[test]
    fn is_attribute_check_supports_literal_on_left_and_not_equal_operator() {
        let reverse_literal = parse_expr("3 <= priority");
        assert_eq!(
            is_attribute_check(&reverse_literal).as_deref(),
            Some("priority")
        );

        let not_equal = parse_expr("status <> 'draft'");
        assert_eq!(is_attribute_check(&not_equal).as_deref(), Some("status"));
    }

    #[test]
    fn extract_membership_columns_detects_reversed_predicates() {
        let select = parse_select(
            "SELECT dm.doc_id
             FROM doc_members dm
             WHERE auth_current_user_id() = dm.user_id
               AND docs.id = dm.doc_id",
        );
        let registry = registry_with_role_level();
        let cols = vec![
            "doc_id".to_string(),
            "user_id".to_string(),
            "role".to_string(),
        ];

        let extracted = extract_membership_columns(&select, "doc_members", &cols, &registry)
            .expect("reversed predicates should still infer membership columns");
        assert_eq!(extracted.0, "doc_id");
        assert_eq!(extracted.1, "user_id");
    }

    #[test]
    fn recognize_p1_rejects_non_numeric_threshold_expressions() {
        let db = db_with_docs_and_members();
        let registry = registry_with_role_level();

        let bool_threshold = parse_expr("role_level(auth_current_user_id(), id) >= TRUE");
        assert!(recognize_p1(&bool_threshold, &db, &registry, &PolicyCommand::Select).is_none());

        let non_value_threshold = parse_expr("role_level(auth_current_user_id(), id) >= owner_id");
        assert!(
            recognize_p1(&non_value_threshold, &db, &registry, &PolicyCommand::Select).is_none()
        );
    }

    #[test]
    fn recognize_p2_ignores_non_literal_in_list_items() {
        let db = db_with_docs_and_members();
        let registry = registry_with_role_level();

        let expr = parse_expr("role_level(auth_current_user_id(), id) IN (owner_id)");
        assert!(recognize_p2(&expr, &db, &registry).is_none());
    }

    #[test]
    fn recognize_p3_accepts_function_on_left_side() {
        let db = db_with_docs_and_members();
        let registry = FunctionRegistry::new();

        let expr = parse_expr("auth_current_user_id() = owner_id");
        let classified = recognize_p3(&expr, &db, &registry).expect("expected ownership match");
        assert!(matches!(
            &classified.pattern,
            PatternClass::P3DirectOwnership { column } if column == "owner_id"
        ));
    }

    #[test]
    fn recognize_p4_and_in_subquery_fail_when_membership_columns_cannot_be_inferred() {
        let db = parse_schema(
            r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE odd_members(alpha text, beta text);
",
        )
        .expect("schema should parse");
        let registry = registry_with_role_level();

        let exists_expr = parse_expr(
            "EXISTS (
               SELECT 1
               FROM odd_members
               WHERE odd_members.alpha = 'x'
             )",
        );
        assert!(recognize_p4(&exists_expr, &db, &registry).is_none());

        let in_subquery_expr = parse_expr(
            "id IN (
               SELECT odd_members.alpha
               FROM odd_members
               WHERE odd_members.beta = 'x'
             )",
        );
        assert!(recognize_p4_in_subquery(&in_subquery_expr, &db, &registry).is_none());
    }

    #[test]
    fn recognize_p4_and_in_subquery_fail_for_unknown_or_unsupported_subqueries() {
        let db = db_with_docs_and_members();
        let registry = registry_with_role_level();

        let unknown_table = parse_expr(
            "EXISTS (
               SELECT 1
               FROM ghost_members
               WHERE ghost_members.doc_id = docs.id
             )",
        );
        assert!(recognize_p4(&unknown_table, &db, &registry).is_none());

        let unsupported = parse_expr(
            "doc_id IN (
               (SELECT dm.doc_id FROM doc_members dm)
               UNION
               (SELECT dm.doc_id FROM doc_members dm)
             )",
        );
        assert!(recognize_p4_in_subquery(&unsupported, &db, &registry).is_none());
    }

    #[test]
    fn recognize_p4_and_in_subquery_reject_multi_from_subqueries() {
        let db = db_with_docs_and_members();
        let registry = registry_with_role_level();

        let exists_multi_from = parse_expr(
            "EXISTS (
               SELECT 1
               FROM doc_members dm, docs d
               WHERE dm.doc_id = d.id
             )",
        );
        assert!(recognize_p4(&exists_multi_from, &db, &registry).is_none());

        let in_multi_from = parse_expr(
            "doc_id IN (
               SELECT dm.doc_id
               FROM doc_members dm, docs d
               WHERE dm.user_id = auth_current_user_id()
             )",
        );
        assert!(recognize_p4_in_subquery(&in_multi_from, &db, &registry).is_none());
    }

    #[test]
    fn recognize_p6_covers_visible_branch_and_non_literal_binary_case() {
        let db = db_with_docs_and_members();
        let registry = FunctionRegistry::new();

        let visible = parse_expr("visible = TRUE");
        let classified = recognize_p6(&visible, &db, &registry).expect("expected visible match");
        assert!(matches!(
            &classified.pattern,
            PatternClass::P6BooleanFlag { column } if column == "visible"
        ));

        let non_literal = parse_expr("is_public = owner_id");
        assert!(recognize_p6(&non_literal, &db, &registry).is_none());
    }

    #[test]
    fn extract_membership_columns_covers_right_join_side_and_extra_predicates() {
        let select = parse_select(
            "SELECT dm.doc_id
             FROM doc_members dm
             WHERE auth_current_user_id() = dm.user_id
               AND docs.id = doc_id
               AND dm.role > 'a'",
        );
        let registry = registry_with_role_level();
        let cols = vec![
            "doc_id".to_string(),
            "user_id".to_string(),
            "role".to_string(),
        ];

        let extracted = extract_membership_columns(&select, "doc_members", &cols, &registry)
            .expect("columns should still be inferred");
        assert_eq!(extracted.0, "doc_id");
        assert_eq!(extracted.1, "user_id");
        assert!(extracted
            .2
            .as_deref()
            .is_some_and(|s| s.contains("dm.role > 'a'")));
    }

    #[test]
    fn extract_membership_columns_handles_queries_without_selection() {
        let select = parse_select("SELECT dm.doc_id FROM doc_members dm");
        let registry = registry_with_role_level();
        let cols = vec![
            "doc_id".to_string(),
            "user_id".to_string(),
            "role".to_string(),
        ];

        let extracted = extract_membership_columns(&select, "doc_members", &cols, &registry)
            .expect("fallback should infer columns even without WHERE");
        assert_eq!(extracted.0, "doc_id");
        assert_eq!(extracted.1, "user_id");
        assert!(extracted.2.is_none());
    }

    #[test]
    fn is_attribute_check_rejects_unsupported_operators() {
        let like_expr = parse_expr("status LIKE 'draft%'");
        assert!(is_attribute_check(&like_expr).is_none());
    }

    #[test]
    fn parse_select_panics_for_non_query_and_non_select_body() {
        let non_query = std::panic::catch_unwind(|| parse_select("DELETE FROM doc_members"));
        assert!(non_query.is_err());

        let non_select = std::panic::catch_unwind(|| parse_select("VALUES (1)"));
        assert!(non_select.is_err());
    }
}

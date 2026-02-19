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

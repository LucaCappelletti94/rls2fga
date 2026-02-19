use sqlparser::ast::{BinaryOperator, Expr, Value};

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
        if !matches!(op, BinaryOperator::GtEq | BinaryOperator::Gt) {
            return None;
        }

        let func_name = extract_function_name(left)?;
        if !registry.is_role_threshold(&func_name) {
            return None;
        }

        let threshold = extract_integer_value(right)?;

        return Some(ClassifiedExpr {
            pattern: PatternClass::P1NumericThreshold {
                function_name: func_name,
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
    _registry: &FunctionRegistry,
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

                    let has_user_col = col_names
                        .iter()
                        .any(|n| n.contains("user_id") || n.contains("member_id"));

                    if has_user_col {
                        let fk_col = col_names
                            .iter()
                            .find(|n| {
                                n.contains("team_id")
                                    || n.contains("group_id")
                                    || n.contains("org_id")
                            })
                            .cloned()
                            .unwrap_or_else(|| "team_id".to_string());

                        let user_col = col_names
                            .iter()
                            .find(|n| n.contains("user_id") || n.contains("member_id"))
                            .cloned()
                            .unwrap_or_else(|| "user_id".to_string());

                        return Some(ClassifiedExpr {
                            pattern: PatternClass::P4ExistsMembership {
                                join_table: table_name,
                                fk_column: fk_col,
                                user_column: user_col,
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
    _registry: &FunctionRegistry,
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
        let _lhs_col = extract_column_name(lhs)?;

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

                    let has_user_col = col_names
                        .iter()
                        .any(|n| n.contains("user_id") || n.contains("member_id"));

                    if has_user_col {
                        let fk_col = col_names
                            .iter()
                            .find(|n| {
                                n.contains("team_id")
                                    || n.contains("group_id")
                                    || n.contains("org_id")
                            })
                            .cloned()
                            .unwrap_or_else(|| "team_id".to_string());

                        let user_col = col_names
                            .iter()
                            .find(|n| n.contains("user_id") || n.contains("member_id"))
                            .cloned()
                            .unwrap_or_else(|| "user_id".to_string());

                        return Some(ClassifiedExpr {
                            pattern: PatternClass::P4ExistsMembership {
                                join_table: table_name,
                                fk_column: fk_col,
                                user_column: user_col,
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

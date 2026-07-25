use super::*;

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
                if is_literal_or_temporal(right) && !is_user_related_column_name(&col) {
                    return Some(col);
                }
            }
            if let Some(col) = extract_column_name(right) {
                if is_literal_or_temporal(left) && !is_user_related_column_name(&col) {
                    return Some(col);
                }
            }
        }
    }
    // `col IN ('a', 'b', ...)` with all-literal items (non-negated).
    if let Expr::InList {
        expr: col_expr,
        list,
        negated: false,
    } = expr
    {
        if let Some(col) = extract_column_name(col_expr) {
            if !is_user_related_column_name(&col)
                && !list.is_empty()
                && list.iter().all(is_literal_value)
            {
                return Some(col);
            }
        }
    }
    // `col IS NOT DISTINCT FROM value` / `col IS DISTINCT FROM value`
    if let Expr::IsNotDistinctFrom(left, right) | Expr::IsDistinctFrom(left, right) = expr {
        if let Some(col) = extract_column_name(left) {
            if is_literal_or_temporal(right) && !is_user_related_column_name(&col) {
                return Some(col);
            }
        }
        if let Some(col) = extract_column_name(right) {
            if is_literal_or_temporal(left) && !is_user_related_column_name(&col) {
                return Some(col);
            }
        }
    }
    // `col BETWEEN low AND high` (non-negated, both bounds literal or temporal).
    if let Expr::Between {
        expr: col_expr,
        low,
        high,
        negated: false,
    } = expr
    {
        if let Some(col) = extract_column_name(col_expr) {
            if !is_user_related_column_name(&col)
                && is_literal_or_temporal(low)
                && is_literal_or_temporal(high)
            {
                return Some(col);
            }
        }
    }
    // `col IS NULL` / `col IS NOT NULL`
    if let Expr::IsNull(col_expr) | Expr::IsNotNull(col_expr) = expr {
        if let Some(col) = extract_column_name(col_expr) {
            if !is_user_related_column_name(&col) {
                return Some(col);
            }
        }
    }
    // `col LIKE pattern` / `col ILIKE pattern` (non-negated)
    if let Expr::Like {
        negated: false,
        expr: col_expr,
        ..
    }
    | Expr::ILike {
        negated: false,
        expr: col_expr,
        ..
    } = expr
    {
        if let Some(col) = extract_column_name(col_expr) {
            if !is_user_related_column_name(&col) {
                return Some(col);
            }
        }
    }
    None
}

fn is_literal_value(expr: &Expr) -> bool {
    match expr {
        Expr::Value(_) => true,
        Expr::Nested(inner)
        | Expr::Cast { expr: inner, .. }
        | Expr::UnaryOp {
            op: UnaryOperator::Plus | UnaryOperator::Minus | UnaryOperator::Not,
            expr: inner,
        } => is_literal_value(inner),
        _ => false,
    }
}

/// Returns `true` when the expression is a literal value or a well-known
/// temporal function call (e.g. `now()`, `current_timestamp`).  Used in
/// `is_attribute_check` so that `valid_until > now()` is recognised as an
/// attribute condition rather than falling through to Unknown.
fn is_literal_or_temporal(expr: &Expr) -> bool {
    if is_literal_value(expr) {
        return true;
    }
    is_well_known_temporal_function(expr)
}

/// Recognise zero-arg temporal built-in functions that produce a deterministic
/// (within a statement) date/time value.
fn is_well_known_temporal_function(expr: &Expr) -> bool {
    let Expr::Function(func) = unwrap_cast_or_nested(expr) else {
        return false;
    };
    let name = normalized_function_name(func);
    matches!(
        name.as_str(),
        "now"
            | "current_timestamp"
            | "current_date"
            | "current_time"
            | "clock_timestamp"
            | "statement_timestamp"
            | "transaction_timestamp"
            | "localtime"
            | "localtimestamp"
    )
}

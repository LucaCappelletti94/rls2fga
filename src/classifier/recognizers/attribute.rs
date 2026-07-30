use super::*;

/// Column name compared in a non-user attribute guard, if `expr` is one.
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
    if let Some(guard) = is_document_attribute_check(expr) {
        return Some(guard);
    }
    None
}

/// A jsonb field or array column compared against a literal, described for the operator.
///
/// Same job as the column forms above: the value is not the caller, so no tuple can
/// carry it. Recognising it keeps `owner_id = caller AND data ->> 'k' = 'v'` behaving
/// like `owner_id = caller AND status = 'v'` instead of collapsing to a denial.
fn is_document_attribute_check(expr: &Expr) -> Option<String> {
    let Expr::BinaryOp { left, op, right } = expr else {
        return None;
    };

    // `data ->> 'status' = 'published'`, in either operand order.
    if matches!(
        op,
        BinaryOperator::Eq
            | BinaryOperator::NotEq
            | BinaryOperator::GtEq
            | BinaryOperator::LtEq
            | BinaryOperator::Gt
            | BinaryOperator::Lt
    ) {
        for (path_side, value_side) in [(left, right), (right, left)] {
            if is_literal_or_temporal(value_side) {
                if let Some(guard) = describe_jsonb_path_guard(path_side) {
                    return Some(guard);
                }
            }
        }
    }

    // Containment and overlap against a literal document or array literal.
    if matches!(
        op,
        BinaryOperator::AtArrow | BinaryOperator::ArrowAt | BinaryOperator::PGOverlap
    ) {
        for (column_side, other_side) in [(left, right), (right, left)] {
            if !is_literal_container(other_side) && extract_column_name(other_side).is_none() {
                continue;
            }
            if let Some(col) = extract_column_name(unwrap_cast_or_nested(column_side)) {
                if !is_user_related_column_name(&col) {
                    return Some(col);
                }
            }
        }
    }
    None
}

/// `data -> meta ->> status` for a jsonb text extraction whose field is not user
/// related, matching the refusal `is_attribute_check` already makes for such a column.
fn describe_jsonb_path_guard(expr: &Expr) -> Option<String> {
    let (column, path) = jsonb_text_path(expr)?;
    if is_user_related_column_name(path.last()?) {
        return None;
    }
    Some(format!("{column} ->> {}", path.join(" -> ")))
}

/// A literal, or an array literal whose every element is a literal.
///
/// A caller expression is a function call, so it never qualifies, which keeps
/// `ARRAY[current_user] && editors` out of the attribute path and in the relationship
/// one regardless of the order the two are tried in.
fn is_literal_container(expr: &Expr) -> bool {
    match unwrap_cast_or_nested(expr) {
        Expr::Array(array) => array.elem.iter().all(is_literal_value),
        other => is_literal_value(other),
    }
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

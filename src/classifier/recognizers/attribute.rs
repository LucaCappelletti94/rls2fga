use super::*;

/// The guard as structure when the compared value is one only the request knows.
///
/// `expires_at > now()` is decided by the row and the clock together, so it becomes a
/// condition the authorization service evaluates per check rather than a tuple.
pub fn attribute_request_predicate(expr: &Expr) -> Option<AttributeRequestPredicate> {
    let Expr::BinaryOp { left, op, right } = unparenthesize(expr) else {
        return None;
    };
    let operator = attribute_operator(op)?;
    if let Some(column) = extract_column_name(left) {
        if is_well_known_temporal_function(right) && !is_user_related_column_name(column.as_str()) {
            return Some(AttributeRequestPredicate {
                column,
                operator,
                request_value: RequestValue::StatementTimestamp,
            });
        }
    }
    let column = extract_column_name(right)?;
    if !is_well_known_temporal_function(left) || is_user_related_column_name(column.as_str()) {
        return None;
    }
    Some(AttributeRequestPredicate {
        column,
        operator: mirrored(operator),
        request_value: RequestValue::StatementTimestamp,
    })
}

/// The guard as structure, but only when the compared value is a literal constant.
///
/// [`is_attribute_check`] deliberately also accepts a well-known temporal function,
/// so `expires_at > now()` is an attribute guard too. That one is not decided by the
/// row: a tuple emitted for the rows qualifying today still grants access tomorrow.
/// So this returns `None` for it, and only a literal constant reaches the emission
/// that turns a guard into tuples.
pub fn attribute_literal_predicate(expr: &Expr) -> Option<AttributePredicate> {
    let Expr::BinaryOp { left, op, right } = unparenthesize(expr) else {
        return None;
    };
    let operator = attribute_operator(op)?;
    // The column may sit on either side, and the operator flips with it so the
    // predicate always reads column-first.
    if let Some(column) = extract_column_name(left) {
        if let Some(value) = attribute_literal(right) {
            if !is_user_related_column_name(column.as_str()) {
                return Some(AttributePredicate {
                    column,
                    operator,
                    value,
                });
            }
        }
    }
    let column = extract_column_name(right)?;
    let value = attribute_literal(left)?;
    if is_user_related_column_name(column.as_str()) {
        return None;
    }
    Some(AttributePredicate {
        column,
        operator: mirrored(operator),
        value,
    })
}

/// The residual conjunct paired with its structure, where a row image alone
/// decides it.
///
/// Anything else keeps only its SQL, and the shape carrying it keeps its
/// query, so an inexpressible residual costs coverage rather than
/// correctness. A bare column is the boolean test SQL makes of it, and a
/// comparison is taken only against a literal constant, so `expires_at >
/// now()` stays SQL: a row admitted today may not be admitted tomorrow, and
/// no change event fires when the clock moves.
pub fn residual_predicate(expr: &Expr) -> ResidualPredicate {
    ResidualPredicate {
        sql: expr.to_string(),
        guard: residual_guard(expr),
    }
}

fn residual_guard(expr: &Expr) -> Option<ResidualGuard> {
    let inner = unparenthesize(expr);
    if let Expr::IsNotNull(operand) = inner {
        return extract_column_name(operand).map(ResidualGuard::NotNull);
    }
    if let Some(column) = extract_column_name(inner) {
        return Some(ResidualGuard::IsTrue(column));
    }
    attribute_literal_predicate(inner).map(ResidualGuard::Compare)
}

fn attribute_operator(op: &BinaryOperator) -> Option<AttributeOperator> {
    match op {
        BinaryOperator::Eq => Some(AttributeOperator::Eq),
        BinaryOperator::NotEq => Some(AttributeOperator::NotEq),
        BinaryOperator::Gt => Some(AttributeOperator::Gt),
        BinaryOperator::GtEq => Some(AttributeOperator::GtEq),
        BinaryOperator::Lt => Some(AttributeOperator::Lt),
        BinaryOperator::LtEq => Some(AttributeOperator::LtEq),
        _ => None,
    }
}

/// The operator reading the other way round, for `3 <= priority`.
fn mirrored(operator: AttributeOperator) -> AttributeOperator {
    match operator {
        AttributeOperator::Eq => AttributeOperator::Eq,
        AttributeOperator::NotEq => AttributeOperator::NotEq,
        AttributeOperator::Gt => AttributeOperator::Lt,
        AttributeOperator::GtEq => AttributeOperator::LtEq,
        AttributeOperator::Lt => AttributeOperator::Gt,
        AttributeOperator::LtEq => AttributeOperator::GtEq,
    }
}

/// A literal constant, and nothing a function or the clock supplies.
fn attribute_literal(expr: &Expr) -> Option<AttributeLiteral> {
    let Expr::Value(value) = unwrap_cast_or_nested(expr) else {
        return None;
    };
    match &value.value {
        Value::SingleQuotedString(text) => Some(AttributeLiteral::Text(text.clone())),
        Value::Number(number, _) => Some(AttributeLiteral::Number(number.clone())),
        Value::Boolean(flag) => Some(AttributeLiteral::Boolean(*flag)),
        _ => None,
    }
}

/// Column name compared in a non-user attribute guard, if `expr` is one.
pub fn is_attribute_check(expr: &Expr) -> Option<ColumnName> {
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
                if is_literal_or_temporal(right) && !is_user_related_column_name(col.as_str()) {
                    return Some(col);
                }
            }
            if let Some(col) = extract_column_name(right) {
                if is_literal_or_temporal(left) && !is_user_related_column_name(col.as_str()) {
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
            if !is_user_related_column_name(col.as_str())
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
            if is_literal_or_temporal(right) && !is_user_related_column_name(col.as_str()) {
                return Some(col);
            }
        }
        if let Some(col) = extract_column_name(right) {
            if is_literal_or_temporal(left) && !is_user_related_column_name(col.as_str()) {
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
            if !is_user_related_column_name(col.as_str())
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
            if !is_user_related_column_name(col.as_str()) {
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
            if !is_user_related_column_name(col.as_str()) {
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
fn is_document_attribute_check(expr: &Expr) -> Option<ColumnName> {
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
                if !is_user_related_column_name(col.as_str()) {
                    return Some(col);
                }
            }
        }
    }
    None
}

/// `data -> meta ->> status` for a jsonb text extraction whose field is not user
/// related, matching the refusal `is_attribute_check` already makes for such a column.
fn describe_jsonb_path_guard(expr: &Expr) -> Option<ColumnName> {
    let (column, path) = jsonb_text_path(expr)?;
    if is_user_related_column_name(path.last()?) {
        return None;
    }
    Some(ColumnName::from_stored(format!(
        "{column} ->> {}",
        path.join(" -> ")
    )))
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

use sqlparser::ast::{BinaryOperator, Expr, Select, SelectItem, TableFactor, UnaryOperator, Value};

use crate::classifier::function_registry::FunctionRegistry;
use crate::classifier::patterns::*;
pub use crate::parser::expr::extract_column_name;
use crate::parser::names::{
    is_owner_like_column_name, is_public_flag_column_name, is_user_related_column_name,
    lookup_table, normalize_relation_name, split_schema_and_relation,
};
use crate::parser::sql_parser::{ColumnLike, DatabaseLike, ForeignKeyLike, ParserDB, TableLike};

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
            BinaryOperator::LtEq => (right.as_ref(), left.as_ref(), ThresholdOperator::Gte),
            BinaryOperator::Lt => (right.as_ref(), left.as_ref(), ThresholdOperator::Gt),
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
    let (left, right) = match expr {
        Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq,
            right,
        }
        | Expr::IsNotDistinctFrom(left, right) => (left.as_ref(), right.as_ref()),
        _ => return None,
    };

    // Try column = accessor_expr or accessor_expr = column.
    let (col_name, accessor_name) = if let (Some(col), Some(accessor)) =
        (extract_column_name(left), current_user_accessor_name(right))
    {
        (col, accessor)
    } else if let (Some(accessor), Some(col)) =
        (current_user_accessor_name(left), extract_column_name(right))
    {
        (col, accessor)
    } else {
        return None;
    };

    // Determine how we matched the accessor and assign confidence accordingly.
    let is_registry_confirmed = registry.is_current_user_accessor(&accessor_name);
    let accessor_lower = accessor_name.to_lowercase();
    let is_sql_keyword = is_current_user_keyword(&accessor_lower);

    if !is_registry_confirmed && !is_sql_keyword {
        // Heuristic accessor name check
        if !accessor_lower.contains("current_user") && !accessor_lower.contains("auth") {
            return None;
        }

        // Heuristic match: require column name to look ownership-related
        if is_owner_like_column_name(&col_name) {
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
    Some(ClassifiedExpr {
        pattern: PatternClass::P3DirectOwnership { column: col_name },
        confidence: ConfidenceLevel::A,
    })
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
            return classify_membership_select(select.as_ref(), db, registry, None);
        }
    }
    None
}

/// Try to recognize P5: parent inheritance via correlated EXISTS on parent table.
pub fn recognize_p5(
    expr: &Expr,
    db: &ParserDB,
    registry: &FunctionRegistry,
    outer_table: &str,
    command: &PolicyCommand,
) -> Option<ClassifiedExpr> {
    if let Expr::Exists { subquery, negated } = expr {
        if *negated {
            return None;
        }

        let query = subquery.as_ref();
        let sqlparser::ast::SetExpr::Select(select) = query.body.as_ref() else {
            return None;
        };
        let sources = relation_sources(select.as_ref());
        if sources.is_empty() {
            return None;
        }
        let outer_table_meta = lookup_table(db, outer_table)?;
        let selection = select.selection.as_ref()?;

        let outer_cols: Vec<String> = outer_table_meta
            .columns(db)
            .map(|c| c.column_name().to_string())
            .collect();

        let mut predicates = Vec::new();
        flatten_and_predicates(selection, &mut predicates);

        let mut matches = Vec::new();
        for source in sources {
            let Some(parent_table) = lookup_table(db, &source.table_name) else {
                continue;
            };
            let parent_cols: Vec<String> = parent_table
                .columns(db)
                .map(|c| c.column_name().to_string())
                .collect();

            let mut fk_column: Option<String> = None;
            let mut inner_predicates: Vec<Expr> = Vec::new();
            let mut invalid_join = false;

            for pred in &predicates {
                if let Some((outer_fk, _parent_col)) = extract_parent_join_columns(
                    pred,
                    outer_table,
                    &outer_cols,
                    &source.table_name,
                    source.alias.as_deref(),
                    &parent_cols,
                ) {
                    if fk_column
                        .as_ref()
                        .is_none_or(|existing| existing == &outer_fk)
                    {
                        fk_column = Some(outer_fk);
                        continue;
                    }
                    invalid_join = true;
                    break;
                }
                inner_predicates.push((*pred).clone());
            }

            if invalid_join {
                continue;
            }
            let Some(fk_column) = fk_column else {
                continue;
            };
            if inner_predicates.is_empty() {
                continue;
            }
            if !table_has_fk_to_parent(outer_table_meta, db, &fk_column, &source.table_name) {
                continue;
            }

            let Some(inner_expr) = combine_predicates_with_and(inner_predicates) else {
                continue;
            };
            let inner_classified = crate::classifier::policy_classifier::classify_expr(
                &inner_expr,
                db,
                registry,
                &source.table_name,
                command,
            );
            // Only accept user-resource relationship patterns as inner patterns.
            // Attribute checks (P6, P9, P10) do not represent a relationship
            // between a user and the parent resource and must not become P5.
            if !matches!(
                inner_classified.pattern,
                PatternClass::P1NumericThreshold { .. }
                    | PatternClass::P2RoleNameInList { .. }
                    | PatternClass::P3DirectOwnership { .. }
                    | PatternClass::P4ExistsMembership { .. }
                    | PatternClass::P5ParentInheritance { .. }
                    | PatternClass::P7AbacAnd { .. }
                    | PatternClass::P8Composite { .. }
            ) {
                continue;
            }

            matches.push(ClassifiedExpr {
                confidence: inner_classified.confidence,
                pattern: PatternClass::P5ParentInheritance {
                    parent_table: source.table_name,
                    fk_column,
                    inner_pattern: Box::new(inner_classified),
                },
            });
        }

        if matches.len() == 1 {
            return matches.into_iter().next();
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
            let projected_col = extract_projection_column(select.as_ref()).unwrap_or(lhs_col);
            return classify_membership_select(select.as_ref(), db, registry, Some(projected_col));
        }
    }
    None
}

fn classify_membership_select(
    select: &Select,
    db: &ParserDB,
    registry: &FunctionRegistry,
    projected_fk: Option<String>,
) -> Option<ClassifiedExpr> {
    // Fail closed when the same table appears more than once (self-join).
    // Self-joins add constraints we cannot express as static membership tuples;
    // accepting them would produce tuples more permissive than the original policy.
    let all_sources = relation_sources(select);
    let unique_table_count = all_sources
        .iter()
        .map(|s| normalize_relation_name(&s.table_name))
        .collect::<std::collections::HashSet<_>>()
        .len();
    if unique_table_count != all_sources.len() {
        return None;
    }

    let matches = membership_matches(select, db, registry, projected_fk.as_deref());
    if matches.len() != 1 {
        return None;
    }

    let (join_table, inferred_fk_column, user_column, extra_predicate_sql) =
        matches.into_iter().next()?;

    Some(ClassifiedExpr {
        pattern: PatternClass::P4ExistsMembership {
            join_table,
            fk_column: projected_fk.unwrap_or(inferred_fk_column),
            user_column,
            extra_predicate_sql,
        },
        confidence: ConfidenceLevel::A,
    })
}

pub(crate) fn diagnose_p4_membership_ambiguity(
    expr: &Expr,
    db: &ParserDB,
    registry: &FunctionRegistry,
) -> Option<String> {
    fn diagnose_select(
        select: &Select,
        db: &ParserDB,
        registry: &FunctionRegistry,
        projected_fk: Option<&str>,
    ) -> Option<String> {
        let matches = membership_matches(select, db, registry, projected_fk);
        if matches.len() > 1 {
            return Some(
                "Ambiguous membership pattern: multiple candidate membership sources matched"
                    .to_string(),
            );
        }
        if matches.is_empty() && selection_references_current_user(select, registry) {
            return Some(
                "Ambiguous membership pattern: could not infer a unique membership join"
                    .to_string(),
            );
        }
        None
    }

    match expr {
        Expr::Exists { subquery, negated } if !negated => {
            let query = subquery.as_ref();
            let body = query.body.as_ref();
            if let sqlparser::ast::SetExpr::Select(select) = body {
                return diagnose_select(select.as_ref(), db, registry, None);
            }
            None
        }
        Expr::InSubquery {
            expr: lhs,
            subquery,
            negated,
        } if !negated => {
            let lhs_col = extract_column_name(lhs)?;
            let query = subquery.as_ref();
            let body = query.body.as_ref();
            if let sqlparser::ast::SetExpr::Select(select) = body {
                let projected_fk = extract_projection_column(select.as_ref())
                    .unwrap_or(lhs_col)
                    .clone();
                return diagnose_select(select.as_ref(), db, registry, Some(&projected_fk));
            }
            None
        }
        _ => None,
    }
}

pub(crate) fn diagnose_p5_parent_inheritance_ambiguity(
    expr: &Expr,
    db: &ParserDB,
    outer_table: &str,
) -> Option<String> {
    let Expr::Exists { subquery, negated } = expr else {
        return None;
    };
    if *negated {
        return None;
    }

    let query = subquery.as_ref();
    let sqlparser::ast::SetExpr::Select(select) = query.body.as_ref() else {
        return None;
    };
    let sources = relation_sources(select.as_ref());
    if sources.is_empty() {
        return None;
    }

    let outer_table_meta = lookup_table(db, outer_table)?;
    let selection = select.selection.as_ref()?;

    let outer_cols: Vec<String> = outer_table_meta
        .columns(db)
        .map(|c| c.column_name().to_string())
        .collect();
    let mut predicates = Vec::new();
    flatten_and_predicates(selection, &mut predicates);

    let mut candidate_matches = 0usize;
    let mut saw_conflicting_join = false;

    for source in sources {
        let Some(parent_table) = lookup_table(db, &source.table_name) else {
            continue;
        };
        let parent_cols: Vec<String> = parent_table
            .columns(db)
            .map(|c| c.column_name().to_string())
            .collect();

        let mut fk_column: Option<String> = None;
        let mut inner_predicates = 0usize;
        let mut invalid_join = false;

        for pred in &predicates {
            if let Some((outer_fk, _parent_col)) = extract_parent_join_columns(
                pred,
                outer_table,
                &outer_cols,
                &source.table_name,
                source.alias.as_deref(),
                &parent_cols,
            ) {
                if fk_column
                    .as_ref()
                    .is_none_or(|existing| existing == &outer_fk)
                {
                    fk_column = Some(outer_fk);
                    continue;
                }
                invalid_join = true;
                break;
            }
            inner_predicates += 1;
        }

        if invalid_join {
            saw_conflicting_join = true;
            continue;
        }
        let Some(fk_column) = fk_column else {
            continue;
        };
        if inner_predicates == 0 {
            continue;
        }
        if !table_has_fk_to_parent(outer_table_meta, db, &fk_column, &source.table_name) {
            continue;
        }

        candidate_matches += 1;
    }

    if candidate_matches > 1 {
        return Some(
            "Ambiguous parent inheritance pattern: multiple candidate parent sources matched"
                .to_string(),
        );
    }
    if saw_conflicting_join {
        return Some(
            "Ambiguous parent inheritance pattern: conflicting outer FK join columns in EXISTS predicate"
                .to_string(),
        );
    }
    None
}

fn selection_references_current_user(select: &Select, registry: &FunctionRegistry) -> bool {
    let Some(selection) = select.selection.as_ref() else {
        return false;
    };
    let mut predicates = Vec::new();
    flatten_and_predicates(selection, &mut predicates);
    predicates.into_iter().any(|predicate| match predicate {
        Expr::BinaryOp { left, right, .. }
        | Expr::IsDistinctFrom(left, right)
        | Expr::IsNotDistinctFrom(left, right) => {
            is_current_user_expr(left, registry) || is_current_user_expr(right, registry)
        }
        _ => is_current_user_expr(predicate, registry),
    })
}

/// Try to recognize P10: constant boolean policies (`TRUE` / `FALSE`).
pub fn recognize_p10_constant_bool(
    expr: &Expr,
    _db: &ParserDB,
    _registry: &FunctionRegistry,
) -> Option<ClassifiedExpr> {
    constant_bool_value(expr).map(|value| ClassifiedExpr {
        pattern: PatternClass::P10ConstantBool { value },
        confidence: ConfidenceLevel::A,
    })
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
            // Check for `column = TRUE` or `TRUE = column`.
            let (col_name, is_true) = if let (Some(col), Some(value)) =
                (extract_column_name(left), constant_bool_value(right))
            {
                (col, value)
            } else if let (Some(value), Some(col)) =
                (constant_bool_value(left), extract_column_name(right))
            {
                (col, value)
            } else {
                return None;
            };

            if is_true && is_public_flag_column_name(&col_name) {
                return Some(ClassifiedExpr {
                    pattern: PatternClass::P6BooleanFlag { column: col_name },
                    confidence: ConfidenceLevel::A,
                });
            }
        }
        Expr::IsTrue(inner) | Expr::IsNotFalse(inner) => {
            let col_name = extract_column_name(inner)?;
            if is_public_flag_column_name(&col_name) {
                return Some(ClassifiedExpr {
                    pattern: PatternClass::P6BooleanFlag { column: col_name },
                    confidence: ConfidenceLevel::A,
                });
            }
        }
        Expr::Identifier(_) | Expr::CompoundIdentifier(_) => {
            let col_name = extract_column_name(expr)?;
            if is_public_flag_column_name(&col_name) {
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

/// Returns the column name if the expression is a negated public-flag check
/// (`col = FALSE`, `FALSE = col`, `col IS FALSE`, `col IS NOT TRUE`).
///
/// These forms look similar to P6 but cannot be expressed as static `OpenFGA`
/// tuples because they filter OUT rows rather than granting access.
pub fn is_negated_boolean_flag(expr: &Expr) -> Option<String> {
    match expr {
        Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq,
            right,
        } => {
            let (col_name, value) = if let (Some(col), Some(v)) =
                (extract_column_name(left), constant_bool_value(right))
            {
                (col, v)
            } else if let (Some(v), Some(col)) =
                (constant_bool_value(left), extract_column_name(right))
            {
                (col, v)
            } else {
                return None;
            };
            if !value && is_public_flag_column_name(&col_name) {
                return Some(col_name);
            }
            None
        }
        Expr::IsFalse(inner) | Expr::IsNotTrue(inner) => {
            let col_name = extract_column_name(inner)?;
            if is_public_flag_column_name(&col_name) {
                return Some(col_name);
            }
            None
        }
        _ => None,
    }
}

fn constant_bool_value(expr: &Expr) -> Option<bool> {
    match expr {
        Expr::Value(v) => match &v.value {
            Value::Boolean(b) => Some(*b),
            _ => None,
        },
        Expr::Nested(inner) | Expr::Cast { expr: inner, .. } => constant_bool_value(inner),
        Expr::UnaryOp {
            op: UnaryOperator::Not,
            expr: inner,
        } => constant_bool_value(inner).map(|value| !value),
        _ => None,
    }
}

// ---- Helper functions ----

/// Extract a function name from an expression.
pub fn extract_function_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Function(func) => Some(normalize_relation_name(&func.name.to_string())),
        Expr::Cast { expr, .. } => extract_function_name(expr),
        Expr::Nested(inner) => extract_function_name(inner),
        _ => None,
    }
}

/// Extract an integer value from an expression.
fn extract_integer_value(expr: &Expr) -> Option<i32> {
    match expr {
        Expr::Value(v) => match &v.value {
            Value::Number(n, _) => n.parse().ok(),
            _ => None,
        },
        Expr::Nested(inner)
        | Expr::Cast { expr: inner, .. }
        | Expr::UnaryOp {
            op: UnaryOperator::Plus,
            expr: inner,
        } => extract_integer_value(inner),
        Expr::UnaryOp {
            op: UnaryOperator::Minus,
            expr: inner,
        } => extract_integer_value(inner).map(|value| -value),
        _ => None,
    }
}

/// Extract a table name from a `TableFactor`.
fn extract_table_name_from_table_factor(tf: &TableFactor) -> Option<String> {
    if let TableFactor::Table { name, .. } = tf {
        Some(name.to_string())
    } else {
        None
    }
}

fn extract_table_alias_from_table_factor(tf: &TableFactor) -> Option<String> {
    if let TableFactor::Table { alias, .. } = tf {
        alias.as_ref().map(|a| a.name.value.clone())
    } else {
        None
    }
}

#[derive(Debug, Clone)]
struct RelationSource {
    table_name: String,
    alias: Option<String>,
}

fn relation_sources(select: &Select) -> Vec<RelationSource> {
    let mut sources = Vec::new();
    for from in &select.from {
        if let Some(source) = relation_source_from_table_factor(&from.relation) {
            sources.push(source);
        }
        for join in &from.joins {
            if let Some(source) = relation_source_from_table_factor(&join.relation) {
                sources.push(source);
            }
        }
    }

    sources
}

fn relation_source_from_table_factor(tf: &TableFactor) -> Option<RelationSource> {
    Some(RelationSource {
        table_name: extract_table_name_from_table_factor(tf)?,
        alias: extract_table_alias_from_table_factor(tf),
    })
}

fn membership_matches(
    select: &Select,
    db: &ParserDB,
    registry: &FunctionRegistry,
    projected_fk_hint: Option<&str>,
) -> Vec<(String, String, String, Option<String>)> {
    let mut matches = Vec::new();
    for source in relation_sources(select) {
        let Some(table) = lookup_table(db, &source.table_name) else {
            continue;
        };
        let col_names: Vec<String> = table
            .columns(db)
            .map(|c| c.column_name().to_string())
            .collect();

        if let Some((fk_col, user_col, extra_predicate_sql)) = extract_membership_columns(
            select,
            &source.table_name,
            source.alias.as_deref(),
            &col_names,
            registry,
            projected_fk_hint,
        ) {
            matches.push((source.table_name, fk_col, user_col, extra_predicate_sql));
        }
    }
    matches
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
    join_alias: Option<&str>,
    join_cols: &[String],
    registry: &FunctionRegistry,
    projected_fk_hint: Option<&str>,
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
                if let Some((qual, col)) = left_col.clone() {
                    if is_join_column_ref(qual.as_deref(), &col, join_table, join_alias, join_cols)
                        && is_current_user_expr(right, registry)
                    {
                        user_col = Some(col);
                        continue;
                    }
                }
                if let Some((qual, col)) = right_col.clone() {
                    if is_join_column_ref(qual.as_deref(), &col, join_table, join_alias, join_cols)
                        && is_current_user_expr(left, registry)
                    {
                        user_col = Some(col);
                        continue;
                    }
                }

                // join_table_fk = outer_table_col
                if let (Some((left_qual, left_name)), Some((right_qual, right_name))) =
                    (left_col, right_col)
                {
                    let left_is_join = is_join_column_ref(
                        left_qual.as_deref(),
                        &left_name,
                        join_table,
                        join_alias,
                        join_cols,
                    );
                    let right_is_join = is_join_column_ref(
                        right_qual.as_deref(),
                        &right_name,
                        join_table,
                        join_alias,
                        join_cols,
                    );

                    if left_is_join && !right_is_join {
                        if fk_col
                            .as_ref()
                            .is_none_or(|existing| existing == &left_name)
                        {
                            fk_col = Some(left_name);
                            continue;
                        }
                        return None;
                    }
                    if right_is_join && !left_is_join {
                        if fk_col
                            .as_ref()
                            .is_none_or(|existing| existing == &right_name)
                        {
                            fk_col = Some(right_name);
                            continue;
                        }
                        return None;
                    }
                }
            }

            // Keep additional predicates for tuple filtering.
            let predicate_sql = pred.to_string();
            extras.push(normalize_extra_predicate_sql(
                &predicate_sql,
                join_table,
                join_alias,
            ));
        }
    }

    if fk_col.is_none() {
        fk_col = infer_membership_fk_column(
            join_table,
            join_cols,
            user_col.as_deref(),
            projected_fk_hint,
        );
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

fn current_user_accessor_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Function(func) => Some(normalize_relation_name(&func.name.to_string())),
        Expr::Identifier(ident) => Some(normalize_relation_name(&ident.value)),
        Expr::Cast { expr, .. } => current_user_accessor_name(expr),
        Expr::Nested(inner) => current_user_accessor_name(inner),
        _ => None,
    }
}

fn is_current_user_keyword(name: &str) -> bool {
    name == "current_user" || name == "session_user" || name == "user"
}

fn is_known_current_user_name(name: &str, registry: &FunctionRegistry) -> bool {
    let normalized = normalize_relation_name(name);
    registry.is_current_user_accessor(&normalized) || is_current_user_keyword(&normalized)
}

fn is_current_user_expr(expr: &Expr, registry: &FunctionRegistry) -> bool {
    current_user_accessor_name(expr)
        .as_deref()
        .is_some_and(|name| is_known_current_user_name(name, registry))
}

fn is_join_column_ref(
    qualifier: Option<&str>,
    column: &str,
    join_table: &str,
    join_alias: Option<&str>,
    join_cols: &[String],
) -> bool {
    if !join_cols.iter().any(|c| c == column) {
        return false;
    }

    match qualifier {
        None => true,
        Some(q) => qualifier_matches_table(q, join_table, join_alias),
    }
}

fn normalize_extra_predicate_sql(sql: &str, join_table: &str, join_alias: Option<&str>) -> String {
    let mut normalized = strip_qualifier_outside_literals(sql, &format!("{join_table}."));
    if let Some((_, relation)) = split_schema_and_relation(join_table) {
        normalized = strip_qualifier_outside_literals(&normalized, &format!("{relation}."));
    }
    if let Some(alias) = join_alias {
        normalized = strip_qualifier_outside_literals(&normalized, &format!("{alias}."));
    }
    normalized
}

fn qualifier_matches_table(qualifier: &str, table_name: &str, alias: Option<&str>) -> bool {
    if alias.is_some_and(|a| qualifier.eq_ignore_ascii_case(a)) {
        return true;
    }

    table_qualifier_candidates(table_name)
        .iter()
        .any(|candidate| qualifier.eq_ignore_ascii_case(candidate))
}

fn table_qualifier_candidates(table_name: &str) -> Vec<String> {
    let mut candidates = vec![table_name.to_string()];
    if let Some((_, relation)) = split_schema_and_relation(table_name) {
        candidates.push(relation);
    }
    candidates
}

fn strip_qualifier_outside_literals(sql: &str, qualifier: &str) -> String {
    if qualifier.is_empty() {
        return sql.to_string();
    }

    let mut out = String::with_capacity(sql.len());
    let mut idx = 0usize;
    let mut in_single_quote = false;

    while idx < sql.len() {
        let rest = &sql[idx..];

        if !in_single_quote && rest.starts_with(qualifier) {
            idx += qualifier.len();
            continue;
        }

        let Some(ch) = rest.chars().next() else {
            break;
        };
        let ch_len = ch.len_utf8();

        if ch == '\'' {
            if in_single_quote {
                let after = &sql[idx + ch_len..];
                if after.starts_with('\'') {
                    out.push('\'');
                    out.push('\'');
                    idx += ch_len + 1;
                    continue;
                }
                in_single_quote = false;
            } else {
                in_single_quote = true;
            }
        }

        out.push(ch);
        idx += ch_len;
    }

    out
}

fn combine_predicates_with_and(predicates: Vec<Expr>) -> Option<Expr> {
    let mut iter = predicates.into_iter();
    let first = iter.next()?;
    Some(iter.fold(first, |acc, next| Expr::BinaryOp {
        left: Box::new(acc),
        op: BinaryOperator::And,
        right: Box::new(next),
    }))
}

fn extract_parent_join_columns(
    predicate: &Expr,
    outer_table: &str,
    outer_cols: &[String],
    parent_table: &str,
    parent_alias: Option<&str>,
    parent_cols: &[String],
) -> Option<(String, String)> {
    let Expr::BinaryOp {
        left,
        op: BinaryOperator::Eq,
        right,
    } = predicate
    else {
        return None;
    };

    let left_col = extract_qualified_column(left)?;
    let right_col = extract_qualified_column(right)?;

    let left_is_parent = is_parent_column_ref(
        left_col.0.as_deref(),
        &left_col.1,
        parent_table,
        parent_alias,
        parent_cols,
        outer_cols,
    );
    let right_is_parent = is_parent_column_ref(
        right_col.0.as_deref(),
        &right_col.1,
        parent_table,
        parent_alias,
        parent_cols,
        outer_cols,
    );

    let left_is_outer = is_outer_column_ref(
        left_col.0.as_deref(),
        &left_col.1,
        outer_table,
        outer_cols,
        parent_cols,
    );
    let right_is_outer = is_outer_column_ref(
        right_col.0.as_deref(),
        &right_col.1,
        outer_table,
        outer_cols,
        parent_cols,
    );

    if left_is_parent && right_is_outer {
        return Some((right_col.1, left_col.1));
    }
    if right_is_parent && left_is_outer {
        return Some((left_col.1, right_col.1));
    }

    None
}

fn is_parent_column_ref(
    qualifier: Option<&str>,
    column: &str,
    parent_table: &str,
    parent_alias: Option<&str>,
    parent_cols: &[String],
    outer_cols: &[String],
) -> bool {
    if !parent_cols.iter().any(|c| c == column) {
        return false;
    }

    match qualifier {
        Some(q) => qualifier_matches_table(q, parent_table, parent_alias),
        None => !outer_cols.iter().any(|c| c == column),
    }
}

fn is_outer_column_ref(
    qualifier: Option<&str>,
    column: &str,
    outer_table: &str,
    outer_cols: &[String],
    parent_cols: &[String],
) -> bool {
    if !outer_cols.iter().any(|c| c == column) {
        return false;
    }

    match qualifier {
        Some(q) => qualifier_matches_table(q, outer_table, None),
        None => !parent_cols.iter().any(|c| c == column),
    }
}

fn table_has_fk_to_parent(
    outer_table: &<ParserDB as DatabaseLike>::Table,
    db: &ParserDB,
    fk_column: &str,
    parent_table_name: &str,
) -> bool {
    outer_table.foreign_keys(db).any(|fk| {
        let host_col_matches = fk
            .host_column(db)
            .is_some_and(|col| col.column_name() == fk_column);
        if !host_col_matches {
            return false;
        }

        qualifier_matches_table(
            fk.referenced_table(db).table_name(),
            parent_table_name,
            None,
        )
    })
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

fn is_user_related_column(col: &str) -> bool {
    is_user_related_column_name(col)
}

fn infer_membership_fk_column(
    join_table: &str,
    join_cols: &[String],
    user_col: Option<&str>,
    projected_fk_hint: Option<&str>,
) -> Option<String> {
    let id_candidates: Vec<String> = join_cols
        .iter()
        .filter(|c| c.ends_with("_id") && Some(c.as_str()) != user_col)
        .cloned()
        .collect();

    if id_candidates.is_empty() {
        return None;
    }
    if id_candidates.len() == 1 {
        return id_candidates.first().cloned();
    }

    if let Some(hint) = projected_fk_hint {
        if id_candidates.iter().any(|c| c == hint) {
            return Some(hint.to_string());
        }
    }

    let relation = normalize_relation_name(join_table);
    let mut relation_hints = Vec::new();
    if let Some(stem) = relation.strip_suffix("_members") {
        relation_hints.push(format!("{stem}_id"));
    }
    if let Some(stem) = relation.strip_suffix("_memberships") {
        relation_hints.push(format!("{stem}_id"));
    }
    if let Some(stem) = relation.strip_suffix("_membership") {
        relation_hints.push(format!("{stem}_id"));
    }

    let hinted: Vec<String> = id_candidates
        .iter()
        .filter(|candidate| relation_hints.iter().any(|hint| hint == *candidate))
        .cloned()
        .collect();
    if hinted.len() == 1 {
        return hinted.into_iter().next();
    }

    let non_scope_candidates: Vec<String> = id_candidates
        .iter()
        .filter(|candidate| {
            !matches!(
                candidate.as_str(),
                "tenant_id" | "org_id" | "organization_id" | "account_id" | "workspace_id"
            )
        })
        .cloned()
        .collect();
    if non_scope_candidates.len() == 1 {
        return non_scope_candidates.into_iter().next();
    }

    None
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
    fn recognize_p1_accepts_reversed_comparators() {
        let db = db_with_docs_and_members();
        let registry = registry_with_role_level();

        let gte = parse_expr("2 <= role_level(auth_current_user_id(), id)");
        let classified_gte =
            recognize_p1(&gte, &db, &registry, &PolicyCommand::Select).expect("expected P1 match");
        assert!(matches!(
            &classified_gte.pattern,
            PatternClass::P1NumericThreshold {
                operator: ThresholdOperator::Gte,
                threshold,
                ..
            } if *threshold == 2
        ));

        let gt = parse_expr("2 < role_level(auth_current_user_id(), id)");
        let classified_gt =
            recognize_p1(&gt, &db, &registry, &PolicyCommand::Delete).expect("expected P1 match");
        assert!(matches!(
            &classified_gt.pattern,
            PatternClass::P1NumericThreshold {
                operator: ThresholdOperator::Gt,
                threshold,
                command: PolicyCommand::Delete,
                ..
            } if *threshold == 2
        ));
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
    fn recognize_p3_supports_is_not_distinct_from() {
        let db = db_with_docs_and_members();
        let registry = FunctionRegistry::new();

        let expr = parse_expr("owner_id IS NOT DISTINCT FROM auth_current_user_id()");
        let classified = recognize_p3(&expr, &db, &registry).expect("expected ownership match");
        assert!(matches!(
            classified.pattern,
            PatternClass::P3DirectOwnership { ref column } if column == "owner_id"
        ));
        assert_eq!(classified.confidence, ConfidenceLevel::A);
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
                    .is_some_and(|s| s.contains("role = 'admin'"))
        ));
    }

    #[test]
    fn recognize_p4_exists_supports_joined_membership_tables() {
        let db = db_with_docs_and_members();
        let registry = registry_with_role_level();

        let exists_expr = parse_expr(
            "EXISTS (
               SELECT 1
               FROM docs d
               JOIN doc_members dm ON dm.doc_id = d.id
               WHERE d.id = docs.id
                 AND dm.user_id = auth_current_user_id()
             )",
        );

        let classified = recognize_p4(&exists_expr, &db, &registry).expect("expected P4 match");
        assert!(matches!(
            &classified.pattern,
            PatternClass::P4ExistsMembership {
                join_table,
                fk_column,
                user_column,
                ..
            } if join_table == "doc_members" && fk_column == "doc_id" && user_column == "user_id"
        ));
    }

    #[test]
    fn recognize_p4_with_alias_and_current_user_keyword_strips_correlated_predicates() {
        let db = db_with_docs_and_members();
        let registry = FunctionRegistry::new();

        let exists_expr = parse_expr(
            "EXISTS (
               SELECT 1
               FROM doc_members dm
               WHERE dm.doc_id = docs.id
                 AND dm.user_id = current_user
                 AND dm.role = 'admin'
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
                    .is_some_and(|s| s == "role = 'admin'")
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
    fn recognize_p4_in_subquery_supports_joined_membership_tables() {
        let db = db_with_docs_and_members();
        let registry = registry_with_role_level();

        let in_subquery = parse_expr(
            "doc_id IN (
               SELECT dm.doc_id
               FROM docs d
               JOIN doc_members dm ON dm.doc_id = d.id
               WHERE dm.user_id = auth_current_user_id()
             )",
        );

        let classified =
            recognize_p4_in_subquery(&in_subquery, &db, &registry).expect("expected P4 match");
        assert!(matches!(
            &classified.pattern,
            PatternClass::P4ExistsMembership {
                join_table,
                fk_column,
                user_column,
                ..
            } if join_table == "doc_members" && fk_column == "doc_id" && user_column == "user_id"
        ));
    }

    #[test]
    fn recognize_p4_paths_remain_parity_aligned_for_membership_shape() {
        let db = db_with_docs_and_members();
        let registry = registry_with_role_level();

        let exists_expr = parse_expr(
            "EXISTS (
               SELECT 1
               FROM doc_members dm
               WHERE dm.doc_id = docs.id
                 AND dm.user_id = auth_current_user_id()
                 AND dm.role = 'admin'
             )",
        );
        let in_subquery = parse_expr(
            "doc_id IN (
               SELECT dm.doc_id
               FROM doc_members dm
               WHERE dm.user_id = auth_current_user_id()
                 AND dm.role = 'admin'
             )",
        );

        let exists = recognize_p4(&exists_expr, &db, &registry).expect("expected EXISTS match");
        let in_sub = recognize_p4_in_subquery(&in_subquery, &db, &registry)
            .expect("expected IN-subquery match");

        let (exists_join_table, exists_fk_column, exists_user_column, exists_extra_predicate_sql) =
            match exists.pattern {
                PatternClass::P4ExistsMembership {
                    join_table,
                    fk_column,
                    user_column,
                    extra_predicate_sql,
                } => (join_table, fk_column, user_column, extra_predicate_sql),
                other => panic!("expected P4 EXISTS classification, got: {other:?}"),
            };

        let (in_join_table, in_fk_column, in_user_column, in_extra_predicate_sql) =
            match in_sub.pattern {
                PatternClass::P4ExistsMembership {
                    join_table,
                    fk_column,
                    user_column,
                    extra_predicate_sql,
                } => (join_table, fk_column, user_column, extra_predicate_sql),
                other => panic!("expected P4 IN-subquery classification, got: {other:?}"),
            };

        assert_eq!(exists_join_table, in_join_table);
        assert_eq!(exists_fk_column, in_fk_column);
        assert_eq!(exists_user_column, in_user_column);
        assert_eq!(exists_extra_predicate_sql, in_extra_predicate_sql);
    }

    #[test]
    fn recognize_p4_paths_fail_closed_on_ambiguous_sources() {
        let db = parse_schema(
            r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE memberships(doc_id UUID, user_id UUID);
",
        )
        .expect("schema should parse");
        let registry = registry_with_role_level();

        let exists_expr = parse_expr(
            "EXISTS (
               SELECT 1
               FROM memberships a
               JOIN memberships b ON b.doc_id = a.doc_id
               WHERE a.user_id = auth_current_user_id()
             )",
        );
        let in_subquery = parse_expr(
            "id IN (
               SELECT a.doc_id
               FROM memberships a
               JOIN memberships b ON b.doc_id = a.doc_id
               WHERE a.user_id = auth_current_user_id()
             )",
        );

        assert!(
            recognize_p4(&exists_expr, &db, &registry).is_none(),
            "ambiguous EXISTS sources should fail closed"
        );
        assert!(
            recognize_p4_in_subquery(&in_subquery, &db, &registry).is_none(),
            "ambiguous IN-subquery sources should fail closed"
        );
    }

    #[test]
    fn recognize_p10_and_p6_cover_non_matching_variants() {
        let db = db_with_docs_and_members();
        let registry = FunctionRegistry::new();

        let p10_true = parse_expr("TRUE");
        assert!(recognize_p10_constant_bool(&p10_true, &db, &registry).is_some());
        let p10_not_true = parse_expr("NOT TRUE");
        assert!(matches!(
            recognize_p10_constant_bool(&p10_not_true, &db, &registry),
            Some(ClassifiedExpr {
                pattern: PatternClass::P10ConstantBool { value: false },
                ..
            })
        ));
        let p10_cast = parse_expr("CAST(TRUE AS BOOLEAN)");
        assert!(matches!(
            recognize_p10_constant_bool(&p10_cast, &db, &registry),
            Some(ClassifiedExpr {
                pattern: PatternClass::P10ConstantBool { value: true },
                ..
            })
        ));

        let p10_not_bool = parse_expr("1");
        assert!(recognize_p10_constant_bool(&p10_not_bool, &db, &registry).is_none());

        let p6_false = parse_expr("FALSE = is_public");
        assert!(recognize_p6(&p6_false, &db, &registry).is_none());
        let p6_is_true = parse_expr("is_public IS TRUE");
        assert!(recognize_p6(&p6_is_true, &db, &registry).is_some());
        let p6_is_not_false = parse_expr("is_public IS NOT FALSE");
        assert!(recognize_p6(&p6_is_not_false, &db, &registry).is_some());

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
        let schema_fun = parse_expr(r#""auth"."uid"()"#);
        assert_eq!(extract_function_name(&schema_fun).as_deref(), Some("uid"));

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
    fn membership_column_extraction_requires_explicit_user_predicate() {
        // WHERE clause has only a role predicate, no current-user equality.
        // Without an explicit user predicate, extract_membership_columns must
        // return None to avoid "exists any admin" false positives.
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

        assert!(
            extract_membership_columns(&select, "doc_members", Some("dm"), &cols, &registry, None)
                .is_none(),
            "membership without user predicate must fail closed"
        );
    }

    #[test]
    fn table_and_projection_extractors_cover_non_table_and_alias_paths() {
        let table_select = parse_select("SELECT dm.doc_id AS projected FROM doc_members dm");
        let from = &table_select.from[0];
        let table_name = extract_table_name_from_table_factor(&from.relation)
            .expect("table factor should resolve");
        assert_eq!(table_name, "doc_members");
        assert_eq!(
            extract_table_alias_from_table_factor(&from.relation).as_deref(),
            Some("dm")
        );
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
        let keyword = parse_expr("current_user");
        let other = parse_expr("owner_id");

        assert!(is_current_user_expr(&nested, &registry));
        assert!(is_current_user_expr(&casted, &registry));
        assert!(is_current_user_expr(&keyword, &registry));
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
    fn extract_integer_value_supports_nested_cast_and_signed_literals() {
        let nested_cast = parse_expr("CAST((2) AS INTEGER)");
        assert_eq!(extract_integer_value(&nested_cast), Some(2));

        let signed = parse_expr("-2");
        assert_eq!(extract_integer_value(&signed), Some(-2));
    }

    #[test]
    fn is_attribute_check_accepts_casted_literal_values() {
        let expr = parse_expr("status = CAST('draft' AS TEXT)");
        assert_eq!(is_attribute_check(&expr).as_deref(), Some("status"));
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

        let extracted =
            extract_membership_columns(&select, "doc_members", Some("dm"), &cols, &registry, None)
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
    fn recognize_p4_paths_fail_closed_for_values_subqueries() {
        let db = db_with_docs_and_members();
        let registry = registry_with_role_level();

        let exists_values = parse_expr("EXISTS (VALUES (1))");
        let in_values = parse_expr("id IN (VALUES (1))");

        assert!(recognize_p4(&exists_values, &db, &registry).is_none());
        assert!(recognize_p4_in_subquery(&in_values, &db, &registry).is_none());
    }

    #[test]
    fn recognize_p4_multi_from_requires_user_predicate() {
        let db = db_with_docs_and_members();
        let registry = registry_with_role_level();

        // No user predicate in EXISTS → must fail closed even when the membership
        // table is present alongside a second resource table.
        let exists_no_user = parse_expr(
            "EXISTS (
               SELECT 1
               FROM doc_members dm, docs d
               WHERE dm.doc_id = d.id
             )",
        );
        assert!(
            recognize_p4(&exists_no_user, &db, &registry).is_none(),
            "EXISTS with no user predicate is an 'exists any row' false positive"
        );

        // IN-subquery with an explicit user predicate over one of the sources
        // should still be accepted; the second source just provides a FK join.
        let in_with_user = parse_expr(
            "doc_id IN (
               SELECT dm.doc_id
               FROM doc_members dm, docs d
               WHERE dm.user_id = auth_current_user_id()
             )",
        );
        assert!(matches!(
            recognize_p4_in_subquery(&in_with_user, &db, &registry),
            Some(ClassifiedExpr {
                pattern: PatternClass::P4ExistsMembership { ref join_table, .. },
                ..
            }) if join_table == "doc_members"
        ));
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

        let extracted =
            extract_membership_columns(&select, "doc_members", Some("dm"), &cols, &registry, None)
                .expect("columns should still be inferred");
        assert_eq!(extracted.0, "doc_id");
        assert_eq!(extracted.1, "user_id");
        assert!(extracted
            .2
            .as_deref()
            .is_some_and(|s| s.contains("role > 'a'")));
    }

    #[test]
    fn extract_membership_columns_returns_none_without_user_predicate() {
        // No WHERE clause at all → no user predicate → must fail closed.
        let select = parse_select("SELECT dm.doc_id FROM doc_members dm");
        let registry = registry_with_role_level();
        let cols = vec![
            "doc_id".to_string(),
            "user_id".to_string(),
            "role".to_string(),
        ];

        assert!(
            extract_membership_columns(&select, "doc_members", Some("dm"), &cols, &registry, None)
                .is_none(),
            "membership without any WHERE must fail closed"
        );
    }

    #[test]
    fn membership_column_extraction_requires_user_predicate_not_just_role() {
        // WHERE has only a role predicate and no current-user equality:
        // even with a tenant_id column present, must still fail closed.
        let select = parse_select(
            "SELECT dm.doc_id
             FROM doc_members dm
             WHERE dm.role = 'admin'",
        );
        let registry = registry_with_role_level();
        let cols = vec![
            "doc_id".to_string(),
            "tenant_id".to_string(),
            "user_id".to_string(),
            "role".to_string(),
        ];

        assert!(
            extract_membership_columns(&select, "doc_members", Some("dm"), &cols, &registry, None)
                .is_none(),
            "membership with only a role predicate must fail closed"
        );
    }

    #[test]
    fn membership_column_extraction_fails_when_fk_remains_ambiguous() {
        let select = parse_select(
            "SELECT m.alpha_id
             FROM memberships m
             WHERE m.role = 'admin'",
        );
        let registry = registry_with_role_level();
        let cols = vec![
            "alpha_id".to_string(),
            "beta_id".to_string(),
            "user_id".to_string(),
            "role".to_string(),
        ];

        let extracted =
            extract_membership_columns(&select, "memberships", Some("m"), &cols, &registry, None);
        assert!(
            extracted.is_none(),
            "ambiguous membership FK should fail closed"
        );
    }

    #[test]
    fn extract_membership_columns_fails_when_join_predicates_conflict() {
        let select = parse_select(
            "SELECT m.doc_id
             FROM doc_members m
             WHERE m.user_id = auth_current_user_id()
               AND m.doc_id = docs.id
               AND m.project_id = docs.project_id",
        );
        let registry = registry_with_role_level();
        let cols = vec![
            "doc_id".to_string(),
            "project_id".to_string(),
            "user_id".to_string(),
        ];

        let extracted =
            extract_membership_columns(&select, "doc_members", Some("m"), &cols, &registry, None);
        assert!(
            extracted.is_none(),
            "conflicting join predicates should fail closed"
        );
    }

    #[test]
    fn recognize_p5_accepts_unqualified_parent_column_when_unambiguous() {
        let db = parse_schema(
            r"
CREATE TABLE users(id UUID PRIMARY KEY);
CREATE TABLE projects(project_uuid UUID PRIMARY KEY, owner_id UUID REFERENCES users(id));
CREATE TABLE tasks(id UUID PRIMARY KEY, project_id UUID REFERENCES projects(project_uuid));
",
        )
        .expect("schema should parse");
        let registry = FunctionRegistry::new();
        let expr = parse_expr(
            "EXISTS (
               SELECT 1
               FROM projects p
               WHERE project_uuid = tasks.project_id
                 AND p.owner_id = current_user
             )",
        );

        let classified = recognize_p5(&expr, &db, &registry, "tasks", &PolicyCommand::Select)
            .expect("expected P5 classification");
        assert!(matches!(
            classified.pattern,
            PatternClass::P5ParentInheritance { ref parent_table, ref fk_column, .. }
                if parent_table == "projects" && fk_column == "project_id"
        ));
    }

    #[test]
    fn recognize_p5_supports_joined_parent_sources() {
        let db = parse_schema(
            r"
CREATE TABLE users(id UUID PRIMARY KEY);
CREATE TABLE projects(project_uuid UUID PRIMARY KEY, owner_id UUID REFERENCES users(id));
CREATE TABLE project_tags(project_id UUID REFERENCES projects(project_uuid), tag TEXT);
CREATE TABLE tasks(id UUID PRIMARY KEY, project_id UUID REFERENCES projects(project_uuid));
",
        )
        .expect("schema should parse");
        let registry = FunctionRegistry::new();
        let expr = parse_expr(
            "EXISTS (
               SELECT 1
               FROM projects p
               JOIN project_tags pt ON pt.project_id = p.project_uuid
               WHERE p.project_uuid = tasks.project_id
                 AND p.owner_id = current_user
             )",
        );

        let classified = recognize_p5(&expr, &db, &registry, "tasks", &PolicyCommand::Select)
            .expect("expected P5 classification");
        assert!(matches!(
            classified.pattern,
            PatternClass::P5ParentInheritance { ref parent_table, ref fk_column, .. }
                if parent_table == "projects" && fk_column == "project_id"
        ));
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

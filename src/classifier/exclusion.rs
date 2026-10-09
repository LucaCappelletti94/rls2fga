//! Correlated blocklist subtraction from positive grants.

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;

use crate::classifier::expansion::ExpansionState;
use crate::classifier::function_registry::FunctionRegistry;
use crate::classifier::patterns::{
    exclusion_confidence, CallerCast, ClassifiedExpr, ExistsMembership, MembershipExclusion,
    PatternClass, PolicyCommand,
};
use crate::classifier::recognizers::{
    diagnose_p4_membership_ambiguity, is_current_user_expr, recognize_p4, recognize_p4_in_subquery,
    unparenthesize,
};
use crate::parser::names::lookup_table_id;
use crate::parser::sql_parser::DatabaseLike;
use crate::types::{ColumnName, TableId};
use sqlparser::ast::{BinaryOperator, Expr, UnaryOperator};

/// Why a correlated blocklist cannot be represented exactly.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ExclusionError {
    #[error("{0}")]
    UnsupportedMembership(String),
    #[error("the blocklist table '{0}' has row level security")]
    GuardedTable(TableId),
    #[error("the blocklist projection '{table}.{column}' must be provably non-null")]
    NullableProjection { table: TableId, column: ColumnName },
    #[error(
        "the blocklist comparison casts the caller to '{cast}', with no declared \
         identity form proving that cast changes no value"
    )]
    UnprovenCallerCast {
        table: TableId,
        column: ColumnName,
        cast: String,
    },
}

/// Split a clause into its positive grant and correlated blocklists.
pub(crate) fn try_membership_exclusion<DB: DatabaseLike>(
    expr: &Expr,
    db: &DB,
    registry: &FunctionRegistry,
    table: &str,
    command: PolicyCommand,
    depth: u32,
    state: &ExpansionState,
) -> Result<Option<ClassifiedExpr>, ExclusionError> {
    if !has_exclusion_conjunct(expr, depth) {
        return Ok(None);
    }
    let mut conjuncts = Vec::new();
    if !flatten_conjuncts(expr, depth, &mut conjuncts) {
        return Ok(None);
    }

    let mut positives = Vec::new();
    let mut subtract = Vec::new();
    for conjunct in conjuncts {
        match exclusion_conjunct(conjunct, db, registry, table, state)? {
            None => positives.push(conjunct),
            Some(membership) => subtract.push(membership),
        }
    }
    if subtract.is_empty() {
        return Ok(None);
    }

    let base = match positives.as_slice() {
        [] => {
            return Ok(Some(ClassifiedExpr {
                pattern: PatternClass::MembershipExclusion(MembershipExclusion {
                    base: None,
                    subtract,
                }),
                confidence: exclusion_confidence(None),
            }));
        }
        [base] => crate::classifier::policy_classifier::classify_expr_depth(
            base,
            db,
            registry,
            table,
            command,
            depth + 1,
            state,
        ),
        [first, rest @ ..] => {
            let base = rest
                .iter()
                .fold((*first).clone(), |previous, conjunct| Expr::BinaryOp {
                    left: Box::new(previous),
                    op: BinaryOperator::And,
                    right: Box::new((*conjunct).clone()),
                });
            crate::classifier::policy_classifier::classify_expr_depth(
                &base,
                db,
                registry,
                table,
                command,
                depth + 1,
                state,
            )
        }
    };
    let confidence = exclusion_confidence(Some(&base));
    Ok(Some(ClassifiedExpr {
        pattern: PatternClass::MembershipExclusion(MembershipExclusion {
            base: Some(Box::new(base)),
            subtract,
        }),
        confidence,
    }))
}

/// Flatten `AND` within the classifier's depth bound.
fn flatten_conjuncts<'a>(expr: &'a Expr, depth: u32, conjuncts: &mut Vec<&'a Expr>) -> bool {
    if depth > crate::classifier::policy_classifier::MAX_CLASSIFY_DEPTH {
        return false;
    }
    match expr {
        Expr::Nested(inner) => flatten_conjuncts(inner, depth + 1, conjuncts),
        Expr::BinaryOp {
            left,
            op: BinaryOperator::And,
            right,
        } => {
            flatten_conjuncts(left, depth + 1, conjuncts)
                && flatten_conjuncts(right, depth + 1, conjuncts)
        }
        _ => {
            conjuncts.push(expr);
            true
        }
    }
}

fn has_exclusion_conjunct(expr: &Expr, depth: u32) -> bool {
    if depth > crate::classifier::policy_classifier::MAX_CLASSIFY_DEPTH {
        return false;
    }
    match expr {
        Expr::Nested(inner) => has_exclusion_conjunct(inner, depth + 1),
        Expr::BinaryOp {
            left,
            op: BinaryOperator::And,
            right,
        } => has_exclusion_conjunct(left, depth + 1) || has_exclusion_conjunct(right, depth + 1),
        Expr::Exists { negated: true, .. }
        | Expr::InSubquery { negated: true, .. }
        | Expr::AllOp {
            compare_op: BinaryOperator::NotEq,
            ..
        } => true,
        Expr::UnaryOp {
            op: UnaryOperator::Not,
            expr,
        } => {
            matches!(unparenthesize(expr), Expr::Exists { negated: false, .. })
        }
        _ => false,
    }
}

fn table_guarded_by_rls<DB: DatabaseLike>(db: &DB, table: &TableId) -> bool {
    use sql_traits::prelude::TableLike;
    let mut frontier = vec![table.clone()];
    let mut seen: alloc::collections::BTreeSet<TableId> = alloc::collections::BTreeSet::new();
    while let Some(current) = frontier.pop() {
        if !seen.insert(current.clone()) {
            continue;
        }
        let Some(current) = lookup_table_id(db, &current) else {
            continue;
        };
        if current.has_row_level_security(db) == Ok(true) {
            return true;
        }
        for parent in current
            .inherits_from(db)
            .into_iter()
            .flatten()
            .chain(current.partition_root(db).ok().flatten())
        {
            let identity = TableId::from_stored(
                parent.stored_table_schema().map(Into::into),
                parent.stored_table_name().into(),
            );
            if !seen.contains(&identity) {
                frontier.push(identity);
            }
        }
    }
    false
}

fn exclusion_conjunct<DB: DatabaseLike>(
    conjunct: &Expr,
    db: &DB,
    registry: &FunctionRegistry,
    table: &str,
    state: &ExpansionState,
) -> Result<Option<ExistsMembership>, ExclusionError> {
    let positive = match unparenthesize(conjunct) {
        Expr::Exists {
            subquery,
            negated: true,
        } => Expr::Exists {
            subquery: subquery.clone(),
            negated: false,
        },
        Expr::UnaryOp {
            op: UnaryOperator::Not,
            expr,
        } => match unparenthesize(expr) {
            Expr::Exists {
                subquery,
                negated: false,
            } => Expr::Exists {
                subquery: subquery.clone(),
                negated: false,
            },
            _ => return Ok(None),
        },
        Expr::InSubquery {
            expr: left,
            subquery,
            negated: true,
        } => {
            if !is_current_user_expr(left, registry) {
                return Ok(None);
            }
            Expr::InSubquery {
                expr: left.clone(),
                subquery: subquery.clone(),
                negated: false,
            }
        }
        Expr::AllOp {
            left,
            compare_op: BinaryOperator::NotEq,
            right,
        } => match right.as_ref() {
            Expr::Subquery(subquery) if is_current_user_expr(left, registry) => Expr::InSubquery {
                expr: left.clone(),
                subquery: subquery.clone(),
                negated: false,
            },
            _ => return Ok(None),
        },
        _ => return Ok(None),
    };

    match membership_from_positive(&positive, db, registry, table, state) {
        None => {
            let reason = diagnose_p4_membership_ambiguity(&positive, db, registry, table, state)
                .unwrap_or_else(|| {
                    "the blocklist subquery must be a plain correlated caller-identity membership"
                        .to_string()
                });
            Err(ExclusionError::UnsupportedMembership(reason))
        }
        Some(membership) => {
            if table_guarded_by_rls(db, &membership.join_table) {
                return Err(ExclusionError::GuardedTable(membership.join_table));
            }
            if let Some(CallerCast { cast_type, .. }) = &membership.caller_cast {
                return Err(ExclusionError::UnprovenCallerCast {
                    table: membership.join_table,
                    column: membership.user_column,
                    cast: cast_type.clone(),
                });
            }
            if requires_non_null_projection(conjunct)
                && !column_proven_not_null(
                    db,
                    &membership.join_table,
                    membership.user_column.as_str(),
                )
            {
                return Err(ExclusionError::NullableProjection {
                    table: membership.join_table,
                    column: membership.user_column,
                });
            }
            Ok(Some(membership))
        }
    }
}

/// Accept only `P4`, excluding caller-set and parent-inheritance patterns.
fn membership_from_positive<DB: DatabaseLike>(
    positive: &Expr,
    db: &DB,
    registry: &FunctionRegistry,
    table: &str,
    state: &ExpansionState,
) -> Option<ExistsMembership> {
    let classified = match positive {
        Expr::Exists { .. } => recognize_p4(positive, db, registry, table, state),
        _ => recognize_p4_in_subquery(positive, db, registry, table, PolicyCommand::Select, state),
    }?;
    match classified.pattern {
        PatternClass::P4ExistsMembership(membership) => Some(membership),
        _ => None,
    }
}

/// `NOT IN` and `<> ALL` deny every caller when a row projects `NULL`.
fn requires_non_null_projection(conjunct: &Expr) -> bool {
    matches!(
        unparenthesize(conjunct),
        Expr::InSubquery { negated: true, .. }
            | Expr::AllOp {
                compare_op: BinaryOperator::NotEq,
                ..
            }
    )
}

fn column_proven_not_null<DB: DatabaseLike>(db: &DB, table: &TableId, column: &str) -> bool {
    use sql_traits::prelude::{ColumnLike, TableLike};
    let Some(table) = lookup_table_id(db, table) else {
        return false;
    };
    let Some(column_ref) = table
        .columns(db)
        .into_iter()
        .flatten()
        .find(|declared| declared.stored_column_name() == column)
    else {
        return false;
    };
    column_ref.is_nullable(db) == Ok(false)
}

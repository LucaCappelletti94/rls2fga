//! Emission for the patterns one column of the row decides.
//!
//! Ownership by a column, an array element or a jsonb field, the public flag, a constant, an
//! attribute guard, and the refusal a clause nobody classified earns.

use super::*;

/// A relation whose subjects are named by one column of the row, and the tuples that fill it.
///
/// P3, P11 and P12 are one shape: mint an ownership relation, declare it direct, and load it
/// from the row unless nothing names the row. Only the memo key, the name, and which
/// `TupleSource` reads the column differ, so the source arrives as a constructor.
pub(crate) fn emit_row_ownership<DB: DatabaseLike>(
    memo_key: &str,
    // What the relation is named after: a column, or a jsonb path joined into one name.
    name_source: &str,
    missing_what: &str,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
    source: impl FnOnce(Vec<ColumnName>, RelationName) -> TupleSource,
) -> UsersetExpr {
    let ownership = table_plan.ownership_relation(memo_key, name_source);
    let relation = table_plan.ensure_direct(
        ownership,
        vec![DirectSubject::Type(table_plan.well_known.user.to_string())],
    );
    let Some(pk_cols) = resolve_pk_columns(ctx.source_table, ctx.db) else {
        skip_source_without_row_identity(table_plan, ctx.source_table, missing_what, ctx.db);
        return deny_expr(table_plan);
    };
    table_plan.add_source(source(pk_cols, relation.clone()));
    UsersetExpr::Computed(relation)
}

/// The public wildcard a boolean flag opens, and the tuples that carry it.
pub(crate) fn emit_boolean_flag<DB: DatabaseLike>(
    boolean_flag: &BooleanFlag,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
) -> UsersetExpr {
    let BooleanFlag { column } = boolean_flag;
    let db = ctx.db;
    let source_table = ctx.source_table;
    if let Some(pk_cols) = resolve_pk_columns(source_table, db) {
        table_plan.add_source(TupleSource::PublicFlag {
            table: source_table.clone(),
            pk_cols,
            flag_col: column.clone(),
        });
    } else {
        skip_source_without_row_identity(table_plan, source_table, "public-flag tuples", db);
        return deny_expr(table_plan);
    }
    public_expr(table_plan)
}

/// Emit the wildcard only for rows whose strict-function arguments are present.
pub(crate) fn emit_row_presence_gate<DB: DatabaseLike>(
    columns: &[ColumnName],
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
) -> UsersetExpr {
    let source_table = ctx.source_table;
    let Some(pk_cols) = resolve_pk_columns(source_table, ctx.db) else {
        skip_source_without_row_identity(
            table_plan,
            source_table,
            "strict-function presence tuples",
            ctx.db,
        );
        return deny_expr(table_plan);
    };
    let relation = table_plan.ensure_direct(
        row_presence_relation_name(columns),
        vec![DirectSubject::Wildcard(
            table_plan.well_known.user.to_string(),
        )],
    );
    table_plan.add_source(TupleSource::RowPresenceGate {
        table: source_table.clone(),
        pk_cols,
        relation: relation.clone(),
        columns: columns.to_vec(),
    });
    UsersetExpr::Computed(relation)
}

/// An attribute guard, as a wildcard the row decides or a condition the request completes.
pub(crate) fn emit_attribute_condition<DB: DatabaseLike>(
    attribute_condition: &AttributeCondition,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
    notes: &mut Vec<TranslationNote>,
) -> UsersetExpr {
    let AttributeCondition {
        column,
        predicate,
        request_predicate,
        ..
    } = attribute_condition;
    let policy_name = ctx.policy_name;
    let db = ctx.db;
    let source_table = ctx.source_table;
    let settings = ctx.settings;
    // A value only the request knows cannot be decided by a tuple, so the
    // guard becomes a condition the service evaluates per check, and the tuple
    // carries the row's own value as its context.
    if let Some(request) = request_predicate {
        if let Some(expr) = conditional_gate_expr(
            request,
            policy_name,
            source_table,
            table_plan,
            ctx.condition_parameters,
            db,
            &settings.request_time_parameter,
        ) {
            return expr;
        }
    }
    // A literal constant is decided by the row, so the guard generalises the
    // boolean flag: emit the wildcard and let the tuple query qualify rows.
    // The wildcard is only correct because the compared value is a literal.
    // A caller-derived one would grant everyone access to rows scoped to one
    // caller, so it arrives here as `None` and keeps falling closed.
    if let Some(predicate) = predicate {
        if let Some(pk_cols) = resolve_pk_columns(source_table, db) {
            table_plan.add_source(TupleSource::AttributeGate {
                table: source_table.clone(),
                pk_cols,
                predicate: predicate.clone(),
            });
        } else {
            skip_source_without_row_identity(table_plan, source_table, "attribute-gate tuples", db);
            return deny_expr(table_plan);
        }
        return public_expr(table_plan);
    }
    notes.push(TranslationNote::StandaloneAttributePolicy {
        policy: policy_name.to_string(),
        column: column.clone(),
    });
    table_plan.add_source(TupleSource::Skipped {
        reason: SkippedTuples::StandaloneAttribute {
            table: source_table.clone(),
            column: column.clone(),
        },
    });
    deny_expr(table_plan)
}

/// Everyone or nobody, which is what a constant clause grants.
pub(crate) fn emit_constant_bool<DB: DatabaseLike>(
    constant_bool: &ConstantBool,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
) -> UsersetExpr {
    let ConstantBool { value } = constant_bool;
    let db = ctx.db;
    let source_table = ctx.source_table;
    if *value {
        if let Some(pk_cols) = resolve_pk_columns(source_table, db) {
            table_plan.add_source(TupleSource::ConstantTrue {
                table: source_table.clone(),
                pk_cols,
            });
        } else {
            skip_source_without_row_identity(table_plan, source_table, "constant-TRUE tuples", db);
            return deny_expr(table_plan);
        }
        public_expr(table_plan)
    } else {
        deny_expr(table_plan)
    }
}

/// A refusal: the clause is reported and the command falls closed.
pub(crate) fn emit_unclassified<DB: DatabaseLike>(
    unclassified: &UnclassifiedExpr,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
    notes: &mut Vec<TranslationNote>,
) -> UsersetExpr {
    let UnclassifiedExpr { reason, .. } = unclassified;
    let policy_name = ctx.policy_name;
    let source_table = ctx.source_table;
    notes.push(TranslationNote::ExpressionRefused {
        policy: policy_name.to_string(),
        reason: reason.clone(),
    });
    table_plan.add_source(TupleSource::Skipped {
        reason: SkippedTuples::UnclassifiedExpression {
            table: source_table.clone(),
            reason: reason.clone(),
        },
    });
    deny_expr(table_plan)
}

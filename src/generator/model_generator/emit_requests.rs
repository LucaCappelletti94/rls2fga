//! Emission for the patterns the request completes rather than the row.
//!
//! A declared setting or token claim supplies the caller's half, so the row carries its value in
//! a condition rather than in the tuple's subject. Also the conditions an attribute guard needs
//! when the value is one only the request knows.

use super::*;

/// Mint the relation, the condition and the tuple source a declared request-scoped
/// value needs.
///
/// The authority split: the tuple carries what only the row or the rule knows, the
/// request carries what only the caller knows, and the condition relates them. Returns
/// `None` when no tuple can name the row, so the caller falls back to closing the
/// policy.
pub(crate) fn session_attribute_expr<DB: DatabaseLike>(
    declared: RequestSide<'_>,
    carried: RowParameterSource<'_>,
    policy_name: &str,
    source_table: &str,
    table_plan: &mut TypePlan,
    db: &DB,
) -> Option<UsersetExpr> {
    let RequestSide {
        source,
        comparison,
        separator,
    } = declared;
    let pk_cols = resolve_pk_columns(source_table, db)?;

    let request_parameter = source.request_parameter().to_string();
    // Two parameters cannot share one name, and the caller's is the one a deployment
    // chose, so the tuple's yields.
    let mut row_parameter = normalize_relation_name(carried.parameter_base());
    if row_parameter == request_parameter {
        row_parameter = format!(
            "{row_parameter}_{}",
            stable_hex_suffix(carried.parameter_base())
        );
    }
    let row_parameter = match carried {
        RowParameterSource::Column(column) => RowParameter::Column {
            parameter: row_parameter,
            column: column.clone(),
        },
        RowParameterSource::Constant(value) => RowParameter::Literal {
            parameter: row_parameter,
            value: value.to_string(),
        },
    };

    let (request_type, operator) = match comparison {
        RequestComparison::CallerSetHolds => {
            (ConditionParameter::ListOf(STRING_PARAMETER_TYPE), "in")
        }
        RequestComparison::CallerValueEquals => {
            (ConditionParameter::Scalar(STRING_PARAMETER_TYPE), "==")
        }
    };
    let expression = format!(
        "{} {operator} {request_parameter}",
        row_parameter.parameter()
    );
    let spec = ConditionSpec {
        expression,
        parameters: [
            (
                row_parameter.parameter().to_string(),
                ConditionParameter::Scalar(STRING_PARAMETER_TYPE),
            ),
            (request_parameter.clone(), request_type),
        ]
        .into_iter()
        .collect(),
        row_parameter: row_parameter.clone(),
    };
    let condition = declare_condition(table_plan, policy_name, spec);

    let relation = table_plan.ensure_direct(
        conditional_gate_relation_name(policy_name),
        vec![DirectSubject::ConditionalWildcard {
            type_name: USER_TYPE.to_string(),
            condition: condition.clone(),
        }],
    );
    table_plan.add_source(TupleSource::SessionAttributeGate {
        table: source_table.to_string(),
        pk_cols,
        relation: relation.clone(),
        condition,
        row_parameter,
        request_parameter,
        setting_key: source.setting_key().to_string(),
        separator: separator.map(str::to_string),
        comparison,
    });
    Some(UsersetExpr::Computed(relation))
}

/// The request's half of the comparison, as the policy declared it.
#[derive(Clone, Copy)]
pub(crate) struct RequestSide<'a> {
    /// The declared source, carrying the parameter the caller supplies.
    pub(crate) source: &'a SessionAttribute,
    /// How the two sides are compared.
    pub(crate) comparison: RequestComparison,
    /// Separator the policy splits the setting on, for a set.
    pub(crate) separator: Option<&'a str>,
}

/// Where the tuple's side of the comparison comes from.
#[derive(Debug, Clone, Copy)]
pub(crate) enum RowParameterSource<'a> {
    /// A column of the guarded row.
    Column(&'a ColumnName),
    /// A constant the policy named, so every row carries the same one.
    Constant(&'a str),
}

impl RowParameterSource<'_> {
    fn parameter_base(&self) -> &str {
        match self {
            Self::Column(column) => column.as_str(),
            // The rule supplies it, so it is named after what it is rather than after
            // its value, which may be any text at all.
            Self::Constant(_) => "required_value",
        }
    }
}

/// Declare `spec` under a name free in this type plan, and answer with that name.
///
/// A policy name is unique only per table and a condition name is global to the model, so
/// the base is keyed on both. One policy covering several commands mints the same guard
/// once per command, which is why an identical spec reuses its name: only a **different**
/// guard inside one policy takes the suffix.
pub(crate) fn declare_condition(
    table_plan: &mut TypePlan,
    policy_name: &str,
    spec: ConditionSpec,
) -> String {
    let base = gate_condition_name(table_plan.type_name.as_str(), policy_name);
    // One more candidate than there are conditions, so one is always free.
    let ceiling = table_plan.conditions.len() + 2;
    let name = core::iter::once(base.clone())
        .chain((2..=ceiling).map(|nth| format!("{base}_{nth}")))
        .find(|candidate| {
            table_plan
                .conditions
                .get(candidate)
                .is_none_or(|existing| *existing == spec)
        })
        .unwrap_or(base);
    table_plan.conditions.insert(name.clone(), spec);
    name
}

/// Mint the relation, the condition and the tuple source a request-time guard needs.
///
/// Returns `None` when the row cannot be identified or the column's type has no
/// condition parameter type, so the caller falls back to closing the policy.
pub(crate) fn conditional_gate_expr<DB: DatabaseLike>(
    request: &AttributeRequestPredicate,
    policy_name: &str,
    source_table: &str,
    table_plan: &mut TypePlan,
    db: &DB,
    request_time_parameter: &str,
) -> Option<UsersetExpr> {
    let pk_cols = resolve_pk_columns(source_table, db)?;
    let parameter_type = condition_parameter_type(source_table, request.column.as_str(), db)?;

    // A column named like the request's parameter yields, since two parameters cannot
    // share one name.
    let request_parameter = request_time_parameter.to_string();
    let mut row_parameter = normalize_relation_name(request.column.as_str());
    if row_parameter == request_parameter {
        row_parameter = format!(
            "{row_parameter}_{}",
            stable_hex_suffix(request.column.as_str())
        );
    }
    let operator = condition_operator(request.operator);

    let condition = declare_condition(
        table_plan,
        policy_name,
        ConditionSpec {
            expression: format!("{row_parameter} {operator} {request_parameter}"),
            parameters: [
                (
                    row_parameter.clone(),
                    ConditionParameter::Scalar(parameter_type),
                ),
                (
                    request_parameter,
                    ConditionParameter::Scalar(TIMESTAMP_PARAMETER_TYPE),
                ),
            ]
            .into_iter()
            .collect(),
            row_parameter: RowParameter::Column {
                parameter: row_parameter.clone(),
                column: request.column.clone(),
            },
        },
    );

    let relation = table_plan.ensure_direct(
        conditional_gate_relation_name(policy_name),
        vec![DirectSubject::ConditionalWildcard {
            type_name: USER_TYPE.to_string(),
            condition: condition.clone(),
        }],
    );
    table_plan.add_source(TupleSource::ConditionalAttributeGate {
        table: source_table.to_string(),
        pk_cols,
        relation: relation.clone(),
        condition,
        row_parameter,
        column: request.column.clone(),
    });
    Some(UsersetExpr::Computed(relation))
}

/// `CEL` spelling of the comparison, which matches SQL for the operators reaching here.
pub(crate) fn condition_operator(operator: AttributeOperator) -> &'static str {
    match operator {
        AttributeOperator::Eq => "==",
        AttributeOperator::NotEq => "!=",
        AttributeOperator::Gt => ">",
        AttributeOperator::GtEq => ">=",
        AttributeOperator::Lt => "<",
        AttributeOperator::LtEq => "<=",
    }
}

/// The condition parameter type for a column, or `None` when the schema does not say
/// or the type has no `OpenFGA` counterpart.
pub(crate) fn condition_parameter_type<DB: DatabaseLike>(
    table: &str,
    column: &str,
    db: &DB,
) -> Option<&'static str> {
    let meta = lookup_table(db, table)?;
    let declared = meta
        .columns(db)
        .into_iter()
        .flatten()
        .find(|candidate| same_identifier(&candidate.stored_column_name(), column))?;
    let data_type = declared.data_type(db).to_lowercase();
    // A tuple's context must be RFC 3339, which only a zoned column renders: a date
    // carries no time part and a zoneless timestamp no offset, and `OpenFGA` v1.11.6
    // refuses both at load while accepting the model that named them.
    matches!(
        data_type.as_str(),
        "timestamptz" | "timestamp with time zone"
    )
    .then_some(TIMESTAMP_PARAMETER_TYPE)
}

/// The gate a request-scoped comparison earns, for all four of the declared shapes.
///
/// P14 to P17 differ only in how the two sides are compared and whether the row's side is a
/// column or a constant the policy named. One emitter answers all four, and the model cannot
/// describe two of them apart, so writing the same tail four times only invited them to drift.
pub(crate) fn emit_request_gate<DB: DatabaseLike>(
    declared: RequestSide<'_>,
    carried: RowParameterSource<'_>,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
) -> UsersetExpr {
    session_attribute_expr(
        declared,
        carried,
        ctx.policy_name,
        ctx.source_table,
        table_plan,
        ctx.db,
    )
    .unwrap_or_else(|| {
        skip_source_without_row_identity(
            table_plan,
            ctx.source_table,
            "request-scoped gate tuples",
            ctx.db,
        );
        deny_expr(table_plan)
    })
}

/// A membership row whose member value the caller's declared set has to contain.
pub(crate) fn emit_membership_in_caller_set<DB: DatabaseLike>(
    membership_in_caller_set: &MembershipInCallerSet,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
    notes: &mut Vec<TranslationNote>,
    readability: &mut BTreeMap<String, JoinTableReadability>,
) -> UsersetExpr {
    let MembershipInCallerSet {
        join_table,
        fk_column,
        outer_column,
        member_column,
        separator,
        source,
        extra_predicates,
    } = membership_in_caller_set;
    let policy_name = ctx.policy_name;
    let db = ctx.db;
    let source_table = ctx.source_table;
    // The gate names the guarded row by the join table's own column, so that
    // column has to hold the row's identifier. Correlated against anything else,
    // the object named is another row's, or no row at all.
    if single_pk_column(source_table, db).as_ref() != Some(outer_column) {
        notes.push(TranslationNote::ExpressionRefused {
            policy: policy_name.to_string(),
            reason: format!(
                "the policy correlates '{outer_column}', which does not identify a \
                     row of {source_table}, so no tuple can name the row the grant is on"
            ),
        });
        return deny_expr(table_plan);
    }
    // The subquery reads `join_table` as the caller, so its own RLS decides which
    // membership rows count, exactly as it does for a membership naming a person.
    let read_scope_roles = match join_table_readability(join_table, db, readability) {
        JoinTableReadability::Unreadable => {
            notes.push(TranslationNote::MembershipTableGrantsNoReads {
                policy: policy_name.to_string(),
                join_table: join_table.clone(),
            });
            return deny_expr(table_plan);
        }
        JoinTableReadability::Guarded { roles } => {
            notes.push(TranslationNote::MembershipTableGuarded {
                policy: policy_name.to_string(),
                join_table: join_table.clone(),
            });
            roles
        }
        JoinTableReadability::Open => Vec::new(),
    };
    if !read_scope_roles.is_empty() {
        // Only those roles see the membership rows, so only they inherit the
        // grant. This shape has no rule for intersecting a role scope with a
        // request-completed gate, so it falls closed rather than widening.
        notes.push(TranslationNote::ExpressionRefused {
            policy: policy_name.to_string(),
            reason: format!(
                "only {} may read {join_table}, and a request-scoped gate cannot \
                     yet be narrowed to a role scope",
                read_scope_roles.join(", ")
            ),
        });
        return deny_expr(table_plan);
    }

    if let Some(extra) = extra_predicates.sql() {
        notes.push(TranslationNote::MembershipExtraPredicate {
            policy: policy_name.to_string(),
            predicate: extra,
        });
    }

    let request_parameter = source.request_parameter().to_string();
    let mut row_parameter = normalize_relation_name(member_column.as_str());
    if row_parameter == request_parameter {
        row_parameter = format!(
            "{row_parameter}_{}",
            stable_hex_suffix(member_column.as_str())
        );
    }
    let spec = ConditionSpec {
        expression: format!("{row_parameter} in {request_parameter}"),
        parameters: [
            (
                row_parameter.clone(),
                ConditionParameter::Scalar(STRING_PARAMETER_TYPE),
            ),
            (
                request_parameter.clone(),
                ConditionParameter::ListOf(STRING_PARAMETER_TYPE),
            ),
        ]
        .into_iter()
        .collect(),
        row_parameter: RowParameter::Column {
            parameter: row_parameter.clone(),
            column: member_column.clone(),
        },
    };
    let condition = declare_condition(table_plan, policy_name, spec);
    let relation = table_plan.ensure_direct(
        conditional_gate_relation_name(policy_name),
        vec![DirectSubject::ConditionalWildcard {
            type_name: USER_TYPE.to_string(),
            condition: condition.clone(),
        }],
    );
    table_plan.add_source(TupleSource::SessionAttributeMembershipGate {
        join_table: join_table.clone(),
        fk_col: fk_column.clone(),
        member_col: member_column.clone(),
        parent_type: table_plan.type_name.to_string(),
        relation: relation.clone(),
        condition,
        row_parameter,
        request_parameter,
        setting_key: source.setting_key().to_string(),
        separator: separator.clone(),
        extra_predicates: extra_predicates.clone(),
    });
    UsersetExpr::Computed(relation)
}

//! Emission for the patterns the request completes rather than the row.
//!
//! A declared setting or token claim supplies the caller's half, so the row carries its value in
//! a condition rather than in the tuple's subject. Also the conditions an attribute guard needs
//! when the value is one only the request knows.

use super::emit_membership::announce_residual;
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
    source_table: &TableId,
    table_plan: &mut TypePlan,
    condition_parameters: &ConditionParameterAllocator,
    db: &DB,
) -> Option<UsersetExpr> {
    let RequestSide {
        source,
        comparison,
        separator,
    } = declared;
    let identity_cols = resolve_row_identity(source_table, db)?;

    let request_parameter = source.condition_parameter().clone();
    let mut namespace = condition_parameters.namespace([&request_parameter]);
    let row_parameter = namespace.allocate_row(carried.parameter_base());
    let row_parameter = match carried {
        RowParameterSource::Column(column) => RowParameter::Column {
            parameter: row_parameter.to_string(),
            column: column.clone(),
        },
        RowParameterSource::Constant(value) => RowParameter::Literal {
            parameter: row_parameter.to_string(),
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
        _ => return None,
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
            (request_parameter.to_string(), request_type),
        ]
        .into_iter()
        .collect(),
        row_parameter: row_parameter.clone(),
    };
    let condition = declare_condition(table_plan, policy_name, spec);

    let relation = table_plan.ensure_direct(
        conditional_gate_relation_name(policy_name),
        vec![DirectSubject::ConditionalWildcard {
            type_name: table_plan.well_known.user.clone(),
            condition: condition.clone(),
        }],
    );
    table_plan.add_source(TupleSource::SessionAttributeGate {
        table: source_table.clone(),
        identity_cols,
        relation: relation.clone(),
        condition,
        row_parameter,
        request_parameter: request_parameter.to_string(),
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
    source_table: &TableId,
    table_plan: &mut TypePlan,
    condition_parameters: &ConditionParameterAllocator,
    db: &DB,
    request_time_parameter: &ConditionParameterName,
) -> Option<UsersetExpr> {
    let identity_cols = resolve_row_identity(source_table, db)?;
    let parameter_type = condition_parameter_type(source_table, request.column.as_str(), db)?;

    let request_parameter = request_time_parameter.clone();
    let mut namespace = condition_parameters.namespace([&request_parameter]);
    let row_parameter = namespace.allocate_row(request.column.as_str());
    let operator = condition_operator(request.operator)?;

    let condition = declare_condition(
        table_plan,
        policy_name,
        ConditionSpec {
            expression: format!(
                "{row_parameter} {operator} {}",
                clock_expr(request_parameter.as_str(), request.offset.as_ref())
            ),
            parameters: [
                (
                    row_parameter.to_string(),
                    ConditionParameter::Scalar(parameter_type),
                ),
                (
                    request_parameter.to_string(),
                    ConditionParameter::Scalar(TIMESTAMP_PARAMETER_TYPE),
                ),
            ]
            .into_iter()
            .collect(),
            row_parameter: RowParameter::Column {
                parameter: row_parameter.to_string(),
                column: request.column.clone(),
            },
        },
    );

    let relation = table_plan.ensure_direct(
        conditional_gate_relation_name(policy_name),
        vec![DirectSubject::ConditionalWildcard {
            type_name: table_plan.well_known.user.clone(),
            condition: condition.clone(),
        }],
    );
    table_plan.add_source(TupleSource::ConditionalAttributeGate {
        table: source_table.clone(),
        identity_cols,
        relation: relation.clone(),
        condition,
        row_parameter: row_parameter.to_string(),
        column: request.column.clone(),
    });
    Some(UsersetExpr::Computed(relation))
}

/// `CEL` spelling of the comparison, which matches SQL for the operators reaching here.
pub(crate) fn condition_operator(operator: AttributeOperator) -> Option<&'static str> {
    match operator {
        AttributeOperator::Eq => Some("=="),
        AttributeOperator::NotEq => Some("!="),
        AttributeOperator::Gt => Some(">"),
        AttributeOperator::GtEq => Some(">="),
        AttributeOperator::Lt => Some("<"),
        AttributeOperator::LtEq => Some("<="),
        _ => None,
    }
}

/// The request clock as a CEL expression, shifted by a fixed offset when the guard
/// carried one (`now() - interval '30 days'` becomes `request_time - duration("720h")`).
pub(crate) fn clock_expr(request_time_parameter: &str, offset: Option<&TemporalOffset>) -> String {
    match offset {
        None => request_time_parameter.to_string(),
        // `{:?}` wraps the CEL duration in the quotes it needs without hand-writing them.
        Some(offset) => format!(
            "{request_time_parameter} {} duration({:?})",
            if offset.subtract { "-" } else { "+" },
            offset.cel_duration
        ),
    }
}

/// The condition parameter type for a column, or `None` when the schema does not say
/// or the type has no `OpenFGA` counterpart.
pub(crate) fn condition_parameter_type<DB: DatabaseLike>(
    table: &TableId,
    column: &str,
    db: &DB,
) -> Option<&'static str> {
    (column_kind(table, column, db) == ColumnKind::TimestampTz).then_some(TIMESTAMP_PARAMETER_TYPE)
}

/// One temporal comparison lifted into a condition: the parameter the row fills, the
/// column it reads, and the CEL fragment comparing it against the request clock.
pub(crate) struct TemporalGate {
    pub(crate) parameter: ConditionParameterName,
    pub(crate) column: ColumnName,
    pub(crate) fragment: String,
    pub(crate) witness: ContextWitness,
}

/// The compressing aggregate's direction for one comparison, `None` for an operator
/// no condition can carry.
fn context_witness(operator: AttributeOperator) -> Option<ContextWitness> {
    match operator {
        AttributeOperator::Gt
        | AttributeOperator::GtEq
        | AttributeOperator::Eq
        | AttributeOperator::NotEq => Some(ContextWitness::Latest),
        AttributeOperator::Lt | AttributeOperator::LtEq => Some(ContextWitness::Earliest),
        _ => None,
    }
}

/// Turn a residual's temporal comparisons (`col > now()`) into condition fragments
/// against the clock the request supplies.
///
/// [`None`] when the residual is not decidable off the row and the clock, or a temporal
/// column has no timestamp parameter type: the caller then leaves the residual in SQL and
/// the shape stays joined, exactly as it did before the clock could be a condition.
pub(crate) fn temporal_gates<DB: DatabaseLike>(
    residual: &ResidualPredicates,
    table: &TableId,
    request_time_parameter: &ConditionParameterName,
    namespace: &mut ConditionParameterNamespace,
    db: &DB,
) -> Option<Vec<TemporalGate>> {
    let decision = residual.decidable()?;
    let mut gates = Vec::with_capacity(decision.requests.len());
    for request in &decision.requests {
        // A zoned column has a timestamp parameter. Anything else cannot be a faithful
        // condition, so the whole residual stays in SQL.
        condition_parameter_type(table, request.column.as_str(), db)?;
        let parameter = namespace.allocate_row(request.column.as_str());
        gates.push(TemporalGate {
            fragment: format!(
                "{parameter} {} {}",
                condition_operator(request.operator)?,
                clock_expr(request_time_parameter.as_str(), request.offset.as_ref())
            ),
            column: request.column.clone(),
            witness: context_witness(request.operator)?,
            parameter,
        });
    }
    Some(gates)
}

/// Declare a condition comparing one or more row columns against the request clock, and
/// answer with its name and the context columns a tuple must carry.
///
/// [`None`] when the residual is not decidable off the row and the clock, or carries no
/// clock at all: the caller then keeps the residual in SQL and the shape stays joined.
pub(crate) fn declare_temporal_condition<DB: DatabaseLike>(
    residual: &ResidualPredicates,
    table: &TableId,
    policy_name: &str,
    table_plan: &mut TypePlan,
    request_time_parameter: &ConditionParameterName,
    condition_parameters: &ConditionParameterAllocator,
    db: &DB,
) -> Option<(String, Vec<GateContextColumn>)> {
    let mut namespace = condition_parameters.namespace([request_time_parameter]);
    let gates = temporal_gates(residual, table, request_time_parameter, &mut namespace, db)?;
    let [first, ..] = gates.as_slice() else {
        return None;
    };
    let expression = gates
        .iter()
        .map(|gate| gate.fragment.as_str())
        .collect::<Vec<_>>()
        .join(" && ");
    let mut parameters: BTreeMap<String, ConditionParameter> = gates
        .iter()
        .map(|gate| {
            (
                gate.parameter.to_string(),
                ConditionParameter::Scalar(TIMESTAMP_PARAMETER_TYPE),
            )
        })
        .collect();
    parameters.insert(
        request_time_parameter.to_string(),
        ConditionParameter::Scalar(TIMESTAMP_PARAMETER_TYPE),
    );
    let row_parameter = RowParameter::Column {
        parameter: first.parameter.to_string(),
        column: first.column.clone(),
    };
    let condition = declare_condition(
        table_plan,
        policy_name,
        ConditionSpec {
            expression,
            parameters,
            row_parameter,
        },
    );
    let context = gates
        .into_iter()
        .map(|gate| GateContextColumn {
            parameter: gate.parameter.to_string(),
            column: gate.column,
            witness: gate.witness,
        })
        .collect();
    Some((condition, context))
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
        ctx.condition_parameters,
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
    all_types: &mut BTreeMap<TypeName, TypePlan>,
    notes: &mut Vec<TranslationNote>,
    readability: &mut BTreeMap<TableId, JoinTableReadability>,
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
    // The bridge names the guarded row by the join table's own column, so that column has
    // to hold the row's identifier. Correlated against anything else, the object named is
    // another row's, or no row at all.
    if single_identity_column(source_table, db).as_ref() != Some(outer_column) {
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
    let Some(read_scope_roles) = noted_membership_read_scope(join_table, ctx, readability, notes)
    else {
        return deny_expr(table_plan);
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
    // Each share row becomes its own object, keyed on the join table's own primary key, so
    // two viewers of one guarded row never collide on one `(user:*, gate, object)` triple.
    // With no key to name the share rows apart, that collision is unavoidable, so refuse.
    let Some(identity_cols) = resolve_row_identity(join_table, db) else {
        notes.push(TranslationNote::ExpressionRefused {
            policy: policy_name.to_string(),
            reason: format!(
                "{join_table} has no primary key, so its share rows cannot be named apart \
                     and two viewers of one row would collide at load"
            ),
        });
        return deny_expr(table_plan);
    };

    let request_parameter = source.condition_parameter().clone();
    let request_time = ctx.settings.request_time_parameter.clone();
    let mut namespace = ctx
        .condition_parameters
        .namespace([&request_parameter, &request_time]);
    let row_parameter = namespace.allocate_row(member_column.as_str());

    // A temporal comparison such as `expires_at > now()` is completed by the request, not
    // the row, so it joins the viewer set inside the condition rather than filtering the
    // query. Everything else stays in the residual: a row guard the query keeps, or an
    // inexpressible conjunct that keeps the shape joined.
    let temporal = temporal_gates(
        extra_predicates,
        join_table,
        &request_time,
        &mut namespace,
        db,
    )
    .unwrap_or_default();

    announce_residual(extra_predicates, !temporal.is_empty(), policy_name, notes);

    let mut expression = format!("{row_parameter} in {request_parameter}");
    let mut parameters = vec![
        (
            row_parameter.to_string(),
            ConditionParameter::Scalar(STRING_PARAMETER_TYPE),
        ),
        (
            request_parameter.to_string(),
            ConditionParameter::ListOf(STRING_PARAMETER_TYPE),
        ),
    ];
    for gate in &temporal {
        expression = format!("{expression} && {}", gate.fragment);
        parameters.push((
            gate.parameter.to_string(),
            ConditionParameter::Scalar(TIMESTAMP_PARAMETER_TYPE),
        ));
    }
    if !temporal.is_empty() {
        parameters.push((
            request_time.to_string(),
            ConditionParameter::Scalar(TIMESTAMP_PARAMETER_TYPE),
        ));
    }
    let spec = ConditionSpec {
        expression,
        parameters: parameters.into_iter().collect(),
        row_parameter: RowParameter::Column {
            parameter: row_parameter.to_string(),
            column: member_column.clone(),
        },
    };

    // The gate rides the share type, keyed on the share row. The guarded type links to it
    // and reaches the gate by tuple-to-userset, so two viewers union rather than collide.
    let share_type = share_type_name(join_table, ctx.table_types);
    let (gate_relation, condition) = {
        let share_plan = all_types.entry(share_type.clone()).or_insert_with(|| {
            TypePlan::new_with_well_known(share_type.clone(), &ctx.settings.well_known)
        });
        let condition = declare_condition(share_plan, policy_name, spec);
        let gate_relation = share_plan.ensure_direct(
            conditional_gate_relation_name(policy_name),
            vec![DirectSubject::ConditionalWildcard {
                type_name: ctx.settings.well_known.user.clone(),
                condition: condition.clone(),
            }],
        );
        (gate_relation, condition)
    };

    let temporal_context: Vec<GateContextColumn> = temporal
        .into_iter()
        .map(|gate| GateContextColumn {
            parameter: gate.parameter.to_string(),
            column: gate.column,
            witness: gate.witness,
        })
        .collect();
    let gate_source = TupleSource::CallerSetShareGate {
        join_table: join_table.clone(),
        identity_cols: identity_cols.clone(),
        share_type: share_type.clone(),
        relation: gate_relation.clone(),
        condition,
        row_parameter: row_parameter.to_string(),
        member_col: member_column.clone(),
        request_parameter: request_parameter.to_string(),
        setting_key: source.setting_key().to_string(),
        separator: separator.clone(),
        extra_predicates: extra_predicates.clone(),
        temporal_context,
    };
    if let Some(share_plan) = all_types.get_mut(&share_type) {
        share_plan.add_source(gate_source.clone());
    }

    let guarded_type = table_plan.type_name.clone();
    let link_relation = table_plan.ensure_direct(
        clamp_relation_name(share_type.to_string()),
        vec![DirectSubject::Type(share_type.clone())],
    );
    table_plan.add_source(gate_source);
    table_plan.add_source(TupleSource::ShareBridge {
        join_table: join_table.clone(),
        identity_cols,
        object_cols: vec![fk_column.clone()],
        guarded_type,
        share_type,
        relation: link_relation.clone(),
    });
    UsersetExpr::TupleToUserset {
        tupleset: link_relation,
        computed: gate_relation,
    }
}

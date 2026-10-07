use super::subquery::{
    classify_membership_select, combine_predicates_with_and, diagnose_membership_select_ambiguity,
    exists_subquery_select, join_on_expr, membership_exists_from_in_subquery,
    qualifier_matches_table, session_zoned_columns, strip_qualifier_from_expr_deep,
    table_factor_is_sampled, table_factor_parts, written_tables_are_same,
};
use super::{
    conjunct_reads_only_the_row, extract_qualified_column, flatten_and_predicates,
    residual_predicate_reading, residual_relations, stored_ident_name, stored_relation_name,
    unparenthesize, MembershipScope,
};
use crate::classifier::expansion::ExpansionState;
use crate::classifier::function_registry::FunctionRegistry;
use crate::classifier::patterns::{
    composite_confidence, BoolOp, ClassifiedExpr, Composite, ConfidenceLevel, ExistsMembership,
    IndirectMembership, MembershipJoinPair, PatternClass, ResidualPredicates,
};
#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use crate::parser::names::{
    lookup_table_id, resolve_table_id, table_id_has_column, table_identity,
};
use crate::parser::sql_parser::{ColumnLike, DatabaseLike, ForeignKeyLike, TableLike};
use crate::types::{ColumnName, TableId};
use alloc::collections::BTreeSet;
use core::ops::ControlFlow;
use sqlparser::ast::{
    BinaryOperator, Expr, GroupByExpr, Ident, Join, JoinOperator, Select, SelectFlavor, SelectItem,
    TableFactor, TableWithJoins, Value, Visit, Visitor,
};

/// Recognize membership reached through a closure table.
pub fn recognize_p19<DB: DatabaseLike>(
    expr: &Expr,
    db: &DB,
    registry: &FunctionRegistry,
    outer_table: &str,
    state: &ExpansionState,
) -> Option<ClassifiedExpr> {
    p19_outcome(expr, db, registry, outer_table, state).ok()
}

pub(crate) fn diagnose_p19_indirect_membership_ambiguity<DB: DatabaseLike>(
    expr: &Expr,
    db: &DB,
    registry: &FunctionRegistry,
    outer_table: &str,
    state: &ExpansionState,
) -> Option<String> {
    match p19_outcome(expr, db, registry, outer_table, state) {
        Ok(_) | Err(P19Refusal::NotThisShape) => None,
        Err(P19Refusal::Refused(reason)) => Some(reason),
    }
}

/// The proven shape of a classified two-hop membership, re-derived from the catalog.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ProvenIndirectMembership {
    /// The bridge's pairs ordered by the guarded table's primary key.
    pub bridge_pairs: Vec<MembershipJoinPair>,
    /// The far's pairs ordered by the owner table's primary key.
    pub far_pairs: Vec<MembershipJoinPair>,
    /// The owner table the closure's columns point at.
    pub owner_table: TableId,
}

/// Re-prove the membership's keys and return their canonical order.
pub(crate) fn prove_indirect_membership<DB: DatabaseLike>(
    db: &DB,
    guarded_table: &TableId,
    membership: &IndirectMembership,
) -> Result<ProvenIndirectMembership, P19Refusal> {
    let bridge_name = table_stored_name(db, &membership.bridge_table);
    let guarded_name = table_stored_name(db, guarded_table);
    let bridge_pairs = bridge_identity_pairs(
        &membership.pairs,
        &membership.bridge_table,
        guarded_table,
        db,
        &guarded_name,
    )?;
    let (far_pairs, owner_table) = bridge_fk_owner_pairs(
        &membership.membership.pairs,
        &membership.bridge_table,
        &bridge_name,
        db,
    )?;
    if owner_table != membership.owner_table {
        return Err(refused(
            "the membership names a different owner table than its closure key",
        ));
    }
    let far = &membership.membership;
    let mut seen = BTreeSet::new();
    for pair in &far_pairs {
        if !seen.insert(&pair.join_column)
            || !table_id_has_column(db, &far.join_table, pair.join_column.as_str())
        {
            return Err(refused(
                "the far membership does not name distinct existing key columns",
            ));
        }
    }
    if !table_id_has_column(db, &far.join_table, far.user_column.as_str()) {
        return Err(refused(
            "the far membership names no existing member column",
        ));
    }
    Ok(ProvenIndirectMembership {
        bridge_pairs,
        far_pairs,
        owner_table,
    })
}

fn table_stored_name<DB: DatabaseLike>(db: &DB, identity: &TableId) -> String {
    lookup_table_id(db, identity)
        .map(|table| table.stored_table_name().into_owned())
        .unwrap_or_default()
}

/// Distinguish unsupported two-hop queries from unrelated expressions.
#[derive(Debug, thiserror::Error)]
pub(crate) enum P19Refusal {
    /// An unrelated expression.
    #[error("not a membership reached through a second table")]
    NotThisShape,
    /// A two-hop membership shape the classifier refuses, with the operator-facing reason.
    #[error("{0}")]
    Refused(String),
}

fn refused(reason: impl Into<String>) -> P19Refusal {
    P19Refusal::Refused(reason.into())
}

enum RefSide {
    Bridge(ColumnName),
    Guarded(ColumnName),
    Other,
}

fn p19_outcome<DB: DatabaseLike>(
    expr: &Expr,
    db: &DB,
    registry: &FunctionRegistry,
    outer_table: &str,
    state: &ExpansionState,
) -> Result<ClassifiedExpr, P19Refusal> {
    let expr = unparenthesize(expr);
    let normalized = membership_exists_from_in_subquery(expr, registry, outer_table);
    let expr = normalized.as_ref().map_or(expr, |e| e);
    let (select, refusal) = exists_subquery_select(expr).ok_or(P19Refusal::NotThisShape)?;
    if let Some(refusal) = refusal {
        return Err(refused(refusal.reason()));
    }

    let [outer_twj] = select.from.as_slice() else {
        return Err(P19Refusal::NotThisShape);
    };
    if outer_twj.joins.is_empty() && !select.selection.as_ref().is_some_and(has_far_check) {
        return Err(P19Refusal::NotThisShape);
    }
    let (bridge_name, bridge_alias) =
        table_factor_parts(&outer_twj.relation).ok_or(P19Refusal::NotThisShape)?;
    if !outer_twj.joins.is_empty()
        && select
            .selection
            .iter()
            .chain(
                outer_twj
                    .joins
                    .iter()
                    .filter_map(|join| join_on_expr(&join.join_operator)),
            )
            .any(|predicate| {
                bridge_reads_caller(predicate, registry, &bridge_name, bridge_alias.as_deref())
            })
    {
        return Err(P19Refusal::NotThisShape);
    }
    if table_factor_is_sampled(&outer_twj.relation) {
        return Err(refused(format!(
            "the closure table '{bridge_name}' is sampled, so a static tupleset would hold \
             every row the sample draws rather than the closure rows the policy walks"
        )));
    }
    let Some(bridge_id) = resolve_table_id(db, &bridge_name) else {
        return Err(refused(format!(
            "the closure table '{bridge_name}' does not resolve, so the walk through it is \
             not proven"
        )));
    };
    let Some(guarded_id) = resolve_table_id(db, outer_table) else {
        return Err(refused(format!(
            "the guarded table '{outer_table}' does not resolve, so the closure's identity of \
             it is not proven"
        )));
    };
    if !state.reading_as_owner()
        && written_tables_are_same(db, &bridge_name, outer_table).unwrap_or(true)
    {
        return Err(refused(format!(
            "the closure table is '{outer_table}', the table the policy guards, so \
             PostgreSQL would raise infinite recursion on every read and no closure row \
             names the guarded row"
        )));
    }
    let bridge_table = lookup_table_id(db, &bridge_id).ok_or_else(|| {
        refused(format!(
            "the closure table '{bridge_name}' cannot be read, so the walk through it is \
             not proven"
        ))
    })?;
    let guarded_table = lookup_table_id(db, &guarded_id).ok_or_else(|| {
        refused(format!(
            "the guarded table '{outer_table}' cannot be read, so the closure's identity of \
             it is not proven"
        ))
    })?;
    let bridge_cols = column_set(bridge_table, db, &bridge_name)?;
    let guarded_cols = column_set(guarded_table, db, outer_table)?;

    let (bridge_pairs, far_factor, far_conjuncts) = match outer_twj.joins.as_slice() {
        [] => nested_far_shape(
            select,
            registry,
            &bridge_name,
            bridge_alias.as_deref(),
            &bridge_cols,
            outer_table,
            &guarded_cols,
        )?,
        [join] => joined_far_shape(
            select,
            join,
            &bridge_name,
            bridge_alias.as_deref(),
            &bridge_cols,
            outer_table,
            &guarded_cols,
        )?,
        _ => {
            return Err(refused(format!(
                "the closure query joins {} tables, and only one far table is reached \
                 through the closure",
                outer_twj.joins.len()
            )))
        }
    };

    let bridge_pairs =
        bridge_identity_pairs(&bridge_pairs, &bridge_id, &guarded_id, db, outer_table)?;

    let (far_name, far_alias) = table_factor_parts(&far_factor).ok_or_else(|| {
        refused("the far table is not a plain table scan, so its membership row cannot be read")
    })?;
    if table_factor_is_sampled(&far_factor) {
        return Err(refused(format!(
            "the far table '{far_name}' is sampled, so a static membership relation would \
             hold every row the sample draws rather than the membership rows the policy reads"
        )));
    }
    let Some(far_id) = resolve_table_id(db, &far_name) else {
        return Err(refused(format!(
            "the far table '{far_name}' does not resolve, so its membership rows are not proven"
        )));
    };
    if written_tables_are_same(db, &far_name, &bridge_name).unwrap_or(true) {
        return Err(refused("the far membership rescans the closure table"));
    }
    if !state.reading_as_owner()
        && written_tables_are_same(db, &far_name, outer_table).unwrap_or(true)
    {
        return Err(refused(format!(
            "the far table is '{outer_table}', the table the policy guards, so PostgreSQL \
             would raise infinite recursion on every read and the membership row is not \
             readable from the policy"
        )));
    }
    if let (Some(bridge_alias), Some(far_alias)) = (&bridge_alias, &far_alias) {
        if bridge_alias == far_alias {
            return Err(refused(format!(
                "the closure and the far table are both aliased '{bridge_alias}', so a \
                 reference like '{bridge_alias}.col' cannot name one of them, give the far \
                 table its own alias"
            )));
        }
    }
    let far_table = lookup_table_id(db, &far_id).ok_or_else(|| {
        refused(format!(
            "the far table '{far_name}' cannot be read, so its membership rows are not proven"
        ))
    })?;
    let far_cols = column_set(far_table, db, &far_name)?;

    let (inner_conjuncts, in_list) = normalize_far_conjuncts(
        far_conjuncts,
        &far_name,
        far_alias.as_deref(),
        &far_cols,
        &bridge_name,
        bridge_alias.as_deref(),
        &bridge_cols,
    )?;

    let inner_select = inner_select_from_parts(far_factor, inner_conjuncts);
    let classified = classify_membership_select(&inner_select, db, registry, &bridge_name, state)
        .ok_or_else(|| {
        refused(
            diagnose_membership_select_ambiguity(&inner_select, db, registry, &bridge_name, state)
                .unwrap_or_else(|| {
                    "the far-table check does not name a membership row of the far table \
                     correlated to the closure"
                        .to_string()
                }),
        )
    })?;
    let PatternClass::P4ExistsMembership(p4) = &classified.pattern else {
        return Err(refused(
            match &classified.pattern {
                PatternClass::P13UncorrelatedMembership(_) => {
                    "the far-table check names no column of the closure, so it admits every \
                 closure row at once and the membership is not reached through it"
                }
                PatternClass::P18MembershipInCallerSet(_) => {
                    "the far table's member column holds a value the caller's declared set has \
                 to contain, which is a different membership than the caller's own identity \
                 this walk reads"
                }
                _ => "the far-table check does not read a membership row of the far table",
            }
            .to_string(),
        ));
    };

    let (far_pairs, owner_id) = bridge_fk_owner_pairs(&p4.pairs, &bridge_id, &bridge_name, db)?;

    let membership = IndirectMembership {
        bridge_table: bridge_id.clone(),
        pairs: bridge_pairs,
        owner_table: owner_id,
        membership: ExistsMembership {
            join_table: p4.join_table.clone(),
            pairs: far_pairs,
            user_column: p4.user_column.clone(),
            extra_predicates: p4.extra_predicates.clone(),
        },
    };

    let Some(role) = in_list else {
        return Ok(ClassifiedExpr {
            pattern: PatternClass::P19IndirectMembership(membership),
            confidence: ConfidenceLevel::A,
        });
    };
    split_in_list_leaves(
        &membership,
        &role,
        (&far_name, far_alias.as_deref()),
        &bridge_name,
        far_table,
        db,
        registry,
    )
}

fn bridge_reads_caller(
    expr: &Expr,
    registry: &FunctionRegistry,
    bridge_name: &str,
    bridge_alias: Option<&str>,
) -> bool {
    let (left, right) = match unparenthesize(expr) {
        Expr::BinaryOp {
            left,
            op: BinaryOperator::And,
            right,
        } => {
            return bridge_reads_caller(left, registry, bridge_name, bridge_alias)
                || bridge_reads_caller(right, registry, bridge_name, bridge_alias);
        }
        Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq,
            right,
        }
        | Expr::IsNotDistinctFrom(left, right) => (left.as_ref(), right.as_ref()),
        _ => return false,
    };
    let column = if super::is_current_user_expr(left, registry) {
        right
    } else if super::is_current_user_expr(right, registry) {
        left
    } else {
        return false;
    };
    let Expr::CompoundIdentifier(parts) = unparenthesize(column) else {
        return false;
    };
    let [.., qualifier, _] = parts.as_slice() else {
        return false;
    };
    qualifier_matches_table(&stored_ident_name(qualifier), bridge_name, bridge_alias)
}

fn has_far_check(expr: &Expr) -> bool {
    match unparenthesize(expr) {
        Expr::Exists { negated: false, .. } | Expr::InSubquery { negated: false, .. } => true,
        Expr::BinaryOp {
            left,
            op: BinaryOperator::And,
            right,
        } => has_far_check(left) || has_far_check(right),
        _ => false,
    }
}

fn inner_select_from_parts(factor: TableFactor, conjuncts: Vec<Expr>) -> Select {
    Select {
        select_token: sqlparser::ast::helpers::attached_token::AttachedToken::empty(),
        optimizer_hints: Vec::new(),
        distinct: None,
        select_modifiers: None,
        top: None,
        top_before_distinct: false,
        projection: vec![SelectItem::UnnamedExpr(Expr::Value(
            Value::Boolean(true).into(),
        ))],
        exclude: None,
        into: None,
        from: vec![TableWithJoins {
            relation: factor,
            joins: Vec::new(),
        }],
        lateral_views: Vec::new(),
        prewhere: None,
        selection: combine_predicates_with_and(conjuncts),
        connect_by: Vec::new(),
        group_by: GroupByExpr::Expressions(Vec::new(), Vec::new()),
        cluster_by: Vec::new(),
        distribute_by: Vec::new(),
        sort_by: Vec::new(),
        having: None,
        named_window: Vec::new(),
        qualify: None,
        window_before_qualify: false,
        value_table_mode: None,
        flavor: SelectFlavor::Standard,
    }
}

fn column_set<DB: DatabaseLike>(
    table: &DB::Table,
    db: &DB,
    table_name: &str,
) -> Result<BTreeSet<String>, P19Refusal> {
    let Ok(columns) = table.columns(db) else {
        return Err(refused(format!(
            "the columns of '{table_name}' cannot be read, so the references it carries are \
             not proven"
        )));
    };
    Ok(columns
        .into_iter()
        .map(|c| c.stored_column_name().into_owned())
        .collect())
}

/// Separate the guarded key from one nested membership check.
fn nested_far_shape(
    select: &Select,
    registry: &FunctionRegistry,
    bridge_name: &str,
    bridge_alias: Option<&str>,
    bridge_cols: &BTreeSet<String>,
    outer_table: &str,
    guarded_cols: &BTreeSet<String>,
) -> Result<(Vec<MembershipJoinPair>, TableFactor, Vec<Expr>), P19Refusal> {
    let mut conjuncts = Vec::new();
    if let Some(selection) = &select.selection {
        flatten_and_predicates(selection, &mut conjuncts);
    }
    let mut pairs = Vec::new();
    let mut far: Option<&Expr> = None;
    for conjunct in &conjuncts {
        if is_bare_true(conjunct) {
            continue;
        }
        match unparenthesize(conjunct) {
            Expr::Exists { negated: false, .. } | Expr::InSubquery { negated: false, .. } => {
                if far.is_some() {
                    return Err(refused(
                        "the closure query nests more than one far-table check, and only one \
                         membership is reached through the closure",
                    ));
                }
                far = Some(conjunct);
            }
            _ => {
                let pair = bridge_guarded_equality(
                    conjunct,
                    bridge_name,
                    bridge_alias,
                    bridge_cols,
                    outer_table,
                    guarded_cols,
                );
                let Some(pair) = pair else {
                    return Err(non_pair_conjunct(conjunct, outer_table));
                };
                pairs.push(pair);
            }
        }
    }
    let Some(far) = far else {
        return Err(P19Refusal::NotThisShape);
    };

    let far_exists: Option<Expr> = match unparenthesize(far) {
        Expr::InSubquery { .. } => Some(
            membership_exists_from_in_subquery(unparenthesize(far), registry, bridge_name)
                .ok_or_else(|| {
                    refused("the far subquery does not project its correlating column")
                })?,
        ),
        _ => None,
    };
    let far_exists = far_exists.as_ref().map_or(unparenthesize(far), |e| e);

    let (inner_select, refusal) =
        exists_subquery_select(far_exists).ok_or(P19Refusal::NotThisShape)?;
    if let Some(refusal) = refusal {
        return Err(refused(refusal.reason()));
    }
    let [twj] = inner_select.from.as_slice() else {
        return Err(refused(
            "the far-table check scans no table, so its membership row cannot be read",
        ));
    };
    if !twj.joins.is_empty() {
        return Err(refused(format!(
            "the far-table check joins {} tables, and only the far table itself is reached \
             through the closure",
            twj.joins.len()
        )));
    }
    if table_factor_is_sampled(&twj.relation) {
        return Err(refused(
            "the far table is sampled, so a static membership relation would hold every row \
             the sample draws rather than the membership rows the policy reads",
        ));
    }
    let mut far_conjuncts = Vec::new();
    if let Some(selection) = &inner_select.selection {
        let mut leaves = Vec::new();
        flatten_and_predicates(selection, &mut leaves);
        far_conjuncts = leaves.into_iter().cloned().collect();
    }
    Ok((pairs, twj.relation.clone(), far_conjuncts))
}

/// Separate the guarded key from the inner join's membership predicates.
fn joined_far_shape(
    select: &Select,
    join: &Join,
    bridge_name: &str,
    bridge_alias: Option<&str>,
    bridge_cols: &BTreeSet<String>,
    outer_table: &str,
    guarded_cols: &BTreeSet<String>,
) -> Result<(Vec<MembershipJoinPair>, TableFactor, Vec<Expr>), P19Refusal> {
    match join.join_operator {
        JoinOperator::Inner(_) | JoinOperator::Join(_) => {}
        _ => {
            return Err(refused(
                "the join to the far table is an outer join, which keeps the closure rows \
                 with no membership row, and no static tuple can carry that",
            ))
        }
    }
    let on = join_on_expr(&join.join_operator).ok_or_else(|| {
        refused(
            "the join to the far table carries no ON condition, so nothing ties the far row \
             to the closure",
        )
    })?;

    let mut pairs = Vec::new();
    let mut far_conjuncts = Vec::new();
    let mut leaves = Vec::new();
    flatten_and_predicates(on, &mut leaves);
    if let Some(selection) = &select.selection {
        flatten_and_predicates(selection, &mut leaves);
    }
    for conjunct in leaves {
        if is_bare_true(conjunct) {
            continue;
        }
        if let Some(pair) = bridge_guarded_equality(
            conjunct,
            bridge_name,
            bridge_alias,
            bridge_cols,
            outer_table,
            guarded_cols,
        ) {
            pairs.push(pair);
            continue;
        }
        let conjunct = unparenthesize(conjunct);
        if conjunct_references_guarded(conjunct, outer_table) {
            return Err(refused(format!(
                "the far membership reads the guarded row in {conjunct}"
            )));
        }
        if conjunct_names_a_subquery(conjunct) {
            return Err(refused(format!(
                "the far membership nests another query in {conjunct}"
            )));
        }
        far_conjuncts.push(conjunct.clone());
    }
    if far_conjuncts.is_empty() {
        return Err(refused(
            "the join to the far table carries no condition on the far row, so the \
             membership row is not readable",
        ));
    }
    Ok((pairs, join.relation.clone(), far_conjuncts))
}

fn non_pair_conjunct(conjunct: &Expr, outer_table: &str) -> P19Refusal {
    if conjunct_references_guarded(unparenthesize(conjunct), outer_table) {
        refused(format!(
            "the closure reads the guarded row outside its key in {conjunct}"
        ))
    } else {
        refused(format!(
            "the closure has an unsupported row predicate in {conjunct}"
        ))
    }
}

fn bridge_guarded_equality(
    conjunct: &Expr,
    bridge_name: &str,
    bridge_alias: Option<&str>,
    bridge_cols: &BTreeSet<String>,
    outer_table: &str,
    guarded_cols: &BTreeSet<String>,
) -> Option<MembershipJoinPair> {
    let Expr::BinaryOp {
        left,
        op: BinaryOperator::Eq,
        right,
    } = unparenthesize(conjunct)
    else {
        return None;
    };
    let (Some((lq, lc)), Some((rq, rc))) = (
        extract_qualified_column(left),
        extract_qualified_column(right),
    ) else {
        return None;
    };
    let left_side = ref_side(
        lq.as_deref(),
        &lc,
        bridge_name,
        bridge_alias,
        bridge_cols,
        outer_table,
        guarded_cols,
    );
    let right_side = ref_side(
        rq.as_deref(),
        &rc,
        bridge_name,
        bridge_alias,
        bridge_cols,
        outer_table,
        guarded_cols,
    );
    match (left_side, right_side) {
        (RefSide::Bridge(b), RefSide::Guarded(g)) | (RefSide::Guarded(g), RefSide::Bridge(b)) => {
            Some(MembershipJoinPair {
                join_column: b,
                outer_column: g,
            })
        }
        _ => None,
    }
}

fn ref_side(
    qualifier: Option<&str>,
    column: &ColumnName,
    bridge_name: &str,
    bridge_alias: Option<&str>,
    bridge_cols: &BTreeSet<String>,
    outer_table: &str,
    guarded_cols: &BTreeSet<String>,
) -> RefSide {
    if let Some(qualifier) = qualifier {
        let matches_bridge = qualifier_matches_table(qualifier, bridge_name, bridge_alias);
        let matches_guarded = qualifier_matches_table(qualifier, outer_table, None);
        if matches_bridge && matches_guarded {
            return RefSide::Other;
        }
        if matches_bridge {
            return if bridge_cols.contains(column.as_str()) {
                RefSide::Bridge(column.clone())
            } else {
                RefSide::Other
            };
        }
        if matches_guarded {
            return if guarded_cols.contains(column.as_str()) {
                RefSide::Guarded(column.clone())
            } else {
                RefSide::Other
            };
        }
        RefSide::Other
    } else {
        let in_bridge = bridge_cols.contains(column.as_str());
        let in_guarded = guarded_cols.contains(column.as_str());
        match (in_bridge, in_guarded) {
            (true, false) => RefSide::Bridge(column.clone()),
            (false, true) => RefSide::Guarded(column.clone()),
            _ => RefSide::Other,
        }
    }
}

fn conjunct_references_guarded(conjunct: &Expr, outer_table: &str) -> bool {
    let mut found = false;
    let visitor = |expr: &Expr| -> ControlFlow<()> {
        if let Expr::CompoundIdentifier(parts) = expr {
            if let [.., qualifier, _] = parts.as_slice() {
                let qualifier = stored_ident_name(qualifier);
                if qualifier_matches_table(&qualifier, outer_table, None) {
                    found = true;
                    return ControlFlow::Break(());
                }
            }
        }
        ControlFlow::Continue(())
    };
    let mut handle = FindVisitor(visitor);
    let _ = conjunct.visit(&mut handle);
    found
}

fn conjunct_names_a_subquery(conjunct: &Expr) -> bool {
    let mut found = false;
    let visitor = |expr: &Expr| -> ControlFlow<()> {
        match expr {
            Expr::Subquery(_) | Expr::Exists { .. } | Expr::InSubquery { .. } => {
                found = true;
                ControlFlow::Break(())
            }
            Expr::AnyOp { right, .. } | Expr::AllOp { right, .. } => {
                if matches!(right.as_ref(), Expr::Subquery(_)) {
                    found = true;
                    ControlFlow::Break(())
                } else {
                    ControlFlow::Continue(())
                }
            }
            _ => ControlFlow::Continue(()),
        }
    };
    let mut handle = FindVisitor(visitor);
    let _ = conjunct.visit(&mut handle);
    found
}

fn is_bare_true(conjunct: &Expr) -> bool {
    matches!(unparenthesize(conjunct), Expr::Value(value) if value.value == Value::Boolean(true))
}

struct FindVisitor<F>(F);

impl<F: FnMut(&Expr) -> ControlFlow<()>> Visitor for FindVisitor<F> {
    type Break = ();

    fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<()> {
        (self.0)(expr)
    }
}

/// Prove the closure identity and order it by the guarded primary key.
fn bridge_identity_pairs<DB: DatabaseLike>(
    pairs: &[MembershipJoinPair],
    bridge_id: &TableId,
    guarded_id: &TableId,
    db: &DB,
    outer_table: &str,
) -> Result<Vec<MembershipJoinPair>, P19Refusal> {
    if pairs.is_empty() {
        return Err(refused(
            "the closure query names no column of the guarded row, so the closure tuples \
             key nothing",
        ));
    }
    let bridge = lookup_table_id(db, bridge_id).ok_or_else(|| {
        refused("the closure table cannot be read, so its foreign keys are not proven")
    })?;
    let guarded = lookup_table_id(db, guarded_id).ok_or_else(|| {
        refused(format!(
            "the guarded table '{outer_table}' cannot be read, so its primary key is not proven"
        ))
    })?;
    let Ok(pk) = guarded.primary_key_columns(db) else {
        return Err(refused(format!(
            "the guarded table '{outer_table}' declares no primary key, so the closure's \
             identity of it is not proven"
        )));
    };
    let guarded_pk: Vec<String> = pk.map(|c| c.stored_column_name().into_owned()).collect();
    if guarded_pk.is_empty() {
        return Err(refused(format!(
            "the guarded table '{outer_table}' declares no primary key, so the closure's \
             identity of it is not proven"
        )));
    }

    let mut bridge_seen = BTreeSet::new();
    let mut guarded_seen = BTreeSet::new();
    for MembershipJoinPair {
        join_column: bridge_col,
        outer_column: guarded_col,
    } in pairs
    {
        if !bridge_seen.insert(bridge_col.as_str()) || !guarded_seen.insert(guarded_col.as_str()) {
            return Err(refused(
                "the closure equalities pair a column twice, so they do not name the \
                 guarded row as its key",
            ));
        }
    }
    if guarded_seen.len() != guarded_pk.len()
        || !guarded_pk
            .iter()
            .all(|column| guarded_seen.contains(column.as_str()))
    {
        return Err(refused(format!(
            "the closure equalities pair the guarded columns {} with the closure, but the \
             guarded table's primary key is {}, so the closure row does not name the \
             guarded row as its key",
            guarded_seen.iter().copied().collect::<Vec<_>>().join(", "),
            guarded_pk.join(", ")
        )));
    }

    let join_set: BTreeSet<&str> = pairs.iter().map(|pair| pair.join_column.as_str()).collect();
    let mut candidates: Vec<Vec<MembershipJoinPair>> = Vec::new();
    for fk in bridge.foreign_keys(db).into_iter().flatten() {
        let Ok(hosts) = fk.host_columns(db) else {
            continue;
        };
        let hosts: Vec<String> = hosts.map(|c| c.stored_column_name().into_owned()).collect();
        if hosts.len() != pairs.len()
            || hosts.iter().map(String::as_str).collect::<BTreeSet<_>>() != join_set
        {
            continue;
        }
        let (Ok(referenced_table), Ok(referenced)) =
            (fk.referenced_table(db), fk.referenced_columns(db))
        else {
            continue;
        };
        let referenced: Vec<String> = referenced
            .map(|c| c.stored_column_name().into_owned())
            .collect();
        let Ok(pk_ref) = referenced_table.primary_key_columns(db) else {
            continue;
        };
        let pk_ref: Vec<String> = pk_ref
            .map(|c| c.stored_column_name().into_owned())
            .collect();
        if pk_ref.is_empty()
            || pk_ref.len() != referenced.len()
            || pk_ref.iter().collect::<BTreeSet<_>>() != referenced.iter().collect::<BTreeSet<_>>()
        {
            continue;
        }
        let ref_id = table_identity(&referenced_table);
        let mut ordered = Vec::new();
        let mut ok = true;
        for pk_col in &pk_ref {
            let Some(pos) = referenced.iter().position(|r| r == pk_col) else {
                ok = false;
                break;
            };
            let Some(host) = hosts.get(pos) else {
                ok = false;
                break;
            };
            let Some(pair) = pairs
                .iter()
                .find(|pair| pair.join_column.as_str() == host.as_str())
            else {
                ok = false;
                break;
            };
            if ref_id == *guarded_id {
                if pair.outer_column.as_str() != pk_col.as_str() {
                    ok = false;
                    break;
                }
            } else if !guarded_column_references(
                db,
                guarded,
                pair.outer_column.as_str(),
                referenced_table,
                pk_col,
            ) {
                ok = false;
                break;
            }
            ordered.push(MembershipJoinPair {
                join_column: pair.join_column.clone(),
                outer_column: pair.outer_column.clone(),
            });
        }
        if ok {
            candidates.push(ordered);
            if candidates.len() > 1 {
                break;
            }
        }
    }

    match candidates.pop() {
        None => Err(refused(format!(
            "the closure columns {} are not tied to the guarded table's primary key {} by a \
             shared foreign key, so the closure row does not prove which guarded row it \
             belongs to",
            join_set.iter().copied().collect::<Vec<_>>().join(", "),
            guarded_pk.join(", ")
        ))),
        Some(mut candidate) if candidates.is_empty() => {
            for (index, column) in guarded_pk.iter().enumerate() {
                let Some((position, _)) = candidate
                    .iter()
                    .enumerate()
                    .skip(index)
                    .find(|(_, pair)| pair.outer_column.as_str() == column.as_str())
                else {
                    return Err(refused(
                        "the closure does not cover the guarded primary key",
                    ));
                };
                candidate.swap(index, position);
            }
            Ok(candidate)
        }
        Some(_) => Err(refused(
            "two foreign keys of the closure table cover the paired columns, so the entity \
             they name is ambiguous",
        )),
    }
}

fn guarded_column_references<DB: DatabaseLike>(
    db: &DB,
    guarded: &DB::Table,
    column: &str,
    entity: &DB::Table,
    entity_column: &str,
) -> bool {
    guarded.foreign_keys(db).into_iter().flatten().any(|fk| {
        fk.host_column(db)
            .ok()
            .flatten()
            .is_some_and(|h| h.stored_column_name() == column)
            && fk
                .referenced_table(db)
                .is_ok_and(|t| table_identity(t) == table_identity(entity))
            && fk
                .referenced_column(db)
                .ok()
                .flatten()
                .is_some_and(|c| c.stored_column_name() == entity_column)
    })
}

/// Prove the closure's owner foreign key and order the far pairs by its primary key.
fn bridge_fk_owner_pairs<DB: DatabaseLike>(
    far_pairs: &[MembershipJoinPair],
    bridge_id: &TableId,
    bridge_name: &str,
    db: &DB,
) -> Result<(Vec<MembershipJoinPair>, TableId), P19Refusal> {
    let bridge = lookup_table_id(db, bridge_id).ok_or_else(|| {
        refused("the closure table cannot be read, so its foreign keys are not proven")
    })?;
    let outer_set: BTreeSet<&str> = far_pairs.iter().map(|p| p.outer_column.as_str()).collect();
    let mut matched: Option<(Vec<MembershipJoinPair>, TableId)> = None;
    for fk in bridge.foreign_keys(db).into_iter().flatten() {
        let Ok(hosts) = fk.host_columns(db) else {
            continue;
        };
        let hosts: Vec<String> = hosts.map(|c| c.stored_column_name().into_owned()).collect();
        if hosts.len() != far_pairs.len()
            || hosts.iter().map(String::as_str).collect::<BTreeSet<_>>() != outer_set
        {
            continue;
        }
        let (Ok(referenced_table), Ok(referenced)) =
            (fk.referenced_table(db), fk.referenced_columns(db))
        else {
            continue;
        };
        let referenced: Vec<String> = referenced
            .map(|c| c.stored_column_name().into_owned())
            .collect();
        let Ok(pk) = referenced_table.primary_key_columns(db) else {
            continue;
        };
        let pk: Vec<String> = pk.map(|c| c.stored_column_name().into_owned()).collect();
        if pk.is_empty()
            || pk.len() != referenced.len()
            || pk.iter().collect::<BTreeSet<_>>() != referenced.iter().collect::<BTreeSet<_>>()
        {
            continue;
        }
        let ordered: Option<Vec<MembershipJoinPair>> = pk
            .iter()
            .map(|pk_col| {
                let pos = referenced.iter().position(|r| r == pk_col)?;
                let host = hosts.get(pos)?;
                far_pairs
                    .iter()
                    .find(|p| p.outer_column.as_str() == host.as_str())
                    .cloned()
            })
            .collect();
        let Some(ordered) = ordered else {
            continue;
        };
        if matched.is_some() {
            return Err(refused(format!(
                "two foreign keys of the closure table '{bridge_name}' cover the closure \
                 columns the far table joins on, so the owner they name is ambiguous"
            )));
        }
        matched = Some((ordered, table_identity(&referenced_table)));
    }
    match matched {
        Some((ordered, owner_id)) => Ok((ordered, owner_id)),
        None => Err(refused(format!(
            "the closure columns the far table joins on ({}) name no declared foreign key \
             of the closure table '{bridge_name}', so the owner object the closure row \
             points at is not proven",
            outer_set.iter().copied().collect::<Vec<_>>().join(", ")
        ))),
    }
}

/// A literal role list on one far column.
struct InListRole {
    column: ColumnName,
    literals: Vec<Expr>,
    original: Expr,
}

/// Normalize bridge references and extract one literal role list.
fn normalize_far_conjuncts(
    conjuncts: Vec<Expr>,
    far_name: &str,
    far_alias: Option<&str>,
    far_cols: &BTreeSet<String>,
    bridge_name: &str,
    bridge_alias: Option<&str>,
    bridge_cols: &BTreeSet<String>,
) -> Result<(Vec<Expr>, Option<InListRole>), P19Refusal> {
    let mut inner = Vec::new();
    let mut in_list: Option<InListRole> = None;
    for conjunct in conjuncts {
        if let Some(role) = in_list_role(&conjunct, far_name, far_alias, far_cols) {
            if in_list.is_some() {
                return Err(refused(
                    "the far residual carries two IN lists, and only one role list is split \
                     into per-role relations",
                ));
            }
            in_list = Some(role);
            continue;
        }
        let mut conjunct = conjunct;
        normalize_bridge_ref_in_equality(
            &mut conjunct,
            far_name,
            far_alias,
            far_cols,
            bridge_name,
            bridge_alias,
            bridge_cols,
        )?;
        inner.push(conjunct);
    }
    Ok((inner, in_list))
}

fn in_list_role(
    conjunct: &Expr,
    far_name: &str,
    far_alias: Option<&str>,
    far_cols: &BTreeSet<String>,
) -> Option<InListRole> {
    let Expr::InList {
        expr,
        list,
        negated: false,
    } = unparenthesize(conjunct)
    else {
        return None;
    };
    let (qualifier, column) = extract_qualified_column(expr)?;
    let is_far_ref = match qualifier.as_deref() {
        Some(qualifier) => qualifier_matches_table(qualifier, far_name, far_alias),
        None => far_cols.contains(column.as_str()),
    };
    if !is_far_ref {
        return None;
    }
    let mut literals = Vec::new();
    for element in list {
        if let Expr::Value(value) = element {
            if matches!(value.value, Value::Placeholder(_)) {
                return None;
            }
            literals.push(element.clone());
        } else {
            return None;
        }
    }
    Some(InListRole {
        column,
        literals,
        original: conjunct.clone(),
    })
}

/// Normalize the bridge qualifier in a far-to-bridge equality.
fn normalize_bridge_ref_in_equality(
    conjunct: &mut Expr,
    far_name: &str,
    far_alias: Option<&str>,
    far_cols: &BTreeSet<String>,
    bridge_name: &str,
    bridge_alias: Option<&str>,
    bridge_cols: &BTreeSet<String>,
) -> Result<(), P19Refusal> {
    let target = match unparenthesize(conjunct) {
        Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq,
            right,
        } => {
            let (left_ref, right_ref) = (
                extract_qualified_column(left),
                extract_qualified_column(right),
            );
            let (Some((lq, lc)), Some((rq, rc))) = (left_ref, right_ref) else {
                return Ok(());
            };
            let l_far = is_far_reference(lq.as_deref(), &lc, far_name, far_alias, far_cols);
            let r_far = is_far_reference(rq.as_deref(), &rc, far_name, far_alias, far_cols);
            let bridge = if l_far && !r_far {
                Some((false, &rc, rq.as_deref()))
            } else if r_far && !l_far {
                Some((true, &lc, lq.as_deref()))
            } else {
                None
            };
            match bridge {
                Some((left_side, column, qualifier)) => {
                    let is_bridge_ref = match qualifier {
                        Some(qualifier) => {
                            if qualifier_matches_table(qualifier, far_name, far_alias) {
                                false
                            } else if qualifier_matches_table(qualifier, bridge_name, bridge_alias)
                            {
                                if !bridge_cols.contains(column.as_str()) {
                                    return Err(refused(format!(
                                        "the far-table check references '{qualifier}.{column}', \
                                         a column the closure table has no, so the pairing \
                                         reaches no closure row"
                                    )));
                                }
                                true
                            } else {
                                false
                            }
                        }
                        None => {
                            !far_cols.contains(column.as_str())
                                && bridge_cols.contains(column.as_str())
                        }
                    };
                    is_bridge_ref.then(|| (left_side, column.clone()))
                }
                None => None,
            }
        }
        _ => None,
    };
    if let Some((left_side, column)) = target {
        let mut expr = conjunct;
        while let Expr::Nested(inner) = expr {
            expr = inner.as_mut();
        }
        if let Expr::BinaryOp { left, right, .. } = expr {
            let side = if left_side { left } else { right };
            **side = Expr::CompoundIdentifier(vec![
                Ident::with_quote('"', stored_relation_name(bridge_name)),
                Ident::with_quote('"', column.as_str()),
            ]);
        }
    }
    Ok(())
}

fn is_far_reference(
    qualifier: Option<&str>,
    column: &ColumnName,
    far_name: &str,
    far_alias: Option<&str>,
    far_cols: &BTreeSet<String>,
) -> bool {
    match qualifier {
        Some(qualifier) => {
            qualifier_matches_table(qualifier, far_name, far_alias)
                && far_cols.contains(column.as_str())
        }
        None => far_cols.contains(column.as_str()),
    }
}

/// Build one row-decidable membership leaf per listed role.
fn split_in_list_leaves<DB: DatabaseLike>(
    membership: &IndirectMembership,
    role: &InListRole,
    far_source: (&str, Option<&str>),
    bridge_name: &str,
    far_table: &DB::Table,
    db: &DB,
    registry: &FunctionRegistry,
) -> Result<ClassifiedExpr, P19Refusal> {
    let (far_name, far_alias) = far_source;
    let far_cols_vec: Vec<String> = far_table
        .columns(db)
        .into_iter()
        .flatten()
        .map(|c| c.stored_column_name().into_owned())
        .collect();
    let far_zoned = session_zoned_columns(far_table, db);
    let mut stripped = role.original.clone();
    strip_qualifier_from_expr_deep(&mut stripped, far_name, far_alias);
    if !conjunct_reads_only_the_row(&stripped, &far_cols_vec, &far_zoned) {
        return Err(refused(format!(
            "the far role list depends on more than its membership row in {stripped}"
        )));
    }
    let scope = MembershipScope {
        table: far_name,
        alias: far_alias,
        columns: &far_cols_vec,
        guarded_table: bridge_name,
    };
    let base_extra_conjuncts = membership.membership.extra_predicates.conjuncts();
    let leaves = role
        .literals
        .iter()
        .map(|literal| {
            let mut leaf = Expr::BinaryOp {
                left: Box::new(Expr::Identifier(Ident::with_quote(
                    '"',
                    role.column.as_str(),
                ))),
                op: BinaryOperator::Eq,
                right: Box::new(literal.clone()),
            };
            let relations =
                residual_relations(&mut leaf, Some(db), registry, &scope).ok_or_else(|| {
                    refused(
                        "the far role list's per-role equality reads a relation the \
                         membership row cannot carry",
                    )
                })?;
            let residual = residual_predicate_reading(&leaf, relations);
            let mut extras = base_extra_conjuncts.to_vec();
            extras.push(residual);
            let leaf_membership = IndirectMembership {
                bridge_table: membership.bridge_table.clone(),
                pairs: membership.pairs.clone(),
                owner_table: membership.owner_table.clone(),
                membership: ExistsMembership {
                    join_table: membership.membership.join_table.clone(),
                    pairs: membership.membership.pairs.clone(),
                    user_column: membership.membership.user_column.clone(),
                    extra_predicates: ResidualPredicates::new(extras),
                },
            };
            Ok(ClassifiedExpr {
                pattern: PatternClass::P19IndirectMembership(leaf_membership),
                confidence: ConfidenceLevel::A,
            })
        })
        .collect::<Result<Vec<_>, P19Refusal>>()?;
    if leaves.is_empty() {
        return Err(refused(
            "the far role list names no role, so no per-role relation is reached",
        ));
    }
    let confidence = composite_confidence(leaves.iter());
    Ok(ClassifiedExpr {
        pattern: PatternClass::P8Composite(Composite {
            op: BoolOp::Or,
            parts: leaves,
        }),
        confidence,
    })
}

use super::*;
use alloc::collections::BTreeSet;

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
        let analysis = analyze_p5_parent_inheritance(select.as_ref(), db, outer_table)?;

        let mut matches = Vec::new();
        for candidate in analysis.candidates {
            let P5InheritanceCandidate {
                parent_table,
                fk_column,
                inner_predicates,
            } = candidate;
            let Some(inner_expr) = combine_predicates_with_and(inner_predicates) else {
                continue;
            };
            let inner_classified = crate::classifier::policy_classifier::classify_expr(
                &inner_expr,
                db,
                registry,
                &parent_table,
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
                    parent_table,
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
    match analyze_membership_select(select, db, registry, projected_fk.as_deref()) {
        MembershipSelectAnalysis::Unique {
            join_table,
            inferred_fk_column,
            user_column,
            extra_predicate_sql,
        } => Some(ClassifiedExpr {
            pattern: PatternClass::P4ExistsMembership {
                join_table,
                fk_column: projected_fk.unwrap_or(inferred_fk_column),
                user_column,
                extra_predicate_sql,
            },
            confidence: ConfidenceLevel::A,
        }),
        MembershipSelectAnalysis::AmbiguousMultiple
        | MembershipSelectAnalysis::AmbiguousNoUniqueJoin
        | MembershipSelectAnalysis::NoMatch => None,
    }
}

enum MembershipSelectAnalysis {
    Unique {
        join_table: String,
        inferred_fk_column: String,
        user_column: String,
        extra_predicate_sql: Option<String>,
    },
    AmbiguousMultiple,
    AmbiguousNoUniqueJoin,
    NoMatch,
}

fn analyze_membership_select(
    select: &Select,
    db: &ParserDB,
    registry: &FunctionRegistry,
    projected_fk_hint: Option<&str>,
) -> MembershipSelectAnalysis {
    if membership_sources_include_ambiguous_unresolvable_shape(select, db)
        && selection_references_current_user(select, registry)
    {
        return MembershipSelectAnalysis::AmbiguousNoUniqueJoin;
    }

    // Fail closed when the same table appears more than once (self-join).
    // Self-joins add constraints we cannot express as static membership tuples;
    // accepting them would produce tuples more permissive than the original policy.
    let all_sources = relation_sources(select);
    let unique_table_count = all_sources
        .iter()
        .map(|s| normalize_relation_name(&s.table_name))
        .collect::<BTreeSet<_>>()
        .len();
    if unique_table_count != all_sources.len() {
        return MembershipSelectAnalysis::AmbiguousMultiple;
    }

    let mut matches = membership_matches(select, db, registry, projected_fk_hint);
    if matches.len() > 1 {
        return MembershipSelectAnalysis::AmbiguousMultiple;
    }
    match matches.pop() {
        Some((join_table, inferred_fk_column, user_column, extra_predicate_sql)) => {
            MembershipSelectAnalysis::Unique {
                join_table,
                inferred_fk_column,
                user_column,
                extra_predicate_sql,
            }
        }
        None if selection_references_current_user(select, registry) => {
            MembershipSelectAnalysis::AmbiguousNoUniqueJoin
        }
        None => MembershipSelectAnalysis::NoMatch,
    }
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
        match analyze_membership_select(select, db, registry, projected_fk) {
            MembershipSelectAnalysis::AmbiguousMultiple => Some(
                "Ambiguous membership pattern: multiple candidate membership sources matched"
                    .to_string(),
            ),
            MembershipSelectAnalysis::AmbiguousNoUniqueJoin => Some(
                "Ambiguous membership pattern: could not infer a unique membership join"
                    .to_string(),
            ),
            MembershipSelectAnalysis::Unique { .. } | MembershipSelectAnalysis::NoMatch => None,
        }
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
    let analysis = analyze_p5_parent_inheritance(select.as_ref(), db, outer_table)?;

    if analysis.candidates.len() > 1 {
        return Some(
            "Ambiguous parent inheritance pattern: multiple candidate parent sources matched"
                .to_string(),
        );
    }
    if analysis.saw_conflicting_join {
        return Some(
            "Ambiguous parent inheritance pattern: conflicting outer FK join columns in EXISTS predicate"
                .to_string(),
        );
    }
    None
}

#[derive(Debug, Clone)]
pub(super) struct P5InheritanceCandidate {
    pub(super) parent_table: String,
    pub(super) fk_column: String,
    pub(super) inner_predicates: Vec<Expr>,
}

#[derive(Debug, Clone, Default)]
pub(super) struct P5InheritanceAnalysis {
    pub(super) candidates: Vec<P5InheritanceCandidate>,
    pub(super) saw_conflicting_join: bool,
}

pub(super) fn analyze_p5_parent_inheritance(
    select: &Select,
    db: &ParserDB,
    outer_table: &str,
) -> Option<P5InheritanceAnalysis> {
    let sources = relation_sources(select);
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

    let mut analysis = P5InheritanceAnalysis::default();

    for source in sources {
        let Some(parent_table) = lookup_table(db, &source.table_name) else {
            continue;
        };
        let parent_cols: Vec<String> = parent_table
            .columns(db)
            .map(|c| c.column_name().to_string())
            .collect();

        let mut fk_column: Option<String> = None;
        let mut inner_predicates = Vec::new();
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
            analysis.saw_conflicting_join = true;
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

        analysis.candidates.push(P5InheritanceCandidate {
            parent_table: source.table_name,
            fk_column,
            inner_predicates,
        });
    }

    Some(analysis)
}

pub(super) fn selection_references_current_user(
    select: &Select,
    registry: &FunctionRegistry,
) -> bool {
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
/// Extract a table name from a `TableFactor`.
pub(super) fn extract_table_name_from_table_factor(tf: &TableFactor) -> Option<String> {
    if let TableFactor::Table { name, .. } = tf {
        Some(name.to_string())
    } else {
        None
    }
}

pub(super) fn extract_table_alias_from_table_factor(tf: &TableFactor) -> Option<String> {
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

fn membership_sources_include_ambiguous_unresolvable_shape(select: &Select, db: &ParserDB) -> bool {
    let mut relation_factor_count = 0usize;
    let mut has_non_plain_source = false;
    let mut has_unresolvable_source = false;

    for from in &select.from {
        relation_factor_count += 1;
        match &from.relation {
            TableFactor::Table { name, .. } => {
                if lookup_table(db, &name.to_string()).is_none() {
                    has_unresolvable_source = true;
                }
            }
            _ => has_non_plain_source = true,
        }
        for join in &from.joins {
            relation_factor_count += 1;
            match &join.relation {
                TableFactor::Table { name, .. } => {
                    if lookup_table(db, &name.to_string()).is_none() {
                        has_unresolvable_source = true;
                    }
                }
                _ => has_non_plain_source = true,
            }
        }
    }

    relation_factor_count > 1 && (has_non_plain_source || has_unresolvable_source)
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

        if let Some((fk_col, user_col, extra_predicate_sql)) = extract_membership_columns_with_db(
            select,
            &source.table_name,
            source.alias.as_deref(),
            &col_names,
            Some(db),
            registry,
            projected_fk_hint,
        ) {
            matches.push((source.table_name, fk_col, user_col, extra_predicate_sql));
        }
    }
    matches
}

pub(super) fn extract_projection_column(select: &Select) -> Option<String> {
    select.projection.first().and_then(|p| match p {
        SelectItem::UnnamedExpr(e) => extract_column_name(e),
        SelectItem::ExprWithAlias { expr, .. } => extract_column_name(expr),
        _ => None,
    })
}

/// Extract the ON expression from a `JoinOperator`, if present.
pub(super) fn join_on_expr(op: &sqlparser::ast::JoinOperator) -> Option<&Expr> {
    use sqlparser::ast::JoinConstraint;
    use sqlparser::ast::JoinOperator::{
        CrossJoin, FullOuter, Inner, Join, Left, LeftOuter, Right, RightOuter,
    };
    let (Join(c) | Inner(c) | Left(c) | LeftOuter(c) | Right(c) | RightOuter(c) | FullOuter(c)
    | CrossJoin(c)) = op
    else {
        return None;
    };
    if let JoinConstraint::On(expr) = c {
        Some(expr)
    } else {
        None
    }
}

enum MembershipEqAnalysis {
    NotRelevant,
    UserColumn(String),
    FkCandidate(String),
    OuterCorrelation,
}

fn analyze_membership_eq_predicate(
    predicate: &Expr,
    join_table: &str,
    join_alias: Option<&str>,
    join_cols: &[String],
    registry: &FunctionRegistry,
) -> MembershipEqAnalysis {
    let Expr::BinaryOp {
        left,
        op: BinaryOperator::Eq,
        right,
    } = predicate
    else {
        return MembershipEqAnalysis::NotRelevant;
    };

    let left_col = extract_qualified_column(left);
    let right_col = extract_qualified_column(right);

    if let Some((qual, col)) = left_col.clone() {
        if is_join_column_ref(qual.as_deref(), &col, join_table, join_alias, join_cols)
            && is_current_user_expr(right, registry)
        {
            return MembershipEqAnalysis::UserColumn(col);
        }
    }
    if let Some((qual, col)) = right_col.clone() {
        if is_join_column_ref(qual.as_deref(), &col, join_table, join_alias, join_cols)
            && is_current_user_expr(left, registry)
        {
            return MembershipEqAnalysis::UserColumn(col);
        }
    }

    let (Some((left_qual, left_name)), Some((right_qual, right_name))) = (left_col, right_col)
    else {
        return MembershipEqAnalysis::NotRelevant;
    };

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
        return MembershipEqAnalysis::FkCandidate(left_name);
    }
    if right_is_join && !left_is_join {
        return MembershipEqAnalysis::FkCandidate(right_name);
    }
    if !left_is_join && !right_is_join {
        return MembershipEqAnalysis::OuterCorrelation;
    }

    MembershipEqAnalysis::NotRelevant
}

#[cfg(test)]
pub(super) fn extract_membership_columns(
    select: &Select,
    join_table: &str,
    join_alias: Option<&str>,
    join_cols: &[String],
    registry: &FunctionRegistry,
    projected_fk_hint: Option<&str>,
) -> Option<(String, String, Option<String>)> {
    extract_membership_columns_with_db(
        select,
        join_table,
        join_alias,
        join_cols,
        None,
        registry,
        projected_fk_hint,
    )
}

fn extract_membership_columns_with_db(
    select: &Select,
    join_table: &str,
    join_alias: Option<&str>,
    join_cols: &[String],
    db: Option<&ParserDB>,
    registry: &FunctionRegistry,
    projected_fk_hint: Option<&str>,
) -> Option<(String, String, Option<String>)> {
    let mut fk_col: Option<String> = None;
    let mut fk_col_is_explicit = false; // true only when found via an explicit `join_col = outer_col` predicate
    let mut user_col: Option<String> = None;
    let mut extras: Vec<String> = Vec::new();
    let unqualified_scope = db
        .map(|db| build_unqualified_membership_scope(select, db, join_table, join_cols))
        .unwrap_or_default();

    // Collect JOIN ON predicates separately (they provide explicit FK correlation but should
    // not be included in the extra_predicate_sql used in generated tuple queries).
    let mut on_predicates: Vec<&Expr> = Vec::new();
    for from_item in &select.from {
        for join in &from_item.joins {
            if let Some(on_expr) = join_on_expr(&join.join_operator) {
                flatten_and_predicates(on_expr, &mut on_predicates);
            }
        }
    }

    // Process WHERE predicates (with extras).
    if let Some(selection) = &select.selection {
        let mut predicates = Vec::new();
        flatten_and_predicates(selection, &mut predicates);

        for pred in predicates {
            match analyze_membership_eq_predicate(pred, join_table, join_alias, join_cols, registry)
            {
                MembershipEqAnalysis::UserColumn(col) => {
                    user_col = Some(col);
                    continue;
                }
                MembershipEqAnalysis::FkCandidate(candidate) => {
                    if fk_col
                        .as_ref()
                        .is_none_or(|existing| existing == &candidate)
                    {
                        fk_col = Some(candidate);
                        fk_col_is_explicit = true;
                        continue;
                    }
                    return None;
                }
                MembershipEqAnalysis::OuterCorrelation => {
                    // Outer correlation predicates are implicit in tuple queries and
                    // must not be copied to extra_predicate_sql.
                    continue;
                }
                MembershipEqAnalysis::NotRelevant => {}
            }

            // Scope validation: reject predicates that reference columns from
            // tables other than the join table.  Such predicates require a JOIN
            // that the generated single-table tuple query cannot provide, so
            // they would produce semantically invalid SQL.
            if predicate_references_other_table(pred, join_table, join_alias) {
                return None;
            }
            if predicate_has_ambiguous_unqualified_column(pred, &unqualified_scope) {
                return None;
            }
            // Keep additional predicates for tuple filtering.
            // Strip join-table qualifiers at the AST level before rendering to SQL.
            // This handles double-quoted identifiers, dollar-quoted strings, and other
            // SQL literal forms that text-based rewriting would mangle.
            let mut normalized_pred = pred.clone();
            strip_qualifier_from_expr(&mut normalized_pred, join_table, join_alias);
            extras.push(normalized_pred.to_string());
        }
    }

    // Also scan JOIN ON conditions for explicit FK correlation.
    // These are NOT added to extras because the generated tuple query does not include a JOIN.
    for pred in &on_predicates {
        if fk_col_is_explicit {
            break; // FK already found; no need to scan further.
        }
        match analyze_membership_eq_predicate(pred, join_table, join_alias, join_cols, registry) {
            MembershipEqAnalysis::UserColumn(col) => {
                if user_col.is_none() {
                    user_col = Some(col);
                }
            }
            MembershipEqAnalysis::FkCandidate(candidate) => {
                if fk_col
                    .as_ref()
                    .is_none_or(|existing| existing == &candidate)
                {
                    fk_col = Some(candidate);
                    fk_col_is_explicit = true;
                }
            }
            MembershipEqAnalysis::OuterCorrelation | MembershipEqAnalysis::NotRelevant => {}
        }
    }

    // Only fall back to column-name inference when the IN-subquery form provides
    // an implicit correlation via the projected FK hint.  An EXISTS without an
    // explicit `join_table_col = outer_table_col` predicate cannot be safely
    // classified as P4: the policy would grant access to any resource the user
    // is a member of, rather than the specific resource being queried.
    if fk_col.is_none() && !fk_col_is_explicit && projected_fk_hint.is_some() {
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

/// Strip join-table qualifiers from all `CompoundIdentifier` nodes in `expr`
/// whose qualifier matches `join_table` or `join_alias`.  Qualifying identifiers
/// are replaced with bare `Identifier` nodes, making the predicate suitable for
/// embedding in a single-table query that does not include the join table.
///
/// Operates at the AST level to correctly handle double-quoted identifiers,
/// dollar-quoted strings, and other SQL literal forms that text-based rewriting
/// would mangle.
pub(super) fn strip_qualifier_from_expr(
    expr: &mut Expr,
    join_table: &str,
    join_alias: Option<&str>,
) {
    use core::ops::ControlFlow;
    use sqlparser::ast::{Query, VisitMut, VisitorMut};

    struct QualifierStripper<'a> {
        join_table: &'a str,
        join_alias: Option<&'a str>,
        subquery_depth: usize,
    }

    impl VisitorMut for QualifierStripper<'_> {
        type Break = ();

        fn pre_visit_query(&mut self, _: &mut Query) -> ControlFlow<()> {
            self.subquery_depth += 1;
            ControlFlow::Continue(())
        }
        fn post_visit_query(&mut self, _: &mut Query) -> ControlFlow<()> {
            self.subquery_depth -= 1;
            ControlFlow::Continue(())
        }
        fn pre_visit_expr(&mut self, expr: &mut Expr) -> ControlFlow<()> {
            if self.subquery_depth == 0 {
                if let Expr::CompoundIdentifier(parts) = &*expr {
                    if let [.., qualifier, last] = parts.as_slice() {
                        if qualifier_matches_table(
                            &qualifier.value,
                            self.join_table,
                            self.join_alias,
                        ) {
                            *expr = Expr::Identifier(last.clone());
                        }
                    }
                }
            }
            ControlFlow::Continue(())
        }
    }

    let mut v = QualifierStripper {
        join_table,
        join_alias,
        subquery_depth: 0,
    };
    let _ = expr.visit(&mut v);
}

/// Returns `true` if `expr` contains any column reference whose qualifier is
/// NOT the join table (or its alias).  Bare (unqualified) column references are
/// assumed to belong to the join table and are allowed.
pub(super) fn predicate_references_other_table(
    expr: &Expr,
    join_table: &str,
    join_alias: Option<&str>,
) -> bool {
    use core::ops::ControlFlow;
    use sqlparser::ast::{Query, Visit, Visitor};

    struct OtherTableChecker<'a> {
        join_table: &'a str,
        join_alias: Option<&'a str>,
        subquery_depth: usize,
    }

    impl Visitor for OtherTableChecker<'_> {
        type Break = ();

        fn pre_visit_query(&mut self, _: &Query) -> ControlFlow<()> {
            self.subquery_depth += 1;
            ControlFlow::Continue(())
        }
        fn post_visit_query(&mut self, _: &Query) -> ControlFlow<()> {
            self.subquery_depth -= 1;
            ControlFlow::Continue(())
        }
        fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<()> {
            if self.subquery_depth == 0 {
                if let Expr::CompoundIdentifier(parts) = expr {
                    if let [.., qualifier, _] = parts.as_slice() {
                        if !qualifier_matches_table(
                            &qualifier.value,
                            self.join_table,
                            self.join_alias,
                        ) {
                            return ControlFlow::Break(());
                        }
                    }
                }
            }
            ControlFlow::Continue(())
        }
    }

    let mut checker = OtherTableChecker {
        join_table,
        join_alias,
        subquery_depth: 0,
    };
    expr.visit(&mut checker).is_break()
}

#[derive(Debug, Default)]
struct UnqualifiedMembershipScope {
    enforce: bool,
    unknown_other_source: bool,
    join_columns: BTreeSet<String>,
    other_columns: BTreeSet<String>,
}

fn build_unqualified_membership_scope(
    select: &Select,
    db: &ParserDB,
    join_table: &str,
    join_cols: &[String],
) -> UnqualifiedMembershipScope {
    let sources = relation_sources(select);
    if sources.len() <= 1 {
        return UnqualifiedMembershipScope::default();
    }

    let join_table_norm = normalize_relation_name(join_table);
    let join_columns = join_cols
        .iter()
        .map(|name| normalize_relation_name(name))
        .collect();

    let mut scope = UnqualifiedMembershipScope {
        enforce: true,
        unknown_other_source: false,
        join_columns,
        other_columns: BTreeSet::new(),
    };

    for source in sources {
        if normalize_relation_name(&source.table_name) == join_table_norm {
            continue;
        }

        let Some(table) = lookup_table(db, &source.table_name) else {
            scope.unknown_other_source = true;
            continue;
        };

        for col in table.columns(db) {
            scope
                .other_columns
                .insert(normalize_relation_name(col.column_name()));
        }
    }

    scope
}

fn predicate_has_ambiguous_unqualified_column(
    expr: &Expr,
    scope: &UnqualifiedMembershipScope,
) -> bool {
    use core::ops::ControlFlow;
    use sqlparser::ast::{Query, Visit, Visitor};

    struct UnqualifiedChecker<'a> {
        scope: &'a UnqualifiedMembershipScope,
        subquery_depth: usize,
    }

    impl Visitor for UnqualifiedChecker<'_> {
        type Break = ();

        fn pre_visit_query(&mut self, _: &Query) -> ControlFlow<()> {
            self.subquery_depth += 1;
            ControlFlow::Continue(())
        }
        fn post_visit_query(&mut self, _: &Query) -> ControlFlow<()> {
            self.subquery_depth -= 1;
            ControlFlow::Continue(())
        }
        fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<()> {
            if self.subquery_depth == 0 {
                if let Expr::Identifier(ident) = expr {
                    let col = normalize_relation_name(&ident.value);
                    let in_join = self.scope.join_columns.contains(&col);
                    let in_other = self.scope.other_columns.contains(&col);
                    if !in_join || in_other || self.scope.unknown_other_source {
                        return ControlFlow::Break(());
                    }
                }
            }
            ControlFlow::Continue(())
        }
    }

    if !scope.enforce {
        return false;
    }

    let mut checker = UnqualifiedChecker {
        scope,
        subquery_depth: 0,
    };
    expr.visit(&mut checker).is_break()
}

pub(super) fn qualifier_matches_table(
    qualifier: &str,
    table_name: &str,
    alias: Option<&str>,
) -> bool {
    if alias.is_some_and(|a| qualifier.eq_ignore_ascii_case(a)) {
        return true;
    }

    table_qualifier_candidates(table_name)
        .iter()
        .any(|candidate| qualifier.eq_ignore_ascii_case(candidate))
}

pub(super) fn table_qualifier_candidates(table_name: &str) -> Vec<String> {
    let mut candidates = vec![table_name.to_string()];
    if let Some((_, relation)) = split_schema_and_relation(table_name) {
        candidates.push(relation);
    }
    candidates
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

pub(super) fn extract_parent_join_columns(
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
pub(super) fn infer_membership_fk_column(
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

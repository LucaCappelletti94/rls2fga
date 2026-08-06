use super::*;
use alloc::collections::BTreeSet;

/// EXISTS membership check.
pub fn recognize_p4<DB: DatabaseLike>(
    expr: &Expr,
    db: &DB,
    registry: &FunctionRegistry,
    outer_table: &str,
) -> Option<ClassifiedExpr> {
    if let Expr::Exists { subquery, negated } = expr {
        if *negated {
            return None;
        }

        let query = subquery.as_ref();
        let body = query.body.as_ref();

        if let sqlparser::ast::SetExpr::Select(select) = body {
            return classify_membership_select(select.as_ref(), db, registry, outer_table, None);
        }
    }
    None
}

/// Parent inheritance via correlated EXISTS.
pub fn recognize_p5<DB: DatabaseLike>(
    expr: &Expr,
    db: &DB,
    registry: &FunctionRegistry,
    outer_table: &str,
    command: PolicyCommand,
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
                parent_alias,
                fk_column,
                inner_predicates,
            } = candidate;
            let Some(mut inner_expr) = combine_predicates_with_and(inner_predicates) else {
                continue;
            };
            // Nested queries use parent alias from outer scope.
            strip_qualifier_from_expr_deep(&mut inner_expr, &parent_table, parent_alias.as_deref());
            let inner_classified = crate::classifier::policy_classifier::classify_expr(
                &inner_expr,
                db,
                registry,
                &parent_table,
                command,
            );
            // Only accept relationship patterns, not attribute checks.
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

/// The `(tested value, subquery)` of `x IN (SELECT ...)` or `x = ANY (SELECT ...)`.
///
/// A query that limits or offsets its rows is refused: membership then tests one
/// arbitrary row rather than the whole result, so reading it as full membership grants
/// rows the policy refuses. Ordering alone is irrelevant to a set membership test.
fn membership_subquery_operands(expr: &Expr) -> Option<(&Expr, &sqlparser::ast::Query)> {
    let (lhs, query) = match expr {
        Expr::InSubquery {
            expr: lhs,
            subquery,
            negated: false,
        } => (lhs.as_ref(), subquery.as_ref()),
        Expr::AnyOp {
            left,
            compare_op: BinaryOperator::Eq,
            right,
            ..
        } => match right.as_ref() {
            Expr::Subquery(subquery) => (left.as_ref(), subquery.as_ref()),
            _ => return None,
        },
        _ => return None,
    };

    if query.limit_clause.is_some() || query.fetch.is_some() {
        return None;
    }
    Some((lhs, query))
}

/// Membership written with the caller on the left: `caller IN (SELECT user_col FROM m
/// WHERE m.fk = outer.id)`, and the `= ANY` spelling of the same.
///
/// Verified on `PostgreSQL` 18 to admit exactly the rows the `EXISTS` spelling admits,
/// differing only where the projected column is NULL, which yields NULL against false and
/// filters either way. So it is rewritten into that `EXISTS` and handed to the one
/// membership analyzer, which keeps every refusal it already makes, the uncorrelated case
/// included.
pub fn recognize_p4_caller_in_subquery<DB: DatabaseLike>(
    expr: &Expr,
    db: &DB,
    registry: &FunctionRegistry,
    outer_table: &str,
) -> Option<ClassifiedExpr> {
    let (caller, query) = membership_subquery_operands(expr)?;
    // The equivalence holds for any left-hand value, but only the caller spelling was
    // verified against PostgreSQL, so the rewrite stays confined to it. Defensive: with a
    // column on the left the analyzer finds no user column and refuses anyway, so no
    // generated model distinguishes this check.
    if !is_current_user_expr(caller, registry) {
        return None;
    }
    recognize_p4(
        &membership_exists_binding_caller(query, caller)?,
        db,
        registry,
        outer_table,
    )
}

/// `SELECT user_col FROM m WHERE p` rewritten as `EXISTS (SELECT user_col FROM m WHERE p
/// AND user_col = caller)`. The projection is left alone because the `EXISTS` path never
/// reads it.
fn membership_exists_binding_caller(query: &sqlparser::ast::Query, caller: &Expr) -> Option<Expr> {
    let sqlparser::ast::SetExpr::Select(select) = query.body.as_ref() else {
        return None;
    };
    let projected = single_projected_column(select.as_ref())?;

    let mut rewritten = query.clone();
    let sqlparser::ast::SetExpr::Select(select) = rewritten.body.as_mut() else {
        return None;
    };
    let bound = Expr::BinaryOp {
        left: Box::new(projected),
        op: BinaryOperator::Eq,
        right: Box::new(caller.clone()),
    };
    select.selection = Some(match select.selection.take() {
        Some(existing) => Expr::BinaryOp {
            left: Box::new(existing),
            op: BinaryOperator::And,
            right: Box::new(bound),
        },
        None => bound,
    });
    Some(Expr::Exists {
        subquery: Box::new(rewritten),
        negated: false,
    })
}

/// The one column a select projects, qualifier kept. `*`, several items, or anything that
/// is not a column reference yields `None`.
fn single_projected_column(select: &Select) -> Option<Expr> {
    let [item] = select.projection.as_slice() else {
        return None;
    };
    let (SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. }) = item else {
        return None;
    };
    extract_column_name(expr).is_some().then(|| expr.clone())
}

/// Recognize P4 membership through `col IN (SELECT ...)` or `col = ANY (SELECT ...)`.
pub fn recognize_p4_in_subquery<DB: DatabaseLike>(
    expr: &Expr,
    db: &DB,
    registry: &FunctionRegistry,
    outer_table: &str,
) -> Option<ClassifiedExpr> {
    let (lhs, query) = membership_subquery_operands(expr)?;

    // LHS should be a column reference (e.g. team_id)
    let lhs_col = extract_column_name(lhs)?;

    if let sqlparser::ast::SetExpr::Select(select) = query.body.as_ref() {
        let projected_col = extract_projection_column(select.as_ref()).unwrap_or(lhs_col);
        return classify_membership_select(
            select.as_ref(),
            db,
            registry,
            outer_table,
            Some(projected_col),
        );
    }
    None
}

fn classify_membership_select<DB: DatabaseLike>(
    select: &Select,
    db: &DB,
    registry: &FunctionRegistry,
    outer_table: &str,
    projected_fk: Option<String>,
) -> Option<ClassifiedExpr> {
    match analyze_membership_select(select, db, registry, outer_table, projected_fk.as_deref()) {
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
        MembershipSelectAnalysis::Uncorrelated {
            member_table,
            user_column,
            extra_predicate_sql,
        } => Some(ClassifiedExpr {
            pattern: PatternClass::P13UncorrelatedMembership {
                member_table,
                user_column,
                extra_predicate_sql,
            },
            confidence: ConfidenceLevel::A,
        }),
        MembershipSelectAnalysis::AmbiguousMultiple
        | MembershipSelectAnalysis::AmbiguousNoUniqueJoin
        | MembershipSelectAnalysis::JoinsAnotherTable { .. }
        | MembershipSelectAnalysis::ScansEntityByOwnKey { .. }
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
    /// The subquery reads more than one table, so it carries conditions a single
    /// membership relation cannot express.
    JoinsAnotherTable {
        tables: Vec<String>,
    },
    /// The join column is the scanned table's own identity, so the subquery selects
    /// entities rather than membership rows.
    ScansEntityByOwnKey {
        join_table: String,
    },
    /// The subquery names no outer column at all, so it asks only whether the caller
    /// is a member of anything. Every row of the guarded table then passes together.
    Uncorrelated {
        member_table: String,
        user_column: String,
        extra_predicate_sql: Option<String>,
    },
    NoMatch,
}

fn analyze_membership_select<DB: DatabaseLike>(
    select: &Select,
    db: &DB,
    registry: &FunctionRegistry,
    outer_table: &str,
    projected_fk_hint: Option<&str>,
) -> MembershipSelectAnalysis {
    if membership_sources_include_ambiguous_unresolvable_shape(select, db)
        && selection_references_current_user(select, registry)
    {
        return MembershipSelectAnalysis::AmbiguousNoUniqueJoin;
    }

    // Fail closed on self-joins: not expressible as static tuples.
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
            // A membership row points at a parent. When the join column is the
            // scanned table's own identity, the rows are the entities themselves and
            // keying them by the child's identifier pairs unrelated rows.
            if scans_root_entity_by_its_key(db, &join_table, &inferred_fk_column) {
                return MembershipSelectAnalysis::ScansEntityByOwnKey { join_table };
            }
            // A third table in the subquery carries conditions that no single
            // membership relation can express, and keeping only the matching side
            // would drop them. A join back to the policy's own table stays translatable.
            let foreign: Vec<String> = all_sources
                .iter()
                .map(|source| source.table_name.clone())
                .filter(|name| {
                    let normalized = normalize_relation_name(name);
                    normalized != normalize_relation_name(&join_table)
                        && normalized != normalize_relation_name(outer_table)
                })
                .collect();
            if !foreign.is_empty() {
                return MembershipSelectAnalysis::JoinsAnotherTable { tables: foreign };
            }
            MembershipSelectAnalysis::Unique {
                join_table,
                inferred_fk_column,
                user_column,
                extra_predicate_sql,
            }
        }
        None if selection_references_current_user(select, registry) => {
            analyze_uncorrelated_membership(select, db, registry, outer_table)
                .unwrap_or(MembershipSelectAnalysis::AmbiguousNoUniqueJoin)
        }
        None => MembershipSelectAnalysis::NoMatch,
    }
}

/// The subquery asks only whether the caller is a member of something, naming no column
/// of the guarded table.
///
/// Every refusal here matters, because the translation grants the whole table at once:
/// exactly one source with no joins, exactly one comparison against the caller, and
/// nothing reaching outside that one table. Anything else stays refused.
fn analyze_uncorrelated_membership<DB: DatabaseLike>(
    select: &Select,
    db: &DB,
    registry: &FunctionRegistry,
    outer_table: &str,
) -> Option<MembershipSelectAnalysis> {
    let sources = relation_sources(select);
    let [source] = sources.as_slice() else {
        return None;
    };
    if select.from.iter().any(|item| !item.joins.is_empty()) {
        return None;
    }
    // Reading the guarded table itself is a self-reference, not a member source.
    if same_identifier(&source.table_name, outer_table) {
        return None;
    }
    let member = lookup_table(db, &source.table_name)?;
    let columns: Vec<String> = member
        .columns(db)
        .into_iter()
        .flatten()
        .map(|c| c.stored_column_name().into_owned())
        .collect();

    let selection = select.selection.as_ref()?;
    let mut predicates = Vec::new();
    flatten_and_predicates(selection, &mut predicates);

    let mut user_column: Option<String> = None;
    let mut extras: Vec<String> = Vec::new();
    for predicate in predicates {
        match analyze_membership_eq_predicate(
            predicate,
            &source.table_name,
            source.alias.as_deref(),
            &columns,
            registry,
        ) {
            MembershipEqAnalysis::UserColumn(column) if user_column.is_none() => {
                user_column = Some(column);
                continue;
            }
            // A second caller comparison, a link to the outer row, or a join column
            // all mean this is not the shape.
            MembershipEqAnalysis::UserColumn(_)
            | MembershipEqAnalysis::FkCandidate(_)
            | MembershipEqAnalysis::OuterCorrelation => return None,
            MembershipEqAnalysis::NotRelevant => {}
        }
        if predicate_references_other_table(predicate, &source.table_name, source.alias.as_deref())
        {
            return None;
        }
        let mut normalized = predicate.clone();
        strip_qualifier_from_expr(&mut normalized, &source.table_name, source.alias.as_deref());
        extras.push(normalized.to_string());
    }

    Some(MembershipSelectAnalysis::Uncorrelated {
        member_table: source.table_name.clone(),
        user_column: user_column?,
        extra_predicate_sql: (!extras.is_empty()).then(|| extras.join(" AND ")),
    })
}

/// True when `column` is `table`'s own identity rather than a link to a parent:
/// the single-column primary key, and not itself a foreign key.
///
/// A dependent row keyed by its parent (`doc_owner(doc_id PRIMARY KEY REFERENCES
/// docs)`) is a membership row and stays translatable. A root entity scanned by its
fn scans_root_entity_by_its_key<DB: DatabaseLike>(db: &DB, table: &str, column: &str) -> bool {
    let Some(meta) = lookup_table(db, table) else {
        return false;
    };
    // Returning true refuses the policy, so an unreadable key cannot rule the scan out.
    let Ok(primary_key) = meta.primary_key_column(db) else {
        return true;
    };
    let is_primary_key = primary_key.is_some_and(|pk| same_identifier(pk.column_name(), column));
    if !is_primary_key {
        return false;
    }
    !meta.foreign_keys(db).into_iter().flatten().any(|fk| {
        fk.host_column(db)
            .ok()
            .flatten()
            .is_some_and(|host| same_identifier(host.column_name(), column))
    })
}

pub(crate) fn diagnose_p4_membership_ambiguity<DB: DatabaseLike>(
    expr: &Expr,
    db: &DB,
    registry: &FunctionRegistry,
    outer_table: &str,
) -> Option<String> {
    fn diagnose_select<DB: DatabaseLike>(
        select: &Select,
        db: &DB,
        registry: &FunctionRegistry,
        outer_table: &str,
        projected_fk: Option<&str>,
    ) -> Option<String> {
        match analyze_membership_select(select, db, registry, outer_table, projected_fk) {
            MembershipSelectAnalysis::AmbiguousMultiple => Some(
                "Ambiguous membership pattern: multiple candidate membership sources matched"
                    .to_string(),
            ),
            MembershipSelectAnalysis::AmbiguousNoUniqueJoin => Some(
                "Ambiguous membership pattern: could not infer a unique membership join"
                    .to_string(),
            ),
            MembershipSelectAnalysis::JoinsAnotherTable { tables } => Some(format!(
                "Membership subquery reads {} together, and a condition on the joined \
                 table cannot be carried by a single OpenFGA relation; split the check or \
                 pre-compute a membership table",
                tables.join(" and ")
            )),
            MembershipSelectAnalysis::ScansEntityByOwnKey { join_table } => Some(format!(
                "Subquery selects '{join_table}' rows by their own primary key, so they are \
                 '{join_table}' entities rather than membership rows; declare the foreign key \
                 from the policy's table to '{join_table}' so the link translates as parent \
                 inheritance"
            )),
            MembershipSelectAnalysis::Unique { .. }
            | MembershipSelectAnalysis::Uncorrelated { .. }
            | MembershipSelectAnalysis::NoMatch => None,
        }
    }

    match expr {
        Expr::Exists { subquery, negated } if !negated => {
            let query = subquery.as_ref();
            let body = query.body.as_ref();
            if let sqlparser::ast::SetExpr::Select(select) = body {
                return diagnose_select(select.as_ref(), db, registry, outer_table, None);
            }
            None
        }
        _ => {
            let (lhs, query) = membership_subquery_operands(expr)?;
            let lhs_col = extract_column_name(lhs)?;
            if let sqlparser::ast::SetExpr::Select(select) = query.body.as_ref() {
                let projected_fk = extract_projection_column(select.as_ref())
                    .unwrap_or(lhs_col)
                    .clone();
                return diagnose_select(
                    select.as_ref(),
                    db,
                    registry,
                    outer_table,
                    Some(&projected_fk),
                );
            }
            None
        }
    }
}

pub(crate) fn diagnose_p5_parent_inheritance_ambiguity<DB: DatabaseLike>(
    expr: &Expr,
    db: &DB,
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
    /// Alias the subquery gave the parent table, if any. Predicates nested inside
    /// this subquery refer to the parent through it.
    pub(super) parent_alias: Option<String>,
    pub(super) fk_column: String,
    pub(super) inner_predicates: Vec<Expr>,
}

#[derive(Debug, Clone, Default)]
pub(super) struct P5InheritanceAnalysis {
    pub(super) candidates: Vec<P5InheritanceCandidate>,
    pub(super) saw_conflicting_join: bool,
}

pub(super) fn analyze_p5_parent_inheritance<DB: DatabaseLike>(
    select: &Select,
    db: &DB,
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
        .into_iter()
        .flatten()
        .map(|c| c.stored_column_name().into_owned())
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
            .into_iter()
            .flatten()
            .map(|c| c.stored_column_name().into_owned())
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
            parent_alias: source.alias,
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

fn membership_sources_include_ambiguous_unresolvable_shape<DB: DatabaseLike>(
    select: &Select,
    db: &DB,
) -> bool {
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

fn membership_matches<DB: DatabaseLike>(
    select: &Select,
    db: &DB,
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
            .into_iter()
            .flatten()
            .map(|c| c.stored_column_name().into_owned())
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
    extract_membership_columns_with_db::<crate::parser::sql_parser::ParserDB>(
        select,
        join_table,
        join_alias,
        join_cols,
        None,
        registry,
        projected_fk_hint,
    )
}

fn extract_membership_columns_with_db<DB: DatabaseLike>(
    select: &Select,
    join_table: &str,
    join_alias: Option<&str>,
    join_cols: &[String],
    db: Option<&DB>,
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

/// Drop `join_table` or `join_alias` qualifiers, leaving bare identifiers that a
/// single-table query can host. Rewrites the AST, not the text, so quoted and
/// dollar-quoted forms survive.
pub(super) fn strip_qualifier_from_expr(
    expr: &mut Expr,
    join_table: &str,
    join_alias: Option<&str>,
) {
    strip_qualifier(expr, join_table, join_alias, false);
}

/// As [`strip_qualifier_from_expr`], but also rewriting references inside nested
/// subqueries.
///
/// Used when the qualifier names a table from an enclosing scope, so a nested
/// reference to it means the same table. A nested query that rebinds the same
/// alias to a different table would be rewritten too, which no realistic policy
/// does.
pub(super) fn strip_qualifier_from_expr_deep(
    expr: &mut Expr,
    join_table: &str,
    join_alias: Option<&str>,
) {
    strip_qualifier(expr, join_table, join_alias, true);
}

fn strip_qualifier(
    expr: &mut Expr,
    join_table: &str,
    join_alias: Option<&str>,
    descend_into_subqueries: bool,
) {
    use core::ops::ControlFlow;
    use sqlparser::ast::{Query, VisitMut, VisitorMut};

    struct QualifierStripper<'a> {
        join_table: &'a str,
        join_alias: Option<&'a str>,
        subquery_depth: usize,
        descend_into_subqueries: bool,
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
            if self.subquery_depth == 0 || self.descend_into_subqueries {
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
        descend_into_subqueries,
    };
    let _ = expr.visit(&mut v);
}

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

fn build_unqualified_membership_scope<DB: DatabaseLike>(
    select: &Select,
    db: &DB,
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

        // An unreadable column list is as blind as an unresolvable table, and this scope
        // only ever adds a refusal, so both take the same flag.
        let Ok(columns) = table.columns(db) else {
            scope.unknown_other_source = true;
            continue;
        };
        for col in columns {
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
    if alias.is_some_and(|a| same_identifier(qualifier, a)) {
        return true;
    }

    table_qualifier_candidates(table_name)
        .iter()
        .any(|candidate| same_identifier(qualifier, candidate))
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

fn table_has_fk_to_parent<DB: DatabaseLike>(
    outer_table: &DB::Table,
    db: &DB,
    fk_column: &str,
    parent_table_name: &str,
) -> bool {
    outer_table
        .foreign_keys(db)
        .into_iter()
        .flatten()
        .any(|fk| {
            let host_col_matches = fk
                .host_column(db)
                .ok()
                .flatten()
                .is_some_and(|col| col.stored_column_name() == fk_column);
            if !host_col_matches {
                return false;
            }

            fk.referenced_table(db).is_ok_and(|referenced| {
                qualifier_matches_table(referenced.table_name(), parent_table_name, None)
            })
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

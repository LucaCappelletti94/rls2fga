//! Whether a residual conjunct answers every caller alike.
//!
//! The loader answers the tuple query once, as itself, so a conjunct the membership row
//! does not decide is safe to precompute exactly when it asks a question whose answer does
//! not depend on who asks. Every relation it reads showing every row to everybody, and
//! nothing in it reading the caller, the session or the clock, is that condition. Anything
//! else keeps refusing.

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use alloc::collections::BTreeSet;
use core::ops::ControlFlow;
use sqlparser::ast::{
    Expr, Ident, ObjectName, ObjectNamePart, Query, SetExpr, TableFactor, Value, Visit, VisitMut,
    Visitor, VisitorMut,
};

use super::attribute::ROW_PURE_FUNCTIONS;
use super::subquery::{session_zoned_columns, set_limiting_clause};
use super::unwrap_cast_or_nested;
use crate::classifier::function_registry::FunctionRegistry;
use crate::generator::unrestricted::restricts_nothing_by_any_route;
use crate::parser::names::{
    builtin_function_name, is_current_user_keyword_name, lookup_table, stored_ident_name,
    stored_relation_name, table_identity,
};
use crate::parser::sql_parser::{ColumnLike, DatabaseLike, TableLike};
use crate::types::TableId;

/// Aggregates whose value the rows decide without their order.
///
/// `array_agg` and `string_agg` are deliberately absent: they answer per row order, which
/// no unordered scan fixes, so the loader's answer and the caller's need not agree.
const ORDER_FREE_AGGREGATES: &[&str] = &[
    "avg", "bool_and", "bool_or", "count", "every", "max", "min", "sum",
];

/// The scopes a membership subquery resolves its names through.
///
/// The generated query keeps every one of them but the guarded table, which is why the
/// guarded table is named here rather than assumed away.
pub(crate) struct MembershipScope<'a> {
    /// The membership table, as the policy spells it.
    pub(crate) table: &'a str,
    /// The policy's alias for it, absent where it gave none.
    pub(crate) alias: Option<&'a str>,
    /// Its columns, as the schema stores them.
    pub(crate) columns: &'a [String],
    /// The guarded table the policy is attached to.
    pub(crate) guarded_table: &'a str,
}

/// The relations `conjunct` reads, proven to answer every caller alike, or [`None`] where
/// no such proof holds.
///
/// An empty list means it reads no relation, which is the residual the row or the request
/// decides and which the caller grades as before. A non-empty list is the exemption: the
/// conjunct is rewritten to name each relation as the catalog carries it, so the generated
/// query reads the proven relation rather than whatever the loader's `search_path` reaches.
pub(crate) fn residual_relations<DB: DatabaseLike>(
    conjunct: &mut Expr,
    db: Option<&DB>,
    registry: &FunctionRegistry,
    scope: &MembershipScope<'_>,
) -> Option<Vec<TableId>> {
    let mut names = RelationNames::default();
    if Visit::visit(&*conjunct, &mut names).is_break() {
        return None;
    }
    if names.0.is_empty() {
        return Some(Vec::new());
    }
    let db = db?;
    let mut relations = BTreeSet::new();
    // A comparison spanning one of these reads the session's own time zone, which the
    // relations say nothing about, so naming one refuses.
    let mut zoned: BTreeSet<String> = lookup_table(db, scope.table)
        .map(|table| session_zoned_columns(table, db))
        .unwrap_or_default()
        .into_iter()
        .collect();
    for name in &names.0 {
        let table = lookup_table(db, name)?;
        if !restricts_nothing_by_any_route(table, db) {
            return None;
        }
        relations.insert(table_identity(table));
        zoned.extend(session_zoned_columns(table, db));
    }
    if answer_depends_on_the_asker(conjunct, registry, &zoned) {
        return None;
    }
    if reaches_the_guarded_row(conjunct, db, scope) {
        return None;
    }
    if VisitMut::visit(conjunct, &mut QualifyRelations { db }).is_break() {
        return None;
    }
    Some(relations.into_iter().collect())
}

/// Every relation named in a `FROM`, refusing anything but a plain table reference.
///
/// A derived table, a table function or a `LATERAL` item reads rows this cannot place, and
/// an unplaced read is not a proven one.
#[derive(Default)]
struct RelationNames(BTreeSet<String>);

impl Visitor for RelationNames {
    type Break = ();

    fn pre_visit_table_factor(&mut self, factor: &TableFactor) -> ControlFlow<()> {
        let TableFactor::Table {
            name,
            args: None,
            version: None,
            sample: None,
            json_path: None,
            with_hints,
            partitions,
            index_hints,
            with_ordinality: false,
            ..
        } = factor
        else {
            return ControlFlow::Break(());
        };
        if !with_hints.is_empty() || !partitions.is_empty() || !index_hints.is_empty() {
            return ControlFlow::Break(());
        }
        self.0.insert(name.to_string());
        ControlFlow::Continue(())
    }
}

/// Whether anything in `conjunct` can answer one caller differently from another.
///
/// An allow-list throughout. A function passes only when it is named among the row-pure
/// scalars or the order-free aggregates, carries no window, and the deployment declared it
/// no accessor semantics, since a name this cannot place may read the caller from a body
/// the schema never showed. Every other kind of expression passes only by appearing below.
///
/// A cast passes, because `pg_dump` writes one around every comparison and the two
/// spellings of one policy have to classify alike. What a cast could read that the
/// relations do not fix is the session's time zone, so a column carrying one refuses
/// instead, whether or not a cast stands beside it.
fn answer_depends_on_the_asker(
    conjunct: &Expr,
    registry: &FunctionRegistry,
    zoned: &BTreeSet<String>,
) -> bool {
    struct AskerDependence<'a> {
        registry: &'a FunctionRegistry,
        /// Columns whose value the evaluating session's time zone decides.
        zoned: &'a BTreeSet<String>,
    }

    impl Visitor for AskerDependence<'_> {
        type Break = ();

        fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<()> {
            // A limit answers per evaluation rather than per identity, so the loader's row
            // and the caller's need not be the same row.
            if set_limiting_clause(query).is_some() {
                return ControlFlow::Break(());
            }
            ControlFlow::Continue(())
        }

        fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<()> {
            // A cast or a parenthesis is peeled by the one peeler, since neither says
            // anything about who is asking and `pg_dump` writes both around everything.
            match unwrap_cast_or_nested(expr) {
                Expr::Identifier(ident) => {
                    if ident.quote_style.is_none() && is_current_user_keyword_name(&ident.value) {
                        return ControlFlow::Break(());
                    }
                    if self.zoned.contains(stored_ident_name(ident).as_ref()) {
                        return ControlFlow::Break(());
                    }
                }
                Expr::Value(value) => {
                    if matches!(value.value, Value::Placeholder(_)) {
                        return ControlFlow::Break(());
                    }
                }
                Expr::Function(func) => {
                    let named = builtin_function_name(func).filter(|name| {
                        ROW_PURE_FUNCTIONS.contains(&name.as_str())
                            || ORDER_FREE_AGGREGATES.contains(&name.as_str())
                    });
                    let Some(name) = named else {
                        return ControlFlow::Break(());
                    };
                    if func.over.is_some() || self.registry.get(&name).is_some() {
                        return ControlFlow::Break(());
                    }
                }
                // A qualifier changes nothing about which column this is, so the zone
                // check reads the terminal part exactly as it reads a bare name.
                Expr::CompoundIdentifier(parts) => {
                    if parts
                        .last()
                        .is_some_and(|part| self.zoned.contains(stored_ident_name(part).as_ref()))
                    {
                        return ControlFlow::Break(());
                    }
                }
                Expr::UnaryOp { .. }
                | Expr::BinaryOp { .. }
                | Expr::IsNull(_)
                | Expr::IsNotNull(_)
                | Expr::IsTrue(_)
                | Expr::IsNotTrue(_)
                | Expr::IsFalse(_)
                | Expr::IsNotFalse(_)
                | Expr::IsUnknown(_)
                | Expr::IsNotUnknown(_)
                | Expr::IsDistinctFrom(..)
                | Expr::IsNotDistinctFrom(..)
                | Expr::Between { .. }
                | Expr::InList { .. }
                | Expr::InSubquery { .. }
                | Expr::AnyOp { .. }
                | Expr::AllOp { .. }
                | Expr::Like { .. }
                | Expr::ILike { .. }
                | Expr::Case { .. }
                | Expr::Tuple(_)
                | Expr::Exists { .. }
                | Expr::Subquery(_) => {}
                _ => return ControlFlow::Break(()),
            }
            ControlFlow::Continue(())
        }
    }

    conjunct
        .visit(&mut AskerDependence { registry, zoned })
        .is_break()
}

/// Whether a nested query reaches the guarded row for any of its references.
///
/// A name resolves through the query's own relations, then each enclosing query's, then
/// the membership scan, then the guarded row. The generated query keeps every one of
/// those but the last: it scans the membership table alone and under no alias. So a name
/// that only the guarded row can supply binds to it in the policy and to nothing in the
/// generated query, which is a different question.
///
/// Resolution is by scope, never by spelling. A nested scan of the membership table
/// qualifies its own columns with that table's name, which `pg_dump` writes out in full,
/// and that names the nested scan rather than the enclosing one. Only a qualifier no
/// entered scope binds is judged against the enclosing names, and refusing there is also
/// why stripping would not help: stripping it would resolve the name to the nested scan
/// and turn a correlation into a comparison of a row with itself.
fn reaches_the_guarded_row<DB: DatabaseLike>(
    conjunct: &Expr,
    db: &DB,
    scope: &MembershipScope<'_>,
) -> bool {
    struct GuardedReference<'a, DB> {
        db: &'a DB,
        enclosing: &'a BTreeSet<String>,
        membership_columns: &'a [String],
        /// What each entered query binds. Empty while the walk is still on the conjunct
        /// itself, whose scope the caller has already checked.
        scopes: Vec<QueryScope>,
    }

    impl<DB: DatabaseLike> GuardedReference<'_, DB> {
        /// Whether a name resolves in a scope both queries have.
        fn shared(&self, name: &str, pick: impl Fn(&QueryScope) -> &BTreeSet<String>) -> bool {
            self.scopes.iter().any(|scope| pick(scope).contains(name))
        }
    }

    impl<DB: DatabaseLike> Visitor for GuardedReference<'_, DB> {
        type Break = ();

        fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<()> {
            match query_scope(query, self.db) {
                Some(scope) => self.scopes.push(scope),
                None => return ControlFlow::Break(()),
            }
            ControlFlow::Continue(())
        }

        fn post_visit_query(&mut self, _: &Query) -> ControlFlow<()> {
            self.scopes.pop();
            ControlFlow::Continue(())
        }

        fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<()> {
            match expr {
                Expr::CompoundIdentifier(parts) => {
                    // The relation is the part before the column, so a schema-qualified
                    // spelling names it second from the end as a bare one names it first.
                    let Some(qualifier) = parts.len().checked_sub(2).and_then(|at| parts.get(at))
                    else {
                        return ControlFlow::Continue(());
                    };
                    let qualifier = stored_ident_name(qualifier);
                    if self.shared(qualifier.as_ref(), |scope| &scope.names) {
                        return ControlFlow::Continue(());
                    }
                    if self.enclosing.contains(qualifier.as_ref()) {
                        return ControlFlow::Break(());
                    }
                }
                Expr::Identifier(ident) if !self.scopes.is_empty() => {
                    let name = stored_ident_name(ident);
                    let shared = self.shared(name.as_ref(), |scope| &scope.columns)
                        || self
                            .membership_columns
                            .iter()
                            .any(|column| column == name.as_ref());
                    if !shared {
                        return ControlFlow::Break(());
                    }
                }
                _ => {}
            }
            ControlFlow::Continue(())
        }
    }

    let enclosing: BTreeSet<String> = [Some(scope.table), scope.alias, Some(scope.guarded_table)]
        .into_iter()
        .flatten()
        .map(stored_relation_name)
        .collect();
    conjunct
        .visit(&mut GuardedReference {
            db,
            enclosing: &enclosing,
            membership_columns: scope.columns,
            scopes: Vec::new(),
        })
        .is_break()
}

/// What one query's own `FROM` binds, or [`None`] where one of its relations is not a
/// resolvable plain table.
struct QueryScope {
    /// The relation names and aliases a qualifier can resolve against here.
    names: BTreeSet<String>,
    /// The columns those relations carry.
    columns: BTreeSet<String>,
}

fn query_scope<DB: DatabaseLike>(query: &Query, db: &DB) -> Option<QueryScope> {
    let SetExpr::Select(select) = query.body.as_ref() else {
        return None;
    };
    let mut scope = QueryScope {
        names: BTreeSet::new(),
        columns: BTreeSet::new(),
    };
    for item in &select.from {
        for factor in core::iter::once(&item.relation).chain(item.joins.iter().map(|j| &j.relation))
        {
            let TableFactor::Table { name, alias, .. } = factor else {
                return None;
            };
            let spelling = name.to_string();
            let table = lookup_table(db, &spelling)?;
            scope.names.insert(stored_relation_name(&spelling));
            if let Some(alias) = alias {
                scope
                    .names
                    .insert(stored_ident_name(&alias.name).into_owned());
            }
            scope.columns.extend(
                table
                    .columns(db)
                    .into_iter()
                    .flatten()
                    .map(|column| column.stored_column_name().into_owned()),
            );
        }
    }
    Some(scope)
}

/// Rewrite each relation reference to the identity the catalog carries, spelled as the
/// generated query spells the table it scans.
struct QualifyRelations<'db, DB> {
    db: &'db DB,
}

impl<DB: DatabaseLike> VisitorMut for QualifyRelations<'_, DB> {
    type Break = ();

    fn pre_visit_table_factor(&mut self, factor: &mut TableFactor) -> ControlFlow<()> {
        let TableFactor::Table { name, .. } = factor else {
            return ControlFlow::Break(());
        };
        let Some(table) = lookup_table(self.db, &name.to_string()) else {
            return ControlFlow::Break(());
        };
        let identity = table_identity(table);
        *name = ObjectName(vec![
            ObjectNamePart::Identifier(Ident::with_quote(
                '"',
                identity.schema().unwrap_or("public"),
            )),
            ObjectNamePart::Identifier(Ident::with_quote('"', identity.name())),
        ]);
        ControlFlow::Continue(())
    }
}

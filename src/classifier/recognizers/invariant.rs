//! Whether a residual conjunct answers every caller alike.
//!
//! The loader answers once, as itself, so precomputing is safe only where the answer does
//! not depend on who asks.

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use alloc::collections::{BTreeMap, BTreeSet};
use core::ops::ControlFlow;
use sqlparser::ast::{
    Expr, Ident, ObjectName, ObjectNamePart, Query, SetExpr, TableFactor, Value, Visit, VisitMut,
    Visitor, VisitorMut,
};

use super::attribute::{attribute_operator, ROW_PURE_FUNCTIONS};
use super::subquery::{query_binds_its_own_names, set_limiting_clause};
use super::unwrap_cast_or_nested;
use crate::classifier::function_registry::FunctionRegistry;
use crate::generator::unrestricted::row_level_security_is_off;
use crate::parser::names::{
    builtin_function_name, is_current_user_keyword_name, lookup_table, stored_ident_name,
    stored_relation_name, table_identity,
};
use crate::parser::sql_parser::{ColumnLike, DatabaseLike, TableLike};
use crate::types::TableId;

/// Aggregates whose value the rows decide without their order.
///
/// `array_agg` and `string_agg` are absent: they answer per row order.
const ORDER_FREE_AGGREGATES: &[&str] = &[
    "avg", "bool_and", "bool_or", "count", "every", "max", "min", "sum",
];

/// The scopes a membership subquery resolves its names through, the guarded table being
/// the one the generated query drops.
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
/// Empty where it reads none, which the caller still judges as before. Non-empty rewrites
/// each relation to the identity the catalog carries, so no `search_path` decides it.
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
    let mut columns = SessionColumns::default();
    if let Some(table) = lookup_table(db, scope.table) {
        columns.extend(table, db);
    }
    for name in &names.0 {
        let table = lookup_table(db, name)?;
        if !row_level_security_is_off(table, db) {
            return None;
        }
        relations.insert(table_identity(table));
        columns.extend(table, db);
    }
    if answer_depends_on_the_asker(conjunct, registry, &columns) {
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

/// The columns whose type leaves part of a value to the evaluating session.
#[derive(Default)]
struct SessionColumns {
    /// Read against the session's zone and printed in its date style.
    temporal: BTreeSet<String>,
    /// Printed to a configured precision and summed in whatever order the rows arrive.
    inexact: BTreeSet<String>,
}

impl SessionColumns {
    fn extend<DB: DatabaseLike>(&mut self, table: &DB::Table, db: &DB) {
        for column in table.columns(db).into_iter().flatten() {
            let data_type = column.data_type(db);
            let name = || column.stored_column_name().into_owned();
            if type_is_temporal(&data_type) {
                self.temporal.insert(name());
            }
            if type_is_inexact(&data_type) {
                self.inexact.insert(name());
            }
        }
    }

    /// Whether `expr` names one of `family` anywhere.
    fn named_in(expr: &Expr, family: &BTreeSet<String>) -> bool {
        struct Named<'a>(&'a BTreeSet<String>);

        impl Visitor for Named<'_> {
            type Break = ();

            fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<()> {
                let named = match expr {
                    Expr::Identifier(ident) => Some(stored_ident_name(ident)),
                    Expr::CompoundIdentifier(parts) => parts.last().map(stored_ident_name),
                    _ => None,
                };
                if named.is_some_and(|name| self.0.contains(name.as_ref())) {
                    return ControlFlow::Break(());
                }
                ControlFlow::Continue(())
            }
        }

        expr.visit(&mut Named(family)).is_break()
    }
}

/// Type families the session's zone or date style decides part of.
const TEMPORAL_TYPES: &[&str] = &["date", "interval", "time", "timestamp"];

/// Type families whose addition is not associative, so a sum answers per row order.
const INEXACT_TYPES: &[&str] = &["double", "float", "real"];

fn type_is_temporal(data_type: &str) -> bool {
    type_family_is(data_type, TEMPORAL_TYPES)
}

fn type_is_inexact(data_type: &str) -> bool {
    type_family_is(data_type, INEXACT_TYPES)
}

fn type_family_is(data_type: &str, families: &[&str]) -> bool {
    let lowered = data_type.to_ascii_lowercase();
    let terminal = lowered
        .rsplit('.')
        .next()
        .unwrap_or(&lowered)
        .trim_matches('"');
    families.iter().any(|family| terminal.starts_with(family))
}

/// Every relation named in a `FROM`, refusing anything but a plain table reference.
///
/// A sample, a version, a derived table or a table function reads rows no flag was proven
/// about.
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
/// An allow-list throughout, so an unlisted expression or an unplaceable function refuses.
/// Types carry the rest: a cast or a column whose type the session decides part of refuses,
/// while two stored values compared against each other do not.
fn answer_depends_on_the_asker(
    conjunct: &Expr,
    registry: &FunctionRegistry,
    columns: &SessionColumns,
) -> bool {
    struct AskerDependence<'a> {
        registry: &'a FunctionRegistry,
        columns: &'a SessionColumns,
    }

    impl AskerDependence<'_> {
        fn spans_a_temporal_column_and_a_literal(&self, left: &Expr, right: &Expr) -> bool {
            let literal = |expr: &Expr| matches!(unwrap_cast_or_nested(expr), Expr::Value(_));
            let temporal = |expr: &Expr| SessionColumns::named_in(expr, &self.columns.temporal);
            (temporal(left) && literal(right)) || (temporal(right) && literal(left))
        }
    }

    impl Visitor for AskerDependence<'_> {
        type Break = ();

        fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<()> {
            // A limit answers per evaluation, not per identity, and a binding resolves a
            // name against something the catalog never saw.
            if set_limiting_clause(query).is_some() || query_binds_its_own_names(query) {
                return ControlFlow::Break(());
            }
            ControlFlow::Continue(())
        }

        fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<()> {
            // A cast to a type the session decides part of, or over a column of one, reads
            // that setting however the value got there.
            if let Expr::Cast {
                expr: inner,
                data_type,
                ..
            } = expr
            {
                let rendered = data_type.to_string();
                if type_is_temporal(&rendered)
                    || type_is_inexact(&rendered)
                    || SessionColumns::named_in(inner, &self.columns.temporal)
                    || SessionColumns::named_in(inner, &self.columns.inexact)
                {
                    return ControlFlow::Break(());
                }
            }
            // A zone-less value beside a zoned column is completed by the session's zone.
            if let Some((left, right)) = comparison_operands(expr) {
                if self.spans_a_temporal_column_and_a_literal(left, right) {
                    return ControlFlow::Break(());
                }
            }
            // Neither a cast nor a parenthesis says who is asking.
            match unwrap_cast_or_nested(expr) {
                Expr::Identifier(ident) => {
                    if ident.quote_style.is_none() && is_current_user_keyword_name(&ident.value) {
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
                    // Adding inexact numbers is not associative, so a sum answers per row
                    // order and the loader's order need not be the caller's.
                    if matches!(name.as_str(), "avg" | "sum")
                        && SessionColumns::named_in(expr, &self.columns.inexact)
                    {
                        return ControlFlow::Break(());
                    }
                }
                Expr::CompoundIdentifier(_)
                | Expr::UnaryOp { .. }
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
        .visit(&mut AskerDependence { registry, columns })
        .is_break()
}

/// The two sides of a comparison, absent where `expr` is not one.
fn comparison_operands(expr: &Expr) -> Option<(&Expr, &Expr)> {
    match expr {
        Expr::BinaryOp { left, op, right } => {
            attribute_operator(op).map(|_| (left.as_ref(), right.as_ref()))
        }
        Expr::IsDistinctFrom(left, right) | Expr::IsNotDistinctFrom(left, right) => {
            Some((left, right))
        }
        _ => None,
    }
}

/// Whether a nested query reaches the guarded row for any of its references.
///
/// The generated query scans the membership table alone and under no alias, so a name only
/// the guarded row supplies binds to nothing there. Resolution is by scope, never by
/// spelling, since a nested scan qualifies its own columns with its own table's name.
fn reaches_the_guarded_row<DB: DatabaseLike>(
    conjunct: &Expr,
    db: &DB,
    scope: &MembershipScope<'_>,
) -> bool {
    struct GuardedReference<'a, DB> {
        db: &'a DB,
        enclosing: &'a BTreeSet<String>,
        /// What each scope binds, the membership row outermost.
        scopes: Vec<QueryScope>,
    }

    impl<DB: DatabaseLike> GuardedReference<'_, DB> {
        /// Whether a qualifier resolves to a relation a scope both queries have binds.
        fn binds_relation(&self, name: &str) -> bool {
            self.scopes.iter().any(|scope| scope.names.contains(name))
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
                    // The relation is the part before the column.
                    let Some(qualifier) = parts.len().checked_sub(2).and_then(|at| parts.get(at))
                    else {
                        return ControlFlow::Continue(());
                    };
                    let qualifier = stored_ident_name(qualifier);
                    if self.binds_relation(qualifier.as_ref()) {
                        return ControlFlow::Continue(());
                    }
                    if self.enclosing.contains(qualifier.as_ref()) {
                        return ControlFlow::Break(());
                    }
                }
                Expr::Identifier(ident) => {
                    let name = stored_ident_name(ident);
                    if !self
                        .scopes
                        .iter()
                        .any(|scope| scope.binds_column(name.as_ref()))
                    {
                        return ControlFlow::Break(());
                    }
                }
                _ => {}
            }
            ControlFlow::Continue(())
        }
    }

    // The alias is already stored, so parsing it again would split a dotted one.
    let mut enclosing: BTreeSet<String> = [scope.table, scope.guarded_table]
        .into_iter()
        .map(stored_relation_name)
        .collect();
    enclosing.extend(scope.alias.map(ToString::to_string));
    // The membership row is the outermost scope both queries have, so seeding it leaves no
    // level unresolved.
    let membership = QueryScope {
        names: BTreeSet::new(),
        columns: scope
            .columns
            .iter()
            .map(|column| (column.clone(), 1))
            .collect(),
    };
    conjunct
        .visit(&mut GuardedReference {
            db,
            enclosing: &enclosing,
            scopes: vec![membership],
        })
        .is_break()
}

/// What one query's own `FROM` binds, or [`None`] where one of its relations is not a
/// resolvable plain table.
struct QueryScope {
    /// The relation names and aliases a qualifier can resolve against here.
    names: BTreeSet<String>,
    /// How many of those relations carry each column name. A name two of them carry binds
    /// to neither, and `PostgreSQL` refuses the query rather than choosing.
    columns: BTreeMap<String, usize>,
}

impl QueryScope {
    fn binds_column(&self, name: &str) -> bool {
        self.columns.get(name) == Some(&1)
    }
}

fn query_scope<DB: DatabaseLike>(query: &Query, db: &DB) -> Option<QueryScope> {
    let SetExpr::Select(select) = query.body.as_ref() else {
        return None;
    };
    let mut scope = QueryScope {
        names: BTreeSet::new(),
        columns: BTreeMap::new(),
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
            for column in table.columns(db).into_iter().flatten() {
                *scope
                    .columns
                    .entry(column.stored_column_name().into_owned())
                    .or_default() += 1;
            }
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

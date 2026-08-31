#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use sqlparser::ast::{Expr, Function, FunctionArg, FunctionArgExpr, FunctionArguments};

use crate::parser::names::stored_ident_name;
use crate::types::ColumnName;

/// Peel the wrappers that carry no meaning for what an expression *is*: a cast and a
/// parenthesis.
///
/// The one place that decides it. Every reader that then asks "is this a column, a call, a
/// literal" starts here, so a wrapper learned once is seen through by all of them. Spelled
/// as a loop deliberately: a second peel written as recursion inside another reader is the
/// duplication `every_cast_peel_routes_through_the_shared_peeler` forbids, and the door
/// this crate was burned through twice.
///
/// A cast changes the value, so a reader that keeps the value rather than its shape must
/// not peel: see `projected_select` and the tuple SQL, which keep the cast.
pub(crate) fn unwrap_cast_or_nested(mut expr: &Expr) -> &Expr {
    loop {
        match expr {
            Expr::Cast { expr: inner, .. } | Expr::Nested(inner) => expr = inner.as_ref(),
            _ => return expr,
        }
    }
}

/// The string literal an expression spells, once its casts and parentheses are peeled.
///
/// A non-literal is not static and a literal of any other kind is not a string, so both
/// refuse. Callers add their own reason for wanting one.
pub(crate) fn string_literal(expr: &Expr) -> Option<String> {
    match unwrap_cast_or_nested(expr) {
        Expr::Value(value) => match &value.value {
            sqlparser::ast::Value::SingleQuotedString(text) => Some(text.clone()),
            _ => None,
        },
        _ => None,
    }
}

/// Extract a simple column name from an expression.
///
/// Supports plain identifiers (`owner_id`) and qualified identifiers
/// (`public.docs.owner_id`), returning only the terminal column component under
/// the name `PostgreSQL` stores it.
pub fn extract_column_name(expr: &Expr) -> Option<ColumnName> {
    match unwrap_cast_or_nested(expr) {
        Expr::Identifier(ident) => Some(ColumnName::from_stored(stored_ident_name(ident))),
        Expr::CompoundIdentifier(parts) => {
            Some(ColumnName::from_stored(stored_ident_name(parts.last()?)))
        }
        _ => None,
    }
}

/// Like [`extract_column_name`] but also unwraps `COALESCE(col, default)` and
/// `NULLIF(col, sentinel)`, extracting the column name from the first argument.
pub fn extract_column_name_through_coalesce(expr: &Expr) -> Option<ColumnName> {
    if let Some(col) = extract_column_name(expr) {
        return Some(col);
    }
    if let Expr::Function(func) = expr {
        let name = crate::parser::names::folded_function_name(func);
        if matches!(name.as_deref(), Some("coalesce" | "nullif")) {
            if let FunctionArguments::List(arg_list) = &func.args {
                if let Some(first_arg) = arg_list.args.first() {
                    if let Some(inner) = function_arg_expr(first_arg) {
                        return extract_column_name(inner);
                    }
                }
            }
        }
    }
    None
}

/// Extract the expression payload from a SQL function argument.
pub fn function_arg_expr(arg: &FunctionArg) -> Option<&Expr> {
    match arg {
        FunctionArg::Unnamed(FunctionArgExpr::Expr(expr))
        | FunctionArg::Named {
            arg: FunctionArgExpr::Expr(expr),
            ..
        }
        | FunctionArg::ExprNamed {
            arg: FunctionArgExpr::Expr(expr),
            ..
        } => Some(expr),
        _ => None,
    }
}

/// The function call `expr` makes, through casts and parentheses.
pub fn function_call(expr: &Expr) -> Option<&Function> {
    match unwrap_cast_or_nested(expr) {
        Expr::Function(function) => Some(function),
        _ => None,
    }
}

/// The argument `function` passes at `index`, absent where it passes fewer or names them
/// in a form that carries no expression.
pub fn positional_function_arg(function: &Function, index: usize) -> Option<&Expr> {
    let FunctionArguments::List(arg_list) = &function.args else {
        return None;
    };
    function_arg_expr(arg_list.args.get(index)?)
}

/// Returns `true` when the expression is wrapped through `COALESCE` or `NULLIF`.
pub fn is_coalesce_wrapped(expr: &Expr) -> bool {
    if let Expr::Function(func) = expr {
        let name = crate::parser::names::folded_function_name(func);
        return matches!(name.as_deref(), Some("coalesce" | "nullif"));
    }
    false
}

/// Whether any relation the expression or its subqueries read satisfies `matches`, which
/// stops the walk. A caller collecting every read returns `false` throughout.
/// Column qualifiers are identifiers, so `docs.owner_id` never reports `docs`.
pub fn reads_relation(expr: &Expr, mut matches: impl FnMut(&str) -> bool) -> bool {
    let mut reads = false;
    let _ = sqlparser::ast::visit_relations(expr, |name| {
        if matches(&name.to_string()) {
            reads = true;
            return core::ops::ControlFlow::Break(());
        }
        core::ops::ControlFlow::Continue(())
    });
    reads
}

#[cfg(test)]
use sqlparser::dialect::PostgreSqlDialect;
#[cfg(test)]
use sqlparser::parser::Parser;

/// Parse one SQL expression for tests.
#[cfg(test)]
pub(crate) fn parse_expr_for_tests(sql: &str) -> Expr {
    Parser::new(&PostgreSqlDialect {})
        .try_with_sql(sql)
        .expect("expression should parse")
        .parse_expr()
        .expect("expression should parse")
}

#[cfg(test)]
mod tests {
    use super::parse_expr_for_tests as parse_expr;
    use super::*;
    use sqlparser::ast::{Expr, Ident};

    #[test]
    fn extract_column_name_handles_simple_and_qualified_identifiers() {
        let simple = Expr::Identifier(Ident::new("owner_id"));
        let qualified = Expr::CompoundIdentifier(vec![
            Ident::new("public"),
            Ident::new("docs"),
            Ident::new("owner_id"),
        ]);
        let nested = Expr::Nested(Box::new(Expr::Identifier(Ident::new("owner_id"))));
        let casted = Expr::Cast {
            kind: sqlparser::ast::CastKind::Cast,
            expr: Box::new(Expr::Identifier(Ident::new("owner_id"))),
            data_type: sqlparser::ast::DataType::Uuid,
            format: None,
        };

        assert_eq!(
            extract_column_name(&simple)
                .as_ref()
                .map(ColumnName::as_str),
            Some("owner_id")
        );
        assert_eq!(
            extract_column_name(&qualified)
                .as_ref()
                .map(ColumnName::as_str),
            Some("owner_id")
        );
        assert_eq!(
            extract_column_name(&nested)
                .as_ref()
                .map(ColumnName::as_str),
            Some("owner_id")
        );
        assert_eq!(
            extract_column_name(&casted)
                .as_ref()
                .map(ColumnName::as_str),
            Some("owner_id")
        );
    }

    #[test]
    fn extract_column_name_through_coalesce_unwraps_coalesce() {
        let expr = parse_expr("COALESCE(owner_id, '00000000-0000-0000-0000-000000000000')");
        assert_eq!(
            extract_column_name_through_coalesce(&expr)
                .as_ref()
                .map(ColumnName::as_str),
            Some("owner_id"),
        );
    }

    #[test]
    fn extract_column_name_through_coalesce_unwraps_nullif() {
        let expr = parse_expr("NULLIF(owner_id, '')");
        assert_eq!(
            extract_column_name_through_coalesce(&expr)
                .as_ref()
                .map(ColumnName::as_str),
            Some("owner_id"),
        );
    }

    #[test]
    fn extract_column_name_through_coalesce_passes_through_plain_col() {
        let expr = Expr::Identifier(Ident::new("owner_id"));
        assert_eq!(
            extract_column_name_through_coalesce(&expr)
                .as_ref()
                .map(ColumnName::as_str),
            Some("owner_id"),
        );
    }
}

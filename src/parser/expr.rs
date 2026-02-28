use sqlparser::ast::{Expr, FunctionArg, FunctionArgExpr, FunctionArguments};

/// Extract a simple column name from an expression.
///
/// Supports plain identifiers (`owner_id`) and qualified identifiers
/// (`public.docs.owner_id`), returning only the terminal column component.
pub fn extract_column_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Identifier(ident) => Some(ident.value.clone()),
        Expr::CompoundIdentifier(parts) => Some(parts.last()?.value.clone()),
        Expr::Nested(inner) => extract_column_name(inner),
        Expr::Cast { expr, .. } => extract_column_name(expr),
        _ => None,
    }
}

/// Like [`extract_column_name`] but also unwraps `COALESCE(col, default)` and
/// `NULLIF(col, sentinel)`, extracting the column name from the first argument.
pub fn extract_column_name_through_coalesce(expr: &Expr) -> Option<String> {
    if let Some(col) = extract_column_name(expr) {
        return Some(col);
    }
    if let Expr::Function(func) = expr {
        let name = crate::parser::names::normalized_function_name(func);
        if name == "coalesce" || name == "nullif" {
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

/// Returns `true` when the expression is wrapped through `COALESCE` or `NULLIF`.
pub fn is_coalesce_wrapped(expr: &Expr) -> bool {
    if let Expr::Function(func) = expr {
        let name = crate::parser::names::normalized_function_name(func);
        return name == "coalesce" || name == "nullif";
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlparser::ast::{Expr, Ident};
    use sqlparser::dialect::PostgreSqlDialect;
    use sqlparser::parser::Parser;

    fn parse_expr(sql: &str) -> Expr {
        Parser::new(&PostgreSqlDialect {})
            .try_with_sql(sql)
            .unwrap()
            .parse_expr()
            .unwrap()
    }

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
            array: false,
            format: None,
        };

        assert_eq!(extract_column_name(&simple).as_deref(), Some("owner_id"));
        assert_eq!(extract_column_name(&qualified).as_deref(), Some("owner_id"));
        assert_eq!(extract_column_name(&nested).as_deref(), Some("owner_id"));
        assert_eq!(extract_column_name(&casted).as_deref(), Some("owner_id"));
    }

    #[test]
    fn extract_column_name_through_coalesce_unwraps_coalesce() {
        let expr = parse_expr("COALESCE(owner_id, '00000000-0000-0000-0000-000000000000')");
        assert_eq!(
            extract_column_name_through_coalesce(&expr).as_deref(),
            Some("owner_id"),
        );
    }

    #[test]
    fn extract_column_name_through_coalesce_unwraps_nullif() {
        let expr = parse_expr("NULLIF(owner_id, '')");
        assert_eq!(
            extract_column_name_through_coalesce(&expr).as_deref(),
            Some("owner_id"),
        );
    }

    #[test]
    fn extract_column_name_through_coalesce_passes_through_plain_col() {
        let expr = Expr::Identifier(Ident::new("owner_id"));
        assert_eq!(
            extract_column_name_through_coalesce(&expr).as_deref(),
            Some("owner_id"),
        );
    }
}

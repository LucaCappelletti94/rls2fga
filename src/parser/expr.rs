use sqlparser::ast::Expr;

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

#[cfg(test)]
mod tests {
    use super::extract_column_name;
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
            array: false,
            format: None,
        };

        assert_eq!(extract_column_name(&simple).as_deref(), Some("owner_id"));
        assert_eq!(extract_column_name(&qualified).as_deref(), Some("owner_id"));
        assert_eq!(extract_column_name(&nested).as_deref(), Some("owner_id"));
        assert_eq!(extract_column_name(&casted).as_deref(), Some("owner_id"));
    }
}

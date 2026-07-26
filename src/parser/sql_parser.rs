pub use sql_traits::prelude::*;

/// Parse SQL DDL into a [`ParserDB`].
///
/// Rejects schemas whose foreign keys reference a table or column absent from
/// the input. Downstream FK-based inference resolves referenced tables eagerly
/// (`sql-traits` panics on an orphaned reference), so validating here keeps the
/// whole translation pipeline total on untrusted input.
pub fn parse_schema(sql: &str) -> Result<ParserDB, sql_traits::errors::Error> {
    let db = ParserDB::parse::<sqlparser::dialect::PostgreSqlDialect>(sql)?;
    db.validate_foreign_key_targets()?;
    Ok(db)
}

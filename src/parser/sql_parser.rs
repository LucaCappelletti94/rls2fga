pub use sql_traits::prelude::*;

/// Convenience: parse SQL DDL into a `ParserDB`.
pub fn parse_schema(sql: &str) -> Result<ParserDB, String> {
    ParserDB::parse::<sqlparser::dialect::PostgreSqlDialect>(sql).map_err(|e| e.to_string())
}

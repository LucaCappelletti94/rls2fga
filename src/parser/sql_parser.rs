pub use sql_traits::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

/// Why a SQL schema could not be turned into a [`ParserDB`].
#[derive(Debug, thiserror::Error)]
pub enum SchemaError {
    /// The schema is invalid or references something it does not define.
    #[error("{0}")]
    Schema(#[from] sql_traits::errors::Error),
}

/// Parse SQL DDL into a [`ParserDB`].
///
/// References to objects the input never creates are read under
/// [`AccessResolution::OpenWorld`]. rls2fga models policies rather than
/// privileges, and roles are cluster objects a schema dump does not emit, so a
/// grant or a policy naming one must not refuse the schema.
///
/// # Errors
///
/// Returns [`SchemaError::Schema`] when the schema does not parse, and when it
/// describes something `PostgreSQL` would refuse: a foreign key whose target
/// table, target column or unique constraint is absent, or a policy on a table
/// the search path does not reach. Those refusals are what keeps the rest of the
/// pipeline total, since it resolves references eagerly.
pub fn parse_schema(sql: &str) -> Result<ParserDB, SchemaError> {
    Ok(ParseOptions::default()
        .with_access_resolution(AccessResolution::OpenWorld)
        .parse::<PostgreSqlDialect>(sql)?)
}

pub use sql_traits::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

/// Why a SQL schema could not be turned into a [`ParserDB`].
#[derive(Debug)]
pub enum SchemaError {
    /// The schema is invalid or references something it does not define.
    Schema(sql_traits::errors::Error),
}

impl core::fmt::Display for SchemaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Schema(error) => write!(f, "{error}"),
        }
    }
}

impl core::error::Error for SchemaError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Schema(error) => Some(error),
        }
    }
}

impl From<sql_traits::errors::Error> for SchemaError {
    fn from(error: sql_traits::errors::Error) -> Self {
        Self::Schema(error)
    }
}

/// Parse SQL DDL into a [`ParserDB`].
///
/// Rejects schemas whose foreign keys reference a table or column absent from
/// the input. Downstream FK-based inference resolves referenced tables eagerly
/// (`sql-traits` panics on an orphaned reference), so validating here keeps the
/// whole translation pipeline total on untrusted input.
///
/// References to objects the input never creates are read under
/// [`AccessResolution::OpenWorld`]. rls2fga models policies rather than
/// privileges, and roles are cluster objects a schema dump does not emit, so a
/// grant or a policy naming one must not refuse the schema.
///
/// # Errors
///
/// Returns [`SchemaError::Schema`] when the schema does not parse or does not
/// validate.
pub fn parse_schema(sql: &str) -> Result<ParserDB, SchemaError> {
    let db = ParseOptions::default()
        .with_access_resolution(AccessResolution::OpenWorld)
        .parse::<PostgreSqlDialect>(sql)?;
    db.validate_foreign_key_targets()?;
    Ok(db)
}

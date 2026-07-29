#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
pub use sql_traits::prelude::*;
use sqlparser::ast::{AlterPolicyOperation, Statement};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;

/// Why a SQL schema could not be turned into a [`ParserDB`].
#[derive(Debug)]
pub enum SchemaError {
    /// The schema is invalid or references something it does not define.
    Schema(sql_traits::errors::Error),
    /// `ALTER POLICY` restates a policy the parser keeps at its original
    /// definition, so the schema no longer describes what `PostgreSQL` enforces.
    UnappliedAlterPolicy(String),
}

impl core::fmt::Display for SchemaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Schema(error) => write!(f, "{error}"),
            Self::UnappliedAlterPolicy(policy) => write!(
                f,
                "ALTER POLICY '{policy}' supersedes the expression the policy was created with, \
                 and the parser keeps the original. Fold the change into the CREATE POLICY."
            ),
        }
    }
}

impl core::error::Error for SchemaError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Schema(error) => Some(error),
            Self::UnappliedAlterPolicy(_) => None,
        }
    }
}

impl From<sql_traits::errors::Error> for SchemaError {
    fn from(error: sql_traits::errors::Error) -> Self {
        Self::Schema(error)
    }
}

/// Name of the first policy an `ALTER POLICY` restates rather than renames.
fn unapplied_alter_policy(sql: &str) -> Option<String> {
    Parser::parse_sql(&PostgreSqlDialect {}, sql)
        .ok()?
        .into_iter()
        .find_map(|statement| match statement {
            Statement::AlterPolicy(alter)
                if matches!(alter.operation, AlterPolicyOperation::Apply { .. }) =>
            {
                Some(alter.name.value)
            }
            _ => None,
        })
}

/// Parse SQL DDL into a [`ParserDB`].
///
/// Rejects schemas whose foreign keys reference a table or column absent from
/// the input. Downstream FK-based inference resolves referenced tables eagerly
/// (`sql-traits` panics on an orphaned reference), so validating here keeps the
/// whole translation pipeline total on untrusted input.
///
/// # Errors
///
/// Returns [`SchemaError::UnappliedAlterPolicy`] when a policy expression is
/// altered after creation, and [`SchemaError::Schema`] when the schema itself
/// does not parse or does not validate.
pub fn parse_schema(sql: &str) -> Result<ParserDB, SchemaError> {
    if let Some(policy) = unapplied_alter_policy(sql) {
        return Err(SchemaError::UnappliedAlterPolicy(policy));
    }
    let db = ParserDB::parse::<PostgreSqlDialect>(sql)?;
    db.validate_foreign_key_targets()?;
    Ok(db)
}

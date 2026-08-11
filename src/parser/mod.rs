/// SQL expression helpers used across classifier and generator code paths.
pub mod expr;
/// Heuristic analysis of SQL function bodies to infer their semantic role.
pub mod function_analyzer;
/// The kinds of name this crate handles, each its own type.
pub mod identifiers;
/// Identifier and table-name normalization helpers (schema-qualified names, quoted identifiers).
pub mod names;
/// Thin wrapper around `sql-traits` for schema parsing.
pub mod sql_parser;

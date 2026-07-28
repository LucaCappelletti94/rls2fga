#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use crate::parser::names::lookup_table;
use crate::parser::sql_parser::{ColumnLike, ParserDB, TableLike};

/// Resolve the primary object identifier column for a table.
///
/// Prefers the declared primary key and falls back to a literal `id` column.
/// Returns `None` for a composite primary key: no single column identifies a
/// row, so using one would merge distinct rows into one `OpenFGA` object.
pub(crate) fn resolve_pk_column(table: &str, db: &ParserDB) -> Option<String> {
    let table_info = lookup_table(db, table)?;
    if let Some(pk) = table_info.primary_key_column(db) {
        return Some(pk.column_name().to_string());
    }
    if composite_primary_key_columns(table, db).is_some() {
        return None;
    }
    table_info
        .columns(db)
        .find(|c| c.column_name() == "id")
        .map(|c| c.column_name().to_string())
}

/// Column names of `table`'s primary key when it spans more than one column.
pub(crate) fn composite_primary_key_columns(table: &str, db: &ParserDB) -> Option<Vec<String>> {
    let table_info = lookup_table(db, table)?;
    let columns: Vec<String> = table_info
        .primary_key_columns(db)
        .map(|c| c.column_name().to_string())
        .collect();
    (columns.len() > 1).then_some(columns)
}

/// Returns true when `table` has a column named `col`.
pub(crate) fn table_has_column(db: &ParserDB, table: &str, col: &str) -> bool {
    lookup_table(db, table).is_some_and(|t| t.columns(db).any(|c| c.column_name() == col))
}

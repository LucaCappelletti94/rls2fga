use crate::parser::names::lookup_table;
use crate::parser::sql_parser::{ColumnLike, ParserDB, TableLike};

/// Resolve the primary object identifier column for a table.
///
/// Prefers the declared primary key and falls back to a literal `id` column.
pub(crate) fn resolve_pk_column(table: &str, db: &ParserDB) -> Option<String> {
    let table_info = lookup_table(db, table)?;
    table_info
        .primary_key_column(db)
        .map(|c| c.column_name().to_string())
        .or_else(|| {
            table_info
                .columns(db)
                .find(|c| c.column_name() == "id")
                .map(|c| c.column_name().to_string())
        })
}

/// Returns true when `table` has a column named `col`.
pub(crate) fn table_has_column(db: &ParserDB, table: &str, col: &str) -> bool {
    lookup_table(db, table).is_some_and(|t| t.columns(db).any(|c| c.column_name() == col))
}

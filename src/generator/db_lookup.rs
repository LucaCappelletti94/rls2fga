#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use crate::parser::names::lookup_table;
use crate::parser::sql_parser::{ColumnLike, IndexLike, ParserDB, TableLike};

/// SQL tables a user principal conventionally lives in, most specific first.
pub(crate) const USER_PRINCIPAL_TABLES: &[&str] = &["users", "user"];

/// SQL tables a team principal conventionally lives in, most specific first.
pub(crate) const TEAM_PRINCIPAL_TABLES: &[&str] = &["teams", "team"];

/// Resolve the primary object identifier column for a table.
///
/// Prefers the declared primary key and falls back to an `id` column a single
/// column unique index and a `NOT NULL` constraint make identify a row.
/// Returns `None` when no single column identifies one, since sharing an object
/// id merges distinct rows into one `OpenFGA` object.
pub(crate) fn resolve_pk_column(table: &str, db: &ParserDB) -> Option<String> {
    let table_info = lookup_table(db, table)?;
    // A lookup that cannot answer leaves no basis for an object identifier, and an
    // object identifier the schema does not confirm merges distinct rows into one
    // object, so every arm below refuses unless it positively knows.
    if let Ok(Some(pk)) = table_info.primary_key_column(db) {
        return Some(pk.stored_column_name().into_owned());
    }
    if table_info.has_composite_primary_key(db) != Ok(false) {
        return None;
    }
    table_info
        .columns(db)
        .into_iter()
        .flatten()
        .find(|c| {
            c.stored_column_name() == "id"
                && c.is_nullable(db) == Ok(false)
                && uniquely_constrained("id", table, db)
        })
        .map(|c| c.stored_column_name().into_owned())
}

/// True when a unique index over `column` alone constrains `table`.
pub(crate) fn uniquely_constrained(column: &str, table: &str, db: &ParserDB) -> bool {
    let Some(table_info) = lookup_table(db, table) else {
        return false;
    };
    table_info
        .unique_indices(db)
        .into_iter()
        .flatten()
        .any(|index| {
            let mut columns = index.columns(db).into_iter().flatten();
            columns
                .next()
                .is_some_and(|c| c.stored_column_name() == column)
                && columns.next().is_none()
        })
}

/// Column names of `table`'s primary key when it spans more than one column.
///
/// `None` also covers a key the schema cannot resolve, so a caller deciding whether to
/// refuse must ask `has_composite_primary_key` rather than read `None` as "single".
pub(crate) fn composite_primary_key_columns(table: &str, db: &ParserDB) -> Option<Vec<String>> {
    let table_info = lookup_table(db, table)?;
    let columns: Vec<String> = table_info
        .primary_key_columns(db)
        .into_iter()
        .flatten()
        .map(|c| c.stored_column_name().into_owned())
        .collect();
    (columns.len() > 1).then_some(columns)
}

/// Returns true when `table` has a column named `col`.
pub(crate) fn table_has_column(db: &ParserDB, table: &str, col: &str) -> bool {
    lookup_table(db, table).is_some_and(|t| {
        t.columns(db)
            .into_iter()
            .flatten()
            .any(|c| c.stored_column_name() == col)
    })
}

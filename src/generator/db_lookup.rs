#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use crate::parser::names::lookup_table;
use crate::parser::sql_parser::{ColumnLike, DatabaseLike, IndexLike, TableLike};

/// SQL tables a user principal conventionally lives in, most specific first.
pub(crate) const USER_PRINCIPAL_TABLES: &[&str] = &["users", "user"];

/// SQL tables a team principal conventionally lives in, most specific first.
pub(crate) const TEAM_PRINCIPAL_TABLES: &[&str] = &["teams", "team"];

/// Every column naming a row of `table`, in declared order.
///
/// A declared primary key answers whatever its arity, and a table with none
/// falls back to an `id` a single column unique index and a `NOT NULL`
/// constraint make identify a row. `None` means nothing positively identifies
/// one, which includes a schema that cannot answer, since a guessed identifier
/// merges distinct rows into one `OpenFGA` object.
pub(crate) fn resolve_pk_columns<DB: DatabaseLike>(table: &str, db: &DB) -> Option<Vec<String>> {
    let table_info = lookup_table(db, table)?;
    // Every arm below refuses unless it positively knows: an identifier the schema
    // does not confirm merges distinct rows into one object.
    let Ok(declared) = table_info.primary_key_columns(db) else {
        return None;
    };
    let declared: Vec<String> = declared
        .map(|c| c.stored_column_name().into_owned())
        .collect();
    if !declared.is_empty() {
        return Some(declared);
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
        .map(|c| vec![c.stored_column_name().into_owned()])
}

/// The one column naming a row, `None` when several do or none does.
///
/// Derived from [`resolve_pk_columns`] rather than resolving again, so a caller
/// that cannot work with a compound key refuses explicitly instead of by
/// accident.
pub(crate) fn single_pk_column<DB: DatabaseLike>(table: &str, db: &DB) -> Option<String> {
    let mut columns = resolve_pk_columns(table, db)?.into_iter();
    let only = columns.next()?;
    columns.next().is_none().then_some(only)
}

/// True when a unique index over `column` alone constrains `table`.
pub(crate) fn uniquely_constrained<DB: DatabaseLike>(column: &str, table: &str, db: &DB) -> bool {
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
pub(crate) fn composite_primary_key_columns<DB: DatabaseLike>(
    table: &str,
    db: &DB,
) -> Option<Vec<String>> {
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
pub(crate) fn table_has_column<DB: DatabaseLike>(db: &DB, table: &str, col: &str) -> bool {
    lookup_table(db, table).is_some_and(|t| {
        t.columns(db)
            .into_iter()
            .flatten()
            .any(|c| c.stored_column_name() == col)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::sql_parser::parse_schema;

    const SCHEMA: &str = "
        CREATE TABLE docs (id uuid PRIMARY KEY, owner text);
        CREATE TABLE paper_shares (
            paper_id uuid,
            viewer text,
            PRIMARY KEY (paper_id, viewer)
        );
        CREATE TABLE loose (id uuid NOT NULL UNIQUE, owner text);
        CREATE TABLE nameless (a text, b text);
    ";

    #[test]
    fn a_compound_key_resolves_every_column_in_declared_order() {
        let db = parse_schema(SCHEMA).expect("schema parses");
        assert_eq!(
            resolve_pk_columns("paper_shares", &db),
            Some(vec!["paper_id".to_string(), "viewer".to_string()]),
            "a key spanning two columns names a row through both"
        );
    }

    #[test]
    fn a_single_column_key_resolves_as_a_list_of_one() {
        let db = parse_schema(SCHEMA).expect("schema parses");
        assert_eq!(
            resolve_pk_columns("docs", &db),
            Some(vec!["id".to_string()])
        );
        assert_eq!(
            resolve_pk_columns("loose", &db),
            Some(vec!["id".to_string()]),
            "the id fallback still answers where no key is declared"
        );
    }

    #[test]
    fn a_table_nothing_identifies_still_refuses() {
        let db = parse_schema(SCHEMA).expect("schema parses");
        assert_eq!(resolve_pk_columns("nameless", &db), None);
        assert_eq!(resolve_pk_columns("absent", &db), None);
    }

    #[test]
    fn the_single_column_answer_refuses_a_compound_key() {
        let db = parse_schema(SCHEMA).expect("schema parses");
        assert_eq!(single_pk_column("docs", &db), Some("id".to_string()));
        assert_eq!(
            single_pk_column("paper_shares", &db),
            None,
            "a caller that can only join one column must refuse rather than take the first"
        );
    }
}

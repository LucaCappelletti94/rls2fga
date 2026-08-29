#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use crate::parser::names::lookup_table_id;
use crate::parser::sql_parser::{ColumnLike, DatabaseLike, IndexLike, TableLike};
use crate::types::ColumnKind;
use crate::types::{ColumnName, TableId};

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
pub(crate) fn resolve_pk_columns<DB: DatabaseLike>(
    table: &TableId,
    db: &DB,
) -> Option<Vec<ColumnName>> {
    let table_info = lookup_table_id(db, table)?;
    // Every arm below refuses unless it positively knows: an identifier the schema
    // does not confirm merges distinct rows into one object.
    let Ok(declared) = table_info.primary_key_columns(db) else {
        return None;
    };
    let declared: Vec<ColumnName> = declared
        .map(|c| ColumnName::from_stored(c.stored_column_name()))
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
        .map(|c| vec![ColumnName::from_stored(c.stored_column_name())])
}

/// The one column naming a row, `None` when several do or none does.
///
/// Derived from [`resolve_pk_columns`] rather than resolving again, so a caller
/// that cannot work with a compound key refuses explicitly instead of by
/// accident.
pub(crate) fn single_pk_column<DB: DatabaseLike>(table: &TableId, db: &DB) -> Option<ColumnName> {
    let mut columns = resolve_pk_columns(table, db)?.into_iter();
    let only = columns.next()?;
    columns.next().is_none().then_some(only)
}

/// True when `key_cols` uniquely keys a row of `table`: its primary key is a subset, so
/// no two rows share those columns. False when unknown (no primary key), since then two
/// rows may key the same tuple and a per-row conditional tuple would collide.
pub(crate) fn row_uniquely_keys<DB: DatabaseLike>(
    table: &TableId,
    key_cols: &[&ColumnName],
    db: &DB,
) -> bool {
    let Some(pk) = resolve_pk_columns(table, db) else {
        return false;
    };
    !pk.is_empty() && pk.iter().all(|pk_col| key_cols.contains(&pk_col))
}

/// True when a unique index over `column` alone constrains `table`.
pub(crate) fn uniquely_constrained<DB: DatabaseLike>(
    column: &str,
    table: &TableId,
    db: &DB,
) -> bool {
    let Some(table_info) = lookup_table_id(db, table) else {
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

pub(crate) fn declared_column_type<DB: DatabaseLike>(
    table: &TableId,
    column: &str,
    db: &DB,
) -> Option<String> {
    let table = lookup_table_id(db, table)?;
    let column = table
        .columns(db)
        .into_iter()
        .flatten()
        .find(|candidate| candidate.stored_column_name() == column)?;
    Some(column.data_type(db).to_string())
}

fn column_kind_from_normalized(normalized: &str) -> ColumnKind {
    match normalized {
        "TEXT" | "VARCHAR" => ColumnKind::Text,
        "UUID" => ColumnKind::Uuid,
        "BOOL" | "BOOLEAN" => ColumnKind::Bool,
        "SMALLINT" | "INT2" | "INTEGER" | "INT" | "INT4" | "BIGINT" | "INT8" | "SMALLSERIAL"
        | "SERIAL" | "BIGSERIAL" => ColumnKind::Integer,
        "NUMERIC" | "DECIMAL" => ColumnKind::Decimal,
        "DATE" => ColumnKind::Date,
        "TIME" | "TIME WITHOUT TIME ZONE" => ColumnKind::Time,
        "TIMESTAMP" | "TIMESTAMP WITHOUT TIME ZONE" => ColumnKind::Timestamp,
        "TIMESTAMPTZ" | "TIMESTAMP WITH TIME ZONE" => ColumnKind::TimestampTz,
        "BYTEA" => ColumnKind::Bytea,
        "JSON" | "JSONB" => ColumnKind::Json,
        _ => ColumnKind::Unsupported,
    }
}

fn list_element_kind_from_normalized(normalized: &str) -> ColumnKind {
    normalized
        .strip_suffix("[]")
        .map_or(ColumnKind::Unsupported, column_kind_from_normalized)
}

/// The modelled kind of one stored scalar column.
pub(crate) fn column_kind<DB: DatabaseLike>(table: &TableId, column: &str, db: &DB) -> ColumnKind {
    declared_column_type(table, column, db).map_or(ColumnKind::Unsupported, |declared| {
        column_kind_from_normalized(&declared)
    })
}

/// The modelled element kind of one stored list column.
pub(crate) fn list_element_kind<DB: DatabaseLike>(
    table: &TableId,
    column: &str,
    db: &DB,
) -> ColumnKind {
    declared_column_type(table, column, db).map_or(ColumnKind::Unsupported, |declared| {
        list_element_kind_from_normalized(&declared)
    })
}

/// Column names of `table`'s primary key when it spans more than one column.
///
/// `None` also covers a key the schema cannot resolve, so a caller deciding whether to
/// refuse must ask `has_composite_primary_key` rather than read `None` as "single".
pub(crate) fn composite_primary_key_columns<DB: DatabaseLike>(
    table: &TableId,
    db: &DB,
) -> Option<Vec<ColumnName>> {
    let table_info = lookup_table_id(db, table)?;
    let columns: Vec<ColumnName> = table_info
        .primary_key_columns(db)
        .into_iter()
        .flatten()
        .map(|c| ColumnName::from_stored(c.stored_column_name()))
        .collect();
    (columns.len() > 1).then_some(columns)
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

    fn table(name: &str) -> TableId {
        TableId::from_stored(None, name.to_string())
    }

    #[test]
    fn a_compound_key_resolves_every_column_in_declared_order() {
        let db = parse_schema(SCHEMA).expect("schema parses");
        assert_eq!(
            resolve_pk_columns(&table("paper_shares"), &db),
            Some(vec![
                ColumnName::from_stored("paper_id"),
                ColumnName::from_stored("viewer")
            ]),
            "a key spanning two columns names a row through both"
        );
    }

    #[test]
    fn a_single_column_key_resolves_as_a_list_of_one() {
        let db = parse_schema(SCHEMA).expect("schema parses");
        assert_eq!(
            resolve_pk_columns(&table("docs"), &db),
            Some(vec![ColumnName::from_stored("id")])
        );
        assert_eq!(
            resolve_pk_columns(&table("loose"), &db),
            Some(vec![ColumnName::from_stored("id")]),
            "the id fallback still answers where no key is declared"
        );
    }

    #[test]
    fn a_table_nothing_identifies_still_refuses() {
        let db = parse_schema(SCHEMA).expect("schema parses");
        assert_eq!(resolve_pk_columns(&table("nameless"), &db), None);
        assert_eq!(resolve_pk_columns(&table("absent"), &db), None);
    }

    #[test]
    fn the_single_column_answer_refuses_a_compound_key() {
        let db = parse_schema(SCHEMA).expect("schema parses");
        assert_eq!(
            single_pk_column(&table("docs"), &db),
            Some(ColumnName::from_stored("id"))
        );
        assert_eq!(
            single_pk_column(&table("paper_shares"), &db),
            None,
            "a caller that can only join one column must refuse rather than take the first"
        );
    }
    #[test]
    fn sql_traits_normalizes_timestamp_declarations_before_kind_mapping() {
        let db = parse_schema(
            r"
CREATE TABLE temporal (
    zoned TIMESTAMP(3) WITH TIME ZONE,
    compact TIMESTAMPTZ(3),
    plain TIMESTAMP(3),
    explicit TIMESTAMP(3) WITHOUT TIME ZONE,
    zoned_list TIMESTAMPTZ(3)[]
);
",
        )
        .expect("schema parses");
        let temporal = table("temporal");

        assert_eq!(
            column_kind(&temporal, "zoned", &db),
            ColumnKind::TimestampTz
        );
        assert_eq!(
            column_kind(&temporal, "compact", &db),
            ColumnKind::TimestampTz
        );
        assert_eq!(column_kind(&temporal, "plain", &db), ColumnKind::Timestamp);
        assert_eq!(
            column_kind(&temporal, "explicit", &db),
            ColumnKind::Timestamp
        );
        assert_eq!(
            list_element_kind(&temporal, "zoned_list", &db),
            ColumnKind::TimestampTz
        );
    }
}

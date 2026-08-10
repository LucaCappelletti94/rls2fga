//! What the emitted model calls a row of a table.
//!
//! A consumer asking an authorization service about one changed row has to name that row,
//! and the name is not the table's: the model assigns a type, appending a suffix when two
//! tables canonicalise alike, and builds the object from the row's key.
//!
//! Reading the naming off the shapes instead is ambiguous, which is why this exists: a
//! table whose whole primary key is a foreign key is keyed identically by its own shape
//! and by a shape describing its parent from its rows, so `doc_acl` rows are named both
//! `doc_acl:4` and `docs:4` and nothing in a shape says which is the row's own.

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;

use crate::generator::db_lookup::resolve_pk_columns;
use crate::generator::model_generator::SchemaPlan;
use crate::generator::records::{ObjectKey, ValueSource};
use crate::parser::sql_parser::DatabaseLike;

/// How rows of one table are named as objects of the emitted model.
///
/// `#[non_exhaustive]`: a naming this learns to report adds a field.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RowNaming {
    /// Table as the schema spells it, which is the spelling
    /// [`RecordDerivation::FromRow::table`](crate::generator::records::RecordDerivation)
    /// carries.
    pub table: String,
    /// The type the model assigned it, after any collision suffix.
    pub type_name: String,
    /// How one of its rows is named. Render it with
    /// [`ObjectKey::render`](crate::generator::records::ObjectKey::render).
    pub key: ObjectKey,
}

/// One entry per table whose rows the model names, in table order.
///
/// A table the model cannot name rows of is absent rather than present with an empty key.
/// That is not a silent loss: the translation reports it as unhandled, and
/// [`Translation::outputs`](crate::translator::Translation::outputs) refuses on it.
pub(crate) fn row_naming<DB: DatabaseLike>(plan: &SchemaPlan, db: &DB) -> Vec<RowNaming> {
    let mut entries: Vec<RowNaming> = plan
        .types
        .iter()
        .filter_map(|type_plan| {
            let table = type_plan.source_table.as_ref()?;
            let columns = resolve_pk_columns(table, db)?;
            Some(RowNaming {
                table: table.clone(),
                type_name: type_plan.type_name.clone(),
                key: ObjectKey::new(columns.into_iter().map(ValueSource::Column).collect()),
            })
        })
        .collect();
    entries.sort_by(|left, right| left.table.cmp(&right.table));
    entries
}

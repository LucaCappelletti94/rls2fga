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
//!
//! A partition is named after its root, which is where its rows already are: the query
//! minting the root's objects reads every partition and the root's key spans them.

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use alloc::collections::BTreeMap;

use crate::generator::db_lookup::resolve_pk_columns;
use crate::generator::model_generator::{qualified_table_name, SchemaPlan, TypePlan};
use crate::generator::records::{ObjectKey, ValueSource};
use crate::parser::identifiers::ColumnName;
use crate::parser::sql_parser::{DatabaseLike, TableLike};

/// How rows of one table are named as objects of the emitted model.
///
/// `#[non_exhaustive]`: a naming this learns to report adds a field.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RowNaming {
    /// Table as the schema spells it. For a table the model types, this is the spelling
    /// [`RecordDerivation::FromRow::table`](crate::generator::records::RecordDerivation)
    /// carries. A partition has no type and no derivation of its own, and carries its
    /// own spelling with its root's type.
    pub table: String,
    /// The type the model assigned it, after any collision suffix.
    pub type_name: String,
    /// How one of its rows is named. Render it with
    /// [`ObjectKey::render`](crate::generator::records::ObjectKey::render).
    pub key: ObjectKey,
}

/// The type a table's rows are named by, and the columns that key them.
fn named_by<DB: DatabaseLike>(type_plan: &TypePlan, db: &DB) -> Option<(String, Vec<ColumnName>)> {
    let table = type_plan.source_table.as_ref()?;
    let columns = resolve_pk_columns(table, db)?;
    Some((type_plan.type_name.to_string(), columns))
}

/// The plan whose objects a partition's rows are named as, walking up until one is
/// planned.
///
/// A partitioned root's own tuple queries read every partition and its key spans them,
/// so a partition's rows already carry the root's objects. An `INHERITS` child is not
/// reached from here: those queries read `FROM ONLY`, and `PostgreSQL` refuses both to
/// inherit from a partitioned table and to inherit from a partition, so this walk cannot
/// arrive at one.
fn planned_partition_root<'plan, DB: DatabaseLike>(
    table: &DB::Table,
    planned: &BTreeMap<&str, &'plan TypePlan>,
    db: &DB,
) -> Option<&'plan TypePlan> {
    let mut current = table.partition_root(db).ok()??;
    loop {
        if let Some(found) = planned.get(qualified_table_name(current).as_str()) {
            return Some(found);
        }
        current = current.partition_root(db).ok()??;
    }
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
            let (type_name, columns) = named_by(type_plan, db)?;
            Some(RowNaming {
                table: table.clone(),
                type_name,
                key: object_key(columns),
            })
        })
        .collect();
    let planned: BTreeMap<&str, &TypePlan> = plan
        .types
        .iter()
        .filter_map(|type_plan| Some((type_plan.source_table.as_deref()?, type_plan)))
        .collect();
    entries.extend(db.tables().filter_map(|table| {
        let root = planned_partition_root(table, &planned, db)?;
        let named = qualified_table_name(table);
        // A partition carrying its own policy already has a type, and one table takes one
        // name: a consumer keying on the table drops whichever entry came second, and
        // which one that is would be arbitrary.
        if planned.contains_key(named.as_str()) {
            return None;
        }
        let (type_name, columns) = named_by(root, db)?;
        Some(RowNaming {
            table: named,
            type_name,
            key: object_key(columns),
        })
    }));
    entries.sort_by(|left, right| left.table.cmp(&right.table));
    entries
}

fn object_key(columns: Vec<ColumnName>) -> ObjectKey {
    ObjectKey::new(columns.into_iter().map(ValueSource::Column).collect())
}

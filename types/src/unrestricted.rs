use crate::TableId;

/// A table the database is positively known to restrict nothing on.
///
/// `#[non_exhaustive]`: a fact this learns to report adds a field.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UnrestrictedTable {
    /// Table as the schema stores it, the spelling
    /// [`RowNaming::table`](crate::RowNaming) carries.
    pub table: TableId,
}
impl UnrestrictedTable {
    /// Build one unrestricted-table entry.
    #[must_use]
    pub fn new(table: TableId) -> Self {
        Self { table }
    }
}

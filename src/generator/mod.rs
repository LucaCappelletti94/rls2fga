/// Shared schema lookup helpers used by model/tuple generation.
pub(crate) mod db_lookup;
/// Whether a relation's records follow from one row.
pub mod decidable;
// `describe` and `records` carry their own `//!` docs, so no outer doc here: a
// module with both resolves its intra-doc links in this file's scope instead of
// its own, and the type names it talks about live there.
pub(crate) mod describe;
/// Shared authorization intermediate representation (`TupleSource` and friends).
pub(crate) mod ir;
/// `OpenFGA` JSON authorization model structs and builder.
pub mod json_model;
/// `OpenFGA` DSL text model generation.
pub mod model_generator;
// `notes` carries its own `//!` docs, so no outer doc here.
pub mod notes;
pub mod records;
/// Shared helpers for stable and valid role-based relation naming.
pub(crate) mod role_relations;
/// SQL queries that populate `OpenFGA` relationship tuples from live data.
pub mod tuple_generator;
/// Type and relation names the generator reserves.
pub(crate) mod well_known;

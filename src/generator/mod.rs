/// Shared schema lookup helpers used by model/tuple generation.
pub(crate) mod db_lookup;
/// Deriving per-row record descriptions from the tuple-source IR.
pub(crate) mod describe;
/// Shared authorization intermediate representation (`TupleSource` and friends).
pub(crate) mod ir;
/// `OpenFGA` JSON authorization model structs and builder.
pub mod json_model;
/// `OpenFGA` DSL text model generation.
pub mod model_generator;
/// Per-row descriptions of the records a tuple query produces.
pub mod records;
/// Shared helpers for stable and valid role-based relation naming.
pub(crate) mod role_relations;
/// SQL queries that populate `OpenFGA` relationship tuples from live data.
pub mod tuple_generator;
/// Type and relation names the generator reserves.
pub(crate) mod well_known;

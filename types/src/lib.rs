//! Parser-independent output contracts and row evaluation.
//!
//! Unchecked `OpenFGA` names are internal.
//!
//! ```compile_fail
//! use rls2fga_types::{RelationName, TypeName};
//! let _ = TypeName::from_resolved("not valid");
//! let _ = RelationName::from_resolved("not valid");
//! ```

#![no_std]
#![warn(missing_docs)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::indexing_slicing,
        clippy::todo,
        clippy::unimplemented
    )
)]

extern crate alloc;

mod action_relations;
mod identifiers;
mod identity;
mod notes;
mod patterns;
mod records;
mod relations;
mod row_naming;
mod unrestricted;

pub use action_relations::{
    ActionAnswer, ActionJudgement, ActionRelations, ActionStatement, RowVersion,
};
pub use identifiers::{
    ColumnName, ConditionParameterName, ConditionParameterNameError, RelationName,
    RelationNameError, TableId, TableRef, TypeName, TypeNameError,
};
pub use notes::{NoteSeverity, TranslationNote};
pub use patterns::{
    AttributeLiteral, AttributeOperator, AttributePredicate, ConfidenceLevel, RolePrivilege,
};
pub use records::{
    records_from_row, BoundQuery, ColumnKind, ColumnRead, ContextRendering, Guard, ObjectKey,
    Record, RecordContext, RecordContextEntry, RecordContextValue, RecordDerivation,
    RecordDescription, RecordError, RecordTemplate, ReplayScope, RowCell, RowList, RowValues,
    SubjectKey, ValueSource,
};
pub use relations::{RelationShapes, RequestComparison, RowDecision};
pub use row_naming::RowNaming;
pub use unrestricted::UnrestrictedTable;

pub(crate) mod prelude {
    pub(crate) use alloc::{
        boxed::Box,
        format,
        string::{String, ToString},
        vec,
        vec::Vec,
    };
}

use crate::prelude::*;
use crate::{RecordDescription, RelationName, TypeName};

/// What one model relation needs and whether one row can decide it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelationShapes {
    /// `OpenFGA` type the relation is defined on.
    pub type_name: TypeName,
    /// Relation name.
    pub relation: RelationName,
    /// True only when every leaf resolves from the object's own row to a named
    /// user. False whenever the analysis cannot establish that, including every
    /// case it does not understand.
    pub from_one_row: bool,
    /// The shapes whose records fill this relation, one per query the loader runs
    /// for it. Empty for a relation the model computes from others, and for one
    /// nothing populates.
    pub shapes: Vec<RecordDescription>,
    /// How the subjects this relation grants compose from one row, `Some` exactly
    /// when `from_one_row` is true.
    pub decision: Option<RowDecision>,
    /// Whether the model refuses this relation for every row, so no record fills it and
    /// no round trip is needed to be told no. False for a direct relation, which grants
    /// whatever is written into it.
    pub grants_nobody: bool,
}

/// How the subjects a relation grants compose from one row's records.
///
/// The whole evaluation: [`Self::Leaf`] is the union of the subjects
/// [`crate::records_from_row`] yields over its shapes,
/// [`Self::Any`] is the union of its children and [`Self::All`] their intersection.
///
/// `#[non_exhaustive]`: a shape the analysis learns to decide adds a variant, and a
/// caller matching this outside the crate keeps a wildcard arm.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RowDecision {
    /// The subjects are the records these shapes produce for this row.
    Leaf {
        /// The direct relation whose records answer. Always on the same type.
        relation: RelationName,
        /// The shapes filling it, identical to that relation's own entry. Never empty.
        shapes: Vec<RecordDescription>,
    },
    /// A subject any child grants.
    Any(Vec<RowDecision>),
    /// A subject every child grants.
    All(Vec<RowDecision>),
    /// The row settles one side of a comparison the caller's own request value
    /// completes, so a consumer holding that value decides with no round trip.
    ///
    /// Taking the subjects at face value is a wrong allow: the shapes here yield
    /// `user:*`, which grants everyone until the comparison is applied.
    RequestGated {
        /// The direct relation whose records carry the row's side. Always on the same
        /// type.
        relation: RelationName,
        /// The shapes filling it, identical to that relation's own entry. Never empty.
        shapes: Vec<RecordDescription>,
        /// Context key each record carries the row's side under.
        context_key: String,
        /// Parameter the caller supplies its own value as, in every check context.
        request_parameter: String,
        /// How the two sides are compared.
        comparison: RequestComparison,
    },
}

/// How a request-gated relation compares the row's side against the caller's.
///
/// `#[non_exhaustive]` permits more comparisons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum RequestComparison {
    /// The caller's set has to hold the row's value.
    CallerSetHolds,
    /// The caller's single value has to equal the row's.
    CallerValueEquals,
}

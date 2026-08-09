//! Per-row description of the records a tuple query produces, and an evaluator
//! for the descriptions that need only one row.
//!
//! [`crate::generator::tuple_generator`] emits whole-table SQL, which loads a
//! store but cannot answer what one changed row implies. A [`RecordDescription`]
//! says the same thing as structure, so a caller holding a row's column values
//! reaches the same records without a database.

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use alloc::borrow::Cow;

use crate::classifier::patterns::{AttributeLiteral, AttributeOperator, AttributePredicate};

/// One `(object, relation, subject)` fact, rendered exactly as the whole-table
/// SQL renders it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Record {
    /// `type:key`.
    pub object: String,
    /// Relation name.
    pub relation: String,
    /// `type:key`, or `user:*` for a wildcard.
    pub subject: String,
    /// The condition context this record carries, absent for an unconditional one.
    ///
    /// Present means the grant is not settled by the row: the service completes it
    /// with what the request supplies, so treating the subject as granted is a wrong
    /// allow.
    pub context: Option<RecordContextValue>,
}

/// One key and value a record puts in its condition context.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RecordContextValue {
    /// Condition parameter the value fills.
    pub key: String,
    /// The value, rendered as the tuple SQL renders it.
    pub value: String,
}

/// Where one side of a record takes its value on the row.
///
/// `#[non_exhaustive]`: a new tuple shape adds a variant, and a caller matching
/// this outside the crate keeps a wildcard arm.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValueSource {
    /// A scalar column, read as text. One record per row.
    Column(String),
    /// A list column, one record per element. An empty or null list yields none,
    /// and a null element is dropped, which is how `= ANY` refuses it.
    ListElements(String),
    /// A path into a JSON column, read as text. A missing key yields no record.
    JsonPath {
        /// The JSON column.
        column: String,
        /// Field names, outermost first.
        path: Vec<String>,
    },
    /// A fixed value, carried by the description rather than read from the row.
    Literal(String),
}

/// A condition the row must satisfy for the records to exist.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Guard {
    /// The column is not SQL NULL.
    NotNull(String),
    /// The boolean column is true.
    IsTrue(String),
    /// The column compares as stated against a literal constant. A NULL column
    /// fails every comparison, exactly as SQL's three-valued logic filters it.
    Compare(AttributePredicate),
}

/// How the object, relation and subject of a record compose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordTemplate {
    /// `OpenFGA` type the object belongs to.
    pub object_type: String,
    /// Where the object's key comes from.
    pub object_key: ValueSource,
    /// Relation name, always fixed.
    pub relation: String,
    /// `OpenFGA` type the subject belongs to.
    pub subject_type: String,
    /// Where the subject's key comes from.
    pub subject_key: ValueSource,
    /// The condition context the record carries, absent for an unconditional one.
    ///
    /// A conditional record grants nobody on its own: the service completes the
    /// comparison with what the request supplies, so a reader that ignores this and
    /// takes the subject at face value grants everyone.
    pub context: Option<RecordContext>,
}

/// One key a record puts in its condition context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordContext {
    /// Condition parameter the value fills.
    pub key: String,
    /// Where the value comes from.
    pub value: ValueSource,
}

/// A query bound to one row of one table by its key, for a shape whose records
/// no single row decides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundQuery {
    /// Table the change arrived on.
    pub table: String,
    /// Column the query binds.
    pub key_column: String,
    /// SQL taking the key value as `$1`.
    pub sql: String,
}

/// Whether a description's records follow from one row.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecordDerivation {
    /// The records are a function of one row of `table`, however many records
    /// that is, so [`records_from_row`] answers with no database.
    FromRow {
        /// The table the row belongs to.
        table: String,
        /// How each record composes. Boxed to keep this variant near the size of the
        /// joining one, which holds only a query list.
        template: Box<RecordTemplate>,
        /// Conditions the row must satisfy, all of them.
        guards: Vec<Guard>,
    },
    /// The records depend on more than the changed row, so a change to any table
    /// the shape reads has to be answered by querying.
    Joined {
        /// One query per table a change may arrive on.
        queries: Vec<BoundQuery>,
        /// Why one row does not decide, for the report.
        reason: String,
    },
}

/// The records one tuple query produces, described as structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordDescription {
    /// Every table the query reads, so a caller can refuse a table its change
    /// stream does not carry. Sorted and deduplicated.
    pub tables: Vec<String>,
    /// Whether one row decides the records.
    pub derivation: RecordDerivation,
}

impl RecordDescription {
    /// True when [`records_from_row`] can answer without a database.
    #[must_use]
    pub fn is_pure(&self) -> bool {
        matches!(self.derivation, RecordDerivation::FromRow { .. })
    }

    /// The table a pure description reads, `None` for a joining one.
    #[must_use]
    pub fn row_table(&self) -> Option<&str> {
        match &self.derivation {
            RecordDerivation::FromRow { table, .. } => Some(table),
            RecordDerivation::Joined { .. } => None,
        }
    }
}

/// One row's column values, as seen by [`records_from_row`].
///
/// Every method defaults to "the row does not say", which yields no record
/// rather than a wrong one. A shape added later therefore reads as absent to an
/// existing implementation instead of failing to compile.
pub trait RowValues {
    /// Text of a scalar column, `None` when SQL NULL or absent.
    fn text(&self, column: &str) -> Option<Cow<'_, str>> {
        let _ = column;
        None
    }

    /// A boolean column, `None` when SQL NULL, absent, or not boolean.
    fn boolean(&self, column: &str) -> Option<bool> {
        let _ = column;
        None
    }

    /// Elements of a list column, `None` when the column is SQL NULL or absent.
    /// A null element is `None` inside the list.
    fn list(&self, column: &str) -> Option<Vec<Option<Cow<'_, str>>>> {
        let _ = column;
        None
    }

    /// Text at a path inside a JSON column, `None` when the column is SQL NULL,
    /// absent, the path is missing, or the value at it is JSON null.
    fn json_text(&self, column: &str, path: &[String]) -> Option<Cow<'_, str>> {
        let _ = (column, path);
        None
    }
}

/// Why a description's records could not be produced from a row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordError {
    /// The description reads more than the one row, so querying is the only
    /// answer. Carries the reason the description recorded.
    NotDerivableFromOneRow(String),
}

impl core::fmt::Display for RecordError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotDerivableFromOneRow(reason) => write!(
                f,
                "records do not follow from one row and must be queried: {reason}"
            ),
        }
    }
}

impl core::error::Error for RecordError {}

/// Produce the records one row implies.
///
/// # Errors
///
/// Returns [`RecordError::NotDerivableFromOneRow`] for a joining description,
/// since an empty set would read as "this row implies nothing", which is a
/// different and wrong answer.
pub fn records_from_row<R: RowValues + ?Sized>(
    description: &RecordDescription,
    row: &R,
) -> Result<Vec<Record>, RecordError> {
    let (table, template, guards) = match &description.derivation {
        RecordDerivation::FromRow {
            table,
            template,
            guards,
        } => (table, template, guards),
        RecordDerivation::Joined { reason, .. } => {
            return Err(RecordError::NotDerivableFromOneRow(reason.clone()))
        }
    };
    let _ = table;

    if !guards.iter().all(|guard| guard_holds(guard, row)) {
        return Ok(Vec::new());
    }

    // The object side never expands, so a missing value drops the whole record
    // exactly as the SQL's NULL guard does.
    let Some(object_key) = single_value(&template.object_key, row) else {
        return Ok(Vec::new());
    };

    // A context the row cannot fill yields no record at all, exactly as the tuple SQL
    // skips a row whose carried column is NULL.
    let context = match &template.context {
        Some(context) => match single_value(&context.value, row) {
            Some(value) => Some(RecordContextValue {
                key: context.key.clone(),
                value,
            }),
            None => return Ok(Vec::new()),
        },
        None => None,
    };

    Ok(expand(&template.subject_key, row)
        .into_iter()
        .map(|subject_key| Record {
            object: format!("{}:{object_key}", template.object_type),
            relation: template.relation.clone(),
            subject: format!("{}:{subject_key}", template.subject_type),
            context: context.clone(),
        })
        .collect())
}

fn guard_holds<R: RowValues + ?Sized>(guard: &Guard, row: &R) -> bool {
    match guard {
        Guard::NotNull(column) => row.text(column).is_some(),
        Guard::IsTrue(column) => row.boolean(column) == Some(true),
        Guard::Compare(predicate) => compare_holds(predicate, row),
    }
}

/// A column against a literal, ordered numerically when both sides are numbers and
/// lexically otherwise, which is what the column's own type decides in SQL.
///
/// A NULL or absent column fails every comparison, `<>` included, mirroring the way
/// three-valued logic filters the row rather than admitting it.
fn compare_holds<R: RowValues + ?Sized>(predicate: &AttributePredicate, row: &R) -> bool {
    let ordering = match &predicate.value {
        AttributeLiteral::Boolean(flag) => {
            let Some(actual) = row.boolean(&predicate.column) else {
                return false;
            };
            actual.cmp(flag)
        }
        AttributeLiteral::Number(number) => {
            let Some(actual) = row.text(&predicate.column) else {
                return false;
            };
            // A number the row or the policy spells unparseably cannot be ordered, so
            // the guard refuses rather than falling back to text.
            let (Ok(left), Ok(right)) = (actual.parse::<f64>(), number.parse::<f64>()) else {
                return false;
            };
            let Some(ordering) = left.partial_cmp(&right) else {
                return false;
            };
            ordering
        }
        AttributeLiteral::Text(text) => {
            let Some(actual) = row.text(&predicate.column) else {
                return false;
            };
            actual.as_ref().cmp(text.as_str())
        }
    };

    match predicate.operator {
        AttributeOperator::Eq => ordering.is_eq(),
        AttributeOperator::NotEq => ordering.is_ne(),
        AttributeOperator::Gt => ordering.is_gt(),
        AttributeOperator::GtEq => ordering.is_ge(),
        AttributeOperator::Lt => ordering.is_lt(),
        AttributeOperator::LtEq => ordering.is_le(),
    }
}

/// The one value a non-expanding source yields.
fn single_value<R: RowValues + ?Sized>(source: &ValueSource, row: &R) -> Option<String> {
    match source {
        ValueSource::Column(column) => row.text(column).map(Cow::into_owned),
        ValueSource::JsonPath { column, path } => row.json_text(column, path).map(Cow::into_owned),
        ValueSource::Literal(value) => Some(value.clone()),
        // A list on the object side is not a shape the crate emits, and guessing
        // an element would key the record on an arbitrary one.
        ValueSource::ListElements(_) => None,
    }
}

/// Every value a source yields, which is at most one except for a list.
fn expand<R: RowValues + ?Sized>(source: &ValueSource, row: &R) -> Vec<String> {
    match source {
        ValueSource::ListElements(column) => row
            .list(column)
            .unwrap_or_default()
            .into_iter()
            .flatten()
            .map(Cow::into_owned)
            .collect(),
        other => single_value(other, row).into_iter().collect(),
    }
}

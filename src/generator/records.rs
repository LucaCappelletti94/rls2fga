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
use alloc::collections::BTreeMap;

use crate::classifier::patterns::{AttributeLiteral, AttributeOperator, AttributePredicate};
use crate::generator::identity::{
    encode_identity, encode_part, object_name_fits, subject_name_fits,
};
use crate::generator::well_known::WILDCARD_SUBJECT_ID;
use crate::parser::identifiers::{ColumnName, RelationName};
use serde::{Deserialize, Serialize};

/// One `(object, relation, subject)` fact, rendered exactly as the whole-table
/// SQL renders it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Record {
    /// `type:key`.
    pub object: String,
    /// Relation name.
    pub relation: RelationName,
    /// `type:key`, or `user:*` for a wildcard.
    pub subject: String,
    /// The condition context this record carries, absent for an unconditional one.
    ///
    /// Present means the grant is not settled by the row: the service completes it
    /// with what the request supplies, so treating the subject as granted is a wrong
    /// allow.
    pub context: Option<RecordContextValue>,
}

/// One key and value a record puts in its condition context, under the condition
/// the tuple has to name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RecordContextValue {
    /// Condition the tuple names, declared by the model.
    pub condition: String,
    /// Each parameter the row fills in the condition context, keyed by parameter
    /// name and rendered as the tuple SQL renders it.
    pub values: BTreeMap<String, String>,
}

/// Column type family the row interface can render like `PostgreSQL`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ColumnKind {
    /// Text types.
    Text,
    /// UUID values.
    Uuid,
    /// Boolean values.
    Bool,
    /// Exact whole numbers.
    Integer,
    /// Exact decimal numbers.
    Decimal,
    /// Date values.
    Date,
    /// Times without a time zone.
    Time,
    /// Timestamps without a time zone.
    Timestamp,
    /// Timestamps with a time zone.
    TimestampTz,
    /// Byte arrays.
    Bytea,
    /// JSON values.
    Json,
    /// A type this evaluator cannot print.
    Unsupported,
}

impl ColumnKind {
    /// Map a declared type to the supported family.
    #[must_use]
    pub fn from_declared(declared: &str) -> Self {
        let lowered = declared.trim().to_ascii_lowercase();
        if lowered.trim_end().ends_with("[]") {
            return Self::Unsupported;
        }
        let base = lowered.split('(').next().unwrap_or(&lowered).trim();
        match base {
            "text" | "varchar" | "character varying" => Self::Text,
            "uuid" => Self::Uuid,
            "bool" | "boolean" => Self::Bool,
            "smallint" | "int2" | "integer" | "int" | "int4" | "bigint" | "int8"
            | "smallserial" | "serial" | "bigserial" => Self::Integer,
            "numeric" | "decimal" => Self::Decimal,
            "date" => Self::Date,
            "time" | "time without time zone" => Self::Time,
            "timestamp" | "timestamp without time zone" => Self::Timestamp,
            "timestamptz" | "timestamp with time zone" => Self::TimestampTz,
            "bytea" => Self::Bytea,
            "json" | "jsonb" => Self::Json,
            _ => Self::Unsupported,
        }
    }

    /// Map an array declared type to its element family.
    #[must_use]
    pub fn from_array_declared(declared: &str) -> Self {
        let lowered = declared.trim().to_ascii_lowercase();
        let Some(element) = lowered.trim_end().strip_suffix("[]") else {
            return Self::Unsupported;
        };
        Self::from_declared(element.trim_end())
    }
}

/// One column read with the type the schema declares.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnRead {
    column: ColumnName,
    kind: ColumnKind,
}

impl ColumnRead {
    /// A resolved column and the type family it carries.
    #[must_use]
    pub fn new(column: ColumnName, kind: ColumnKind) -> Self {
        Self { column, kind }
    }

    /// A text column named as stored in the schema.
    #[must_use]
    pub fn text(name: impl Into<String>) -> Self {
        Self::new(ColumnName::from_stored(name), ColumnKind::Text)
    }

    /// The stored column name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.column.as_str()
    }

    /// The type family this read expects.
    #[must_use]
    pub const fn kind(&self) -> ColumnKind {
        self.kind
    }

    /// The stored column name as an identifier.
    #[must_use]
    pub const fn column(&self) -> &ColumnName {
        &self.column
    }
}

impl core::ops::Deref for ColumnRead {
    type Target = ColumnName;

    fn deref(&self) -> &Self::Target {
        &self.column
    }
}

impl core::fmt::Display for ColumnRead {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.column.fmt(f)
    }
}

impl PartialEq for ColumnRead {
    fn eq(&self, other: &Self) -> bool {
        self.column == other.column
    }
}

impl PartialEq<str> for ColumnRead {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<&str> for ColumnRead {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl Eq for ColumnRead {}

/// One row cell as decoded by the consumer.
///
/// Every spelling variant must carry `PostgreSQL`'s own text output for the value,
/// as `::text` renders it under the session settings the tuple script pins (`UTC`,
/// `ISO, MDY`, hex bytea). The spelling is the identity: a `numeric` rendered `1.00`
/// by the database and handed here as `1` names a different object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RowCell<'a> {
    /// The row image has no such column.
    Absent,
    /// The cell is SQL NULL.
    Null,
    /// The consumer could not decode this cell.
    Undecodable,
    /// A text value.
    Text(Cow<'a, str>),
    /// A UUID value.
    Uuid(Cow<'a, str>),
    /// A boolean value.
    Bool(bool),
    /// A whole number spelling.
    Integer(Cow<'a, str>),
    /// A decimal spelling.
    Decimal(Cow<'a, str>),
    /// A date spelling.
    Date(Cow<'a, str>),
    /// A time spelling.
    Time(Cow<'a, str>),
    /// A timestamp spelling without a time zone.
    Timestamp(Cow<'a, str>),
    /// A timestamp spelling with a time zone.
    TimestampTz(Cow<'a, str>),
    /// Raw bytes.
    Bytea(Cow<'a, [u8]>),
}

/// One list column as decoded by the consumer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RowList<'a> {
    /// The row image has no such column.
    Absent,
    /// The list cell is SQL NULL.
    Null,
    /// The consumer could not decode the list.
    Undecodable,
    /// The decoded list elements.
    Values(Vec<RowCell<'a>>),
}

/// One condition context spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContextRendering {
    /// Render like tuple SQL text.
    SqlText,
    /// Render like condition context JSON.
    Json,
}

/// Where one side of a record takes its value on the row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ValueSource {
    /// A scalar column. One record per row.
    Column(ColumnRead),
    /// A list column, one record per element.
    ListElements(ColumnRead),
    /// A path into a JSON column, read as text.
    JsonPath {
        /// The JSON column.
        column: ColumnRead,
        /// Field names, outermost first.
        path: Vec<String>,
    },
    /// A fixed value, carried by the description rather than read from the row.
    Literal(String),
}

impl ValueSource {
    /// Read a scalar column named as the caller already resolved it.
    #[must_use]
    pub fn column(name: impl Into<String>) -> Self {
        Self::Column(ColumnRead::text(name))
    }

    #[must_use]
    /// Read a scalar column with its schema type.
    pub fn typed_column(name: ColumnName, kind: ColumnKind) -> Self {
        Self::Column(ColumnRead::new(name, kind))
    }
}

/// A condition the row must satisfy for the records to exist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Guard {
    /// The column is not SQL NULL.
    NotNull(ColumnRead),
    /// The boolean column is true.
    IsTrue(ColumnRead),
    /// The column compares as stated against a literal constant.
    Compare {
        /// The column being tested.
        column: ColumnRead,
        /// The predicate to apply.
        predicate: AttributePredicate,
    },
}

impl Guard {
    #[must_use]
    /// Require that a column is not SQL NULL.
    pub fn not_null(column: ColumnRead) -> Self {
        Self::NotNull(column)
    }

    #[must_use]
    /// Require that a boolean column is true.
    pub fn is_true(column: ColumnRead) -> Self {
        Self::IsTrue(column)
    }
}

/// How an object's name is built from a row.
///
/// Each part is encoded before the parts are joined, so `(1, "a|b")` and
/// `("1|a", "b")` cannot render alike. A single column key is a list of one.
/// Ask this for the name rather than assembling one: the whole-table SQL builds
/// the same string, and two spellings of it drift silently.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectKey {
    parts: Vec<ValueSource>,
}

impl ObjectKey {
    /// A key built from `parts`, in order.
    #[must_use]
    pub fn new(parts: Vec<ValueSource>) -> Self {
        Self { parts }
    }

    /// A key naming the row through one column, taken as the caller already resolved it.
    #[must_use]
    pub fn column(name: impl Into<String>) -> Self {
        Self::new(vec![ValueSource::column(name)])
    }

    /// The parts, so a caller can settle up front whether it reads the shape.
    #[must_use]
    pub fn parts(&self) -> &[ValueSource] {
        &self.parts
    }

    /// The name this row gives the object, `None` where the row does not say.
    ///
    /// # Errors
    ///
    /// [`RecordError::RowCannotBeNamed`] when the encoded name is longer than
    /// the target accepts. Shortening it would merge two rows into one object,
    /// so this refuses instead.
    pub(crate) fn render<R: RowValues + ?Sized>(
        &self,
        object_type: &str,
        row: &R,
    ) -> Result<Option<String>, RecordError> {
        match self.evaluate(object_type, row) {
            Eval::Value(name) => Ok(Some(name)),
            Eval::Empty => Ok(None),
            Eval::Refuse(error) => Err(error),
        }
    }

    fn evaluate<R: RowValues + ?Sized>(&self, object_type: &str, row: &R) -> Eval<String> {
        let mut values = Vec::with_capacity(self.parts.len());
        for part in &self.parts {
            match single_value(part, row) {
                Eval::Value(RowCell::Null) | Eval::Empty => return Eval::Empty,
                Eval::Value(cell) => {
                    let Some(value) = render_sql_text(&cell) else {
                        return Eval::Refuse(render_source_failure(part, &cell));
                    };
                    values.push(value);
                }
                Eval::Refuse(error) => return Eval::Refuse(error),
            }
        }
        let name = format!(
            "{object_type}:{}",
            encode_identity(values.iter().map(String::as_str))
        );
        match fit_object_name(name) {
            Ok(name) => Eval::Value(name),
            Err(error) => Eval::Refuse(error),
        }
    }
}

/// How a subject's name is built from a row.
///
/// One part, which may expand into several subjects when it is a list column.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectKey {
    part: ValueSource,
    /// Further parts when the subject is a composite-key object, joined the way an
    /// object key is. Empty for the ordinary single-column or wildcard subject.
    rest: Vec<ValueSource>,
    /// The typed wildcard, which is the crate's own spelling for "every user"
    /// rather than a value read out of a row.
    ///
    /// A row value of `*` still encodes, so only this spelling is exempt. Without
    /// the distinction the evaluator escapes the wildcard into an ordinary name
    /// and the grant reaches nobody, where the tuple SQL still writes `user:*`.
    wildcard: bool,
}

impl SubjectKey {
    /// A key reading `part`.
    #[must_use]
    pub fn new(part: ValueSource) -> Self {
        Self {
            part,
            rest: Vec::new(),
            wildcard: false,
        }
    }

    /// A key naming the subject through several columns, encoded together the way a
    /// composite [`ObjectKey`] is, so the subject names one object rather than a list of
    /// users. Takes the first column and the rest apart, so an empty key is unspellable.
    #[must_use]
    pub fn composite(first: &ColumnName, rest: &[ColumnName]) -> Self {
        Self {
            part: ValueSource::Column(ColumnRead::text(first.as_str())),
            rest: rest
                .iter()
                .map(|column| ValueSource::Column(ColumnRead::text(column.as_str())))
                .collect(),
            wildcard: false,
        }
    }

    #[must_use]
    /// A subject key from already typed sources.
    pub fn composite_sources(first: ValueSource, rest: Vec<ValueSource>) -> Self {
        Self {
            part: first,
            rest,
            wildcard: false,
        }
    }

    /// A key naming the subject through one column, taken as resolved, exactly as
    /// [`ObjectKey::column`] does.
    #[must_use]
    pub fn column(name: impl Into<String>) -> Self {
        Self::new(ValueSource::column(name))
    }

    /// The typed wildcard: every subject of the type, granted by the rule itself
    /// rather than named by the row.
    #[must_use]
    pub fn wildcard() -> Self {
        Self {
            part: ValueSource::Literal(WILDCARD_SUBJECT_ID.to_string()),
            rest: Vec::new(),
            wildcard: true,
        }
    }

    /// Where the value comes from, so a caller can settle whether it reads it.
    #[must_use]
    pub const fn part(&self) -> &ValueSource {
        &self.part
    }

    /// Every subject this row names, which is at most one except for a list.
    ///
    /// # Errors
    ///
    /// [`RecordError::RowCannotBeNamed`] when an encoded name is longer than the
    /// target accepts.
    pub fn render<R: RowValues + ?Sized>(
        &self,
        subject_type: &str,
        row: &R,
    ) -> Result<Vec<String>, RecordError> {
        match self.evaluate(subject_type, row) {
            Eval::Value(subjects) => Ok(subjects),
            Eval::Empty => Ok(Vec::new()),
            Eval::Refuse(error) => Err(error),
        }
    }

    fn evaluate<R: RowValues + ?Sized>(&self, subject_type: &str, row: &R) -> Eval<Vec<String>> {
        if self.wildcard {
            return Eval::Value(vec![format!("{subject_type}:{WILDCARD_SUBJECT_ID}")]);
        }
        if !self.rest.is_empty() {
            let mut values = Vec::with_capacity(1 + self.rest.len());
            for source in core::iter::once(&self.part).chain(&self.rest) {
                match single_value(source, row) {
                    Eval::Value(RowCell::Null) | Eval::Empty => return Eval::Empty,
                    Eval::Value(cell) => {
                        let Some(value) = render_sql_text(&cell) else {
                            return Eval::Refuse(render_source_failure(source, &cell));
                        };
                        values.push(value);
                    }
                    Eval::Refuse(error) => return Eval::Refuse(error),
                }
            }
            let name = format!(
                "{subject_type}:{}",
                encode_identity(values.iter().map(String::as_str))
            );
            return match fit_subject_name(name) {
                Ok(name) => Eval::Value(vec![name]),
                Err(error) => Eval::Refuse(error),
            };
        }
        match expand(&self.part, row) {
            Eval::Value(values) => {
                let mut subjects = Vec::with_capacity(values.len());
                for value in values {
                    let name = format!("{subject_type}:{}", encode_part(&value));
                    match fit_subject_name(name) {
                        Ok(name) => subjects.push(name),
                        Err(error) => return Eval::Refuse(error),
                    }
                }
                Eval::Value(subjects)
            }
            Eval::Empty => Eval::Empty,
            Eval::Refuse(error) => Eval::Refuse(error),
        }
    }
}

impl From<ValueSource> for ObjectKey {
    fn from(part: ValueSource) -> Self {
        Self::new(vec![part])
    }
}

impl From<ValueSource> for SubjectKey {
    fn from(part: ValueSource) -> Self {
        Self::new(part)
    }
}

/// How the object, relation and subject of a record compose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordTemplate {
    /// `OpenFGA` type the object belongs to.
    pub object_type: String,
    /// How the object's name is built.
    pub object_key: ObjectKey,
    /// Relation name, always fixed.
    pub relation: RelationName,
    /// `OpenFGA` type the subject belongs to.
    pub subject_type: String,
    /// How the subject's name is built.
    pub subject_key: SubjectKey,
    /// The condition context the record carries, absent for an unconditional one.
    ///
    /// A conditional record grants nobody on its own: the service completes the
    /// comparison with what the request supplies, so a reader that ignores this and
    /// takes the subject at face value grants everyone.
    pub context: Option<RecordContext>,
}

/// How a record's condition context is built from a row: the condition it names and
/// each parameter the row fills.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordContext {
    /// Condition the tuple names, declared by the model.
    pub condition: String,
    /// Each parameter the row fills, in the order the emitter recorded them.
    pub entries: Vec<RecordContextEntry>,
}

/// One parameter a record's condition context fills, and where its value comes from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordContextEntry {
    /// Condition parameter the value fills.
    pub key: String,
    /// Where the value comes from.
    pub value: ValueSource,
    /// How the tuple SQL spells this value inside `jsonb_build_object`.
    pub rendering: ContextRendering,
}

/// A query bound by the columns keying the slice it determines, for a shape whose
/// records no single row decides.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundQuery {
    /// Table the change arrived on.
    pub table: String,
    /// Columns the query binds, in the order its placeholders take them.
    ///
    /// All of the columns naming the slice, since a query bound to a prefix of a
    /// compound key answers for every row sharing that prefix, which is a different
    /// question.
    pub key_columns: Vec<ColumnName>,
    /// SQL taking the key values as `$1` through `$n`, in `key_columns` order.
    pub sql: String,
    /// Condition the rows carry, when the query yields the two extra columns a
    /// conditional tuple needs. `None` means three columns and no condition, so a
    /// caller replaying one row knows the shape without parsing the SQL.
    pub condition: Option<String>,
    /// Which stored facts this query's result fully determines. A fact in the
    /// slice the result no longer returns is stale, which is what lets a
    /// consumer take a withdrawn grant out of its store.
    pub scope: ReplayScope,
}

/// The slice of stored facts one bound query's result fully determines.
///
/// The result is the whole truth for the slice as this shape states it, so
/// what the result stopped returning is stale. Which slice that is belongs to
/// the query, since nothing downstream can rediscover it from the SQL: one
/// query is keyed on the object it moves, another on the subject it grants
/// to, and the two reconcile against different reads.
///
/// Whole only as **this shape** states it: a consumer reconciling the slice
/// must first establish that no other shape states facts in the same slice,
/// or the reconciliation deletes the other shape's facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplayScope {
    /// Every fact `relations` state about the one object the bound key names.
    Object {
        /// Type the object belongs to.
        object_type: String,
        /// The relations this query's rows can carry.
        relations: Vec<RelationName>,
    },
    /// Every fact `relation` grants on `object_type` rows to the one subject
    /// the bound key names.
    Subject {
        /// Type the subject belongs to.
        subject_type: String,
        /// Relation the facts grant through.
        relation: RelationName,
        /// Type of the objects the facts are about.
        object_type: String,
    },
}

impl ReplayScope {
    /// The name the bound key's values give the object or subject the slice
    /// is keyed on, spelled the way every other name is spelled. `values` are
    /// the replayed key values as text, one per
    /// [`BoundQuery::key_columns`](BoundQuery::key_columns) and in that
    /// order, rendered as the database renders them in a cast to text.
    ///
    /// # Errors
    ///
    /// [`RecordError::RowCannotBeNamed`] when the encoded name is longer than
    /// the target accepts, exactly as rendering the same values off a row
    /// refuses, and [`RecordError::SubjectKeyNotSingular`] when a subject
    /// slice is handed anything but its one key value.
    pub fn rendered_key(&self, values: &[&str]) -> Result<String, RecordError> {
        match self {
            Self::Object { object_type, .. } => fit_object_name(format!(
                "{object_type}:{}",
                encode_identity(values.iter().copied())
            )),
            Self::Subject { subject_type, .. } => {
                let [value] = values else {
                    return Err(RecordError::SubjectKeyNotSingular(values.len()));
                };
                fit_subject_name(format!("{subject_type}:{}", encode_part(value)))
            }
        }
    }
}

/// `name` when the target accepts it as an object, refusing with its length in
/// characters, the unit the object cap is measured in.
fn fit_object_name(name: String) -> Result<String, RecordError> {
    if object_name_fits(&name) {
        Ok(name)
    } else {
        Err(RecordError::RowCannotBeNamed(name.chars().count()))
    }
}

/// `name` when the target accepts it as a subject, refusing with its length in
/// bytes, the unit the subject cap is measured in.
fn fit_subject_name(name: String) -> Result<String, RecordError> {
    if subject_name_fits(&name) {
        Ok(name)
    } else {
        Err(RecordError::RowCannotBeNamed(name.len()))
    }
}

/// Whether a description's records follow from one row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// The records follow from the translation alone: no row and no table decides
    /// them, so nothing evaluates and no row event can withdraw them. The load writes
    /// them once, and a consumer reconciling what a changed row implies never sees
    /// them, since [`RecordDescription::tables`] is empty.
    Constant {
        /// The fact itself. A constant needs no key to render, so this is the record
        /// rather than a recipe for one.
        record: Record,
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
            RecordDerivation::Constant { .. } | RecordDerivation::Joined { .. } => None,
        }
    }
}

/// One row's column values, as seen by [`records_from_row`].
pub trait RowValues {
    /// Read one scalar cell.
    fn cell(&self, column: &str, kind: ColumnKind) -> RowCell<'_>;

    /// Read one list cell.
    fn list(&self, column: &str, kind: ColumnKind) -> RowList<'_>;

    /// Read a JSON leaf as text.
    fn json_text(&self, column: &str, path: &[String]) -> RowCell<'_>;
}

/// Why a description's records could not be produced from a row.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecordError {
    /// The description reads more than the one row.
    NotDerivableFromOneRow(String),
    /// The row's values render a name longer than the target accepts.
    RowCannotBeNamed(usize),
    /// A subject slice is keyed on one column, and the replayed key carried this many values.
    SubjectKeyNotSingular(usize),
    /// The row image did not carry a column this record needs.
    ColumnAbsent(String),
    /// The row image carried a column value the consumer could not decode.
    ColumnUndecodable(String),
    /// The schema declares a type this row evaluator refuses to print.
    ColumnTypeUnsupported {
        /// The requested column.
        column: String,
        /// The unsupported type family.
        kind: ColumnKind,
    },
    /// The decoded cell kind does not match the schema.
    ColumnTypeMismatch {
        /// The requested column.
        column: String,
        /// The schema type family.
        expected: ColumnKind,
        /// The decoded type family.
        actual: ColumnKind,
    },
    /// The database needs state the row image does not carry to compare this column.
    ComparisonNeedsQuery(String),
}

impl core::fmt::Display for RecordError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotDerivableFromOneRow(reason) => write!(
                f,
                "records do not follow from one row and must be queried: {reason}"
            ),
            Self::RowCannotBeNamed(length) => write!(
                f,
                "the row renders an identifier of {length}, longer than the target accepts"
            ),
            Self::SubjectKeyNotSingular(count) => write!(
                f,
                "a subject slice is keyed on one column, and the replayed key carried {count}"
            ),
            Self::ColumnAbsent(column) => write!(f, "the row image did not carry {column}"),
            Self::ColumnUndecodable(column) => {
                write!(f, "the row image carried an undecodable value for {column}")
            }
            Self::ColumnTypeUnsupported { column, kind } => {
                write!(f, "the row column {column} has unsupported type {kind:?}")
            }
            Self::ColumnTypeMismatch {
                column,
                expected,
                actual,
            } => write!(
                f,
                "the row column {column} decoded as {actual:?}, not {expected:?}"
            ),
            Self::ComparisonNeedsQuery(column) => {
                write!(f, "the row comparison on {column} needs the database")
            }
        }
    }
}

impl core::error::Error for RecordError {}

enum Eval<T> {
    Value(T),
    Empty,
    Refuse(RecordError),
}

/// Produce the records one row implies.
pub fn records_from_row<R: RowValues + ?Sized>(
    description: &RecordDescription,
    row: &R,
) -> Result<Vec<Record>, RecordError> {
    let (template, guards) = match &description.derivation {
        RecordDerivation::FromRow {
            template, guards, ..
        } => (template, guards),
        RecordDerivation::Joined { reason, .. } => {
            return Err(RecordError::NotDerivableFromOneRow(reason.clone()))
        }
        RecordDerivation::Constant { .. } => {
            return Err(RecordError::NotDerivableFromOneRow(
                "the fact follows from the translation, so no row decides it".to_string(),
            ))
        }
    };

    let mut refusal = None;
    for guard in guards {
        match guard_holds(guard, row) {
            Eval::Value(()) => {}
            Eval::Empty => return Ok(Vec::new()),
            Eval::Refuse(error) => {
                if refusal.is_none() {
                    refusal = Some(error);
                }
            }
        }
    }

    let object = match template.object_key.evaluate(&template.object_type, row) {
        Eval::Value(object) => object,
        Eval::Empty => return Ok(Vec::new()),
        Eval::Refuse(error) => {
            if refusal.is_none() {
                refusal = Some(error);
            }
            String::new()
        }
    };

    let context = match &template.context {
        Some(context) => {
            let mut values = BTreeMap::new();
            for entry in &context.entries {
                match context_value(entry, row) {
                    Eval::Value(value) => {
                        values.insert(entry.key.clone(), value);
                    }
                    Eval::Empty => return Ok(Vec::new()),
                    Eval::Refuse(error) => {
                        if refusal.is_none() {
                            refusal = Some(error);
                        }
                    }
                }
            }
            Some(RecordContextValue {
                condition: context.condition.clone(),
                values,
            })
        }
        None => None,
    };

    let subjects = match template.subject_key.evaluate(&template.subject_type, row) {
        Eval::Value(subjects) => subjects,
        Eval::Empty => return Ok(Vec::new()),
        Eval::Refuse(error) => {
            if refusal.is_none() {
                refusal = Some(error);
            }
            Vec::new()
        }
    };

    if let Some(error) = refusal {
        return Err(error);
    }

    Ok(subjects
        .into_iter()
        .map(|subject| Record {
            object: object.clone(),
            relation: template.relation.clone(),
            subject,
            context: context.clone(),
        })
        .collect())
}

fn guard_holds<R: RowValues + ?Sized>(guard: &Guard, row: &R) -> Eval<()> {
    match guard {
        Guard::NotNull(column) => match checked_cell(row, column) {
            Eval::Value(RowCell::Null) | Eval::Empty => Eval::Empty,
            Eval::Value(_) => Eval::Value(()),
            Eval::Refuse(error) => Eval::Refuse(error),
        },
        Guard::IsTrue(column) => match checked_cell(row, column) {
            Eval::Value(RowCell::Bool(true)) => Eval::Value(()),
            Eval::Value(RowCell::Bool(false) | RowCell::Null) | Eval::Empty => Eval::Empty,
            Eval::Value(cell) => Eval::Refuse(type_mismatch(column, &cell)),
            Eval::Refuse(error) => Eval::Refuse(error),
        },
        Guard::Compare { column, predicate } => compare_holds(column, predicate, row),
    }
}

fn compare_holds<R: RowValues + ?Sized>(
    column: &ColumnRead,
    predicate: &AttributePredicate,
    row: &R,
) -> Eval<()> {
    let cell = match checked_cell(row, column) {
        Eval::Value(RowCell::Null) | Eval::Empty => return Eval::Empty,
        Eval::Value(cell) => cell,
        Eval::Refuse(error) => return Eval::Refuse(error),
    };
    let ordering = match (&cell, &predicate.value) {
        (RowCell::Bool(actual), AttributeLiteral::Boolean(expected)) => actual.cmp(expected),
        (
            RowCell::Integer(actual) | RowCell::Decimal(actual),
            AttributeLiteral::Number(expected),
        ) => {
            let Some(ordering) = compare_decimals(actual.as_ref(), expected) else {
                return Eval::Refuse(RecordError::ComparisonNeedsQuery(column.to_string()));
            };
            ordering
        }
        (RowCell::Text(actual), AttributeLiteral::Text(expected)) => {
            if !matches!(
                predicate.operator,
                AttributeOperator::Eq | AttributeOperator::NotEq
            ) {
                return Eval::Refuse(RecordError::ComparisonNeedsQuery(column.to_string()));
            }
            actual.as_ref().cmp(expected.as_str())
        }
        _ => return Eval::Refuse(RecordError::ComparisonNeedsQuery(column.to_string())),
    };

    if ordering_matches(predicate.operator, ordering) {
        Eval::Value(())
    } else {
        Eval::Empty
    }
}

fn ordering_matches(operator: AttributeOperator, ordering: core::cmp::Ordering) -> bool {
    match operator {
        AttributeOperator::Eq => ordering.is_eq(),
        AttributeOperator::NotEq => ordering.is_ne(),
        AttributeOperator::Gt => ordering.is_gt(),
        AttributeOperator::GtEq => ordering.is_ge(),
        AttributeOperator::Lt => ordering.is_lt(),
        AttributeOperator::LtEq => ordering.is_le(),
    }
}

fn context_value<R: RowValues + ?Sized>(entry: &RecordContextEntry, row: &R) -> Eval<String> {
    match single_value(&entry.value, row) {
        Eval::Value(RowCell::Null) | Eval::Empty => Eval::Empty,
        Eval::Value(cell) => render_context_cell(&cell, entry.rendering).map_or_else(
            || Eval::Refuse(render_source_failure(&entry.value, &cell)),
            Eval::Value,
        ),
        Eval::Refuse(error) => Eval::Refuse(error),
    }
}

fn single_value<'a, R: RowValues + ?Sized>(
    source: &'a ValueSource,
    row: &'a R,
) -> Eval<RowCell<'a>> {
    match source {
        ValueSource::Column(column) => checked_cell(row, column),
        ValueSource::JsonPath { column, path } => match row.json_text(column.as_str(), path) {
            RowCell::Absent => Eval::Refuse(RecordError::ColumnAbsent(column.to_string())),
            RowCell::Null => Eval::Empty,
            RowCell::Undecodable => {
                Eval::Refuse(RecordError::ColumnUndecodable(column.to_string()))
            }
            cell => Eval::Value(cell),
        },
        ValueSource::Literal(value) => Eval::Value(RowCell::Text(Cow::Borrowed(value.as_str()))),
        ValueSource::ListElements(_) => Eval::Empty,
    }
}

fn expand<R: RowValues + ?Sized>(source: &ValueSource, row: &R) -> Eval<Vec<String>> {
    match source {
        ValueSource::ListElements(column) => match row.list(column.as_str(), column.kind()) {
            RowList::Absent => Eval::Refuse(RecordError::ColumnAbsent(column.to_string())),
            RowList::Null => Eval::Empty,
            RowList::Undecodable => {
                Eval::Refuse(RecordError::ColumnUndecodable(column.to_string()))
            }
            RowList::Values(values) => {
                let mut out = Vec::new();
                for value in values {
                    match checked_list_cell(column, value) {
                        Eval::Value(RowCell::Null) | Eval::Empty => {}
                        Eval::Value(cell) => {
                            let Some(rendered) = render_sql_text(&cell) else {
                                return Eval::Refuse(render_cell_failure(column, &cell));
                            };
                            out.push(rendered);
                        }
                        Eval::Refuse(error) => return Eval::Refuse(error),
                    }
                }
                if out.is_empty() {
                    Eval::Empty
                } else {
                    Eval::Value(out)
                }
            }
        },
        other => match single_value(other, row) {
            Eval::Value(RowCell::Null) | Eval::Empty => Eval::Empty,
            Eval::Value(cell) => render_sql_text(&cell).map_or_else(
                || Eval::Refuse(render_source_failure(other, &cell)),
                |value| Eval::Value(vec![value]),
            ),
            Eval::Refuse(error) => Eval::Refuse(error),
        },
    }
}

fn checked_cell<'a, R: RowValues + ?Sized>(row: &'a R, column: &ColumnRead) -> Eval<RowCell<'a>> {
    match column.kind() {
        ColumnKind::Unsupported | ColumnKind::Json => {
            return Eval::Refuse(RecordError::ColumnTypeUnsupported {
                column: column.to_string(),
                kind: column.kind(),
            })
        }
        _ => {}
    }
    checked_list_cell(column, row.cell(column.as_str(), column.kind()))
}

fn checked_list_cell<'a>(column: &ColumnRead, cell: RowCell<'a>) -> Eval<RowCell<'a>> {
    match cell {
        RowCell::Absent => Eval::Refuse(RecordError::ColumnAbsent(column.to_string())),
        RowCell::Null => Eval::Value(RowCell::Null),
        RowCell::Undecodable => Eval::Refuse(RecordError::ColumnUndecodable(column.to_string())),
        cell => {
            if cell_kind(&cell) == Some(column.kind()) {
                Eval::Value(cell)
            } else {
                Eval::Refuse(type_mismatch(column, &cell))
            }
        }
    }
}

fn cell_kind(cell: &RowCell<'_>) -> Option<ColumnKind> {
    match cell {
        RowCell::Text(_) => Some(ColumnKind::Text),
        RowCell::Uuid(_) => Some(ColumnKind::Uuid),
        RowCell::Bool(_) => Some(ColumnKind::Bool),
        RowCell::Integer(_) => Some(ColumnKind::Integer),
        RowCell::Decimal(_) => Some(ColumnKind::Decimal),
        RowCell::Date(_) => Some(ColumnKind::Date),
        RowCell::Time(_) => Some(ColumnKind::Time),
        RowCell::Timestamp(_) => Some(ColumnKind::Timestamp),
        RowCell::TimestampTz(_) => Some(ColumnKind::TimestampTz),
        RowCell::Bytea(_) => Some(ColumnKind::Bytea),
        RowCell::Absent | RowCell::Null | RowCell::Undecodable => None,
    }
}

fn type_mismatch(column: &ColumnRead, cell: &RowCell<'_>) -> RecordError {
    RecordError::ColumnTypeMismatch {
        column: column.to_string(),
        expected: column.kind(),
        actual: cell_kind(cell).unwrap_or(ColumnKind::Unsupported),
    }
}

fn render_cell_failure(column: &ColumnRead, cell: &RowCell<'_>) -> RecordError {
    if matches!(cell, RowCell::TimestampTz(_)) {
        RecordError::ColumnUndecodable(column.to_string())
    } else {
        type_mismatch(column, cell)
    }
}

fn render_source_failure(source: &ValueSource, cell: &RowCell<'_>) -> RecordError {
    match source {
        ValueSource::Column(column)
        | ValueSource::ListElements(column)
        | ValueSource::JsonPath { column, .. }
            if matches!(cell, RowCell::TimestampTz(_)) =>
        {
            RecordError::ColumnUndecodable(column.to_string())
        }
        _ => type_mismatch_source(source, cell),
    }
}

fn type_mismatch_source(source: &ValueSource, cell: &RowCell<'_>) -> RecordError {
    match source {
        ValueSource::Column(column) | ValueSource::ListElements(column) => {
            type_mismatch(column, cell)
        }
        ValueSource::JsonPath { column, .. } => type_mismatch(column, cell),
        ValueSource::Literal(_) => RecordError::ColumnTypeMismatch {
            column: "literal".to_string(),
            expected: ColumnKind::Text,
            actual: cell_kind(cell).unwrap_or(ColumnKind::Unsupported),
        },
    }
}

fn render_sql_text(cell: &RowCell<'_>) -> Option<String> {
    match cell {
        RowCell::Absent | RowCell::Null | RowCell::Undecodable => None,
        RowCell::Text(value)
        | RowCell::Uuid(value)
        | RowCell::Integer(value)
        | RowCell::Decimal(value)
        | RowCell::Date(value)
        | RowCell::Time(value) => Some(value.to_string()),
        RowCell::Bool(flag) => Some(if *flag { "true" } else { "false" }.to_string()),
        RowCell::Timestamp(value) => Some(timestamp_sql_text(value.as_ref())),
        RowCell::TimestampTz(value) => timestamptz_sql_text(value.as_ref()),
        RowCell::Bytea(bytes) => Some(bytea_sql_text(bytes.as_ref())),
    }
}

fn render_context_cell(cell: &RowCell<'_>, rendering: ContextRendering) -> Option<String> {
    match rendering {
        ContextRendering::SqlText => render_sql_text(cell),
        ContextRendering::Json => render_json_text(cell),
    }
}

fn render_json_text(cell: &RowCell<'_>) -> Option<String> {
    match cell {
        RowCell::Absent | RowCell::Null | RowCell::Undecodable => None,
        RowCell::Text(value)
        | RowCell::Uuid(value)
        | RowCell::Integer(value)
        | RowCell::Decimal(value)
        | RowCell::Date(value)
        | RowCell::Time(value) => Some(value.to_string()),
        RowCell::Bool(flag) => Some(if *flag { "true" } else { "false" }.to_string()),
        RowCell::Timestamp(value) => Some(timestamp_json_text(value.as_ref())),
        RowCell::TimestampTz(value) => timestamptz_json_text(value.as_ref()),
        RowCell::Bytea(bytes) => Some(bytea_sql_text(bytes.as_ref())),
    }
}

fn timestamp_sql_text(value: &str) -> String {
    value.replace('T', " ")
}

fn timestamp_json_text(value: &str) -> String {
    value.replacen(' ', "T", 1)
}

fn utc_timestamptz_base(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    for suffix in ["+00:00", "-00:00", "+00", "-00", "Z"] {
        if let Some(base) = trimmed.strip_suffix(suffix) {
            return Some(base);
        }
    }
    None
}

fn timestamptz_sql_text(value: &str) -> Option<String> {
    let base = utc_timestamptz_base(value)?;
    let mut text = timestamp_sql_text(base);
    text.push_str("+00");
    Some(text)
}

fn timestamptz_json_text(value: &str) -> Option<String> {
    let base = utc_timestamptz_base(value)?;
    let mut text = timestamp_json_text(base);
    text.push_str("+00:00");
    Some(text)
}

fn bytea_sql_text(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("\\x");
    for byte in bytes {
        out.push(hex_digit(byte >> 4));
        out.push(hex_digit(byte & 0x0f));
    }
    out
}

fn hex_digit(nibble: u8) -> char {
    match nibble {
        0..=9 => char::from(b'0' + nibble),
        10..=15 => char::from(b'a' + (nibble - 10)),
        _ => char::from(b'0'),
    }
}

fn compare_decimals(left: &str, right: &str) -> Option<core::cmp::Ordering> {
    let (left_negative, mut left_digits, left_scale) = parse_decimal(left)?;
    let (right_negative, mut right_digits, right_scale) = parse_decimal(right)?;
    if left_negative != right_negative {
        return Some(if left_negative {
            core::cmp::Ordering::Less
        } else {
            core::cmp::Ordering::Greater
        });
    }
    let scale = left_scale.max(right_scale);
    left_digits.extend(core::iter::repeat_n('0', scale - left_scale));
    right_digits.extend(core::iter::repeat_n('0', scale - right_scale));
    trim_leading_zeroes(&mut left_digits);
    trim_leading_zeroes(&mut right_digits);
    let ordering = left_digits
        .len()
        .cmp(&right_digits.len())
        .then_with(|| left_digits.cmp(&right_digits));
    Some(if left_negative {
        ordering.reverse()
    } else {
        ordering
    })
}

fn parse_decimal(input: &str) -> Option<(bool, String, usize)> {
    let trimmed = input.trim();
    if trimmed.is_empty() || trimmed.contains(['e', 'E']) {
        return None;
    }
    let (negative, unsigned) = if let Some(rest) = trimmed.strip_prefix('-') {
        (true, rest)
    } else if let Some(rest) = trimmed.strip_prefix('+') {
        (false, rest)
    } else {
        (false, trimmed)
    };
    let mut parts = unsigned.split('.');
    let whole = parts.next()?;
    let fraction = parts.next().unwrap_or("");
    if parts.next().is_some() || whole.is_empty() && fraction.is_empty() {
        return None;
    }
    if !whole
        .bytes()
        .chain(fraction.bytes())
        .all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let mut digits = String::with_capacity(whole.len() + fraction.len());
    digits.push_str(whole);
    digits.push_str(fraction);
    let mut scale = fraction.len();
    while scale > 0 && digits.ends_with('0') {
        digits.pop();
        scale -= 1;
    }
    trim_leading_zeroes(&mut digits);
    if digits == "0" {
        Some((false, digits, 0))
    } else {
        Some((negative, digits, scale))
    }
}

fn trim_leading_zeroes(digits: &mut String) {
    let first_non_zero = digits
        .bytes()
        .position(|byte| byte != b'0')
        .unwrap_or(digits.len());
    if first_non_zero == digits.len() {
        digits.clear();
        digits.push('0');
    } else if first_non_zero > 0 {
        digits.drain(..first_non_zero);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generator::well_known::member_relation;
    use alloc::collections::BTreeMap;

    struct Row(BTreeMap<String, String>);

    impl Row {
        fn of(pairs: &[(&str, &str)]) -> Self {
            Self(
                pairs
                    .iter()
                    .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                    .collect(),
            )
        }
    }

    impl RowValues for Row {
        fn cell(&self, column: &str, kind: ColumnKind) -> RowCell<'_> {
            match self.0.get(column) {
                Some(value) if kind == ColumnKind::Text => RowCell::Text(Cow::Borrowed(value)),
                Some(_) => RowCell::Undecodable,
                None => RowCell::Absent,
            }
        }

        fn list(&self, _column: &str, _kind: ColumnKind) -> RowList<'_> {
            RowList::Absent
        }

        fn json_text(&self, _column: &str, _path: &[String]) -> RowCell<'_> {
            RowCell::Absent
        }
    }

    struct TimestampTzRow(&'static str);

    impl RowValues for TimestampTzRow {
        fn cell(&self, column: &str, kind: ColumnKind) -> RowCell<'_> {
            if column == "observed_at" && kind == ColumnKind::TimestampTz {
                RowCell::TimestampTz(Cow::Borrowed(self.0))
            } else {
                RowCell::Absent
            }
        }

        fn list(&self, _column: &str, _kind: ColumnKind) -> RowList<'_> {
            RowList::Absent
        }

        fn json_text(&self, _column: &str, _path: &[String]) -> RowCell<'_> {
            RowCell::Absent
        }
    }

    #[test]
    fn an_object_name_joins_every_key_part_encoded() {
        let key = ObjectKey::new(vec![
            ValueSource::column("paper_id"),
            ValueSource::column("viewer"),
        ]);
        let row = Row::of(&[("paper_id", "1"), ("viewer", "a|b")]);
        assert_eq!(
            key.render("paper_shares", &row).unwrap(),
            Some("paper_shares:1|~617c62".to_string())
        );
    }

    #[test]
    fn a_missing_key_part_yields_no_record_rather_than_a_short_name() {
        let key = ObjectKey::new(vec![
            ValueSource::column("paper_id"),
            ValueSource::column("viewer"),
        ]);
        let row = Row::of(&[("paper_id", "1")]);
        assert_eq!(
            key.render("paper_shares", &row),
            Err(RecordError::ColumnAbsent("viewer".to_string()))
        );
    }

    #[test]
    fn a_non_utc_timestamptz_key_is_refused() {
        let key = ObjectKey::new(vec![ValueSource::typed_column(
            ColumnName::from_stored("observed_at"),
            ColumnKind::TimestampTz,
        )]);
        let row = TimestampTzRow("2026-01-01T01:00:00+01:00");

        assert_eq!(
            key.render("readings", &row),
            Err(RecordError::ColumnUndecodable("observed_at".to_string()))
        );
    }

    fn share_description_with_two_context_parameters() -> RecordDescription {
        RecordDescription {
            tables: vec!["paper_shares".to_string()],
            derivation: RecordDerivation::FromRow {
                table: "paper_shares".to_string(),
                template: Box::new(RecordTemplate {
                    object_type: "papers".to_string(),
                    object_key: ObjectKey::column("paper_id"),
                    relation: member_relation(),
                    subject_type: "user".to_string(),
                    subject_key: SubjectKey::wildcard(),
                    context: Some(RecordContext {
                        condition: "when_share".to_string(),
                        entries: vec![
                            RecordContextEntry {
                                key: "viewer".to_string(),
                                value: ValueSource::column("viewer"),
                                rendering: ContextRendering::SqlText,
                            },
                            RecordContextEntry {
                                key: "expires_at".to_string(),
                                value: ValueSource::column("expires_at"),
                                rendering: ContextRendering::SqlText,
                            },
                        ],
                    }),
                }),
                guards: vec![
                    Guard::NotNull(ColumnRead::text("viewer")),
                    Guard::NotNull(ColumnRead::text("expires_at")),
                ],
            },
        }
    }

    #[test]
    fn a_record_context_carries_every_parameter_the_row_fills() {
        let description = share_description_with_two_context_parameters();
        let row = Row::of(&[
            ("paper_id", "1"),
            ("viewer", "team-a"),
            ("expires_at", "2099-01-01T00:00:00Z"),
        ]);
        let records = records_from_row(&description, &row).expect("the row evaluates");
        let [record] = records.as_slice() else {
            panic!("one record, got {records:?}");
        };
        let context = record
            .context
            .as_ref()
            .expect("a conditional record carries its context");
        assert_eq!(context.condition, "when_share");
        assert_eq!(
            context.values.get("viewer").map(String::as_str),
            Some("team-a")
        );
        assert_eq!(
            context.values.get("expires_at").map(String::as_str),
            Some("2099-01-01T00:00:00Z"),
            "both row parameters travel, not just the first"
        );
    }

    #[test]
    fn a_record_context_missing_one_parameter_is_refused() {
        let description = share_description_with_two_context_parameters();
        let row = Row::of(&[("paper_id", "1"), ("viewer", "team-a")]);
        assert_eq!(
            records_from_row(&description, &row),
            Err(RecordError::ColumnAbsent("expires_at".to_string())),
            "a missing context parameter would load a mismatched condition"
        );
    }

    #[test]
    fn an_object_name_past_the_cap_is_refused_rather_than_shortened() {
        // Shortening would give two rows one name, and each the other's access.
        let key = ObjectKey::column("id");
        let row = Row::of(&[("id", &"a".repeat(300))]);
        assert_eq!(
            key.render("docs", &row),
            Err(RecordError::RowCannotBeNamed(305))
        );
    }

    #[test]
    fn the_object_budget_shrinks_as_the_type_name_grows() {
        // The cap covers the whole `type:id` string, so the same value fits one
        // type and not another.
        let key = ObjectKey::column("id");
        let row = Row::of(&[("id", &"a".repeat(250))]);
        assert!(key.render("d", &row).unwrap().is_some());
        assert!(key.render("a_much_longer_type_name", &row).is_err());
    }

    #[test]
    fn a_subject_name_is_encoded_and_capped_in_bytes() {
        let key = SubjectKey::column("owner");
        let row = Row::of(&[("owner", "alice smith")]);
        assert_eq!(
            key.render("user", &row).unwrap(),
            vec!["user:~616c69636520736d697468".to_string()]
        );

        // Bytes, not characters: two-byte runes spend the budget twice as fast.
        let long = Row::of(&[("owner", &"e".repeat(600))]);
        assert!(matches!(
            key.render("user", &long),
            Err(RecordError::RowCannotBeNamed(_))
        ));
    }

    #[test]
    fn every_rendered_name_is_ascii_so_the_two_caps_cannot_disagree() {
        // The service caps an object in characters and a subject in bytes, and the crate
        // spells each guard in its own unit to match that contract. The difference is
        // inert rather than load bearing: the safe set is ASCII and the escape is hex, so
        // a rendered name is always ASCII and the two units coincide. Widening the safe
        // set to non-ASCII is what would make it live, and this is the test that notices.
        let awkward = Row::of(&[("id", "caf\u{e9} \u{1f600}"), ("owner", "\u{5317}\u{4eac}")]);
        let object = ObjectKey::column("id")
            .render("docs", &awkward)
            .unwrap()
            .expect("the row names its object");
        let subjects = SubjectKey::column("owner")
            .render("user", &awkward)
            .unwrap();

        assert!(object.is_ascii(), "object rendered non-ASCII: {object}");
        assert_eq!(object.len(), object.chars().count());
        for subject in &subjects {
            assert!(subject.is_ascii(), "subject rendered non-ASCII: {subject}");
            assert_eq!(subject.len(), subject.chars().count());
        }
    }

    #[test]
    fn the_two_caps_are_different_numbers() {
        // 300 characters fits a subject and not an object, which is the difference that
        // is live. Both numbers were measured against v1.11.6.
        let long = Row::of(&[("id", &"a".repeat(300)), ("owner", &"a".repeat(300))]);
        assert!(
            ObjectKey::column("id").render("docs", &long).is_err(),
            "an object is capped at 256 including its type"
        );
        assert!(
            SubjectKey::column("owner").render("user", &long).is_ok(),
            "a subject is capped at 512, so the same value fits"
        );
    }

    #[test]
    fn an_empty_value_still_names_its_row() {
        // `user:` is malformed to the target, so the encoding has to give the empty
        // string a spelling of its own rather than leave the name unspellable.
        let row = Row::of(&[("id", ""), ("owner", "")]);
        assert_eq!(
            ObjectKey::column("id").render("docs", &row).unwrap(),
            Some("docs:~".to_string())
        );
        assert_eq!(
            SubjectKey::column("owner").render("user", &row).unwrap(),
            vec!["user:~".to_string()]
        );
    }

    #[test]
    fn a_wildcard_looking_owner_does_not_become_the_wildcard() {
        // `user:*` grants every user, so a row whose owner is literally `*` would
        // hand the row to everyone. Verified against v1.11.6, which accepts the
        // write and answers allowed for an unrelated user.
        let row = Row::of(&[("owner", "*")]);
        assert_eq!(
            SubjectKey::column("owner").render("user", &row).unwrap(),
            vec!["user:~2a".to_string()]
        );
    }

    #[test]
    fn an_object_slice_renders_its_key_as_a_row_would() {
        let scope = ReplayScope::Object {
            object_type: "readings".to_string(),
            relations: vec![member_relation()],
        };
        // Compound keys join with the same separator, and a value carrying the
        // separator escapes, so two keys cannot render alike.
        assert_eq!(scope.rendered_key(&["7", "9"]).unwrap(), "readings:7|9");
        assert_eq!(
            scope.rendered_key(&["a|b"]).unwrap(),
            "readings:~617c62",
            "a value carrying the separator escapes as a row value would"
        );
    }

    #[test]
    fn a_subject_slice_renders_its_one_key_value() {
        let scope = ReplayScope::Subject {
            subject_type: "user".to_string(),
            relation: member_relation(),
            object_type: "docs".to_string(),
        };
        assert_eq!(scope.rendered_key(&["alice"]).unwrap(), "user:alice");
        assert_eq!(
            scope.rendered_key(&["*"]).unwrap(),
            "user:~2a",
            "a wildcard looking value does not become the wildcard"
        );
    }

    #[test]
    fn a_subject_slice_refuses_a_compound_key() {
        let scope = ReplayScope::Subject {
            subject_type: "user".to_string(),
            relation: member_relation(),
            object_type: "docs".to_string(),
        };
        assert_eq!(
            scope.rendered_key(&["a", "b"]),
            Err(RecordError::SubjectKeyNotSingular(2))
        );
    }

    #[test]
    fn an_oversize_slice_key_refuses_rather_than_shortening() {
        let long = "x".repeat(600);
        let scope = ReplayScope::Object {
            object_type: "docs".to_string(),
            relations: vec![member_relation()],
        };
        assert!(matches!(
            scope.rendered_key(&[long.as_str()]),
            Err(RecordError::RowCannotBeNamed(_))
        ));
    }

    #[derive(Default)]
    struct FullRow {
        cells: BTreeMap<String, RowCell<'static>>,
        lists: BTreeMap<String, RowList<'static>>,
        json: BTreeMap<String, RowCell<'static>>,
    }

    impl FullRow {
        fn with_cell(mut self, column: &str, cell: RowCell<'static>) -> Self {
            self.cells.insert(column.to_string(), cell);
            self
        }

        fn with_list(mut self, column: &str, list: RowList<'static>) -> Self {
            self.lists.insert(column.to_string(), list);
            self
        }

        fn with_json(mut self, column: &str, cell: RowCell<'static>) -> Self {
            self.json.insert(column.to_string(), cell);
            self
        }
    }

    impl RowValues for FullRow {
        fn cell(&self, column: &str, _kind: ColumnKind) -> RowCell<'_> {
            self.cells.get(column).cloned().unwrap_or(RowCell::Absent)
        }

        fn list(&self, column: &str, _kind: ColumnKind) -> RowList<'_> {
            self.lists.get(column).cloned().unwrap_or(RowList::Absent)
        }

        fn json_text(&self, column: &str, _path: &[String]) -> RowCell<'_> {
            self.json.get(column).cloned().unwrap_or(RowCell::Absent)
        }
    }

    fn read(column: &str, kind: ColumnKind) -> ColumnRead {
        ColumnRead::new(ColumnName::from_stored(column), kind)
    }

    fn predicate(
        column: &str,
        operator: AttributeOperator,
        value: AttributeLiteral,
    ) -> AttributePredicate {
        AttributePredicate {
            column: ColumnName::from_stored(column),
            operator,
            value,
        }
    }

    fn single_row_description(
        object_key: ObjectKey,
        subject_key: SubjectKey,
        guards: Vec<Guard>,
        context: Option<RecordContext>,
    ) -> RecordDescription {
        RecordDescription {
            tables: vec!["docs".to_string()],
            derivation: RecordDerivation::FromRow {
                table: "docs".to_string(),
                template: Box::new(RecordTemplate {
                    object_type: "docs".to_string(),
                    object_key,
                    relation: member_relation(),
                    subject_type: "user".to_string(),
                    subject_key,
                    context,
                }),
                guards,
            },
        }
    }

    #[test]
    fn column_reads_and_guard_builders_keep_their_kind() {
        let id = read("id", ColumnKind::Text);

        assert_eq!(id.column().as_str(), "id");
        assert_eq!(id.kind(), ColumnKind::Text);
        assert!(<ColumnRead as PartialEq<str>>::eq(&id, "id"));
        let literal: &str = "id";
        assert!(<ColumnRead as PartialEq<&str>>::eq(&id, &literal));
        assert_eq!(Guard::not_null(id.clone()), Guard::NotNull(id.clone()));
        assert_eq!(Guard::is_true(id.clone()), Guard::IsTrue(id));
        assert_eq!(ColumnKind::from_declared("inet"), ColumnKind::Unsupported);
        assert_eq!(
            ColumnKind::from_array_declared("text"),
            ColumnKind::Unsupported
        );
        assert_eq!(ColumnKind::from_array_declared("text[]"), ColumnKind::Text);
    }

    #[test]
    fn render_helpers_cover_supported_cells_and_refusals() {
        assert_eq!(render_sql_text(&RowCell::Absent), None);
        assert_eq!(render_sql_text(&RowCell::Null), None);
        assert_eq!(render_sql_text(&RowCell::Undecodable), None);
        assert_eq!(
            render_sql_text(&RowCell::Integer(Cow::Borrowed("7"))),
            Some("7".to_string())
        );
        assert_eq!(
            render_sql_text(&RowCell::Decimal(Cow::Borrowed("7.5"))),
            Some("7.5".to_string())
        );
        assert_eq!(
            render_sql_text(&RowCell::Bool(true)),
            Some("true".to_string())
        );
        assert_eq!(
            render_sql_text(&RowCell::Timestamp(Cow::Borrowed("2026-01-01T00:00:00"))),
            Some("2026-01-01 00:00:00".to_string())
        );
        assert_eq!(
            render_sql_text(&RowCell::TimestampTz(Cow::Borrowed("2026-01-01T00:00:00Z"))),
            Some("2026-01-01 00:00:00+00".to_string())
        );
        assert_eq!(
            render_context_cell(
                &RowCell::TimestampTz(Cow::Borrowed("2026-01-01 00:00:00+00")),
                ContextRendering::Json
            ),
            Some("2026-01-01T00:00:00+00:00".to_string())
        );
        assert_eq!(
            render_json_text(&RowCell::Bytea(Cow::Owned(vec![0, 15, 255]))),
            Some("\\x000fff".to_string())
        );
        assert_eq!(timestamptz_sql_text("2026-01-01T00:00:00+01:00"), None);
        assert_eq!(hex_digit(15), 'f');
        assert_eq!(hex_digit(16), '0');
    }

    #[test]
    fn decimal_comparison_covers_scale_sign_and_invalid_spelling() {
        assert_eq!(compare_decimals("-1", "0"), Some(core::cmp::Ordering::Less));
        assert_eq!(
            compare_decimals("1", "-1"),
            Some(core::cmp::Ordering::Greater)
        );
        assert_eq!(
            compare_decimals("+001.2300", "1.23"),
            Some(core::cmp::Ordering::Equal)
        );
        assert_eq!(
            compare_decimals("-2.0", "-1.5"),
            Some(core::cmp::Ordering::Less)
        );
        assert_eq!(compare_decimals("1e2", "100"), None);
        assert_eq!(compare_decimals(".", "0"), None);
        assert_eq!(compare_decimals("abc", "0"), None);
        assert_eq!(compare_decimals("1.2.3", "0"), None);
    }

    #[test]
    fn record_error_display_covers_new_refusals() {
        assert_eq!(
            RecordError::ColumnAbsent("id".to_string()).to_string(),
            "the row image did not carry id"
        );
        assert_eq!(
            RecordError::ColumnUndecodable("id".to_string()).to_string(),
            "the row image carried an undecodable value for id"
        );
        assert_eq!(
            RecordError::ColumnTypeUnsupported {
                column: "id".to_string(),
                kind: ColumnKind::Json,
            }
            .to_string(),
            "the row column id has unsupported type Json"
        );
        assert_eq!(
            RecordError::ColumnTypeMismatch {
                column: "id".to_string(),
                expected: ColumnKind::Text,
                actual: ColumnKind::Bool,
            }
            .to_string(),
            "the row column id decoded as Bool, not Text"
        );
        assert_eq!(
            RecordError::ComparisonNeedsQuery("id".to_string()).to_string(),
            "the row comparison on id needs the database"
        );
    }

    #[test]
    fn guards_cover_empty_match_and_refusal_paths() {
        let active = read("active", ColumnKind::Bool);
        let priority = read("priority", ColumnKind::Decimal);
        let status = read("status", ColumnKind::Text);

        let active_true = FullRow::default().with_cell("active", RowCell::Bool(true));
        assert!(matches!(
            guard_holds(&Guard::IsTrue(active.clone()), &active_true),
            Eval::Value(())
        ));

        let active_false = FullRow::default().with_cell("active", RowCell::Bool(false));
        assert!(matches!(
            guard_holds(&Guard::IsTrue(active.clone()), &active_false),
            Eval::Empty
        ));

        let active_null = FullRow::default().with_cell("active", RowCell::Null);
        assert!(matches!(
            guard_holds(&Guard::NotNull(active.clone()), &active_null),
            Eval::Empty
        ));
        assert!(matches!(
            guard_holds(&Guard::IsTrue(active.clone()), &active_null),
            Eval::Empty
        ));

        let active_text =
            FullRow::default().with_cell("active", RowCell::Text(Cow::Borrowed("true")));
        assert!(matches!(
            guard_holds(&Guard::IsTrue(active.clone()), &active_text),
            Eval::Refuse(RecordError::ColumnTypeMismatch { .. })
        ));

        let priority_row =
            FullRow::default().with_cell("priority", RowCell::Decimal(Cow::Borrowed("10.50")));
        assert!(matches!(
            guard_holds(
                &Guard::Compare {
                    column: priority.clone(),
                    predicate: predicate(
                        "priority",
                        AttributeOperator::GtEq,
                        AttributeLiteral::Number("10.5".to_string())
                    ),
                },
                &priority_row
            ),
            Eval::Value(())
        ));
        assert!(matches!(
            guard_holds(
                &Guard::Compare {
                    column: priority.clone(),
                    predicate: predicate(
                        "priority",
                        AttributeOperator::Gt,
                        AttributeLiteral::Number("9".to_string())
                    ),
                },
                &priority_row
            ),
            Eval::Value(())
        ));
        assert!(matches!(
            guard_holds(
                &Guard::Compare {
                    column: priority.clone(),
                    predicate: predicate(
                        "priority",
                        AttributeOperator::Lt,
                        AttributeLiteral::Number("10".to_string())
                    ),
                },
                &priority_row
            ),
            Eval::Empty
        ));
        assert!(matches!(
            guard_holds(
                &Guard::Compare {
                    column: priority.clone(),
                    predicate: predicate(
                        "priority",
                        AttributeOperator::Eq,
                        AttributeLiteral::Number("1e1".to_string())
                    ),
                },
                &priority_row
            ),
            Eval::Refuse(RecordError::ComparisonNeedsQuery(_))
        ));
        let integer_priority = read("priority_int", ColumnKind::Integer);
        let priority_integer =
            FullRow::default().with_cell("priority_int", RowCell::Integer(Cow::Borrowed("10")));
        assert!(matches!(
            guard_holds(
                &Guard::Compare {
                    column: integer_priority,
                    predicate: predicate(
                        "priority_int",
                        AttributeOperator::GtEq,
                        AttributeLiteral::Number("10".to_string())
                    ),
                },
                &priority_integer
            ),
            Eval::Value(())
        ));

        let status_row =
            FullRow::default().with_cell("status", RowCell::Text(Cow::Borrowed("published")));
        assert!(matches!(
            guard_holds(
                &Guard::Compare {
                    column: status.clone(),
                    predicate: predicate(
                        "status",
                        AttributeOperator::NotEq,
                        AttributeLiteral::Text("draft".to_string())
                    ),
                },
                &status_row
            ),
            Eval::Value(())
        ));
        assert!(matches!(
            guard_holds(
                &Guard::Compare {
                    column: status.clone(),
                    predicate: predicate(
                        "status",
                        AttributeOperator::Gt,
                        AttributeLiteral::Text("draft".to_string())
                    ),
                },
                &status_row
            ),
            Eval::Refuse(RecordError::ComparisonNeedsQuery(_))
        ));
        assert!(matches!(
            guard_holds(
                &Guard::Compare {
                    column: status,
                    predicate: predicate(
                        "status",
                        AttributeOperator::Eq,
                        AttributeLiteral::Boolean(true)
                    ),
                },
                &status_row
            ),
            Eval::Refuse(RecordError::ComparisonNeedsQuery(_))
        ));

        let text_flag = FullRow::default().with_cell("flag", RowCell::Text(Cow::Borrowed("yes")));
        assert!(matches!(
            guard_holds(&Guard::IsTrue(read("flag", ColumnKind::Text)), &text_flag),
            Eval::Refuse(RecordError::ColumnTypeMismatch { .. })
        ));

        let missing_priority = FullRow::default();
        assert!(matches!(
            guard_holds(
                &Guard::Compare {
                    column: priority.clone(),
                    predicate: predicate(
                        "priority",
                        AttributeOperator::Eq,
                        AttributeLiteral::Number("1".to_string())
                    ),
                },
                &missing_priority
            ),
            Eval::Refuse(RecordError::ColumnAbsent(_))
        ));

        let null_priority = FullRow::default().with_cell("priority", RowCell::Null);
        assert!(matches!(
            guard_holds(
                &Guard::Compare {
                    column: priority,
                    predicate: predicate(
                        "priority",
                        AttributeOperator::Eq,
                        AttributeLiteral::Number("1".to_string())
                    ),
                },
                &null_priority
            ),
            Eval::Empty
        ));

        let active_bool = FullRow::default().with_cell("active", RowCell::Bool(true));
        assert!(matches!(
            guard_holds(
                &Guard::Compare {
                    column: active,
                    predicate: predicate(
                        "active",
                        AttributeOperator::Eq,
                        AttributeLiteral::Boolean(true)
                    ),
                },
                &active_bool
            ),
            Eval::Value(())
        ));
    }

    #[test]
    fn record_evaluation_keeps_empty_records_ahead_of_refusals() {
        let description = single_row_description(
            ObjectKey::new(vec![ValueSource::typed_column(
                ColumnName::from_stored("id"),
                ColumnKind::Text,
            )]),
            SubjectKey::column("owner"),
            vec![Guard::not_null(read("gate", ColumnKind::Text))],
            Some(RecordContext {
                condition: "when_row_matches".to_string(),
                entries: vec![RecordContextEntry {
                    key: "ctx".to_string(),
                    value: ValueSource::typed_column(
                        ColumnName::from_stored("ctx"),
                        ColumnKind::Text,
                    ),
                    rendering: ContextRendering::SqlText,
                }],
            }),
        );

        let empty_by_guard = FullRow::default()
            .with_cell("id", RowCell::Text(Cow::Borrowed("d1")))
            .with_cell("owner", RowCell::Text(Cow::Borrowed("alice")))
            .with_cell("gate", RowCell::Null)
            .with_cell("ctx", RowCell::Text(Cow::Borrowed("v")));
        assert_eq!(
            records_from_row(&description, &empty_by_guard).unwrap(),
            Vec::new()
        );

        let empty_by_object = FullRow::default()
            .with_cell("id", RowCell::Null)
            .with_cell("owner", RowCell::Undecodable)
            .with_cell("gate", RowCell::Text(Cow::Borrowed("ok")))
            .with_cell("ctx", RowCell::Text(Cow::Borrowed("v")));
        assert_eq!(
            records_from_row(&description, &empty_by_object).unwrap(),
            Vec::new()
        );

        let empty_by_context = FullRow::default()
            .with_cell("id", RowCell::Text(Cow::Borrowed("d1")))
            .with_cell("owner", RowCell::Undecodable)
            .with_cell("gate", RowCell::Text(Cow::Borrowed("ok")))
            .with_cell("ctx", RowCell::Null);
        assert_eq!(
            records_from_row(&description, &empty_by_context).unwrap(),
            Vec::new()
        );

        let subject_refusal = FullRow::default()
            .with_cell("id", RowCell::Text(Cow::Borrowed("d1")))
            .with_cell("owner", RowCell::Undecodable)
            .with_cell("gate", RowCell::Text(Cow::Borrowed("ok")))
            .with_cell("ctx", RowCell::Text(Cow::Borrowed("v")));
        assert_eq!(
            records_from_row(&description, &subject_refusal),
            Err(RecordError::ColumnUndecodable("owner".to_string()))
        );

        let context_refusal = FullRow::default()
            .with_cell("id", RowCell::Text(Cow::Borrowed("d1")))
            .with_cell("owner", RowCell::Text(Cow::Borrowed("alice")))
            .with_cell("gate", RowCell::Text(Cow::Borrowed("ok")))
            .with_cell("ctx", RowCell::Undecodable);
        assert_eq!(
            records_from_row(&description, &context_refusal),
            Err(RecordError::ColumnUndecodable("ctx".to_string()))
        );
    }

    #[test]
    fn subject_keys_cover_composite_and_list_sources() {
        let composite = SubjectKey::composite(
            &ColumnName::from_stored("tenant_id"),
            &[ColumnName::from_stored("user_id")],
        );
        let row = FullRow::default()
            .with_cell("tenant_id", RowCell::Text(Cow::Borrowed("t1")))
            .with_cell("user_id", RowCell::Text(Cow::Borrowed("u|1")));
        assert_eq!(
            composite.render("account", &row).unwrap(),
            vec!["account:t1|~757c31".to_string()]
        );

        let null_composite = FullRow::default()
            .with_cell("tenant_id", RowCell::Text(Cow::Borrowed("t1")))
            .with_cell("user_id", RowCell::Null);
        assert_eq!(
            composite.render("account", &null_composite).unwrap(),
            Vec::<String>::new()
        );

        let long_composite = FullRow::default()
            .with_cell("tenant_id", RowCell::Text(Cow::Borrowed("t1")))
            .with_cell("user_id", RowCell::Text(Cow::Owned("x".repeat(600))));
        assert!(matches!(
            composite.render("account", &long_composite),
            Err(RecordError::RowCannotBeNamed(_))
        ));

        let list_subject =
            SubjectKey::new(ValueSource::ListElements(read("editors", ColumnKind::Text)));
        let list_row = FullRow::default().with_list(
            "editors",
            RowList::Values(vec![
                RowCell::Text(Cow::Borrowed("alice")),
                RowCell::Null,
                RowCell::Text(Cow::Borrowed("bob smith")),
            ]),
        );
        assert_eq!(
            list_subject.render("user", &list_row).unwrap(),
            vec![
                "user:alice".to_string(),
                "user:~626f6220736d697468".to_string()
            ]
        );

        let empty_list = FullRow::default().with_list(
            "editors",
            RowList::Values(vec![RowCell::Null, RowCell::Null]),
        );
        assert_eq!(
            list_subject.render("user", &empty_list).unwrap(),
            Vec::<String>::new()
        );

        let null_list = FullRow::default().with_list("editors", RowList::Null);
        assert_eq!(
            list_subject.render("user", &null_list).unwrap(),
            Vec::<String>::new()
        );

        let undecodable_list = FullRow::default().with_list("editors", RowList::Undecodable);
        assert_eq!(
            list_subject.render("user", &undecodable_list),
            Err(RecordError::ColumnUndecodable("editors".to_string()))
        );

        let absent_list = FullRow::default();
        assert_eq!(
            list_subject.render("user", &absent_list),
            Err(RecordError::ColumnAbsent("editors".to_string()))
        );

        let mismatched_list = FullRow::default().with_list(
            "editors",
            RowList::Values(vec![RowCell::Integer(Cow::Borrowed("1"))]),
        );
        assert!(matches!(
            list_subject.render("user", &mismatched_list),
            Err(RecordError::ColumnTypeMismatch { .. })
        ));

        let zoned_list = SubjectKey::new(ValueSource::ListElements(read(
            "instants",
            ColumnKind::TimestampTz,
        )));
        let bad_zone = FullRow::default().with_list(
            "instants",
            RowList::Values(vec![RowCell::TimestampTz(Cow::Borrowed(
                "2026-01-01T01:00:00+01:00",
            ))]),
        );
        assert_eq!(
            zoned_list.render("instant", &bad_zone),
            Err(RecordError::ColumnUndecodable("instants".to_string()))
        );
    }

    #[test]
    fn json_path_sources_keep_absent_null_and_decode_failures_distinct() {
        let json_source = ValueSource::JsonPath {
            column: read("meta", ColumnKind::Json),
            path: vec!["owner".to_string()],
        };
        let object_key = ObjectKey::new(vec![json_source.clone()]);

        let absent = FullRow::default();
        assert_eq!(
            object_key.render("docs", &absent),
            Err(RecordError::ColumnAbsent("meta".to_string()))
        );

        let null = FullRow::default().with_json("meta", RowCell::Null);
        assert_eq!(object_key.render("docs", &null).unwrap(), None);

        let undecodable = FullRow::default().with_json("meta", RowCell::Undecodable);
        assert_eq!(
            object_key.render("docs", &undecodable),
            Err(RecordError::ColumnUndecodable("meta".to_string()))
        );

        let owner = FullRow::default().with_json("meta", RowCell::Text(Cow::Borrowed("alice")));
        assert_eq!(
            object_key.render("docs", &owner).unwrap(),
            Some("docs:alice".to_string())
        );

        let bad_zone = FullRow::default().with_json(
            "meta",
            RowCell::TimestampTz(Cow::Borrowed("2026-01-01T01:00:00+01:00")),
        );
        assert_eq!(
            object_key.render("docs", &bad_zone),
            Err(RecordError::ColumnUndecodable("meta".to_string()))
        );
    }

    #[test]
    fn typed_cell_checks_cover_unsupported_and_mismatched_kinds() {
        let json_column = read("meta", ColumnKind::Json);
        let unsupported_column = read("id", ColumnKind::Unsupported);
        let text_column = read("id", ColumnKind::Text);

        let row = FullRow::default().with_cell("id", RowCell::Bool(true));
        assert!(matches!(
            checked_cell(&row, &json_column),
            Eval::Refuse(RecordError::ColumnTypeUnsupported { .. })
        ));
        assert!(matches!(
            checked_cell(&row, &unsupported_column),
            Eval::Refuse(RecordError::ColumnTypeUnsupported { .. })
        ));
        assert!(matches!(
            checked_cell(&row, &text_column),
            Eval::Refuse(RecordError::ColumnTypeMismatch { .. })
        ));

        assert_eq!(
            cell_kind(&RowCell::Uuid(Cow::Borrowed("u"))),
            Some(ColumnKind::Uuid)
        );
        assert_eq!(
            cell_kind(&RowCell::Decimal(Cow::Borrowed("1.2"))),
            Some(ColumnKind::Decimal)
        );
        assert_eq!(
            cell_kind(&RowCell::Time(Cow::Borrowed("12:00:00"))),
            Some(ColumnKind::Time)
        );
        assert_eq!(
            cell_kind(&RowCell::Timestamp(Cow::Borrowed("2026-01-01T00:00:00"))),
            Some(ColumnKind::Timestamp)
        );
        assert_eq!(
            cell_kind(&RowCell::Bytea(Cow::Owned(vec![1]))),
            Some(ColumnKind::Bytea)
        );
        assert_eq!(cell_kind(&RowCell::Absent), None);
    }

    #[test]
    fn remaining_record_branches_cover_refusals_and_fallbacks() {
        let composite = SubjectKey::composite_sources(
            ValueSource::typed_column(ColumnName::from_stored("seen_at"), ColumnKind::TimestampTz),
            vec![ValueSource::typed_column(
                ColumnName::from_stored("user_id"),
                ColumnKind::Text,
            )],
        );
        let bad_zone = FullRow::default()
            .with_cell(
                "seen_at",
                RowCell::TimestampTz(Cow::Borrowed("2026-01-01T01:00:00+01:00")),
            )
            .with_cell("user_id", RowCell::Text(Cow::Borrowed("alice")));
        assert_eq!(
            composite.render("account", &bad_zone),
            Err(RecordError::ColumnUndecodable("seen_at".to_string()))
        );

        let missing_rest = FullRow::default().with_cell(
            "seen_at",
            RowCell::TimestampTz(Cow::Borrowed("2026-01-01T00:00:00Z")),
        );
        assert_eq!(
            composite.render("account", &missing_rest),
            Err(RecordError::ColumnAbsent("user_id".to_string()))
        );

        let object_refuses = single_row_description(
            ObjectKey::column("id"),
            SubjectKey::wildcard(),
            Vec::new(),
            None,
        );
        let bad_object = FullRow::default().with_cell("id", RowCell::Undecodable);
        assert_eq!(
            records_from_row(&object_refuses, &bad_object),
            Err(RecordError::ColumnUndecodable("id".to_string()))
        );

        let subject_empty = single_row_description(
            ObjectKey::column("id"),
            SubjectKey::column("owner"),
            Vec::new(),
            None,
        );
        let null_subject = FullRow::default()
            .with_cell("id", RowCell::Text(Cow::Borrowed("d1")))
            .with_cell("owner", RowCell::Null);
        assert_eq!(
            records_from_row(&subject_empty, &null_subject).unwrap(),
            Vec::new()
        );

        let bad_context = single_row_description(
            ObjectKey::column("id"),
            SubjectKey::wildcard(),
            Vec::new(),
            Some(RecordContext {
                condition: "when_seen".to_string(),
                entries: vec![RecordContextEntry {
                    key: "seen_at".to_string(),
                    value: ValueSource::typed_column(
                        ColumnName::from_stored("seen_at"),
                        ColumnKind::TimestampTz,
                    ),
                    rendering: ContextRendering::Json,
                }],
            }),
        );
        let bad_context_row = FullRow::default()
            .with_cell("id", RowCell::Text(Cow::Borrowed("d1")))
            .with_cell(
                "seen_at",
                RowCell::TimestampTz(Cow::Borrowed("2026-01-01T01:00:00+01:00")),
            );
        assert_eq!(
            records_from_row(&bad_context, &bad_context_row),
            Err(RecordError::ColumnUndecodable("seen_at".to_string()))
        );
    }

    #[test]
    fn helper_branches_cover_literal_list_and_render_failures() {
        assert!(matches!(
            single_value(&ValueSource::Literal("fixed".to_string()), &FullRow::default()),
            Eval::Value(RowCell::Text(value)) if value == "fixed"
        ));
        assert!(matches!(
            single_value(
                &ValueSource::ListElements(read("editors", ColumnKind::Text)),
                &FullRow::default()
            ),
            Eval::Empty
        ));

        let null_row = FullRow::default().with_cell("id", RowCell::Null);
        assert!(matches!(
            expand(&ValueSource::column("id"), &null_row),
            Eval::Empty
        ));

        let bad_zone = FullRow::default().with_cell(
            "seen_at",
            RowCell::TimestampTz(Cow::Borrowed("2026-01-01T01:00:00+01:00")),
        );
        assert!(matches!(
            expand(
                &ValueSource::typed_column(
                    ColumnName::from_stored("seen_at"),
                    ColumnKind::TimestampTz
                ),
                &bad_zone
            ),
            Eval::Refuse(RecordError::ColumnUndecodable(_))
        ));

        let bad_row = FullRow::default().with_cell("id", RowCell::Undecodable);
        assert!(matches!(
            expand(&ValueSource::column("id"), &bad_row),
            Eval::Refuse(RecordError::ColumnUndecodable(_))
        ));

        let text_column = read("id", ColumnKind::Text);
        assert!(matches!(
            render_cell_failure(&text_column, &RowCell::Bool(true)),
            RecordError::ColumnTypeMismatch { .. }
        ));
        assert!(matches!(
            render_source_failure(
                &ValueSource::ListElements(read("seen_at", ColumnKind::TimestampTz)),
                &RowCell::TimestampTz(Cow::Borrowed("2026-01-01T01:00:00+01:00"))
            ),
            RecordError::ColumnUndecodable(_)
        ));
        assert!(matches!(
            render_source_failure(&ValueSource::column("id"), &RowCell::Bool(true)),
            RecordError::ColumnTypeMismatch { .. }
        ));
        assert!(matches!(
            render_source_failure(
                &ValueSource::Literal("fixed".to_string()),
                &RowCell::Bool(true)
            ),
            RecordError::ColumnTypeMismatch { .. }
        ));
        assert!(matches!(
            type_mismatch_source(&ValueSource::column("id"), &RowCell::Bool(true)),
            RecordError::ColumnTypeMismatch { .. }
        ));
        assert!(matches!(
            type_mismatch_source(
                &ValueSource::ListElements(read("ids", ColumnKind::Text)),
                &RowCell::Bool(true)
            ),
            RecordError::ColumnTypeMismatch { .. }
        ));
        assert!(matches!(
            type_mismatch_source(
                &ValueSource::JsonPath {
                    column: read("meta", ColumnKind::Json),
                    path: vec!["owner".to_string()],
                },
                &RowCell::Bool(true)
            ),
            RecordError::ColumnTypeMismatch { .. }
        ));
        assert_eq!(
            type_mismatch_source(&ValueSource::Literal("fixed".to_string()), &RowCell::Null),
            RecordError::ColumnTypeMismatch {
                column: "literal".to_string(),
                expected: ColumnKind::Text,
                actual: ColumnKind::Unsupported,
            }
        );
    }

    #[test]
    fn json_and_sql_rendering_cover_every_added_cell_arm() {
        assert_eq!(
            render_sql_text(&RowCell::Bytea(Cow::Owned(vec![222, 173]))),
            Some("\\xdead".to_string())
        );
        assert_eq!(render_json_text(&RowCell::Absent), None);
        assert_eq!(render_json_text(&RowCell::Null), None);
        assert_eq!(render_json_text(&RowCell::Undecodable), None);
        assert_eq!(
            render_json_text(&RowCell::Text(Cow::Borrowed("alice"))),
            Some("alice".to_string())
        );
        assert_eq!(
            render_json_text(&RowCell::Uuid(Cow::Borrowed(
                "00000000-0000-0000-0000-000000000001"
            ))),
            Some("00000000-0000-0000-0000-000000000001".to_string())
        );
        assert_eq!(
            render_json_text(&RowCell::Integer(Cow::Borrowed("42"))),
            Some("42".to_string())
        );
        assert_eq!(
            render_json_text(&RowCell::Decimal(Cow::Borrowed("42.5"))),
            Some("42.5".to_string())
        );
        assert_eq!(
            render_json_text(&RowCell::Date(Cow::Borrowed("2026-01-01"))),
            Some("2026-01-01".to_string())
        );
        assert_eq!(
            render_json_text(&RowCell::Time(Cow::Borrowed("12:34:56"))),
            Some("12:34:56".to_string())
        );
        assert_eq!(
            render_json_text(&RowCell::Bool(false)),
            Some("false".to_string())
        );
        assert_eq!(
            render_json_text(&RowCell::Timestamp(Cow::Borrowed("2026-01-01 12:34:56"))),
            Some("2026-01-01T12:34:56".to_string())
        );
    }

    #[test]
    fn local_test_rows_cover_their_non_text_paths() {
        let row = Row::of(&[("id", "not-a-uuid")]);
        assert_eq!(row.cell("id", ColumnKind::Uuid), RowCell::Undecodable);
        assert_eq!(row.list("id", ColumnKind::Text), RowList::Absent);
        assert_eq!(row.json_text("id", &["owner".to_string()]), RowCell::Absent);

        let timestamp = TimestampTzRow("2026-01-01T00:00:00Z");
        assert_eq!(
            timestamp.cell("other", ColumnKind::TimestampTz),
            RowCell::Absent
        );
        assert_eq!(
            timestamp.list("observed_at", ColumnKind::TimestampTz),
            RowList::Absent
        );
        assert_eq!(
            timestamp.json_text("observed_at", &["owner".to_string()]),
            RowCell::Absent
        );
    }
}

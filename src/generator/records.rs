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

/// One `(object, relation, subject)` fact, rendered exactly as the whole-table
/// SQL renders it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
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
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RecordContextValue {
    /// Condition the tuple names, declared by the model.
    pub condition: String,
    /// Each parameter the row fills in the condition context, keyed by parameter
    /// name and rendered as the tuple SQL renders it.
    pub values: BTreeMap<String, String>,
}

/// Column type family the row interface can render like `PostgreSQL`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextRendering {
    /// Render like tuple SQL text.
    SqlText,
    /// Render like condition context JSON.
    Json,
}

/// Where one side of a record takes its value on the row.
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
    pub fn render<R: RowValues + ?Sized>(
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
        if object_name_fits(&name) {
            Eval::Value(name)
        } else {
            Eval::Refuse(RecordError::RowCannotBeNamed(name.chars().count()))
        }
    }
}

/// How a subject's name is built from a row.
///
/// One part, which may expand into several subjects when it is a list column.
#[derive(Debug, Clone, PartialEq, Eq)]
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
            return if subject_name_fits(&name) {
                Eval::Value(vec![name])
            } else {
                Eval::Refuse(RecordError::RowCannotBeNamed(name.len()))
            };
        }
        match expand(&self.part, row) {
            Eval::Value(values) => {
                let mut subjects = Vec::with_capacity(values.len());
                for value in values {
                    let name = format!("{subject_type}:{}", encode_part(&value));
                    if subject_name_fits(&name) {
                        subjects.push(name);
                    } else {
                        return Eval::Refuse(RecordError::RowCannotBeNamed(name.len()));
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordContext {
    /// Condition the tuple names, declared by the model.
    pub condition: String,
    /// Each parameter the row fills, in the order the emitter recorded them.
    pub entries: Vec<RecordContextEntry>,
}

/// One parameter a record's condition context fills, and where its value comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
            Self::Object { object_type, .. } => {
                let name = format!("{object_type}:{}", encode_identity(values.iter().copied()));
                if object_name_fits(&name) {
                    Ok(name)
                } else {
                    Err(RecordError::RowCannotBeNamed(name.chars().count()))
                }
            }
            Self::Subject { subject_type, .. } => {
                let [value] = values else {
                    return Err(RecordError::SubjectKeyNotSingular(values.len()));
                };
                let name = format!("{subject_type}:{}", encode_part(value));
                if subject_name_fits(&name) {
                    Ok(name)
                } else {
                    Err(RecordError::RowCannotBeNamed(name.len()))
                }
            }
        }
    }
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
        Eval::Value(object) => Some(object),
        Eval::Empty => return Ok(Vec::new()),
        Eval::Refuse(error) => {
            if refusal.is_none() {
                refusal = Some(error);
            }
            None
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
    let Some(object) = object else {
        return Ok(Vec::new());
    };

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
}

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
    Column(ColumnName),
    /// A list column, one record per element. An empty or null list yields none,
    /// and a null element is dropped, which is how `= ANY` refuses it.
    ListElements(ColumnName),
    /// A path into a JSON column, read as text. A missing key yields no record.
    JsonPath {
        /// The JSON column.
        column: ColumnName,
        /// Field names, outermost first.
        path: Vec<String>,
    },
    /// A fixed value, carried by the description rather than read from the row.
    Literal(String),
}

impl ValueSource {
    /// Read a scalar column named as the caller already resolved it.
    ///
    /// The one place outside the crate that turns text into a
    /// [`crate::parser::identifiers::ColumnName`]. It can only ever make a column, so it cannot
    /// be the confusion the name kinds exist to stop, and keeping it to one function is what
    /// stops a second spelling of the same door appearing.
    #[must_use]
    pub fn column(name: impl Into<String>) -> Self {
        Self::Column(ColumnName::from_stored(name))
    }
}

/// A condition the row must satisfy for the records to exist.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Guard {
    /// The column is not SQL NULL.
    NotNull(ColumnName),
    /// The boolean column is true.
    IsTrue(ColumnName),
    /// The column compares as stated against a literal constant. A NULL column
    /// fails every comparison, exactly as SQL's three-valued logic filters it.
    Compare(AttributePredicate),
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
        let mut values = Vec::with_capacity(self.parts.len());
        for part in &self.parts {
            let Some(value) = single_value(part, row) else {
                return Ok(None);
            };
            values.push(value);
        }
        let name = format!(
            "{object_type}:{}",
            encode_identity(values.iter().map(String::as_str))
        );
        if object_name_fits(&name) {
            Ok(Some(name))
        } else {
            Err(RecordError::RowCannotBeNamed(name.chars().count()))
        }
    }
}

/// How a subject's name is built from a row.
///
/// One part, which may expand into several subjects when it is a list column.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectKey {
    part: ValueSource,
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
        if self.wildcard {
            return Ok(vec![format!("{subject_type}:{WILDCARD_SUBJECT_ID}")]);
        }
        expand(&self.part, row)
            .into_iter()
            .map(|value| {
                let name = format!("{subject_type}:{}", encode_part(&value));
                if subject_name_fits(&name) {
                    Ok(name)
                } else {
                    Err(RecordError::RowCannotBeNamed(name.len()))
                }
            })
            .collect()
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

/// One key a record puts in its condition context, under the condition the tuple
/// has to name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordContext {
    /// Condition the tuple names, declared by the model.
    pub condition: String,
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
    pub key_column: ColumnName,
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
///
/// `#[non_exhaustive]`: every arm is a refusal, so a caller's wildarm still
/// falls closed, and a later reason costs it no rewrite.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecordError {
    /// The description reads more than the one row, so querying is the only
    /// answer. Carries the reason the description recorded.
    NotDerivableFromOneRow(String),
    /// The row's values render a name longer than the target accepts, carrying
    /// that length. The whole-table SQL leaves such a row out, so no fact names
    /// it either way. Shortening the name would merge two rows into one object
    /// and hand each the other's access, so this refuses rather than guesses.
    RowCannotBeNamed(usize),
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
    // exactly as the SQL's NULL guard does. A name the target cannot spell is a
    // refusal rather than an empty set, which would read as "this row grants
    // nobody" and be believed.
    let Some(object) = template.object_key.render(&template.object_type, row)? else {
        return Ok(Vec::new());
    };

    // A context the row cannot fill yields no record at all, exactly as the tuple SQL
    // skips a row whose carried column is NULL.
    let context = match &template.context {
        Some(context) => match single_value(&context.value, row) {
            Some(value) => Some(RecordContextValue {
                condition: context.condition.clone(),
                key: context.key.clone(),
                value,
            }),
            None => return Ok(Vec::new()),
        },
        None => None,
    };

    Ok(template
        .subject_key
        .render(&template.subject_type, row)?
        .into_iter()
        .map(|subject| Record {
            object: object.clone(),
            relation: template.relation.clone(),
            subject,
            context: context.clone(),
        })
        .collect())
}

fn guard_holds<R: RowValues + ?Sized>(guard: &Guard, row: &R) -> bool {
    match guard {
        Guard::NotNull(column) => row.text(column.as_str()).is_some(),
        Guard::IsTrue(column) => row.boolean(column.as_str()) == Some(true),
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
            let Some(actual) = row.boolean(predicate.column.as_str()) else {
                return false;
            };
            actual.cmp(flag)
        }
        AttributeLiteral::Number(number) => {
            let Some(actual) = row.text(predicate.column.as_str()) else {
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
            let Some(actual) = row.text(predicate.column.as_str()) else {
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
        ValueSource::Column(column) => row.text(column.as_str()).map(Cow::into_owned),
        ValueSource::JsonPath { column, path } => {
            row.json_text(column.as_str(), path).map(Cow::into_owned)
        }
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
            .list(column.as_str())
            .unwrap_or_default()
            .into_iter()
            .flatten()
            .map(Cow::into_owned)
            .collect(),
        other => single_value(other, row).into_iter().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        fn text(&self, column: &str) -> Option<Cow<'_, str>> {
            self.0.get(column).map(|v| Cow::Borrowed(v.as_str()))
        }
    }

    #[test]
    fn an_object_name_joins_every_key_part_encoded() {
        let key = ObjectKey::new(vec![
            ValueSource::Column(ColumnName::from_stored("paper_id")),
            ValueSource::Column(ColumnName::from_stored("viewer")),
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
            ValueSource::Column(ColumnName::from_stored("paper_id")),
            ValueSource::Column(ColumnName::from_stored("viewer")),
        ]);
        let row = Row::of(&[("paper_id", "1")]);
        assert_eq!(key.render("paper_shares", &row).unwrap(), None);
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
}

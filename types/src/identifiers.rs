//! The kinds of name this crate handles, each its own type.
//!
//! Six kinds are in play and they obey different rules. A table reference as written may be
//! quoted and may omit its schema. A table's identity is the folded pair the schema stores. A
//! column name arrives already unquoted. A model type name is canonicalised and suffixed on
//! collision. A relation name is normalised and clamped to what `OpenFGA` accepts. A condition
//! parameter is a valid non-reserved `CEL` identifier. An object id is encoded and length-capped.
//!
//! The table kinds live here already. The other five arrive with the conversion that wires them,
//! so no type sits here unused and every increment of this work leaves the gate green.
//!
//! They were all `String`, and every over-grant this crate has recorded is two of them confused:
//! a type re-derived from a table name so `app.docs` and `public.docs` both emitted `docs:id`, a
//! policy spelled `ON "docs"` building one table twice and deleting a RESTRICTIVE barrier, and the
//! six manifestations of "an identifier's spelling is not its name".
//!
//! # Construction is the guarantee
//!
//! Resolvers build these types where identifiers enter the translation. `TableId` also
//! deserializes its stored schema and name as part of the public output graph. The rest of the
//! pipeline compares typed values.
//!
//! A table reference cannot stand in for a table identity, which is the `ON "docs"` defect:
//!
//! ```compile_fail
//! use rls2fga_types::TableRef;
//! # fn takes_identity(_: &rls2fga_types::TableId) {}
//! // A spelling is not an identity, and nothing resolved this one.
//! takes_identity(&TableRef::as_written("\"docs\""));
//! ```
//!
//! Nor can two spellings be compared, which is what built one table twice and deleted a
//! RESTRICTIVE barrier:
//!
//! ```compile_fail
//! use rls2fga_types::TableRef;
//! let quoted = TableRef::as_written("\"docs\"");
//! let bare = TableRef::as_written("docs");
//! // `TableRef` implements no equality on purpose: resolve both, then compare identities.
//! assert!(quoted == bare);
//! ```
//!
//! A model type name is a different kind again, so a table reference cannot stand in for it either,
//! which is the `docs:id` collision where a type was re-derived from a table name:
//!
//! ```compile_fail
//! use rls2fga_types::TableRef;
//! # fn takes_type(_: &rls2fga_types::TypeName) {}
//! takes_type(&TableRef::as_written("docs"));
//! ```
//!
//! Nor can a relation name stand in for a type name. They are the two halves of every
//! `type#relation` the model spells, and the reserved names are the ones the generator uses most:
//!
//! ```compile_fail
//! # fn takes_type(_: &rls2fga_types::TypeName) {}
//! # fn relation() -> rls2fga_types::RelationName { loop {} }
//! takes_type(&relation());
//! ```
//!
//! And a column name cannot stand in for a relation name, which is the acceptance this work was
//! written against: a column is a name the database stores, a relation is a name the model mints:
//!
//! ```compile_fail
//! use rls2fga_types::ValueSource;
//! # fn takes_relation(_: &rls2fga_types::RelationName) {}
//! let ValueSource::Column(column) = ValueSource::column("owner_id") else { unreachable!() };
//! takes_relation(&column);
//! ```
//!
//! Each of those uses only the public constructor, so it fails on the type and not on privacy. A
//! proof that reaches for a crate-private constructor fails for the wrong reason and shows nothing.

use crate::prelude::*;
use core::fmt;

/// Render a name kind and compare it against text in both directions.
///
/// Comparing against text is what a caller does most, and a lookup key has to reach the map
/// through `&str` or every site allocates. `Borrow` is sound here because `Eq`, `Ord` and
/// `Hash` all delegate to the wrapped `String`.
macro_rules! compares_against_text {
    ($name:ident) => {
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl core::borrow::Borrow<str> for $name {
            fn borrow(&self) -> &str {
                &self.0
            }
        }

        impl From<$name> for String {
            fn from(name: $name) -> Self {
                name.0
            }
        }

        impl PartialEq<str> for $name {
            fn eq(&self, other: &str) -> bool {
                self.0 == other
            }
        }

        impl PartialEq<&str> for $name {
            fn eq(&self, other: &&str) -> bool {
                self.0 == *other
            }
        }

        impl PartialEq<String> for $name {
            fn eq(&self, other: &String) -> bool {
                &self.0 == other
            }
        }

        impl PartialEq<$name> for String {
            fn eq(&self, other: &$name) -> bool {
                self == &other.0
            }
        }

        impl PartialEq<$name> for &str {
            fn eq(&self, other: &$name) -> bool {
                *self == other.0
            }
        }
    };
}

/// A table as some SQL text spelled it, before anything resolved it.
///
/// May be quoted, may omit the schema, and two of these may name one table. Comparing two as text
/// is the mistake that built one table twice, so this deliberately offers no equality: resolve it
/// first.
#[derive(Debug, Clone)]
pub struct TableRef(String);

/// A table's identity, as the schema stores it.
///
/// The schema and name folded the way `PostgreSQL` stores them, which is what makes two references
/// to one table compare equal. Renders as the canonical key
/// `lookup_table` resolves either way.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct TableId {
    schema: Option<String>,
    name: String,
}

impl TableRef {
    /// Take a reference as some SQL text spelled it.
    ///
    /// The only unchecked constructor here, because a spelling is exactly the thing nothing has
    /// resolved yet. Everything downstream needs a [`TableId`].
    #[must_use]
    pub fn as_written(spelling: impl Into<String>) -> Self {
        Self(spelling.into())
    }

    /// The spelling, for a diagnostic that has to quote what the policy said.
    #[must_use]
    pub fn spelling(&self) -> &str {
        &self.0
    }
}

impl TableId {
    /// Build an identity from names a schema stored.
    ///
    /// `pub(crate)` on purpose: outside this crate an identity comes from resolving a
    /// [`TableRef`], never from assembling two strings.
    #[doc(hidden)]
    pub fn from_stored(schema: Option<String>, name: String) -> Self {
        Self { schema, name }
    }

    /// The stored schema, absent where the table has none.
    #[must_use]
    pub fn schema(&self) -> Option<&str> {
        self.schema.as_deref()
    }

    /// The stored name, without its schema.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The fully qualified SQL name.
    ///
    /// A table stored without a schema resides in `public`, so this names that schema
    /// rather than leaving the reading session's search path to choose one.
    #[must_use]
    pub fn sql_name(&self) -> String {
        format!(
            "{}.{}",
            quoted_for_sql(self.schema.as_deref().unwrap_or("public")),
            quoted_for_sql(&self.name)
        )
    }
}

/// The canonical key, which is the identity rendered so `lookup_table` resolves it either way.
///
/// One rendering, because two would be two answers to "which table is this", which is what the
/// crate carried before: an identity built from raw names beside a key built from stored ones.
impl fmt::Display for TableId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.schema {
            Some(schema) => write!(
                f,
                "{}.{}",
                quoted_for_lookup(schema),
                quoted_for_lookup(&self.name)
            ),
            None => write!(f, "{}", quoted_for_lookup(&self.name)),
        }
    }
}

/// Quote a part for a lookup key unless it is a bare lowercase identifier.
///
/// `lookup_table` tries both spellings, so this form resolves either way.
fn quoted_for_lookup(part: &str) -> String {
    let bare = !part.is_empty()
        && !part.starts_with(|ch: char| ch.is_ascii_digit())
        && part
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_');
    if bare {
        part.to_string()
    } else {
        format!("\"{}\"", part.replace('"', "\"\""))
    }
}

fn quoted_for_sql(part: &str) -> String {
    format!("\"{}\"", part.replace('"', "\"\""))
}

fn canonical_identifier(name: &str, fallback: &str) -> String {
    let mut canonical = String::with_capacity(name.len());
    for ch in name.chars() {
        let ch = ch.to_ascii_lowercase();
        if ch.is_ascii_alphanumeric() || ch == '_' {
            canonical.push(ch);
        } else if !canonical.is_empty() && !canonical.ends_with('_') {
            canonical.push('_');
        }
    }
    let trimmed = canonical.trim_matches('_');
    if trimmed.is_empty() {
        fallback.to_string()
    } else {
        trimmed.to_string()
    }
}

/// Return the stable eight-digit suffix used to disambiguate generated names.
#[must_use]
pub fn stable_hex_suffix(value: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in value.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{:08x}", hash & u64::from(u32::MAX))
}

/// An `OpenFGA` model type name.
///
/// Generator-assigned names are canonicalized and disambiguated before construction.
/// Configured names are validated and preserve their exact text.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
#[serde(transparent)]
pub struct TypeName(String);

impl TypeName {
    /// Canonicalize a generator-assigned name.
    #[must_use]
    pub fn canonicalized(name: impl AsRef<str>) -> Self {
        let name = name.as_ref();
        if is_openfga_type_name(name) && !matches!(name, "self" | "this") {
            return Self(name.to_string());
        }
        let mut canonical = canonical_identifier(name, "resource");
        if canonical.starts_with(|ch: char| ch.is_ascii_digit())
            || matches!(canonical.as_str(), "self" | "this")
        {
            canonical.insert_str(0, "t_");
        }
        Self(canonical)
    }

    /// The name, for rendering.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for TypeName {
    type Error = TypeNameError;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        if name.is_empty() {
            return Err(TypeNameError::Empty);
        }
        if matches!(name.as_str(), "self" | "this") {
            return Err(TypeNameError::Reserved { name });
        }
        if !is_openfga_type_name(&name) {
            return Err(TypeNameError::Invalid { name });
        }
        Ok(Self(name))
    }
}

impl TryFrom<&str> for TypeName {
    type Error = TypeNameError;

    fn try_from(name: &str) -> Result<Self, Self::Error> {
        Self::try_from(name.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for TypeName {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = String::deserialize(deserializer)?;
        Self::try_from(name).map_err(serde::de::Error::custom)
    }
}

/// Why an `OpenFGA` type name was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TypeNameError {
    /// Empty names cannot identify a type.
    #[error("an OpenFGA type name cannot be empty")]
    Empty,
    /// `OpenFGA` reserves this name.
    #[error("OpenFGA reserves the type name {name:?}")]
    Reserved {
        /// Refused name.
        name: String,
    },
    /// The name cannot be rendered in the `OpenFGA` DSL.
    #[error("{name:?} is not a valid OpenFGA type name")]
    Invalid {
        /// Refused name.
        name: String,
    },
}

fn is_openfga_type_name(name: &str) -> bool {
    let mut chars = name.chars();
    if !chars
        .next()
        .is_some_and(|ch| ch.is_ascii_alphabetic() || ch == '_')
    {
        return false;
    }

    let mut after_separator = false;
    for ch in chars {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            after_separator = false;
        } else if matches!(ch, '/' | '.' | '-') && !after_separator {
            after_separator = true;
        } else {
            return false;
        }
    }
    !after_separator
}

impl AsRef<str> for TypeName {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

compares_against_text!(TypeName);

/// A relation of the emitted model, normalised and clamped to what `OpenFGA` accepts.
///
/// Not every use of `clamp_relation_name` or
/// `normalize_relation_name` makes one of
/// these: the clamp also turns a type name into a relation reference, and the normaliser also
/// compares table and column names. A relation name is one only where a relation is decided,
/// which is the four minting methods on a type plan, the four derived scope names, the
/// collision yield, the role pair, and the reserved names.
///
/// Serializes as its text, since the JSON model spells a relation as a bare name, and
/// deserializes the same way, taking the text as a name the emitter already decided.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
#[serde(transparent)]
pub struct RelationName(String);

impl RelationName {
    /// Canonicalize and clamp a generated relation name.
    #[must_use]
    pub fn canonicalized(name: impl AsRef<str>) -> Self {
        const MAX_LEN: usize = 50;
        let original = name.as_ref();
        let mut canonical = canonical_identifier(original, "relation");
        if canonical.len() > MAX_LEN {
            let suffix = stable_hex_suffix(original);
            canonical.truncate(MAX_LEN - suffix.len() - 1);
            canonical.push('_');
            canonical.push_str(&suffix);
        }
        Self(canonical)
    }

    /// The name, for rendering.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for RelationName {
    type Error = RelationNameError;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        if name.is_empty() {
            return Err(RelationNameError::Empty);
        }
        if name.len() > 50 {
            return Err(RelationNameError::TooLong { name });
        }
        if !name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        {
            return Err(RelationNameError::Invalid { name });
        }
        Ok(Self(name))
    }
}

impl TryFrom<&str> for RelationName {
    type Error = RelationNameError;

    fn try_from(name: &str) -> Result<Self, Self::Error> {
        Self::try_from(name.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for RelationName {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = String::deserialize(deserializer)?;
        Self::try_from(name).map_err(serde::de::Error::custom)
    }
}

/// Why an `OpenFGA` relation name was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RelationNameError {
    /// Empty names cannot identify a relation.
    #[error("an OpenFGA relation name cannot be empty")]
    Empty,
    /// The name exceeds the `OpenFGA` limit.
    #[error("{name:?} exceeds the OpenFGA relation name limit")]
    TooLong {
        /// Refused name.
        name: String,
    },
    /// The name contains an unsupported character.
    #[error("{name:?} is not a valid OpenFGA relation name")]
    Invalid {
        /// Refused name.
        name: String,
    },
}

compares_against_text!(RelationName);

/// A condition parameter that can be referenced by a `CEL` expression.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
#[serde(transparent)]
pub struct ConditionParameterName(String);

impl ConditionParameterName {
    /// Derive a valid parameter while preserving already valid non-reserved names.
    #[doc(hidden)]
    pub fn derived(source: &str) -> Self {
        let mut name = String::with_capacity(source.len() + 1);
        if source.chars().next().is_some_and(|ch| ch.is_ascii_digit()) {
            name.push('_');
        }
        for ch in source.chars() {
            name.push(if ch.is_ascii_alphanumeric() || ch == '_' {
                ch.to_ascii_lowercase()
            } else {
                '_'
            });
        }
        if name.is_empty() {
            name.push_str("parameter");
        }
        if is_reserved_cel_identifier(&name) {
            name.insert(0, '_');
        }
        Self(name)
    }

    /// The name, for rendering.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ConditionParameterName {
    type Error = ConditionParameterNameError;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        if is_condition_parameter_name(&name) {
            Ok(Self(name))
        } else {
            Err(ConditionParameterNameError::Invalid { name })
        }
    }
}

impl TryFrom<&str> for ConditionParameterName {
    type Error = ConditionParameterNameError;

    fn try_from(name: &str) -> Result<Self, Self::Error> {
        Self::try_from(name.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for ConditionParameterName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let name = String::deserialize(deserializer)?;
        Self::try_from(name).map_err(serde::de::Error::custom)
    }
}

compares_against_text!(ConditionParameterName);

/// Why a condition parameter name was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ConditionParameterNameError {
    /// The name is not a usable `CEL` identifier.
    #[error("{name:?} is not a valid CEL condition parameter name")]
    Invalid {
        /// Refused name.
        name: String,
    },
}

fn is_condition_parameter_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|ch| ch.is_ascii_alphabetic() || ch == '_')
        && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        && !is_reserved_cel_identifier(name)
}

fn is_reserved_cel_identifier(name: &str) -> bool {
    matches!(
        name,
        "as" | "break"
            | "const"
            | "continue"
            | "else"
            | "false"
            | "for"
            | "function"
            | "if"
            | "import"
            | "in"
            | "let"
            | "loop"
            | "namespace"
            | "null"
            | "package"
            | "return"
            | "true"
            | "var"
            | "void"
            | "while"
    )
}

/// A column of a table, under the name `PostgreSQL` stores it.
///
/// An unquoted spelling folds to lowercase and a quoted one keeps its case, so `Owner_Id` and
/// `owner_id` are one column while `"Owner_Id"` is another. Deciding that is the whole kind,
/// and there are three places it happens: a name a policy expression wrote reaches
/// `extract_column_name`, a qualified reference
/// splits inside the recognizers, and a declared column arrives from the schema through
/// `db_lookup`. Everywhere else a column is carried, never re-derived.
///
/// Serializes as its text, since a record spells a column as a bare name, and deserializes so a
/// function registry can declare one. A configured name is taken as the deployment spelled it,
/// which is a fourth place a column enters and the only one the schema does not vouch for.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Default,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(transparent)]
pub struct ColumnName(String);

impl ColumnName {
    /// Take a name the fold already decided.
    ///
    #[doc(hidden)]
    pub fn from_stored(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// The name, for rendering.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

compares_against_text!(ColumnName);

#[cfg(test)]
mod tests {
    use super::*;

    /// The canonical key is the identity rendered, so a schema-qualified table and a bare one each
    /// render to the form `lookup_table` resolves.
    #[test]
    fn an_identity_renders_the_key_that_resolves_it() {
        let qualified = TableId::from_stored(Some("app".to_string()), "docs".to_string());
        assert_eq!(qualified.to_string(), "app.docs");

        let bare = TableId::from_stored(None, "docs".to_string());
        assert_eq!(bare.to_string(), "docs");
    }

    /// A stored name needing quotes gets them back, and an interior quote is doubled rather than
    /// closing the identifier.
    #[test]
    fn a_name_needing_quotes_is_requoted_and_escaped() {
        let mixed = TableId::from_stored(None, "Docs".to_string());
        assert_eq!(mixed.to_string(), "\"Docs\"");

        let awkward = TableId::from_stored(None, "do\"cs".to_string());
        assert_eq!(awkward.to_string(), "\"do\"\"cs\"");
    }

    /// Identity is the stored pair, so a schema distinguishes two tables sharing a name.
    #[test]
    fn two_schemas_holding_one_name_are_two_identities() {
        let app = TableId::from_stored(Some("app".to_string()), "docs".to_string());
        let public = TableId::from_stored(Some("public".to_string()), "docs".to_string());
        assert_ne!(app, public);
        assert_ne!(app, TableId::from_stored(None, "docs".to_string()));
    }

    #[test]
    fn type_names_validate_at_the_public_boundary() {
        assert_eq!(TypeName::try_from("docs").expect("valid type name"), "docs");
        assert!(TypeName::try_from("not a type").is_err());
    }

    /// A second pass changes nothing, which is what lets a canonical name be carried
    /// through references and definitions alike.
    #[test]
    fn canonicalizing_a_type_name_twice_answers_the_same() {
        for name in [
            "",
            "docs",
            "Docs",
            "self",
            "this",
            "t_self",
            "123_items",
            "a-b",
            "app.docs",
            "___",
            "resource",
        ] {
            let once = TypeName::canonicalized(name);
            let twice = TypeName::canonicalized(once.as_str());
            assert_eq!(once, twice, "for {name:?}");
        }
    }

    /// The two names `OpenFGA` reserves never survive as themselves.
    #[test]
    fn a_reserved_type_name_is_prefixed() {
        assert_eq!(TypeName::canonicalized("self"), "t_self");
        assert_eq!(TypeName::canonicalized("this"), "t_this");
        assert_eq!(TypeName::canonicalized("selfish"), "selfish");
    }
}

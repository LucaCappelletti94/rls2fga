//! The kinds of name this crate handles, each its own type.
//!
//! Five kinds are in play and they obey different rules. A table reference as written may be
//! quoted and may omit its schema. A table's identity is the folded pair the schema stores. A
//! column name arrives already unquoted. A model type name is canonicalised and suffixed on
//! collision. A relation name is normalised and clamped to what `OpenFGA` accepts. An object id
//! is encoded and length-capped.
//!
//! The table kinds live here already. The other four arrive with the conversion that wires them,
//! so no type sits here unused and every increment of this work leaves the gate green.
//!
//! They were all `String`, and every over-grant this crate has recorded is two of them confused:
//! a type re-derived from a table name so `app.docs` and `public.docs` both emitted `docs:id`, a
//! policy spelled `ON "docs"` building one table twice and deleting a RESTRICTIVE barrier, and the
//! six manifestations of "an identifier's spelling is not its name".
//!
//! # Construction is the guarantee
//!
//! Each type is built only by the resolver that already owns its rule, so a value of the type is
//! proof the rule ran. Nothing here takes a `&str` and trusts it: the fold happens where an
//! identifier enters, and the rest of the pipeline compares typed values.
//!
//! A table reference cannot stand in for a table identity, which is the `ON "docs"` defect:
//!
//! ```compile_fail
//! use rls2fga::parser::identifiers::TableRef;
//! # fn takes_identity(_: &rls2fga::parser::identifiers::TableId) {}
//! // A spelling is not an identity, and nothing resolved this one.
//! takes_identity(&TableRef::as_written("\"docs\""));
//! ```
//!
//! Nor can two spellings be compared, which is what built one table twice and deleted a
//! RESTRICTIVE barrier:
//!
//! ```compile_fail
//! use rls2fga::parser::identifiers::TableRef;
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
//! use rls2fga::parser::identifiers::TableRef;
//! # fn takes_type(_: &rls2fga::parser::identifiers::TypeName) {}
//! takes_type(&TableRef::as_written("docs"));
//! ```
//!
//! Nor can a relation name stand in for a type name. They are the two halves of every
//! `type#relation` the model spells, and the reserved names are the ones the generator uses most:
//!
//! ```compile_fail
//! # fn takes_type(_: &rls2fga::parser::identifiers::TypeName) {}
//! takes_type(&rls2fga::generator::well_known::can_select_relation());
//! ```
//!
//! And a column name cannot stand in for a relation name, which is the acceptance this work was
//! written against: a column is a name the database stores, a relation is a name the model mints:
//!
//! ```compile_fail
//! use rls2fga::generator::records::ValueSource;
//! # fn takes_relation(_: &rls2fga::parser::identifiers::RelationName) {}
//! let ValueSource::Column(column) = ValueSource::column("owner_id") else { unreachable!() };
//! takes_relation(&column);
//! ```
//!
//! Each of those uses only the public constructor, so it fails on the type and not on privacy. A
//! proof that reaches for a crate-private constructor fails for the wrong reason and shows nothing.

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
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
/// [`lookup_table`](crate::parser::names::lookup_table) resolves either way.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
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
    pub(crate) fn from_stored(schema: Option<String>, name: String) -> Self {
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

/// A type of the emitted model, canonicalised and disambiguated where two tables canonicalise
/// alike.
///
/// Not every use of [`canonical_fga_type_name`](crate::parser::names::canonical_fga_type_name)
/// makes one of these: the same canonicaliser also builds relation names and the id of a
/// `pg_role` object. A type name is one only where a type is finally decided, which is the type
/// assignment pass, the holder for an uncorrelated membership, a parent named from a foreign key,
/// and the reserved names.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct TypeName(String);

impl TypeName {
    /// Take a name the type assignment already decided.
    ///
    /// `pub(crate)`, so a value of this type is proof the canonicalisation and the collision check
    /// both ran.
    pub(crate) fn from_resolved(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// The name, for rendering.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

compares_against_text!(TypeName);

/// A relation of the emitted model, normalised and clamped to what `OpenFGA` accepts.
///
/// Not every use of [`clamp_relation_name`](crate::parser::names::clamp_relation_name) or
/// [`normalize_relation_name`](crate::parser::names::normalize_relation_name) makes one of
/// these: the clamp also turns a type name into a relation reference, and the normaliser also
/// compares table and column names. A relation name is one only where a relation is decided,
/// which is the four minting methods on a type plan, the four derived scope names, the
/// collision yield, the role pair, and the reserved names.
///
/// Serializes as its text, since the JSON model spells a relation as a bare name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, serde::Serialize)]
#[serde(transparent)]
pub struct RelationName(String);

impl RelationName {
    /// Take a name a minting or deriving step already decided.
    ///
    /// `pub(crate)`, so a value of this type is proof the clamp and the collision check both
    /// ran.
    pub(crate) fn from_resolved(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// The name, for rendering.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

compares_against_text!(RelationName);

/// A column of a table, under the name `PostgreSQL` stores it.
///
/// An unquoted spelling folds to lowercase and a quoted one keeps its case, so `Owner_Id` and
/// `owner_id` are one column while `"Owner_Id"` is another. Deciding that is the whole kind,
/// and there are three places it happens: a name a policy expression wrote reaches
/// [`extract_column_name`](crate::parser::expr::extract_column_name), a qualified reference
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
    /// `pub(crate)`, so a value of this type is proof the quoting was read rather than guessed.
    pub(crate) fn from_stored(name: impl Into<String>) -> Self {
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
}

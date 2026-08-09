//! One place a database value becomes an identifier the target accepts.
//!
//! `OpenFGA` refuses some values outright and silently reinterprets others, so
//! every name the crate renders passes through here, objects and subjects
//! alike. A second spelling anywhere reintroduces the drift this exists to
//! close.

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use alloc::borrow::Cow;
use core::fmt::Write;

/// Introduces an escaped value. Outside [`is_spelled_verbatim`], so no verbatim
/// value can begin with it and the mapping stays injective.
pub(crate) const ESCAPE_MARKER: char = '~';

/// Joins the parts of a compound identity. Outside [`is_spelled_verbatim`], so
/// a part holding one escapes and two different splits cannot render alike.
pub(crate) const PART_SEPARATOR: char = '|';

/// Longest object name the target accepts, counted in **characters** over the
/// whole `type:id` string, so the key's budget shrinks as the type name grows.
/// Measured against v1.11.6, whose check is `^[^\s]{2,256}$`.
pub(crate) const MAX_OBJECT_NAME_CHARS: usize = 256;

/// Longest subject name the target accepts, counted in **bytes** over the whole
/// `type:id` string. Measured against v1.11.6. Bytes rather than characters, so
/// this is not the object rule with a different number.
pub(crate) const MAX_SUBJECT_NAME_BYTES: usize = 512;

/// Whether the target accepts `name` as an object.
///
/// Characters, mirroring the service's own regex. The unit is inert today, since
/// [`encode_part`] renders ASCII either way, and it is spelled correctly so that
/// widening [`SAFE_PUNCTUATION`] past ASCII cannot quietly change the answer.
pub(crate) fn object_name_fits(name: &str) -> bool {
    name.chars().count() <= MAX_OBJECT_NAME_CHARS
}

/// Whether the target accepts `name` as a subject.
///
/// Bytes, mirroring the service's own check, and inert for the same reason.
pub(crate) fn subject_name_fits(name: &str) -> bool {
    name.len() <= MAX_SUBJECT_NAME_BYTES
}

/// Characters a verbatim identifier may hold beside ASCII alphanumerics.
///
/// One source for the Rust predicate and the SQL regex, so the two cannot
/// disagree about the safe set. The hyphen stays **last**: interpolated into a
/// regex character class anywhere else it reads as a range.
const SAFE_PUNCTUATION: &str = "._@-";

/// Whether the target spells `value` verbatim.
///
/// A whitelist, so a character the service later gives meaning to stays escaped
/// unless it is alphanumeric. The empty string is not verbatim: the target
/// refuses an empty identifier.
fn is_spelled_verbatim(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || SAFE_PUNCTUATION.as_bytes().contains(&b))
}

/// One nibble as a lowercase hex digit, matching what
/// `encode(convert_to(v,'UTF8'),'hex')` renders on the SQL side. The two must
/// agree byte for byte.
const fn hex_digit(nibble: u8) -> char {
    let nibble = nibble & 0x0f;
    (if nibble < 10 {
        b'0' + nibble
    } else {
        b'a' + nibble - 10
    }) as char
}

/// Render one value as one part of an identifier.
///
/// A verbatim value borrows, so the ordinary case allocates nothing.
pub(crate) fn encode_part(value: &str) -> Cow<'_, str> {
    if is_spelled_verbatim(value) {
        return Cow::Borrowed(value);
    }
    let mut out = String::with_capacity(1 + value.len() * 2);
    out.push(ESCAPE_MARKER);
    for byte in value.bytes() {
        out.push(hex_digit(byte >> 4));
        out.push(hex_digit(byte & 0x0f));
    }
    Cow::Owned(out)
}

/// Render an ordered list of values as one identifier.
pub(crate) fn encode_identity<'a, I>(parts: I) -> String
where
    I: IntoIterator<Item = &'a str>,
{
    let mut out = String::new();
    for (index, part) in parts.into_iter().enumerate() {
        if index > 0 {
            out.push(PART_SEPARATOR);
        }
        out.push_str(&encode_part(part));
    }
    out
}

/// The regex character class matching a value the target spells verbatim.
///
/// Built from [`SAFE_PUNCTUATION`], so the SQL side and [`is_spelled_verbatim`]
/// cannot describe different sets.
fn safe_character_class() -> String {
    format!("A-Za-z0-9{SAFE_PUNCTUATION}")
}

/// SQL rendering one value expression as one part of an identifier.
///
/// Must agree with [`encode_part`] for every input. The pair is what the per
/// row record parity suite compares, since no assertion on either alone can
/// see them drift.
pub(crate) fn encode_part_sql(value_sql: &str) -> String {
    let class = safe_character_class();
    format!(
        "CASE WHEN {value_sql}::text ~ '^[{class}]+$' THEN {value_sql}::text \
         ELSE '{ESCAPE_MARKER}' || encode(convert_to({value_sql}::text, 'UTF8'), 'hex') END"
    )
}

/// SQL rendering an ordered list of value expressions as one identifier.
pub(crate) fn encode_identity_sql<'a, I>(parts: I) -> String
where
    I: IntoIterator<Item = &'a str>,
{
    let mut out = String::new();
    for (index, part) in parts.into_iter().enumerate() {
        if index > 0 {
            let _ = write!(out, " || '{PART_SEPARATOR}' || ");
        }
        out.push_str(&encode_part_sql(part));
    }
    out
}

/// SQL for a typed name whose key is read from `parts`.
///
/// The type name is deliberately **not** encoded: it has to match the type the
/// model declares, and `canonical_fga_type_name` already restricts it to
/// `[a-z0-9_]`, so there is nothing here to escape.
pub(crate) fn typed_name_sql<'a, I>(type_name: &str, parts: I) -> String
where
    I: IntoIterator<Item = &'a str>,
{
    format!("'{type_name}:' || {}", encode_identity_sql(parts))
}

/// A typed name whose key is already known, as a SQL string literal.
///
/// For a key the crate holds at generation time (a role name, a fixed holder
/// id) rather than one a column supplies. An encoded key never contains a
/// quote, so the literal needs no further escaping.
pub(crate) fn typed_name_literal(type_name: &str, key: &str) -> String {
    format!("'{type_name}:{}'", encode_part(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ordinary_value_is_spelled_verbatim() {
        for value in [
            "alice",
            "42",
            "11111111-2222-3333-4444-555555555555",
            "a.b@example.com",
            "Docs_1",
        ] {
            assert_eq!(
                encode_part(value),
                value,
                "expected {value} to need no escaping"
            );
        }
    }

    #[test]
    fn a_value_the_target_refuses_is_escaped_behind_the_marker() {
        // Every expectation is the hex PostgreSQL's `encode(convert_to(v,'UTF8'),'hex')`
        // produces for the same input, so the two renderings are pinned to one answer.
        for (value, expected) in [
            ("alice smith", "~616c69636520736d697468"),
            ("", "~"),
            ("a:b", "~613a62"),
            ("ali\u{e7}e", "~616c69c3a765"),
            ("a\nb", "~610a62"),
        ] {
            assert_eq!(encode_part(value), expected, "for {value:?}");
        }
    }

    #[test]
    fn a_value_the_target_silently_reinterprets_is_escaped_too() {
        // Neither of these fails on write. `user:*` is the typed wildcard and grants
        // everyone, and `user:alice#member` is a userset granting that relation's
        // members, so leaving either verbatim is a wrong allow rather than a failed load.
        assert_eq!(encode_part("*"), "~2a");
        assert_eq!(encode_part("alice#member"), "~616c696365236d656d626572");
    }

    #[test]
    fn the_marker_and_the_separator_escape_themselves() {
        // Without this the mapping stops being injective and a compound identity
        // built from encoded parts can be read back two ways.
        assert_eq!(encode_part("~tilde"), "~7e74696c6465");
        assert_eq!(encode_part("a|b"), "~617c62");
    }

    #[test]
    fn two_compound_keys_splitting_differently_do_not_render_alike() {
        let left = encode_identity(["1", "a|b"]);
        let right = encode_identity(["1|a", "b"]);
        assert_eq!(left, "1|~617c62");
        assert_eq!(right, "~317c61|b");
        assert_ne!(
            left, right,
            "a separator inside a part must escape or the parts cannot be told apart"
        );
    }

    #[test]
    fn a_single_column_key_is_a_list_of_one() {
        assert_eq!(encode_identity(["alice"]), "alice");
        assert_eq!(encode_identity(["alice smith"]), "~616c69636520736d697468");
    }

    #[test]
    fn the_sql_spells_one_part_as_a_verbatim_test_over_an_escape() {
        assert_eq!(
            encode_part_sql(r#""owner""#),
            concat!(
                r#"CASE WHEN "owner"::text ~ '^[A-Za-z0-9._@-]+$' THEN "owner"::text"#,
                r#" ELSE '~' || encode(convert_to("owner"::text, 'UTF8'), 'hex') END"#
            )
        );
    }

    #[test]
    fn the_sql_joins_compound_parts_with_the_separator() {
        let sql = encode_identity_sql([r#""paper_id""#, r#""viewer""#]);
        assert!(
            sql.contains(" || '|' || "),
            "expected the parts joined by the separator: {sql}"
        );
        assert_eq!(
            sql.matches("CASE WHEN").count(),
            2,
            "every part is encoded before joining, or the join is not injective: {sql}"
        );
    }

    #[test]
    fn both_readers_take_the_safe_set_from_one_place() {
        // The Rust predicate accepts exactly ASCII alphanumerics plus the declared
        // punctuation, and the SQL class is built from the same constant, so the two
        // cannot disagree about which values are spelled verbatim. Whether PostgreSQL
        // reads that class as intended is settled by the parity case, not here.
        let class = safe_character_class();
        assert_eq!(class, "A-Za-z0-9._@-");
        assert!(
            class.ends_with('-'),
            "a hyphen anywhere but last reads as a range inside a character class: {class}"
        );
        for byte in 0u8..=127 {
            let value = (byte as char).to_string();
            let verbatim = encode_part(&value) == value;
            let expected =
                byte.is_ascii_alphanumeric() || SAFE_PUNCTUATION.as_bytes().contains(&byte);
            assert_eq!(verbatim, expected, "for byte {byte:#04x}");
        }
    }

    #[test]
    fn a_typed_name_keeps_its_type_unencoded_and_encodes_only_the_key() {
        // The type has to match what the model declares, and `canonical_fga_type_name`
        // already restricts it to `[a-z0-9_]`, so encoding it here would rename the type.
        let sql = typed_name_sql("paper_shares", [r#""paper_id""#, r#""viewer""#]);
        assert!(sql.starts_with("'paper_shares:' || "), "{sql}");
        assert_eq!(sql.matches("CASE WHEN").count(), 2, "{sql}");
    }

    #[test]
    fn a_generation_time_key_is_encoded_into_the_literal() {
        // A role name comes from the schema and may hold anything PostgreSQL allows.
        assert_eq!(
            typed_name_literal("pg_role", "app_admin"),
            "'pg_role:app_admin'"
        );
        assert_eq!(
            typed_name_literal("pg_role", "read only"),
            "'pg_role:~72656164206f6e6c79'"
        );
    }

    #[test]
    fn an_encoded_key_can_never_close_a_sql_string_literal() {
        // `typed_name_literal` interpolates without escaping, which is only safe
        // because the encoding admits no quote. Swept rather than argued.
        for byte in 0u8..=127 {
            let value = (byte as char).to_string();
            let encoded = encode_part(&value);
            assert!(
                !encoded.contains('\'') && !encoded.contains('\\'),
                "byte {byte:#04x} encoded to {encoded:?}"
            );
        }
    }
}

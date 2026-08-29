use crate::prelude::*;
use alloc::borrow::Cow;

pub(crate) const WILDCARD_SUBJECT_ID: &str = "*";

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
pub(crate) const fn hex_digit(nibble: u8) -> char {
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

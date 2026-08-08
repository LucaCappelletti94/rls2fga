#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
/// Return the identifier without surrounding double quotes, decoding internal
/// escaped double-quote sequences (`""` → `"`).
///
/// Malformed identifiers (e.g. unterminated `"foo`) are returned unchanged so
/// the caller can still produce a reasonable output.
pub fn unquote_identifier(ident: &str) -> alloc::borrow::Cow<'_, str> {
    let Some(inner) = ident.strip_prefix('"').and_then(|s| s.strip_suffix('"')) else {
        return alloc::borrow::Cow::Borrowed(ident);
    };
    if !inner.contains("\"\"") {
        return alloc::borrow::Cow::Borrowed(inner);
    }
    alloc::borrow::Cow::Owned(inner.replace("\"\"", "\""))
}

/// Normalize an identifier for case-insensitive matching.
///
/// Trims whitespace, removes surrounding double quotes on a single identifier,
/// and lowercases the result.
pub fn normalize_identifier(ident: &str) -> String {
    unquote_identifier(ident.trim()).to_ascii_lowercase()
}

/// True when two identifiers name the same thing, ignoring case and quoting.
pub fn same_identifier(left: &str, right: &str) -> bool {
    normalize_identifier(left) == normalize_identifier(right)
}

/// The name `PostgreSQL` stores for an identifier written in SQL: unquoted folds
/// to lowercase, quoted keeps its case.
///
/// Declared identifiers use `ColumnLike::stored_column_name`,
/// `TableLike::stored_table_name` and `TableLike::stored_table_schema` instead.
/// This is the sqlparser side, which those traits do not cover.
pub fn stored_identifier(value: &str, quoted: bool) -> alloc::borrow::Cow<'_, str> {
    sql_traits::utils::identifier_resolution::normalize_identifier(value, quoted)
}

/// Stored name of an identifier written in a policy expression.
pub fn stored_ident_name(ident: &sqlparser::ast::Ident) -> alloc::borrow::Cow<'_, str> {
    stored_identifier(&ident.value, ident.quote_style.is_some())
}

/// True when `name` is a SQL keyword that resolves to the current session role.
///
/// `session_user` is intentionally excluded: it does not follow `SET ROLE`.
/// `user` is intentionally excluded because it is parser-ambiguous with
/// user-defined function names and can produce false positives.
pub fn is_current_user_keyword_name(name: &str) -> bool {
    matches!(
        normalize_relation_name(name).as_str(),
        "current_user" | "current_role"
    )
}

/// Split a potentially schema-qualified name into `(schema, relation)`.
///
/// Handles dots inside quoted identifiers, e.g. `"my.schema"."table.name"`.
pub(crate) fn split_qualified_identifier_parts(name: &str) -> Vec<String> {
    let mut in_quotes = false;
    let mut start = 0usize;
    let mut parts: Vec<String> = Vec::new();
    let mut chars = name.char_indices().peekable();

    while let Some((idx, ch)) = chars.next() {
        match ch {
            '"' => {
                if in_quotes && chars.peek().is_some_and(|(_, next)| *next == '"') {
                    // Escaped quote inside a quoted identifier: "".
                    chars.next();
                    continue;
                }
                in_quotes = !in_quotes;
            }
            '.' if !in_quotes => {
                parts.push(name[start..idx].trim().to_string());
                start = idx + 1;
            }
            _ => {}
        }
    }
    parts.push(name[start..].trim().to_string());

    parts
}

/// Split a potentially schema-qualified name into `(schema, relation)`.
///
/// Handles dots inside quoted identifiers, e.g. `"my.schema"."table.name"`.
pub fn split_schema_and_relation(name: &str) -> Option<(String, String)> {
    let parts = split_qualified_identifier_parts(name);
    let [.., schema_part, relation_part] = parts.as_slice() else {
        return None;
    };
    let schema = unquote_identifier(schema_part).to_string();
    let relation = unquote_identifier(relation_part).to_string();
    Some((schema, relation))
}

/// Normalize an object name to its terminal relation/function identifier.
///
/// Examples:
/// - `"public.docs"` -> `"docs"`
/// - `"\"auth\".\"uid\""` -> `"uid"`
/// - `"CURRENT_USER"` -> `"current_user"`
pub fn normalize_relation_name(name: &str) -> String {
    if let Some((_, relation)) = split_schema_and_relation(name.trim()) {
        return normalize_identifier(&relation);
    }
    normalize_identifier(name)
}

/// Terminal lowercase identifier of a possibly schema-qualified function name.
pub fn normalized_function_name(func: &sqlparser::ast::Function) -> String {
    normalize_relation_name(&func.name.to_string())
}

/// Canonicalize a SQL object name to `[a-z0-9_]`, keeping the terminal relation
/// when schema-qualified. Falls back to `resource` when nothing survives.
pub fn canonical_fga_type_name(name: &str) -> String {
    let relation = if let Some((_, relation)) = split_schema_and_relation(name.trim()) {
        relation
    } else {
        unquote_identifier(name.trim()).to_string()
    };

    let mut normalized = String::with_capacity(relation.len());
    let mut previous_was_underscore = false;

    for ch in relation.chars() {
        let lower = ch.to_ascii_lowercase();
        if lower.is_ascii_alphanumeric() || lower == '_' {
            if lower == '_' {
                if previous_was_underscore {
                    continue;
                }
                previous_was_underscore = true;
            } else {
                previous_was_underscore = false;
            }
            normalized.push(lower);
        } else if !previous_was_underscore {
            normalized.push('_');
            previous_was_underscore = true;
        }
    }

    let trimmed = normalized.trim_matches('_').to_string();
    let canonical = if trimmed.is_empty() {
        "resource".to_string()
    } else {
        trimmed
    };

    if canonical
        .chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_digit())
    {
        return format!("t_{canonical}");
    }

    canonical
}

pub(crate) fn stable_hex_suffix(input: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{:08x}", (hash & 0xffff_ffff) as u32)
}

/// `OpenFGA` rejects a relation name longer than this.
pub const MAX_RELATION_NAME_LEN: usize = 50;

/// Shorten `name` to `OpenFGA`'s relation-name limit, keeping distinct names
/// distinct by ending an over-long one with a hash of the original.
///
/// Applies to relations only. Type names have a far larger limit and are left
/// alone, so a relation named after a long type is shortened while the type it
/// points at keeps its full name.
pub fn clamp_relation_name(name: String) -> String {
    if name.len() <= MAX_RELATION_NAME_LEN {
        return name;
    }
    let suffix = stable_hex_suffix(&name);
    let head: String = name
        .chars()
        .take(MAX_RELATION_NAME_LEN - suffix.len() - 1)
        .collect();
    format!("{head}_{suffix}")
}

/// How many times a colliding relation name yields before the crate stops looking.
///
/// The first yield is keyed on the value, so the only way it is taken too is something else
/// holding that exact name, which a schema can arrange. Bounded so such input cannot spin,
/// in the same spirit as the classifier's depth limit: each attempt appends a distinct
/// counter, so reaching this many needs that many engineered names rather than bad luck.
pub(crate) const MAX_RELATION_RENAME_ATTEMPTS: usize = 64;

/// Name for the `attempt`th yield of `base`, keyed on `key` so one value always yields one
/// name. Attempt zero is what a single rename produced, so a first collision reads as before.
pub(crate) fn yielded_relation_name(base: &str, key: &str, attempt: usize) -> String {
    let suffix = stable_hex_suffix(key);
    let candidate = if attempt == 0 {
        format!("{base}_{suffix}")
    } else {
        format!("{base}_{suffix}_{}", attempt + 1)
    };
    clamp_relation_name(candidate)
}

/// Derive a stable relation name used to scope a policy by `PostgreSQL` roles.
pub fn policy_scope_relation_name(policy_name: &str) -> String {
    scope_relation_name("scope", policy_name)
}

/// Derive a stable relation name used to scope reads of a membership table by
/// `PostgreSQL` roles.
pub fn membership_read_scope_relation_name(join_table: &str) -> String {
    scope_relation_name("read_scope", join_table)
}

/// Derive a stable relation name for the part of an action a role scoped
/// RESTRICTIVE policy binds.
pub fn role_limited_relation_name(policy_name: &str) -> String {
    scope_relation_name("limit", policy_name)
}

/// Derive a stable relation name for a guard the authorization service evaluates per
/// check rather than one the tuples decide.
pub fn conditional_gate_relation_name(policy_name: &str) -> String {
    scope_relation_name("gate", policy_name)
}

/// Derive the condition name that guard's relation reference points at.
///
/// Keyed on the type as well as the policy: a condition name is global to the model while
/// a `PostgreSQL` policy name is unique only per table, so one name reused across tables
/// would otherwise collapse two guards into one spec.
pub fn gate_condition_name(type_name: &str, policy_name: &str) -> String {
    // The base joins on an underscore to read as a name, which is ambiguous between
    // (a_b, c) and (a, b_c), so the hash joins on a dot instead. A type name is canonical
    // and so carries no dot, which makes that pair unambiguous.
    let base = canonical_fga_type_name(&format!("{type_name}_{policy_name}"));
    let suffix = stable_hex_suffix(&format!("{type_name}.{policy_name}"));
    clamp_relation_name(format!("when_{base}_{suffix}"))
}

fn scope_relation_name(prefix: &str, key: &str) -> String {
    let base = canonical_fga_type_name(key);
    let suffix = stable_hex_suffix(key);
    clamp_relation_name(format!("{prefix}_{base}_{suffix}"))
}

/// Infer the parent `OpenFGA` type from a foreign-key-like column name.
pub fn parent_type_from_fk_column(fk_column: &str) -> String {
    canonical_fga_type_name(fk_column.strip_suffix("_id").unwrap_or(fk_column))
}

/// True when the name looks like a public-visibility column.
///
/// Uses underscore-delimited word-boundary matching to avoid false positives on
/// names like `publication_id` (contains "public") or `is_invisible` (contains "visible").
pub fn is_public_flag_column_name(name: &str) -> bool {
    let lower = normalize_identifier(name);
    lower
        .split('_')
        .any(|token| matches!(token, "public" | "published" | "visible"))
}

/// True when the name looks like a user/owner column.
///
/// Uses underscore-delimited word-boundary matching to avoid false positives
/// on names like `abuser_id` (contains `user_id` as a substring).
pub fn is_user_related_column_name(name: &str) -> bool {
    let lower = normalize_identifier(name);
    let tokens: Vec<&str> = lower.split('_').collect();
    let has_user_id = has_token_pair(&tokens, "user", "id");
    let has_owner_id = has_token_pair(&tokens, "owner", "id");
    let has_created_by = has_token_pair(&tokens, "created", "by");
    let has_author_id = has_token_pair(&tokens, "author", "id");
    has_user_id || has_owner_id || has_created_by || has_author_id
}

/// True when the name looks like a direct ownership column.
///
/// Uses underscore-delimited word-boundary matching to avoid false positives
/// on names like `ownership_status` (contains "owner") or `abuser_id`
/// (contains `user_id` as substring).
pub fn is_owner_like_column_name(name: &str) -> bool {
    let lower = normalize_identifier(name);
    let tokens: Vec<&str> = lower.split('_').collect();
    // "owner" must appear as a complete token
    let has_owner = tokens.contains(&"owner");
    // "user_id" must be the last two tokens ("user", "id")
    let has_user_id = has_token_pair(&tokens, "user", "id");
    // "created_by" must appear as two consecutive tokens
    let has_created_by = has_token_pair(&tokens, "created", "by");
    // "author_id" is an exact match of the two-token form
    let has_author_id = has_token_pair(&tokens, "author", "id");
    has_owner || has_user_id || has_created_by || has_author_id
}

fn has_token_pair(tokens: &[&str], first: &str, second: &str) -> bool {
    tokens.windows(2).any(|w| w == [first, second])
}

/// Split a name a statement wrote into the target it denotes, keeping the quoting
/// of each part because that is what decides case sensitivity.
fn target_parts(name: &str) -> (Option<(String, bool)>, (String, bool)) {
    fn part(raw: &str) -> (String, bool) {
        let trimmed = raw.trim();
        let quoted = trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"');
        (unquote_identifier(trimmed).to_string(), quoted)
    }

    let parts = split_qualified_identifier_parts(name);
    match parts.as_slice() {
        [.., schema, relation] => (Some(part(schema)), part(relation)),
        [relation] => (None, part(relation)),
        [] => (None, (String::new(), false)),
    }
}

/// Resolve a name a statement wrote into the table it denotes, by `PostgreSQL`'s
/// rules: a qualified name matches exactly, and an unqualified one walks the search
/// path in order. An ambiguous name stays unresolved.
pub fn lookup_table<'db, DB>(
    db: &'db DB,
    name: &str,
) -> Option<&'db <DB as sql_traits::prelude::DatabaseLike>::Table>
where
    DB: sql_traits::prelude::DatabaseLike,
{
    let (schema, (relation, relation_quoted)) = target_parts(name);
    let target = sql_traits::structs::TargetName::new(&relation, relation_quoted);
    let target = match schema.as_ref() {
        Some((schema, quoted)) => target.with_schema(schema, *quoted),
        None => target,
    };
    db.resolve_target_table(target).ok().flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::sql_parser::{parse_schema, TableLike};

    fn resolved(sql: &str, spelling: &str) -> Option<(Option<String>, String)> {
        let db = parse_schema(sql).expect("the schema parses");
        lookup_table(&db, spelling).map(|table| {
            (
                table.table_schema().map(ToString::to_string),
                table.table_name().to_string(),
            )
        })
    }

    #[test]
    fn split_schema_and_relation_handles_quoted_dots() {
        assert_eq!(
            split_schema_and_relation(r#""my.schema"."table.name""#),
            Some(("my.schema".to_string(), "table.name".to_string()))
        );
    }

    #[test]
    fn unquote_identifier_decodes_escaped_quotes() {
        // Simple quoted identifier with no inner quotes.
        assert_eq!(unquote_identifier(r#""foo""#).as_ref(), "foo");

        // Double-quote escape: `"A""B"` → `A"B`
        assert_eq!(unquote_identifier(r#""A""B""#).as_ref(), r#"A"B"#);

        // Malformed (no closing quote) → returned unchanged.
        assert_eq!(unquote_identifier(r#""foo"#).as_ref(), r#""foo"#);

        // Unquoted identifier → returned unchanged.
        assert_eq!(unquote_identifier("foo").as_ref(), "foo");
    }

    #[test]
    fn stored_identifier_folds_only_unquoted_spellings() {
        assert_eq!(stored_identifier("Owner_Id", false), "owner_id");
        assert_eq!(stored_identifier("Owner_Id", true), "Owner_Id");

        // Both spellings can name distinct columns of one table, so folding a
        // quoted identifier would merge them.
        assert_ne!(
            stored_identifier("Owner_Id", true),
            stored_identifier("owner_id", false)
        );
    }

    #[test]
    fn stored_ident_name_follows_the_parsed_quote_style() {
        use sqlparser::ast::Ident;

        assert_eq!(stored_ident_name(&Ident::new("Owner_Id")), "owner_id");
        assert_eq!(
            stored_ident_name(&Ident::with_quote('"', "Owner_Id")),
            "Owner_Id"
        );
    }

    #[test]
    fn split_qualified_identifier_parts_handles_quoted_dots() {
        assert_eq!(
            split_qualified_identifier_parts(r#""my.schema"."table.name""#),
            vec!["\"my.schema\"".to_string(), "\"table.name\"".to_string()]
        );
    }

    #[test]
    fn split_qualified_identifier_parts_handles_escaped_quotes() {
        assert_eq!(
            split_qualified_identifier_parts(r#""a""b"."c.d""#),
            vec![r#""a""b""#.to_string(), r#""c.d""#.to_string()]
        );
        assert_eq!(
            split_qualified_identifier_parts(r#""a""b".c"#),
            vec![r#""a""b""#.to_string(), "c".to_string()]
        );
    }

    #[test]
    fn split_schema_and_relation_handles_escaped_quotes() {
        assert_eq!(
            split_schema_and_relation(r#""a""b"."c.d""#),
            Some((r#"a"b"#.to_string(), "c.d".to_string()))
        );
    }

    #[test]
    fn lookup_table_resolves_a_qualified_spelling_to_that_schema() {
        assert_eq!(
            resolved(
                "CREATE SCHEMA app; CREATE TABLE app.docs(id INT); CREATE TABLE docs(id INT);",
                "app.docs"
            ),
            Some((Some("app".to_string()), "docs".to_string()))
        );
    }

    #[test]
    fn lookup_table_walks_the_search_path_for_an_unqualified_spelling() {
        assert_eq!(
            resolved(
                "CREATE SCHEMA app; SET search_path TO app; CREATE TABLE docs(id INT);",
                "docs"
            ),
            Some((Some("app".to_string()), "docs".to_string())),
            "the path carries the name into the schema it selects"
        );
    }

    /// Two schemas hold the name and the path decides, in both directions. A table written
    /// unqualified is `public`, which the resolver treats as the schema-less one it models.
    #[test]
    fn lookup_table_lets_the_path_order_decide_between_two_schemas() {
        let schema = |path: &str| {
            format!(
                "CREATE SCHEMA app;\
                 CREATE TABLE docs(id INT);\
                 CREATE TABLE app.docs(id INT);\
                 SET search_path TO {path};"
            )
        };

        assert_eq!(
            resolved(&schema("app, public"), "docs"),
            Some((Some("app".to_string()), "docs".to_string()))
        );
        assert_eq!(
            resolved(&schema("public, app"), "docs"),
            Some((None, "docs".to_string())),
            "reversing the path must reverse the answer, or the order is not being read"
        );
    }

    #[test]
    fn lookup_table_answers_nothing_for_a_name_no_table_bears() {
        assert_eq!(resolved("CREATE TABLE other(id INT);", "docs"), None);
    }

    #[test]
    fn lookup_table_keeps_quoting_case_sensitive() {
        let sql = r#"CREATE TABLE "Doc Items"(id INT);"#;
        assert_eq!(
            resolved(sql, r#""Doc Items""#),
            Some((None, "Doc Items".to_string()))
        );
        assert_eq!(
            resolved(sql, r#""doc items""#),
            None,
            "a quoted spelling matches exactly, so a folded one must not"
        );
    }

    #[test]
    fn normalize_relation_name_handles_schema_quotes_and_case() {
        assert_eq!(normalize_relation_name("auth.uid"), "uid");
        assert_eq!(normalize_relation_name(r#""auth"."uid""#), "uid");
        assert_eq!(normalize_relation_name(r#""UID""#), "uid");
    }

    #[test]
    fn is_current_user_keyword_name_matches_supported_keywords_only() {
        assert!(is_current_user_keyword_name("current_user"));
        assert!(is_current_user_keyword_name("CURRENT_ROLE"));
        assert!(!is_current_user_keyword_name("user"));
        assert!(!is_current_user_keyword_name("session_user"));
        assert!(!is_current_user_keyword_name("my_current_user"));
    }

    #[test]
    fn ownership_and_public_name_heuristics_are_shared() {
        assert!(is_owner_like_column_name("Owner_ID"));
        assert!(is_user_related_column_name("created_by"));
        assert!(is_public_flag_column_name("is_public"));
        assert!(!is_public_flag_column_name("tenant_id"));
    }

    #[test]
    fn is_owner_like_column_name_uses_word_boundaries() {
        // Positive: exact token matches.
        assert!(is_owner_like_column_name("owner_id"));
        assert!(is_owner_like_column_name("owner"));
        assert!(is_owner_like_column_name("user_id"));
        assert!(is_owner_like_column_name("created_by"));
        assert!(is_owner_like_column_name("author_id"));
        assert!(is_owner_like_column_name("Owner_ID")); // case-insensitive

        // Negative: "owner" or "user_id" are substrings, not complete tokens.
        assert!(
            !is_owner_like_column_name("ownership_status"),
            "ownership_status should not match: 'ownership' ≠ 'owner'"
        );
        assert!(
            !is_owner_like_column_name("abuser_id"),
            "abuser_id should not match: 'abuser' breaks the user_id window"
        );
        // team_owner_flag DOES match because "owner" appears as a complete token.
        assert!(
            is_owner_like_column_name("team_owner_flag"),
            "team_owner_flag should match: 'owner' is a complete token"
        );
    }

    #[test]
    fn is_public_flag_column_name_uses_word_boundaries() {
        // Positive: exact word match after splitting on '_'.
        assert!(is_public_flag_column_name("is_public"));
        assert!(is_public_flag_column_name("public"));
        assert!(is_public_flag_column_name("is_published"));
        assert!(is_public_flag_column_name("is_visible"));
        assert!(is_public_flag_column_name("visible"));

        // Negative: "public" is a substring of the token, not the whole token.
        assert!(!is_public_flag_column_name("publication_id"));
        assert!(!is_public_flag_column_name("publicly_accessible")); // "publicly" ≠ "public"
        assert!(!is_public_flag_column_name("is_invisible")); // "invisible" ≠ "visible"
        assert!(!is_public_flag_column_name("republish_count")); // "republish" ≠ "published"
    }

    #[test]
    fn canonical_fga_type_name_normalizes_schema_quotes_and_special_chars() {
        assert_eq!(canonical_fga_type_name("public.docs"), "docs");
        assert_eq!(
            canonical_fga_type_name(r#""Auth"."User-Docs""#),
            "user_docs"
        );
        assert_eq!(canonical_fga_type_name("___"), "resource");
        assert_eq!(canonical_fga_type_name("123-items"), "t_123_items");
    }

    /// Callers name a relation or a type straight from this, with no emptiness check of
    /// their own, so a name that survives nothing has to come back as `resource`.
    #[test]
    fn canonical_fga_type_name_never_returns_an_empty_name() {
        for name in [
            "",
            "   ",
            "___",
            "---",
            ".",
            "\"\"",
            "public.",
            "\u{65e5}\u{672c}",
        ] {
            assert!(
                !canonical_fga_type_name(name).is_empty(),
                "canonical_fga_type_name({name:?}) must name something"
            );
        }
    }

    #[test]
    fn policy_scope_relation_name_is_stable_and_namespaced() {
        let first = policy_scope_relation_name("EditorsOnly");
        let second = policy_scope_relation_name("EditorsOnly");
        let third = policy_scope_relation_name("editors_only");

        assert_eq!(first, second);
        assert!(first.starts_with("scope_"));
        assert_ne!(first, third);
    }

    #[test]
    fn role_limited_relation_name_is_stable_and_clamped() {
        let first = role_limited_relation_name("DocsReview");

        assert_eq!(first, role_limited_relation_name("DocsReview"));
        assert!(first.starts_with("limit_"));
        assert_ne!(first, role_limited_relation_name("docs_review"));
        assert!(role_limited_relation_name(&"p".repeat(80)).len() <= MAX_RELATION_NAME_LEN);
    }

    #[test]
    fn parent_type_from_fk_column_handles_fk_suffix() {
        assert_eq!(parent_type_from_fk_column("project_id"), "project");
        assert_eq!(
            parent_type_from_fk_column("organization_uuid"),
            "organization_uuid"
        );
    }

    /// The readable base joins on an underscore, which cannot tell `(a_b, c)` from
    /// `(a, b_c)`. Two distinct guards mapping to one condition name is the whole defect
    /// this key exists to prevent, so the hash has to see the boundary.
    #[test]
    fn gate_condition_name_separates_a_type_from_a_policy() {
        assert_ne!(
            gate_condition_name("a_b", "c"),
            gate_condition_name("a", "b_c")
        );
        // Same policy name, two tables, which is the shape PostgreSQL allows freely.
        assert_ne!(
            gate_condition_name("campaigns", "visible_now"),
            gate_condition_name("embargoes", "visible_now")
        );
        // Stable, since it reaches the tuple SQL an operator reloads.
        assert_eq!(
            gate_condition_name("campaigns", "visible_now"),
            gate_condition_name("campaigns", "visible_now")
        );
    }
}

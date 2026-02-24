/// Return the identifier without surrounding double quotes.
pub fn unquote_identifier(ident: &str) -> &str {
    ident
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(ident)
}

/// Normalize an identifier for case-insensitive matching.
///
/// Trims whitespace, removes surrounding double quotes on a single identifier,
/// and lowercases the result.
pub fn normalize_identifier(ident: &str) -> String {
    unquote_identifier(ident.trim()).to_ascii_lowercase()
}

/// Split a potentially schema-qualified name into `(schema, relation)`.
///
/// Handles dots inside quoted identifiers, e.g. `"my.schema"."table.name"`.
pub fn split_schema_and_relation(name: &str) -> Option<(String, String)> {
    let mut in_quotes = false;
    let mut start = 0usize;
    let mut parts: Vec<&str> = Vec::new();

    for (idx, ch) in name.char_indices() {
        match ch {
            '"' => in_quotes = !in_quotes,
            '.' if !in_quotes => {
                parts.push(name[start..idx].trim());
                start = idx + 1;
            }
            _ => {}
        }
    }
    parts.push(name[start..].trim());

    if parts.len() < 2 {
        return None;
    }

    let schema = unquote_identifier(parts[parts.len() - 2]).to_string();
    let relation = unquote_identifier(parts[parts.len() - 1]).to_string();
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

/// Canonicalize a SQL object name into an `OpenFGA`-safe type identifier.
///
/// Rules:
/// - keep the terminal relation when schema-qualified
/// - lowercase ASCII
/// - replace non `[a-z0-9_]` with `_`
/// - collapse repeated `_`
/// - trim leading/trailing `_`
/// - if empty, return `"resource"`
/// - if starting with a digit, prefix with `"t_"`
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

/// True when the name looks like a public-visibility column.
pub fn is_public_flag_column_name(name: &str) -> bool {
    let lower = normalize_identifier(name);
    lower.contains("public") || lower.contains("published") || lower.contains("visible")
}

/// True when the name looks like a user/owner column.
pub fn is_user_related_column_name(name: &str) -> bool {
    let lower = normalize_identifier(name);
    lower.contains("user_id")
        || lower.contains("owner_id")
        || lower.contains("created_by")
        || lower == "author_id"
}

/// True when the name looks like a direct ownership column.
pub fn is_owner_like_column_name(name: &str) -> bool {
    let lower = normalize_identifier(name);
    lower.contains("owner")
        || lower.contains("created_by")
        || lower.contains("user_id")
        || lower == "author_id"
}

/// Build lookup candidates for schema-aware table resolution.
///
/// Ordered from most specific to least specific.
pub fn table_lookup_candidates(name: &str) -> Vec<(Option<String>, String)> {
    let mut candidates = Vec::new();

    if let Some((schema, relation)) = split_schema_and_relation(name) {
        candidates.push((Some(schema), relation.clone()));
        candidates.push((None, name.to_string()));
        candidates.push((None, relation));
    } else {
        candidates.push((None, name.to_string()));
    }

    let mut deduped = Vec::new();
    for candidate in candidates {
        if !deduped.contains(&candidate) {
            deduped.push(candidate);
        }
    }
    deduped
}

/// Resolve a table by trying schema-aware fallback candidates.
pub fn lookup_table<'db, DB>(
    db: &'db DB,
    name: &str,
) -> Option<&'db <DB as sql_traits::prelude::DatabaseLike>::Table>
where
    DB: sql_traits::prelude::DatabaseLike,
{
    table_lookup_candidates(name)
        .into_iter()
        .find_map(|(schema, relation)| db.table(schema.as_deref(), &relation))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_schema_and_relation_handles_quoted_dots() {
        assert_eq!(
            split_schema_and_relation(r#""my.schema"."table.name""#),
            Some(("my.schema".to_string(), "table.name".to_string()))
        );
    }

    #[test]
    fn table_lookup_candidates_prioritize_schema_then_fallbacks() {
        let candidates = table_lookup_candidates("app.docs");
        assert_eq!(
            candidates,
            vec![
                (Some("app".to_string()), "docs".to_string()),
                (None, "app.docs".to_string()),
                (None, "docs".to_string()),
            ]
        );
    }

    #[test]
    fn normalize_relation_name_handles_schema_quotes_and_case() {
        assert_eq!(normalize_relation_name("auth.uid"), "uid");
        assert_eq!(normalize_relation_name(r#""auth"."uid""#), "uid");
        assert_eq!(normalize_relation_name(r#""UID""#), "uid");
    }

    #[test]
    fn ownership_and_public_name_heuristics_are_shared() {
        assert!(is_owner_like_column_name("Owner_ID"));
        assert!(is_user_related_column_name("created_by"));
        assert!(is_public_flag_column_name("is_public"));
        assert!(!is_public_flag_column_name("tenant_id"));
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
}

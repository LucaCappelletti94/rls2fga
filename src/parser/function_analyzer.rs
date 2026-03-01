use serde::{Deserialize, Serialize};
use sqlparser::ast::{Expr, FunctionArguments, SelectItem, SetExpr, Statement, Value};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;
use std::collections::{HashMap, HashSet};

use crate::parser::expr::function_arg_expr;
use crate::parser::names::{
    is_current_user_keyword_name, normalized_function_name, split_schema_and_relation,
};

/// Semantic classification of a SQL function body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
#[allow(clippy::large_enum_variant)]
pub enum FunctionSemantic {
    /// A role-threshold function that returns an integer role level.
    /// Checks: direct ownership → team membership → explicit grants.
    #[serde(rename = "role_threshold")]
    RoleThreshold {
        /// Positional index of the user parameter in the function signature.
        user_param_index: usize,
        /// Positional index of the resource parameter in the function signature.
        resource_param_index: usize,
        /// Maps role name (e.g. `"viewer"`) to its integer level.
        role_levels: HashMap<String, i32>,
        /// Table that stores explicit role grants.
        grant_table: String,
        /// Column in `grant_table` identifying the grantee (user or team).
        grant_grantee_col: String,
        /// Column in `grant_table` identifying the target resource.
        grant_resource_col: String,
        /// Column in `grant_table` storing the integer role level.
        grant_role_col: String,
        /// Optional team-membership table for team-based grant resolution.
        #[serde(default)]
        team_membership_table: Option<String>,
        /// User column in the team-membership table.
        #[serde(default)]
        team_membership_user_col: Option<String>,
        /// Team column in the team-membership table.
        #[serde(default)]
        team_membership_team_col: Option<String>,
        /// Optional user principal table used for ownership/grant subject resolution.
        #[serde(default)]
        user_table: Option<String>,
        /// Primary-key column of `user_table`.
        #[serde(default)]
        user_pk_col: Option<String>,
        /// Optional team principal table used for ownership/grant subject resolution.
        #[serde(default)]
        team_table: Option<String>,
        /// Primary-key column of `team_table`.
        #[serde(default)]
        team_pk_col: Option<String>,
    },

    /// A function that returns the current authenticated user's ID.
    #[serde(rename = "current_user_accessor")]
    CurrentUserAccessor {
        /// SQL return type of the accessor (e.g. `"uuid"`).
        #[serde(default = "default_uuid")]
        returns: String,
    },

    /// A function that returns the current user's role name as a string.
    ///
    /// Typical example: Supabase `auth.role()` which returns `'authenticated'`,
    /// `'anon'`, or a custom role string.  Policies using this function compare
    /// the return value against string literals rather than integer levels.
    #[serde(rename = "role_accessor")]
    RoleAccessor {
        /// SQL return type of the accessor (e.g. `"text"`).
        #[serde(default = "default_text")]
        returns: String,
    },

    /// A function whose semantics could not be determined.
    #[serde(rename = "unknown")]
    Unknown {
        /// Explanation of why analysis failed.
        reason: String,
    },
}

fn default_text() -> String {
    "text".to_string()
}

fn default_uuid() -> String {
    "uuid".to_string()
}

fn normalize_setting_key(key: &str) -> String {
    key.trim().to_ascii_lowercase()
}

/// Settings controlling automatic current-user accessor inference from SQL bodies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessorInferenceSettings {
    current_user_setting_keys: HashSet<String>,
}

impl AccessorInferenceSettings {
    /// Build settings from an explicit list of allowed `current_setting` keys.
    pub fn from_keys<I, S>(keys: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let current_user_setting_keys = keys
            .into_iter()
            .map(|key| normalize_setting_key(key.as_ref()))
            .collect();
        Self {
            current_user_setting_keys,
        }
    }

    /// Allowed `current_setting` keys that can be inferred as current-user accessors.
    pub fn current_user_setting_keys(&self) -> &HashSet<String> {
        &self.current_user_setting_keys
    }

    fn allows_current_setting_key(&self, key: &str) -> bool {
        self.current_user_setting_keys
            .contains(&normalize_setting_key(key))
    }
}

impl Default for AccessorInferenceSettings {
    fn default() -> Self {
        Self::from_keys([
            "app.current_user_id",
            "app.user_id",
            "request.jwt.claim.sub",
            "request.jwt.claims",
        ])
    }
}

/// Returns `true` when the lowercase function body looks like a simple, direct
/// accessor expression — i.e. the body reduces to a single `current_setting(…)`
/// or `current_user` expression, optionally with a type cast.
///
/// Rejects bodies that contain DML or control-flow keywords, which indicate a
/// complex function that merely *references* `current_user` incidentally (e.g.
/// an audit trigger that writes `current_user` to a log table).
fn is_direct_accessor_body(body_lower: &str) -> bool {
    let sanitized = sanitize_sql_for_keyword_scan(body_lower);
    !contains_disallowed_complex_token(&sanitized)
}

fn is_dollar_tag_start_char(ch: char) -> bool {
    ch.is_ascii_alphabetic() || ch == '_'
}

fn is_dollar_tag_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

fn parse_dollar_quote_delimiter(chars: &[char], start: usize) -> Option<Vec<char>> {
    if chars.get(start) != Some(&'$') {
        return None;
    }

    // Untagged form: $$...$$
    if chars.get(start + 1) == Some(&'$') {
        return Some(vec!['$', '$']);
    }

    // Tagged form: $tag$...$tag$
    let first_tag_char = *chars.get(start + 1)?;
    if !is_dollar_tag_start_char(first_tag_char) {
        return None;
    }

    let mut idx = start + 2;
    while let Some(ch) = chars.get(idx) {
        if *ch == '$' {
            return Some(chars[start..=idx].to_vec());
        }
        if !is_dollar_tag_char(*ch) {
            return None;
        }
        idx += 1;
    }

    None
}

fn matches_at(chars: &[char], idx: usize, needle: &[char]) -> bool {
    chars
        .get(idx..idx.saturating_add(needle.len()))
        .is_some_and(|slice| slice == needle)
}

fn sanitize_sql_for_keyword_scan(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len());
    let chars: Vec<char> = sql.chars().collect();
    let mut i = 0usize;
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut in_line_comment = false;
    let mut block_comment_depth = 0usize;
    let mut dollar_delimiter: Option<Vec<char>> = None;

    while i < chars.len() {
        let ch = chars[i];
        if let Some(delim) = dollar_delimiter.as_ref() {
            if matches_at(&chars, i, delim) {
                out.extend(std::iter::repeat_n(' ', delim.len()));
                i += delim.len();
                dollar_delimiter = None;
                continue;
            }

            out.push(if ch == '\n' { '\n' } else { ' ' });
            i += 1;
            continue;
        }

        if in_single_quote {
            if ch == '\'' {
                // Escaped quote inside string literal: ''
                if chars.get(i + 1).is_some_and(|next| *next == '\'') {
                    out.push(' ');
                    out.push(' ');
                    i += 2;
                    continue;
                }
                in_single_quote = false;
                out.push(' ');
                i += 1;
                continue;
            }
            // Preserve token boundaries by replacing literal content with spaces.
            out.push(' ');
            i += 1;
            continue;
        }

        if in_double_quote {
            if ch == '"' {
                // Escaped quote inside quoted identifier: ""
                if chars.get(i + 1).is_some_and(|next| *next == '"') {
                    out.push(' ');
                    out.push(' ');
                    i += 2;
                    continue;
                }
                in_double_quote = false;
                out.push(' ');
                i += 1;
                continue;
            }
            out.push(' ');
            i += 1;
            continue;
        }

        if in_line_comment {
            if ch == '\n' {
                in_line_comment = false;
                out.push('\n');
            } else {
                out.push(' ');
            }
            i += 1;
            continue;
        }

        if block_comment_depth > 0 {
            if ch == '/' && chars.get(i + 1).is_some_and(|next| *next == '*') {
                block_comment_depth += 1;
                out.push(' ');
                out.push(' ');
                i += 2;
                continue;
            }

            if ch == '*' && chars.get(i + 1).is_some_and(|next| *next == '/') {
                block_comment_depth -= 1;
                out.push(' ');
                out.push(' ');
                i += 2;
                continue;
            }

            out.push(if ch == '\n' { '\n' } else { ' ' });
            i += 1;
            continue;
        }

        if ch == '-' && chars.get(i + 1).is_some_and(|next| *next == '-') {
            in_line_comment = true;
            out.push(' ');
            out.push(' ');
            i += 2;
            continue;
        }

        if ch == '/' && chars.get(i + 1).is_some_and(|next| *next == '*') {
            block_comment_depth = 1;
            out.push(' ');
            out.push(' ');
            i += 2;
            continue;
        }

        if ch == '\'' {
            in_single_quote = true;
            out.push(' ');
            i += 1;
            continue;
        }

        if ch == '"' {
            in_double_quote = true;
            out.push(' ');
            i += 1;
            continue;
        }

        if ch == '$' {
            if let Some(delim) = parse_dollar_quote_delimiter(&chars, i) {
                out.extend(std::iter::repeat_n(' ', delim.len()));
                i += delim.len();
                dollar_delimiter = Some(delim);
                continue;
            }
        }

        out.push(ch);
        i += 1;
    }

    out
}

fn is_identifier_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

fn is_current_user_keyword_for_body_scan(token: &str) -> bool {
    matches!(token, "current_user" | "current_role")
}

fn next_non_whitespace_char(sql: &str, start: usize) -> Option<char> {
    sql[start..].chars().find(|ch| !ch.is_whitespace())
}

fn scan_identifier_tokens<F>(sql: &str, mut on_token: F) -> bool
where
    F: FnMut(&str, usize, usize) -> bool,
{
    let mut token_start: Option<usize> = None;
    for (idx, ch) in sql.char_indices() {
        if is_identifier_char(ch) {
            if token_start.is_none() {
                token_start = Some(idx);
            }
            continue;
        }

        if let Some(start) = token_start.take() {
            if on_token(&sql[start..idx], start, idx) {
                return true;
            }
        }
    }

    token_start.is_some_and(|start| on_token(&sql[start..], start, sql.len()))
}

fn contains_identifier_token(sql: &str, target: &str) -> bool {
    scan_identifier_tokens(sql, |token, _start, _end| token == target)
}

fn contains_disallowed_complex_token(sql: &str) -> bool {
    const COMPLEX_TOKENS: &[&str] = &[
        "insert", "update", "delete", "from", "where", "join", "begin", "end", "if", "loop",
        "raise", "perform", "execute", "call", "create", "drop", "alter",
    ];
    scan_identifier_tokens(sql, |token, _start, _end| COMPLEX_TOKENS.contains(&token))
}

fn is_scalar_uuid_return_type(return_type_lower: &str) -> bool {
    if !contains_identifier_token(return_type_lower, "uuid") {
        return false;
    }

    // Reject collection/set-returning declarations.
    !return_type_lower.contains("[]")
        && !contains_identifier_token(return_type_lower, "array")
        && !contains_identifier_token(return_type_lower, "setof")
}

fn contains_current_user_keyword_token(sql: &str) -> bool {
    fn token_can_precede_expression_operand(token: &str) -> bool {
        matches!(
            token,
            "select"
                | "where"
                | "and"
                | "or"
                | "not"
                | "when"
                | "then"
                | "else"
                | "case"
                | "on"
                | "from"
                | "join"
                | "left"
                | "right"
                | "inner"
                | "outer"
                | "cross"
                | "full"
                | "having"
                | "group"
                | "order"
                | "by"
                | "limit"
                | "offset"
                | "return"
                | "returning"
                | "into"
                | "values"
                | "set"
                | "is"
                | "in"
                | "exists"
                | "distinct"
                | "all"
                | "any"
                | "some"
                | "union"
                | "intersect"
                | "except"
                | "null"
                | "true"
                | "false"
        )
    }

    fn only_whitespace_or_closing_parens(sql: &str, start: usize, end: usize) -> bool {
        sql[start..end]
            .chars()
            .all(|ch| ch.is_whitespace() || ch == ')')
    }

    let mut prev_token: Option<String> = None;
    let mut prev_end = 0usize;
    scan_identifier_tokens(sql, |token, start, end| {
        let is_accessor_keyword =
            is_current_user_keyword_for_body_scan(token) && is_current_user_keyword_name(token);
        let is_explicit_alias = prev_token.as_deref().is_some_and(|prev| prev == "as");
        let is_implicit_alias = is_accessor_keyword
            && prev_token
                .as_deref()
                .is_some_and(|prev| !token_can_precede_expression_operand(prev) && prev != "as")
            && only_whitespace_or_closing_parens(sql, prev_end, start);
        let matched = is_accessor_keyword && !is_explicit_alias && !is_implicit_alias;
        prev_token = Some(token.to_string());
        prev_end = end;
        matched
    })
}

fn contains_function_call_token(sql: &str, function_name: &str) -> bool {
    scan_identifier_tokens(sql, |token, _start, end| {
        token == function_name && next_non_whitespace_char(sql, end) == Some('(')
    })
}

fn contains_current_user_accessor_marker(body_lower: &str) -> bool {
    let sanitized = sanitize_sql_for_keyword_scan(body_lower);
    contains_function_call_token(&sanitized, "current_setting")
        || contains_current_user_keyword_token(&sanitized)
}

fn unwrap_accessor_expr(mut expr: &Expr) -> &Expr {
    loop {
        match expr {
            Expr::Cast { expr: inner, .. } | Expr::Nested(inner) => {
                expr = inner.as_ref();
            }
            _ => return expr,
        }
    }
}

fn current_setting_literal_key(expr: &Expr) -> Option<String> {
    let Expr::Function(func) = expr else {
        return None;
    };
    if normalized_function_name(func) != "current_setting" {
        return None;
    }
    let FunctionArguments::List(arg_list) = &func.args else {
        return None;
    };
    let [arg] = arg_list.args.as_slice() else {
        return None;
    };
    let arg_expr = function_arg_expr(arg)?;
    let Expr::Value(value) = arg_expr else {
        return None;
    };
    let Value::SingleQuotedString(key) = &value.value else {
        return None;
    };

    Some(normalize_setting_key(key))
}

fn is_direct_current_user_accessor_expr(expr: &Expr, settings: &AccessorInferenceSettings) -> bool {
    match unwrap_accessor_expr(expr) {
        Expr::Identifier(ident) => {
            ident.quote_style.is_none() && is_current_user_keyword_name(&ident.value)
        }
        Expr::Function(func) => {
            current_setting_literal_key(unwrap_accessor_expr(expr))
                .is_some_and(|key| settings.allows_current_setting_key(&key))
                || {
                    let normalized = normalized_function_name(func);
                    is_current_user_keyword_name(&normalized)
                        && split_schema_and_relation(&func.name.to_string()).is_none()
                        && matches!(func.args, FunctionArguments::None)
                }
        }
        _ => false,
    }
}

fn has_single_direct_accessor_expression(body: &str, settings: &AccessorInferenceSettings) -> bool {
    let Ok(statements) = Parser::parse_sql(&PostgreSqlDialect {}, body) else {
        return false;
    };
    let [statement] = statements.as_slice() else {
        return false;
    };
    let Statement::Query(query) = statement else {
        return false;
    };
    let SetExpr::Select(select) = query.body.as_ref() else {
        return false;
    };
    if select.projection.len() != 1 {
        return false;
    }

    let (SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. }) =
        &select.projection[0]
    else {
        return false;
    };

    is_direct_current_user_accessor_expr(expr, settings)
}

impl FunctionSemantic {
    /// Attempt to classify a function body by simple heuristic analysis with
    /// default accessor inference settings.
    pub fn analyze_body(body: &str, return_type: &str, language: &str) -> Option<FunctionSemantic> {
        let settings = AccessorInferenceSettings::default();
        Self::analyze_body_with_settings(body, return_type, language, &settings)
    }

    /// Attempt to classify a function body by simple heuristic analysis.
    /// Returns `None` if the function cannot be classified from its body alone.
    pub fn analyze_body_with_settings(
        body: &str,
        return_type: &str,
        _language: &str,
        settings: &AccessorInferenceSettings,
    ) -> Option<FunctionSemantic> {
        let body_lower = body.to_lowercase();
        let return_type_lower = return_type.to_lowercase();

        // Detect current_user accessor patterns.
        // Require the body to be a *direct* accessor expression, not a complex function
        // that merely references current_user/current_setting incidentally (e.g. audit
        // triggers or functions that record the caller but return a different value).
        if is_scalar_uuid_return_type(&return_type_lower)
            && contains_current_user_accessor_marker(&body_lower)
            && is_direct_accessor_body(&body_lower)
            && has_single_direct_accessor_expression(body, settings)
        {
            return Some(FunctionSemantic::CurrentUserAccessor {
                returns: "uuid".to_string(),
            });
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::{AccessorInferenceSettings, FunctionSemantic};
    use std::collections::HashMap;

    #[test]
    fn analyze_body_detects_current_user_accessor() {
        let semantic = FunctionSemantic::analyze_body(
            "SELECT current_setting('app.current_user_id')::uuid",
            "UUID",
            "sql",
        );

        assert!(matches!(
            semantic,
            Some(FunctionSemantic::CurrentUserAccessor { ref returns }) if returns == "uuid"
        ));
    }

    #[test]
    fn analyze_body_detects_direct_current_user_keyword_accessor() {
        let semantic = FunctionSemantic::analyze_body("SELECT current_user::uuid", "UUID", "sql");

        assert!(matches!(
            semantic,
            Some(FunctionSemantic::CurrentUserAccessor { ref returns }) if returns == "uuid"
        ));

        let semantic_role =
            FunctionSemantic::analyze_body("SELECT current_role::uuid", "UUID", "sql");
        assert!(matches!(
            semantic_role,
            Some(FunctionSemantic::CurrentUserAccessor { ref returns }) if returns == "uuid"
        ));
    }

    #[test]
    fn analyze_body_does_not_auto_classify_role_threshold() {
        let semantic = FunctionSemantic::analyze_body(
            "SELECT grant_level FROM grants WHERE user_id = $1",
            "integer",
            "sql",
        );

        assert!(
            semantic.is_none(),
            "role-threshold-like SQL should remain unclassified without explicit metadata"
        );
    }

    #[test]
    fn analyze_body_rejects_complex_body_that_incidentally_references_current_user() {
        // A PL/pgSQL audit function that writes current_user to a log table and
        // returns a UUID is NOT a current-user accessor.
        let audit_body = "
            INSERT INTO audit_log (table_name, performed_by)
            VALUES ($1, current_user);
            SELECT gen_random_uuid()::uuid;
        ";
        let semantic = FunctionSemantic::analyze_body(audit_body, "UUID", "plpgsql");
        assert!(
            semantic.is_none(),
            "complex body mentioning current_user should not be auto-classified as accessor"
        );

        // A function with a FROM clause is also too complex.
        let complex_body = "SELECT u.id FROM users u WHERE u.login = current_user LIMIT 1::uuid";
        let semantic2 = FunctionSemantic::analyze_body(complex_body, "UUID", "sql");
        assert!(
            semantic2.is_none(),
            "body with FROM clause should not be classified as accessor"
        );
    }

    #[test]
    fn analyze_body_accepts_accessor_when_literal_contains_keyword_substrings() {
        let settings = AccessorInferenceSettings::from_keys(["app.from_user_id"]);
        let semantic = FunctionSemantic::analyze_body_with_settings(
            "SELECT current_setting('app.from_user_id')::uuid",
            "UUID",
            "sql",
            &settings,
        );
        assert!(
            matches!(
                semantic,
                Some(FunctionSemantic::CurrentUserAccessor { ref returns }) if returns == "uuid"
            ),
            "keyword-like substrings inside literals should not trigger complex-body rejection"
        );
    }

    #[test]
    fn analyze_body_ignores_keyword_substrings_inside_literals() {
        let settings = AccessorInferenceSettings::from_keys(["custom.update_marker"]);
        let semantic = FunctionSemantic::analyze_body_with_settings(
            "SELECT current_setting('custom.update_marker')::uuid",
            "UUID",
            "sql",
            &settings,
        );
        assert!(
            matches!(
                semantic,
                Some(FunctionSemantic::CurrentUserAccessor { ref returns }) if returns == "uuid"
            ),
            "literal text containing update/from/etc must not be treated as SQL structure"
        );
    }

    #[test]
    fn analyze_body_rejects_comment_only_current_user_marker() {
        let semantic = FunctionSemantic::analyze_body(
            "SELECT gen_random_uuid()::uuid -- current_user marker in comment",
            "UUID",
            "sql",
        );
        assert!(
            semantic.is_none(),
            "current_user marker in SQL comments must not classify as accessor"
        );
    }

    #[test]
    fn analyze_body_rejects_nested_block_comment_current_user_marker() {
        let semantic = FunctionSemantic::analyze_body(
            "SELECT gen_random_uuid()::uuid /* outer /* inner */ current_user */",
            "UUID",
            "sql",
        );
        assert!(
            semantic.is_none(),
            "nested block-comment marker must not classify as accessor"
        );
    }

    #[test]
    fn analyze_body_rejects_literal_only_current_user_marker() {
        let semantic = FunctionSemantic::analyze_body(
            "SELECT '-- current_user marker in literal only'::uuid",
            "UUID",
            "sql",
        );
        assert!(
            semantic.is_none(),
            "current_user marker in string literals must not classify as accessor"
        );
    }

    #[test]
    fn analyze_body_rejects_alias_named_user() {
        let semantic =
            FunctionSemantic::analyze_body("SELECT gen_random_uuid()::uuid AS user", "UUID", "sql");
        assert!(
            semantic.is_none(),
            "identifier token `user` used as an alias must not classify as accessor"
        );
    }

    #[test]
    fn analyze_body_rejects_alias_named_current_user_or_current_role() {
        let alias_current_user = FunctionSemantic::analyze_body(
            "SELECT gen_random_uuid()::uuid AS current_user",
            "UUID",
            "sql",
        );
        assert!(
            alias_current_user.is_none(),
            "alias named current_user must not classify as accessor"
        );

        let alias_current_role = FunctionSemantic::analyze_body(
            "SELECT gen_random_uuid()::uuid AS current_role",
            "UUID",
            "sql",
        );
        assert!(
            alias_current_role.is_none(),
            "alias named current_role must not classify as accessor"
        );
    }

    #[test]
    fn analyze_body_rejects_alias_without_as_named_current_user_or_current_role() {
        let alias_current_user = FunctionSemantic::analyze_body(
            "SELECT gen_random_uuid()::uuid current_user",
            "UUID",
            "sql",
        );
        assert!(
            alias_current_user.is_none(),
            "implicit alias named current_user must not classify as accessor"
        );

        let alias_current_role = FunctionSemantic::analyze_body(
            "SELECT gen_random_uuid()::uuid current_role",
            "UUID",
            "sql",
        );
        assert!(
            alias_current_role.is_none(),
            "implicit alias named current_role must not classify as accessor"
        );
    }

    #[test]
    fn analyze_body_does_not_treat_user_keyword_as_accessor_marker() {
        let semantic = FunctionSemantic::analyze_body("SELECT user::uuid", "UUID", "sql");
        assert!(
            semantic.is_none(),
            "`user` keyword is too ambiguous to auto-classify as current-user accessor"
        );
    }

    #[test]
    fn analyze_body_rejects_non_direct_current_user_expressions() {
        let case_expr = FunctionSemantic::analyze_body(
            "SELECT CASE WHEN TRUE THEN current_user::uuid ELSE gen_random_uuid() END",
            "UUID",
            "sql",
        );
        assert!(
            case_expr.is_none(),
            "CASE expression containing current_user must not classify as direct accessor"
        );

        let coalesce_expr = FunctionSemantic::analyze_body(
            "SELECT COALESCE(current_user::uuid, gen_random_uuid())",
            "UUID",
            "sql",
        );
        assert!(
            coalesce_expr.is_none(),
            "COALESCE expression containing current_user must not classify as direct accessor"
        );

        let concat_expr = FunctionSemantic::analyze_body(
            "SELECT (current_user::uuid || '')::uuid",
            "UUID",
            "sql",
        );
        assert!(
            concat_expr.is_none(),
            "composed expressions around current_user must not classify as direct accessor"
        );
    }

    #[test]
    fn analyze_body_rejects_dollar_quoted_literal_only_current_user_marker() {
        let untagged =
            FunctionSemantic::analyze_body("SELECT $$ current_user $$::uuid", "UUID", "sql");
        assert!(
            untagged.is_none(),
            "current_user marker in untagged dollar-quoted literals must not classify as accessor"
        );

        let tagged = FunctionSemantic::analyze_body(
            "SELECT $tag$current_setting('app.current_user_id')$tag$::uuid",
            "UUID",
            "sql",
        );
        assert!(
            tagged.is_none(),
            "current_setting marker in tagged dollar-quoted literals must not classify as accessor"
        );
    }

    #[test]
    fn analyze_body_rejects_identifier_substring_current_user_marker() {
        let semantic =
            FunctionSemantic::analyze_body("SELECT my_current_user_token::uuid", "UUID", "sql");
        assert!(
            semantic.is_none(),
            "identifier substrings like my_current_user_token are not accessor markers"
        );
    }

    #[test]
    fn analyze_body_rejects_non_allowlisted_current_setting_key_by_default() {
        let semantic = FunctionSemantic::analyze_body(
            "SELECT current_setting('timezone')::uuid",
            "UUID",
            "sql",
        );
        assert!(
            semantic.is_none(),
            "non-allowlisted current_setting keys must not be inferred as current-user accessors"
        );
    }

    #[test]
    fn analyze_body_with_settings_accepts_custom_allowlisted_current_setting_key() {
        let settings = AccessorInferenceSettings::from_keys(["tenant.current_user_uuid"]);
        let semantic = FunctionSemantic::analyze_body_with_settings(
            "SELECT current_setting('tenant.current_user_uuid')::uuid",
            "UUID",
            "sql",
            &settings,
        );
        assert!(
            matches!(
                semantic,
                Some(FunctionSemantic::CurrentUserAccessor { ref returns }) if returns == "uuid"
            ),
            "custom allowlisted key should be inferred as current-user accessor"
        );
    }

    #[test]
    fn analyze_body_rejects_non_literal_current_setting_argument() {
        let semantic = FunctionSemantic::analyze_body(
            "SELECT current_setting(app.current_user_id)::uuid",
            "UUID",
            "sql",
        );
        assert!(
            semantic.is_none(),
            "non-literal current_setting arguments must not be inferred as current-user accessors"
        );
    }

    #[test]
    fn analyze_body_rejects_uuid_array_return_type_for_accessor() {
        let semantic = FunctionSemantic::analyze_body(
            "SELECT current_setting('app.current_user_id')::uuid[]",
            "UUID[]",
            "sql",
        );
        assert!(
            semantic.is_none(),
            "array return types must not be inferred as scalar current-user accessors"
        );
    }

    #[test]
    fn analyze_body_rejects_setof_uuid_return_type_for_accessor() {
        let semantic = FunctionSemantic::analyze_body(
            "SELECT current_setting('app.current_user_id')::uuid",
            "SETOF UUID",
            "sql",
        );
        assert!(
            semantic.is_none(),
            "set-returning declarations must not be inferred as scalar current-user accessors"
        );
    }

    #[test]
    fn analyze_body_accepts_direct_accessor_with_keyword_substring_alias() {
        let semantic = FunctionSemantic::analyze_body(
            "SELECT current_setting('app.current_user_id')::uuid AS from_id",
            "UUID",
            "sql",
        );
        assert!(
            matches!(
                semantic,
                Some(FunctionSemantic::CurrentUserAccessor { ref returns }) if returns == "uuid"
            ),
            "token-aware complexity scan should not reject direct accessors aliased as from_id"
        );
    }

    #[test]
    fn current_user_accessor_default_return_type_deserializes_to_uuid() {
        let semantic: FunctionSemantic = serde_json::from_str(
            r#"{
  "kind": "current_user_accessor"
}"#,
        )
        .expect("semantic json should parse");

        assert!(matches!(
            semantic,
            FunctionSemantic::CurrentUserAccessor { ref returns } if returns == "uuid"
        ));
    }

    #[test]
    fn role_threshold_semantic_round_trips_with_all_fields() {
        let semantic = FunctionSemantic::RoleThreshold {
            user_param_index: 0,
            resource_param_index: 1,
            role_levels: HashMap::from([("viewer".to_string(), 1), ("editor".to_string(), 2)]),
            grant_table: "object_grants".to_string(),
            grant_grantee_col: "grantee_id".to_string(),
            grant_resource_col: "resource_id".to_string(),
            grant_role_col: "role_level".to_string(),
            team_membership_table: Some("team_memberships".to_string()),
            team_membership_user_col: Some("user_id".to_string()),
            team_membership_team_col: Some("team_id".to_string()),
            user_table: Some("users".to_string()),
            user_pk_col: Some("id".to_string()),
            team_table: Some("teams".to_string()),
            team_pk_col: Some("id".to_string()),
        };

        let json = serde_json::to_string(&semantic).expect("semantic should serialize");
        let parsed: FunctionSemantic =
            serde_json::from_str(&json).expect("semantic should deserialize");

        assert!(matches!(
            parsed,
            FunctionSemantic::RoleThreshold {
                team_membership_table: Some(ref table),
                team_membership_user_col: Some(ref user_col),
                team_membership_team_col: Some(ref team_col),
                user_table: Some(ref user_table),
                user_pk_col: Some(ref user_pk_col),
                team_table: Some(ref team_table),
                team_pk_col: Some(ref team_pk_col),
                ..
            } if table == "team_memberships"
                && user_col == "user_id"
                && team_col == "team_id"
                && user_table == "users"
                && user_pk_col == "id"
                && team_table == "teams"
                && team_pk_col == "id"
        ));
    }
}

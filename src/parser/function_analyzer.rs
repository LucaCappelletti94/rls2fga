#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use alloc::collections::BTreeMap;
use serde::{Deserialize, Serialize};
use sqlparser::ast::{
    Expr, FunctionArguments, FunctionSecurity, SelectItem, SetExpr, Statement, Value,
};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;

use crate::classifier::function_registry::{SessionAttribute, SessionAttributeKind};
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
        role_levels: BTreeMap<String, i32>,
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

    /// A function whose whole body reads one `current_setting` key, so calling it is
    /// calling that key and the two spellings are one declaration.
    #[serde(rename = "setting_reader")]
    SettingReader {
        /// The key the body reads.
        key: String,
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

pub(crate) fn normalize_setting_key(key: &str) -> String {
    key.trim().to_ascii_lowercase()
}

/// The request-scoped values a deployment declared readable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessorInferenceSettings {
    session_attributes: Vec<SessionAttribute>,
}

impl AccessorInferenceSettings {
    /// Build settings naming these keys as holding the caller's identity.
    pub fn from_keys<I, S>(keys: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self::from_attributes(
            keys.into_iter()
                .map(|key| SessionAttribute::setting(key, SessionAttributeKind::CallerId)),
        )
    }

    /// Build settings from explicit declarations of any kind.
    pub fn from_attributes<I>(attributes: I) -> Self
    where
        I: IntoIterator<Item = SessionAttribute>,
    {
        Self {
            session_attributes: attributes.into_iter().collect(),
        }
    }

    /// Every declared source, whether the call sits inline in a policy or is the whole
    /// body of a function the policy calls.
    pub fn session_attributes(&self) -> &[SessionAttribute] {
        &self.session_attributes
    }

    fn allows_current_setting_key(&self, key: &str) -> bool {
        let key = normalize_setting_key(key);
        self.session_attributes.iter().any(|attribute| {
            attribute.kind() == SessionAttributeKind::CallerId
                && attribute.path().is_empty()
                && attribute.setting_key() == key
        })
    }

    /// True when a deployment declared the value at `key` readable at all, whatever kind
    /// it named. A wrapper function around such a key resolves to it.
    pub(crate) fn declares_setting_key(&self, key: &str) -> bool {
        let key = normalize_setting_key(key);
        self.session_attributes
            .iter()
            .any(|attribute| attribute.setting_key() == key)
    }
}

impl Default for AccessorInferenceSettings {
    /// The keys whose value is the caller's identity.
    ///
    /// `request.jwt.claim.sub` holds one identity, which is what `PostgREST` sets it to.
    /// `request.jwt.claims` holds the whole token, so its value names nobody.
    fn default() -> Self {
        Self::from_keys([
            "app.current_user_id",
            "app.user_id",
            "request.jwt.claim.sub",
        ])
    }
}

/// Returns `true` when the lowercase function body looks like a simple, direct
/// accessor expression: i.e. the body reduces to a single `current_setting(…)`
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
            return chars.get(start..=idx).map(<[char]>::to_vec);
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
        let Some(&ch) = chars.get(i) else {
            break;
        };
        if let Some(delim) = dollar_delimiter.as_ref() {
            if matches_at(&chars, i, delim) {
                out.extend(core::iter::repeat_n(' ', delim.len()));
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
                out.extend(core::iter::repeat_n(' ', delim.len()));
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

/// True when the declaration returns one value that can name the caller.
///
/// Not a collection and not a set: those are many identities, not one. Not a document
/// either: `sub` inside a token is an identity and so is `tenant`, and a body that hands
/// back the whole token leaves nothing to say which of them the caller is.
fn returns_one_identity(return_type_lower: &str) -> bool {
    if return_type_lower.trim().is_empty() {
        return false;
    }

    // `TABLE(...)` reaches here as `"table"`, carrying no `setof` token to notice.
    !return_type_lower.contains("[]")
        && !contains_identifier_token(return_type_lower, "array")
        && !contains_identifier_token(return_type_lower, "setof")
        && !contains_identifier_token(return_type_lower, "table")
        && !contains_identifier_token(return_type_lower, "json")
        && !contains_identifier_token(return_type_lower, "jsonb")
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

/// Extract the literal setting key from `current_setting('key')` or
/// `current_setting('key', missing_ok)`.
///
/// The two-argument form returns NULL instead of raising when the key is unset.
/// That only makes the policy deny (a NULL comparison is never true), so the key
/// identifies the current user exactly as in the one-argument form.
pub(crate) fn current_setting_literal_key(expr: &Expr) -> Option<String> {
    let Expr::Function(func) = expr else {
        return None;
    };
    if normalized_function_name(func) != "current_setting" {
        return None;
    }
    let FunctionArguments::List(arg_list) = &func.args else {
        return None;
    };
    let ([arg] | [arg, _]) = arg_list.args.as_slice() else {
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

/// The single expression a one-statement `SELECT` body projects.
///
/// The one place a body is unwrapped to its expression, so a rule applied to one reader
/// cannot be dropped by another.
fn body_single_projection(body: &str) -> Option<Expr> {
    let statements = Parser::parse_sql(&PostgreSqlDialect {}, body).ok()?;
    let [Statement::Query(query)] = statements.as_slice() else {
        return None;
    };
    let SetExpr::Select(select) = query.body.as_ref() else {
        return None;
    };
    let [SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. }] =
        select.projection.as_slice()
    else {
        return None;
    };
    Some(expr.clone())
}

fn has_single_direct_accessor_expression(body: &str, settings: &AccessorInferenceSettings) -> bool {
    body_single_projection(body)
        .is_some_and(|expr| is_direct_current_user_accessor_expr(&expr, settings))
}

/// The `current_setting` key a whole body reads, so a call to the function is a call to
/// that key.
pub(crate) fn body_setting_key(body: &str) -> Option<String> {
    let expr = body_single_projection(body)?;
    current_setting_literal_key(unwrap_accessor_expr(&expr))
}

impl FunctionSemantic {
    /// Attempt to classify a function body by simple heuristic analysis with
    /// default accessor inference settings, as `SECURITY INVOKER`.
    pub fn analyze_body(body: &str, return_type: &str, language: &str) -> Option<FunctionSemantic> {
        let settings = AccessorInferenceSettings::default();
        Self::analyze_body_with_settings(
            body,
            return_type,
            language,
            &FunctionSecurity::Invoker,
            &settings,
        )
    }

    /// Attempt to classify a function body by simple heuristic analysis.
    pub fn analyze_body_with_settings(
        body: &str,
        return_type: &str,
        _language: &str,
        security: &FunctionSecurity,
        settings: &AccessorInferenceSettings,
    ) -> Option<FunctionSemantic> {
        let body_lower = body.to_lowercase();
        let return_type_lower = return_type.to_lowercase();

        // Detect current_user accessor patterns.
        // Require the body to be a *direct* accessor expression, not a complex function
        // that merely references current_user/current_setting incidentally (e.g. audit
        // triggers or functions that record the caller but return a different value).
        if returns_one_identity(&return_type_lower)
            && contains_current_user_accessor_marker(&body_lower)
            && is_direct_accessor_body(&body_lower)
            && has_single_direct_accessor_expression(body, settings)
            && !runs_as_owner_reading_effective_user(&body_lower, security)
        {
            return Some(FunctionSemantic::CurrentUserAccessor {
                returns: return_type_lower.trim().to_string(),
            });
        }

        None
    }
}

/// True when the body identifies its caller through `current_user` or `current_role`
/// but runs as the owner, which makes that value the owner's for every caller.
///
/// A session setting is per session, so a `current_setting` body is unaffected.
fn runs_as_owner_reading_effective_user(body_lower: &str, security: &FunctionSecurity) -> bool {
    matches!(security, FunctionSecurity::Definer)
        && contains_current_user_keyword_token(&sanitize_sql_for_keyword_scan(body_lower))
}

#[cfg(test)]
mod tests {
    use super::{AccessorInferenceSettings, FunctionSecurity, FunctionSemantic};
    use alloc::collections::BTreeMap;

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
    fn analyze_body_rejects_the_keyword_accessor_when_the_function_runs_as_its_owner() {
        let settings = AccessorInferenceSettings::default();
        for body in ["SELECT current_user::uuid", "SELECT CURRENT_USER::uuid"] {
            let semantic = FunctionSemantic::analyze_body_with_settings(
                body,
                "UUID",
                "sql",
                &FunctionSecurity::Definer,
                &settings,
            );
            assert!(
                semantic.is_none(),
                "a definer body returns the owner's name, not the caller's, for {body}"
            );
        }

        let setting_body = FunctionSemantic::analyze_body_with_settings(
            "SELECT current_setting('app.current_user_id')::uuid",
            "UUID",
            "sql",
            &FunctionSecurity::Definer,
            &settings,
        );
        assert!(
            matches!(
                setting_body,
                Some(FunctionSemantic::CurrentUserAccessor { ref returns }) if returns == "uuid"
            ),
            "a session setting is per session, so the security mode cannot change it"
        );
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
            &FunctionSecurity::Invoker,
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
            &FunctionSecurity::Invoker,
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
            &FunctionSecurity::Invoker,
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

    /// The declared type is recorded, not assumed: a text identity is at least as
    /// common as a UUID one.
    #[test]
    fn analyze_body_records_the_declared_return_type() {
        let semantic = FunctionSemantic::analyze_body(
            "SELECT current_setting('app.user_id', true)",
            "TEXT",
            "sql",
        );

        assert!(
            matches!(
                semantic,
                Some(FunctionSemantic::CurrentUserAccessor { ref returns }) if returns == "text"
            ),
            "the accessor carries the type it was declared with, got: {semantic:?}"
        );
    }

    /// A declaration that says nothing says nothing about identifying the caller, and
    /// `return_type_name` answers nothing for a body with no declared return.
    #[test]
    fn analyze_body_rejects_an_absent_return_type() {
        let semantic = FunctionSemantic::analyze_body(
            "SELECT current_setting('app.user_id', true)",
            "",
            "sql",
        );

        assert!(
            semantic.is_none(),
            "an undeclared return type is not a scalar identity, got: {semantic:?}"
        );
    }

    /// A row is not one identity. `RETURNS TABLE(...)` reaches here as `"TABLE"`, which
    /// carries no `setof` token to notice.
    #[test]
    fn analyze_body_rejects_a_row_returning_declaration() {
        for declaration in ["TABLE", "TABLE(id TEXT)", "SETOF TEXT", "TEXT[]"] {
            let semantic = FunctionSemantic::analyze_body(
                "SELECT current_setting('app.user_id', true)",
                declaration,
                "sql",
            );

            assert!(
                semantic.is_none(),
                "`RETURNS {declaration}` is not one identity, got: {semantic:?}"
            );
        }
    }

    /// A body handing back the whole login token names nobody: the identity is one field
    /// of it, and the declaration does not say which.
    #[test]
    fn analyze_body_rejects_a_document_returning_declaration() {
        for declaration in ["JSON", "JSONB"] {
            let semantic = FunctionSemantic::analyze_body(
                "SELECT current_setting('app.user_id', true)::jsonb",
                declaration,
                "sql",
            );

            assert!(
                semantic.is_none(),
                "`RETURNS {declaration}` is a document, not an identity, got: {semantic:?}"
            );
        }
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
            role_levels: BTreeMap::from([("viewer".to_string(), 1), ("editor".to_string(), 2)]),
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

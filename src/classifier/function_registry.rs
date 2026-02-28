use std::collections::{HashMap, HashSet};

use crate::parser::function_analyzer::FunctionSemantic;
use crate::parser::names::{
    normalize_identifier, normalize_relation_name, split_schema_and_relation,
};
use crate::parser::sql_parser::{DatabaseLike, FunctionLike, ParserDB};

/// Registry of known function semantics, loaded from JSON or analyzed from bodies.
#[derive(Debug, Clone)]
pub struct FunctionRegistry {
    /// Function name → semantic classification lookup table.
    pub(crate) functions: HashMap<String, FunctionSemantic>,
    /// Explicitly registered public-flag column names (normalized to lowercase).
    ///
    /// When non-empty, only these columns will produce a high-confidence (A) `P6BooleanFlag`
    /// classification.  Columns that match the heuristic (`is_public_flag_column_name`) but
    /// are *not* in this set receive `ConfidenceLevel::B` instead, signalling that manual
    /// review is recommended before granting wildcard public access.
    ///
    /// When empty (the default), all heuristic matches receive `ConfidenceLevel::B` —
    /// ensuring that implicit public-access grants always surface for review.
    pub(crate) public_flag_columns: HashSet<String>,
}

impl FunctionRegistry {
    fn normalized_function_keys(name: &str) -> Vec<String> {
        let mut keys = vec![normalize_identifier(
            &crate::parser::names::unquote_identifier(name),
        )];

        if let Some((schema, relation)) = split_schema_and_relation(name) {
            keys.push(format!(
                "{}.{}",
                normalize_identifier(&schema),
                normalize_identifier(&relation)
            ));
            keys.push(normalize_relation_name(&relation));
        } else {
            keys.push(normalize_relation_name(name));
        }

        keys.sort();
        keys.dedup();
        keys
    }

    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            functions: HashMap::new(),
            public_flag_columns: HashSet::new(),
        }
    }

    /// Register a column name as a confirmed public-flag column (e.g. `"is_public"`).
    ///
    /// Registered columns produce a `P6BooleanFlag` at `ConfidenceLevel::A`.
    /// Unregistered columns that match the name heuristic still produce `P6BooleanFlag`
    /// but at `ConfidenceLevel::B` to encourage manual review.
    pub fn register_public_flag_column(&mut self, column: impl Into<String>) {
        self.public_flag_columns
            .insert(normalize_identifier(&column.into()));
    }

    /// True when `column` is an explicitly registered public-flag column.
    pub(crate) fn is_confirmed_public_flag_column(&self, column: &str) -> bool {
        self.public_flag_columns
            .contains(&normalize_identifier(column))
    }

    /// Load function semantics from a JSON string.
    pub fn load_from_json(&mut self, json: &str) -> Result<(), String> {
        let parsed: HashMap<String, FunctionSemantic> = serde_json::from_str(json)
            .map_err(|e| format!("Invalid function registry JSON: {e}"))?;
        // Registry takes precedence over analyzed functions
        for (name, semantic) in parsed {
            for key in Self::normalized_function_keys(&name) {
                self.functions.insert(key, semantic.clone());
            }
        }
        Ok(())
    }

    /// Get the semantic for a function by name.
    pub fn get(&self, name: &str) -> Option<&FunctionSemantic> {
        Self::normalized_function_keys(name)
            .into_iter()
            .find_map(|key| self.functions.get(&key))
    }

    /// Register a function semantic (analyzed results, won't overwrite registry entries).
    pub fn register_if_absent(&mut self, name: &str, semantic: &FunctionSemantic) {
        for key in Self::normalized_function_keys(name) {
            self.functions
                .entry(key)
                .or_insert_with(|| semantic.clone());
        }
    }

    /// Check if a function is a known role-threshold function.
    pub fn is_role_threshold(&self, name: &str) -> bool {
        matches!(self.get(name), Some(FunctionSemantic::RoleThreshold { .. }))
    }

    /// Check if a function is a current-user accessor.
    pub fn is_current_user_accessor(&self, name: &str) -> bool {
        matches!(
            self.get(name),
            Some(FunctionSemantic::CurrentUserAccessor { .. })
        )
    }

    /// Check if a function is a role-name accessor (returns the current user's role as a string).
    pub fn is_role_accessor(&self, name: &str) -> bool {
        matches!(self.get(name), Some(FunctionSemantic::RoleAccessor { .. }))
    }

    /// Infer function semantics from parsed in-schema function bodies.
    /// Explicitly provided registry entries take precedence.
    pub fn enrich_from_schema(&mut self, db: &ParserDB) {
        for function in db.functions() {
            let Some(body) = function.body() else {
                continue;
            };
            let return_type = function
                .return_type
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_default();
            if let Some(semantic) = FunctionSemantic::analyze_body(body, &return_type, "sql") {
                self.register_if_absent(function.name(), &semantic);
            }
        }
    }
}

impl Default for FunctionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::sql_parser::parse_schema;

    #[test]
    fn load_from_json_reports_invalid_payload() {
        let mut registry = FunctionRegistry::new();
        let err = registry
            .load_from_json("{not-valid-json")
            .expect_err("invalid json should fail");
        assert!(err.contains("Invalid function registry JSON"));
    }

    #[test]
    fn enrich_from_schema_infers_known_semantics_only() {
        let sql = r"
CREATE FUNCTION current_tenant_id() RETURNS UUID
  LANGUAGE sql STABLE
  AS 'SELECT current_setting(''app.current_user_id'')::uuid';

CREATE FUNCTION opaque_lookup() RETURNS TEXT
  LANGUAGE sql STABLE
  AS 'SELECT ''noop''::text';
";
        let db = parse_schema(sql).expect("schema should parse");

        let mut registry = FunctionRegistry::new();
        registry.enrich_from_schema(&db);

        assert!(registry.is_current_user_accessor("current_tenant_id"));
        assert!(
            registry.get("opaque_lookup").is_none(),
            "non-recognized function should not be registered"
        );
    }

    #[test]
    fn default_registry_is_empty() {
        let registry = FunctionRegistry::default();
        assert!(registry.functions.is_empty());
    }

    #[test]
    fn enrich_from_schema_skips_functions_without_body() {
        let sql = r"
CREATE FUNCTION declared_only() RETURNS UUID LANGUAGE SQL;

CREATE FUNCTION current_tenant_id() RETURNS UUID
  LANGUAGE sql STABLE
  AS 'SELECT current_setting(''app.current_user_id'')::uuid';
";
        let db = parse_schema(sql).expect("schema should parse");

        let mut registry = FunctionRegistry::new();
        registry.enrich_from_schema(&db);

        assert!(
            registry.get("declared_only").is_none(),
            "functions without bodies should be ignored"
        );
        assert!(registry.is_current_user_accessor("current_tenant_id"));
    }

    #[test]
    fn function_lookup_normalizes_schema_and_quotes() {
        let mut registry = FunctionRegistry::new();
        registry.register_if_absent(
            r#""auth"."uid""#,
            &FunctionSemantic::CurrentUserAccessor {
                returns: "uuid".to_string(),
            },
        );

        assert!(registry.is_current_user_accessor("auth.uid"));
        assert!(registry.is_current_user_accessor(r#""auth"."uid""#));
        assert!(registry.is_current_user_accessor("UID"));
    }
}

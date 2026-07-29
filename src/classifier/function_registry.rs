#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use alloc::collections::{BTreeMap, BTreeSet};

use crate::parser::function_analyzer::{AccessorInferenceSettings, FunctionSemantic};
use crate::parser::names::{
    normalize_identifier, normalize_relation_name, split_schema_and_relation,
};
use crate::parser::sql_parser::{DatabaseLike, FunctionLike, ParserDB};

/// Registry of known function semantics, loaded from JSON or analyzed from bodies.
#[derive(Debug, Clone)]
pub struct FunctionRegistry {
    pub(crate) functions: BTreeMap<String, FunctionSemantic>,
    /// Columns confirmed as public flags. Only these reach confidence A, so an
    /// implicit wildcard grant always surfaces for review.
    pub(crate) public_flag_columns: BTreeSet<String>,
    /// Functions whose body describes a caller accessor their security mode
    /// invalidates, kept so the report can name the cause.
    owner_bound_accessors: BTreeSet<String>,
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
            functions: BTreeMap::new(),
            public_flag_columns: BTreeSet::new(),
            owner_bound_accessors: BTreeSet::new(),
        }
    }

    /// Functions that would identify the caller but run as their owner, so
    /// `current_user` inside them is the owner's for every caller.
    pub fn owner_bound_accessors(&self) -> impl Iterator<Item = &str> {
        self.owner_bound_accessors.iter().map(String::as_str)
    }

    /// Confirm a column as a public flag, lifting its `P6BooleanFlag` to confidence A.
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
        let parsed: BTreeMap<String, FunctionSemantic> = serde_json::from_str(json)
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
        let settings = AccessorInferenceSettings::default();
        self.enrich_from_schema_with_settings(db, &settings);
    }

    /// Infer function semantics from parsed in-schema function bodies using
    /// explicit accessor-inference settings.
    pub fn enrich_from_schema_with_settings(
        &mut self,
        db: &ParserDB,
        settings: &AccessorInferenceSettings,
    ) {
        for function in db.functions() {
            let Some(body) = function.body() else {
                continue;
            };
            let return_type = function
                .return_type
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_default();
            if let Some(semantic) = FunctionSemantic::analyze_body_with_settings(
                body,
                &return_type,
                "sql",
                function.security.as_ref(),
                settings,
            ) {
                self.register_if_absent(function.name(), &semantic);
            } else if self.get(function.name()).is_none()
                && FunctionSemantic::analyze_body_with_settings(
                    body,
                    &return_type,
                    "sql",
                    None,
                    settings,
                )
                .is_some()
            {
                // The same body as `SECURITY INVOKER` is an accessor, so the security
                // mode is what stops it identifying the caller.
                self.owner_bound_accessors
                    .insert(function.name().to_string());
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

    #[test]
    fn enrich_from_schema_does_not_register_non_allowlisted_current_setting_keys_by_default() {
        let sql = r"
CREATE FUNCTION wrong_user_id() RETURNS UUID
  LANGUAGE sql STABLE
  AS 'SELECT current_setting(''timezone'')::uuid';
";
        let db = parse_schema(sql).expect("schema should parse");

        let mut registry = FunctionRegistry::new();
        registry.enrich_from_schema(&db);

        assert!(
            registry.get("wrong_user_id").is_none(),
            "non-allowlisted current_setting keys must not auto-register user accessors"
        );
    }

    #[test]
    fn enrich_from_schema_with_settings_registers_custom_allowlisted_current_setting_key() {
        let sql = r"
CREATE FUNCTION tenant_user_id() RETURNS UUID
  LANGUAGE sql STABLE
  AS 'SELECT current_setting(''tenant.current_user_uuid'')::uuid';
";
        let db = parse_schema(sql).expect("schema should parse");
        let settings = AccessorInferenceSettings::from_keys(["tenant.current_user_uuid"]);

        let mut registry = FunctionRegistry::new();
        registry.enrich_from_schema_with_settings(&db, &settings);

        assert!(
            registry.is_current_user_accessor("tenant_user_id"),
            "custom allowlisted key should allow schema-based accessor inference"
        );
    }

    #[test]
    fn enrich_from_schema_rejects_uuid_array_accessor_return_type() {
        let sql = r"
CREATE FUNCTION listed_ids_accessor() RETURNS UUID[]
  LANGUAGE sql STABLE
  AS 'SELECT current_setting(''app.current_user_id'')::uuid[]';
";
        let db = parse_schema(sql).expect("schema should parse");

        let mut registry = FunctionRegistry::new();
        registry.enrich_from_schema(&db);

        assert!(
            !registry.is_current_user_accessor("listed_ids_accessor"),
            "UUID[] accessors must not be inferred as scalar current-user accessors"
        );
    }
}

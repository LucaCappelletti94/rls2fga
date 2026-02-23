use std::collections::HashMap;

use crate::parser::function_analyzer::FunctionSemantic;
use crate::parser::sql_parser::{DatabaseLike, FunctionLike, ParserDB};

/// Registry of known function semantics, loaded from JSON or analyzed from bodies.
#[derive(Debug, Clone)]
pub struct FunctionRegistry {
    /// Function name → semantic classification lookup table.
    pub functions: HashMap<String, FunctionSemantic>,
}

impl FunctionRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            functions: HashMap::new(),
        }
    }

    /// Load function semantics from a JSON string.
    pub fn load_from_json(&mut self, json: &str) -> Result<(), String> {
        let parsed: HashMap<String, FunctionSemantic> = serde_json::from_str(json)
            .map_err(|e| format!("Invalid function registry JSON: {e}"))?;
        // Registry takes precedence over analyzed functions
        for (name, semantic) in parsed {
            self.functions.insert(name, semantic);
        }
        Ok(())
    }

    /// Get the semantic for a function by name.
    pub fn get(&self, name: &str) -> Option<&FunctionSemantic> {
        self.functions.get(name)
    }

    /// Register a function semantic (analyzed results, won't overwrite registry entries).
    pub fn register_if_absent(&mut self, name: String, semantic: FunctionSemantic) {
        self.functions.entry(name).or_insert(semantic);
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
                self.register_if_absent(function.name().to_string(), semantic);
            }
        }
    }
}

impl Default for FunctionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

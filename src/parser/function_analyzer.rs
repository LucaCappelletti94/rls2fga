use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
    },

    /// A function that returns the current authenticated user's ID.
    #[serde(rename = "current_user_accessor")]
    CurrentUserAccessor {
        /// SQL return type of the accessor (e.g. `"uuid"`).
        #[serde(default = "default_uuid")]
        returns: String,
    },

    /// A function whose semantics could not be determined.
    #[serde(rename = "unknown")]
    Unknown {
        /// Explanation of why analysis failed.
        reason: String,
    },
}

fn default_uuid() -> String {
    "uuid".to_string()
}

impl FunctionSemantic {
    /// Attempt to classify a function body by simple heuristic analysis.
    /// Returns None if the function cannot be classified from its body alone.
    pub fn analyze_body(body: &str, return_type: &str, language: &str) -> Option<FunctionSemantic> {
        let body_lower = body.to_lowercase();
        let return_type_lower = return_type.to_lowercase();
        let language_lower = language.to_lowercase();

        // Detect current_user accessor patterns
        if return_type_lower.contains("uuid")
            && (body_lower.contains("current_setting") || body_lower.contains("current_user"))
        {
            return Some(FunctionSemantic::CurrentUserAccessor {
                returns: "uuid".to_string(),
            });
        }

        // Detect role-threshold pattern: returns integer, references grants
        if (return_type_lower.contains("int") || return_type_lower.contains("integer"))
            && language_lower == "sql"
            && body_lower.contains("grant")
        {
            // This is a simplified heuristic - the function registry is preferred
            return None;
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::FunctionSemantic;

    #[test]
    fn analyze_body_detects_current_user_accessor() {
        let semantic = FunctionSemantic::analyze_body(
            "SELECT current_setting('app.current_user_id')::uuid",
            "UUID",
            "sql",
        );

        match semantic {
            Some(FunctionSemantic::CurrentUserAccessor { returns }) => {
                assert_eq!(returns, "uuid");
            }
            other => panic!("expected current user accessor, got {other:?}"),
        }
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
}

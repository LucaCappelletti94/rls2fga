//! The translator every schema pasted into the app runs through.

use rls2fga::classifier::function_registry::{
    RegistryLoadError, SessionAttribute, SessionAttributeKind,
};
use rls2fga::translator::{Translator, TranslatorBuilder};
use rls2fga::types::ConfidenceLevel;

/// The session setting the example schemas read the caller from.
pub const CALLER_SETTING: &str = "app.current_user_id";

/// What the role-threshold example's `get_owner_role` means, which no schema can say.
pub const REGISTRY: &str = r#"{
  "get_owner_role": {
    "kind": "role_threshold",
    "user_param_index": 0,
    "resource_param_index": 1,
    "role_levels": {"viewer": 2, "editor": 3, "admin": 4},
    "grant_table": "owner_grants",
    "grant_grantee_col": "grantee_owner_id",
    "grant_resource_col": "granted_owner_id",
    "grant_role_col": "role_id",
    "team_membership": {"table": "team_members", "user_col": "user_id", "team_col": "team_id"}
  }
}"#;

/// The translator at `level`.
///
/// The examples cast the caller to `uuid`, so the app declares that every request sends
/// it in canonical `uuid` form, as a deployment would.
///
/// # Errors
///
/// Returns [`RegistryLoadError`] when [`REGISTRY`] is not a registry payload.
pub fn translator(level: ConfidenceLevel) -> Result<Translator, RegistryLoadError> {
    Ok(TranslatorBuilder::new()
        .with_min_confidence(level)
        .with_registry_json(REGISTRY)?
        .with_session_attributes([SessionAttribute::setting(
            CALLER_SETTING,
            SessionAttributeKind::CallerId,
        )
        .with_identity_cast("uuid")])
        .build())
}

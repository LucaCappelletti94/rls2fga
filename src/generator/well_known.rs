//! Type and relation names the generator reserves. The DSL, the JSON model and the
//! tuple SQL all read them from here so they cannot drift apart.

/// Subject type for a database user.
pub(crate) const USER_TYPE: &str = "user";

/// Subject type for a team, minted by role threshold translation.
pub(crate) const TEAM_TYPE: &str = "team";

/// Subject type for a `PostgreSQL` role named in a policy's `TO` clause.
pub(crate) const PG_ROLE_TYPE: &str = "pg_role";

/// Relation that grants nobody, used wherever a policy must fail closed.
pub(crate) const DENY_RELATION: &str = "no_access";

/// Relation that grants everyone, used wherever a policy is unconditionally open.
pub(crate) const PUBLIC_RELATION: &str = "public_viewer";

/// Condition parameter the request supplies for a guard against statement time.
///
/// A choice, not a convention `OpenFGA` imposes, so the operator has to pass it in the
/// check context under exactly this name.
pub(crate) const REQUEST_TIME_PARAMETER: &str = "request_time";

/// `OpenFGA` name for a timestamp condition parameter.
pub(crate) const TIMESTAMP_PARAMETER_TYPE: &str = "TYPE_NAME_TIMESTAMP";

/// Relation holding the users a membership row attaches to its parent object.
pub(crate) const MEMBER_RELATION: &str = "member";

/// Relation holding the owning user of a row.
pub(crate) const OWNER_USER_RELATION: &str = "owner_user";

/// Relation holding the owning team of a row.
pub(crate) const OWNER_TEAM_RELATION: &str = "owner_team";

/// Action relation answering for a SQL `SELECT`.
pub(crate) const CAN_SELECT_RELATION: &str = "can_select";

/// Action relation answering for a SQL `INSERT`.
pub(crate) const CAN_INSERT_RELATION: &str = "can_insert";

/// Action relation answering for a SQL `UPDATE`.
pub(crate) const CAN_UPDATE_RELATION: &str = "can_update";

/// Action relation answering for a SQL `DELETE`.
pub(crate) const CAN_DELETE_RELATION: &str = "can_delete";

/// The `USING` half of an `UPDATE`, which picks the rows the statement may touch.
pub(crate) const CAN_UPDATE_USING_RELATION: &str = "can_update_using";

/// The `WITH CHECK` half of an `UPDATE`, which admits the new row.
pub(crate) const CAN_UPDATE_CHECK_RELATION: &str = "can_update_check";

/// Inserting a row and reading it back, which returning a table column or naming
/// an `ON CONFLICT` target both do, so the `SELECT` policies apply to the new row.
pub(crate) const CAN_INSERT_RETURNING_RELATION: &str = "can_insert_returning";

/// Inserting with `ON CONFLICT ... DO UPDATE`, which updates the conflicting row,
/// so the `UPDATE` policies apply to it and to the merged row.
pub(crate) const CAN_UPSERT_RELATION: &str = "can_upsert";

/// Reading a row under a locking clause (`FOR UPDATE`, `FOR NO KEY UPDATE`,
/// `FOR SHARE`, `FOR KEY SHARE`), which `PostgreSQL` filters by the `UPDATE`
/// policies' `USING` clause on top of the `SELECT` policies.
pub(crate) const CAN_SELECT_FOR_UPDATE_RELATION: &str = "can_select_for_update";

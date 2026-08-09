//! Type and relation names the generator reserves. The DSL, the JSON model and the
//! tuple SQL all read them from here so they cannot drift apart.

/// Subject type for a database user.
pub const USER_TYPE: &str = "user";

/// Subject type for a team, minted by role threshold translation.
pub const TEAM_TYPE: &str = "team";

/// Subject type for a `PostgreSQL` role named in a policy's `TO` clause.
pub const PG_ROLE_TYPE: &str = "pg_role";

/// Relation that grants nobody, used wherever a policy must fail closed.
pub const DENY_RELATION: &str = "no_access";

/// Relation that grants everyone, used wherever a policy is unconditionally open.
pub const PUBLIC_RELATION: &str = "public_viewer";

/// Condition parameter the request supplies for a guard against statement time.
///
/// A choice, not a convention `OpenFGA` imposes, so the operator has to pass it in the
/// check context under exactly this name.
pub const REQUEST_TIME_PARAMETER: &str = "request_time";

/// `OpenFGA` name for a timestamp condition parameter.
pub const TIMESTAMP_PARAMETER_TYPE: &str = "TYPE_NAME_TIMESTAMP";

/// `OpenFGA` name for a string condition parameter.
pub const STRING_PARAMETER_TYPE: &str = "TYPE_NAME_STRING";

/// `OpenFGA` name for a list condition parameter, whose element type is a generic.
pub const LIST_PARAMETER_TYPE: &str = "TYPE_NAME_LIST";

/// Relation holding the users a membership row attaches to its parent object.
pub const MEMBER_RELATION: &str = "member";

/// Alias an unnested list element takes in generated SQL.
///
/// Deliberately not `member`: it is a column alias, not the [`MEMBER_RELATION`],
/// and one spelling for both made the two read as related.
pub(crate) const ARRAY_ELEMENT_ALIAS: &str = "element";

/// Relation holding the owning user of a row.
pub const OWNER_USER_RELATION: &str = "owner_user";

/// Relation holding the owning team of a row.
pub const OWNER_TEAM_RELATION: &str = "owner_team";

/// Object id of every holder, since exactly one stands for each member source.
pub const HOLDER_OBJECT_ID: &str = "all";

/// Identifier standing for every subject of a type.
///
/// The crate's own spelling for "everyone", never a value out of a row, so it is
/// the one identifier the encoding leaves alone. A row whose value is literally
/// `*` still encodes, or it would grant everybody.
pub const WILDCARD_SUBJECT_ID: &str = "*";

/// Action relation answering for a SQL `SELECT`.
pub const CAN_SELECT_RELATION: &str = "can_select";

/// Action relation answering for a SQL `INSERT`.
pub const CAN_INSERT_RELATION: &str = "can_insert";

/// Action relation answering for a SQL `UPDATE`.
pub const CAN_UPDATE_RELATION: &str = "can_update";

/// Action relation answering for a SQL `DELETE`.
pub const CAN_DELETE_RELATION: &str = "can_delete";

/// The `USING` half of an `UPDATE`, which picks the rows the statement may touch.
pub const CAN_UPDATE_USING_RELATION: &str = "can_update_using";

/// The `WITH CHECK` half of an `UPDATE`, which admits the new row.
pub const CAN_UPDATE_CHECK_RELATION: &str = "can_update_check";

/// Updating without naming a row, as `UPDATE t SET c = 1` does. `PostgreSQL` applies
/// the `UPDATE` policies to it and not the `SELECT` policies, since the statement reads
/// no row to decide which to change.
pub const CAN_UPDATE_WITHOUT_READING_RELATION: &str = "can_update_without_reading";

/// Inserting a row and reading it back, which returning a table column or naming
/// an `ON CONFLICT` target both do, so the `SELECT` policies apply to the new row.
pub const CAN_INSERT_RETURNING_RELATION: &str = "can_insert_returning";

/// Inserting with `ON CONFLICT ... DO UPDATE`, which updates the conflicting row,
/// so the `UPDATE` policies apply to it and to the merged row.
pub const CAN_UPSERT_RELATION: &str = "can_upsert";

/// Reading a row under a locking clause (`FOR UPDATE`, `FOR NO KEY UPDATE`,
/// `FOR SHARE`, `FOR KEY SHARE`), which `PostgreSQL` filters by the `UPDATE`
/// policies' `USING` clause on top of the `SELECT` policies.
pub const CAN_SELECT_FOR_UPDATE_RELATION: &str = "can_select_for_update";

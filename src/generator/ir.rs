//! Shared authorization intermediate representation.
//!
//! [`TupleSource`] describes how to populate a single `OpenFGA` relation with
//! tuples from SQL.  It is produced once — during the pattern-to-model
//! translation in [`crate::generator::model_generator`] — and then consumed by
//! both the DSL/JSON renderers (which ignore it) and the tuple-SQL renderer in
//! [`crate::generator::tuple_generator`].
//!
//! Having one place that produces this data guarantees that the model and the
//! tuple queries are always consistent: adding a new pattern requires updating
//! only `pattern_to_expr_for_target`, not two independent match trees.

use crate::classifier::patterns::ConfidenceLevel;

/// Information about a principal table (users or teams) referenced by a
/// role-threshold function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PrincipalInfo {
    /// Table that stores the principal entities.
    pub table: String,
    /// Primary-key column of `table`.
    pub pk_col: String,
}

/// Describes how to populate a single `OpenFGA` relation with tuples from SQL.
///
/// Each variant corresponds to one kind of access-control fact that can be
/// expressed as a static SQL query against the application schema.
///
/// Variants are intentionally data-only: all SQL rendering logic lives in
/// [`crate::generator::tuple_generator`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TupleSource {
    /// Direct ownership column — `owner_col` IS NOT NULL.
    ///
    /// Produces: `(type:pk, relation, user:owner_col)`.
    ///
    /// Maps from: **P3** `DirectOwnership`.
    DirectOwnership {
        /// Table that holds the owned resources.
        table: String,
        /// Primary-key column of `table`.
        pk_col: String,
        /// Column whose value is the owner's identifier.
        owner_col: String,
    },

    /// User-side ownership inferred from a role-threshold function.
    ///
    /// Produces: `(type:pk, owner_user, user:owner_col)` filtered to the user
    /// principal table.
    ///
    /// Maps from: **P1** / **P2** `RoleThreshold` (user principal branch).
    RoleOwnerUser {
        /// Resource table.
        table: String,
        /// Primary-key column of `table`.
        pk_col: String,
        /// Column whose value is the owner's identifier.
        owner_col: String,
        /// User principal table.
        user_table: String,
        /// Primary-key column of `user_table`.
        user_pk_col: String,
    },

    /// Team-side ownership inferred from a role-threshold function.
    ///
    /// Produces: `(type:pk, owner_team, team:owner_col)` filtered to the team
    /// principal table.
    ///
    /// Maps from: **P1** / **P2** `RoleThreshold` (team principal branch).
    RoleOwnerTeam {
        /// Resource table.
        table: String,
        /// Primary-key column of `table`.
        pk_col: String,
        /// Column whose value is the owner's identifier.
        owner_col: String,
        /// Team principal table.
        team_table: String,
        /// Primary-key column of `team_table`.
        team_pk_col: String,
    },

    /// Explicit grant rows expanded to per-role resource tuples.
    ///
    /// Produces one or more queries of the form:
    /// `(type:resource_col, grant_relation, user:grantee_col)` for each role
    /// case, joined via `grant_join_col` back to the resource table.
    ///
    /// Maps from: **P1** / **P2** `RoleThreshold` (explicit grants branch).
    ExplicitGrants {
        /// Resource table.
        table: String,
        /// Primary-key column of `table`.
        pk_col: String,
        /// Column in `table` used to join to the grant table.
        grant_join_col: String,
        /// Table that stores the explicit grants.
        grant_table: String,
        /// Column in `grant_table` storing the integer role level.
        grant_role_col: String,
        /// Column in `grant_table` identifying the grantee.
        grant_grantee_col: String,
        /// Column in `grant_table` identifying the target resource.
        grant_resource_col: String,
        /// `(level, grant_relation, original_name)` — one entry per role level to emit.
        ///
        /// `grant_relation` (e.g. `"grant_viewer"`) goes into the SQL `CASE` expression;
        /// `original_name` (e.g. `"viewer"`) is used in the human-readable comment.
        role_cases: Vec<(i32, String, String)>,
        /// User principal table (if resolvable).
        user_principal: Option<PrincipalInfo>,
        /// Team principal table (if resolvable).
        team_principal: Option<PrincipalInfo>,
    },

    /// Team-membership rows from a dedicated join table.
    ///
    /// Produces: `(team:team_col, member, user:user_col)`.
    ///
    /// Maps from: **P1** / **P2** `RoleThreshold` (team-membership table).
    TeamMembership {
        /// Table that stores team ↔ member associations.
        membership_table: String,
        /// Column in `membership_table` referencing the team.
        team_col: String,
        /// Column in `membership_table` referencing the user.
        user_col: String,
    },

    /// `EXISTS`-based membership from a join table (also covers `IN`-subquery).
    ///
    /// Produces: `(type:fk_col, member, user:user_col)`.
    ///
    /// Maps from: **P4** `ExistsMembership`.
    ExistsMembership {
        /// Join table scanned in the `EXISTS` subquery.
        join_table: String,
        /// Column in `join_table` that references the parent resource.
        fk_col: String,
        /// Column in `join_table` referencing the user.
        user_col: String,
        /// Additional predicate SQL, if any (e.g. `role = 'admin'`).
        extra_predicate_sql: Option<String>,
    },

    /// FK-based bridge: child entity linked to its parent.
    ///
    /// Produces: `(parent_type:fk_col_val, relation, type:pk)`.
    ///
    /// Maps from: **P4** (resource bridge) and **P5** `ParentInheritance`.
    ///
    /// The object column is resolved at render time via `resolve_bridge_columns`
    /// rather than being stored here, to keep the IR free of schema lookups.
    ParentBridge {
        /// Child resource table.
        table: String,
        /// FK column in `table` that references the parent entity.
        fk_col: String,
        /// `OpenFGA` type name of the parent entity.
        parent_type: String,
    },

    /// Boolean public-flag column — `flag_col = TRUE`.
    ///
    /// Produces: `(type:pk, public_viewer, user:*)`.
    ///
    /// Maps from: **P6** `BooleanFlag`.
    PublicFlag {
        /// Resource table.
        table: String,
        /// Primary-key column of `table`.
        pk_col: String,
        /// Boolean column controlling public visibility.
        flag_col: String,
    },

    /// Constant-`TRUE` policy — every row is publicly accessible.
    ///
    /// Produces: `(type:pk, public_viewer, user:*)` for every row in `table`.
    ///
    /// Maps from: **P10** `ConstantBool { value: true }`.
    ConstantTrue {
        /// Resource table.
        table: String,
        /// Primary-key column of `table`.
        pk_col: String,
    },

    /// `PostgreSQL` role-scoped policy.
    ///
    /// Produces: `(type:pk, scope_relation, pg_role:pg_role_name)`.
    ///
    /// Maps from: `ClassifiedPolicy::scoped_roles()` when non-empty.
    PolicyScope {
        /// Resource table.
        table: String,
        /// Primary-key column of `table`.
        pk_col: String,
        /// `OpenFGA` relation name that gates access for scoped roles.
        scope_relation: String,
        /// `PostgreSQL` role name (e.g. `"app_user"`).
        pg_role: String,
    },

    /// Cannot be expressed as a static SQL query.
    ///
    /// The renderer emits the pre-rendered `comment` and `sql` strings as-is,
    /// directing the operator to add runtime enforcement.
    ///
    /// Maps from: **P7** attribute guard, **P9** standalone attribute, **Unknown**.
    Todo {
        /// Confidence level that triggered this item.
        level: ConfidenceLevel,
        /// Pre-rendered SQL comment line (e.g. `"-- TODO [Level C]: ..."`).
        comment: String,
        /// Pre-rendered body line (e.g. `"-- Tuple query not emitted; ..."`)
        sql: String,
    },
}

impl TupleSource {
    /// A stable string key used to deduplicate identical tuple queries.
    ///
    /// Two sources with the same key produce the same SQL; only the first is
    /// emitted.
    pub(crate) fn dedup_key(&self) -> String {
        match self {
            Self::DirectOwnership {
                table, owner_col, ..
            } => {
                format!("p3:{table}:{owner_col}")
            }
            Self::RoleOwnerUser {
                table, owner_col, ..
            } => {
                format!("role_owner_user:{table}:{owner_col}")
            }
            Self::RoleOwnerTeam {
                table, owner_col, ..
            } => {
                format!("role_owner_team:{table}:{owner_col}")
            }
            Self::ExplicitGrants {
                table,
                grant_table,
                grant_role_col,
                role_cases,
                ..
            } => {
                let levels: Vec<String> =
                    role_cases.iter().map(|(l, _, _)| l.to_string()).collect();
                format!(
                    "grants:{table}:{grant_table}:{grant_role_col}:{}",
                    levels.join(",")
                )
            }
            Self::TeamMembership {
                membership_table,
                team_col,
                user_col,
            } => {
                format!("team_membership:{membership_table}:{team_col}:{user_col}")
            }
            Self::ExistsMembership {
                join_table,
                fk_col,
                user_col,
                extra_predicate_sql,
            } => {
                let extra = extra_predicate_sql.as_deref().unwrap_or("");
                format!("p4:{join_table}:{fk_col}:{user_col}:{extra}")
            }
            Self::ParentBridge {
                table,
                fk_col,
                parent_type,
            } => {
                format!("bridge:{table}:{fk_col}:{parent_type}")
            }
            Self::PublicFlag {
                table, flag_col, ..
            } => {
                format!("p6:{table}:{flag_col}")
            }
            Self::ConstantTrue { table, .. } => {
                format!("p10_true:{table}")
            }
            Self::PolicyScope {
                table,
                scope_relation,
                pg_role,
                ..
            } => {
                format!("scope:{table}:{scope_relation}:{pg_role}")
            }
            Self::Todo {
                level,
                comment,
                sql,
            } => {
                format!("todo:{level}:{comment}:{sql}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classifier::patterns::ConfidenceLevel;

    #[test]
    fn dedup_key_differentiates_explicit_grants_across_tables() {
        let grants_a = TupleSource::ExplicitGrants {
            table: "table_a".to_string(),
            pk_col: "id".to_string(),
            grant_join_col: "resource_id".to_string(),
            grant_table: "grants".to_string(),
            grant_role_col: "role".to_string(),
            grant_grantee_col: "grantee".to_string(),
            grant_resource_col: "resource_id".to_string(),
            role_cases: vec![(1, "viewer".to_string(), "viewer".to_string())],
            user_principal: None,
            team_principal: None,
        };
        let grants_b = TupleSource::ExplicitGrants {
            table: "table_b".to_string(),
            pk_col: "id".to_string(),
            grant_join_col: "resource_id".to_string(),
            grant_table: "grants".to_string(),
            grant_role_col: "role".to_string(),
            grant_grantee_col: "grantee".to_string(),
            grant_resource_col: "resource_id".to_string(),
            role_cases: vec![(1, "viewer".to_string(), "viewer".to_string())],
            user_principal: None,
            team_principal: None,
        };
        assert_ne!(
            grants_a.dedup_key(),
            grants_b.dedup_key(),
            "ExplicitGrants from different tables must have different dedup keys"
        );
    }

    #[test]
    fn dedup_key_differentiates_team_membership_by_columns() {
        let mem_a = TupleSource::TeamMembership {
            membership_table: "team_members".to_string(),
            team_col: "team_id".to_string(),
            user_col: "user_id".to_string(),
        };
        let mem_b = TupleSource::TeamMembership {
            membership_table: "team_members".to_string(),
            team_col: "group_id".to_string(),
            user_col: "member_id".to_string(),
        };
        assert_ne!(
            mem_a.dedup_key(),
            mem_b.dedup_key(),
            "TeamMembership with different columns must have different dedup keys"
        );
    }

    #[test]
    fn dedup_key_differentiates_exists_membership_by_user_col_and_predicate() {
        let base = TupleSource::ExistsMembership {
            join_table: "members".to_string(),
            fk_col: "project_id".to_string(),
            user_col: "user_id".to_string(),
            extra_predicate_sql: None,
        };
        let different_user = TupleSource::ExistsMembership {
            join_table: "members".to_string(),
            fk_col: "project_id".to_string(),
            user_col: "member_id".to_string(),
            extra_predicate_sql: None,
        };
        let with_predicate = TupleSource::ExistsMembership {
            join_table: "members".to_string(),
            fk_col: "project_id".to_string(),
            user_col: "user_id".to_string(),
            extra_predicate_sql: Some("role = 'admin'".to_string()),
        };
        assert_ne!(base.dedup_key(), different_user.dedup_key());
        assert_ne!(base.dedup_key(), with_predicate.dedup_key());
    }

    #[test]
    fn dedup_key_differentiates_todo_by_sql_and_level() {
        let todo_c = TupleSource::Todo {
            level: ConfidenceLevel::C,
            comment: "-- TODO".to_string(),
            sql: "-- query not emitted".to_string(),
        };
        let todo_d_diff_sql = TupleSource::Todo {
            level: ConfidenceLevel::D,
            comment: "-- TODO".to_string(),
            sql: "-- different".to_string(),
        };
        assert_ne!(todo_c.dedup_key(), todo_d_diff_sql.dedup_key());
    }
}

//! Shared authorization intermediate representation.
//!
//! [`TupleSource`] says how to populate one `OpenFGA` relation from SQL. It is
//! produced once during pattern translation, so the model and the tuple queries
//! cannot drift apart.

use crate::classifier::patterns::ConfidenceLevel;
#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;

/// Principal table (users or teams) named by a role-threshold function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PrincipalInfo {
    /// Table that stores the principal entities.
    pub table: String,
    pub pk_col: String,
}

/// One kind of access-control fact, expressible as a static SQL query.
///
/// Data only: rendering lives in [`crate::generator::tuple_generator`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TupleSource {
    /// P3 ownership. Produces `(type:pk, relation, user:owner_col)`.
    DirectOwnership {
        table: String,
        pk_col: String,
        owner_col: String,
        /// One relation per column, so two ownership columns cannot union their
        /// principals.
        relation: String,
    },

    /// P1/P2 user-side ownership. Produces `(type:pk, owner_user, user:owner_col)`
    /// filtered to the user principal table.
    RoleOwnerUser {
        table: String,
        pk_col: String,
        owner_col: String,
        user_table: String,
        user_pk_col: String,
    },

    /// P1/P2 team-side ownership. Produces `(type:pk, owner_team, team:owner_col)`
    /// filtered to the team principal table.
    RoleOwnerTeam {
        table: String,
        pk_col: String,
        owner_col: String,
        team_table: String,
        team_pk_col: String,
    },

    /// P1/P2 explicit grants. Produces one
    /// `(type:resource_col, grant_relation, user:grantee_col)` query per role case.
    ExplicitGrants {
        table: String,
        pk_col: String,
        /// Column of `table` joined to the grant table.
        grant_join_col: String,
        grant_table: String,
        /// Column of `grant_table` holding the integer role level.
        grant_role_col: String,
        grant_grantee_col: String,
        grant_resource_col: String,
        /// `(level, grant_relation, original_name)`. The relation goes into the SQL
        /// `CASE`, the original name into the comment.
        role_cases: Vec<(i32, String, String)>,
        user_principal: Option<PrincipalInfo>,
        team_principal: Option<PrincipalInfo>,
    },

    /// P1/P2 team membership. Produces `(team:team_col, member, user:user_col)`.
    TeamMembership {
        membership_table: String,
        team_col: String,
        user_col: String,
    },

    /// P4 membership, from `EXISTS` or an `IN` subquery.
    /// Produces `(parent_type:fk_col, member, user:user_col)`.
    ExistsMembership {
        join_table: String,
        /// Column of `join_table` referencing the parent resource.
        fk_col: String,
        user_col: String,
        /// Resolved from the table `fk_col` references, not from its name.
        parent_type: String,
        /// Residual predicate no tuple can express.
        extra_predicate_sql: Option<String>,
    },

    /// P4/P5 child-to-parent link. Produces `(type:pk, relation, parent_type:fk_col)`.
    ///
    /// The object column is resolved at render time, keeping the IR free of schema
    /// lookups.
    ParentBridge {
        table: String,
        fk_col: String,
        parent_type: String,
        /// Named after `parent_type` but subject to the shorter relation-name limit,
        /// so the two can differ.
        relation: String,
    },

    /// P6 public flag. Produces `(type:pk, public_viewer, user:*)` where the flag holds.
    PublicFlag {
        table: String,
        pk_col: String,
        flag_col: String,
    },

    /// P10 constant `TRUE`. Produces `(type:pk, public_viewer, user:*)` for every row.
    ConstantTrue { table: String, pk_col: String },

    /// Role-scoped policy. Produces `(type:pk, scope_relation, pg_role:pg_role)`.
    PolicyScope {
        table: String,
        pk_col: String,
        scope_relation: String,
        pg_role: String,
    },

    /// Not expressible as a static query. The renderer emits `comment` and `sql`
    /// verbatim so the operator knows to enforce it at runtime.
    Todo {
        level: ConfidenceLevel,
        /// Pre-rendered comment line.
        comment: String,
        /// Pre-rendered body line.
        sql: String,
    },
}

impl TupleSource {
    /// True when the rendered objects belong to the type plan this source is
    /// attached to, rather than to a type named inside the source itself.
    ///
    /// Such a source is identified only up to its owning type, since two tables
    /// canonicalizing alike become separate types. The rest name their object
    /// type explicitly and deduplicate on content alone.
    pub(crate) fn emits_owner_type_objects(&self) -> bool {
        match self {
            Self::DirectOwnership { .. }
            | Self::RoleOwnerUser { .. }
            | Self::RoleOwnerTeam { .. }
            | Self::ExplicitGrants { .. }
            | Self::ParentBridge { .. }
            | Self::PublicFlag { .. }
            | Self::ConstantTrue { .. }
            | Self::PolicyScope { .. } => true,
            Self::TeamMembership { .. } | Self::ExistsMembership { .. } | Self::Todo { .. } => {
                false
            }
        }
    }

    /// A stable string key used to deduplicate identical tuple queries.
    ///
    /// Two sources with the same key produce the same SQL; only the first is
    /// emitted.
    pub(crate) fn dedup_key(&self) -> String {
        match self {
            Self::DirectOwnership {
                table,
                pk_col,
                owner_col,
                relation,
            } => {
                format!("p3:{table}:{pk_col}:{owner_col}:{relation}")
            }
            Self::RoleOwnerUser {
                table,
                pk_col,
                owner_col,
                user_table,
                user_pk_col,
            } => {
                format!("role_owner_user:{table}:{pk_col}:{owner_col}:{user_table}:{user_pk_col}")
            }
            Self::RoleOwnerTeam {
                table,
                pk_col,
                owner_col,
                team_table,
                team_pk_col,
            } => {
                format!("role_owner_team:{table}:{pk_col}:{owner_col}:{team_table}:{team_pk_col}")
            }
            Self::ExplicitGrants {
                table,
                grant_join_col,
                grant_table,
                grant_role_col,
                grant_grantee_col,
                grant_resource_col,
                role_cases,
                ..
            } => {
                let role_keys: Vec<String> = role_cases
                    .iter()
                    .map(|(l, rel, name)| format!("{l}:{rel}:{name}"))
                    .collect();
                format!(
                    "grants:{table}:{grant_table}:{grant_role_col}:{grant_join_col}:\
                     {grant_grantee_col}:{grant_resource_col}:{}",
                    role_keys.join(",")
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
                parent_type,
                extra_predicate_sql,
            } => {
                let extra = extra_predicate_sql.as_deref().unwrap_or("");
                format!("p4:{join_table}:{fk_col}:{user_col}:{parent_type}:{extra}")
            }
            Self::ParentBridge {
                table,
                fk_col,
                parent_type,
                relation,
            } => {
                format!("bridge:{table}:{fk_col}:{parent_type}:{relation}")
            }
            Self::PublicFlag {
                table,
                pk_col,
                flag_col,
            } => {
                format!("p6:{table}:{pk_col}:{flag_col}")
            }
            Self::ConstantTrue { table, pk_col } => {
                format!("p10_true:{table}:{pk_col}")
            }
            Self::PolicyScope {
                table,
                pk_col,
                scope_relation,
                pg_role,
            } => {
                format!("scope:{table}:{pk_col}:{scope_relation}:{pg_role}")
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
            parent_type: "projects".to_string(),
            extra_predicate_sql: None,
        };
        let different_user = TupleSource::ExistsMembership {
            join_table: "members".to_string(),
            fk_col: "project_id".to_string(),
            user_col: "member_id".to_string(),
            parent_type: "projects".to_string(),
            extra_predicate_sql: None,
        };
        let with_predicate = TupleSource::ExistsMembership {
            join_table: "members".to_string(),
            fk_col: "project_id".to_string(),
            user_col: "user_id".to_string(),
            parent_type: "projects".to_string(),
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

//! Shared authorization intermediate representation.
//!
//! [`TupleSource`] says how to populate one `OpenFGA` relation from SQL. It is
//! produced once during pattern translation, so the model and the tuple queries
//! cannot drift apart.

use crate::classifier::patterns::AttributePredicate;
use crate::generator::model_generator::RowParameter;
use crate::generator::notes::SkippedTuples;
use crate::generator::relations::RequestComparison;
use crate::generator::well_known::{
    MEMBER_RELATION, OWNER_TEAM_RELATION, OWNER_USER_RELATION, PUBLIC_RELATION, TEAM_TYPE,
};
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
        pk_cols: Vec<String>,
        owner_col: String,
        /// One relation per column, so two ownership columns cannot union their
        /// principals.
        relation: String,
    },

    /// P11 array membership. Produces `(type:pk, relation, user:element)` by
    /// expanding `array_col`, which drops a NULL or empty array exactly as
    /// `= ANY` refuses it.
    ArrayMembership {
        table: String,
        pk_cols: Vec<String>,
        array_col: String,
        relation: String,
    },

    /// P12 jsonb field ownership. Produces `(type:pk, relation, user:field)` by
    /// extracting `path` as text, dropping the NULL a missing key yields.
    JsonbFieldOwnership {
        table: String,
        pk_cols: Vec<String>,
        column: String,
        path: Vec<String>,
        relation: String,
    },

    /// P1/P2 user-side ownership. Produces `(type:pk, owner_user, user:owner_col)`
    /// filtered to the user principal table.
    RoleOwnerUser {
        table: String,
        pk_cols: Vec<String>,
        owner_col: String,
        user_table: String,
        user_pk_col: String,
    },

    /// P1/P2 team-side ownership. Produces `(type:pk, owner_team, team:owner_col)`
    /// filtered to the team principal table.
    RoleOwnerTeam {
        table: String,
        pk_cols: Vec<String>,
        owner_col: String,
        team_table: String,
        team_pk_col: String,
    },

    /// P1/P2 explicit grants. Produces one
    /// `(type:resource_col, grant_relation, user:grantee_col)` query per role case.
    ExplicitGrants {
        table: String,
        pk_cols: Vec<String>,
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
        pk_cols: Vec<String>,
        flag_col: String,
    },

    /// P9 attribute guard over a literal constant. Produces
    /// `(type:pk, public_viewer, user:*)` for the rows the guard admits.
    AttributeGate {
        table: String,
        pk_cols: Vec<String>,
        predicate: AttributePredicate,
    },

    /// P9 guard the service evaluates per check. Produces
    /// `(type:pk, relation, user:*, condition, context)` where the context carries the
    /// row's own value for the parameter the request cannot supply.
    ConditionalAttributeGate {
        table: String,
        pk_cols: Vec<String>,
        relation: String,
        condition: String,
        /// Condition parameter the row supplies, and the column it reads.
        row_parameter: String,
        column: String,
    },

    /// A declared request-scoped value the service compares per check. Produces
    /// `(type:pk, relation, user:*, condition, context)` where the context carries what
    /// only the row or the rule knows: the row's own value, or the constant the policy
    /// named.
    SessionAttributeGate {
        table: String,
        pk_cols: Vec<String>,
        relation: String,
        condition: String,
        /// Condition parameter the tuple supplies, and where its value comes from.
        row_parameter: RowParameter,
        /// Condition parameter the caller supplies in every check context.
        request_parameter: String,
        /// Session setting the caller's value mirrors, so the contract can name it.
        setting_key: String,
        /// Separator the policy splits that setting on, for a list parameter.
        separator: Option<String>,
        /// How the two sides are compared.
        comparison: RequestComparison,
    },

    /// A membership row whose member column holds a value the caller's declared set has
    /// to contain. Produces `(parent_type:fk, relation, user:*, condition, context)` per
    /// **membership** row, so the objects are named after the parent while the facts are
    /// read from the join table.
    SessionAttributeMembershipGate {
        /// Table whose rows record the grants.
        join_table: String,
        /// Column of `join_table` naming the guarded row, which the object is keyed on.
        fk_col: String,
        /// Column of `join_table` holding the value the caller's set must contain.
        member_col: String,
        /// Type the objects belong to, named here because the facts are read from the
        /// join table rather than from the type's own rows.
        parent_type: String,
        relation: String,
        condition: String,
        /// Condition parameter the membership row supplies.
        row_parameter: String,
        /// Condition parameter the caller supplies in every check context.
        request_parameter: String,
        /// Session setting the caller's value mirrors, so the contract can name it.
        setting_key: String,
        /// Separator the policy splits that setting on, absent for a list source.
        separator: Option<String>,
        /// Residual filter on the membership row.
        extra_predicate_sql: Option<String>,
    },

    /// P10 constant `TRUE`. Produces `(type:pk, public_viewer, user:*)` for every row.
    ConstantTrue { table: String, pk_cols: Vec<String> },

    /// Role-scoped policy. Produces `(type:pk, scope_relation, pg_role:pg_role)`.
    PolicyScope {
        table: String,
        pk_cols: Vec<String>,
        scope_relation: String,
        pg_role: String,
    },

    /// Every row of `table` pointing at the one holder object, so a member of the
    /// holder reaches all of them.
    HolderBridge {
        table: String,
        pk_cols: Vec<String>,
        relation: String,
        holder_type: String,
    },

    /// Everyone listed in `member_table`, attached to the holder object.
    HolderMembers {
        holder_type: String,
        member_table: String,
        user_col: String,
        extra_predicate_sql: Option<String>,
    },

    /// Why no tuple query stands here. Rendered as the two comment lines that take
    /// its place in the loader's script.
    Skipped { reason: SkippedTuples },
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
            | Self::ArrayMembership { .. }
            | Self::JsonbFieldOwnership { .. }
            | Self::RoleOwnerUser { .. }
            | Self::RoleOwnerTeam { .. }
            | Self::ExplicitGrants { .. }
            | Self::ParentBridge { .. }
            | Self::PublicFlag { .. }
            | Self::AttributeGate { .. }
            | Self::ConditionalAttributeGate { .. }
            | Self::SessionAttributeGate { .. }
            | Self::ConstantTrue { .. }
            | Self::PolicyScope { .. }
            | Self::HolderBridge { .. } => true,
            Self::TeamMembership { .. }
            | Self::ExistsMembership { .. }
            | Self::SessionAttributeMembershipGate { .. }
            | Self::HolderMembers { .. }
            | Self::Skipped { .. } => false,
        }
    }

    /// The `(type, relation)` pairs this source populates. Empty means it carries no
    /// tuples, so it is never dropped as unreachable.
    pub(crate) fn feeds(&self, owner_type: &str) -> Vec<(String, String)> {
        let own = |relation: &str| vec![(owner_type.to_string(), relation.to_string())];
        match self {
            Self::DirectOwnership { relation, .. }
            | Self::ArrayMembership { relation, .. }
            | Self::JsonbFieldOwnership { relation, .. }
            | Self::ParentBridge { relation, .. }
            | Self::ConditionalAttributeGate { relation, .. }
            | Self::SessionAttributeGate { relation, .. }
            | Self::SessionAttributeMembershipGate { relation, .. }
            | Self::HolderBridge { relation, .. } => own(relation),
            Self::RoleOwnerUser { .. } => own(OWNER_USER_RELATION),
            Self::RoleOwnerTeam { .. } => own(OWNER_TEAM_RELATION),
            Self::ExplicitGrants { role_cases, .. } => role_cases
                .iter()
                .map(|(_, relation, _)| (owner_type.to_string(), relation.clone()))
                .collect(),
            Self::TeamMembership { .. } => {
                vec![(TEAM_TYPE.to_string(), MEMBER_RELATION.to_string())]
            }
            Self::ExistsMembership { parent_type, .. } => {
                vec![(parent_type.clone(), MEMBER_RELATION.to_string())]
            }
            Self::HolderMembers { holder_type, .. } => {
                vec![(holder_type.clone(), MEMBER_RELATION.to_string())]
            }
            Self::PublicFlag { .. } | Self::AttributeGate { .. } | Self::ConstantTrue { .. } => {
                own(PUBLIC_RELATION)
            }
            Self::PolicyScope { scope_relation, .. } => own(scope_relation),
            Self::Skipped { .. } => Vec::new(),
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
                pk_cols,
                owner_col,
                relation,
            } => {
                format!("p3:{table}:{pk_cols:?}:{owner_col}:{relation}")
            }
            Self::ArrayMembership {
                table,
                pk_cols,
                array_col,
                relation,
            } => {
                format!("p11:{table}:{pk_cols:?}:{array_col}:{relation}")
            }
            Self::JsonbFieldOwnership {
                table,
                pk_cols,
                column,
                path,
                relation,
            } => {
                format!(
                    "p12:{table}:{pk_cols:?}:{column}:{}:{relation}",
                    path.join(".")
                )
            }
            Self::RoleOwnerUser {
                table,
                pk_cols,
                owner_col,
                user_table,
                user_pk_col,
            } => {
                format!(
                    "role_owner_user:{table}:{pk_cols:?}:{owner_col}:{user_table}:{user_pk_col}"
                )
            }
            Self::RoleOwnerTeam {
                table,
                pk_cols,
                owner_col,
                team_table,
                team_pk_col,
            } => {
                format!(
                    "role_owner_team:{table}:{pk_cols:?}:{owner_col}:{team_table}:{team_pk_col}"
                )
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
                pk_cols,
                flag_col,
            } => {
                format!("p6:{table}:{pk_cols:?}:{flag_col}")
            }
            Self::AttributeGate {
                table,
                pk_cols,
                predicate,
            } => {
                format!(
                    "p9:{table}:{pk_cols:?}:{}:{:?}:{:?}",
                    predicate.column, predicate.operator, predicate.value
                )
            }
            Self::ConditionalAttributeGate {
                table,
                pk_cols,
                relation,
                condition,
                row_parameter,
                column,
            } => {
                format!("p9c:{table}:{pk_cols:?}:{relation}:{condition}:{row_parameter}:{column}")
            }
            Self::SessionAttributeGate {
                table,
                pk_cols,
                relation,
                condition,
                row_parameter,
                request_parameter,
                setting_key,
                separator,
                comparison,
            } => {
                let _ = (setting_key, separator);
                format!(
                    "sess:{table}:{pk_cols:?}:{relation}:{condition}:{}:{}:{request_parameter}:{comparison:?}",
                    row_parameter.parameter(),
                    row_parameter.column().unwrap_or_default()
                )
            }
            Self::SessionAttributeMembershipGate {
                join_table,
                fk_col,
                member_col,
                parent_type,
                relation,
                condition,
                row_parameter,
                request_parameter,
                setting_key,
                separator,
                extra_predicate_sql,
            } => {
                let _ = (setting_key, separator);
                format!(
                    "sessmem:{parent_type}:{join_table}:{fk_col}:{member_col}:{relation}:\
                     {condition}:{row_parameter}:{request_parameter}:{}",
                    extra_predicate_sql.as_deref().unwrap_or_default()
                )
            }
            Self::ConstantTrue { table, pk_cols } => {
                format!("p10_true:{table}:{pk_cols:?}")
            }
            Self::PolicyScope {
                table,
                pk_cols,
                scope_relation,
                pg_role,
            } => {
                format!("scope:{table}:{pk_cols:?}:{scope_relation}:{pg_role}")
            }
            Self::HolderBridge {
                table,
                pk_cols,
                relation,
                holder_type,
            } => {
                format!("holder:{table}:{pk_cols:?}:{relation}:{holder_type}")
            }
            Self::HolderMembers {
                holder_type,
                member_table,
                user_col,
                extra_predicate_sql,
            } => {
                format!(
                    "holdermembers:{holder_type}:{member_table}:{user_col}:{}",
                    extra_predicate_sql.as_deref().unwrap_or("")
                )
            }
            Self::Skipped { reason } => {
                format!("skipped:{}:{}", reason.comment(), reason.body())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_key_differentiates_explicit_grants_across_tables() {
        let grants_a = TupleSource::ExplicitGrants {
            table: "table_a".to_string(),
            pk_cols: vec!["id".to_string()],
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
            pk_cols: vec!["id".to_string()],
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
    fn dedup_key_differentiates_skips_by_their_reason() {
        let attribute = TupleSource::Skipped {
            reason: SkippedTuples::AttributeRuntimeEnforcement {
                table: "docs".to_string(),
                attribute: "status = 'active'".to_string(),
            },
        };
        let unclassified = TupleSource::Skipped {
            reason: SkippedTuples::UnclassifiedExpression {
                table: "docs".to_string(),
                reason: "no pattern".to_string(),
            },
        };
        assert_ne!(attribute.dedup_key(), unclassified.dedup_key());
    }
}

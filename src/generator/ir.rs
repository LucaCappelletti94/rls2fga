//! Shared authorization intermediate representation.
//!
//! [`TupleSource`] says how to populate one `OpenFGA` relation from SQL. It is
//! produced once during pattern translation, so the model and the tuple queries
//! cannot drift apart.

use crate::classifier::patterns::{AttributePredicate, ResidualPredicates};
use crate::generator::model_generator::RowParameter;
use crate::generator::notes::SkippedTuples;
use crate::generator::relations::RequestComparison;
use crate::generator::well_known::{member_relation, public_relation, WellKnownTypes};
#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use crate::parser::identifiers::{ColumnName, RelationName, TypeName};

/// Principal table (users or teams) named by a role-threshold function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PrincipalInfo {
    /// Table that stores the principal entities.
    pub table: String,
    pub pk_col: ColumnName,
}

/// One condition-context entry a conditional membership tuple carries: the parameter
/// name the row fills and the column its value is read from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GateContextColumn {
    /// Condition parameter the value fills.
    pub parameter: String,
    /// Column of the join table the value is read from.
    pub column: ColumnName,
}

/// The condition a temporal membership tuple names, with every column its context
/// carries. Present on a membership source only when a clock comparison rides its member
/// tuple. Absent for a plain member tuple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MembershipGate {
    /// The condition the member tuple names, declared on the parent or holder type.
    pub condition: String,
    /// Columns the row fills the condition context with, one per clock comparison.
    pub context: Vec<GateContextColumn>,
    /// True when several member rows can key the same `(object, user)`, so the query
    /// groups by it and carries `MAX(deadline)`, and the shape joins rather than settling
    /// from one row. False when the row uniquely keys the tuple, which stays `FromRow`.
    pub aggregate: bool,
}

/// One kind of access-control fact, expressible as a static SQL query.
///
/// Data only: rendering lives in [`crate::generator::tuple_generator`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TupleSource {
    /// P3 ownership. Produces `(type:pk, relation, user:owner_col)`.
    DirectOwnership {
        table: String,
        pk_cols: Vec<ColumnName>,
        owner_col: ColumnName,
        /// One relation per column, so two ownership columns cannot union their
        /// principals.
        relation: RelationName,
    },

    /// P11 array membership. Produces `(type:pk, relation, user:element)` by
    /// expanding `array_col`, which drops a NULL or empty array exactly as
    /// `= ANY` refuses it.
    ArrayMembership {
        table: String,
        pk_cols: Vec<ColumnName>,
        array_col: ColumnName,
        relation: RelationName,
    },

    /// P12 jsonb field ownership. Produces `(type:pk, relation, user:field)` by
    /// extracting `path` as text, dropping the NULL a missing key yields.
    JsonbFieldOwnership {
        table: String,
        pk_cols: Vec<ColumnName>,
        column: ColumnName,
        path: Vec<String>,
        relation: RelationName,
    },

    /// P1/P2 owner identity: `(owner_type:pk, relation, subject_type:pk)` over a
    /// principal table.
    ///
    /// The policy compares the caller against the owner value itself, so this is that
    /// comparison as a fact: the owner identity X is the principal X, true whether or
    /// not X owns a row.
    OwnerIdentity {
        /// Type the owner identities belong to.
        owner_type: String,
        principal_table: String,
        principal_pk_col: ColumnName,
        /// `user` or `team`.
        subject_type: String,
        relation: RelationName,
    },

    /// P1/P2 explicit grants. Produces one
    /// `(owner_type:grant_resource_col, grant_relation, user:grantee_col)` query per role
    /// case. Reads no guarded table: a grant is a fact about the owner it names.
    ExplicitGrants {
        /// Type the granted owner identities belong to.
        owner_type: String,
        grant_table: String,
        /// Column of `grant_table` holding the integer role level.
        grant_role_col: ColumnName,
        grant_grantee_col: ColumnName,
        grant_resource_col: ColumnName,
        /// `(level, grant_relation, original_name)`. The relation goes into the SQL
        /// `CASE`, the original name into the comment.
        role_cases: Vec<(i32, RelationName, String)>,
        user_principal: Option<PrincipalInfo>,
        team_principal: Option<PrincipalInfo>,
    },

    /// P1/P2 team membership. Produces `(team:team_col, member, user:user_col)`.
    TeamMembership {
        membership_table: String,
        team_col: ColumnName,
        user_col: ColumnName,
    },

    /// P4 membership, from `EXISTS` or an `IN` subquery.
    /// Produces `(parent_type:fk_col, member, user:user_col)`.
    ExistsMembership {
        join_table: String,
        /// Column of `join_table` referencing the parent resource.
        fk_col: ColumnName,
        user_col: ColumnName,
        /// Resolved from the table `fk_col` references, not from its name.
        parent_type: String,
        /// Residual predicate, structured where a row image alone decides it.
        extra_predicates: ResidualPredicates,
        /// The clock condition its member tuple names, absent for a plain membership.
        gate: Option<MembershipGate>,
    },

    /// P4/P5 child-to-parent link. Produces `(type:pk, relation, parent_type:fk_col)`.
    ///
    /// The object column is resolved at render time, keeping the IR free of schema
    /// lookups.
    ParentBridge {
        table: String,
        fk_col: ColumnName,
        parent_type: String,
        /// Named after `parent_type` but subject to the shorter relation-name limit,
        /// so the two can differ.
        relation: RelationName,
    },

    /// P6 public flag. Produces `(type:pk, public_viewer, user:*)` where the flag holds.
    PublicFlag {
        table: String,
        pk_cols: Vec<ColumnName>,
        flag_col: ColumnName,
    },

    /// P9 attribute guard over a literal constant. Produces
    /// `(type:pk, public_viewer, user:*)` for the rows the guard admits.
    AttributeGate {
        table: String,
        pk_cols: Vec<ColumnName>,
        predicate: AttributePredicate,
    },

    /// P9 guard the service evaluates per check. Produces
    /// `(type:pk, relation, user:*, condition, context)` where the context carries the
    /// row's own value for the parameter the request cannot supply.
    ConditionalAttributeGate {
        table: String,
        pk_cols: Vec<ColumnName>,
        relation: RelationName,
        condition: String,
        /// Condition parameter the row supplies, and the column it reads.
        row_parameter: String,
        column: ColumnName,
    },

    /// A declared request-scoped value the service compares per check. Produces
    /// `(type:pk, relation, user:*, condition, context)` where the context carries what
    /// only the row or the rule knows: the row's own value, or the constant the policy
    /// named.
    SessionAttributeGate {
        table: String,
        pk_cols: Vec<ColumnName>,
        relation: RelationName,
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

    /// A share row keyed on its own join-table primary key, gated by a conditional
    /// wildcard: the caller passes only when the row's member value is in the caller's
    /// set (and any composed clock still holds). Produces
    /// `(share_type:pk, relation, user:*, condition, context)` per share row, so two
    /// viewers of one guarded row become two objects rather than colliding on one.
    CallerSetShareGate {
        /// Table whose rows record the grants.
        join_table: String,
        /// Primary key of `join_table`, which the share object is keyed on so each row is
        /// its own object.
        pk_cols: Vec<ColumnName>,
        /// Synthetic type the share objects belong to.
        share_type: String,
        relation: RelationName,
        condition: String,
        /// Condition parameter the share row supplies.
        row_parameter: String,
        /// Column of `join_table` holding the value the caller's set must contain.
        member_col: ColumnName,
        /// Condition parameter the caller supplies in every check context.
        request_parameter: String,
        /// Session setting the caller's value mirrors, so the contract can name it.
        setting_key: String,
        /// Separator the policy splits that setting on, absent for a list source.
        separator: Option<String>,
        /// Residual filter on the share row.
        extra_predicates: ResidualPredicates,
        /// Temporal comparisons composed into the condition: each carries its row column
        /// in the context and compares it against the request clock. Empty when the arm
        /// carries no clock, in which case the shape may still join on its residual.
        temporal_context: Vec<GateContextColumn>,
    },

    /// Links a guarded row to each of its share objects, so a caller a share admits
    /// reaches the guarded row through the share. Produces
    /// `(guarded_type:fk_col, relation, share_type:pk)` per share row, read from the join
    /// table.
    CallerSetShareBridge {
        join_table: String,
        /// Primary key of `join_table`, which the share subject is keyed on.
        pk_cols: Vec<ColumnName>,
        /// Column of `join_table` naming the guarded row the share is on.
        fk_col: ColumnName,
        /// The guarded table's own type, which the objects belong to.
        guarded_type: String,
        /// Synthetic type the share subjects belong to.
        share_type: String,
        relation: RelationName,
    },

    /// P10 constant `TRUE`. Produces `(type:pk, public_viewer, user:*)` for every row.
    ConstantTrue {
        table: String,
        pk_cols: Vec<ColumnName>,
    },

    /// Links every row of a role-scoped table to the scope its policy declares. Produces
    /// `(type:pk, scope_relation, scope_type:scope_object)` per row.
    ///
    /// The roles the scope admits are a fact about the policy, carried once by
    /// [`Self::PolicyScopeRoles`], so a policy naming several roles no longer writes one fact
    /// per row per role.
    PolicyScope {
        table: String,
        pk_cols: Vec<ColumnName>,
        scope_relation: RelationName,
        /// Synthetic type the scope objects belong to.
        scope_type: String,
        /// Object id standing for this policy's scope.
        scope_object: String,
    },

    /// One role a policy's scope admits: `(scope_type:scope_object, roles, pg_role:pg_role)`.
    ///
    /// Names no table. Which roles a scope admits is decided by the policy, so the query is
    /// a constant `SELECT` yielding exactly one row whatever any table holds. Reading it off
    /// the guarded table instead tied the fact to that table having rows, and made every row
    /// of it look like a reason the fact exists.
    PolicyScopeRoles {
        scope_type: String,
        scope_object: String,
        relation: RelationName,
        pg_role: String,
    },

    /// Every row of `table` pointing at the one holder object, so a member of the
    /// holder reaches all of them.
    HolderBridge {
        table: String,
        pk_cols: Vec<ColumnName>,
        relation: RelationName,
        holder_type: String,
    },

    /// Everyone listed in `member_table`, attached to the holder object.
    HolderMembers {
        holder_type: String,
        member_table: String,
        user_col: ColumnName,
        extra_predicates: ResidualPredicates,
        /// The clock condition its member tuple names, absent for a plain membership.
        gate: Option<MembershipGate>,
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
            | Self::ParentBridge { .. }
            | Self::PublicFlag { .. }
            | Self::AttributeGate { .. }
            | Self::ConditionalAttributeGate { .. }
            | Self::SessionAttributeGate { .. }
            | Self::ConstantTrue { .. }
            | Self::PolicyScope { .. }
            | Self::HolderBridge { .. }
            | Self::CallerSetShareBridge { .. } => true,
            Self::PolicyScopeRoles { .. }
            | Self::OwnerIdentity { .. }
            | Self::ExplicitGrants { .. }
            | Self::TeamMembership { .. }
            | Self::ExistsMembership { .. }
            | Self::CallerSetShareGate { .. }
            | Self::HolderMembers { .. }
            | Self::Skipped { .. } => false,
        }
    }

    /// The `(type, relation)` pairs this source populates. Empty means it carries no
    /// tuples, so it is never dropped as unreachable.
    pub(crate) fn feeds(
        &self,
        owner_type: &TypeName,
        well_known: &WellKnownTypes,
    ) -> Vec<(String, RelationName)> {
        let own = |relation: &RelationName| vec![(owner_type.to_string(), relation.clone())];
        match self {
            Self::DirectOwnership { relation, .. }
            | Self::ArrayMembership { relation, .. }
            | Self::JsonbFieldOwnership { relation, .. }
            | Self::ParentBridge { relation, .. }
            | Self::ConditionalAttributeGate { relation, .. }
            | Self::SessionAttributeGate { relation, .. }
            | Self::CallerSetShareBridge { relation, .. }
            | Self::HolderBridge { relation, .. } => own(relation),
            Self::OwnerIdentity {
                owner_type,
                relation,
                ..
            } => vec![(owner_type.clone(), relation.clone())],
            Self::ExplicitGrants {
                owner_type,
                role_cases,
                ..
            } => role_cases
                .iter()
                .map(|(_, relation, _)| (owner_type.clone(), relation.clone()))
                .collect(),
            Self::TeamMembership { .. } => vec![(well_known.team.clone(), member_relation())],
            Self::ExistsMembership { parent_type, .. } => {
                vec![(parent_type.clone(), member_relation())]
            }
            Self::HolderMembers { holder_type, .. } => {
                vec![(holder_type.clone(), member_relation())]
            }
            Self::CallerSetShareGate {
                share_type,
                relation,
                ..
            } => vec![(share_type.clone(), relation.clone())],
            Self::PublicFlag { .. } | Self::AttributeGate { .. } | Self::ConstantTrue { .. } => {
                own(&public_relation())
            }
            Self::PolicyScope { scope_relation, .. } => own(scope_relation),
            Self::PolicyScopeRoles {
                scope_type,
                relation,
                ..
            } => vec![(scope_type.clone(), relation.clone())],
            Self::Skipped { .. } => Vec::new(),
        }
    }

    /// A stable string key used to deduplicate identical tuple queries.
    ///
    /// Two sources with the same key produce the same SQL. Only the first is emitted.
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
            Self::OwnerIdentity {
                owner_type,
                principal_table,
                principal_pk_col,
                subject_type,
                relation,
            } => {
                format!(
                    "owner_identity:{owner_type}:{principal_table}:{principal_pk_col}:\
                     {subject_type}:{relation}"
                )
            }
            Self::ExplicitGrants {
                owner_type,
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
                    "grants:{owner_type}:{grant_table}:{grant_role_col}:\
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
                extra_predicates,
                gate,
            } => {
                let extra = extra_predicates.sql().unwrap_or_default();
                format!("p4:{join_table}:{fk_col}:{user_col}:{parent_type}:{extra}:{gate:?}")
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
                    row_parameter.column().map_or("", ColumnName::as_str)
                )
            }
            Self::CallerSetShareGate {
                join_table,
                pk_cols,
                share_type,
                member_col,
                relation,
                condition,
                row_parameter,
                request_parameter,
                setting_key,
                separator,
                extra_predicates,
                temporal_context,
            } => {
                let _ = (setting_key, separator);
                let temporal = temporal_context
                    .iter()
                    .map(|gate| format!("{}={}", gate.parameter, gate.column))
                    .collect::<Vec<_>>()
                    .join(",");
                format!(
                    "sharegate:{share_type}:{join_table}:{pk_cols:?}:{member_col}:{relation}:\
                     {condition}:{row_parameter}:{request_parameter}:{}:{temporal}",
                    extra_predicates.sql().unwrap_or_default()
                )
            }
            Self::CallerSetShareBridge {
                join_table,
                pk_cols,
                fk_col,
                guarded_type,
                share_type,
                relation,
            } => {
                format!(
                    "sharebridge:{guarded_type}:{join_table}:{pk_cols:?}:{fk_col}:{share_type}:{relation}"
                )
            }
            Self::ConstantTrue { table, pk_cols } => {
                format!("p10_true:{table}:{pk_cols:?}")
            }
            Self::PolicyScope {
                table,
                pk_cols,
                scope_relation,
                scope_type,
                scope_object,
            } => {
                format!("scope:{table}:{pk_cols:?}:{scope_relation}:{scope_type}:{scope_object}")
            }
            Self::PolicyScopeRoles {
                scope_type,
                scope_object,
                relation,
                pg_role,
            } => {
                format!("scoperoles:{scope_type}:{scope_object}:{relation}:{pg_role}")
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
                extra_predicates,
                gate,
            } => {
                format!(
                    "holdermembers:{holder_type}:{member_table}:{user_col}:{}:{gate:?}",
                    extra_predicates.sql().unwrap_or_default()
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
    use crate::classifier::patterns::ResidualPredicate;
    use crate::generator::well_known::owner_user_relation;

    fn grants(owner_type: &str, grant_table: &str) -> TupleSource {
        TupleSource::ExplicitGrants {
            owner_type: owner_type.to_string(),
            grant_table: grant_table.to_string(),
            grant_role_col: ColumnName::from_stored("role"),
            grant_grantee_col: ColumnName::from_stored("grantee"),
            grant_resource_col: ColumnName::from_stored("resource_id"),
            role_cases: vec![(
                1,
                RelationName::from_resolved("viewer"),
                "viewer".to_string(),
            )],
            user_principal: None,
            team_principal: None,
        }
    }

    /// A grant is a fact about the owner it names, so two guarded tables reading one
    /// grant table write it once. Emitting it per table is the fan-out this shape exists
    /// to remove.
    #[test]
    fn dedup_key_collapses_explicit_grants_over_one_owner() {
        assert_eq!(
            grants("grants_owner", "grants").dedup_key(),
            grants("grants_owner", "grants").dedup_key()
        );
        assert_ne!(
            grants("grants_owner", "grants").dedup_key(),
            grants("other_owner", "grants").dedup_key(),
            "two owner namespaces must not pool their grants"
        );
    }

    /// The identity fact says the owner is a principal, so it is keyed on the namespace
    /// and the principal table, never on a guarded table.
    #[test]
    fn dedup_key_separates_owner_identities_by_namespace_and_principal() {
        let identity = |owner_type: &str, principal: &str| TupleSource::OwnerIdentity {
            owner_type: owner_type.to_string(),
            principal_table: principal.to_string(),
            principal_pk_col: ColumnName::from_stored("id"),
            subject_type: "user".to_string(),
            relation: owner_user_relation(),
        };
        assert_eq!(
            identity("grants_owner", "users").dedup_key(),
            identity("grants_owner", "users").dedup_key()
        );
        assert_ne!(
            identity("grants_owner", "users").dedup_key(),
            identity("other_owner", "users").dedup_key()
        );
        assert_ne!(
            identity("grants_owner", "users").dedup_key(),
            identity("grants_owner", "people").dedup_key()
        );
    }

    #[test]
    fn dedup_key_differentiates_team_membership_by_columns() {
        let mem_a = TupleSource::TeamMembership {
            membership_table: "team_members".to_string(),
            team_col: ColumnName::from_stored("team_id"),
            user_col: ColumnName::from_stored("user_id"),
        };
        let mem_b = TupleSource::TeamMembership {
            membership_table: "team_members".to_string(),
            team_col: ColumnName::from_stored("group_id"),
            user_col: ColumnName::from_stored("member_id"),
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
            fk_col: ColumnName::from_stored("project_id"),
            user_col: ColumnName::from_stored("user_id"),
            parent_type: "projects".to_string(),
            extra_predicates: ResidualPredicates::default(),
            gate: None,
        };
        let different_user = TupleSource::ExistsMembership {
            join_table: "members".to_string(),
            fk_col: ColumnName::from_stored("project_id"),
            user_col: ColumnName::from_stored("member_id"),
            parent_type: "projects".to_string(),
            extra_predicates: ResidualPredicates::default(),
            gate: None,
        };
        let with_predicate = TupleSource::ExistsMembership {
            join_table: "members".to_string(),
            fk_col: ColumnName::from_stored("project_id"),
            user_col: ColumnName::from_stored("user_id"),
            parent_type: "projects".to_string(),
            extra_predicates: ResidualPredicates::new(vec![ResidualPredicate {
                sql: "role = 'admin'".to_string(),
                guard: None,
                request: None,
            }]),
            gate: None,
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

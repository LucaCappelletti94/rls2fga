//! Shared authorization intermediate representation.
//!
//! [`TupleSource`] says how to populate one `OpenFGA` relation from SQL. It is
//! produced once during pattern translation, so the model and the tuple queries
//! cannot drift apart.

use crate::classifier::patterns::{AttributePredicate, ResidualPredicates};
use crate::generator::model_generator::RowParameter;
use crate::generator::notes::SkippedTuples;
use crate::generator::well_known::{member_relation, WellKnownTypes};
#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use crate::types::RequestComparison;
use crate::types::{ColumnName, RelationName, TableId, TypeName};

/// Principal table (users or teams) named by a role-threshold function.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct PrincipalInfo {
    /// Table that stores the principal entities.
    pub table: TableId,
    pub identity_col: ColumnName,
}

/// Which value of a compressed column witnesses the comparison when several rows
/// collapse into one fact. Sound either way, because the carried value is a real
/// row's value. The direction decides completeness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ContextWitness {
    /// `MAX`, exact for future comparisons and sound for equality.
    Latest,
    /// `MIN`, exact for past comparisons.
    Earliest,
}

/// One condition-context entry a conditional membership tuple carries: the parameter
/// name the row fills and the column its value is read from.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct GateContextColumn {
    /// Condition parameter the value fills.
    pub parameter: String,
    /// Column of the join table the value is read from.
    pub column: ColumnName,
    /// The compressing aggregate's direction, unused where no compression happens.
    pub witness: ContextWitness,
}

/// The condition a temporal membership tuple names, with every column its context
/// carries. Present on a membership source only when a clock comparison rides its member
/// tuple. Absent for a plain member tuple.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
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
        table: TableId,
        identity_cols: Vec<ColumnName>,
        owner_col: ColumnName,
        /// One relation per column, so two ownership columns cannot union their
        /// principals.
        relation: RelationName,
    },

    /// P11 array membership. Produces `(type:pk, relation, user:element)` by
    /// expanding `array_col`, which drops a NULL or empty array exactly as
    /// `= ANY` refuses it.
    ArrayMembership {
        table: TableId,
        identity_cols: Vec<ColumnName>,
        array_col: ColumnName,
        relation: RelationName,
    },

    /// P12 jsonb field ownership. Produces `(type:pk, relation, user:field)` by
    /// extracting `path` as text, dropping the NULL a missing key yields.
    JsonbFieldOwnership {
        table: TableId,
        identity_cols: Vec<ColumnName>,
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
        principal_table: TableId,
        principal_identity_col: ColumnName,
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
        grant_table: TableId,
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
        membership_table: TableId,
        team_col: ColumnName,
        user_col: ColumnName,
    },

    /// P4 membership, from `EXISTS` or an `IN` subquery.
    /// Produces `(parent_type:fk_cols, member, user:user_col)`.
    ExistsMembership {
        join_table: TableId,
        /// Columns of `join_table` naming the parent resource, in the parent
        /// key's order.
        fk_cols: Vec<ColumnName>,
        user_col: ColumnName,
        /// Resolved from the table the columns reference, not from their names.
        parent_type: String,
        /// Residual predicate, structured where a row image alone decides it.
        extra_predicates: ResidualPredicates,
        /// The clock condition its member tuple names, absent for a plain membership.
        gate: Option<MembershipGate>,
    },

    /// P4/P5 child-to-parent link. Produces `(type:pk, relation, parent_type:fk_cols)`.
    ///
    /// The object column is resolved at render time, keeping the IR free of schema
    /// lookups.
    ParentBridge {
        table: TableId,
        /// Columns of `table` naming the parent, in the parent key's order.
        fk_cols: Vec<ColumnName>,
        parent_type: String,
        /// Named after `parent_type` but subject to the shorter relation-name limit,
        /// so the two can differ.
        relation: RelationName,
    },

    /// P6 public flag. Produces `(type:pk, relation, user:*)` where the flag holds.
    PublicFlag {
        table: TableId,
        identity_cols: Vec<ColumnName>,
        flag_col: ColumnName,
        relation: RelationName,
    },

    /// A strict function's column arguments must be present before its body can grant.
    RowPresenceGate {
        table: TableId,
        identity_cols: Vec<ColumnName>,
        relation: RelationName,
        columns: Vec<ColumnName>,
    },

    /// P9 attribute guard over a literal constant. Produces
    /// `(type:pk, relation, user:*)` for the rows the guard admits.
    AttributeGate {
        table: TableId,
        identity_cols: Vec<ColumnName>,
        predicate: AttributePredicate,
        relation: RelationName,
    },

    /// P9 guard the service evaluates per check. Produces
    /// `(type:pk, relation, user:*, condition, context)` where the context carries the
    /// row's own value for the parameter the request cannot supply.
    ConditionalAttributeGate {
        table: TableId,
        identity_cols: Vec<ColumnName>,
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
        table: TableId,
        identity_cols: Vec<ColumnName>,
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
        join_table: TableId,
        /// Primary key of `join_table`, which the share object is keyed on so each row is
        /// its own object.
        identity_cols: Vec<ColumnName>,
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
    /// `(guarded_type:object_cols, relation, share_type:identity)` per share row, read
    /// from the join table.
    ShareBridge {
        join_table: TableId,
        /// Declared row identity of `join_table`, which the share subject is keyed on.
        identity_cols: Vec<ColumnName>,
        /// Columns of `join_table` naming the guarded row the share is on.
        object_cols: Vec<ColumnName>,
        /// The guarded table's own type, which the objects belong to.
        guarded_type: String,
        /// Synthetic type the share subjects belong to.
        share_type: String,
        relation: RelationName,
    },

    /// A membership row as its own witness object: the member is the subject and the
    /// row's own clock values ride the tuple, so the condition is evaluated per row
    /// exactly as `EXISTS` is. Produces
    /// `(share_type:identity, relation, user:user_col, condition, context)` per row.
    MembershipShareMembers {
        join_table: TableId,
        /// Declared row identity of `join_table`, keying each witness object.
        identity_cols: Vec<ColumnName>,
        user_col: ColumnName,
        /// Synthetic type the witness objects belong to.
        share_type: String,
        /// The share type's member relation this policy's tuples feed. Minted per
        /// condition, so two policies over one join table never collide their clocks.
        relation: RelationName,
        condition: String,
        /// Residual filter on the membership row, requests excluded by the condition.
        extra_predicates: ResidualPredicates,
        /// Clock comparisons composed into the condition, one context column each.
        context: Vec<GateContextColumn>,
    },

    /// P10 constant `TRUE`. Produces `(type:pk, relation, user:*)` for every row.
    ConstantTrue {
        table: TableId,
        identity_cols: Vec<ColumnName>,
        relation: RelationName,
    },

    /// Links every row of a role-scoped table to the scope its policy declares. Produces
    /// `(type:pk, scope_relation, scope_type:scope_object)` per row.
    ///
    /// The roles the scope admits are a fact about the policy, carried once by
    /// [`Self::PolicyScopeRoles`], so a policy naming several roles no longer writes one fact
    /// per row per role.
    PolicyScope {
        table: TableId,
        identity_cols: Vec<ColumnName>,
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
        table: TableId,
        identity_cols: Vec<ColumnName>,
        relation: RelationName,
        holder_type: String,
    },

    /// Links the one holder object to each membership row's witness. Produces
    /// `(holder_type:all, relation, share_type:identity)` per row.
    HolderShares {
        member_table: TableId,
        /// Declared row identity of `member_table`, keying each witness subject.
        identity_cols: Vec<ColumnName>,
        holder_type: String,
        share_type: String,
        relation: RelationName,
    },

    /// Everyone listed in `member_table`, attached to the holder object.
    HolderMembers {
        holder_type: String,
        member_table: TableId,
        user_col: ColumnName,
        extra_predicates: ResidualPredicates,
        /// The clock condition its member tuple names, absent for a plain membership.
        gate: Option<MembershipGate>,
    },

    /// Why no tuple query stands here. Rendered as the two comment lines that take
    /// its place in the loader's script.
    Skipped { reason: SkippedTuples },
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ResidualSqlKey<'a> {
    predicates: &'a ResidualPredicates,
    include_requests: bool,
}

impl ResidualSqlKey<'_> {
    fn all(predicates: &ResidualPredicates) -> ResidualSqlKey<'_> {
        ResidualSqlKey {
            predicates,
            include_requests: true,
        }
    }

    fn excluding_requests(predicates: &ResidualPredicates) -> ResidualSqlKey<'_> {
        ResidualSqlKey {
            predicates,
            include_requests: false,
        }
    }

    fn conjuncts(&self) -> impl Iterator<Item = &str> {
        self.predicates.sql_conjuncts(self.include_requests)
    }
}

impl PartialEq for ResidualSqlKey<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.conjuncts().eq(other.conjuncts())
    }
}

impl Eq for ResidualSqlKey<'_> {}

impl PartialOrd for ResidualSqlKey<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ResidualSqlKey<'_> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.conjuncts().cmp(other.conjuncts())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum TupleSourceKey<'a> {
    DirectOwnership {
        table: &'a TableId,
        identity_cols: &'a [ColumnName],
        owner_col: &'a ColumnName,
        relation: &'a RelationName,
    },
    ArrayMembership {
        table: &'a TableId,
        identity_cols: &'a [ColumnName],
        array_col: &'a ColumnName,
        relation: &'a RelationName,
    },
    JsonbFieldOwnership {
        table: &'a TableId,
        identity_cols: &'a [ColumnName],
        column: &'a ColumnName,
        path: &'a [String],
        relation: &'a RelationName,
    },
    OwnerIdentity {
        owner_type: &'a str,
        principal_table: &'a TableId,
        principal_identity_col: &'a ColumnName,
        subject_type: &'a str,
        relation: &'a RelationName,
    },
    ExplicitGrants {
        owner_type: &'a str,
        grant_table: &'a TableId,
        grant_role_col: &'a ColumnName,
        grant_grantee_col: &'a ColumnName,
        grant_resource_col: &'a ColumnName,
        role_cases: &'a [(i32, RelationName, String)],
        user_principal: Option<&'a PrincipalInfo>,
        team_principal: Option<&'a PrincipalInfo>,
    },
    TeamMembership {
        membership_table: &'a TableId,
        team_col: &'a ColumnName,
        user_col: &'a ColumnName,
    },
    ExistsMembership {
        join_table: &'a TableId,
        fk_cols: &'a [ColumnName],
        user_col: &'a ColumnName,
        parent_type: &'a str,
        extra_predicates: ResidualSqlKey<'a>,
        gate: Option<&'a MembershipGate>,
    },
    ParentBridge {
        table: &'a TableId,
        fk_cols: &'a [ColumnName],
        parent_type: &'a str,
        relation: &'a RelationName,
    },
    PublicFlag {
        table: &'a TableId,
        identity_cols: &'a [ColumnName],
        flag_col: &'a ColumnName,
        relation: &'a RelationName,
    },
    RowPresenceGate {
        table: &'a TableId,
        identity_cols: &'a [ColumnName],
        columns: &'a [ColumnName],
        relation: &'a RelationName,
    },
    AttributeGate {
        table: &'a TableId,
        identity_cols: &'a [ColumnName],
        predicate: &'a AttributePredicate,
        relation: &'a RelationName,
    },
    ConditionalAttributeGate {
        table: &'a TableId,
        identity_cols: &'a [ColumnName],
        relation: &'a RelationName,
        condition: &'a str,
        row_parameter: &'a str,
        column: &'a ColumnName,
    },
    SessionAttributeGate {
        table: &'a TableId,
        identity_cols: &'a [ColumnName],
        relation: &'a RelationName,
        condition: &'a str,
        row_parameter: &'a RowParameter,
        request_parameter: &'a str,
        comparison: RequestComparison,
    },
    CallerSetShareGate {
        share_type: &'a str,
        join_table: &'a TableId,
        identity_cols: &'a [ColumnName],
        member_col: &'a ColumnName,
        relation: &'a RelationName,
        condition: &'a str,
        row_parameter: &'a str,
        request_parameter: &'a str,
        extra_predicates: ResidualSqlKey<'a>,
        temporal_context: &'a [GateContextColumn],
    },
    ShareBridge {
        guarded_type: &'a str,
        join_table: &'a TableId,
        identity_cols: &'a [ColumnName],
        object_cols: &'a [ColumnName],
        share_type: &'a str,
        relation: &'a RelationName,
    },
    MembershipShareMembers {
        join_table: &'a TableId,
        identity_cols: &'a [ColumnName],
        user_col: &'a ColumnName,
        share_type: &'a str,
        relation: &'a RelationName,
        condition: &'a str,
        extra_predicates: ResidualSqlKey<'a>,
        context: &'a [GateContextColumn],
    },
    HolderShares {
        member_table: &'a TableId,
        identity_cols: &'a [ColumnName],
        holder_type: &'a str,
        share_type: &'a str,
        relation: &'a RelationName,
    },
    ConstantTrue {
        table: &'a TableId,
        identity_cols: &'a [ColumnName],
        relation: &'a RelationName,
    },
    PolicyScope {
        table: &'a TableId,
        identity_cols: &'a [ColumnName],
        scope_relation: &'a RelationName,
        scope_type: &'a str,
        scope_object: &'a str,
    },
    PolicyScopeRoles {
        scope_type: &'a str,
        scope_object: &'a str,
        relation: &'a RelationName,
        pg_role: &'a str,
    },
    HolderBridge {
        table: &'a TableId,
        identity_cols: &'a [ColumnName],
        relation: &'a RelationName,
        holder_type: &'a str,
    },
    HolderMembers {
        holder_type: &'a str,
        member_table: &'a TableId,
        user_col: &'a ColumnName,
        extra_predicates: ResidualSqlKey<'a>,
        gate: Option<&'a MembershipGate>,
    },
    Skipped {
        reason: &'a SkippedTuples,
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
            | Self::ArrayMembership { .. }
            | Self::JsonbFieldOwnership { .. }
            | Self::ParentBridge { .. }
            | Self::PublicFlag { .. }
            | Self::RowPresenceGate { .. }
            | Self::AttributeGate { .. }
            | Self::ConditionalAttributeGate { .. }
            | Self::SessionAttributeGate { .. }
            | Self::ConstantTrue { .. }
            | Self::PolicyScope { .. }
            | Self::HolderBridge { .. } => true,
            Self::ShareBridge { .. }
            | Self::PolicyScopeRoles { .. }
            | Self::OwnerIdentity { .. }
            | Self::ExplicitGrants { .. }
            | Self::TeamMembership { .. }
            | Self::ExistsMembership { .. }
            | Self::CallerSetShareGate { .. }
            | Self::MembershipShareMembers { .. }
            | Self::HolderShares { .. }
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
            | Self::RowPresenceGate { relation, .. }
            | Self::ConditionalAttributeGate { relation, .. }
            | Self::SessionAttributeGate { relation, .. }
            | Self::PublicFlag { relation, .. }
            | Self::AttributeGate { relation, .. }
            | Self::ConstantTrue { relation, .. }
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
            Self::ShareBridge {
                guarded_type,
                relation,
                ..
            } => vec![(guarded_type.clone(), relation.clone())],
            Self::MembershipShareMembers {
                share_type,
                relation,
                ..
            }
            | Self::CallerSetShareGate {
                share_type,
                relation,
                ..
            } => vec![(share_type.clone(), relation.clone())],
            Self::HolderShares {
                holder_type,
                relation,
                ..
            } => vec![(holder_type.clone(), relation.clone())],
            Self::TeamMembership { .. } => {
                vec![(well_known.team.to_string(), member_relation())]
            }
            Self::ExistsMembership { parent_type, .. } => {
                vec![(parent_type.clone(), member_relation())]
            }
            Self::HolderMembers { holder_type, .. } => {
                vec![(holder_type.clone(), member_relation())]
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

    /// Borrowed structural identity of the rendered tuple query.
    pub(crate) fn dedup_key(&self) -> TupleSourceKey<'_> {
        match self {
            Self::DirectOwnership {
                table,
                identity_cols,
                owner_col,
                relation,
            } => TupleSourceKey::DirectOwnership {
                table,
                identity_cols,
                owner_col,
                relation,
            },
            Self::ArrayMembership {
                table,
                identity_cols,
                array_col,
                relation,
            } => TupleSourceKey::ArrayMembership {
                table,
                identity_cols,
                array_col,
                relation,
            },
            Self::JsonbFieldOwnership {
                table,
                identity_cols,
                column,
                path,
                relation,
            } => TupleSourceKey::JsonbFieldOwnership {
                table,
                identity_cols,
                column,
                path,
                relation,
            },
            Self::OwnerIdentity {
                owner_type,
                principal_table,
                principal_identity_col,
                subject_type,
                relation,
            } => TupleSourceKey::OwnerIdentity {
                owner_type,
                principal_table,
                principal_identity_col,
                subject_type,
                relation,
            },
            Self::ExplicitGrants {
                owner_type,
                grant_table,
                grant_role_col,
                grant_grantee_col,
                grant_resource_col,
                role_cases,
                user_principal,
                team_principal,
            } => TupleSourceKey::ExplicitGrants {
                owner_type,
                grant_table,
                grant_role_col,
                grant_grantee_col,
                grant_resource_col,
                role_cases,
                user_principal: user_principal.as_ref(),
                team_principal: team_principal.as_ref(),
            },
            Self::TeamMembership {
                membership_table,
                team_col,
                user_col,
            } => TupleSourceKey::TeamMembership {
                membership_table,
                team_col,
                user_col,
            },
            Self::ExistsMembership {
                join_table,
                fk_cols,
                user_col,
                parent_type,
                extra_predicates,
                gate,
            } => TupleSourceKey::ExistsMembership {
                join_table,
                fk_cols,
                user_col,
                parent_type,
                extra_predicates: if gate.is_some() {
                    ResidualSqlKey::excluding_requests(extra_predicates)
                } else {
                    ResidualSqlKey::all(extra_predicates)
                },
                gate: gate.as_ref(),
            },
            Self::ParentBridge {
                table,
                fk_cols,
                parent_type,
                relation,
            } => TupleSourceKey::ParentBridge {
                table,
                fk_cols,
                parent_type,
                relation,
            },
            Self::PublicFlag {
                table,
                identity_cols,
                flag_col,
                relation,
            } => TupleSourceKey::PublicFlag {
                table,
                identity_cols,
                flag_col,
                relation,
            },
            Self::RowPresenceGate {
                table,
                identity_cols,
                columns,
                relation,
            } => TupleSourceKey::RowPresenceGate {
                table,
                identity_cols,
                columns,
                relation,
            },
            Self::AttributeGate {
                table,
                identity_cols,
                predicate,
                relation,
            } => TupleSourceKey::AttributeGate {
                table,
                identity_cols,
                predicate,
                relation,
            },
            Self::ConditionalAttributeGate {
                table,
                identity_cols,
                relation,
                condition,
                row_parameter,
                column,
            } => TupleSourceKey::ConditionalAttributeGate {
                table,
                identity_cols,
                relation,
                condition,
                row_parameter,
                column,
            },
            Self::SessionAttributeGate {
                table,
                identity_cols,
                relation,
                condition,
                row_parameter,
                request_parameter,
                comparison,
                ..
            } => TupleSourceKey::SessionAttributeGate {
                table,
                identity_cols,
                relation,
                condition,
                row_parameter,
                request_parameter,
                comparison: *comparison,
            },
            Self::CallerSetShareGate {
                join_table,
                identity_cols,
                share_type,
                member_col,
                relation,
                condition,
                row_parameter,
                request_parameter,
                extra_predicates,
                temporal_context,
                ..
            } => TupleSourceKey::CallerSetShareGate {
                share_type,
                join_table,
                identity_cols,
                member_col,
                relation,
                condition,
                row_parameter,
                request_parameter,
                extra_predicates: if temporal_context.is_empty() {
                    ResidualSqlKey::all(extra_predicates)
                } else {
                    ResidualSqlKey::excluding_requests(extra_predicates)
                },
                temporal_context,
            },
            Self::ShareBridge {
                join_table,
                identity_cols,
                object_cols,
                guarded_type,
                share_type,
                relation,
            } => TupleSourceKey::ShareBridge {
                guarded_type,
                join_table,
                identity_cols,
                object_cols,
                share_type,
                relation,
            },
            Self::MembershipShareMembers {
                join_table,
                identity_cols,
                user_col,
                share_type,
                relation,
                condition,
                extra_predicates,
                context,
            } => TupleSourceKey::MembershipShareMembers {
                join_table,
                identity_cols,
                user_col,
                share_type,
                relation,
                condition,
                extra_predicates: ResidualSqlKey::excluding_requests(extra_predicates),
                context,
            },
            Self::HolderShares {
                member_table,
                identity_cols,
                holder_type,
                share_type,
                relation,
            } => TupleSourceKey::HolderShares {
                member_table,
                identity_cols,
                holder_type,
                share_type,
                relation,
            },
            Self::ConstantTrue {
                table,
                identity_cols,
                relation,
            } => TupleSourceKey::ConstantTrue {
                table,
                identity_cols,
                relation,
            },
            Self::PolicyScope {
                table,
                identity_cols,
                scope_relation,
                scope_type,
                scope_object,
            } => TupleSourceKey::PolicyScope {
                table,
                identity_cols,
                scope_relation,
                scope_type,
                scope_object,
            },
            Self::PolicyScopeRoles {
                scope_type,
                scope_object,
                relation,
                pg_role,
            } => TupleSourceKey::PolicyScopeRoles {
                scope_type,
                scope_object,
                relation,
                pg_role,
            },
            Self::HolderBridge {
                table,
                identity_cols,
                relation,
                holder_type,
            } => TupleSourceKey::HolderBridge {
                table,
                identity_cols,
                relation,
                holder_type,
            },
            Self::HolderMembers {
                holder_type,
                member_table,
                user_col,
                extra_predicates,
                gate,
            } => TupleSourceKey::HolderMembers {
                holder_type,
                member_table,
                user_col,
                extra_predicates: if gate.is_some() {
                    ResidualSqlKey::excluding_requests(extra_predicates)
                } else {
                    ResidualSqlKey::all(extra_predicates)
                },
                gate: gate.as_ref(),
            },
            Self::Skipped { reason } => TupleSourceKey::Skipped { reason },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classifier::patterns::ResidualPredicate;
    use crate::generator::well_known::owner_user_relation;

    fn table(name: &str) -> TableId {
        TableId::from_stored(None, name.to_string())
    }

    fn grants(owner_type: &str, grant_table: &str) -> TupleSource {
        TupleSource::ExplicitGrants {
            owner_type: owner_type.to_string(),
            grant_table: table(grant_table),
            grant_role_col: ColumnName::from_stored("role"),
            grant_grantee_col: ColumnName::from_stored("grantee"),
            grant_resource_col: ColumnName::from_stored("resource_id"),
            role_cases: vec![(
                1,
                RelationName::canonicalized("viewer"),
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
            principal_table: table(principal),
            principal_identity_col: ColumnName::from_stored("id"),
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
            membership_table: table("team_members"),
            team_col: ColumnName::from_stored("team_id"),
            user_col: ColumnName::from_stored("user_id"),
        };
        let mem_b = TupleSource::TeamMembership {
            membership_table: table("team_members"),
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
            join_table: table("members"),
            fk_cols: vec![ColumnName::from_stored("project_id")],
            user_col: ColumnName::from_stored("user_id"),
            parent_type: "projects".to_string(),
            extra_predicates: ResidualPredicates::default(),
            gate: None,
        };
        let different_user = TupleSource::ExistsMembership {
            join_table: table("members"),
            fk_cols: vec![ColumnName::from_stored("project_id")],
            user_col: ColumnName::from_stored("member_id"),
            parent_type: "projects".to_string(),
            extra_predicates: ResidualPredicates::default(),
            gate: None,
        };
        let with_predicate = TupleSource::ExistsMembership {
            join_table: table("members"),
            fk_cols: vec![ColumnName::from_stored("project_id")],
            user_col: ColumnName::from_stored("user_id"),
            parent_type: "projects".to_string(),
            extra_predicates: ResidualPredicates::new(vec![ResidualPredicate {
                sql: "role = 'admin'".to_string(),
                guard: None,
                request: None,
                relations: Vec::new(),
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
                table: table("docs"),
                attribute: "status = 'active'".to_string(),
            },
        };
        let unclassified = TupleSource::Skipped {
            reason: SkippedTuples::UnclassifiedExpression {
                table: table("docs"),
                reason: "no pattern".to_string(),
            },
        };
        assert_ne!(attribute.dedup_key(), unclassified.dedup_key());
    }
    #[test]
    fn dedup_key_separates_separator_text_across_identifier_fields() {
        let separator_in_team = TupleSource::TeamMembership {
            membership_table: table("team"),
            team_col: ColumnName::from_stored("members:team"),
            user_col: ColumnName::from_stored("user"),
        };
        let separator_in_user = TupleSource::TeamMembership {
            membership_table: table("team"),
            team_col: ColumnName::from_stored("members"),
            user_col: ColumnName::from_stored("team:user"),
        };

        assert_ne!(separator_in_team.dedup_key(), separator_in_user.dedup_key());
    }

    #[test]
    fn dedup_key_separates_explicit_grant_principal_joins() {
        let with_principal = |principal: &str| {
            let mut source = grants("grants_owner", "grants");
            let TupleSource::ExplicitGrants { user_principal, .. } = &mut source else {
                unreachable!();
            };
            *user_principal = Some(PrincipalInfo {
                table: table(principal),
                identity_col: ColumnName::from_stored("id"),
            });
            source
        };

        assert_ne!(
            with_principal("users").dedup_key(),
            with_principal("people").dedup_key()
        );
    }
}

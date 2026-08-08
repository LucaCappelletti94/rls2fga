//! What a translation reports about itself.
//!
//! Every note is a typed cause. Its sentence is rendered here and never stored beside
//! it, so a note cannot say one thing while its kind says another, and
//! [`NoteSeverity`] answers the question a caller actually has: whether anything went
//! unhandled, whether their own threshold dropped it, or whether the model simply says
//! what the database says.

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use core::fmt;

/// How a note bears on what the model says compared with the database.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum NoteSeverity {
    /// Nothing is missing. The model says what the database says.
    Faithful,
    /// The model is complete, but the operator has to supply or confirm something.
    ActionRequired,
    /// Translated in part, with the rest left to the caller to enforce.
    Partial,
    /// A clause the caller's own confidence threshold removed.
    BelowThreshold,
    /// A principal the database exempts from row level security entirely, so the model
    /// describes rules that do not reach them.
    Exempt,
    /// An expression nobody classified, so the model denies what the database may
    /// grant. The only severity that blocks reaching the model.
    Unhandled,
}

impl fmt::Display for NoteSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Faithful => "Faithful",
            Self::ActionRequired => "Action required",
            Self::Partial => "Partial",
            Self::BelowThreshold => "Below threshold",
            Self::Exempt => "Exempt",
            Self::Unhandled => "Unhandled",
        })
    }
}

impl NoteSeverity {
    /// Whether the model disagrees with the database about what the rules grant.
    ///
    /// [`NoteSeverity::Exempt`] is not a disagreement: the policies genuinely do not
    /// govern that principal, so the model is not wrong about them, it is saying the
    /// rules do not reach there. That belongs in the report rather than above the
    /// outputs beside a refused clause.
    ///
    /// Written as a refusal rather than a list, so a severity added later counts as a
    /// disagreement until someone decides otherwise.
    #[must_use]
    pub fn diverges_from_database(self) -> bool {
        !matches!(self, Self::Faithful | Self::ActionRequired | Self::Exempt)
    }
}

/// One thing a translation has to tell its caller about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TranslationNote {
    /// A function running as its owner cannot identify the caller.
    OwnerBoundFunction {
        /// Function the policies call.
        function: String,
    },
    /// A policy names something that is not one table in the schema.
    UnresolvedPolicyTable {
        /// Policy naming it.
        policy: String,
        /// The name as the policy spelled it.
        named: String,
    },
    /// A RESTRICTIVE clause guards on an attribute no relation can express.
    RestrictiveAttributeRefused {
        /// Policy carrying the clause.
        policy: String,
    },
    /// A barrier bound to roles binds everyone, since nothing can say who is bound.
    RestrictiveBarrierBindsEveryone {
        /// Policy carrying the barrier.
        policy: String,
        /// Roles it named.
        roles: Vec<String>,
    },
    /// Reading a table expands its policies, and a loop there raises `infinite
    /// recursion` rather than filtering.
    PolicyReadRecursion {
        /// Table whose commands the loop denies.
        table: String,
        /// Commands it denies.
        commands: Vec<String>,
        /// Tables the loop runs through, in order.
        cycle: Vec<String>,
    },
    /// No permissive policy covers these commands, so the database denies them too.
    NoPermissivePolicy {
        /// Table with no covering policy.
        table: String,
        /// Commands nothing covers.
        commands: Vec<String>,
    },
    /// Every policy covering these commands fell below the caller's threshold.
    CoveringPoliciesBelowThreshold {
        /// Table whose policies were dropped.
        table: String,
        /// Commands left uncovered by the drop.
        commands: Vec<String>,
    },
    /// A policy names a command without the clause that command needs.
    PolicyClauseAbsent {
        /// Policy missing the clause.
        policy: String,
        /// Commands it names.
        commands: String,
        /// Clause it does not store.
        clause: String,
    },
    /// Reads are denied, so no statement can name a row to change.
    ReadsDeniedSoWritesCannotName {
        /// Table whose reads are denied.
        table: String,
    },
    /// A policy's `TO` clause became a role scope relation.
    PolicyRoleScope {
        /// Policy carrying the clause.
        policy: String,
        /// Roles it names.
        roles: Vec<String>,
        /// Relation the scope became.
        relation: String,
    },
    /// A role test in the expression became a role scope relation.
    RoleGateScope {
        /// Policy carrying the test.
        policy: String,
        /// Roles it admits.
        roles: Vec<String>,
        /// Relation the gate became.
        relation: String,
        /// Relation on `pg_role` holding the kind of membership the policy asked about.
        held_by: String,
    },
    /// Reading the membership table needs a role, so the grant is scoped to it.
    MembershipReadScope {
        /// Policy holding the membership check.
        policy: String,
        /// Membership table only those roles may read.
        join_table: String,
        /// Roles that may read it.
        roles: Vec<String>,
        /// Relation the scope became.
        relation: String,
    },
    /// A role name is not an `OpenFGA` identifier and was rewritten.
    RoleNameRewritten {
        /// Policy naming the role.
        policy: String,
        /// Role as `PostgreSQL` spells it.
        role: String,
        /// Identifier it became.
        pg_role: String,
    },
    /// Two table spellings canonicalize to one type name.
    TypeNameCollision {
        /// Table whose type was renamed.
        spelling: String,
        /// Table already holding the name.
        prior: String,
        /// Name they both wanted.
        canonical: String,
        /// Name this one got instead.
        renamed: String,
    },
    /// The table has `INHERITS` children, so its tuple queries read `FROM ONLY` and
    /// child rows carry no tuples on this type.
    InheritanceParentReadsOwnRowsOnly {
        /// Inheritance parent whose type this is.
        table: String,
        /// Its direct children, whose rows fall closed on this type.
        children: Vec<String>,
    },
    /// The membership table grants no reads, so no membership row is visible.
    MembershipTableGrantsNoReads {
        /// Policy holding the membership check.
        policy: String,
        /// Membership table nobody may read.
        join_table: String,
    },
    /// Row level security on the membership table hides rows no relation can hide.
    MembershipTableGuarded {
        /// Policy holding the membership check.
        policy: String,
        /// Guarded membership table.
        join_table: String,
    },
    /// The membership check carries a predicate beyond the join.
    MembershipExtraPredicate {
        /// Policy holding the check.
        policy: String,
        /// The extra predicate, as written.
        predicate: String,
    },
    /// The parent-side rule of an inheritance is an expression nobody classified.
    ParentRuleUnknown {
        /// Policy inheriting from the parent.
        policy: String,
        /// Parent table.
        parent_table: String,
        /// Why the inner rule was refused.
        reason: String,
    },
    /// The parent-side rule could not be translated.
    ParentRuleUntranslated {
        /// Policy inheriting from the parent.
        policy: String,
        /// Parent table.
        parent_table: String,
    },
    /// The attribute half of a hybrid policy is the caller's to enforce.
    AttributeNeedsRuntimeEnforcement {
        /// Policy carrying the hybrid clause.
        policy: String,
        /// Attribute condition left to the caller.
        attribute: String,
    },
    /// An attribute policy standing alone is not decided by the row.
    StandaloneAttributePolicy {
        /// Policy carrying the condition.
        policy: String,
        /// Column it guards on.
        column: String,
    },
    /// An expression nobody classified.
    ExpressionRefused {
        /// Policy carrying the expression.
        policy: String,
        /// Why it was refused.
        reason: String,
    },
    /// A role-threshold function the registry says nothing about.
    FunctionMissingMetadata {
        /// Policy calling it.
        policy: String,
        /// What kind of call it is, as the caller describes it.
        function_kind: String,
        /// Function called.
        function: String,
    },
    /// A role the database exempts from row level security everywhere.
    RoleBypassesPolicies {
        /// Role carrying `BYPASSRLS`.
        role: String,
    },
    /// A table whose owner is exempt from its own policies, which is the default.
    TableOwnerBypassesPolicies {
        /// Table that does not force row level security on its owner.
        table: String,
        /// Role that owns it, where the schema says so. A schema that never assigns
        /// ownership records none, and the note then cannot name the exempt principal.
        owner: Option<String>,
    },
}

impl TranslationNote {
    /// How this note bears on what the model says compared with the database.
    #[must_use]
    pub fn severity(&self) -> NoteSeverity {
        match self {
            Self::OwnerBoundFunction { .. }
            | Self::UnresolvedPolicyTable { .. }
            | Self::RestrictiveAttributeRefused { .. }
            | Self::RestrictiveBarrierBindsEveryone { .. }
            | Self::ParentRuleUnknown { .. }
            | Self::ParentRuleUntranslated { .. }
            | Self::StandaloneAttributePolicy { .. }
            | Self::ExpressionRefused { .. }
            | Self::FunctionMissingMetadata { .. } => NoteSeverity::Unhandled,
            Self::RoleBypassesPolicies { .. } | Self::TableOwnerBypassesPolicies { .. } => {
                NoteSeverity::Exempt
            }
            Self::CoveringPoliciesBelowThreshold { .. } => NoteSeverity::BelowThreshold,
            Self::MembershipTableGuarded { .. }
            | Self::AttributeNeedsRuntimeEnforcement { .. }
            | Self::InheritanceParentReadsOwnRowsOnly { .. } => NoteSeverity::Partial,
            Self::ReadsDeniedSoWritesCannotName { .. }
            | Self::PolicyRoleScope { .. }
            | Self::RoleGateScope { .. }
            | Self::MembershipReadScope { .. }
            | Self::RoleNameRewritten { .. }
            | Self::TypeNameCollision { .. } => NoteSeverity::ActionRequired,
            Self::PolicyReadRecursion { .. }
            | Self::NoPermissivePolicy { .. }
            | Self::PolicyClauseAbsent { .. }
            | Self::MembershipTableGrantsNoReads { .. }
            | Self::MembershipExtraPredicate { .. } => NoteSeverity::Faithful,
        }
    }

    /// The policy, table or function the note is about.
    #[must_use]
    pub fn subject(&self) -> &str {
        match self {
            Self::OwnerBoundFunction { function } => function,
            Self::TypeNameCollision { spelling, .. } => spelling,
            Self::RoleBypassesPolicies { role } => role,
            Self::PolicyReadRecursion { table, .. }
            | Self::NoPermissivePolicy { table, .. }
            | Self::CoveringPoliciesBelowThreshold { table, .. }
            | Self::TableOwnerBypassesPolicies { table, .. }
            | Self::InheritanceParentReadsOwnRowsOnly { table, .. }
            | Self::ReadsDeniedSoWritesCannotName { table } => table,
            Self::UnresolvedPolicyTable { policy, .. }
            | Self::RestrictiveAttributeRefused { policy }
            | Self::RestrictiveBarrierBindsEveryone { policy, .. }
            | Self::PolicyClauseAbsent { policy, .. }
            | Self::PolicyRoleScope { policy, .. }
            | Self::RoleGateScope { policy, .. }
            | Self::MembershipReadScope { policy, .. }
            | Self::RoleNameRewritten { policy, .. }
            | Self::MembershipTableGrantsNoReads { policy, .. }
            | Self::MembershipTableGuarded { policy, .. }
            | Self::MembershipExtraPredicate { policy, .. }
            | Self::ParentRuleUnknown { policy, .. }
            | Self::ParentRuleUntranslated { policy, .. }
            | Self::AttributeNeedsRuntimeEnforcement { policy, .. }
            | Self::StandaloneAttributePolicy { policy, .. }
            | Self::ExpressionRefused { policy, .. }
            | Self::FunctionMissingMetadata { policy, .. } => policy,
        }
    }

    /// The sentence this note renders to.
    #[must_use]
    pub fn message(&self) -> String {
        self.to_string()
    }
}

impl fmt::Display for TranslationNote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OwnerBoundFunction { function } => write!(
                f,
                "Function '{function}' runs as its owner, so current_user inside it is the \
                 owner's name for every caller and identifies nobody; policies calling it are \
                 dropped"
            ),
            Self::UnresolvedPolicyTable { policy, named } => write!(
                f,
                "Policy '{policy}' names '{named}', which does not resolve to one table in the \
                 schema, so qualify it with a schema to have the policy translated"
            ),
            Self::RestrictiveBarrierBindsEveryone { policy, roles } => write!(
                f,
                "RESTRICTIVE policy '{policy}' binds only {}, but no tuple can name a row of \
                 this table, so nothing can say who is bound and the barrier is applied to \
                 everyone. That denies more than RLS does",
                roles.join(", ")
            ),
            Self::RestrictiveAttributeRefused { policy } => write!(
                f,
                "RESTRICTIVE policy '{policy}' guards on an attribute the model cannot express, \
                 so the command is denied"
            ),
            Self::PolicyReadRecursion {
                table,
                commands,
                cycle,
            } => write!(
                f,
                "PostgreSQL raises infinite recursion on {} of '{table}', since the policies it \
                 expands loop ({}), so the model denies to match",
                commands.join(", "),
                render_read_loop(cycle)
            ),
            Self::NoPermissivePolicy { table, commands } => write!(
                f,
                "No permissive policy on '{table}' covers {}; RLS denies {those} outright and \
                 the model mirrors that with no_access",
                commands.join(", "),
                those = if commands.len() == 1 { "it" } else { "them" }
            ),
            Self::CoveringPoliciesBelowThreshold { table, commands } => write!(
                f,
                "Every permissive policy on '{table}' covering {} fell below the confidence \
                 threshold, so the model denies what RLS grants",
                commands.join(", ")
            ),
            Self::PolicyClauseAbsent {
                policy,
                commands,
                clause,
            } => write!(
                f,
                "Policy '{policy}' names {commands} without a {clause} clause, so PostgreSQL \
                 admits no row through it"
            ),
            Self::ReadsDeniedSoWritesCannotName { table } => write!(
                f,
                "Reads of '{table}' are denied, so UPDATE and DELETE cannot name a row either. \
                 Add a SELECT policy the model can translate."
            ),
            Self::PolicyRoleScope {
                roles, relation, ..
            } => write!(
                f,
                "Policy role scope TO ({}) mapped to relation '{relation}'; ensure pg_role \
                 memberships are loaded",
                roles.join(", ")
            ),
            Self::RoleGateScope {
                roles,
                relation,
                held_by,
                ..
            } => write!(
                f,
                "Role gate ({}) mapped to relation '{relation}', which reads pg_role '{held_by}', \
                 so load that relation with the roles' holders of that kind",
                roles.join(", ")
            ),
            Self::MembershipReadScope {
                join_table,
                roles,
                relation,
                ..
            } => write!(
                f,
                "Reading membership table '{join_table}' needs PostgreSQL role ({}), mapped to \
                 relation '{relation}'; ensure pg_role memberships are loaded",
                roles.join(", ")
            ),
            Self::RoleNameRewritten { role, pg_role, .. } => write!(
                f,
                "PostgreSQL role '{role}' is not a valid OpenFGA identifier and was rewritten to \
                 'pg_role:{pg_role}'; confirm no other role maps to the same identifier"
            ),
            Self::TypeNameCollision {
                spelling,
                prior,
                canonical,
                renamed,
            } => write!(
                f,
                "Type name collision: '{spelling}' and '{prior}' both canonicalize to \
                 '{canonical}'. Renamed to '{renamed}'. Update your OpenFGA model references \
                 accordingly."
            ),
            Self::InheritanceParentReadsOwnRowsOnly { table, children } => write!(
                f,
                "'{table}' has inheritance children ({}), so its tuple queries read FROM ONLY \
                 its own rows. Child rows are readable through '{table}' in PostgreSQL but \
                 carry no tuples here, so the model denies them.",
                children.join(", ")
            ),
            Self::MembershipTableGrantsNoReads { join_table, .. } => write!(
                f,
                "Membership table '{join_table}' grants no reads, so no membership row is \
                 visible and the command is denied"
            ),
            Self::MembershipTableGuarded { join_table, .. } => write!(
                f,
                "Row level security on membership table '{join_table}' decides which membership \
                 rows a user sees, which no relation can express. Load tuples only for the rows \
                 it exposes."
            ),
            Self::MembershipExtraPredicate { predicate, .. } => write!(
                f,
                "Membership policy carries extra predicate '{predicate}' that must be preserved \
                 in tuple SQL"
            ),
            Self::ParentRuleUnknown {
                parent_table,
                reason,
                ..
            } => write!(
                f,
                "Parent inheritance from '{parent_table}' has unknown inner rule ({reason}); \
                 mapped to no_access"
            ),
            Self::ParentRuleUntranslated { parent_table, .. } => write!(
                f,
                "Parent inheritance from '{parent_table}' could not translate the parent-side \
                 rule, so the command is denied"
            ),
            Self::AttributeNeedsRuntimeEnforcement { attribute, .. } => write!(
                f,
                "Attribute condition '{attribute}' still requires runtime enforcement"
            ),
            Self::StandaloneAttributePolicy { column, .. } => write!(
                f,
                "Standalone attribute policy on '{column}' mapped to no_access for safety"
            ),
            Self::ExpressionRefused { reason, .. } => write!(
                f,
                "Expression could not be safely translated ({reason}); mapped to no_access"
            ),
            Self::FunctionMissingMetadata {
                function_kind,
                function,
                ..
            } => write!(
                f,
                "{function_kind} function '{function}' missing semantic metadata"
            ),
            Self::RoleBypassesPolicies { role } => write!(
                f,
                "Role '{role}' has BYPASSRLS, so every policy is skipped for it and the \
                 model answers for nobody connecting as that role"
            ),
            Self::TableOwnerBypassesPolicies { table, owner } => {
                let who = owner.as_ref().map_or_else(
                    || "the table's owner is".to_string(),
                    |owner| format!("its owner '{owner}' is"),
                );
                write!(
                    f,
                    "Row level security on '{table}' is not FORCEd, so {who} exempt from \
                     every policy on it. ALTER TABLE '{table}' FORCE ROW LEVEL SECURITY \
                     subjects them to it"
                )
            }
        }
    }
}

/// A loop in the policy read graph as `a reads b, b reads a`. A table reading itself is
/// a one-element loop.
fn render_read_loop(cycle: &[String]) -> String {
    let hops: Vec<String> = cycle
        .iter()
        .enumerate()
        .filter_map(|(index, table)| {
            let next = cycle.get(index + 1).or_else(|| cycle.first())?;
            Some(format!("{table} reads {next}"))
        })
        .collect();
    hops.join(", ")
}

/// Why a tuple query was not emitted, rendered as the two comment lines that stand in
/// its place in the loader's script.
///
/// Separate from [`TranslationNote`] because it answers a different reader: someone
/// running the SQL, who needs to know what to do about the gap in their tuple set
/// rather than what the model says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SkippedTuples {
    /// A hybrid policy's attribute half, which no tuple can express.
    AttributeRuntimeEnforcement { table: String, attribute: String },
    /// An attribute condition the row does not decide.
    StandaloneAttribute { table: String, column: String },
    /// An expression nobody classified.
    UnclassifiedExpression { table: String, reason: String },
    /// Nothing identifies a row of the table.
    NoObjectIdentifier {
        table: String,
        what: String,
        reason: String,
    },
    /// Nothing identifies a row, so the parent bridge cannot be built.
    NoBridge {
        table: String,
        parent_type: String,
        reason: String,
    },
    /// Neither a user nor a team table holds the principals a grant table names.
    NoPrincipalTypeForGrants { grant_table: String },
    /// The column joining a row to its parent is not in the schema.
    BridgeColumnMissing {
        table: String,
        parent_type: String,
        fk_col: String,
    },
    /// Policies disagree about which column joins the grant table.
    ExplicitGrantsConflictingColumns { table: String },
    /// No column joins the grant table.
    ExplicitGrantsNoResourceColumn { table: String },
    /// No table holds the user principals a role-threshold grant joins to.
    NoUserPrincipalTable { table: String },
    /// No table holds the team principals a role-threshold grant joins to.
    NoTeamPrincipalTable { table: String },
    /// No column carries the owner a role-threshold grant reads.
    NoOwnerColumn { table: String },
}

/// Advice printed where the tuple query would have been.
pub(crate) const MISSING_OBJECT_IDENTIFIER_SQL: &str =
    "-- Tuple query not emitted; table needs a single-column primary key or a NOT NULL UNIQUE `id` column for stable object IDs.";

impl SkippedTuples {
    /// The comment line naming what was skipped.
    pub(crate) fn comment(&self) -> String {
        match self {
            Self::AttributeRuntimeEnforcement { table, attribute } => format!(
                "-- TODO [Level C]: attribute condition '{attribute}' on {table} requires runtime enforcement"
            ),
            Self::StandaloneAttribute { table, .. } => format!(
                "-- TODO [Level D]: skipped tuple generation for {table} (unsupported pattern P9)"
            ),
            Self::UnclassifiedExpression { table, .. } => format!(
                "-- TODO [Level D]: skipped tuple generation for {table} (unsupported pattern Unknown)"
            ),
            Self::NoObjectIdentifier {
                table,
                what,
                reason,
            } => format!("-- TODO [Level D]: skipped {what} for {table} ({reason})"),
            Self::NoBridge {
                table,
                parent_type,
                reason,
            } => format!("-- TODO [Level D]: skipped {table} to {parent_type} bridge ({reason})"),
            Self::NoPrincipalTypeForGrants { grant_table } => format!(
                "-- TODO [Level C]: ExplicitGrants on '{grant_table}' could not resolve \
                 principal type (no user or team table identified). \
                 Review the grant table schema and register the principal tables."
            ),
            Self::BridgeColumnMissing {
                table,
                parent_type,
                fk_col,
            } => format!(
                "-- TODO [Level D]: skipped {table} to {parent_type} bridge \
                 (missing column '{fk_col}')"
            ),
            Self::ExplicitGrantsConflictingColumns { table } => format!(
                "-- TODO [Level D]: skipped explicit grants for {table} (conflicting resource join columns inferred from policies)"
            ),
            Self::ExplicitGrantsNoResourceColumn { table } => format!(
                "-- TODO [Level D]: skipped explicit grants for {table} (missing resource join column)"
            ),
            Self::NoUserPrincipalTable { table } => format!(
                "-- TODO [Level D]: skipped user ownership tuples for {table} (unresolved user principal table)"
            ),
            Self::NoTeamPrincipalTable { table } => format!(
                "-- TODO [Level D]: skipped team ownership tuples for {table} (unresolved team principal table)"
            ),
            Self::NoOwnerColumn { table } => format!(
                "-- TODO [Level D]: skipped ownership tuples for {table} (no owner-like column/FK found)"
            ),
        }
    }

    /// The body line saying what to do about it.
    pub(crate) fn body(&self) -> String {
        match self {
            Self::AttributeRuntimeEnforcement { attribute, .. } => format!(
                "-- No tuple can express the attribute filter '{attribute}', so application logic must enforce it."
            ),
            Self::StandaloneAttribute { column, .. } => format!(
                "-- Tuple query not emitted; attribute condition on '{column}' is not decided by the row, so no static tuple mapping."
            ),
            Self::UnclassifiedExpression { reason, .. } => format!(
                "-- Tuple query not emitted; classifier could not translate expression: {reason}."
            ),
            Self::NoObjectIdentifier { .. } => MISSING_OBJECT_IDENTIFIER_SQL.to_string(),
            Self::NoBridge { .. } | Self::BridgeColumnMissing { .. } => {
                "-- Bridge tuple not emitted; review schema/FK mapping.".to_string()
            }
            Self::NoPrincipalTypeForGrants { grant_table } => {
                format!("-- Unresolved: SELECT ... FROM {grant_table} og ...;")
            }
            Self::ExplicitGrantsConflictingColumns { .. } => {
                "-- Grant tuples not emitted; align resource arguments for role-threshold calls across policies.".to_string()
            }
            Self::ExplicitGrantsNoResourceColumn { .. } => {
                "-- Grant tuples not emitted; add function metadata or owner FK.".to_string()
            }
            Self::NoUserPrincipalTable { .. } => {
                "-- User ownership tuples not emitted; add role_threshold.user_table metadata or users table.".to_string()
            }
            Self::NoTeamPrincipalTable { .. } => {
                "-- Team ownership tuples not emitted; add role_threshold.team_table metadata or teams table.".to_string()
            }
            Self::NoOwnerColumn { .. } => {
                "-- Ownership tuples not emitted; review owner mapping.".to_string()
            }
        }
    }
}

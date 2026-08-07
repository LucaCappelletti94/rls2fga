#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use core::fmt;
use serde::{Deserialize, Serialize};
use sqlparser::ast::{CreatePolicyCommand, CreatePolicyType, Expr};

use crate::generator::well_known::MEMBER_RELATION;
use crate::parser::sql_parser::PolicyLike;

/// The command a policy applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PolicyCommand {
    /// Policy applies to SELECT queries only.
    Select,
    /// Policy applies to INSERT queries only.
    Insert,
    /// Policy applies to UPDATE queries only.
    Update,
    /// Policy applies to DELETE queries only.
    Delete,
    /// Policy applies to all DML commands.
    All,
}

/// Policy combination mode in `PostgreSQL` RLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PolicyMode {
    /// OR-combined policy branch.
    Permissive,
    /// AND-combined policy branch.
    Restrictive,
}

impl fmt::Display for PolicyMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyMode::Permissive => write!(f, "PERMISSIVE"),
            PolicyMode::Restrictive => write!(f, "RESTRICTIVE"),
        }
    }
}

impl From<CreatePolicyType> for PolicyMode {
    fn from(value: CreatePolicyType) -> Self {
        match value {
            CreatePolicyType::Permissive => PolicyMode::Permissive,
            CreatePolicyType::Restrictive => PolicyMode::Restrictive,
        }
    }
}

/// Comparison operator for numeric threshold checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThresholdOperator {
    /// `>= N`
    Gte,
    /// `> N`
    Gt,
}

/// Which kind of membership in a role a policy asked about.
///
/// `pg_has_role` answers a different question per kind, verified against `PostgreSQL` 18.1
/// over six ways of granting one role: a member granted `NOINHERIT` holds `Member` and `SetRole`
/// but not `Usage`, a member granted `WITH SET FALSE` holds `Member` and `Usage` but not
/// `SetRole`, and only a member granted `WITH ADMIN OPTION` holds `AdminOption`. The kind
/// written before `WITH ADMIN OPTION` makes no difference to the answer, so all three of those
/// spellings are one variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RolePrivilege {
    /// A member of the role, directly or through a chain of grants.
    Member,
    /// A member whose privileges apply without `SET ROLE`, so every grant in the chain
    /// inherits.
    Usage,
    /// A member who may `SET ROLE` to it.
    SetRole,
    /// A holder of the role's admin option.
    AdminOption,
}

impl RolePrivilege {
    /// Relation on the `pg_role` type holding the facts this kind needs.
    ///
    /// One relation per kind, since the sets differ: sharing one would make the operator's
    /// facts mean whichever policy the reader happened to look at.
    #[must_use]
    pub fn relation_name(self) -> &'static str {
        match self {
            Self::Member => MEMBER_RELATION,
            Self::Usage => "usage",
            Self::SetRole => "set_role",
            Self::AdminOption => "admin_option",
        }
    }

    /// Parse the privilege argument of `pg_has_role`, or `None` when it names no kind the
    /// crate can act on. `PostgreSQL` compares case insensitively and ignores surrounding
    /// space, and answers false for a string it does not know, so refusing one falls closed
    /// the same way.
    #[must_use]
    pub fn parse(argument: &str) -> Option<Self> {
        let normalized = argument.trim().to_ascii_uppercase();
        let kind = normalized
            .strip_suffix("WITH ADMIN OPTION")
            .map(str::trim_end);
        if let Some(kind) = kind {
            return matches!(kind, "MEMBER" | "USAGE" | "SET").then_some(Self::AdminOption);
        }
        match normalized.as_str() {
            "MEMBER" => Some(Self::Member),
            "USAGE" => Some(Self::Usage),
            "SET" => Some(Self::SetRole),
            _ => None,
        }
    }
}

impl fmt::Display for PolicyCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyCommand::Select => write!(f, "SELECT"),
            PolicyCommand::Insert => write!(f, "INSERT"),
            PolicyCommand::Update => write!(f, "UPDATE"),
            PolicyCommand::Delete => write!(f, "DELETE"),
            PolicyCommand::All => write!(f, "ALL"),
        }
    }
}

/// Boolean operator for composite patterns.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BoolOp {
    /// Logical conjunction: all sub-conditions must hold.
    And,
    /// Logical disjunction: at least one sub-condition must hold.
    Or,
}

/// Comparison an attribute guard applies.
///
/// `#[non_exhaustive]`: a recognizer widening to another operator adds a variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AttributeOperator {
    /// `=`
    Eq,
    /// `<>`
    NotEq,
    /// `>`
    Gt,
    /// `>=`
    GtEq,
    /// `<`
    Lt,
    /// `<=`
    LtEq,
}

/// A literal constant an attribute guard compares against.
///
/// A number keeps its source spelling, so the generated SQL reproduces the literal
/// the policy wrote rather than a reformatted one.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AttributeLiteral {
    /// A string literal.
    Text(String),
    /// A numeric literal, unparsed.
    Number(String),
    /// `TRUE` or `FALSE`.
    Boolean(bool),
}

/// A column compared against a literal constant, which the row alone decides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributePredicate {
    /// Column the guard reads, folded to its stored name.
    pub column: String,
    /// Comparison applied, oriented with the column on the left.
    pub operator: AttributeOperator,
    /// The literal the column is compared against.
    pub value: AttributeLiteral,
}

/// A column compared against a value only the request knows, which no static tuple
/// can decide. The row supplies the column, the caller supplies the rest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeRequestPredicate {
    /// Column the guard reads, folded to its stored name.
    pub column: String,
    /// Comparison applied, oriented with the column on the left.
    pub operator: AttributeOperator,
    /// What the request supplies.
    pub request_value: RequestValue,
}

/// A value the request supplies rather than the row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RequestValue {
    /// The moment the statement runs, from `now()` and its spellings.
    StatementTimestamp,
}

/// Classified pattern for an expression.
///
/// `#[non_exhaustive]`: a new recognizer adds a variant, so matching this outside the
/// crate needs a wildcard arm. Two variants were added in one session already.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum PatternClass {
    /// P1: Numeric role threshold: `role_level(user, resource) >= N`.
    P1NumericThreshold {
        /// Role-level function called.
        function_name: String,
        /// Comparison used.
        operator: ThresholdOperator,
        /// Level the policy requires.
        threshold: i32,
        /// Command the threshold applies to.
        command: PolicyCommand,
    },
    /// P2: Role name IN-list: `role_name(user, resource) IN ('viewer', ...)`.
    P2RoleNameInList {
        /// Role-name function called.
        function_name: String,
        /// Roles the list admits.
        role_names: Vec<String>,
        /// Which kind of membership in those roles the policy asked about.
        privilege: RolePrivilege,
    },
    /// P3: Direct column equality: `owner_id = current_user_id()`.
    P3DirectOwnership {
        /// Column compared against the current user.
        column: String,
    },
    /// P4: EXISTS subquery membership: `EXISTS (SELECT 1 FROM members ...)`.
    P4ExistsMembership {
        /// Table scanned in the subquery.
        join_table: String,
        /// Column of `join_table` identifying the parent entity.
        fk_column: String,
        /// Column of `join_table` identifying the user.
        user_column: String,
        /// Residual filter such as `role = 'admin'`, which no tuple can express.
        extra_predicate_sql: Option<String>,
    },
    /// P5: Parent permission inheritance through a foreign key.
    P5ParentInheritance {
        /// Parent table read by the policy.
        parent_table: String,
        /// Column of the child table linking to `parent_table`.
        fk_column: String,
        /// The parent-side rule the policy requires.
        inner_pattern: Box<ClassifiedExpr>,
    },
    /// P6: Boolean flag or public access: `is_public = TRUE`.
    P6BooleanFlag {
        /// Column controlling visibility.
        column: String,
    },
    /// P7: A relationship check AND an attribute guard.
    P7AbacAnd {
        /// The translatable relationship half.
        relationship_part: Box<ClassifiedExpr>,
        /// Column the attribute guard reads.
        attribute_part: String,
    },
    /// P8: `OR` or `AND` of two or more sub-patterns.
    P8Composite {
        /// Operator joining `parts`.
        op: BoolOp,
        /// Sub-patterns being combined.
        parts: Vec<ClassifiedExpr>,
    },
    /// P9: Standalone attribute condition: `status = 'published'`.
    P9AttributeCondition {
        /// Column the guard reads.
        column: String,
        /// Human-readable form of the compared value.
        value_description: String,
        /// The guard as structure, when the compared value is a literal constant and
        /// so is decided by the row alone.
        predicate: Option<AttributePredicate>,
        /// The guard as structure, when the compared value is one only the request
        /// knows. Such a guard becomes a condition rather than a tuple, since a tuple
        /// computed once would outlive the value it was computed against.
        request_predicate: Option<AttributeRequestPredicate>,
    },
    /// P10: Constant `TRUE` or `FALSE` policy.
    P10ConstantBool {
        /// The constant.
        value: bool,
    },
    /// P11: The caller is an element of an array column: `current_user = ANY (editors)`.
    ///
    /// Exact, not a widening: `UNNEST` enumerates precisely the rows `= ANY` admits.
    P11ArrayMembership {
        /// Array column holding the admitted principals.
        column: String,
    },
    /// P12: The caller is named by a jsonb field: `data ->> 'owner' = current_user`.
    ///
    /// Exact: `->>` yields NULL for a missing key, a null value and a null column, and
    /// the comparison then filters, which is what dropping the NULLs reproduces.
    P12JsonbFieldOwnership {
        /// Column holding the document.
        column: String,
        /// Key chain to the field, the last hop extracted as text.
        path: Vec<String>,
    },
    /// A membership check naming no column of the guarded table, so it admits every
    /// row at once to whoever appears in the member table.
    P13UncorrelatedMembership {
        /// Table whose rows list the members.
        member_table: String,
        /// Column of that table holding the member.
        user_column: String,
        /// Any further condition the membership row has to satisfy.
        extra_predicate_sql: Option<String>,
    },
    /// No known pattern matched.
    Unknown {
        /// The expression as written.
        sql_text: String,
        /// Why classification failed, surfaced to the operator.
        reason: String,
    },
}

/// Confidence level for a classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ConfidenceLevel {
    /// Lowest confidence: unrecognised or unsupported expression.
    D,
    /// Low confidence: partially recognised (e.g. ABAC crossover).
    C,
    /// Medium confidence: composite patterns where sub-parts are well-understood.
    B,
    /// Highest confidence: fully recognised, single-pattern expression.
    A,
}

impl fmt::Display for ConfidenceLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfidenceLevel::A => write!(f, "A"),
            ConfidenceLevel::B => write!(f, "B"),
            ConfidenceLevel::C => write!(f, "C"),
            ConfidenceLevel::D => write!(f, "D"),
        }
    }
}

impl core::str::FromStr for ConfidenceLevel {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "A" => Ok(ConfidenceLevel::A),
            "B" => Ok(ConfidenceLevel::B),
            "C" => Ok(ConfidenceLevel::C),
            "D" => Ok(ConfidenceLevel::D),
            _ => Err(format!("Invalid confidence level: {s}")),
        }
    }
}

/// A classified expression with its pattern and confidence.
#[derive(Debug, Clone, PartialEq)]
pub struct ClassifiedExpr {
    /// The matched pattern (P1 to P10 or Unknown).
    pub pattern: PatternClass,
    /// How confident the classifier is in this match.
    pub confidence: ConfidenceLevel,
}

/// Grade a pattern built out of `parts`.
///
/// The lowest part decides, capped at `B`: combining separately recognized halves is
/// never as certain as recognizing one shape whole. Both `AND` and `OR` used this rule
/// already, spelled differently, and an oracle substituting a part has to regrade the
/// same way or the composite keeps the grade its refused part dragged it to.
#[must_use]
pub fn composite_confidence<'a, I>(parts: I) -> ConfidenceLevel
where
    I: IntoIterator<Item = &'a ClassifiedExpr>,
{
    parts
        .into_iter()
        .map(|part| part.confidence)
        .min()
        .map_or(ConfidenceLevel::D, |lowest| {
            core::cmp::min(lowest, ConfidenceLevel::B)
        })
}

impl From<CreatePolicyCommand> for PolicyCommand {
    fn from(cmd: CreatePolicyCommand) -> Self {
        match cmd {
            CreatePolicyCommand::All => PolicyCommand::All,
            CreatePolicyCommand::Select => PolicyCommand::Select,
            CreatePolicyCommand::Insert => PolicyCommand::Insert,
            CreatePolicyCommand::Update => PolicyCommand::Update,
            CreatePolicyCommand::Delete => PolicyCommand::Delete,
        }
    }
}

/// Policy mode as declared, `PERMISSIVE` when the policy omits it.
pub fn derive_policy_mode<P: PolicyLike>(policy: &P) -> PolicyMode {
    PolicyMode::from(policy.policy_type())
}

/// Whether a policy can grant reads: permissive, covering `SELECT`, and storing
/// the `USING` clause a read is filtered by.
pub fn policy_grants_select<P: PolicyLike>(policy: &P, db: &P::DB) -> bool {
    derive_policy_mode(policy) == PolicyMode::Permissive
        && policy.using_expression(db).is_some()
        && matches!(
            PolicyCommand::from(policy.command()),
            PolicyCommand::Select | PolicyCommand::All
        )
}

/// Roles in `TO (...)` that constrain policy applicability.
///
/// Empty when the policy applies to every role, which `PostgreSQL` spells both as
/// `TO PUBLIC` and as no `TO` clause at all.
pub fn derive_scoped_roles<P: PolicyLike>(policy: &P, db: &P::DB) -> Vec<String> {
    if policy.applies_to_public() {
        return Vec::new();
    }

    let mut roles: Vec<String> = policy
        .roles(db)
        .map(ToString::to_string)
        .map(|role| role.trim().to_string())
        .filter(|role| !role.is_empty())
        .collect();

    roles.sort();
    roles.dedup();
    roles
}

/// A classified policy with classifications for USING and WITH CHECK.
///
/// Holds what rls2fga reads of a policy rather than the catalog's own policy value,
/// so the pipeline runs against any [`DatabaseLike`](crate::parser::sql_parser::DatabaseLike)
/// rather than one instantiation of it.
#[derive(Debug, Clone)]
pub struct ClassifiedPolicy {
    /// Policy name as declared in the DDL.
    pub name: String,
    /// Target table as the policy spelled it, quoting and schema qualifier kept.
    pub table: String,
    /// DML command this policy restricts (`ALL` when unspecified).
    pub command: PolicyCommand,
    /// Policy mode (`PERMISSIVE` when omitted).
    pub mode: PolicyMode,
    /// Roles in `TO (...)`, empty when the policy applies to every role.
    pub scoped_roles: Vec<String>,
    /// The `USING` expression the policy stores, if any.
    pub using: Option<Expr>,
    /// The `WITH CHECK` expression the policy stores, if any.
    pub with_check: Option<Expr>,
    /// Classification of the USING expression, if present.
    pub using_classification: Option<ClassifiedExpr>,
    /// Classification of the WITH CHECK expression, if present.
    pub with_check_classification: Option<ClassifiedExpr>,
    /// Set to `true` when `using_classification` was present but dropped by
    /// `filter_policies_for_output` due to insufficient confidence.
    /// Distinguishes "expression never existed" from "expression was filtered".
    pub using_was_filtered: bool,
    /// Set to `true` when `with_check_classification` was present but dropped
    /// by `filter_policies_for_output` due to insufficient confidence.
    /// When `true`, the USING→WITH CHECK mirror fallback must not be applied.
    pub with_check_was_filtered: bool,
}

impl ClassifiedPolicy {
    /// Read a policy out of a catalog, before anything classifies its clauses.
    ///
    /// The single place a catalog's own policy becomes one of these, so nothing
    /// downstream has to know what the catalog stores.
    pub fn from_policy<P: PolicyLike>(policy: &P, db: &P::DB) -> Self {
        Self {
            name: policy.name().to_string(),
            table: policy.target_table_name().to_string(),
            command: PolicyCommand::from(policy.command()),
            mode: derive_policy_mode(policy),
            scoped_roles: derive_scoped_roles(policy, db),
            using: policy.using_expression(db).cloned(),
            with_check: policy.check_expression(db).cloned(),
            using_classification: None,
            with_check_classification: None,
            using_was_filtered: false,
            with_check_was_filtered: false,
        }
    }

    /// Policy name as declared in the DDL.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Table name targeted by this policy, in the spelling the policy wrote.
    pub fn table_name(&self) -> &str {
        &self.table
    }

    /// DML command this policy restricts (ALL if unspecified).
    pub fn command(&self) -> PolicyCommand {
        self.command
    }

    /// Policy mode (`PERMISSIVE` by default when omitted).
    pub fn mode(&self) -> PolicyMode {
        self.mode
    }

    /// Iterate over all classified policy expressions (`USING` and `WITH CHECK`).
    pub fn classifications(&self) -> impl Iterator<Item = &ClassifiedExpr> {
        [
            self.using_classification.as_ref(),
            self.with_check_classification.as_ref(),
        ]
        .into_iter()
        .flatten()
    }

    /// Roles in `TO (...)` that constrain policy applicability.
    pub fn scoped_roles(&self) -> &[String] {
        &self.scoped_roles
    }
}

/// Keep only policy classifications at or above the requested confidence level.
///
/// A RESTRICTIVE policy is kept even when all its classifications drop: RLS is
/// `(permissive OR ...) AND restrictive AND ...`, so removing one grants access
/// it forbids. The `*_was_filtered` flags tell the generator to fall closed. A policy
/// whose reads loop needs no such retention, since the generator reads that loop off the
/// schema rather than off the classifications.
pub fn filter_policies_for_output(
    policies: &[ClassifiedPolicy],
    min_confidence: ConfidenceLevel,
) -> Vec<ClassifiedPolicy> {
    policies
        .iter()
        .filter_map(|cp| {
            let mut filtered = cp.clone();
            let using_kept = cp
                .using_classification
                .as_ref()
                .filter(|c| c.confidence >= min_confidence)
                .cloned();
            filtered.using_was_filtered = cp.using_classification.is_some() && using_kept.is_none();
            filtered.using_classification = using_kept;

            let with_check_kept = cp
                .with_check_classification
                .as_ref()
                .filter(|c| c.confidence >= min_confidence)
                .cloned();
            filtered.with_check_was_filtered =
                cp.with_check_classification.is_some() && with_check_kept.is_none();
            filtered.with_check_classification = with_check_kept;

            if filtered.using_classification.is_some()
                || filtered.with_check_classification.is_some()
                || filtered.mode() == PolicyMode::Restrictive
            {
                Some(filtered)
            } else {
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::sql_parser::{parse_schema, DatabaseLike};
    use core::str::FromStr;
    use sqlparser::ast::{CreatePolicyCommand, CreatePolicyType};

    fn first_classified(sql: &str) -> ClassifiedPolicy {
        let db = parse_schema(sql).expect("schema should parse");
        let policy = db.policies().next().expect("expected one policy");
        ClassifiedPolicy::from_policy(policy, &db)
    }

    #[test]
    fn policy_mode_and_command_format_and_conversion() {
        assert_eq!(
            PolicyMode::from(CreatePolicyType::Permissive),
            PolicyMode::Permissive
        );
        assert_eq!(
            PolicyMode::from(CreatePolicyType::Restrictive),
            PolicyMode::Restrictive
        );
        assert_eq!(format!("{}", PolicyMode::Permissive), "PERMISSIVE");
        assert_eq!(format!("{}", PolicyMode::Restrictive), "RESTRICTIVE");

        assert_eq!(
            PolicyCommand::from(CreatePolicyCommand::All),
            PolicyCommand::All
        );
        assert_eq!(
            PolicyCommand::from(CreatePolicyCommand::Select),
            PolicyCommand::Select
        );
        assert_eq!(
            PolicyCommand::from(CreatePolicyCommand::Insert),
            PolicyCommand::Insert
        );
        assert_eq!(
            PolicyCommand::from(CreatePolicyCommand::Update),
            PolicyCommand::Update
        );
        assert_eq!(
            PolicyCommand::from(CreatePolicyCommand::Delete),
            PolicyCommand::Delete
        );

        assert_eq!(format!("{}", PolicyCommand::Select), "SELECT");
        assert_eq!(format!("{}", PolicyCommand::Insert), "INSERT");
        assert_eq!(format!("{}", PolicyCommand::Update), "UPDATE");
        assert_eq!(format!("{}", PolicyCommand::Delete), "DELETE");
        assert_eq!(format!("{}", PolicyCommand::All), "ALL");
    }

    #[test]
    fn classified_policy_defaults_and_explicit_values() {
        let cp_default = first_classified(
            r"
CREATE TABLE docs(id uuid primary key);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_default ON docs USING (TRUE);
",
        );
        assert_eq!(cp_default.name(), "p_default");
        assert_eq!(cp_default.table_name(), "docs");
        assert_eq!(cp_default.command(), PolicyCommand::All);
        assert_eq!(cp_default.mode(), PolicyMode::Permissive);

        let cp_explicit = first_classified(
            r"
CREATE TABLE docs(id uuid primary key);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_explicit ON docs AS RESTRICTIVE FOR DELETE USING (FALSE);
",
        );
        assert_eq!(cp_explicit.name(), "p_explicit");
        assert_eq!(cp_explicit.table_name(), "docs");
        assert_eq!(cp_explicit.command(), PolicyCommand::Delete);
        assert_eq!(cp_explicit.mode(), PolicyMode::Restrictive);
    }

    #[test]
    fn confidence_level_parsing_is_case_insensitive() {
        assert_eq!(ConfidenceLevel::from_str("a"), Ok(ConfidenceLevel::A));
        assert_eq!(ConfidenceLevel::from_str("B"), Ok(ConfidenceLevel::B));
        assert_eq!(ConfidenceLevel::from_str("c"), Ok(ConfidenceLevel::C));
        assert_eq!(ConfidenceLevel::from_str("D"), Ok(ConfidenceLevel::D));
        assert_eq!(format!("{}", ConfidenceLevel::A), "A");
        assert_eq!(format!("{}", ConfidenceLevel::B), "B");
        assert_eq!(format!("{}", ConfidenceLevel::C), "C");
        assert_eq!(format!("{}", ConfidenceLevel::D), "D");

        let err = ConfidenceLevel::from_str("z").expect_err("invalid level should fail");
        assert!(err.contains("Invalid confidence level: z"));
    }

    #[test]
    fn classified_policy_scoped_roles_excludes_public_and_dedupes() {
        let scoped = first_classified(
            r"
CREATE TABLE docs(id uuid primary key);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_scoped ON docs FOR SELECT TO app_user, app_user, auditors USING (TRUE);
",
        );
        assert_eq!(
            scoped.scoped_roles(),
            ["app_user".to_string(), "auditors".to_string()]
        );

        let public = first_classified(
            r"
CREATE TABLE docs(id uuid primary key);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_public ON docs FOR SELECT TO PUBLIC, app_user USING (TRUE);
",
        );
        assert!(public.scoped_roles().is_empty());
    }

    /// `PostgreSQL` compares the privilege case insensitively and ignores surrounding space,
    /// and it answers false for a string it does not know rather than raising. Verified on
    /// 18.1, including that `'MEMBER WITH GRANT OPTION'` simply returns false.
    #[test]
    fn role_privilege_parses_every_spelling_postgres_accepts() {
        use RolePrivilege::{AdminOption, Member, SetRole, Usage};

        for (spelling, expected) in [
            ("MEMBER", Member),
            ("USAGE", Usage),
            ("SET", SetRole),
            ("member", Member),
            ("  usage  ", Usage),
            // The kind before the admin option makes no difference to the answer, so all
            // three spellings are one relation.
            ("MEMBER WITH ADMIN OPTION", AdminOption),
            ("USAGE WITH ADMIN OPTION", AdminOption),
            ("SET WITH ADMIN OPTION", AdminOption),
            ("member with admin option", AdminOption),
            ("MEMBER  WITH ADMIN OPTION", AdminOption),
        ] {
            assert_eq!(
                RolePrivilege::parse(spelling),
                Some(expected),
                "`{spelling}` names {expected:?} to PostgreSQL"
            );
        }

        for unknown in [
            "MEMBER WITH GRANT OPTION",
            "WITH ADMIN OPTION",
            "ADMIN",
            "nonsense",
            "",
            "MEMBERSHIP",
        ] {
            assert_eq!(
                RolePrivilege::parse(unknown),
                None,
                "`{unknown}` names no kind the crate can act on"
            );
        }

        // One relation per kind, since the sets differ.
        let names = [Member, Usage, SetRole, AdminOption].map(RolePrivilege::relation_name);
        assert_eq!(
            names
                .iter()
                .collect::<alloc::collections::BTreeSet<_>>()
                .len(),
            names.len(),
            "two kinds sharing a relation would make the operator's facts mean both"
        );
    }
}

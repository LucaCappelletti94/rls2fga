#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use core::fmt;
use serde::{Deserialize, Serialize};
use sqlparser::ast::{CreatePolicyCommand, CreatePolicyType};

use crate::parser::names::{normalize_identifier, normalize_relation_name};

/// The command a policy applies to.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

/// Classified pattern for an expression.
#[derive(Debug, Clone, PartialEq)]
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
    },
    /// P10: Constant `TRUE` or `FALSE` policy.
    P10ConstantBool {
        /// The constant.
        value: bool,
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

/// Derive a policy command from an optional parsed command (`ALL` when absent).
pub fn derive_policy_command(command: Option<&CreatePolicyCommand>) -> PolicyCommand {
    command.map_or(PolicyCommand::All, |cmd| PolicyCommand::from(*cmd))
}

/// Derive a policy mode from a parsed policy (`PERMISSIVE` when absent).
pub fn derive_policy_mode(policy: &sqlparser::ast::CreatePolicy) -> PolicyMode {
    policy
        .policy_type
        .as_ref()
        .map_or(PolicyMode::Permissive, |p| PolicyMode::from(*p))
}

/// Whether a policy can grant reads, which needs it to be permissive and to cover
/// `SELECT`. Only restrictive policies means no row is readable at all.
pub fn policy_grants_select(policy: &sqlparser::ast::CreatePolicy) -> bool {
    derive_policy_mode(policy) == PolicyMode::Permissive
        && matches!(
            derive_policy_command(policy.command.as_ref()),
            PolicyCommand::Select | PolicyCommand::All
        )
}

/// A classified policy with classifications for USING and WITH CHECK.
#[derive(Debug, Clone)]
pub struct ClassifiedPolicy {
    /// The original parsed `CREATE POLICY` statement.
    pub policy: sqlparser::ast::CreatePolicy,
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
    /// Policy name as declared in the DDL.
    pub fn name(&self) -> &str {
        &self.policy.name.value
    }

    /// Fully-qualified table name targeted by this policy.
    pub fn table_name(&self) -> String {
        self.policy.table_name.to_string()
    }

    /// DML command this policy restricts (ALL if unspecified).
    pub fn command(&self) -> PolicyCommand {
        derive_policy_command(self.policy.command.as_ref())
    }

    /// Policy mode (`PERMISSIVE` by default when omitted).
    pub fn mode(&self) -> PolicyMode {
        derive_policy_mode(&self.policy)
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
    ///
    /// Returns an empty vector when no explicit role scope is present or when
    /// scope includes `PUBLIC`.
    pub fn scoped_roles(&self) -> Vec<String> {
        let Some(to) = self.policy.to.as_ref() else {
            return Vec::new();
        };

        let mut roles: Vec<String> = to
            .iter()
            .map(ToString::to_string)
            .map(|role| role.trim().to_string())
            .filter(|role| !role.is_empty())
            .collect();
        if roles.is_empty() {
            return Vec::new();
        }

        if roles
            .iter()
            .any(|role| normalize_identifier(role) == "public")
        {
            return Vec::new();
        }

        roles.sort();
        roles.dedup();
        roles
    }
}

/// Keep only policy classifications at or above the requested confidence level.
///
/// A RESTRICTIVE policy is kept even when all its classifications drop: RLS is
/// `(permissive OR ...) AND restrictive AND ...`, so removing one grants access
/// it forbids. A `SELECT` policy reading its own table is kept for the same
/// reason, since it makes `PostgreSQL` refuse every read rather than grant one.
/// The `*_was_filtered` flags tell the generator to fall closed.
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
                || reads_its_own_table_on_select(cp)
            {
                Some(filtered)
            } else {
                None
            }
        })
        .collect()
}

/// Whether a policy guarding reads also reads the table it guards, judged on the
/// normalized relation names alone. Retaining one policy too many costs nothing here,
/// since the generator resolves the types properly before acting.
fn reads_its_own_table_on_select(cp: &ClassifiedPolicy) -> bool {
    if !matches!(cp.command(), PolicyCommand::Select | PolicyCommand::All) {
        return false;
    }
    let Some(using) = cp.policy.using.as_ref() else {
        return false;
    };
    let guarded = normalize_relation_name(&cp.table_name());
    crate::parser::expr::reads_relation(using, |name| normalize_relation_name(name) == guarded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::sql_parser::{parse_schema, DatabaseLike};
    use core::str::FromStr;
    use sqlparser::ast::{CreatePolicyCommand, CreatePolicyType};

    fn first_policy(sql: &str) -> sqlparser::ast::CreatePolicy {
        let db = parse_schema(sql).expect("schema should parse");
        let policy = db.policies().next().expect("expected one policy").clone();
        policy
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
    fn derive_policy_command_defaults_and_maps_explicit_values() {
        assert_eq!(derive_policy_command(None), PolicyCommand::All);
        assert_eq!(
            derive_policy_command(Some(&CreatePolicyCommand::Select)),
            PolicyCommand::Select
        );
        assert_eq!(
            derive_policy_command(Some(&CreatePolicyCommand::Update)),
            PolicyCommand::Update
        );
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
    fn classified_policy_defaults_and_explicit_values() {
        let sql_default = r"
CREATE TABLE docs(id uuid primary key);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_default ON docs USING (TRUE);
";
        let sql_explicit = r"
CREATE TABLE docs(id uuid primary key);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_explicit ON docs AS RESTRICTIVE FOR DELETE USING (FALSE);
";

        let cp_default = ClassifiedPolicy {
            policy: first_policy(sql_default),
            using_classification: None,
            with_check_classification: None,
            using_was_filtered: false,
            with_check_was_filtered: false,
        };
        assert_eq!(cp_default.name(), "p_default");
        assert_eq!(cp_default.table_name(), "docs");
        assert_eq!(cp_default.command(), PolicyCommand::All);
        assert_eq!(cp_default.mode(), PolicyMode::Permissive);

        let cp_explicit = ClassifiedPolicy {
            policy: first_policy(sql_explicit),
            using_classification: None,
            with_check_classification: None,
            using_was_filtered: false,
            with_check_was_filtered: false,
        };
        assert_eq!(cp_explicit.name(), "p_explicit");
        assert_eq!(cp_explicit.table_name(), "docs");
        assert_eq!(cp_explicit.command(), PolicyCommand::Delete);
        assert_eq!(cp_explicit.mode(), PolicyMode::Restrictive);
    }

    #[test]
    fn classified_policy_scoped_roles_excludes_public_and_dedupes() {
        let scoped_sql = r"
CREATE TABLE docs(id uuid primary key);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_scoped ON docs FOR SELECT TO app_user, app_user, auditors USING (TRUE);
";
        let scoped = ClassifiedPolicy {
            policy: first_policy(scoped_sql),
            using_classification: None,
            with_check_classification: None,
            using_was_filtered: false,
            with_check_was_filtered: false,
        };
        assert_eq!(
            scoped.scoped_roles(),
            vec!["app_user".to_string(), "auditors".to_string()]
        );

        let public_sql = r"
CREATE TABLE docs(id uuid primary key);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_public ON docs FOR SELECT TO PUBLIC, app_user USING (TRUE);
";
        let public = ClassifiedPolicy {
            policy: first_policy(public_sql),
            using_classification: None,
            with_check_classification: None,
            using_was_filtered: false,
            with_check_was_filtered: false,
        };
        assert!(public.scoped_roles().is_empty());
    }
}

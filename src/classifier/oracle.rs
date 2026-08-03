//! Consumer-supplied classification for expressions this crate refuses.
//!
//! The crate falls closed on an expression it cannot recognize, which denies what
//! `PostgreSQL` grants. A consumer who knows what their own expression means can say so
//! by implementing [`PolicyOracle`] and calling [`consult_oracle`] between
//! [`Translator::classify`](crate::translator::Translator::classify) and the generators.
//!
//! Doing that by hand is possible, since every field involved is public, and it is a
//! trap. A refusal nests inside [`PatternClass::P5ParentInheritance`],
//! [`PatternClass::P7AbacAnd`] and [`PatternClass::P8Composite`], so a walk that knows
//! only the obvious one leaves the refusal in place and the model silently denies. An
//! enclosing pattern also keeps the grade its refused part dragged it to, so
//! `filter_policies_for_output` drops the whole clause even after the leaf is answered.
//! This module owns both problems.
//!
//! ```
//! use rls2fga::classifier::oracle::{consult_oracle, PolicyOracle, RefusedExpr};
//! use rls2fga::classifier::patterns::{ClassifiedExpr, ConfidenceLevel, PatternClass};
//! use rls2fga::parser::sql_parser::parse_schema;
//! use rls2fga::translator::TranslatorBuilder;
//!
//! struct BitFlagIsPublic;
//!
//! impl PolicyOracle for BitFlagIsPublic {
//!     fn classify(&self, refused: &RefusedExpr<'_>) -> Option<ClassifiedExpr> {
//!         // `&` has no translation in this crate, but the deployment knows bit 4 marks
//!         // a row readable by anyone.
//!         refused.sql_text().contains("flags & 4").then_some(ClassifiedExpr {
//!             pattern: PatternClass::P10ConstantBool { value: true },
//!             confidence: ConfidenceLevel::A,
//!         })
//!     }
//! }
//!
//! let db = parse_schema(
//!     "CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT, flags INT);\n\
//!      ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
//!      CREATE POLICY docs_sel ON docs FOR SELECT\n\
//!        USING ((flags & 4) = 4 AND owner_id = current_user);\n",
//! )?;
//! let translator = TranslatorBuilder::new()
//!     .with_min_confidence(ConfidenceLevel::B)
//!     .build();
//!
//! let mut classified = translator.classify(&db);
//! let answered = consult_oracle(&mut classified, &BitFlagIsPublic);
//!
//! assert_eq!(answered.len(), 1);
//! assert_eq!(answered[0].sql_text(), "(flags & 4) = 4");
//! # Ok::<(), rls2fga::parser::sql_parser::SchemaError>(())
//! ```

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;

use crate::classifier::patterns::{
    composite_confidence, ClassifiedExpr, ClassifiedPolicy, ConfidenceLevel, PatternClass,
};

/// Which clause of a policy an expression came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PolicyClause {
    /// The `USING` clause, which filters the rows a command sees.
    Using,
    /// The `WITH CHECK` clause, which admits the rows a command writes.
    WithCheck,
}

impl PolicyClause {
    /// The clause as it is spelled in DDL.
    #[must_use]
    pub fn as_sql(self) -> &'static str {
        match self {
            Self::Using => "USING",
            Self::WithCheck => "WITH CHECK",
        }
    }
}

/// One expression the crate refused, offered to a [`PolicyOracle`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefusedExpr<'a> {
    policy_name: &'a str,
    clause: PolicyClause,
    sql_text: &'a str,
    reason: &'a str,
}

impl<'a> RefusedExpr<'a> {
    /// Name of the policy the expression belongs to.
    #[must_use]
    pub fn policy_name(&self) -> &'a str {
        self.policy_name
    }

    /// Clause the expression came from.
    #[must_use]
    pub fn clause(&self) -> PolicyClause {
        self.clause
    }

    /// The expression as written, which is what an oracle matches on.
    #[must_use]
    pub fn sql_text(&self) -> &'a str {
        self.sql_text
    }

    /// Why this crate refused it.
    #[must_use]
    pub fn reason(&self) -> &'a str {
        self.reason
    }
}

/// Supplies a classification for an expression this crate refused.
///
/// Return `None` to leave the refusal in place, which keeps the closed default.
pub trait PolicyOracle {
    /// Classify `refused`, or decline it.
    fn classify(&self, refused: &RefusedExpr<'_>) -> Option<ClassifiedExpr>;
}

/// What an oracle answered, so a report can attribute the classification to it.
#[derive(Debug, Clone, PartialEq)]
pub struct OracleSubstitution {
    policy_name: String,
    clause: PolicyClause,
    sql_text: String,
    reason: String,
    confidence: ConfidenceLevel,
}

impl OracleSubstitution {
    /// Name of the policy whose clause the oracle answered.
    #[must_use]
    pub fn policy_name(&self) -> &str {
        &self.policy_name
    }

    /// Clause the answered expression came from.
    #[must_use]
    pub fn clause(&self) -> PolicyClause {
        self.clause
    }

    /// The expression the oracle answered for.
    #[must_use]
    pub fn sql_text(&self) -> &str {
        &self.sql_text
    }

    /// Why this crate had refused it.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// Grade the oracle claimed.
    #[must_use]
    pub fn confidence(&self) -> ConfidenceLevel {
        self.confidence
    }
}

/// Offer every refused expression in `policies` to `oracle` and apply what it answers.
///
/// Refusals are found wherever they nest, and every enclosing pattern is regraded
/// through [`composite_confidence`] so a clause is not dropped for a refusal that no
/// longer exists. Returns one entry per substitution, in the order they were applied.
pub fn consult_oracle<O>(policies: &mut [ClassifiedPolicy], oracle: &O) -> Vec<OracleSubstitution>
where
    O: PolicyOracle + ?Sized,
{
    let mut answered = Vec::new();
    for policy in policies {
        let name = policy.name().to_string();
        for (clause, expr) in [
            (PolicyClause::Using, policy.using_classification.as_mut()),
            (
                PolicyClause::WithCheck,
                policy.with_check_classification.as_mut(),
            ),
        ] {
            if let Some(expr) = expr {
                consult_expr(expr, &name, clause, oracle, &mut answered);
            }
        }
    }
    answered
}

/// Apply `oracle` to `expr` and everything nested in it, regrading on the way out.
///
/// Returns `true` when anything below `expr` changed, which is what tells the caller to
/// regrade.
fn consult_expr<O>(
    expr: &mut ClassifiedExpr,
    policy_name: &str,
    clause: PolicyClause,
    oracle: &O,
    answered: &mut Vec<OracleSubstitution>,
) -> bool
where
    O: PolicyOracle + ?Sized,
{
    if let PatternClass::Unknown { sql_text, reason } = &expr.pattern {
        let refused = RefusedExpr {
            policy_name,
            clause,
            sql_text,
            reason,
        };
        let Some(supplied) = oracle.classify(&refused) else {
            return false;
        };
        answered.push(OracleSubstitution {
            policy_name: policy_name.to_string(),
            clause,
            sql_text: sql_text.clone(),
            reason: reason.clone(),
            confidence: supplied.confidence,
        });
        *expr = supplied;
        return true;
    }

    // Every variant holding a `ClassifiedExpr`. Matched exhaustively on purpose: a new
    // nesting variant must fail to compile here rather than hide a refusal from the
    // oracle.
    let changed = match &mut expr.pattern {
        PatternClass::P5ParentInheritance { inner_pattern, .. } => {
            consult_expr(inner_pattern, policy_name, clause, oracle, answered)
        }
        PatternClass::P7AbacAnd {
            relationship_part, ..
        } => consult_expr(relationship_part, policy_name, clause, oracle, answered),
        PatternClass::P8Composite { parts, .. } => {
            let mut any = false;
            for part in parts.iter_mut() {
                any |= consult_expr(part, policy_name, clause, oracle, answered);
            }
            any
        }
        PatternClass::P1NumericThreshold { .. }
        | PatternClass::P2RoleNameInList { .. }
        | PatternClass::P3DirectOwnership { .. }
        | PatternClass::P4ExistsMembership { .. }
        | PatternClass::P6BooleanFlag { .. }
        | PatternClass::P9AttributeCondition { .. }
        | PatternClass::P10ConstantBool { .. }
        | PatternClass::P11ArrayMembership { .. }
        | PatternClass::P12JsonbFieldOwnership { .. }
        | PatternClass::Unknown { .. } => false,
    };

    if changed {
        expr.confidence = regraded(&expr.pattern, expr.confidence);
    }
    changed
}

/// The grade an enclosing pattern earns once a part below it was answered.
fn regraded(pattern: &PatternClass, current: ConfidenceLevel) -> ConfidenceLevel {
    match pattern {
        PatternClass::P8Composite { parts, .. } => composite_confidence(parts.iter()),
        PatternClass::P5ParentInheritance { inner_pattern, .. } => {
            composite_confidence([inner_pattern.as_ref()])
        }
        PatternClass::P7AbacAnd {
            relationship_part, ..
        } => composite_confidence([relationship_part.as_ref()]),
        _ => current,
    }
}

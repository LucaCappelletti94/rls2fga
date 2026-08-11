#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use crate::parser::identifiers::ColumnName;
use crate::parser::names::table_has_column;
use sqlparser::ast::{BinaryOperator, Expr, UnaryOperator, Value};

use crate::classifier::function_registry::FunctionRegistry;
use crate::classifier::patterns::*;
use crate::classifier::recognizers;
use crate::parser::function_analyzer::{AccessorInferenceSettings, FunctionSemantic};
use crate::parser::sql_parser::DatabaseLike;

/// Classify all policies in the database.
pub fn classify_policies<DB: DatabaseLike>(
    db: &DB,
    registry: &FunctionRegistry,
) -> Vec<ClassifiedPolicy> {
    let settings = AccessorInferenceSettings::default();
    classify_policies_with_effective_registry_and_settings(db, registry, &settings).0
}

/// Classify all policies and return the enriched function registry used by the classifier.
pub fn classify_policies_with_effective_registry<DB: DatabaseLike>(
    db: &DB,
    registry: &FunctionRegistry,
) -> (Vec<ClassifiedPolicy>, FunctionRegistry) {
    let settings = AccessorInferenceSettings::default();
    classify_policies_with_effective_registry_and_settings(db, registry, &settings)
}

/// Classify all policies using explicit accessor-inference settings.
pub fn classify_policies_with_effective_registry_and_settings<DB: DatabaseLike>(
    db: &DB,
    registry: &FunctionRegistry,
    settings: &AccessorInferenceSettings,
) -> (Vec<ClassifiedPolicy>, FunctionRegistry) {
    let mut effective_registry = registry.clone();
    effective_registry.declare_session_attributes(settings.session_attributes().iter().cloned());
    // The two lists become one before anything reads either, so a declaration made on the
    // registry and one made through the settings cannot describe the same source apart.
    let declared: Vec<_> = effective_registry.session_attributes().cloned().collect();
    let effective_settings = AccessorInferenceSettings::from_attributes(declared);
    effective_registry.enrich_from_schema_with_settings(db, &effective_settings);

    let classified = classify_policies_with_registry(db, &effective_registry);
    (classified, effective_registry)
}

/// Classify all policies using the provided (already prepared) function registry.
pub fn classify_policies_with_registry<DB: DatabaseLike>(
    db: &DB,
    registry: &FunctionRegistry,
) -> Vec<ClassifiedPolicy> {
    db.policies()
        .map(|policy| {
            let mut classified = ClassifiedPolicy::from_policy(policy, db);
            let classify = |expr: &Expr| {
                classify_expr(expr, db, registry, &classified.table, classified.command)
            };

            // An absent clause is not `TRUE`: PostgreSQL stores no qual for it, and
            // with no permissive qual the command falls closed.
            let using = classified.using.as_ref().map(&classify);
            let with_check = classified.with_check.as_ref().map(&classify);

            classified.using_classification = using;
            classified.with_check_classification = with_check;
            classified
        })
        .collect()
}

/// Maximum recursion depth for `classify_expr`.
///
/// Beyond this depth an expression is classified as `Unknown D` to avoid
/// stack overflows from adversarially-nested SQL.
const MAX_CLASSIFY_DEPTH: u32 = 64;

/// Rewrite `CASE WHEN c1 THEN TRUE WHEN c2 THEN TRUE ... ELSE FALSE END` into
/// an OR-tree of the TRUE-branch conditions.  Returns `None` when the CASE has
/// a non-boolean result or is not a simple searched CASE.
fn normalize_boolean_case(
    conditions: &[sqlparser::ast::CaseWhen],
    else_result: Option<&Expr>,
) -> Option<Expr> {
    if conditions.is_empty() {
        return None;
    }

    // ELSE must be FALSE or absent (absent ELSE in a boolean context is NULL,
    // which we treat as false).
    if let Some(else_expr) = else_result {
        if recognizers::constant_bool_value(else_expr) != Some(false) {
            return None;
        }
    }

    // Collect conditions whose result is TRUE.
    let mut true_conditions: Vec<Expr> = Vec::new();
    for case_when in conditions {
        match recognizers::constant_bool_value(&case_when.result) {
            Some(true) => true_conditions.push(case_when.condition.clone()),
            Some(false) => {}    // skip FALSE branches
            None => return None, // non-boolean result → bail
        }
    }

    if true_conditions.is_empty() {
        return None;
    }

    Some(fold_or(true_conditions))
}

/// Fold a non-empty list of expressions into a left-associative OR tree.
fn fold_or(mut exprs: Vec<Expr>) -> Expr {
    assert!(!exprs.is_empty());
    let mut result = exprs.remove(0);
    for next in exprs {
        result = Expr::BinaryOp {
            left: Box::new(result),
            op: BinaryOperator::Or,
            right: Box::new(next),
        };
    }
    result
}

/// Fold a non-empty list of expressions into a left-associative AND tree.
fn fold_and(mut exprs: Vec<Expr>) -> Expr {
    assert!(!exprs.is_empty());
    let mut result = exprs.remove(0);
    for next in exprs {
        result = Expr::BinaryOp {
            left: Box::new(result),
            op: BinaryOperator::And,
            right: Box::new(next),
        };
    }
    result
}

fn unknown_d(expr: &Expr, reason: impl Into<String>) -> ClassifiedExpr {
    ClassifiedExpr {
        pattern: PatternClass::Unknown(UnclassifiedExpr {
            sql_text: expr.to_string(),
            reason: reason.into(),
        }),
        confidence: ConfidenceLevel::D,
    }
}

/// Recursively classify an expression using the pattern decision tree.
pub fn classify_expr<DB: DatabaseLike>(
    expr: &Expr,
    db: &DB,
    registry: &FunctionRegistry,
    table: &str,
    command: PolicyCommand,
) -> ClassifiedExpr {
    classify_expr_depth(expr, db, registry, table, command, 0)
}

fn classify_expr_depth<DB: DatabaseLike>(
    expr: &Expr,
    db: &DB,
    registry: &FunctionRegistry,
    table: &str,
    command: PolicyCommand,
    depth: u32,
) -> ClassifiedExpr {
    if depth > MAX_CLASSIFY_DEPTH {
        return unknown_d(
            expr,
            format!(
                "Expression exceeds maximum nesting depth ({MAX_CLASSIFY_DEPTH}); \
                 manual review required"
            ),
        );
    }
    let classified = classify_expr_inner(expr, db, registry, table, command, depth);
    // Every classification passes through here, including each part of a composite and
    // the inner rule of an inheritance, each against its own table.
    match guarded_column(&classified.pattern) {
        Some(column) if !table_has_column(db, table, column.as_str()) => unknown_d(
            expr,
            format!(
                "'{table}' has no column '{column}', so this would name a relation \
                 no tuple can fill"
            ),
        ),
        _ => classified,
    }
}

/// The column of the table being classified that `pattern` reads, if it names one.
///
/// Matched exhaustively on purpose: a pattern added later that reads a column must fail
/// to compile here rather than emit a relation nobody can fill. A column belonging to
/// another table, a membership table's own or a parent's, is checked where that table is
/// resolved, which is why those arms yield nothing.
fn guarded_column(pattern: &PatternClass) -> Option<&ColumnName> {
    match pattern {
        PatternClass::P3DirectOwnership(DirectOwnership { column, .. })
        | PatternClass::P6BooleanFlag(BooleanFlag { column, .. })
        | PatternClass::P9AttributeCondition(AttributeCondition { column, .. })
        | PatternClass::P11ArrayMembership(ArrayMembership { column, .. })
        | PatternClass::P12JsonbFieldOwnership(JsonbFieldOwnership { column, .. })
        | PatternClass::P14RowValueInCallerSet(RowValueInCallerSet { column, .. })
        | PatternClass::P15RowValueEqualsCallerScalar(RowValueEqualsCallerScalar {
            column, ..
        }) => Some(column),
        PatternClass::P5ParentInheritance(ParentInheritance { fk_column, .. }) => Some(fk_column),
        // Nothing these read belongs to the table being classified: a role function
        // takes the caller, a constant takes no row, a composite's parts and an
        // inheritance's inner rule are classified in their own right, and an
        // uncorrelated membership reads only the member table.
        //
        // A membership's `outer_column` is the guarded table's, and it is deliberately
        // absent from the list above: `resolve_bridge_columns` already refuses it with
        // `BridgeColumnMissing`, which names the bridge that could not be written, and
        // refusing here instead would replace that with a threshold drop saying less.
        PatternClass::P4ExistsMembership(ExistsMembership { .. })
        | PatternClass::P18MembershipInCallerSet(MembershipInCallerSet { .. })
        | PatternClass::P1NumericThreshold(NumericThreshold { .. })
        | PatternClass::P2RoleNameInList(RoleNameInList { .. })
        | PatternClass::P7AbacAnd(AbacAnd { .. })
        | PatternClass::P8Composite(Composite { .. })
        | PatternClass::P10ConstantBool(ConstantBool { .. })
        | PatternClass::P13UncorrelatedMembership(UncorrelatedMembership { .. })
        | PatternClass::P16ConstantInCallerSet(ConstantInCallerSet { .. })
        | PatternClass::P17CallerScalarEqualsConstant(CallerScalarEqualsConstant { .. })
        | PatternClass::Unknown(UnclassifiedExpr { .. }) => None,
    }
}

fn classify_expr_inner<DB: DatabaseLike>(
    expr: &Expr,
    db: &DB,
    registry: &FunctionRegistry,
    table: &str,
    command: PolicyCommand,
    depth: u32,
) -> ClassifiedExpr {
    // Gap 7: Row-value comparison decomposition.
    if let Expr::BinaryOp {
        left,
        op: BinaryOperator::Eq,
        right,
    } = expr
    {
        if let (Expr::Tuple(lhs), Expr::Tuple(rhs)) = (left.as_ref(), right.as_ref()) {
            if lhs.len() == rhs.len() && !lhs.is_empty() {
                let equalities: Vec<Expr> = lhs
                    .iter()
                    .zip(rhs.iter())
                    .map(|(l, r)| Expr::BinaryOp {
                        left: Box::new(l.clone()),
                        op: BinaryOperator::Eq,
                        right: Box::new(r.clone()),
                    })
                    .collect();
                let conjunction = fold_and(equalities);
                return classify_expr_depth(&conjunction, db, registry, table, command, depth + 1);
            }
        }
    }

    // Handle AND/OR composition first
    if let Expr::BinaryOp { left, op, right } = expr {
        match op {
            BinaryOperator::Or => {
                let left_class = classify_expr_depth(left, db, registry, table, command, depth + 1);
                let right_class =
                    classify_expr_depth(right, db, registry, table, command, depth + 1);

                let confidence = composite_confidence([&left_class, &right_class]);

                return ClassifiedExpr {
                    pattern: PatternClass::P8Composite(Composite {
                        op: BoolOp::Or,
                        parts: vec![left_class, right_class],
                    }),
                    confidence,
                };
            }
            BinaryOperator::And => {
                // "the caller is known" beside a rule that already needs the caller adds
                // nothing, so the rule stands alone rather than the pair being refused.
                if recognizers::is_redundant_caller_presence(left, registry) {
                    return classify_expr_depth(right, db, registry, table, command, depth + 1);
                }
                if recognizers::is_redundant_caller_presence(right, registry) {
                    return classify_expr_depth(left, db, registry, table, command, depth + 1);
                }
                let left_class = classify_expr_depth(left, db, registry, table, command, depth + 1);
                let right_class =
                    classify_expr_depth(right, db, registry, table, command, depth + 1);

                // Check if either branch is an attribute check → P7
                let left_attr = recognizers::is_attribute_check(left);
                let right_attr = recognizers::is_attribute_check(right);

                if let Some(attr) = left_attr {
                    if is_relationship_pattern_for_p7(&right_class.pattern) {
                        return ClassifiedExpr {
                            pattern: PatternClass::P7AbacAnd(AbacAnd {
                                relationship_part: Box::new(right_class),
                                attribute_part: attr.to_string(),
                            }),
                            confidence: ConfidenceLevel::C,
                        };
                    }
                }
                if let Some(attr) = right_attr {
                    if is_relationship_pattern_for_p7(&left_class.pattern) {
                        return ClassifiedExpr {
                            pattern: PatternClass::P7AbacAnd(AbacAnd {
                                relationship_part: Box::new(left_class),
                                attribute_part: attr.to_string(),
                            }),
                            confidence: ConfidenceLevel::C,
                        };
                    }
                }

                let confidence = composite_confidence([&left_class, &right_class]);

                return ClassifiedExpr {
                    pattern: PatternClass::P8Composite(Composite {
                        op: BoolOp::And,
                        parts: vec![left_class, right_class],
                    }),
                    confidence,
                };
            }
            _ => {}
        }
    }

    // Handle nested parens / grouped expressions
    if let Expr::Nested(inner) = expr {
        return classify_expr_depth(inner, db, registry, table, command, depth + 1);
    }

    // Gap 4: CASE WHEN cond1 THEN TRUE WHEN cond2 THEN TRUE ... ELSE FALSE END
    // conditions, then recurse.
    if let Expr::Case {
        operand: None,
        conditions,
        else_result,
        ..
    } = expr
    {
        if let Some(rewritten) = normalize_boolean_case(conditions, else_result.as_deref()) {
            return classify_expr_depth(&rewritten, db, registry, table, command, depth + 1);
        }
    }

    // Handle NOT unary operator.
    if let Expr::UnaryOp {
        op: UnaryOperator::Not,
        expr: inner,
    } = expr
    {
        // NOT TRUE → FALSE, NOT FALSE → TRUE: classify as P10 constant bool.
        if let Some(classified) = recognizers::recognize_p10_constant_bool(expr, db, registry) {
            return classified;
        }
        let inner_classified = classify_expr_depth(inner, db, registry, table, command, depth + 1);
        let desc = pattern_short_name(&inner_classified.pattern);
        return unknown_d(
            expr,
            format!(
                "NOT applied to {desc}; negation cannot be expressed as a static \
                 OpenFGA tuple, consider rewriting as an allowlist policy"
            ),
        );
    }

    // Handle negated structural forms (NOT IN list / NOT EXISTS / NOT IN subquery).
    // Each recognizer already returns None for these, so intercept them here to give
    if let Expr::InList { negated: true, .. } = expr {
        return unknown_d(
            expr,
            "NOT IN (...) cannot be represented as static OpenFGA tuples; \
             negation requires runtime filtering",
        );
    }
    if let Expr::Exists { negated: true, .. } = expr {
        return unknown_d(
            expr,
            "NOT EXISTS cannot be represented as static OpenFGA membership tuples; \
             negation requires runtime filtering",
        );
    }
    if let Expr::InSubquery { negated: true, .. } = expr {
        return unknown_d(
            expr,
            "NOT IN (subquery) cannot be represented as static OpenFGA membership \
             tuples; negation requires runtime filtering",
        );
    }
    // `col <> ALL (subquery)` is the quantified spelling of `NOT IN (subquery)`.
    if matches!(
        expr,
        Expr::AllOp {
            compare_op: BinaryOperator::NotEq,
            ..
        } | Expr::AnyOp {
            compare_op: BinaryOperator::NotEq,
            ..
        }
    ) {
        return unknown_d(
            expr,
            "Negated quantified comparison cannot be represented as static OpenFGA \
             membership tuples; negation requires runtime filtering",
        );
    }

    // Try P1: numeric threshold
    if let Some(classified) = recognizers::recognize_p1(expr, db, registry, command) {
        return classified;
    }

    // Try P2: role name IN-list
    if let Some(classified) = recognizers::recognize_p2(expr, db, registry) {
        return classified;
    }

    // Try P14 to P17: a value the request carries, which a deployment declared. Before
    // P3, since a declared source is never the caller and ownership must not claim it.
    if let Some(classified) = recognizers::recognize_session_attribute(expr, registry) {
        return classified;
    }

    // Try P3: direct ownership
    if let Some(classified) = recognizers::recognize_p3(expr, db, registry) {
        return classified;
    }

    // Try P12: the caller's identity held in a jsonb field.
    if let Some(classified) = recognizers::recognize_jsonb_field_ownership(expr, registry) {
        return classified;
    }

    // Try P5: parent inheritance via correlated EXISTS
    if let Some(classified) = recognizers::recognize_p5(expr, db, registry, table, command) {
        return classified;
    }

    // Try P4: EXISTS membership
    if let Some(classified) = recognizers::recognize_p4(expr, db, registry, table) {
        return classified;
    }

    // Try P4 and P5: the IN-subquery spellings, normalized into the EXISTS one.
    if let Some(classified) =
        recognizers::recognize_p4_in_subquery(expr, db, registry, table, command)
    {
        return classified;
    }

    if let Some(reason) =
        recognizers::diagnose_p5_parent_inheritance_ambiguity(expr, db, registry, table, command)
    {
        return unknown_d(expr, reason);
    }

    if let Some(reason) = recognizers::diagnose_p4_membership_ambiguity(expr, db, registry, table) {
        return unknown_d(expr, reason);
    }

    // Detect negated public-flag: `is_public = FALSE`, `col IS FALSE`, `col IS NOT TRUE`.
    // to P9 (attribute condition) since they cannot be expressed as static OpenFGA tuples.
    if let Some(col) = recognizers::is_negated_boolean_flag(expr) {
        return unknown_d(
            expr,
            format!(
                "Negated boolean-flag check on column '{col}' cannot be expressed as static \
                 OpenFGA tuples; negation requires runtime filtering"
            ),
        );
    }

    // Try P6: boolean flag
    if let Some(classified) = recognizers::recognize_p6(expr, db, registry) {
        return classified;
    }

    // Try P10: constant boolean policy
    if let Some(classified) = recognizers::recognize_p10_constant_bool(expr, db, registry) {
        return classified;
    }

    // Try array membership / overlap (Phase 6e): = ANY(...) and &&.
    if let Some(classified) = recognizers::recognize_array_patterns(expr, registry) {
        return classified;
    }

    // Try P9: standalone attribute condition. A literal constant is decided by the
    // row, so it grades with the boolean flag it generalises. Anything else, a
    // temporal function among them, keeps falling closed at C.
    if let Some(col) = recognizers::is_attribute_check(expr) {
        let value_desc = describe_comparison_value(expr);
        let predicate = recognizers::attribute_literal_predicate(expr);
        let request_predicate = recognizers::attribute_request_predicate(expr);
        // A literal is row data and a request value becomes a condition the service
        // evaluates, so both translate. Anything else still falls closed at C.
        let confidence = if predicate.is_some() || request_predicate.is_some() {
            ConfidenceLevel::B
        } else {
            ConfidenceLevel::C
        };
        return ClassifiedExpr {
            pattern: PatternClass::P9AttributeCondition(AttributeCondition {
                column: col,
                value_description: value_desc,
                predicate,
                request_predicate,
            }),
            confidence,
        };
    }

    let mut blamed: Vec<String> = recognizers::subquery_set_constructors(expr)
        .into_iter()
        .map(|name| describe_set_constructor(&name))
        .collect();
    blamed.extend(
        recognizers::called_function_names(expr, registry)
            .into_iter()
            .map(|name| describe_unrecognized_function(&name, registry)),
    );
    blamed.extend(
        recognizers::unrecognized_operators(expr)
            .into_iter()
            .map(|op| format!("Operator '{op}' has no translation")),
    );
    if !blamed.is_empty() {
        return unknown_d(expr, blamed.join(". "));
    }

    unknown_d(expr, "Expression does not match any known pattern")
}

/// Why naming `func_name` does not tell the translator how to translate the call.
fn describe_unrecognized_function(func_name: &str, registry: &FunctionRegistry) -> String {
    match registry.get(func_name) {
        Some(FunctionSemantic::Unknown { reason }) => {
            format!("Function '{func_name}' is registered as Unknown: {reason}")
        }
        None => format!("Function '{func_name}' not in registry and body not available"),
        _ => format!("Function '{func_name}' did not match any recognized translation pattern"),
    }
}

/// Why a set a constructor builds cannot be translated, and why registering a name
/// cannot help.
fn describe_set_constructor(name: &str) -> String {
    format!(
        "'{name}(subquery)' is SQL syntax rather than a function call, so no registry \
         entry can name it, and a set built from a subquery has no translation"
    )
}

/// Extract a human-readable description of the comparison value in a binary expression.
fn describe_comparison_value(expr: &Expr) -> String {
    if let Expr::BinaryOp { left, right, .. } = expr {
        for side in [left.as_ref(), right.as_ref()] {
            if let Expr::Value(v) = side {
                return match &v.value {
                    Value::SingleQuotedString(s) => format!("'{s}'"),
                    Value::Number(n, _) => n.clone(),
                    Value::Boolean(b) => b.to_string(),
                    _ => side.to_string(),
                };
            }
        }
    }
    "unknown".to_string()
}

fn pattern_short_name(pattern: &PatternClass) -> &'static str {
    match pattern {
        PatternClass::P1NumericThreshold(NumericThreshold { .. }) => "numeric role-threshold check",
        PatternClass::P2RoleNameInList(RoleNameInList { .. }) => "role-name-in-list check",
        PatternClass::P3DirectOwnership(DirectOwnership { .. }) => "direct-ownership check",
        PatternClass::P4ExistsMembership(ExistsMembership { .. }) => "EXISTS membership check",
        PatternClass::P18MembershipInCallerSet(MembershipInCallerSet { .. }) => {
            "membership row naming a value the caller's declared set holds"
        }
        PatternClass::P5ParentInheritance(ParentInheritance { .. }) => "parent-inheritance check",
        PatternClass::P6BooleanFlag(BooleanFlag { .. }) => "boolean-flag check",
        PatternClass::P7AbacAnd(AbacAnd { .. }) => "ABAC-and-relationship check",
        PatternClass::P8Composite(Composite { .. }) => "composite check",
        PatternClass::P9AttributeCondition(AttributeCondition { .. }) => {
            "attribute-condition check"
        }
        PatternClass::P10ConstantBool(ConstantBool { .. }) => "constant-boolean check",
        PatternClass::P11ArrayMembership(ArrayMembership { .. }) => "array-membership check",
        PatternClass::P12JsonbFieldOwnership(JsonbFieldOwnership { .. }) => {
            "jsonb-field-ownership check"
        }
        PatternClass::P13UncorrelatedMembership(UncorrelatedMembership { .. }) => {
            "uncorrelated membership check"
        }
        PatternClass::P14RowValueInCallerSet(RowValueInCallerSet { .. }) => {
            "declared caller set holding the row's value"
        }
        PatternClass::P15RowValueEqualsCallerScalar(RowValueEqualsCallerScalar { .. }) => {
            "declared caller value equal to the row's"
        }
        PatternClass::P16ConstantInCallerSet(ConstantInCallerSet { .. }) => {
            "declared caller set holding a constant"
        }
        PatternClass::P17CallerScalarEqualsConstant(CallerScalarEqualsConstant { .. }) => {
            "declared caller value equal to a constant"
        }
        PatternClass::Unknown(UnclassifiedExpr { .. }) => "unrecognized expression",
    }
}

fn is_relationship_pattern_for_p7(pattern: &PatternClass) -> bool {
    match pattern {
        PatternClass::P1NumericThreshold(NumericThreshold { .. })
        | PatternClass::P2RoleNameInList(RoleNameInList { .. })
        | PatternClass::P3DirectOwnership(DirectOwnership { .. })
        // The caller is an element of the array column, or named by the jsonb field, so
        // both are user-resource relationships exactly as ownership is.
        | PatternClass::P11ArrayMembership(ArrayMembership { .. })
        | PatternClass::P12JsonbFieldOwnership(JsonbFieldOwnership { .. })
        | PatternClass::P4ExistsMembership(ExistsMembership { .. })
        // Membership of the holder is still a user-resource relationship, even though
        // the holder stands for the whole table.
        | PatternClass::P13UncorrelatedMembership(UncorrelatedMembership { .. })
        | PatternClass::P5ParentInheritance(ParentInheritance { .. }) => true,
        // P6 (boolean public flag) is a resource-attribute check, not a user-resource
        // relationship. Including it here would misclassify e.g.
        // `is_public = TRUE AND status = 'published'` as P7 (ABAC+relationship)
        // when it is really two attribute conditions with no user dimension.
        PatternClass::P7AbacAnd(AbacAnd {
            relationship_part, ..
        }) => is_relationship_pattern_for_p7(&relationship_part.pattern),
        PatternClass::P8Composite(Composite { parts, .. }) => {
            !parts.is_empty()
                && parts
                    .iter()
                    .all(|part| is_relationship_pattern_for_p7(&part.pattern))
        }
        // A declared request-scoped value is not a user-resource relationship a tuple
        // can carry, so an attribute guard beside one composes as a plain intersection
        // rather than through the P7 shape.
        PatternClass::P6BooleanFlag(BooleanFlag { .. })
        | PatternClass::P9AttributeCondition(AttributeCondition { .. })
        | PatternClass::P10ConstantBool(ConstantBool { .. })
        | PatternClass::P14RowValueInCallerSet(RowValueInCallerSet { .. })
        | PatternClass::P18MembershipInCallerSet(MembershipInCallerSet { .. })
        | PatternClass::P15RowValueEqualsCallerScalar(RowValueEqualsCallerScalar { .. })
        | PatternClass::P16ConstantInCallerSet(ConstantInCallerSet { .. })
        | PatternClass::P17CallerScalarEqualsConstant(CallerScalarEqualsConstant { .. })
        | PatternClass::Unknown(UnclassifiedExpr { .. }) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::identifiers::ColumnName;
    use crate::parser::sql_parser::{parse_schema, ParserDB};
    use sqlparser::dialect::PostgreSqlDialect;
    use sqlparser::parser::Parser;

    fn parse_expr(expr_sql: &str) -> Expr {
        Parser::new(&PostgreSqlDialect {})
            .try_with_sql(expr_sql)
            .expect("expression should parse")
            .parse_expr()
            .expect("expression should parse")
    }

    fn docs_db() -> ParserDB {
        parse_schema(
            r"
CREATE TABLE docs (
  id UUID PRIMARY KEY,
  owner_id UUID,
  is_public BOOLEAN,
  status TEXT,
  priority INTEGER,
  archived BOOLEAN
);
CREATE TABLE doc_members (
  doc_id UUID,
  user_id UUID
);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
",
        )
        .expect("schema should parse")
    }

    #[test]
    fn classify_or_of_level_a_patterns_becomes_level_b_composite() {
        let db = docs_db();
        let registry = FunctionRegistry::new();
        let expr = parse_expr("owner_id = current_user OR is_public = TRUE");

        let classified = classify_expr(&expr, &db, &registry, "docs", PolicyCommand::Select);

        assert!(matches!(
            &classified.pattern,
            PatternClass::P8Composite(Composite {
                op: BoolOp::Or,
                parts
            }) if parts.len() == 2
        ));
        assert_eq!(classified.confidence, ConfidenceLevel::B);
    }

    #[test]
    fn classify_and_with_attribute_on_each_side_maps_to_p7() {
        let db = docs_db();
        let registry = FunctionRegistry::new();

        for expr_sql in [
            "status = 'published' AND owner_id = current_user",
            "owner_id = current_user AND status = 'published'",
        ] {
            let expr = parse_expr(expr_sql);
            let classified = classify_expr(&expr, &db, &registry, "docs", PolicyCommand::Select);
            assert!(matches!(
                &classified.pattern,
                PatternClass::P7AbacAnd(AbacAnd { attribute_part, .. }) if attribute_part == "status"
            ));
            assert_eq!(classified.confidence, ConfidenceLevel::C);
        }
    }

    #[test]
    fn classify_and_with_in_list_attribute_guard_maps_to_p7() {
        // Phase 3g: `status IN ('active', 'pending')` is an attribute check so
        // `owner_id = current_user AND status IN ('active', 'pending')` maps to P7.
        let db = docs_db();
        let registry = FunctionRegistry::new();

        let expr = parse_expr("owner_id = current_user AND status IN ('active', 'pending')");
        let classified = classify_expr(&expr, &db, &registry, "docs", PolicyCommand::Select);
        assert!(
            matches!(
                &classified.pattern,
                PatternClass::P7AbacAnd(AbacAnd { attribute_part, .. }) if attribute_part == "status"
            ),
            "IN-list attribute guard should produce P7, got: {:?}",
            classified.pattern
        );
        assert_eq!(classified.confidence, ConfidenceLevel::C);
    }

    #[test]
    fn classify_and_with_attribute_and_non_relationship_side_stays_composite() {
        let db = docs_db();
        let registry = FunctionRegistry::new();
        let expr = parse_expr("status = 'published' AND TRUE");

        let classified = classify_expr(&expr, &db, &registry, "docs", PolicyCommand::Select);

        assert!(matches!(
            &classified.pattern,
            PatternClass::P8Composite(Composite {
                op: BoolOp::And,
                parts
            }) if parts.len() == 2
        ));
        // The attribute half now grades B, and a composite takes the weaker of its
        // parts, so the whole is B rather than the old C.
        assert_eq!(classified.confidence, ConfidenceLevel::B);
    }

    #[test]
    fn classify_and_relationships_without_attributes_remains_composite() {
        let db = docs_db();
        let registry = FunctionRegistry::new();
        let expr = parse_expr("owner_id = current_user AND TRUE");

        let classified = classify_expr(&expr, &db, &registry, "docs", PolicyCommand::Select);

        assert!(matches!(
            &classified.pattern,
            PatternClass::P8Composite(Composite {
                op: BoolOp::And,
                parts
            }) if parts.len() == 2
        ));
        assert_eq!(classified.confidence, ConfidenceLevel::B);
    }

    #[test]
    fn classify_nested_expression_is_unwrapped() {
        let db = docs_db();
        let registry = FunctionRegistry::new();
        let expr = parse_expr("(owner_id = current_user)");

        let classified = classify_expr(&expr, &db, &registry, "docs", PolicyCommand::Select);

        assert!(matches!(
            &classified.pattern,
            PatternClass::P3DirectOwnership(DirectOwnership { column }) if column == "owner_id"
        ));
        assert_eq!(classified.confidence, ConfidenceLevel::A);
    }

    #[test]
    fn classify_attribute_fallback_formats_literal_values() {
        let db = docs_db();
        let registry = FunctionRegistry::new();

        let cases = [
            ("status = 'draft'", "status", "'draft'"),
            ("priority >= 3", "priority", "3"),
            ("archived = FALSE", "archived", "false"),
        ];

        for (expr_sql, expected_col, expected_value) in cases {
            let expr = parse_expr(expr_sql);
            let classified = classify_expr(&expr, &db, &registry, "docs", PolicyCommand::Select);
            assert!(matches!(
                &classified.pattern,
                PatternClass::P9AttributeCondition(AttributeCondition {
                    column,
                    value_description,
                    predicate: Some(_),
                    ..
                }) if column == expected_col && value_description == expected_value
            ));
            // A literal constant is decided by the row, so it grades with the boolean
            // flag rather than falling to the review tier.
            assert_eq!(classified.confidence, ConfidenceLevel::B);
        }
    }

    #[test]
    fn classify_unknown_function_has_specific_reason() {
        let db = docs_db();
        let registry = FunctionRegistry::new();
        let expr = parse_expr("mystery_auth(owner_id)");

        let classified = classify_expr(&expr, &db, &registry, "docs", PolicyCommand::Select);

        assert!(matches!(
            &classified.pattern,
            PatternClass::Unknown(UnclassifiedExpr { reason, .. }) if reason.contains("Function 'mystery_auth' not in registry")
        ));
        assert_eq!(classified.confidence, ConfidenceLevel::D);
    }

    #[test]
    fn classify_membership_ambiguity_has_specific_reason() {
        let db = docs_db();
        let registry = FunctionRegistry::new();
        let expr = parse_expr(
            "EXISTS (
               SELECT 1
               FROM doc_members dm1
               JOIN doc_members dm2 ON dm1.doc_id = dm2.doc_id
               WHERE dm1.doc_id = docs.id
                 AND dm1.user_id = current_user
                 AND dm2.doc_id = docs.id
                 AND dm2.user_id = current_user
             )",
        );

        let classified = classify_expr(&expr, &db, &registry, "docs", PolicyCommand::Select);

        assert!(matches!(
            &classified.pattern,
            PatternClass::Unknown(UnclassifiedExpr { reason, .. }) if reason.contains("Ambiguous membership pattern")
        ));
        assert_eq!(classified.confidence, ConfidenceLevel::D);
    }

    #[test]
    fn classify_membership_reading_the_guarded_table_is_refused() {
        let db = docs_db();
        let registry = FunctionRegistry::new();
        let expr = parse_expr(
            "EXISTS (
               SELECT 1
               FROM doc_members dm
               JOIN docs d ON dm.doc_id = d.id
               WHERE dm.doc_id = docs.id
                 AND dm.user_id = current_user
                 AND is_public = TRUE
             )",
        );

        let classified = classify_expr(&expr, &db, &registry, "docs", PolicyCommand::Select);

        assert!(
            matches!(
                &classified.pattern,
                PatternClass::Unknown(UnclassifiedExpr { reason, .. }) if reason.contains("infinite recursion")
            ),
            "reading the guarded table is a read PostgreSQL refuses to plan, got {:?}",
            classified.pattern
        );
        assert_eq!(classified.confidence, ConfidenceLevel::D);
    }

    #[test]
    fn classify_derived_joined_membership_with_unqualified_extra_is_ambiguous() {
        let db = docs_db();
        let registry = FunctionRegistry::new();
        let expr = parse_expr(
            "EXISTS (
               SELECT 1
               FROM doc_members dm
               JOIN (SELECT id, is_public FROM docs) d ON dm.doc_id = d.id
               WHERE dm.doc_id = docs.id
                 AND dm.user_id = current_user
                 AND is_public = TRUE
             )",
        );

        let classified = classify_expr(&expr, &db, &registry, "docs", PolicyCommand::Select);

        assert!(matches!(
            &classified.pattern,
            PatternClass::Unknown(UnclassifiedExpr { reason, .. }) if reason.contains("Ambiguous membership pattern")
        ));
        assert_eq!(classified.confidence, ConfidenceLevel::D);
    }

    #[test]
    fn classify_parent_inheritance_ambiguity_has_specific_reason() {
        let db = parse_schema(
            r"
CREATE TABLE projects(id UUID PRIMARY KEY, owner_id UUID);
CREATE TABLE accounts(id UUID PRIMARY KEY, owner_id UUID);
CREATE TABLE tasks(
  id UUID PRIMARY KEY,
  project_id UUID REFERENCES projects(id),
  account_id UUID REFERENCES accounts(id)
);
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
",
        )
        .expect("schema should parse");
        let registry = FunctionRegistry::new();
        let expr = parse_expr(
            "EXISTS (
               SELECT 1
               FROM projects p, accounts a
               WHERE p.id = tasks.project_id
                 AND p.owner_id = current_user
                 AND a.id = tasks.account_id
                 AND a.owner_id = current_user
             )",
        );

        let classified = classify_expr(&expr, &db, &registry, "tasks", PolicyCommand::Select);

        assert!(matches!(
            &classified.pattern,
            PatternClass::Unknown(UnclassifiedExpr { reason, .. }) if reason.contains("Ambiguous parent inheritance pattern")
        ));
        assert_eq!(classified.confidence, ConfidenceLevel::D);
    }

    #[test]
    fn classify_not_expression_names_the_inner_pattern() {
        let db = docs_db();
        let registry = FunctionRegistry::new();

        let cases = [
            (
                "NOT (owner_id = current_user)",
                "NOT applied to direct-ownership check",
            ),
            (
                "NOT (is_public = TRUE)",
                "NOT applied to boolean-flag check",
            ),
            (
                "NOT (status = 'deleted')",
                "NOT applied to attribute-condition check",
            ),
        ];

        for (expr_sql, expected_fragment) in cases {
            let expr = parse_expr(expr_sql);
            let classified = classify_expr(&expr, &db, &registry, "docs", PolicyCommand::Select);
            assert!(
                matches!(&classified.pattern, PatternClass::Unknown(UnclassifiedExpr { reason, .. })
                    if reason.contains(expected_fragment)),
                "`{expr_sql}`: expected reason containing '{expected_fragment}', got: {:?}",
                classified.pattern
            );
            assert_eq!(classified.confidence, ConfidenceLevel::D, "`{expr_sql}`");
        }
    }

    #[test]
    fn classify_negated_structural_forms_give_specific_reasons() {
        let db = docs_db();
        let registry = FunctionRegistry::new();

        let cases = [
            (
                "owner_id NOT IN ('user-1', 'user-2')",
                "NOT IN (...) cannot be represented",
            ),
            (
                "NOT EXISTS (SELECT 1 FROM doc_members WHERE doc_id = id AND user_id = current_user)",
                "NOT EXISTS cannot be represented",
            ),
            (
                "owner_id NOT IN (SELECT user_id FROM doc_members WHERE doc_id = id)",
                "NOT IN (subquery) cannot be represented",
            ),
        ];

        for (expr_sql, expected_fragment) in cases {
            let expr = parse_expr(expr_sql);
            let classified = classify_expr(&expr, &db, &registry, "docs", PolicyCommand::Select);
            assert!(
                matches!(&classified.pattern, PatternClass::Unknown(UnclassifiedExpr { reason, .. })
                    if reason.contains(expected_fragment)),
                "`{expr_sql}`: expected reason containing '{expected_fragment}', got: {:?}",
                classified.pattern
            );
            assert_eq!(classified.confidence, ConfidenceLevel::D, "`{expr_sql}`");
        }
    }

    /// `ARRAY(subquery)` parses as a function named `array`, so blaming it as a call sent
    /// the operator after a registry entry that cannot exist.
    #[test]
    fn a_set_the_array_constructor_builds_is_not_blamed_on_a_missing_function() {
        let db = docs_db();
        let registry = FunctionRegistry::new();

        let claim_set = "owner_id = ANY (ARRAY(SELECT jsonb_array_elements_text(\
                         current_setting('request.jwt.claims')::jsonb -> 'teams')))";
        let function_set = "owner_id = ANY (ARRAY(SELECT user_teams()))";

        for expr_sql in [claim_set, function_set] {
            let expr = parse_expr(expr_sql);
            let classified = classify_expr(&expr, &db, &registry, "docs", PolicyCommand::Select);
            let PatternClass::Unknown(UnclassifiedExpr { reason, .. }) = &classified.pattern else {
                panic!(
                    "`{expr_sql}`: expected Unknown, got {:?}",
                    classified.pattern
                );
            };
            assert!(
                reason.contains("'array(subquery)'"),
                "`{expr_sql}`: the reason must name the constructor, got: {reason}"
            );
            assert!(
                !reason.contains("Function 'array'"),
                "`{expr_sql}`: a constructor is not a call an operator can register, got: {reason}"
            );
            assert_eq!(classified.confidence, ConfidenceLevel::D, "`{expr_sql}`");
        }

        // The genuine call inside the second spelling still earns its own blame, so the
        // constructor arm cannot pass by silencing everything under it.
        let expr = parse_expr(function_set);
        let classified = classify_expr(&expr, &db, &registry, "docs", PolicyCommand::Select);
        let PatternClass::Unknown(UnclassifiedExpr { reason, .. }) = &classified.pattern else {
            panic!("expected Unknown, got {:?}", classified.pattern);
        };
        assert!(
            reason.contains("Function 'user_teams' not in registry"),
            "an unregistered function is still named, got: {reason}"
        );
    }

    /// The constructor is told apart by its arguments being a subquery, never by its
    /// name, so a call that happens to be named `array` is still blamed as a call.
    #[test]
    fn a_function_named_array_is_still_blamed_as_a_call() {
        let db = docs_db();
        let registry = FunctionRegistry::new();
        let expr = parse_expr("owner_id = app.array(owner_id)");

        let classified = classify_expr(&expr, &db, &registry, "docs", PolicyCommand::Select);

        let PatternClass::Unknown(UnclassifiedExpr { reason, .. }) = &classified.pattern else {
            panic!("expected Unknown, got {:?}", classified.pattern);
        };
        assert!(
            reason.contains("Function 'array' not in registry"),
            "a call taking an argument list is a call, got: {reason}"
        );
        assert!(
            !reason.contains("(subquery)"),
            "nothing here builds a set from a subquery, got: {reason}"
        );
    }

    #[test]
    fn classify_generic_unknown_expression_has_fallback_reason() {
        let db = docs_db();
        let registry = FunctionRegistry::new();
        let expr = parse_expr("owner_id IS NULL");

        let classified = classify_expr(&expr, &db, &registry, "docs", PolicyCommand::Select);

        assert!(matches!(
            &classified.pattern,
            PatternClass::Unknown(UnclassifiedExpr { reason, .. }) if reason == "Expression does not match any known pattern"
        ));
        assert_eq!(classified.confidence, ConfidenceLevel::D);
    }

    #[test]
    fn classify_or_and_confidence_can_drop_below_b() {
        let db = docs_db();
        let registry = FunctionRegistry::new();

        let or_expr = parse_expr("mystery_auth(owner_id) OR owner_id = current_user");
        let or_classified = classify_expr(&or_expr, &db, &registry, "docs", PolicyCommand::Select);
        assert_eq!(or_classified.confidence, ConfidenceLevel::D);

        let and_expr = parse_expr("mystery_auth(owner_id) AND owner_id = current_user");
        let and_classified =
            classify_expr(&and_expr, &db, &registry, "docs", PolicyCommand::Select);
        assert_eq!(and_classified.confidence, ConfidenceLevel::D);
    }

    #[test]
    fn classify_current_user_accessor_function_without_pattern_falls_back_to_unknown_reason() {
        let db = docs_db();
        let mut registry = FunctionRegistry::new();
        registry
            .load_from_json(
                r#"{
  "auth_current_user_id": {"kind": "current_user_accessor", "returns": "uuid"}
}"#,
            )
            .expect("registry json should parse");

        let expr = parse_expr("auth_current_user_id()");
        let classified = classify_expr(&expr, &db, &registry, "docs", PolicyCommand::Select);

        assert!(matches!(
            &classified.pattern,
            PatternClass::Unknown(UnclassifiedExpr { reason, .. }) if reason == "Expression does not match any known pattern"
        ));
        assert_eq!(classified.confidence, ConfidenceLevel::D);
    }

    #[test]
    fn classify_function_registered_as_unknown_semantic_has_accurate_reason() {
        let db = docs_db();
        let mut registry = FunctionRegistry::new();
        registry
            .load_from_json(
                r#"{
  "mystery_auth": {"kind": "unknown", "reason": "custom business logic, cannot be inferred"}
}"#,
            )
            .expect("registry json should parse");

        let expr = parse_expr("mystery_auth(owner_id)");
        let classified = classify_expr(&expr, &db, &registry, "docs", PolicyCommand::Select);

        assert!(
            matches!(
                &classified.pattern,
                PatternClass::Unknown(UnclassifiedExpr { reason, .. })
                    if reason.contains("registered as Unknown")
                    && !reason.contains("not in registry")
            ),
            "when a function is in the registry as Unknown, the reason should say so, got: {:?}",
            classified.pattern
        );
        assert_eq!(classified.confidence, ConfidenceLevel::D);
    }

    #[test]
    fn classify_names_a_function_call_sitting_under_an_operator() {
        let db = docs_db();
        let registry = FunctionRegistry::new();

        // A call at the root of the clause was already named. These shapes bury it
        // under an operator, a quantifier or a subquery.
        let cases = [
            "mystery_auth(owner_id) = 'x'",
            "'x' = mystery_auth(owner_id)",
            "mystery_auth(owner_id) > 3",
            "mystery_auth(owner_id) IS TRUE",
            "mystery_auth(owner_id) IN ('a', 'b')",
            "owner_id = mystery_auth(id)",
            "EXISTS (SELECT 1 FROM doc_members WHERE doc_members.doc_id = mystery_auth(docs.id))",
        ];

        for expr_sql in cases {
            let expr = parse_expr(expr_sql);
            let classified = classify_expr(&expr, &db, &registry, "docs", PolicyCommand::Select);
            assert!(
                matches!(&classified.pattern, PatternClass::Unknown(UnclassifiedExpr { reason, .. })
                    if reason.contains("mystery_auth")),
                "`{expr_sql}`: the reason must name the call, got: {:?}",
                classified.pattern
            );
            assert_eq!(classified.confidence, ConfidenceLevel::D, "`{expr_sql}`");
        }
    }

    #[test]
    fn classify_names_every_unrecognized_call_but_never_a_known_accessor() {
        let db = docs_db();
        let mut registry = FunctionRegistry::new();
        registry
            .load_from_json(
                r#"{
  "auth_current_user_id": {"kind": "current_user_accessor", "returns": "uuid"}
}"#,
            )
            .expect("registry json should parse");

        let expr = parse_expr("outer_guard(inner_guard(auth_current_user_id())) = 'x'");
        let classified = classify_expr(&expr, &db, &registry, "docs", PolicyCommand::Select);

        let PatternClass::Unknown(UnclassifiedExpr { reason, .. }) = &classified.pattern else {
            panic!("expected Unknown, got: {:?}", classified.pattern);
        };
        assert!(
            reason.contains("outer_guard") && reason.contains("inner_guard"),
            "the classifier cannot tell which wrapper blocked it, so both are named: {reason}"
        );
        assert!(
            !reason.contains("auth_current_user_id"),
            "a call the registry resolves is not at fault: {reason}"
        );

        // One call spelled twice is one thing to go read.
        let repeated = parse_expr("tenant_of(owner_id) = tenant_of(id)");
        let classified = classify_expr(&repeated, &db, &registry, "docs", PolicyCommand::Select);
        let PatternClass::Unknown(UnclassifiedExpr { reason, .. }) = &classified.pattern else {
            panic!("expected Unknown, got: {:?}", classified.pattern);
        };
        assert_eq!(
            reason.matches("tenant_of").count(),
            1,
            "a repeated call is named once: {reason}"
        );
    }

    /// `current_user` parses as a function call but is a SQL keyword nobody wrote,
    /// so blaming it sends the operator hunting for a function that does not exist.
    #[test]
    fn classify_never_blames_a_sql_current_user_keyword() {
        let db = docs_db();
        let registry = FunctionRegistry::new();

        for expr_sql in [
            "data ->> 'owner_id' = current_user",
            "current_user = data ->> 'owner_id'",
            "current_role = data ->> 'owner_id'",
        ] {
            let expr = parse_expr(expr_sql);
            let classified = classify_expr(&expr, &db, &registry, "docs", PolicyCommand::Select);
            let PatternClass::Unknown(UnclassifiedExpr { reason, .. }) = &classified.pattern else {
                continue;
            };
            assert!(
                !reason.contains("current_user") && !reason.contains("current_role"),
                "`{expr_sql}`: a SQL keyword is not a missing function: {reason}"
            );
        }
    }

    /// Lead 3 named the unrecognized call. An operator carries no function to name, so
    /// these shapes kept the generic reason and sent the operator reading the whole
    /// clause to find which piece defeated recognition.
    #[test]
    fn classify_names_the_operator_that_defeated_recognition() {
        let db = docs_db();
        let registry = FunctionRegistry::new();

        for (expr_sql, expected) in [
            ("archived -> 'k' = status", "->"),
            ("archived #> '{a}' = status", "#>"),
            ("priority << 2 = status", "<<"),
        ] {
            let expr = parse_expr(expr_sql);
            let classified = classify_expr(&expr, &db, &registry, "docs", PolicyCommand::Select);
            let PatternClass::Unknown(UnclassifiedExpr { reason, .. }) = &classified.pattern else {
                panic!(
                    "`{expr_sql}`: expected Unknown, got {:?}",
                    classified.pattern
                );
            };
            assert!(
                reason.contains(expected),
                "`{expr_sql}`: the reason must name the '{expected}' operator: {reason}"
            );
        }
    }

    #[test]
    fn describe_comparison_value_handles_null_and_non_binary() {
        let null_expr = parse_expr("status = NULL");
        assert_eq!(describe_comparison_value(&null_expr), "NULL");

        let non_binary = parse_expr("status IS NULL");
        assert_eq!(describe_comparison_value(&non_binary), "unknown");
    }

    #[test]
    fn classify_policies_handles_using_and_with_check() {
        let db = parse_schema(
            r"
CREATE TABLE docs (
  id UUID PRIMARY KEY,
  owner_id UUID
);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_update ON docs FOR UPDATE
  USING (owner_id = current_user)
  WITH CHECK (owner_id = current_user);
",
        )
        .expect("schema should parse");

        let registry = FunctionRegistry::new();
        let classified = classify_policies(&db, &registry);
        assert_eq!(classified.len(), 1);

        let policy = &classified[0];
        assert!(policy.using_classification.is_some());
        assert!(policy.with_check_classification.is_some());
    }

    #[test]
    fn classify_negated_public_flag_is_unknown_not_p9() {
        let db = docs_db();
        let registry = FunctionRegistry::new();

        let cases = [
            "is_public = FALSE",
            "FALSE = is_public",
            "is_public IS FALSE",
            "is_public IS NOT TRUE",
        ];

        for expr_sql in cases {
            let expr = parse_expr(expr_sql);
            let classified = classify_expr(&expr, &db, &registry, "docs", PolicyCommand::Select);
            assert!(
                matches!(&classified.pattern, PatternClass::Unknown(UnclassifiedExpr { reason, .. })
                    if reason.contains("Negated boolean-flag check")),
                "`{expr_sql}`: expected Unknown with negated-flag reason, got: {:?}",
                classified.pattern
            );
            assert_eq!(
                classified.confidence,
                ConfidenceLevel::D,
                "`{expr_sql}` should be D-confidence"
            );
        }
    }

    #[test]
    fn classify_p6_and_attribute_does_not_trigger_p7() {
        let db = docs_db();
        let registry = FunctionRegistry::new();

        // `is_public = TRUE AND status = 'published'`: both are attribute-like checks;
        // P6 must NOT be treated as the "relationship side" of P7.
        let expr = parse_expr("status = 'published' AND is_public = TRUE");
        let classified = classify_expr(&expr, &db, &registry, "docs", PolicyCommand::Select);

        assert!(
            matches!(
                &classified.pattern,
                PatternClass::P8Composite(Composite {
                    op: BoolOp::And,
                    ..
                })
            ),
            "P6 AND attribute should be P8Composite, not P7, got: {:?}",
            classified.pattern
        );
    }

    #[test]
    fn classify_p3_does_not_match_column_to_column_equality() {
        let db = parse_schema(
            "CREATE TABLE tasks(id uuid primary key, assigned_to uuid, manager_id uuid);",
        )
        .expect("schema should parse");
        let registry = FunctionRegistry::new();

        // `assigned_to = manager_id`: both sides are bare column references.
        // Even though `manager_id` contains "user_id" as a substring, it is not
        // a current-user accessor and must not be mistaken for one.
        let expr = parse_expr("assigned_to = manager_id");
        let classified = classify_expr(&expr, &db, &registry, "tasks", PolicyCommand::Select);

        assert!(
            !matches!(
                &classified.pattern,
                PatternClass::P3DirectOwnership(DirectOwnership { .. })
            ),
            "column = column must not classify as P3DirectOwnership, got: {:?}",
            classified.pattern
        );
    }

    #[test]
    fn classify_p3_does_not_match_owner_like_column_to_column_equality() {
        let db =
            parse_schema("CREATE TABLE docs(id uuid primary key, owner_id uuid, author_id uuid);")
                .expect("schema should parse");
        let registry = FunctionRegistry::new();

        // `owner_id = author_id`: both sides are table columns.
        // `author_id` must not be treated as a user accessor just because it contains "auth".
        let expr = parse_expr("owner_id = author_id");
        let classified = classify_expr(&expr, &db, &registry, "docs", PolicyCommand::Select);

        assert!(
            !matches!(
                &classified.pattern,
                PatternClass::P3DirectOwnership(DirectOwnership { .. })
            ),
            "owner_id = author_id must not classify as P3DirectOwnership, got: {:?}",
            classified.pattern
        );
    }

    #[test]
    fn classify_p4_exists_any_row_without_user_predicate_is_unknown() {
        let db = parse_schema(
            r"
CREATE TABLE docs(id uuid primary key);
CREATE TABLE doc_members(doc_id uuid, user_id uuid);
",
        )
        .expect("schema should parse");
        let registry = FunctionRegistry::new();

        // EXISTS with no current-user filter is an "exists any member" check ,
        // it does not identify the current user and must not classify as P4.
        let expr = parse_expr("EXISTS (SELECT 1 FROM doc_members WHERE doc_id = docs.id)");
        let classified = classify_expr(&expr, &db, &registry, "docs", PolicyCommand::Select);

        assert!(
            !matches!(
                &classified.pattern,
                PatternClass::P4ExistsMembership(ExistsMembership { .. })
            ),
            "EXISTS with no user predicate must not classify as P4, got: {:?}",
            classified.pattern
        );
    }

    #[test]
    fn classify_not_true_and_not_false_become_p10() {
        let db = docs_db();
        let registry = FunctionRegistry::new();

        let not_true = parse_expr("NOT TRUE");
        let classified_not_true =
            classify_expr(&not_true, &db, &registry, "docs", PolicyCommand::Select);
        assert_eq!(
            classified_not_true.pattern,
            PatternClass::P10ConstantBool(ConstantBool { value: false }),
            "NOT TRUE should classify as P10 constant false"
        );
        assert_eq!(classified_not_true.confidence, ConfidenceLevel::A);

        let not_false = parse_expr("NOT FALSE");
        let classified_not_false =
            classify_expr(&not_false, &db, &registry, "docs", PolicyCommand::Select);
        assert_eq!(
            classified_not_false.pattern,
            PatternClass::P10ConstantBool(ConstantBool { value: true }),
            "NOT FALSE should classify as P10 constant true"
        );
        assert_eq!(classified_not_false.confidence, ConfidenceLevel::A);
    }

    #[test]
    fn classify_bare_policy_leaves_both_clauses_unclassified() {
        let db = parse_schema(
            r"
CREATE TABLE docs (id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_open ON docs;
",
        )
        .expect("schema should parse");

        let registry = FunctionRegistry::new();
        let classified = classify_policies(&db, &registry);
        assert_eq!(classified.len(), 1);

        let policy = &classified[0];
        assert!(
            policy.using_classification.is_none(),
            "a policy storing no USING must not classify one, got {:?}",
            policy.using_classification
        );
        assert!(
            policy.with_check_classification.is_none(),
            "bare policy should have no WITH CHECK"
        );
    }

    #[test]
    fn classify_current_role_is_treated_as_current_user_accessor() {
        let db = docs_db();
        let registry = FunctionRegistry::new();

        // `current_role` is a PostgreSQL session-variable keyword equivalent to
        // `current_user` for authorization purposes.
        let expr = parse_expr("owner_id = current_role");
        let classified = classify_expr(&expr, &db, &registry, "docs", PolicyCommand::Select);
        assert!(
            matches!(&classified.pattern, PatternClass::P3DirectOwnership(DirectOwnership { column })
                if column == "owner_id"),
            "owner_id = current_role should classify as P3, got: {:?}",
            classified.pattern
        );
    }

    #[test]
    fn classify_session_user_is_not_treated_as_current_user_accessor() {
        // `session_user` is the original connection user and does NOT change under SET ROLE,
        // unlike `current_user`.  Policies using `session_user` must classify as Unknown (D)
        // so the operator can manually verify the intended semantics.
        let db = docs_db();
        let registry = FunctionRegistry::new();

        let expr = parse_expr("owner_id = session_user");
        let classified = classify_expr(&expr, &db, &registry, "docs", PolicyCommand::Select);
        assert!(
            matches!(
                &classified.pattern,
                PatternClass::Unknown(UnclassifiedExpr { .. })
            ),
            "owner_id = session_user should classify as Unknown, got: {:?}",
            classified.pattern
        );
        assert_eq!(
            classified.confidence,
            ConfidenceLevel::D,
            "session_user policies should produce confidence D"
        );
    }

    #[test]
    fn classify_deeply_nested_expression_returns_unknown_d_beyond_depth_limit() {
        let db = docs_db();
        let registry = FunctionRegistry::new();

        // Build an AND chain more than 64 levels deep:
        // `TRUE AND TRUE AND TRUE AND ...` with 66 levels forces depth > 64.
        // The AND handler recurses into each sub-expression; with 66 ANDs the
        // depth counter will exceed MAX_CLASSIFY_DEPTH.
        let inner_sql = "owner_id = current_user";
        // Build a chain of 70 ANDs: `TRUE AND TRUE AND ... AND (owner_id = current_user)`
        let and_chain: String = "TRUE AND ".repeat(70) + inner_sql;

        let expr = parse_expr(&and_chain);
        let classified = classify_expr(&expr, &db, &registry, "docs", PolicyCommand::Select);
        // With 70 levels of AND nesting the leaf expressions are beyond depth 64.
        // The resulting P8Composite or Unknown D is acceptable; what matters is
        // the classifier does not panic or overflow the stack.
        assert!(
            !matches!(
                &classified.pattern,
                PatternClass::P3DirectOwnership(DirectOwnership { .. })
            ),
            "deeply nested expression should not silently classify as P3, got: {:?}",
            classified.pattern
        );
    }

    #[test]
    fn classify_p5_rejects_attribute_only_inner_pattern() {
        let db = parse_schema(
            r"
CREATE TABLE projects(id uuid primary key, status text);
CREATE TABLE tasks(id uuid primary key, project_id uuid references projects(id), status text);
",
        )
        .expect("schema should parse");
        let registry = FunctionRegistry::new();

        // `EXISTS (SELECT 1 FROM projects p WHERE p.id = tasks.project_id AND p.status = 'active')`
        // The inner expression `p.status = 'active'` is a P9 attribute condition, not a
        // user-resource relationship. P5 must not wrap it.
        let expr = parse_expr(
            "EXISTS (SELECT 1 FROM projects p WHERE p.id = tasks.project_id AND p.status = 'active')",
        );
        let classified = classify_expr(&expr, &db, &registry, "tasks", PolicyCommand::Select);

        assert!(
            !matches!(
                &classified.pattern,
                PatternClass::P5ParentInheritance(ParentInheritance { .. })
            ),
            "P5 with attribute-only inner pattern must be rejected, got: {:?}",
            classified.pattern
        );
    }

    #[test]
    fn pattern_short_name_covers_all_variants() {
        let cases: Vec<(PatternClass, &str)> = vec![
            (
                PatternClass::P1NumericThreshold(NumericThreshold {
                    function_name: "f".into(),
                    operator: ThresholdOperator::Gte,
                    threshold: 1,
                    command: PolicyCommand::Select,
                }),
                "numeric role-threshold check",
            ),
            (
                PatternClass::P2RoleNameInList(RoleNameInList {
                    function_name: "f".into(),
                    role_names: vec!["a".into()],
                    privilege: RolePrivilege::Member,
                }),
                "role-name-in-list check",
            ),
            (
                PatternClass::P3DirectOwnership(DirectOwnership {
                    column: ColumnName::from_stored("c"),
                }),
                "direct-ownership check",
            ),
            (
                PatternClass::P4ExistsMembership(ExistsMembership {
                    join_table: "t".into(),
                    fk_column: ColumnName::from_stored("c"),
                    outer_column: ColumnName::from_stored("o"),
                    user_column: ColumnName::from_stored("u"),
                    extra_predicate_sql: None,
                }),
                "EXISTS membership check",
            ),
            (
                PatternClass::P5ParentInheritance(ParentInheritance {
                    parent_table: "p".into(),
                    fk_column: ColumnName::from_stored("c"),
                    inner_pattern: Box::new(ClassifiedExpr {
                        pattern: PatternClass::P3DirectOwnership(DirectOwnership {
                            column: ColumnName::from_stored("c"),
                        }),
                        confidence: ConfidenceLevel::A,
                    }),
                }),
                "parent-inheritance check",
            ),
            (
                PatternClass::P6BooleanFlag(BooleanFlag {
                    column: ColumnName::from_stored("c"),
                }),
                "boolean-flag check",
            ),
            (
                PatternClass::P7AbacAnd(AbacAnd {
                    relationship_part: Box::new(ClassifiedExpr {
                        pattern: PatternClass::P3DirectOwnership(DirectOwnership {
                            column: ColumnName::from_stored("c"),
                        }),
                        confidence: ConfidenceLevel::A,
                    }),
                    attribute_part: "a".into(),
                }),
                "ABAC-and-relationship check",
            ),
            (
                PatternClass::P8Composite(Composite {
                    op: BoolOp::Or,
                    parts: Vec::new(),
                }),
                "composite check",
            ),
            (
                PatternClass::P9AttributeCondition(AttributeCondition {
                    column: ColumnName::from_stored("c"),
                    value_description: "v".into(),
                    predicate: None,
                    request_predicate: None,
                }),
                "attribute-condition check",
            ),
            (
                PatternClass::P10ConstantBool(ConstantBool { value: true }),
                "constant-boolean check",
            ),
            (
                PatternClass::Unknown(UnclassifiedExpr {
                    sql_text: "x".into(),
                    reason: "r".into(),
                }),
                "unrecognized expression",
            ),
        ];
        for (pattern, expected) in cases {
            assert_eq!(
                pattern_short_name(&pattern),
                expected,
                "pattern_short_name mismatch for {pattern:?}"
            );
        }
    }

    #[test]
    fn is_relationship_pattern_for_p7_covers_recursive_arms() {
        let p3 = PatternClass::P3DirectOwnership(DirectOwnership {
            column: ColumnName::from_stored("c"),
        });
        let p3_expr = ClassifiedExpr {
            pattern: p3.clone(),
            confidence: ConfidenceLevel::A,
        };

        // Direct relationship patterns
        assert!(is_relationship_pattern_for_p7(
            &PatternClass::P1NumericThreshold(NumericThreshold {
                function_name: "f".into(),
                operator: ThresholdOperator::Gte,
                threshold: 1,
                command: PolicyCommand::Select,
            })
        ));
        assert!(is_relationship_pattern_for_p7(
            &PatternClass::P2RoleNameInList(RoleNameInList {
                function_name: "f".into(),
                role_names: vec!["a".into()],
                privilege: RolePrivilege::Member,
            })
        ));
        assert!(is_relationship_pattern_for_p7(&p3));
        assert!(is_relationship_pattern_for_p7(
            &PatternClass::P4ExistsMembership(ExistsMembership {
                join_table: "t".into(),
                fk_column: ColumnName::from_stored("c"),
                outer_column: ColumnName::from_stored("o"),
                user_column: ColumnName::from_stored("u"),
                extra_predicate_sql: None,
            })
        ));
        assert!(is_relationship_pattern_for_p7(
            &PatternClass::P5ParentInheritance(ParentInheritance {
                parent_table: "p".into(),
                fk_column: ColumnName::from_stored("c"),
                inner_pattern: Box::new(p3_expr.clone()),
            })
        ));

        // Non-relationship patterns
        assert!(!is_relationship_pattern_for_p7(
            &PatternClass::P6BooleanFlag(BooleanFlag {
                column: ColumnName::from_stored("c")
            })
        ));
        assert!(!is_relationship_pattern_for_p7(
            &PatternClass::P9AttributeCondition(AttributeCondition {
                column: ColumnName::from_stored("c"),
                value_description: "v".into(),
                predicate: None,
                request_predicate: None,
            })
        ));
        assert!(!is_relationship_pattern_for_p7(
            &PatternClass::P10ConstantBool(ConstantBool { value: true })
        ));
        assert!(!is_relationship_pattern_for_p7(&PatternClass::Unknown(
            UnclassifiedExpr {
                sql_text: "x".into(),
                reason: "r".into(),
            }
        )));

        assert!(is_relationship_pattern_for_p7(&PatternClass::P7AbacAnd(
            AbacAnd {
                relationship_part: Box::new(p3_expr.clone()),
                attribute_part: "a".into(),
            }
        )));

        assert!(is_relationship_pattern_for_p7(&PatternClass::P8Composite(
            Composite {
                op: BoolOp::Or,
                parts: vec![
                    p3_expr.clone(),
                    ClassifiedExpr {
                        pattern: PatternClass::P4ExistsMembership(ExistsMembership {
                            join_table: "t".into(),
                            fk_column: ColumnName::from_stored("c"),
                            outer_column: ColumnName::from_stored("o"),
                            user_column: ColumnName::from_stored("u"),
                            extra_predicate_sql: None,
                        }),
                        confidence: ConfidenceLevel::A,
                    },
                ],
            }
        )));

        assert!(!is_relationship_pattern_for_p7(&PatternClass::P8Composite(
            Composite {
                op: BoolOp::Or,
                parts: vec![ClassifiedExpr {
                    pattern: PatternClass::P6BooleanFlag(BooleanFlag {
                        column: ColumnName::from_stored("c")
                    }),
                    confidence: ConfidenceLevel::A,
                }],
            }
        )));

        assert!(!is_relationship_pattern_for_p7(&PatternClass::P8Composite(
            Composite {
                op: BoolOp::Or,
                parts: Vec::new(),
            }
        )));
    }

    #[test]
    fn is_distinct_from_classified_as_p9() {
        let db = docs_db();
        let registry = FunctionRegistry::new();
        let expr = parse_expr("status IS DISTINCT FROM 'deleted'");
        let classified = classify_expr(&expr, &db, &registry, "docs", PolicyCommand::Select);
        assert!(
            matches!(&classified.pattern, PatternClass::P9AttributeCondition(AttributeCondition { column, .. }) if column == "status"),
            "IS DISTINCT FROM should classify as P9, got: {:?}",
            classified.pattern
        );
    }

    #[test]
    fn is_not_distinct_from_classified_as_p9() {
        let db = docs_db();
        let registry = FunctionRegistry::new();
        let expr = parse_expr("status IS NOT DISTINCT FROM 'active'");
        let classified = classify_expr(&expr, &db, &registry, "docs", PolicyCommand::Select);
        assert!(
            matches!(&classified.pattern, PatternClass::P9AttributeCondition(AttributeCondition { column, .. }) if column == "status"),
            "IS NOT DISTINCT FROM should classify as P9, got: {:?}",
            classified.pattern
        );
    }

    #[test]
    fn between_classified_as_p9_attribute_condition() {
        let db = docs_db();
        let registry = FunctionRegistry::new();
        let expr = parse_expr("priority BETWEEN 1 AND 10");
        let classified = classify_expr(&expr, &db, &registry, "docs", PolicyCommand::Select);
        assert!(
            matches!(&classified.pattern, PatternClass::P9AttributeCondition(AttributeCondition { column, .. }) if column == "priority"),
            "BETWEEN should classify as P9, got: {:?}",
            classified.pattern
        );
    }

    #[test]
    fn temporal_comparison_classified_as_p9() {
        let db = docs_db();
        let registry = FunctionRegistry::new();
        let expr = parse_expr("status > now()");
        let classified = classify_expr(&expr, &db, &registry, "docs", PolicyCommand::Select);
        assert!(
            matches!(&classified.pattern, PatternClass::P9AttributeCondition(AttributeCondition { column, .. }) if column == "status"),
            "temporal comparison should classify as P9, got: {:?}",
            classified.pattern
        );
    }

    // ── Gap 7: Row-value comparison decomposition ─────────────────────────

    #[test]
    fn row_value_comparison_decomposed_to_and() {
        let db = parse_schema(
            r"
CREATE TABLE docs (
  id UUID PRIMARY KEY,
  owner_id UUID,
  tenant_id UUID,
  is_public BOOLEAN,
  status TEXT,
  priority INTEGER,
  archived BOOLEAN
);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
",
        )
        .expect("schema should parse");
        let registry = FunctionRegistry::new();

        // (owner_id, status) = (current_user, 'active') should decompose to
        let expr = parse_expr("(owner_id, status) = (current_user, 'active')");
        let classified = classify_expr(&expr, &db, &registry, "docs", PolicyCommand::Select);
        assert!(
            matches!(
                &classified.pattern,
                PatternClass::P7AbacAnd(AbacAnd { attribute_part, .. }) if attribute_part == "status"
            ),
            "Row-value comparison should decompose and classify as P7, got: {:?}",
            classified.pattern
        );
    }

    #[test]
    fn row_value_single_element() {
        let db = docs_db();
        let registry = FunctionRegistry::new();
        let expr = parse_expr("(owner_id) = (current_user)");
        let classified = classify_expr(&expr, &db, &registry, "docs", PolicyCommand::Select);
        assert!(
            matches!(&classified.pattern, PatternClass::P3DirectOwnership(DirectOwnership { column }) if column == "owner_id"),
            "Single-element row-value should decompose to P3, got: {:?}",
            classified.pattern
        );
    }

    #[test]
    fn case_when_true_else_false_normalizes_to_or() {
        let db = docs_db();
        let registry = FunctionRegistry::new();
        let expr = parse_expr(
            "CASE WHEN owner_id = current_user THEN TRUE \
                  WHEN is_public = TRUE THEN TRUE \
                  ELSE FALSE END",
        );
        let classified = classify_expr(&expr, &db, &registry, "docs", PolicyCommand::Select);
        assert!(
            matches!(&classified.pattern, PatternClass::P8Composite(Composite { op: BoolOp::Or, parts }) if parts.len() == 2),
            "CASE with two TRUE branches should become P8 OR, got: {:?}",
            classified.pattern
        );
    }

    #[test]
    fn case_when_single_branch_normalizes_to_inner() {
        let db = docs_db();
        let registry = FunctionRegistry::new();
        let expr = parse_expr("CASE WHEN owner_id = current_user THEN TRUE ELSE FALSE END");
        let classified = classify_expr(&expr, &db, &registry, "docs", PolicyCommand::Select);
        assert!(
            matches!(&classified.pattern, PatternClass::P3DirectOwnership(DirectOwnership { column }) if column == "owner_id"),
            "CASE with one TRUE branch should collapse to inner, got: {:?}",
            classified.pattern
        );
    }

    #[test]
    fn case_when_non_boolean_result_stays_unknown() {
        let db = docs_db();
        let registry = FunctionRegistry::new();
        let expr = parse_expr("CASE WHEN owner_id = current_user THEN 'yes' ELSE 'no' END");
        let classified = classify_expr(&expr, &db, &registry, "docs", PolicyCommand::Select);
        assert!(
            matches!(
                &classified.pattern,
                PatternClass::Unknown(UnclassifiedExpr { .. })
            ),
            "CASE with non-boolean results should stay Unknown, got: {:?}",
            classified.pattern
        );
    }
}

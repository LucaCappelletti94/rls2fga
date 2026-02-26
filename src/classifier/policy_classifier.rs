use sqlparser::ast::{BinaryOperator, Expr, UnaryOperator, Value};

use crate::classifier::function_registry::FunctionRegistry;
use crate::classifier::patterns::*;
use crate::classifier::recognizers;
use crate::parser::function_analyzer::FunctionSemantic;
use crate::parser::sql_parser::{DatabaseLike, ParserDB};

/// Classify all policies in the database.
pub fn classify_policies(db: &ParserDB, registry: &FunctionRegistry) -> Vec<ClassifiedPolicy> {
    classify_policies_with_effective_registry(db, registry).0
}

/// Classify all policies and return the enriched function registry used by the classifier.
pub fn classify_policies_with_effective_registry(
    db: &ParserDB,
    registry: &FunctionRegistry,
) -> (Vec<ClassifiedPolicy>, FunctionRegistry) {
    let mut effective_registry = registry.clone();
    effective_registry.enrich_from_schema(db);

    let classified = classify_policies_with_registry(db, &effective_registry);
    (classified, effective_registry)
}

/// Classify all policies using the provided (already prepared) function registry.
pub fn classify_policies_with_registry(
    db: &ParserDB,
    registry: &FunctionRegistry,
) -> Vec<ClassifiedPolicy> {
    db.policies()
        .map(|policy| {
            let table_name = policy.table_name.to_string();
            let command: PolicyCommand = policy
                .command
                .as_ref()
                .map_or(PolicyCommand::All, |c| PolicyCommand::from(*c));

            let using_classification = policy
                .using
                .as_ref()
                .map(|expr| classify_expr(expr, db, registry, &table_name, &command));

            let with_check_classification = policy
                .with_check
                .as_ref()
                .map(|expr| classify_expr(expr, db, registry, &table_name, &command));

            // PostgreSQL semantics: a bare `CREATE POLICY p ON t` with no
            // USING or WITH CHECK clause defaults to USING (TRUE), granting
            // unrestricted access.  Synthesize P10ConstantBool{true} so the
            // policy is not silently dropped by the confidence filter.
            let using_classification =
                if using_classification.is_none() && with_check_classification.is_none() {
                    Some(ClassifiedExpr {
                        pattern: PatternClass::P10ConstantBool { value: true },
                        confidence: ConfidenceLevel::A,
                    })
                } else {
                    using_classification
                };

            ClassifiedPolicy {
                policy: policy.clone(),
                using_classification,
                with_check_classification,
                using_was_filtered: false,
                with_check_was_filtered: false,
            }
        })
        .collect()
}

/// Maximum recursion depth for `classify_expr`.
///
/// Beyond this depth an expression is classified as `Unknown D` to avoid
/// stack overflows from adversarially-nested SQL.
const MAX_CLASSIFY_DEPTH: u32 = 64;

/// Recursively classify an expression using the pattern decision tree.
pub fn classify_expr(
    expr: &Expr,
    db: &ParserDB,
    registry: &FunctionRegistry,
    table: &str,
    command: &PolicyCommand,
) -> ClassifiedExpr {
    classify_expr_depth(expr, db, registry, table, command, 0)
}

fn classify_expr_depth(
    expr: &Expr,
    db: &ParserDB,
    registry: &FunctionRegistry,
    table: &str,
    command: &PolicyCommand,
    depth: u32,
) -> ClassifiedExpr {
    if depth > MAX_CLASSIFY_DEPTH {
        return ClassifiedExpr {
            pattern: PatternClass::Unknown {
                sql_text: expr.to_string(),
                reason: format!(
                    "Expression exceeds maximum nesting depth ({MAX_CLASSIFY_DEPTH}); \
                     manual review required"
                ),
            },
            confidence: ConfidenceLevel::D,
        };
    }
    classify_expr_inner(expr, db, registry, table, command, depth)
}

fn classify_expr_inner(
    expr: &Expr,
    db: &ParserDB,
    registry: &FunctionRegistry,
    table: &str,
    command: &PolicyCommand,
    depth: u32,
) -> ClassifiedExpr {
    // Handle AND/OR composition first
    if let Expr::BinaryOp { left, op, right } = expr {
        match op {
            BinaryOperator::Or => {
                let left_class = classify_expr_depth(left, db, registry, table, command, depth + 1);
                let right_class =
                    classify_expr_depth(right, db, registry, table, command, depth + 1);

                // Confidence: B if all sub-patterns are A; escalates to highest otherwise
                let min_conf = std::cmp::min(left_class.confidence, right_class.confidence);
                let confidence = if min_conf == ConfidenceLevel::A {
                    ConfidenceLevel::B
                } else {
                    min_conf
                };

                return ClassifiedExpr {
                    pattern: PatternClass::P8Composite {
                        op: BoolOp::Or,
                        parts: vec![left_class, right_class],
                    },
                    confidence,
                };
            }
            BinaryOperator::And => {
                let left_class = classify_expr_depth(left, db, registry, table, command, depth + 1);
                let right_class =
                    classify_expr_depth(right, db, registry, table, command, depth + 1);

                // Check if either branch is an attribute check → P7
                let left_attr = recognizers::is_attribute_check(left);
                let right_attr = recognizers::is_attribute_check(right);

                if let Some(attr) = left_attr {
                    if is_relationship_pattern_for_p7(&right_class.pattern) {
                        return ClassifiedExpr {
                            pattern: PatternClass::P7AbacAnd {
                                relationship_part: Box::new(right_class),
                                attribute_part: attr,
                            },
                            confidence: ConfidenceLevel::C,
                        };
                    }
                }
                if let Some(attr) = right_attr {
                    if is_relationship_pattern_for_p7(&left_class.pattern) {
                        return ClassifiedExpr {
                            pattern: PatternClass::P7AbacAnd {
                                relationship_part: Box::new(left_class),
                                attribute_part: attr,
                            },
                            confidence: ConfidenceLevel::C,
                        };
                    }
                }

                // Both relationship-based → intersection (Level B)
                let min_conf = std::cmp::min(left_class.confidence, right_class.confidence);
                let confidence = if min_conf >= ConfidenceLevel::B {
                    ConfidenceLevel::B
                } else {
                    min_conf
                };

                return ClassifiedExpr {
                    pattern: PatternClass::P8Composite {
                        op: BoolOp::And,
                        parts: vec![left_class, right_class],
                    },
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
        return ClassifiedExpr {
            pattern: PatternClass::Unknown {
                sql_text: expr.to_string(),
                reason: format!(
                    "NOT applied to {desc}; negation cannot be expressed as a static \
                     OpenFGA tuple — consider rewriting as an allowlist policy"
                ),
            },
            confidence: ConfidenceLevel::D,
        };
    }

    // Handle negated structural forms (NOT IN list / NOT EXISTS / NOT IN subquery).
    // Each recognizer already returns None for these, so intercept them here to give
    // a specific diagnostic reason instead of the generic "unknown pattern" fallback.
    if let Expr::InList { negated: true, .. } = expr {
        return ClassifiedExpr {
            pattern: PatternClass::Unknown {
                sql_text: expr.to_string(),
                reason: "NOT IN (...) cannot be represented as static OpenFGA tuples; \
                         negation requires runtime filtering"
                    .to_string(),
            },
            confidence: ConfidenceLevel::D,
        };
    }
    if let Expr::Exists { negated: true, .. } = expr {
        return ClassifiedExpr {
            pattern: PatternClass::Unknown {
                sql_text: expr.to_string(),
                reason: "NOT EXISTS cannot be represented as static OpenFGA membership tuples; \
                         negation requires runtime filtering"
                    .to_string(),
            },
            confidence: ConfidenceLevel::D,
        };
    }
    if let Expr::InSubquery { negated: true, .. } = expr {
        return ClassifiedExpr {
            pattern: PatternClass::Unknown {
                sql_text: expr.to_string(),
                reason: "NOT IN (subquery) cannot be represented as static OpenFGA membership \
                         tuples; negation requires runtime filtering"
                    .to_string(),
            },
            confidence: ConfidenceLevel::D,
        };
    }

    // Try P1: numeric threshold
    if let Some(classified) = recognizers::recognize_p1(expr, db, registry, command) {
        return classified;
    }

    // Try P2: role name IN-list
    if let Some(classified) = recognizers::recognize_p2(expr, db, registry) {
        return classified;
    }

    // Try P3: direct ownership
    if let Some(classified) = recognizers::recognize_p3(expr, db, registry) {
        return classified;
    }

    // Try P5: parent inheritance via correlated EXISTS
    if let Some(classified) = recognizers::recognize_p5(expr, db, registry, table, command) {
        return classified;
    }

    // Try P4: EXISTS membership
    if let Some(classified) = recognizers::recognize_p4(expr, db, registry) {
        return classified;
    }

    // Try P4: IN-subquery membership
    if let Some(classified) = recognizers::recognize_p4_in_subquery(expr, db, registry) {
        return classified;
    }

    if let Some(reason) = recognizers::diagnose_p5_parent_inheritance_ambiguity(expr, db, table) {
        return ClassifiedExpr {
            pattern: PatternClass::Unknown {
                sql_text: expr.to_string(),
                reason,
            },
            confidence: ConfidenceLevel::D,
        };
    }

    if let Some(reason) = recognizers::diagnose_p4_membership_ambiguity(expr, db, registry) {
        return ClassifiedExpr {
            pattern: PatternClass::Unknown {
                sql_text: expr.to_string(),
                reason,
            },
            confidence: ConfidenceLevel::D,
        };
    }

    // Detect negated public-flag: `is_public = FALSE`, `col IS FALSE`, `col IS NOT TRUE`.
    // These fall through P6 because they're not an allowlist — they must not degrade silently
    // to P9 (attribute condition) since they cannot be expressed as static OpenFGA tuples.
    if let Some(col) = recognizers::is_negated_boolean_flag(expr) {
        return ClassifiedExpr {
            pattern: PatternClass::Unknown {
                sql_text: expr.to_string(),
                reason: format!(
                    "Negated boolean-flag check on column '{col}' cannot be expressed as static \
                     OpenFGA tuples; negation requires runtime filtering"
                ),
            },
            confidence: ConfidenceLevel::D,
        };
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

    // Try P9: standalone attribute condition (fallback at confidence C)
    if let Some(col) = recognizers::is_attribute_check(expr) {
        let value_desc = describe_comparison_value(expr);
        return ClassifiedExpr {
            pattern: PatternClass::P9AttributeCondition {
                column: col,
                value_description: value_desc,
            },
            confidence: ConfidenceLevel::C,
        };
    }

    // Check for function call with unknown function → Level D
    if let Some(func_name) = recognizers::extract_function_name(expr) {
        if !registry.is_current_user_accessor(&func_name) {
            let reason = match registry.get(&func_name) {
                Some(FunctionSemantic::Unknown { reason }) => {
                    format!("Function '{func_name}' is registered as Unknown: {reason}")
                }
                None => {
                    format!("Function '{func_name}' not in registry and body not available")
                }
                _ => {
                    format!(
                        "Function '{func_name}' did not match any recognized translation pattern"
                    )
                }
            };
            return ClassifiedExpr {
                pattern: PatternClass::Unknown {
                    sql_text: expr.to_string(),
                    reason,
                },
                confidence: ConfidenceLevel::D,
            };
        }
    }

    // Fallback: Unknown
    ClassifiedExpr {
        pattern: PatternClass::Unknown {
            sql_text: expr.to_string(),
            reason: "Expression does not match any known pattern".to_string(),
        },
        confidence: ConfidenceLevel::D,
    }
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
        PatternClass::P1NumericThreshold { .. } => "numeric role-threshold check",
        PatternClass::P2RoleNameInList { .. } => "role-name-in-list check",
        PatternClass::P3DirectOwnership { .. } => "direct-ownership check",
        PatternClass::P4ExistsMembership { .. } => "EXISTS membership check",
        PatternClass::P5ParentInheritance { .. } => "parent-inheritance check",
        PatternClass::P6BooleanFlag { .. } => "boolean-flag check",
        PatternClass::P7AbacAnd { .. } => "ABAC-and-relationship check",
        PatternClass::P8Composite { .. } => "composite check",
        PatternClass::P9AttributeCondition { .. } => "attribute-condition check",
        PatternClass::P10ConstantBool { .. } => "constant-boolean check",
        PatternClass::Unknown { .. } => "unrecognized expression",
    }
}

fn is_relationship_pattern_for_p7(pattern: &PatternClass) -> bool {
    match pattern {
        PatternClass::P1NumericThreshold { .. }
        | PatternClass::P2RoleNameInList { .. }
        | PatternClass::P3DirectOwnership { .. }
        | PatternClass::P4ExistsMembership { .. }
        | PatternClass::P5ParentInheritance { .. } => true,
        // P6 (boolean public flag) is a resource-attribute check, not a user-resource
        // relationship. Including it here would misclassify e.g.
        // `is_public = TRUE AND status = 'published'` as P7 (ABAC+relationship)
        // when it is really two attribute conditions with no user dimension.
        PatternClass::P7AbacAnd {
            relationship_part, ..
        } => is_relationship_pattern_for_p7(&relationship_part.pattern),
        PatternClass::P8Composite { parts, .. } => {
            !parts.is_empty()
                && parts
                    .iter()
                    .all(|part| is_relationship_pattern_for_p7(&part.pattern))
        }
        PatternClass::P6BooleanFlag { .. }
        | PatternClass::P9AttributeCondition { .. }
        | PatternClass::P10ConstantBool { .. }
        | PatternClass::Unknown { .. } => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::sql_parser::parse_schema;
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

        let classified = classify_expr(&expr, &db, &registry, "docs", &PolicyCommand::Select);

        assert!(matches!(
            &classified.pattern,
            PatternClass::P8Composite {
                op: BoolOp::Or,
                parts
            } if parts.len() == 2
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
            let classified = classify_expr(&expr, &db, &registry, "docs", &PolicyCommand::Select);
            assert!(matches!(
                &classified.pattern,
                PatternClass::P7AbacAnd { attribute_part, .. } if attribute_part == "status"
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
        let classified = classify_expr(&expr, &db, &registry, "docs", &PolicyCommand::Select);
        assert!(
            matches!(
                &classified.pattern,
                PatternClass::P7AbacAnd { attribute_part, .. } if attribute_part == "status"
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

        let classified = classify_expr(&expr, &db, &registry, "docs", &PolicyCommand::Select);

        assert!(matches!(
            &classified.pattern,
            PatternClass::P8Composite {
                op: BoolOp::And,
                parts
            } if parts.len() == 2
        ));
        assert_eq!(classified.confidence, ConfidenceLevel::C);
    }

    #[test]
    fn classify_and_relationships_without_attributes_remains_composite() {
        let db = docs_db();
        let registry = FunctionRegistry::new();
        let expr = parse_expr("owner_id = current_user AND TRUE");

        let classified = classify_expr(&expr, &db, &registry, "docs", &PolicyCommand::Select);

        assert!(matches!(
            &classified.pattern,
            PatternClass::P8Composite {
                op: BoolOp::And,
                parts
            } if parts.len() == 2
        ));
        assert_eq!(classified.confidence, ConfidenceLevel::B);
    }

    #[test]
    fn classify_nested_expression_is_unwrapped() {
        let db = docs_db();
        let registry = FunctionRegistry::new();
        let expr = parse_expr("(owner_id = current_user)");

        let classified = classify_expr(&expr, &db, &registry, "docs", &PolicyCommand::Select);

        assert!(matches!(
            &classified.pattern,
            PatternClass::P3DirectOwnership { column } if column == "owner_id"
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
            let classified = classify_expr(&expr, &db, &registry, "docs", &PolicyCommand::Select);
            assert!(matches!(
                &classified.pattern,
                PatternClass::P9AttributeCondition {
                    column,
                    value_description
                } if column == expected_col && value_description == expected_value
            ));
            assert_eq!(classified.confidence, ConfidenceLevel::C);
        }
    }

    #[test]
    fn classify_unknown_function_has_specific_reason() {
        let db = docs_db();
        let registry = FunctionRegistry::new();
        let expr = parse_expr("mystery_auth(owner_id)");

        let classified = classify_expr(&expr, &db, &registry, "docs", &PolicyCommand::Select);

        assert!(matches!(
            &classified.pattern,
            PatternClass::Unknown { reason, .. } if reason.contains("Function 'mystery_auth' not in registry")
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

        let classified = classify_expr(&expr, &db, &registry, "docs", &PolicyCommand::Select);

        assert!(matches!(
            &classified.pattern,
            PatternClass::Unknown { reason, .. } if reason.contains("Ambiguous membership pattern")
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

        let classified = classify_expr(&expr, &db, &registry, "tasks", &PolicyCommand::Select);

        assert!(matches!(
            &classified.pattern,
            PatternClass::Unknown { reason, .. } if reason.contains("Ambiguous parent inheritance pattern")
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
            let classified = classify_expr(&expr, &db, &registry, "docs", &PolicyCommand::Select);
            assert!(
                matches!(&classified.pattern, PatternClass::Unknown { reason, .. }
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
            let classified = classify_expr(&expr, &db, &registry, "docs", &PolicyCommand::Select);
            assert!(
                matches!(&classified.pattern, PatternClass::Unknown { reason, .. }
                    if reason.contains(expected_fragment)),
                "`{expr_sql}`: expected reason containing '{expected_fragment}', got: {:?}",
                classified.pattern
            );
            assert_eq!(classified.confidence, ConfidenceLevel::D, "`{expr_sql}`");
        }
    }

    #[test]
    fn classify_generic_unknown_expression_has_fallback_reason() {
        let db = docs_db();
        let registry = FunctionRegistry::new();
        let expr = parse_expr("owner_id IS NULL");

        let classified = classify_expr(&expr, &db, &registry, "docs", &PolicyCommand::Select);

        assert!(matches!(
            &classified.pattern,
            PatternClass::Unknown { reason, .. } if reason == "Expression does not match any known pattern"
        ));
        assert_eq!(classified.confidence, ConfidenceLevel::D);
    }

    #[test]
    fn classify_or_and_confidence_can_drop_below_b() {
        let db = docs_db();
        let registry = FunctionRegistry::new();

        let or_expr = parse_expr("mystery_auth(owner_id) OR owner_id = current_user");
        let or_classified = classify_expr(&or_expr, &db, &registry, "docs", &PolicyCommand::Select);
        assert_eq!(or_classified.confidence, ConfidenceLevel::D);

        let and_expr = parse_expr("mystery_auth(owner_id) AND owner_id = current_user");
        let and_classified =
            classify_expr(&and_expr, &db, &registry, "docs", &PolicyCommand::Select);
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
        let classified = classify_expr(&expr, &db, &registry, "docs", &PolicyCommand::Select);

        assert!(matches!(
            &classified.pattern,
            PatternClass::Unknown { reason, .. } if reason == "Expression does not match any known pattern"
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
        let classified = classify_expr(&expr, &db, &registry, "docs", &PolicyCommand::Select);

        assert!(
            matches!(
                &classified.pattern,
                PatternClass::Unknown { reason, .. }
                    if reason.contains("registered as Unknown")
                    && !reason.contains("not in registry")
            ),
            "when a function is in the registry as Unknown, the reason should say so, got: {:?}",
            classified.pattern
        );
        assert_eq!(classified.confidence, ConfidenceLevel::D);
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
            let classified = classify_expr(&expr, &db, &registry, "docs", &PolicyCommand::Select);
            assert!(
                matches!(&classified.pattern, PatternClass::Unknown { reason, .. }
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
        let classified = classify_expr(&expr, &db, &registry, "docs", &PolicyCommand::Select);

        assert!(
            matches!(
                &classified.pattern,
                PatternClass::P8Composite {
                    op: BoolOp::And,
                    ..
                }
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
        let classified = classify_expr(&expr, &db, &registry, "tasks", &PolicyCommand::Select);

        assert!(
            !matches!(&classified.pattern, PatternClass::P3DirectOwnership { .. }),
            "column = column must not classify as P3DirectOwnership, got: {:?}",
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

        // EXISTS with no current-user filter is an "exists any member" check —
        // it does not identify the current user and must not classify as P4.
        let expr = parse_expr("EXISTS (SELECT 1 FROM doc_members WHERE doc_id = docs.id)");
        let classified = classify_expr(&expr, &db, &registry, "docs", &PolicyCommand::Select);

        assert!(
            !matches!(&classified.pattern, PatternClass::P4ExistsMembership { .. }),
            "EXISTS with no user predicate must not classify as P4, got: {:?}",
            classified.pattern
        );
    }

    #[test]
    fn classify_not_true_and_not_false_become_p10() {
        let db = docs_db();
        let registry = FunctionRegistry::new();

        // NOT TRUE → P10ConstantBool{value: false}
        let not_true = parse_expr("NOT TRUE");
        let classified_not_true =
            classify_expr(&not_true, &db, &registry, "docs", &PolicyCommand::Select);
        assert_eq!(
            classified_not_true.pattern,
            PatternClass::P10ConstantBool { value: false },
            "NOT TRUE should classify as P10 constant false"
        );
        assert_eq!(classified_not_true.confidence, ConfidenceLevel::A);

        // NOT FALSE → P10ConstantBool{value: true}
        let not_false = parse_expr("NOT FALSE");
        let classified_not_false =
            classify_expr(&not_false, &db, &registry, "docs", &PolicyCommand::Select);
        assert_eq!(
            classified_not_false.pattern,
            PatternClass::P10ConstantBool { value: true },
            "NOT FALSE should classify as P10 constant true"
        );
        assert_eq!(classified_not_false.confidence, ConfidenceLevel::A);
    }

    #[test]
    fn classify_bare_policy_synthesizes_p10_true() {
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
        assert_eq!(
            policy.using_classification.as_ref().map(|c| &c.pattern),
            Some(&PatternClass::P10ConstantBool { value: true }),
            "bare policy with no USING/WITH CHECK should synthesize P10 true as USING"
        );
        assert_eq!(
            policy.using_classification.as_ref().map(|c| c.confidence),
            Some(ConfidenceLevel::A),
            "synthesized implicit TRUE should have confidence A"
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
        let classified = classify_expr(&expr, &db, &registry, "docs", &PolicyCommand::Select);
        assert!(
            matches!(&classified.pattern, PatternClass::P3DirectOwnership { column }
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
        let classified = classify_expr(&expr, &db, &registry, "docs", &PolicyCommand::Select);
        assert!(
            matches!(&classified.pattern, PatternClass::Unknown { .. }),
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
        let classified = classify_expr(&expr, &db, &registry, "docs", &PolicyCommand::Select);
        // With 70 levels of AND nesting the leaf expressions are beyond depth 64.
        // The resulting P8Composite or Unknown D is acceptable; what matters is
        // the classifier does not panic or overflow the stack.
        assert!(
            !matches!(&classified.pattern, PatternClass::P3DirectOwnership { .. }),
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
        let classified = classify_expr(&expr, &db, &registry, "tasks", &PolicyCommand::Select);

        assert!(
            !matches!(
                &classified.pattern,
                PatternClass::P5ParentInheritance { .. }
            ),
            "P5 with attribute-only inner pattern must be rejected, got: {:?}",
            classified.pattern
        );
    }
}

use sqlparser::ast::{BinaryOperator, Expr, Value};

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

            ClassifiedPolicy {
                policy: policy.clone(),
                using_classification,
                with_check_classification,
            }
        })
        .collect()
}

/// Recursively classify an expression using the pattern decision tree.
#[allow(clippy::only_used_in_recursion)]
pub fn classify_expr(
    expr: &Expr,
    db: &ParserDB,
    registry: &FunctionRegistry,
    table: &str,
    command: &PolicyCommand,
) -> ClassifiedExpr {
    // Handle AND/OR composition first
    if let Expr::BinaryOp { left, op, right } = expr {
        match op {
            BinaryOperator::Or => {
                let left_class = classify_expr(left, db, registry, table, command);
                let right_class = classify_expr(right, db, registry, table, command);

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
                let left_class = classify_expr(left, db, registry, table, command);
                let right_class = classify_expr(right, db, registry, table, command);

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
        return classify_expr(inner, db, registry, table, command);
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

    // Try P6: boolean flag
    if let Some(classified) = recognizers::recognize_p6(expr, db, registry) {
        return classified;
    }

    // Try P10: constant boolean policy
    if let Some(classified) = recognizers::recognize_p10_constant_bool(expr, db, registry) {
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

fn is_relationship_pattern_for_p7(pattern: &PatternClass) -> bool {
    match pattern {
        PatternClass::P1NumericThreshold { .. }
        | PatternClass::P2RoleNameInList { .. }
        | PatternClass::P3DirectOwnership { .. }
        | PatternClass::P4ExistsMembership { .. }
        | PatternClass::P5ParentInheritance { .. }
        | PatternClass::P6BooleanFlag { .. } => true,
        PatternClass::P7AbacAnd {
            relationship_part, ..
        } => is_relationship_pattern_for_p7(&relationship_part.pattern),
        PatternClass::P8Composite { parts, .. } => {
            !parts.is_empty()
                && parts
                    .iter()
                    .all(|part| is_relationship_pattern_for_p7(&part.pattern))
        }
        PatternClass::P9AttributeCondition { .. }
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
}

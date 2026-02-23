use sqlparser::ast::{BinaryOperator, Expr, Value};

use crate::classifier::function_registry::FunctionRegistry;
use crate::classifier::patterns::*;
use crate::classifier::recognizers;
use crate::parser::sql_parser::{DatabaseLike, ParserDB};

/// Classify all policies in the database.
pub fn classify_policies(db: &ParserDB, registry: &FunctionRegistry) -> Vec<ClassifiedPolicy> {
    let mut effective_registry = registry.clone();
    effective_registry.enrich_from_schema(db);

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
                .map(|expr| classify_expr(expr, db, &effective_registry, &table_name, &command));

            let with_check_classification = policy
                .with_check
                .as_ref()
                .map(|expr| classify_expr(expr, db, &effective_registry, &table_name, &command));

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
                    return ClassifiedExpr {
                        pattern: PatternClass::P7AbacAnd {
                            relationship_part: Box::new(right_class),
                            attribute_part: attr,
                        },
                        confidence: ConfidenceLevel::C,
                    };
                }
                if let Some(attr) = right_attr {
                    return ClassifiedExpr {
                        pattern: PatternClass::P7AbacAnd {
                            relationship_part: Box::new(left_class),
                            attribute_part: attr,
                        },
                        confidence: ConfidenceLevel::C,
                    };
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

    // Try P4: EXISTS membership
    if let Some(classified) = recognizers::recognize_p4(expr, db, registry) {
        return classified;
    }

    // Try P4: IN-subquery membership
    if let Some(classified) = recognizers::recognize_p4_in_subquery(expr, db, registry) {
        return classified;
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
            return ClassifiedExpr {
                pattern: PatternClass::Unknown {
                    sql_text: expr.to_string(),
                    reason: format!(
                        "Function '{func_name}' not in registry and body not available"
                    ),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::sql_parser::parse_schema;
    use sqlparser::ast::SetExpr;
    use sqlparser::dialect::PostgreSqlDialect;
    use sqlparser::parser::Parser;

    fn parse_expr(expr_sql: &str) -> Expr {
        let sql = format!("SELECT 1 WHERE {expr_sql}");
        let stmts = Parser::parse_sql(&PostgreSqlDialect {}, &sql).expect("query should parse");
        let stmt = stmts.first().expect("expected one statement");
        let sqlparser::ast::Statement::Query(query) = stmt else {
            panic!("expected query statement");
        };
        let SetExpr::Select(select) = query.body.as_ref() else {
            panic!("expected select set expression");
        };
        select.selection.clone().expect("expected where expression")
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

        match classified.pattern {
            PatternClass::P8Composite { op, parts } => {
                assert_eq!(op, BoolOp::Or);
                assert_eq!(parts.len(), 2);
            }
            other => panic!("expected OR composite, got {other:?}"),
        }
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
            match classified.pattern {
                PatternClass::P7AbacAnd { attribute_part, .. } => {
                    assert_eq!(attribute_part, "status");
                }
                other => panic!("expected P7 ABAC pattern, got {other:?}"),
            }
            assert_eq!(classified.confidence, ConfidenceLevel::C);
        }
    }

    #[test]
    fn classify_and_relationships_without_attributes_remains_composite() {
        let db = docs_db();
        let registry = FunctionRegistry::new();
        let expr = parse_expr("owner_id = current_user AND TRUE");

        let classified = classify_expr(&expr, &db, &registry, "docs", &PolicyCommand::Select);

        match classified.pattern {
            PatternClass::P8Composite { op, parts } => {
                assert_eq!(op, BoolOp::And);
                assert_eq!(parts.len(), 2);
            }
            other => panic!("expected AND composite, got {other:?}"),
        }
        assert_eq!(classified.confidence, ConfidenceLevel::B);
    }

    #[test]
    fn classify_nested_expression_is_unwrapped() {
        let db = docs_db();
        let registry = FunctionRegistry::new();
        let expr = parse_expr("(owner_id = current_user)");

        let classified = classify_expr(&expr, &db, &registry, "docs", &PolicyCommand::Select);

        match classified.pattern {
            PatternClass::P3DirectOwnership { column } => assert_eq!(column, "owner_id"),
            other => panic!("expected ownership pattern, got {other:?}"),
        }
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
            match classified.pattern {
                PatternClass::P9AttributeCondition {
                    column,
                    value_description,
                } => {
                    assert_eq!(column, expected_col);
                    assert_eq!(value_description, expected_value);
                }
                other => panic!("expected P9 attribute pattern, got {other:?}"),
            }
            assert_eq!(classified.confidence, ConfidenceLevel::C);
        }
    }

    #[test]
    fn classify_unknown_function_has_specific_reason() {
        let db = docs_db();
        let registry = FunctionRegistry::new();
        let expr = parse_expr("mystery_auth(owner_id)");

        let classified = classify_expr(&expr, &db, &registry, "docs", &PolicyCommand::Select);

        match classified.pattern {
            PatternClass::Unknown { reason, .. } => {
                assert!(reason.contains("Function 'mystery_auth' not in registry"));
            }
            other => panic!("expected Unknown pattern, got {other:?}"),
        }
        assert_eq!(classified.confidence, ConfidenceLevel::D);
    }

    #[test]
    fn classify_generic_unknown_expression_has_fallback_reason() {
        let db = docs_db();
        let registry = FunctionRegistry::new();
        let expr = parse_expr("owner_id IS NULL");

        let classified = classify_expr(&expr, &db, &registry, "docs", &PolicyCommand::Select);

        match classified.pattern {
            PatternClass::Unknown { reason, .. } => {
                assert_eq!(reason, "Expression does not match any known pattern");
            }
            other => panic!("expected Unknown pattern, got {other:?}"),
        }
        assert_eq!(classified.confidence, ConfidenceLevel::D);
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

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

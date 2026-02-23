use std::fmt::Write;

use crate::classifier::patterns::ClassifiedPolicy;
use crate::generator::model_generator::GeneratedModel;

/// Build a markdown report with confidence table and TODOs.
pub fn build_report(model: &GeneratedModel, policies: &[ClassifiedPolicy]) -> String {
    let mut report = String::new();

    writeln!(report, "# rls2fga Translation Report").unwrap();
    writeln!(report).unwrap();

    // Confidence table
    writeln!(report, "## Confidence Summary").unwrap();
    writeln!(report).unwrap();
    writeln!(report, "| Policy | Pattern | Confidence | Notes |").unwrap();
    writeln!(report, "|--------|---------|------------|-------|").unwrap();

    for cp in policies {
        if let Some(ref c) = cp.using_classification {
            writeln!(
                report,
                "| {} (USING) | {} | {} | {} |",
                cp.name(),
                format_pattern(&c.pattern),
                c.confidence,
                format_notes(&c.pattern)
            )
            .unwrap();
        }
        if let Some(ref c) = cp.with_check_classification {
            writeln!(
                report,
                "| {} (WITH CHECK) | {} | {} | {} |",
                cp.name(),
                format_pattern(&c.pattern),
                c.confidence,
                format_notes(&c.pattern)
            )
            .unwrap();
        }
        if cp.using_classification.is_none() && cp.with_check_classification.is_none() {
            writeln!(report, "| {} | N/A | N/A |  |", cp.name()).unwrap();
        }
    }

    // TODOs
    if !model.todos.is_empty() {
        writeln!(report).unwrap();
        writeln!(report, "## TODOs").unwrap();
        writeln!(report).unwrap();

        for todo in &model.todos {
            writeln!(
                report,
                "- **[Level {}]** {}: {}",
                todo.level, todo.policy_name, todo.message
            )
            .unwrap();
        }
    }

    report
}

fn format_pattern(pattern: &crate::classifier::patterns::PatternClass) -> String {
    use crate::classifier::patterns::PatternClass;
    match pattern {
        PatternClass::P1NumericThreshold {
            operator,
            threshold,
            ..
        } => {
            let op = match operator {
                crate::classifier::patterns::ThresholdOperator::Gte => ">=",
                crate::classifier::patterns::ThresholdOperator::Gt => ">",
            };
            format!("P1 (threshold {op} {threshold})")
        }
        PatternClass::P2RoleNameInList { role_names, .. } => {
            format!("P2 (roles: {})", role_names.join(", "))
        }
        PatternClass::P3DirectOwnership { column } => format!("P3 ({column} = user)"),
        PatternClass::P4ExistsMembership { join_table, .. } => {
            format!("P4 (EXISTS {join_table})")
        }
        PatternClass::P5ParentInheritance { parent_table, .. } => {
            format!("P5 (inherits from {parent_table})")
        }
        PatternClass::P6BooleanFlag { column } => format!("P6 ({column})"),
        PatternClass::P7AbacAnd { attribute_part, .. } => {
            format!("P7 (ABAC: {attribute_part})")
        }
        PatternClass::P8Composite { op, parts } => {
            format!("P8 ({op:?} of {} parts)", parts.len())
        }
        PatternClass::P9AttributeCondition {
            column,
            value_description,
        } => {
            format!("P9 ({column} = {value_description})")
        }
        PatternClass::P10ConstantBool { value } => {
            format!("P10 (constant {value})")
        }
        PatternClass::Unknown { reason, .. } => format!("Unknown: {reason}"),
    }
}

fn format_notes(pattern: &crate::classifier::patterns::PatternClass) -> String {
    use crate::classifier::patterns::PatternClass;
    match pattern {
        PatternClass::P7AbacAnd { attribute_part, .. } => {
            format!("REVIEW: attribute condition on '{attribute_part}'")
        }
        PatternClass::Unknown { reason, .. } => reason.clone(),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classifier::patterns::*;
    use crate::generator::model_generator::TodoItem;
    use crate::parser::sql_parser::{parse_schema, DatabaseLike};

    fn policy_with_name(name: &str) -> sqlparser::ast::CreatePolicy {
        let sql = format!(
            "
CREATE TABLE docs(id uuid primary key);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY {name} ON docs USING (TRUE);
"
        );
        let db = parse_schema(&sql).expect("schema should parse");
        let policy = db.policies().next().expect("expected a policy").clone();
        policy
    }

    fn classified_policy(
        name: &str,
        using: Option<PatternClass>,
        with_check: Option<PatternClass>,
    ) -> ClassifiedPolicy {
        ClassifiedPolicy {
            policy: policy_with_name(name),
            using_classification: using.map(|pattern| ClassifiedExpr {
                pattern,
                confidence: ConfidenceLevel::A,
            }),
            with_check_classification: with_check.map(|pattern| ClassifiedExpr {
                pattern,
                confidence: ConfidenceLevel::C,
            }),
        }
    }

    #[test]
    fn format_pattern_covers_all_variants() {
        let p3 = ClassifiedExpr {
            pattern: PatternClass::P3DirectOwnership {
                column: "owner_id".to_string(),
            },
            confidence: ConfidenceLevel::A,
        };
        let patterns = vec![
            (
                PatternClass::P1NumericThreshold {
                    function_name: "role_level".to_string(),
                    operator: ThresholdOperator::Gte,
                    threshold: 2,
                    command: PolicyCommand::Select,
                },
                "P1 (threshold >= 2)",
            ),
            (
                PatternClass::P2RoleNameInList {
                    function_name: "role_level".to_string(),
                    role_names: vec!["viewer".to_string(), "editor".to_string()],
                },
                "P2 (roles: viewer, editor)",
            ),
            (
                PatternClass::P3DirectOwnership {
                    column: "owner_id".to_string(),
                },
                "P3 (owner_id = user)",
            ),
            (
                PatternClass::P4ExistsMembership {
                    join_table: "doc_members".to_string(),
                    fk_column: "doc_id".to_string(),
                    user_column: "user_id".to_string(),
                    extra_predicate_sql: None,
                },
                "P4 (EXISTS doc_members)",
            ),
            (
                PatternClass::P5ParentInheritance {
                    parent_table: "projects".to_string(),
                    fk_column: "project_id".to_string(),
                    inner_pattern: Box::new(p3.clone()),
                },
                "P5 (inherits from projects)",
            ),
            (
                PatternClass::P6BooleanFlag {
                    column: "is_public".to_string(),
                },
                "P6 (is_public)",
            ),
            (
                PatternClass::P7AbacAnd {
                    relationship_part: Box::new(p3.clone()),
                    attribute_part: "status".to_string(),
                },
                "P7 (ABAC: status)",
            ),
            (
                PatternClass::P8Composite {
                    op: BoolOp::And,
                    parts: vec![p3.clone()],
                },
                "P8 (And of 1 parts)",
            ),
            (
                PatternClass::P9AttributeCondition {
                    column: "status".to_string(),
                    value_description: "'published'".to_string(),
                },
                "P9 (status = 'published')",
            ),
            (
                PatternClass::P10ConstantBool { value: true },
                "P10 (constant true)",
            ),
            (
                PatternClass::Unknown {
                    sql_text: "mystery()".to_string(),
                    reason: "no recognizer".to_string(),
                },
                "Unknown: no recognizer",
            ),
        ];

        for (pattern, expected) in patterns {
            assert_eq!(format_pattern(&pattern), expected);
        }
    }

    #[test]
    fn format_pattern_renders_gt_threshold_operator() {
        let pattern = PatternClass::P1NumericThreshold {
            function_name: "role_level".to_string(),
            operator: ThresholdOperator::Gt,
            threshold: 5,
            command: PolicyCommand::Delete,
        };
        assert_eq!(format_pattern(&pattern), "P1 (threshold > 5)");
    }

    #[test]
    fn format_notes_handles_review_and_unknown_paths() {
        let p3 = ClassifiedExpr {
            pattern: PatternClass::P3DirectOwnership {
                column: "owner_id".to_string(),
            },
            confidence: ConfidenceLevel::A,
        };
        let p7 = PatternClass::P7AbacAnd {
            relationship_part: Box::new(p3),
            attribute_part: "status".to_string(),
        };
        assert_eq!(format_notes(&p7), "REVIEW: attribute condition on 'status'");

        let unknown = PatternClass::Unknown {
            sql_text: "mystery()".to_string(),
            reason: "manual review".to_string(),
        };
        assert_eq!(format_notes(&unknown), "manual review");

        let p6 = PatternClass::P6BooleanFlag {
            column: "is_public".to_string(),
        };
        assert_eq!(format_notes(&p6), "");
    }

    #[test]
    fn build_report_renders_using_with_check_na_and_todos() {
        let model = GeneratedModel {
            dsl: "model".to_string(),
            todos: vec![TodoItem {
                level: ConfidenceLevel::C,
                policy_name: "docs_select".to_string(),
                message: "requires manual review".to_string(),
            }],
            confidence_summary: Vec::new(),
        };

        let policies = vec![
            classified_policy(
                "docs_select",
                Some(PatternClass::P3DirectOwnership {
                    column: "owner_id".to_string(),
                }),
                Some(PatternClass::P9AttributeCondition {
                    column: "status".to_string(),
                    value_description: "'published'".to_string(),
                }),
            ),
            classified_policy("docs_noop", None, None),
        ];

        let report = build_report(&model, &policies);
        assert!(report.contains("docs_select (USING)"));
        assert!(report.contains("docs_select (WITH CHECK)"));
        assert!(report.contains("| docs_noop | N/A | N/A |  |"));
        assert!(report.contains("## TODOs"));
        assert!(report.contains("**[Level C]** docs_select: requires manual review"));
    }
}

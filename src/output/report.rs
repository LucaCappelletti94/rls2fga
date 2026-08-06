#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use core::fmt::Write;

use crate::classifier::patterns::{ClassifiedExpr, ClassifiedPolicy, ConfidenceLevel};
use crate::generator::notes::TranslationNote;

/// Escape a user-controlled string for safe embedding in a Markdown table cell.
///
/// Replaces `|` with `\|`, strips control characters, and collapses newlines
/// so they do not break the table row.
fn md_escape(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() || *c == ' ')
        .collect::<String>()
        .replace('|', r"\|")
}

/// Build a markdown report with the confidence table and the translation's notes.
///
/// `policies` is the unfiltered classification output. Clauses below `min_confidence`
/// are absent from the model and tuples, so the report is the only place their loss is
/// visible.
pub(crate) fn build_report(
    notes: &[TranslationNote],
    policies: &[ClassifiedPolicy],
    min_confidence: ConfidenceLevel,
) -> String {
    let mut report = String::new();

    let _ = writeln!(report, "# rls2fga Translation Report");
    let _ = writeln!(report);

    // Confidence table
    let _ = writeln!(report, "## Confidence Summary");
    let _ = writeln!(report);
    let _ = writeln!(report, "| Policy | Pattern | Confidence | Notes |");
    let _ = writeln!(report, "|--------|---------|------------|-------|");

    for cp in policies {
        let mut wrote_row = false;
        wrote_row |= write_classification_row(
            &mut report,
            cp.name(),
            "USING",
            cp.using_classification.as_ref(),
        );
        wrote_row |= write_classification_row(
            &mut report,
            cp.name(),
            "WITH CHECK",
            cp.with_check_classification.as_ref(),
        );
        if !wrote_row {
            let _ = writeln!(report, "| {} | N/A | N/A |  |", md_escape(cp.name()));
        }
    }

    write_dropped_section(&mut report, policies, min_confidence);

    if !notes.is_empty() {
        let _ = writeln!(report);
        let _ = writeln!(report, "## Notes");
        let _ = writeln!(report);

        for note in notes {
            let _ = writeln!(
                report,
                "- **[{}]** {}: {}",
                note.severity(),
                note.subject(),
                note
            );
        }
    }

    report
}

/// Enumerate the policy clauses excluded from the model and tuple output.
fn write_dropped_section(
    report: &mut String,
    policies: &[ClassifiedPolicy],
    min_confidence: ConfidenceLevel,
) {
    let dropped: Vec<(&ClassifiedPolicy, &str, &ClassifiedExpr)> = policies
        .iter()
        .flat_map(|cp| {
            [
                ("USING", cp.using_classification.as_ref()),
                ("WITH CHECK", cp.with_check_classification.as_ref()),
            ]
            .into_iter()
            .filter_map(move |(label, classification)| {
                classification
                    .filter(|c| c.confidence < min_confidence)
                    .map(|c| (cp, label, c))
            })
        })
        .collect();

    if dropped.is_empty() {
        return;
    }

    let _ = writeln!(report);
    let _ = writeln!(report, "## Dropped Below Confidence {min_confidence}");
    let _ = writeln!(report);
    let _ = writeln!(
        report,
        "Excluded from the model and tuple output. A PERMISSIVE clause grants \
         nothing, so the model is narrower than the policy. A RESTRICTIVE clause \
         becomes `no_access`, since PostgreSQL ANDs it onto every other policy."
    );
    let _ = writeln!(report);

    for (cp, label, classification) in dropped {
        let _ = writeln!(
            report,
            "- `{}` ({label}, {} {}, confidence {}): {}",
            md_escape(cp.name()),
            cp.mode(),
            cp.command(),
            classification.confidence,
            md_escape(&format_pattern(&classification.pattern))
        );
    }
}

fn write_classification_row(
    report: &mut String,
    policy_name: &str,
    clause_label: &str,
    classification: Option<&ClassifiedExpr>,
) -> bool {
    let Some(classification) = classification else {
        return false;
    };
    let _ = writeln!(
        report,
        "| {} ({}) | {} | {} | {} |",
        md_escape(policy_name),
        clause_label,
        md_escape(&format_pattern(&classification.pattern)),
        classification.confidence,
        md_escape(&format_notes(&classification.pattern))
    );
    true
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
        PatternClass::P11ArrayMembership { column } => format!("P11 (user in {column})"),
        PatternClass::P12JsonbFieldOwnership { column, path } => {
            format!("P12 ({column} ->> {} = user)", path.join(" -> "))
        }
        PatternClass::P4ExistsMembership { join_table, .. } => {
            format!("P4 (EXISTS {join_table})")
        }
        PatternClass::P13UncorrelatedMembership { member_table, .. } => {
            format!("P13 (member of {member_table}, any row)")
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
            ..
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
    use crate::parser::sql_parser::{parse_schema, DatabaseLike};

    fn classified_policy(
        name: &str,
        using: Option<PatternClass>,
        with_check: Option<PatternClass>,
    ) -> ClassifiedPolicy {
        let sql = format!(
            "
CREATE TABLE docs(id uuid primary key);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY {name} ON docs USING (TRUE);
"
        );
        let db = parse_schema(&sql).expect("schema should parse");
        let policy = db.policies().next().expect("expected a policy");
        let mut result = ClassifiedPolicy::from_policy(policy, &db);
        result.using_classification = using.map(|pattern| ClassifiedExpr {
            pattern,
            confidence: ConfidenceLevel::A,
        });
        result.with_check_classification = with_check.map(|pattern| ClassifiedExpr {
            pattern,
            confidence: ConfidenceLevel::C,
        });
        result
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
                    predicate: None,
                    request_predicate: None,
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
    fn build_report_renders_using_with_check_na_and_notes() {
        let notes = vec![TranslationNote::RestrictiveAttributeRefused {
            policy: "docs_select".to_string(),
        }];

        let policies = vec![
            classified_policy(
                "docs_select",
                Some(PatternClass::P3DirectOwnership {
                    column: "owner_id".to_string(),
                }),
                Some(PatternClass::P9AttributeCondition {
                    column: "status".to_string(),
                    value_description: "'published'".to_string(),
                    predicate: None,
                    request_predicate: None,
                }),
            ),
            classified_policy("docs_noop", None, None),
        ];

        let report = build_report(&notes, &policies, ConfidenceLevel::D);
        assert!(report.contains("docs_select (USING)"));
        assert!(report.contains("docs_select (WITH CHECK)"));
        assert!(report.contains("| docs_noop | N/A | N/A |  |"));
        assert!(report.contains("## Notes"));
        assert!(report.contains(
            "**[Unhandled]** docs_select: RESTRICTIVE policy 'docs_select' guards on an \
             attribute the model cannot express, so the command is denied"
        ));
    }
}

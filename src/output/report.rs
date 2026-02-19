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
        let pattern_desc = if let Some(ref c) = cp.using_classification {
            format_pattern(&c.pattern)
        } else if let Some(ref c) = cp.with_check_classification {
            format_pattern(&c.pattern)
        } else {
            "N/A".to_string()
        };

        let confidence = if let Some(ref c) = cp.using_classification {
            c.confidence.to_string()
        } else if let Some(ref c) = cp.with_check_classification {
            c.confidence.to_string()
        } else {
            "N/A".to_string()
        };

        let notes = if let Some(ref c) = cp.using_classification {
            format_notes(&c.pattern)
        } else {
            String::new()
        };

        writeln!(
            report,
            "| {} | {} | {} | {} |",
            cp.name(),
            pattern_desc,
            confidence,
            notes
        )
        .unwrap();
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
        PatternClass::P1NumericThreshold { threshold, .. } => {
            format!("P1 (threshold >= {threshold})")
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
        PatternClass::P9AttributeCondition { column, value_description } => {
            format!("P9 ({column} = {value_description})")
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

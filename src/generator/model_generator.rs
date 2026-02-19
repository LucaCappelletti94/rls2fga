use std::collections::HashMap;
use std::fmt::Write;

use crate::classifier::function_registry::FunctionRegistry;
use crate::classifier::patterns::*;
use crate::parser::function_analyzer::FunctionSemantic;
use crate::parser::sql_parser::{DatabaseLike, ParserDB, TableLike};

/// Generated ``OpenFGA`` model output.
#[derive(Debug, Clone)]
pub struct GeneratedModel {
    /// The complete `OpenFGA` DSL text.
    pub dsl: String,
    /// Action items for policies that need manual review.
    pub todos: Vec<TodoItem>,
    /// Per-policy confidence levels for the report.
    pub confidence_summary: Vec<(String, ConfidenceLevel)>,
}

/// An action item generated when a policy cannot be fully translated.
#[derive(Debug, Clone)]
pub struct TodoItem {
    /// Confidence level that triggered this item.
    pub level: ConfidenceLevel,
    /// Name of the policy that needs attention.
    pub policy_name: String,
    /// Human-readable description of what needs manual review.
    pub message: String,
}

/// Generate an ``OpenFGA`` model from classified policies.
pub fn generate_model(
    policies: &[ClassifiedPolicy],
    db: &ParserDB,
    registry: &FunctionRegistry,
    _min_confidence: &ConfidenceLevel,
) -> GeneratedModel {
    let mut dsl = String::new();
    let mut todos = Vec::new();
    let mut confidence_summary = Vec::new();

    // Group policies by table
    let mut by_table: HashMap<String, Vec<&ClassifiedPolicy>> = HashMap::new();
    for cp in policies {
        by_table.entry(cp.table_name()).or_default().push(cp);
    }

    // Detect which features are needed
    let needs_team = detect_team_usage(policies, registry);
    let mut role_threshold_info: Option<&FunctionSemantic> = None;

    // Find the role threshold function info
    for cp in policies {
        if let Some(ClassifiedExpr {
            pattern: PatternClass::P1NumericThreshold { function_name, .. },
            ..
        }) = &cp.using_classification
        {
            role_threshold_info = registry.get(function_name);
            break;
        }
        if let Some(ClassifiedExpr {
            pattern: PatternClass::P1NumericThreshold { function_name, .. },
            ..
        }) = &cp.with_check_classification
        {
            role_threshold_info = registry.get(function_name);
            break;
        }
    }

    // Write header
    writeln!(dsl, "model").unwrap();
    writeln!(dsl, "  schema 1.1").unwrap();

    // Type: user
    writeln!(dsl).unwrap();
    writeln!(dsl, "type user").unwrap();

    // Type: team (if team membership detected)
    if needs_team {
        writeln!(dsl).unwrap();
        writeln!(dsl, "type team").unwrap();
        writeln!(dsl, "  relations").unwrap();
        writeln!(dsl, "    define member: [user]").unwrap();
    }

    // Types for each RLS-enabled table
    let mut sorted_tables: Vec<&String> = by_table.keys().collect();
    sorted_tables.sort();

    for table_name in sorted_tables {
        let table_policies = &by_table[table_name];

        // Check if this table has RLS enabled via sql-traits
        if let Some(table) = db.table(None, table_name) {
            if !table.has_row_level_security(db) {
                continue;
            }
        } else {
            continue;
        }

        // Track confidence for all policies on this table
        for cp in table_policies {
            if let Some(ref c) = cp.using_classification {
                confidence_summary.push((cp.name().to_string(), c.confidence));
            }
            if let Some(ref c) = cp.with_check_classification {
                confidence_summary.push((format!("{} (WITH CHECK)", cp.name()), c.confidence));
            }
        }

        // Determine the primary pattern for this table
        let primary_pattern = determine_primary_pattern(table_policies);

        match primary_pattern {
            PrimaryPattern::RoleThreshold => {
                generate_role_threshold_type(
                    &mut dsl,
                    &mut todos,
                    table_name,
                    table_policies,
                    role_threshold_info,
                    needs_team,
                );
            }
            PrimaryPattern::DirectOwnership { column } => {
                generate_direct_ownership_type(&mut dsl, table_name, &column, table_policies);
            }
            PrimaryPattern::Membership {
                join_table,
                fk_column,
            } => {
                generate_membership_type(
                    &mut dsl,
                    table_name,
                    &join_table,
                    &fk_column,
                    table_policies,
                );
            }
            PrimaryPattern::BooleanFlag { column } => {
                generate_boolean_flag_type(&mut dsl, table_name, &column, table_policies);
            }
            PrimaryPattern::AttributeCondition { column } => {
                generate_attribute_condition_type(
                    &mut dsl,
                    &mut todos,
                    table_name,
                    &column,
                    table_policies,
                );
            }
            PrimaryPattern::Composite {
                op,
                ref sub_patterns,
            } => {
                generate_composite_type(
                    &mut dsl,
                    table_name,
                    &op,
                    sub_patterns,
                    table_policies,
                );
            }
            PrimaryPattern::Unknown => {
                for cp in table_policies {
                    todos.push(TodoItem {
                        level: ConfidenceLevel::D,
                        policy_name: cp.name().to_string(),
                        message: format!(
                            "Policy '{}' could not be classified. Manual translation required.",
                            cp.name()
                        ),
                    });
                }
                writeln!(dsl).unwrap();
                writeln!(dsl, "type {table_name}").unwrap();
                writeln!(
                    dsl,
                    "  # TODO [Level D]: Policies on this table could not be classified"
                )
                .unwrap();
            }
        }
    }

    GeneratedModel {
        dsl,
        todos,
        confidence_summary,
    }
}

pub(crate) enum PrimaryPattern {
    RoleThreshold,
    DirectOwnership {
        column: String,
    },
    Membership {
        join_table: String,
        fk_column: String,
    },
    BooleanFlag {
        column: String,
    },
    AttributeCondition {
        column: String,
    },
    Composite {
        op: BoolOp,
        sub_patterns: Vec<PrimaryPattern>,
    },
    Unknown,
}

pub(crate) fn determine_primary_pattern(policies: &[&ClassifiedPolicy]) -> PrimaryPattern {
    // Check the first classified policy to determine the primary pattern
    for cp in policies {
        let classification = cp
            .using_classification
            .as_ref()
            .or(cp.with_check_classification.as_ref());

        if let Some(c) = classification {
            if let Some(pp) = pattern_class_to_primary(&c.pattern) {
                return pp;
            }
        }
    }
    PrimaryPattern::Unknown
}

fn pattern_class_to_primary(pattern: &PatternClass) -> Option<PrimaryPattern> {
    match pattern {
        PatternClass::P1NumericThreshold { .. } | PatternClass::P2RoleNameInList { .. } => {
            Some(PrimaryPattern::RoleThreshold)
        }
        PatternClass::P3DirectOwnership { column } => Some(PrimaryPattern::DirectOwnership {
            column: column.clone(),
        }),
        PatternClass::P4ExistsMembership {
            join_table,
            fk_column,
            ..
        } => Some(PrimaryPattern::Membership {
            join_table: join_table.clone(),
            fk_column: fk_column.clone(),
        }),
        PatternClass::P6BooleanFlag { column } => Some(PrimaryPattern::BooleanFlag {
            column: column.clone(),
        }),
        PatternClass::P9AttributeCondition { column, .. } => {
            Some(PrimaryPattern::AttributeCondition {
                column: column.clone(),
            })
        }
        PatternClass::P8Composite { op, parts } => {
            let sub_patterns: Vec<PrimaryPattern> =
                parts.iter().filter_map(|p| pattern_class_to_primary(&p.pattern)).collect();
            if sub_patterns.is_empty() {
                None
            } else {
                Some(PrimaryPattern::Composite {
                    op: op.clone(),
                    sub_patterns,
                })
            }
        }
        _ => None,
    }
}

fn generate_role_threshold_type(
    dsl: &mut String,
    _todos: &mut Vec<TodoItem>,
    table_name: &str,
    policies: &[&ClassifiedPolicy],
    _role_info: Option<&FunctionSemantic>,
    needs_team: bool,
) {
    writeln!(dsl).unwrap();
    writeln!(dsl, "type {table_name}").unwrap();
    writeln!(dsl, "  relations").unwrap();

    // Owner relations
    writeln!(dsl, "    define owner_user: [user]").unwrap();
    if needs_team {
        writeln!(dsl, "    define owner_team: [team]").unwrap();
    }

    // Grant relations
    let grant_types = if needs_team { "[user, team]" } else { "[user]" };
    writeln!(dsl, "    define grant_viewer: {grant_types}").unwrap();
    writeln!(dsl, "    define grant_editor: {grant_types}").unwrap();
    writeln!(dsl, "    define grant_admin: {grant_types}").unwrap();

    // Role fan-out
    let admin_def = if needs_team {
        "owner_user or owner_team->member or grant_admin or grant_admin->member"
    } else {
        "owner_user or grant_admin"
    };
    writeln!(dsl, "    define role_admin: {admin_def}").unwrap();

    let editor_def = if needs_team {
        "role_admin or grant_editor or grant_editor->member"
    } else {
        "role_admin or grant_editor"
    };
    writeln!(dsl, "    define role_editor: {editor_def}").unwrap();

    let viewer_def = if needs_team {
        "role_editor or grant_viewer or grant_viewer->member"
    } else {
        "role_editor or grant_viewer"
    };
    writeln!(dsl, "    define role_viewer: {viewer_def}").unwrap();

    // Action permissions from policy thresholds
    let mut action_map: HashMap<String, i32> = HashMap::new();
    for cp in policies {
        if let Some(ClassifiedExpr {
            pattern: PatternClass::P1NumericThreshold { threshold, .. },
            ..
        }) = &cp.using_classification
        {
            let action = command_to_action(&cp.command());
            action_map.insert(action, *threshold);
        }
        if let Some(ClassifiedExpr {
            pattern: PatternClass::P1NumericThreshold { threshold, .. },
            ..
        }) = &cp.with_check_classification
        {
            let action = command_to_action(&cp.command());
            action_map.entry(action).or_insert(*threshold);
        }
    }

    // Sort actions consistently
    let mut actions: Vec<(String, i32)> = action_map.into_iter().collect();
    actions.sort_by_key(|(a, _)| match a.as_str() {
        "can_select" => 0,
        "can_insert" => 1,
        "can_update" => 2,
        "can_delete" => 3,
        _ => 4,
    });

    for (action, threshold) in &actions {
        let role = threshold_to_role(*threshold);
        writeln!(dsl, "    define {action}: {role}").unwrap();
    }
}

fn generate_direct_ownership_type(
    dsl: &mut String,
    table_name: &str,
    _column: &str,
    policies: &[&ClassifiedPolicy],
) {
    writeln!(dsl).unwrap();
    writeln!(dsl, "type {table_name}").unwrap();
    writeln!(dsl, "  relations").unwrap();
    writeln!(dsl, "    define owner: [user]").unwrap();

    // Map all policy commands to permissions
    for cp in policies {
        let action = command_to_action(&cp.command());
        writeln!(dsl, "    define {action}: owner").unwrap();
    }
}

fn generate_membership_type(
    dsl: &mut String,
    table_name: &str,
    _join_table: &str,
    fk_column: &str,
    _policies: &[&ClassifiedPolicy],
) {
    let parent_type = fk_column.strip_suffix("_id").unwrap_or(fk_column);

    writeln!(dsl).unwrap();
    writeln!(dsl, "type {table_name}").unwrap();
    writeln!(dsl, "  relations").unwrap();
    writeln!(dsl, "    define {parent_type}: [{parent_type}]").unwrap();
    writeln!(dsl, "    define can_view: {parent_type}->member").unwrap();
}

fn generate_boolean_flag_type(
    dsl: &mut String,
    table_name: &str,
    _column: &str,
    policies: &[&ClassifiedPolicy],
) {
    writeln!(dsl).unwrap();
    writeln!(dsl, "type {table_name}").unwrap();
    writeln!(dsl, "  relations").unwrap();
    writeln!(dsl, "    define public_viewer: [user:*]").unwrap();

    for cp in policies {
        let action = command_to_action(&cp.command());
        writeln!(dsl, "    define {action}: public_viewer").unwrap();
    }
}

fn generate_attribute_condition_type(
    dsl: &mut String,
    todos: &mut Vec<TodoItem>,
    table_name: &str,
    column: &str,
    policies: &[&ClassifiedPolicy],
) {
    writeln!(dsl).unwrap();
    writeln!(dsl, "type {table_name}").unwrap();
    writeln!(dsl, "  relations").unwrap();
    writeln!(
        dsl,
        "    # TODO [Level C]: Attribute condition on '{column}' — map to a conditional relation"
    )
    .unwrap();
    writeln!(dsl, "    define public_viewer: [user:*]").unwrap();

    for cp in policies {
        let action = command_to_action(&cp.command());
        writeln!(dsl, "    define {action}: public_viewer").unwrap();
    }

    todos.push(TodoItem {
        level: ConfidenceLevel::C,
        policy_name: policies
            .first()
            .map_or("unknown".to_string(), |cp| cp.name().to_string()),
        message: format!(
            "Attribute condition '{column}' requires runtime evaluation. \
             Mapped to public_viewer as placeholder — review needed."
        ),
    });
}

fn generate_composite_type(
    dsl: &mut String,
    table_name: &str,
    op: &BoolOp,
    sub_patterns: &[PrimaryPattern],
    policies: &[&ClassifiedPolicy],
) {
    writeln!(dsl).unwrap();
    writeln!(dsl, "type {table_name}").unwrap();
    writeln!(dsl, "  relations").unwrap();

    // Collect relation names from sub-patterns
    let mut relation_names = Vec::new();

    for sub in sub_patterns {
        match sub {
            PrimaryPattern::DirectOwnership { .. } => {
                writeln!(dsl, "    define owner: [user]").unwrap();
                relation_names.push("owner".to_string());
            }
            PrimaryPattern::BooleanFlag { .. } => {
                writeln!(dsl, "    define public_viewer: [user:*]").unwrap();
                relation_names.push("public_viewer".to_string());
            }
            PrimaryPattern::Membership { fk_column, .. } => {
                let parent_type = fk_column.strip_suffix("_id").unwrap_or(fk_column);
                writeln!(dsl, "    define {parent_type}: [{parent_type}]").unwrap();
                let rel = format!("{parent_type}->member");
                relation_names.push(rel);
            }
            PrimaryPattern::AttributeCondition { column } => {
                writeln!(
                    dsl,
                    "    # TODO [Level C]: Attribute condition on '{column}'"
                )
                .unwrap();
                writeln!(dsl, "    define public_viewer: [user:*]").unwrap();
                relation_names.push("public_viewer".to_string());
            }
            _ => {}
        }
    }

    // Generate action permissions combining relations with the boolean operator
    if !relation_names.is_empty() {
        let joiner = match op {
            BoolOp::Or => " or ",
            BoolOp::And => " and ",
        };
        let combined = relation_names.join(joiner);

        for cp in policies {
            let action = command_to_action(&cp.command());
            writeln!(dsl, "    define {action}: {combined}").unwrap();
        }
    }
}

pub(crate) fn detect_team_usage(
    policies: &[ClassifiedPolicy],
    registry: &FunctionRegistry,
) -> bool {
    for cp in policies {
        for classification in [&cp.using_classification, &cp.with_check_classification] {
            if let Some(ClassifiedExpr {
                pattern: PatternClass::P1NumericThreshold { function_name, .. },
                ..
            }) = classification
            {
                if let Some(FunctionSemantic::RoleThreshold {
                    team_membership_table,
                    ..
                }) = registry.get(function_name)
                {
                    if team_membership_table.is_some() {
                        return true;
                    }
                }
            }
        }
    }
    false
}

pub(crate) fn command_to_action(command: &PolicyCommand) -> String {
    match command {
        PolicyCommand::Select => "can_select".to_string(),
        PolicyCommand::Insert => "can_insert".to_string(),
        PolicyCommand::Update => "can_update".to_string(),
        PolicyCommand::Delete => "can_delete".to_string(),
        PolicyCommand::All => "can_all".to_string(),
    }
}

pub(crate) fn threshold_to_role(threshold: i32) -> &'static str {
    match threshold {
        t if t >= 4 => "role_admin",
        t if t >= 3 => "role_editor",
        _ => "role_viewer",
    }
}

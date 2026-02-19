use std::collections::{BTreeMap, HashMap};

use serde::Serialize;

use crate::classifier::function_registry::FunctionRegistry;
use crate::classifier::patterns::*;
use crate::parser::function_analyzer::FunctionSemantic;
use crate::parser::sql_parser::{DatabaseLike, ParserDB, TableLike};

use super::model_generator::{
    command_to_action, detect_team_usage, determine_primary_pattern, threshold_to_role,
    PrimaryPattern,
};

// ── `OpenFGA` JSON model structs ──────────────────────────────────────

/// Top-level `OpenFGA` authorization model, serializable to the JSON format accepted by the API.
#[derive(Debug, Clone, Serialize)]
pub struct AuthorizationModel {
    /// Schema version string (currently `"1.1"`).
    pub schema_version: String,
    /// Ordered list of type definitions (user, team, resource types).
    pub type_definitions: Vec<TypeDefinition>,
}

/// A single type (e.g. `user`, `team`, or a resource table) with its relations.
#[derive(Debug, Clone, Serialize)]
pub struct TypeDefinition {
    /// Type identifier used in tuple objects and subjects.
    #[serde(rename = "type")]
    pub type_name: String,
    /// Relation name → userset rewrite rule. `None` for types with no relations (e.g. `user`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relations: Option<BTreeMap<String, Userset>>,
    /// Allowed directly-related user types per relation. `None` for computed-only relations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<TypeMetadata>,
}

/// Per-relation metadata declaring which types may be directly assigned.
#[derive(Debug, Clone, Serialize)]
pub struct TypeMetadata {
    /// Relation name → list of allowed assignable types.
    pub relations: BTreeMap<String, RelationMetadata>,
}

/// Allowed directly-related types for a single relation.
#[derive(Debug, Clone, Serialize)]
pub struct RelationMetadata {
    /// Types that may appear as subjects in tuples for this relation.
    pub directly_related_user_types: Vec<RelationReference>,
}

/// Reference to an allowed subject type, optionally as a public wildcard.
#[derive(Debug, Clone, Serialize)]
pub struct RelationReference {
    /// Subject type name (e.g. `"user"`, `"team"`).
    #[serde(rename = "type")]
    pub type_name: String,
    /// If `Some`, this reference represents the public wildcard (`type:*`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wildcard: Option<EmptyObject>,
}

/// Marker struct serialized as `{}` for `OpenFGA`'s `this` and `wildcard` fields.
#[derive(Debug, Clone, Serialize)]
pub struct EmptyObject {}

/// A userset rewrite rule — the core of `OpenFGA`'s relation definitions.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum Userset {
    /// Direct assignment (`this: {}`).
    This {
        /// Marker value serialized as `{}`.
        this: EmptyObject,
    },
    /// Reference to another relation on the same type.
    ComputedUserset {
        /// The relation to compute from.
        #[serde(rename = "computedUserset")]
        computed_userset: ObjectRelation,
    },
    /// Indirection through a tupleset relation to a computed userset on the target.
    TupleToUserset {
        /// The tupleset and computed userset pair.
        #[serde(rename = "tupleToUserset")]
        tuple_to_userset: TupleToUsersetDef,
    },
    /// Union of multiple child usersets (logical OR).
    Union {
        /// Child usersets combined with union semantics.
        union: UnionDef,
    },
}

/// Identifies a single relation by name.
#[derive(Debug, Clone, Serialize)]
pub struct ObjectRelation {
    /// Relation name (e.g. `"owner"`, `"member"`).
    pub relation: String,
}

/// Defines a tuple-to-userset indirection: follow `tupleset` then compute `computed_userset`.
#[derive(Debug, Clone, Serialize)]
pub struct TupleToUsersetDef {
    /// Relation whose tuples provide the intermediate objects.
    pub tupleset: ObjectRelation,
    /// Relation to evaluate on each intermediate object.
    #[serde(rename = "computedUserset")]
    pub computed_userset: ObjectRelation,
}

/// A union of child userset rewrite rules.
#[derive(Debug, Clone, Serialize)]
pub struct UnionDef {
    /// Child usersets — access is granted if any child grants access.
    pub child: Vec<Userset>,
}

// ── Helpers ─────────────────────────────────────────────────────────

fn this() -> Userset {
    Userset::This {
        this: EmptyObject {},
    }
}

fn computed(relation: &str) -> Userset {
    Userset::ComputedUserset {
        computed_userset: ObjectRelation {
            relation: relation.to_string(),
        },
    }
}

fn ttu(tupleset_rel: &str, computed_rel: &str) -> Userset {
    Userset::TupleToUserset {
        tuple_to_userset: TupleToUsersetDef {
            tupleset: ObjectRelation {
                relation: tupleset_rel.to_string(),
            },
            computed_userset: ObjectRelation {
                relation: computed_rel.to_string(),
            },
        },
    }
}

fn union(children: Vec<Userset>) -> Userset {
    Userset::Union {
        union: UnionDef { child: children },
    }
}

fn ref_type(name: &str) -> RelationReference {
    RelationReference {
        type_name: name.to_string(),
        wildcard: None,
    }
}

fn ref_wildcard(name: &str) -> RelationReference {
    RelationReference {
        type_name: name.to_string(),
        wildcard: Some(EmptyObject {}),
    }
}

fn direct_meta(types: &[RelationReference]) -> RelationMetadata {
    RelationMetadata {
        directly_related_user_types: types.to_vec(),
    }
}

// ── Main generation function ────────────────────────────────────────

/// Build a JSON-serializable `AuthorizationModel` from classified RLS policies.
pub fn generate_json_model(
    policies: &[ClassifiedPolicy],
    db: &ParserDB,
    registry: &FunctionRegistry,
    _min_confidence: &ConfidenceLevel,
) -> AuthorizationModel {
    let mut type_definitions = Vec::new();

    let mut by_table: HashMap<String, Vec<&ClassifiedPolicy>> = HashMap::new();
    for cp in policies {
        by_table.entry(cp.table_name()).or_default().push(cp);
    }

    let needs_team = detect_team_usage(policies, registry);

    let mut role_threshold_info: Option<&FunctionSemantic> = None;
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

    // Type: user
    type_definitions.push(TypeDefinition {
        type_name: "user".to_string(),
        relations: None,
        metadata: None,
    });

    // Type: team (if team membership detected)
    if needs_team {
        let mut relations = BTreeMap::new();
        relations.insert("member".to_string(), this());

        let mut meta_relations = BTreeMap::new();
        meta_relations.insert("member".to_string(), direct_meta(&[ref_type("user")]));

        type_definitions.push(TypeDefinition {
            type_name: "team".to_string(),
            relations: Some(relations),
            metadata: Some(TypeMetadata {
                relations: meta_relations,
            }),
        });
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

        let primary_pattern = determine_primary_pattern(table_policies);

        let type_def = match primary_pattern {
            PrimaryPattern::RoleThreshold => build_role_threshold_type(
                table_name,
                table_policies,
                role_threshold_info,
                needs_team,
            ),
            PrimaryPattern::DirectOwnership { column } => {
                build_direct_ownership_type(table_name, &column, table_policies)
            }
            PrimaryPattern::Membership {
                join_table,
                fk_column,
            } => build_membership_type(table_name, &join_table, &fk_column, table_policies),
            PrimaryPattern::BooleanFlag { column } => {
                build_boolean_flag_type(table_name, &column, table_policies)
            }
            PrimaryPattern::AttributeCondition { .. }
            | PrimaryPattern::Composite { .. }
            | PrimaryPattern::Unknown => TypeDefinition {
                type_name: table_name.clone(),
                relations: None,
                metadata: None,
            },
        };

        type_definitions.push(type_def);
    }

    AuthorizationModel {
        schema_version: "1.1".to_string(),
        type_definitions,
    }
}

// ── Per-pattern type builders ───────────────────────────────────────

fn build_role_threshold_type(
    table_name: &str,
    policies: &[&ClassifiedPolicy],
    _role_info: Option<&FunctionSemantic>,
    needs_team: bool,
) -> TypeDefinition {
    let mut relations = BTreeMap::new();
    let mut meta_relations = BTreeMap::new();

    // Owner relations
    relations.insert("owner_user".to_string(), this());
    meta_relations.insert("owner_user".to_string(), direct_meta(&[ref_type("user")]));

    if needs_team {
        relations.insert("owner_team".to_string(), this());
        meta_relations.insert("owner_team".to_string(), direct_meta(&[ref_type("team")]));
    }

    // Grant relations
    let grant_types: Vec<RelationReference> = if needs_team {
        vec![ref_type("user"), ref_type("team")]
    } else {
        vec![ref_type("user")]
    };

    for grant in &["grant_admin", "grant_editor", "grant_viewer"] {
        relations.insert(grant.to_string(), this());
        meta_relations.insert(grant.to_string(), direct_meta(&grant_types));
    }

    // Role fan-out
    let admin_children = if needs_team {
        vec![
            computed("owner_user"),
            ttu("owner_team", "member"),
            computed("grant_admin"),
            ttu("grant_admin", "member"),
        ]
    } else {
        vec![computed("owner_user"), computed("grant_admin")]
    };
    relations.insert("role_admin".to_string(), union(admin_children));

    let editor_children = if needs_team {
        vec![
            computed("role_admin"),
            computed("grant_editor"),
            ttu("grant_editor", "member"),
        ]
    } else {
        vec![computed("role_admin"), computed("grant_editor")]
    };
    relations.insert("role_editor".to_string(), union(editor_children));

    let viewer_children = if needs_team {
        vec![
            computed("role_editor"),
            computed("grant_viewer"),
            ttu("grant_viewer", "member"),
        ]
    } else {
        vec![computed("role_editor"), computed("grant_viewer")]
    };
    relations.insert("role_viewer".to_string(), union(viewer_children));

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
        relations.insert(action.clone(), computed(role));
    }

    TypeDefinition {
        type_name: table_name.to_string(),
        relations: Some(relations),
        metadata: Some(TypeMetadata {
            relations: meta_relations,
        }),
    }
}

fn build_direct_ownership_type(
    table_name: &str,
    _column: &str,
    policies: &[&ClassifiedPolicy],
) -> TypeDefinition {
    let mut relations = BTreeMap::new();
    let mut meta_relations = BTreeMap::new();

    relations.insert("owner".to_string(), this());
    meta_relations.insert("owner".to_string(), direct_meta(&[ref_type("user")]));

    for cp in policies {
        let action = command_to_action(&cp.command());
        relations.insert(action, computed("owner"));
    }

    TypeDefinition {
        type_name: table_name.to_string(),
        relations: Some(relations),
        metadata: Some(TypeMetadata {
            relations: meta_relations,
        }),
    }
}

fn build_membership_type(
    table_name: &str,
    _join_table: &str,
    fk_column: &str,
    _policies: &[&ClassifiedPolicy],
) -> TypeDefinition {
    let parent_type = fk_column.strip_suffix("_id").unwrap_or(fk_column);

    let mut relations = BTreeMap::new();
    let mut meta_relations = BTreeMap::new();

    relations.insert(parent_type.to_string(), this());
    meta_relations.insert(
        parent_type.to_string(),
        direct_meta(&[ref_type(parent_type)]),
    );

    relations.insert("can_view".to_string(), ttu(parent_type, "member"));

    TypeDefinition {
        type_name: table_name.to_string(),
        relations: Some(relations),
        metadata: Some(TypeMetadata {
            relations: meta_relations,
        }),
    }
}

fn build_boolean_flag_type(
    table_name: &str,
    _column: &str,
    policies: &[&ClassifiedPolicy],
) -> TypeDefinition {
    let mut relations = BTreeMap::new();
    let mut meta_relations = BTreeMap::new();

    relations.insert("public_viewer".to_string(), this());
    meta_relations.insert(
        "public_viewer".to_string(),
        direct_meta(&[ref_wildcard("user")]),
    );

    for cp in policies {
        let action = command_to_action(&cp.command());
        relations.insert(action, computed("public_viewer"));
    }

    TypeDefinition {
        type_name: table_name.to_string(),
        relations: Some(relations),
        metadata: Some(TypeMetadata {
            relations: meta_relations,
        }),
    }
}

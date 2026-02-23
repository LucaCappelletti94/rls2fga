use std::collections::BTreeMap;

use serde::Serialize;

use crate::classifier::function_registry::FunctionRegistry;
use crate::classifier::patterns::{ClassifiedPolicy, ConfidenceLevel};
use crate::generator::model_generator::{build_schema_plan, DirectSubject, TypePlan, UsersetExpr};
use crate::parser::sql_parser::ParserDB;

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
    /// Intersection of multiple child usersets (logical AND).
    Intersection {
        /// Child usersets combined with intersection semantics.
        intersection: IntersectionDef,
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

/// An intersection of child userset rewrite rules.
#[derive(Debug, Clone, Serialize)]
pub struct IntersectionDef {
    /// Child usersets — access is granted only if all children grant access.
    pub child: Vec<Userset>,
}

/// Build a JSON-serializable `AuthorizationModel` from classified RLS policies.
pub fn generate_json_model(
    policies: &[ClassifiedPolicy],
    db: &ParserDB,
    registry: &FunctionRegistry,
    min_confidence: &ConfidenceLevel,
) -> AuthorizationModel {
    let filtered = filter_policies_for_output(policies, *min_confidence);
    let plan = build_schema_plan(&filtered, db, registry);

    let type_definitions = plan
        .types
        .into_iter()
        .map(type_plan_to_definition)
        .collect();

    AuthorizationModel {
        schema_version: "1.1".to_string(),
        type_definitions,
    }
}

fn filter_policies_for_output(
    policies: &[ClassifiedPolicy],
    min_confidence: ConfidenceLevel,
) -> Vec<ClassifiedPolicy> {
    policies
        .iter()
        .filter_map(|cp| {
            let mut filtered = cp.clone();
            filtered.using_classification = cp
                .using_classification
                .as_ref()
                .filter(|c| c.confidence >= min_confidence)
                .cloned();
            filtered.with_check_classification = cp
                .with_check_classification
                .as_ref()
                .filter(|c| c.confidence >= min_confidence)
                .cloned();

            if filtered.using_classification.is_some()
                || filtered.with_check_classification.is_some()
            {
                Some(filtered)
            } else {
                None
            }
        })
        .collect()
}

fn type_plan_to_definition(plan: TypePlan) -> TypeDefinition {
    if plan.direct_relations.is_empty() && plan.computed_relations.is_empty() {
        return TypeDefinition {
            type_name: plan.type_name,
            relations: None,
            metadata: None,
        };
    }

    let mut relations = BTreeMap::new();
    let mut meta_relations = BTreeMap::new();

    for (name, subjects) in plan.direct_relations {
        relations.insert(
            name.clone(),
            Userset::This {
                this: EmptyObject {},
            },
        );

        let refs = subjects
            .into_iter()
            .map(|subject| match subject {
                DirectSubject::Type(t) => RelationReference {
                    type_name: t,
                    wildcard: None,
                },
                DirectSubject::Wildcard(t) => RelationReference {
                    type_name: t,
                    wildcard: Some(EmptyObject {}),
                },
            })
            .collect::<Vec<_>>();

        meta_relations.insert(
            name,
            RelationMetadata {
                directly_related_user_types: refs,
            },
        );
    }

    for (name, expr) in plan.computed_relations {
        relations.insert(name, expr_to_userset(&expr));
    }

    TypeDefinition {
        type_name: plan.type_name,
        relations: Some(relations),
        metadata: Some(TypeMetadata {
            relations: meta_relations,
        }),
    }
}

fn expr_to_userset(expr: &UsersetExpr) -> Userset {
    match expr {
        UsersetExpr::Computed(relation) => Userset::ComputedUserset {
            computed_userset: ObjectRelation {
                relation: relation.clone(),
            },
        },
        UsersetExpr::TupleToUserset { tupleset, computed } => Userset::TupleToUserset {
            tuple_to_userset: TupleToUsersetDef {
                tupleset: ObjectRelation {
                    relation: tupleset.clone(),
                },
                computed_userset: ObjectRelation {
                    relation: computed.clone(),
                },
            },
        },
        UsersetExpr::Union(children) => Userset::Union {
            union: UnionDef {
                child: children.iter().map(expr_to_userset).collect(),
            },
        },
        UsersetExpr::Intersection(children) => Userset::Intersection {
            intersection: IntersectionDef {
                child: children.iter().map(expr_to_userset).collect(),
            },
        },
    }
}

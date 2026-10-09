//! The `validate.rules` bounds the written model must satisfy, checked against the
//! JSON model the client writes.
//!
//! `OpenFGA` refuses a model that crosses one of these bounds at the write call, too
//! late. The check runs while the plan is built, so `PlanningError::ModelBoundExceeded`
//! names the bound before the model leaves.
//!
//! Server-configurable limits are not errors. The type count and the encoded size stay
//! on the outputs for a consumer to compare with its server.

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;

use crate::generator::model_generator::PlanningError;
use alloc::collections::BTreeMap;
use core::fmt;

use crate::generator::json_model::{
    AuthorizationModel, Condition, RelationReference, TypeDefinition, Userset,
};
use crate::types::{ConditionName, RelationName};

/// The number of pairs `AuthorizationModel.conditions` and
/// `WriteAuthorizationModelRequest.conditions` admit.
const MAX_CONDITIONS: usize = 25;

/// The number of pairs `Condition.parameters` admits.
const MAX_CONDITION_PARAMETERS: usize = 25;

/// The number of bytes a `Condition.expression` may carry.
const MAX_CONDITION_EXPRESSION_BYTES: usize = 512;

/// The number of characters a `TypeDefinition.type` or `RelationReference.type`
/// may carry.
const MAX_TYPE_NAME_CHARS: usize = 254;

/// The number of characters a relation, condition or parameter name may carry.
const MAX_NAME_CHARS: usize = 50;

/// The number of bytes an `ObjectRelation.relation` or `ComputedUserset.relation`
/// may carry.
const MAX_RELATION_NAME_BYTES: usize = 50;

/// A `validate.rules` bound in `openfga/api` the written model must satisfy, read
/// from `openfga/v1/authzmodel.proto` and `openfga/v1/openfga_service.proto`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelBound {
    /// `TypeDefinition.type`, one to 254 characters.
    TypeName,
    /// A `TypeDefinition.relations` key, one to 50 characters.
    RelationKey,
    /// A `RelationReference.type`, one to 254 characters.
    ReferenceType,
    /// A `RelationReference.condition`, one to 50 characters.
    ReferenceCondition,
    /// An `ObjectRelation.relation` or `ComputedUserset.relation`, at most 50 bytes.
    UsersetRelation,
    /// `AuthorizationModel.conditions`, at most 25 pairs.
    Conditions,
    /// A `Condition.name`, one to 50 characters.
    ConditionName,
    /// A `Condition.expression`, at most 512 bytes.
    ConditionExpression,
    /// `Condition.parameters`, at most 25 pairs.
    ConditionParameters,
    /// A `Condition.parameters` key, one to 50 characters.
    ConditionParameterKey,
}

impl fmt::Display for ModelBound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TypeName => "type name length",
            Self::RelationKey => "relation name length",
            Self::ReferenceType => "reference type name length",
            Self::ReferenceCondition => "reference condition name length",
            Self::UsersetRelation => "userset relation name length",
            Self::Conditions => "condition count",
            Self::ConditionName => "condition name length",
            Self::ConditionExpression => "condition expression size",
            Self::ConditionParameters => "condition parameter count",
            Self::ConditionParameterKey => "condition parameter name length",
        })
    }
}

/// Check `model` against the bounds the `WriteAuthorizationModel` call enforces,
/// which `openfga/api` spells as `validate.rules` in `openfga/v1/authzmodel.proto`
/// and `openfga/v1/openfga_service.proto`.
///
/// # Errors
///
/// Returns the first bound the model crosses.
pub fn check(model: &AuthorizationModel) -> Result<(), PlanningError> {
    for definition in &model.type_definitions {
        check_type_definition(definition)?;
    }
    if let Some(conditions) = &model.conditions {
        check_conditions(conditions)
    } else {
        Ok(())
    }
}

fn check_type_definition(definition: &TypeDefinition) -> Result<(), PlanningError> {
    check_name(
        definition.type_name.as_str(),
        ModelBound::TypeName,
        MAX_TYPE_NAME_CHARS,
    )?;
    if let Some(relations) = &definition.relations {
        for (name, userset) in relations {
            check_relation_name(name.as_str(), ModelBound::RelationKey)?;
            check_userset(userset)?;
        }
    }
    if let Some(metadata) = &definition.metadata {
        for relation in metadata.relations.values() {
            for reference in &relation.directly_related_user_types {
                check_reference(reference)?;
            }
        }
    }
    Ok(())
}

fn check_reference(reference: &RelationReference) -> Result<(), PlanningError> {
    check_name(
        reference.type_name.as_str(),
        ModelBound::ReferenceType,
        MAX_TYPE_NAME_CHARS,
    )?;
    if let Some(condition) = &reference.condition {
        check_name(
            condition.as_str(),
            ModelBound::ReferenceCondition,
            MAX_NAME_CHARS,
        )?;
    }
    Ok(())
}

fn check_userset(userset: &Userset) -> Result<(), PlanningError> {
    match userset {
        Userset::This { .. } => Ok(()),
        Userset::ComputedUserset { computed_userset } => {
            check_userset_relation(&computed_userset.relation)
        }
        Userset::TupleToUserset { tuple_to_userset } => {
            check_userset_relation(&tuple_to_userset.tupleset.relation)?;
            check_userset_relation(&tuple_to_userset.computed_userset.relation)
        }
        Userset::Union { union } => union.child.iter().try_for_each(check_userset),
        Userset::Intersection { intersection } => {
            intersection.child.iter().try_for_each(check_userset)
        }
        Userset::Difference { difference } => {
            check_userset(&difference.base)?;
            check_userset(&difference.subtract)
        }
    }
}

fn check_userset_relation(relation: &RelationName) -> Result<(), PlanningError> {
    check_relation_name(relation.as_str(), ModelBound::UsersetRelation)
}

fn check_relation_name(name: &str, bound: ModelBound) -> Result<(), PlanningError> {
    if !name_within_pattern(name, MAX_NAME_CHARS) {
        return Err(bound_error(
            bound,
            name.chars().count(),
            MAX_NAME_CHARS,
            name,
        ));
    }
    if name.len() > MAX_RELATION_NAME_BYTES {
        return Err(bound_error(
            bound,
            name.len(),
            MAX_RELATION_NAME_BYTES,
            name,
        ));
    }
    Ok(())
}

fn check_name(name: &str, bound: ModelBound, max_chars: usize) -> Result<(), PlanningError> {
    if name_within_pattern(name, max_chars) {
        Ok(())
    } else {
        Err(bound_error(bound, name.chars().count(), max_chars, name))
    }
}

fn check_conditions(conditions: &BTreeMap<ConditionName, Condition>) -> Result<(), PlanningError> {
    if conditions.len() > MAX_CONDITIONS {
        return Err(PlanningError::ModelBoundExceeded {
            bound: ModelBound::Conditions,
            measured: conditions.len(),
            limit: MAX_CONDITIONS,
            item: conditions
                .keys()
                .nth(MAX_CONDITIONS)
                .map_or_else(String::new, ToString::to_string),
        });
    }
    for (name, condition) in conditions {
        check_name(name.as_str(), ModelBound::ConditionName, MAX_NAME_CHARS)?;
        check_condition(condition)?;
    }
    Ok(())
}

fn check_condition(condition: &Condition) -> Result<(), PlanningError> {
    let name = condition.name.as_str();
    if condition.expression.len() > MAX_CONDITION_EXPRESSION_BYTES {
        return Err(PlanningError::ModelBoundExceeded {
            bound: ModelBound::ConditionExpression,
            measured: condition.expression.len(),
            limit: MAX_CONDITION_EXPRESSION_BYTES,
            item: name.to_string(),
        });
    }
    if condition.parameters.len() > MAX_CONDITION_PARAMETERS {
        return Err(PlanningError::ModelBoundExceeded {
            bound: ModelBound::ConditionParameters,
            measured: condition.parameters.len(),
            limit: MAX_CONDITION_PARAMETERS,
            item: name.to_string(),
        });
    }
    for parameter in condition.parameters.keys() {
        check_name(parameter, ModelBound::ConditionParameterKey, MAX_NAME_CHARS)?;
    }
    Ok(())
}

/// The `OpenFGA` name pattern `^[^:#@\s]{1, $max_chars}$`, counted in characters.
fn name_within_pattern(name: &str, max_chars: usize) -> bool {
    !name.is_empty()
        && name.chars().count() <= max_chars
        && !name
            .chars()
            .any(|ch| ch.is_whitespace() || matches!(ch, ':' | '#' | '@'))
}

fn bound_error(bound: ModelBound, measured: usize, limit: usize, item: &str) -> PlanningError {
    PlanningError::ModelBoundExceeded {
        bound,
        measured,
        limit,
        item: item.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;

    use crate::generator::json_model::{
        AuthorizationModel, Condition, ConditionParamType, EmptyObject, RelationMetadata,
        RelationReference, TypeDefinition, TypeMetadata,
    };
    use crate::types::{ConditionName, RelationName, TypeName};

    /// One type with one direct relation and no conditions.
    fn base_model() -> AuthorizationModel {
        AuthorizationModel {
            schema_version: "1.1".to_string(),
            type_definitions: vec![TypeDefinition {
                type_name: TypeName::canonicalized("docs"),
                relations: Some(BTreeMap::from([(
                    RelationName::canonicalized("can_select"),
                    Userset::This {
                        this: EmptyObject {},
                    },
                )])),
                metadata: None,
            }],
            conditions: None,
        }
    }

    fn condition_with(
        expression: &str,
        parameters: BTreeMap<String, ConditionParamType>,
    ) -> Condition {
        let name = ConditionName::canonicalized("when_docs");
        Condition {
            name,
            expression: expression.to_string(),
            parameters,
        }
    }

    fn one_parameter(key: &str) -> BTreeMap<String, ConditionParamType> {
        BTreeMap::from([(
            key.to_string(),
            ConditionParamType {
                parameter_type: "TYPE_NAME_STRING".to_string(),
                generic_types: None,
            },
        )])
    }

    #[test]
    fn a_model_at_the_bounds_passes() {
        let mut model = base_model();
        model.conditions = Some(BTreeMap::from([(
            ConditionName::canonicalized("when_docs"),
            condition_with(
                "docs.expires_at > request_time - duration(\"720h\")",
                one_parameter("expires_at"),
            ),
        )]));
        check(&model).expect("every bound is met");
    }

    #[test]
    fn an_expression_over_five_hundred_twelve_bytes_refuses() {
        let mut model = base_model();
        model.conditions = Some(BTreeMap::from([(
            ConditionName::canonicalized("when_docs"),
            condition_with(&"e".repeat(513), BTreeMap::new()),
        )]));
        let error = check(&model).expect_err("the expression bound is crossed");
        let PlanningError::ModelBoundExceeded {
            bound,
            measured,
            limit,
            item,
        } = error
        else {
            panic!("the crossed bound must name itself: {error:?}");
        };
        assert!(
            matches!(bound, ModelBound::ConditionExpression),
            "got {bound:?}"
        );
        assert_eq!(measured, 513);
        assert_eq!(limit, 512);
        assert_eq!(item, "when_docs");
    }

    #[test]
    fn an_expression_at_five_hundred_twelve_bytes_passes() {
        let mut model = base_model();
        model.conditions = Some(BTreeMap::from([(
            ConditionName::canonicalized("when_docs"),
            condition_with(&"e".repeat(512), BTreeMap::new()),
        )]));
        check(&model).expect("the bound is not crossed");
    }

    #[test]
    fn twenty_six_conditions_refuse() {
        let mut model = base_model();
        let mut conditions = BTreeMap::new();
        for index in 0..26 {
            let name = ConditionName::canonicalized(format!("when_{index}"));
            conditions.insert(
                name.clone(),
                Condition {
                    name,
                    expression: "docs.expires_at > request_time".to_string(),
                    parameters: BTreeMap::new(),
                },
            );
        }
        model.conditions = Some(conditions);
        let error = check(&model).expect_err("the condition count bound is crossed");
        let PlanningError::ModelBoundExceeded {
            bound,
            measured,
            limit,
            item,
        } = error
        else {
            panic!("the crossed bound must name itself: {error:?}");
        };
        assert!(matches!(bound, ModelBound::Conditions), "got {bound:?}");
        assert_eq!(measured, 26);
        assert_eq!(limit, 25);
        assert!(!item.is_empty(), "the item must name a condition");
    }

    #[test]
    fn twenty_five_conditions_pass() {
        let mut model = base_model();
        let mut conditions = BTreeMap::new();
        for index in 0..25 {
            let name = ConditionName::canonicalized(format!("when_{index}"));
            conditions.insert(
                name.clone(),
                Condition {
                    name,
                    expression: "docs.expires_at > request_time".to_string(),
                    parameters: BTreeMap::new(),
                },
            );
        }
        model.conditions = Some(conditions);
        check(&model).expect("the bound is not crossed");
    }

    #[test]
    fn twenty_six_condition_parameters_refuse() {
        let mut parameters = BTreeMap::new();
        for index in 0..26 {
            parameters.insert(
                format!("p{index}"),
                ConditionParamType {
                    parameter_type: "TYPE_NAME_STRING".to_string(),
                    generic_types: None,
                },
            );
        }
        let mut model = base_model();
        model.conditions = Some(BTreeMap::from([(
            ConditionName::canonicalized("when_docs"),
            condition_with("docs.expires_at > request_time", parameters),
        )]));
        let error = check(&model).expect_err("the parameter count bound is crossed");
        let PlanningError::ModelBoundExceeded {
            bound,
            measured,
            limit,
            item,
        } = error
        else {
            panic!("the crossed bound must name itself: {error:?}");
        };
        assert!(
            matches!(bound, ModelBound::ConditionParameters),
            "got {bound:?}"
        );
        assert_eq!(measured, 26);
        assert_eq!(limit, 25);
        assert_eq!(item, "when_docs");
    }

    #[test]
    fn a_parameter_name_over_fifty_characters_refuses() {
        let mut model = base_model();
        model.conditions = Some(BTreeMap::from([(
            ConditionName::canonicalized("when_docs"),
            condition_with(
                "docs.expires_at > request_time",
                one_parameter(&"p".repeat(51)),
            ),
        )]));
        let error = check(&model).expect_err("the parameter name bound is crossed");
        let PlanningError::ModelBoundExceeded {
            bound,
            measured,
            limit,
            ..
        } = error
        else {
            panic!("the crossed bound must name itself: {error:?}");
        };
        assert!(
            matches!(bound, ModelBound::ConditionParameterKey),
            "got {bound:?}"
        );
        assert_eq!(measured, 51);
        assert_eq!(limit, 50);
    }

    #[test]
    fn a_type_name_over_two_hundred_fifty_four_characters_refuses() {
        let mut model = base_model();
        model.type_definitions[0].type_name =
            TypeName::try_from("a".repeat(255)).expect("the name is otherwise valid");
        let error = check(&model).expect_err("the type name bound is crossed");
        let PlanningError::ModelBoundExceeded {
            bound,
            measured,
            limit,
            item,
        } = error
        else {
            panic!("the crossed bound must name itself: {error:?}");
        };
        assert!(matches!(bound, ModelBound::TypeName), "got {bound:?}");
        assert_eq!(measured, 255);
        assert_eq!(limit, 254);
        assert_eq!(item, "a".repeat(255));
    }

    #[test]
    fn a_reference_type_over_two_hundred_fifty_four_characters_refuses() {
        let mut model = base_model();
        model.type_definitions[0].metadata = Some(TypeMetadata {
            relations: BTreeMap::from([(
                RelationName::canonicalized("can_select"),
                RelationMetadata {
                    directly_related_user_types: vec![RelationReference {
                        type_name: TypeName::try_from("a".repeat(255))
                            .expect("the name is otherwise valid"),
                        wildcard: None,
                        condition: None,
                    }],
                },
            )]),
        });
        let error = check(&model).expect_err("the reference type bound is crossed");
        let PlanningError::ModelBoundExceeded {
            bound,
            measured,
            limit,
            ..
        } = error
        else {
            panic!("the crossed bound must name itself: {error:?}");
        };
        assert!(matches!(bound, ModelBound::ReferenceType), "got {bound:?}");
        assert_eq!(measured, 255);
        assert_eq!(limit, 254);
    }
}

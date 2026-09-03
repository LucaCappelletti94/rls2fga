//! Each relation of the emitted model, the shapes whose records fill it, and how one
//! row decides them.
//!
//! A consumer watching a change stream wants to answer the cheapest questions with
//! no round trip, by testing the changed row's records against its own subscriber
//! list. That is correct only for some relations, and being wrong in the permissive
//! direction is a wrong allow, so the analysis refuses to guess: anything it cannot
//! judge is reported as not decidable.
//!
//! The flag and the recipe leave one traversal. Derived apart they could disagree,
//! which is the divergence this surface exists to remove.

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use crate::types::{
    RecordDerivation, RecordDescription, RelationName, RelationShapes, RequestComparison,
    RowDecision, ValueSource,
};
use alloc::collections::{BTreeMap, BTreeSet};

use crate::generator::db_lookup::resolve_row_identity;
use crate::generator::ir::TupleSource;
use crate::generator::model_generator::{
    relation_grants_nothing, SchemaPlan, TypePlan, UsersetExpr,
};
use crate::generator::tuple_generator::{rendered_source_key, RenderedSourceKey};
use crate::generator::well_known::WellKnownTypes;
use crate::parser::sql_parser::DatabaseLike;

/// Report every relation of the emitted model.
pub(crate) fn relation_shapes<'plan, DB: DatabaseLike>(
    plan: &'plan SchemaPlan,
    descriptions: &BTreeMap<RenderedSourceKey<'plan>, Option<RecordDescription>>,
    db: &DB,
) -> Vec<RelationShapes> {
    let sources = index_sources(plan, descriptions);

    let mut out = Vec::new();
    for type_plan in &plan.types {
        let mut names: BTreeSet<&RelationName> = BTreeSet::new();
        names.extend(type_plan.direct_relations.keys());
        names.extend(type_plan.computed_relations.keys());
        for relation in names {
            let mut visiting = BTreeSet::new();
            let decision = relation_decision(
                type_plan.type_name.as_str(),
                relation,
                plan,
                &sources,
                db,
                &mut visiting,
            );
            out.push(RelationShapes {
                type_name: type_plan.type_name.clone(),
                relation: relation.clone(),
                from_one_row: decision.is_some(),
                shapes: shapes_filling(type_plan.type_name.as_str(), relation, &sources),
                decision,
                grants_nobody: relation_grants_nothing(type_plan, relation),
            });
        }
    }
    out
}

fn index_sources<'plan, 'description>(
    plan: &'plan SchemaPlan,
    descriptions: &'description BTreeMap<RenderedSourceKey<'plan>, Option<RecordDescription>>,
) -> SourceIndex<'plan, 'description> {
    let mut index: SourceIndex<'plan, 'description> = BTreeMap::new();
    for type_plan in &plan.types {
        for source in &type_plan.table_tuple_sources {
            let key = rendered_source_key(
                source,
                type_plan.type_name.as_str(),
                type_plan.reads_only_its_own_rows,
            );
            let description = descriptions.get(&key).and_then(Option::as_ref);
            for target in source.feeds(&type_plan.type_name, &plan.well_known) {
                index.entry(target).or_default().push(IndexedSource {
                    source,
                    description,
                });
            }
        }
    }
    index
}

#[derive(Clone, Copy)]
struct IndexedSource<'plan, 'description> {
    source: &'plan TupleSource,
    description: Option<&'description RecordDescription>,
}

type SourceIndex<'plan, 'description> =
    BTreeMap<(String, RelationName), Vec<IndexedSource<'plan, 'description>>>;

/// One shape per source. A source feeding the same relation from two type plans
/// describes it twice, and the key the renderer deduplicates queries on is what
/// says the two are the same. Scoping it by owner type would add nothing: a source
/// keying its objects on the owning type only ever reaches the bucket named after
/// that type.
fn shapes_filling(
    type_name: &str,
    relation: &RelationName,
    sources: &SourceIndex<'_, '_>,
) -> Vec<RecordDescription> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for indexed in sources
        .get(&(type_name.to_string(), relation.clone()))
        .into_iter()
        .flatten()
    {
        if !seen.insert(indexed.source.dedup_key()) {
            continue;
        }
        if let Some(description) = indexed.description {
            out.push(description.clone());
        }
    }
    out
}

fn find_type<'plan>(plan: &'plan SchemaPlan, type_name: &str) -> Option<&'plan TypePlan> {
    plan.types
        .iter()
        .find(|candidate| candidate.type_name.as_str() == type_name)
}

fn relation_decision<DB: DatabaseLike>(
    type_name: &str,
    relation: &RelationName,
    plan: &SchemaPlan,
    sources: &SourceIndex<'_, '_>,
    db: &DB,
    visiting: &mut BTreeSet<(String, RelationName)>,
) -> Option<RowDecision> {
    // A cycle is not something the analysis can judge, so it falls closed.
    if !visiting.insert((type_name.to_string(), relation.clone())) {
        return None;
    }
    let answer = match find_type(plan, type_name) {
        None => None,
        // A clause the database evaluates was lost here, so the emitted rule and the
        // database disagree and no row can settle the difference.
        Some(type_plan) if type_plan.narrowed_relations.contains(relation) => None,
        Some(type_plan) => match type_plan.computed_relations.get(relation) {
            Some(expr) => expr_decision(type_name, expr, plan, sources, db, visiting),
            // A relation with direct subjects is answered by the tuples loaded into
            // it, so the sources feeding it decide.
            None => leaf_decision(type_name, relation, sources, &plan.well_known, db),
        },
    };
    visiting.remove(&(type_name.to_string(), relation.clone()));
    answer
}

fn expr_decision<DB: DatabaseLike>(
    type_name: &str,
    expr: &UsersetExpr,
    plan: &SchemaPlan,
    sources: &SourceIndex<'_, '_>,
    db: &DB,
    visiting: &mut BTreeSet<(String, RelationName)>,
) -> Option<RowDecision> {
    match expr {
        // A named relation stands for its own definition, so the recipe reaches
        // through it to the relations records actually fill.
        UsersetExpr::Computed(name) => {
            relation_decision(type_name, name, plan, sources, db, visiting)
        }
        // Every child has to decide, otherwise the composition does not either.
        UsersetExpr::Union(children) => {
            child_decisions(type_name, children, plan, sources, db, visiting).map(RowDecision::Any)
        }
        UsersetExpr::Intersection(children) => {
            child_decisions(type_name, children, plan, sources, db, visiting).map(RowDecision::All)
        }
        // A tuple-to-userset resolves on the object the tupleset reaches rather than
        // on this row, and an exclusion lets adding a record revoke access, so
        // neither is decidable from the row.
        UsersetExpr::TupleToUserset { .. } | UsersetExpr::Exclusion { .. } => None,
    }
}

fn child_decisions<DB: DatabaseLike>(
    type_name: &str,
    children: &[UsersetExpr],
    plan: &SchemaPlan,
    sources: &SourceIndex<'_, '_>,
    db: &DB,
    visiting: &mut BTreeSet<(String, RelationName)>,
) -> Option<Vec<RowDecision>> {
    children
        .iter()
        .map(|child| expr_decision(type_name, child, plan, sources, db, visiting))
        .collect()
}

/// Every source feeding `relation` must key its object on this row's identity and
/// name a user the row itself supplies. The shapes that pass are the ones
/// [`shapes_filling`] reports for it, deduplicated the same way.
fn leaf_decision<DB: DatabaseLike>(
    type_name: &str,
    relation: &RelationName,
    sources: &SourceIndex<'_, '_>,
    well_known: &WellKnownTypes,
    db: &DB,
) -> Option<RowDecision> {
    let feeding = sources.get(&(type_name.to_string(), relation.clone()))?;
    if feeding.is_empty() {
        return None;
    }

    let mut seen = BTreeSet::new();
    let distinct: Vec<_> = feeding
        .iter()
        .copied()
        .filter(|indexed| seen.insert(indexed.source.dedup_key()))
        .collect();
    if distinct
        .iter()
        .any(|indexed| matches!(indexed.source, TupleSource::SessionAttributeGate { .. }))
    {
        let [indexed] = distinct.as_slice() else {
            return None;
        };
        let TupleSource::SessionAttributeGate {
            row_parameter,
            request_parameter,
            comparison,
            ..
        } = indexed.source
        else {
            return None;
        };
        let description = indexed.description?.clone();
        return Some(RowDecision::RequestGated {
            relation: relation.clone(),
            shapes: vec![description],
            context_key: row_parameter.parameter().to_string(),
            request_parameter: request_parameter.clone(),
            comparison: *comparison,
        });
    }

    if distinct
        .iter()
        .any(|indexed| matches!(indexed.source, TupleSource::CallerSetShareGate { .. }))
    {
        let [indexed] = distinct.as_slice() else {
            return None;
        };
        let TupleSource::CallerSetShareGate {
            row_parameter,
            request_parameter,
            temporal_context,
            ..
        } = indexed.source
        else {
            return None;
        };
        if !temporal_context.is_empty() {
            return None;
        }
        let description = indexed.description?.clone();
        return Some(RowDecision::RequestGated {
            relation: relation.clone(),
            shapes: vec![description],
            context_key: row_parameter.clone(),
            request_parameter: request_parameter.clone(),
            comparison: RequestComparison::CallerSetHolds,
        });
    }

    let mut unique = BTreeSet::new();
    let mut shapes = Vec::new();
    for indexed in feeding {
        let description = indexed.description?;
        if !row_names_a_user(
            &description.derivation,
            type_name,
            well_known.user.as_str(),
            db,
        ) {
            return None;
        }
        if unique.insert(indexed.source.dedup_key()) {
            shapes.push(description.clone());
        }
    }
    Some(RowDecision::Leaf {
        relation: relation.clone(),
        shapes,
    })
}

fn row_names_a_user<DB: DatabaseLike>(
    derivation: &RecordDerivation,
    type_name: &str,
    user_type: &str,
    db: &DB,
) -> bool {
    let RecordDerivation::FromRow {
        table, template, ..
    } = derivation
    else {
        // A joining source reads a second table, so the row does not decide.
        return false;
    };
    // A conditional record grants only while its condition holds, which a plain leaf
    // cannot say, so the consumer must ask rather than read the subject at face value.
    if template.context.is_some() {
        return false;
    }
    if template.object_type != type_name {
        return false;
    }
    // The object has to be this row's identity: every key column, in declared order. A
    // record keyed by a foreign column describes another object, which a change to this
    // row does not own. A single-column key is a list of one, so nothing about that case
    // moves.
    let object_columns: Option<Vec<&str>> = template
        .object_key
        .parts()
        .iter()
        .map(|part| match part {
            ValueSource::Column(column) => Some(column.as_str()),
            _ => None,
        })
        .collect();
    let Some(object_columns) = object_columns else {
        return false;
    };
    let Some(primary_key) = resolve_row_identity(table, db) else {
        return false;
    };
    if object_columns != primary_key {
        return false;
    }
    // The subject has to be a user the consumer can compare against, named by
    // this row rather than reached through another type's membership.
    if template.subject_type != user_type {
        return false;
    }
    !matches!(template.subject_key.part(), ValueSource::Literal(_))
}

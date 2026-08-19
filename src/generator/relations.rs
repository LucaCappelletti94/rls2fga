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
use crate::parser::identifiers::{RelationName, TypeName};
use alloc::collections::{BTreeMap, BTreeSet};

use crate::generator::db_lookup::resolve_pk_columns;
use crate::generator::describe::describe_tuple_source;
use crate::generator::ir::TupleSource;
use crate::generator::model_generator::{
    relation_grants_nothing, SchemaPlan, TypePlan, UsersetExpr,
};
use crate::generator::records::{RecordDerivation, RecordDescription, ValueSource};
use crate::generator::well_known::USER_TYPE;
use crate::parser::sql_parser::DatabaseLike;

/// One relation's shapes and answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelationShapes {
    /// `OpenFGA` type the relation is defined on.
    pub type_name: TypeName,
    /// Relation name.
    pub relation: RelationName,
    /// True only when every leaf resolves from the object's own row to a named
    /// user. False whenever the analysis cannot establish that, including every
    /// case it does not understand.
    pub from_one_row: bool,
    /// The shapes whose records fill this relation, one per query the loader runs
    /// for it. Empty for a relation the model computes from others, and for one
    /// nothing populates.
    pub shapes: Vec<RecordDescription>,
    /// How the subjects this relation grants compose from one row, `Some` exactly
    /// when `from_one_row` is true.
    pub decision: Option<RowDecision>,
    /// Whether the model refuses this relation for every row, so no record fills it and
    /// no round trip is needed to be told no. False for a direct relation, which grants
    /// whatever is written into it.
    pub grants_nobody: bool,
}

/// How the subjects a relation grants compose from one row's records.
///
/// The whole evaluation: [`Self::Leaf`] is the union of the subjects
/// [`crate::generator::records::records_from_row`] yields over its shapes,
/// [`Self::Any`] is the union of its children and [`Self::All`] their intersection.
///
/// `#[non_exhaustive]`: a shape the analysis learns to decide adds a variant, and a
/// caller matching this outside the crate keeps a wildcard arm.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RowDecision {
    /// The subjects are the records these shapes produce for this row.
    Leaf {
        /// The direct relation whose records answer. Always on the same type.
        relation: RelationName,
        /// The shapes filling it, identical to that relation's own entry. Never empty.
        shapes: Vec<RecordDescription>,
    },
    /// A subject any child grants.
    Any(Vec<RowDecision>),
    /// A subject every child grants.
    All(Vec<RowDecision>),
    /// The row settles one side of a comparison the caller's own request value
    /// completes, so a consumer holding that value decides with no round trip.
    ///
    /// Taking the subjects at face value is a wrong allow: the shapes here yield
    /// `user:*`, which grants everyone until the comparison is applied.
    RequestGated {
        /// The direct relation whose records carry the row's side. Always on the same
        /// type.
        relation: RelationName,
        /// The shapes filling it, identical to that relation's own entry. Never empty.
        shapes: Vec<RecordDescription>,
        /// Context key each record carries the row's side under.
        context_key: String,
        /// Parameter the caller supplies its own value as, in every check context.
        request_parameter: String,
        /// How the two sides are compared.
        comparison: RequestComparison,
    },
}

/// How a request-gated relation compares the row's side against the caller's.
///
/// `#[non_exhaustive]`: a comparison the analysis learns adds a variant, and a caller
/// matching this outside the crate keeps a wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RequestComparison {
    /// The caller's set has to hold the row's value.
    CallerSetHolds,
    /// The caller's single value has to equal the row's.
    CallerValueEquals,
}

/// Report every relation of the emitted model.
pub(crate) fn relation_shapes<DB: DatabaseLike>(plan: &SchemaPlan, db: &DB) -> Vec<RelationShapes> {
    let sources = index_sources(plan);

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
                shapes: shapes_filling(type_plan.type_name.as_str(), relation, &sources, db),
                decision,
                grants_nobody: relation_grants_nothing(type_plan, relation),
            });
        }
    }
    out
}

/// Tuple sources by the `(type, relation)` pair each one populates.
fn index_sources(plan: &SchemaPlan) -> SourceIndex<'_> {
    let mut index: SourceIndex<'_> = BTreeMap::new();
    for type_plan in &plan.types {
        for source in &type_plan.table_tuple_sources {
            for target in source.feeds(&type_plan.type_name) {
                index.entry(target).or_default().push((
                    source,
                    type_plan.type_name.as_str(),
                    type_plan.reads_only_its_own_rows,
                ));
            }
        }
    }
    index
}

type SourceIndex<'plan> =
    BTreeMap<(String, RelationName), Vec<(&'plan TupleSource, &'plan str, bool)>>;

/// One shape per source. A source feeding the same relation from two type plans
/// describes it twice, and the key the renderer deduplicates queries on is what
/// says the two are the same. Scoping it by owner type would add nothing: a source
/// keying its objects on the owning type only ever reaches the bucket named after
/// that type.
fn shapes_filling<DB: DatabaseLike>(
    type_name: &str,
    relation: &RelationName,
    sources: &SourceIndex<'_>,
    db: &DB,
) -> Vec<RecordDescription> {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut out = Vec::new();
    for (source, owner_type, only_own_rows) in sources
        .get(&(type_name.to_string(), relation.clone()))
        .into_iter()
        .flatten()
    {
        if !seen.insert(source.dedup_key()) {
            continue;
        }
        if let Some(description) = describe_tuple_source(source, owner_type, *only_own_rows, db) {
            out.push(description);
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
    sources: &SourceIndex<'_>,
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
            None => leaf_decision(type_name, relation, sources, db),
        },
    };
    visiting.remove(&(type_name.to_string(), relation.clone()));
    answer
}

fn expr_decision<DB: DatabaseLike>(
    type_name: &str,
    expr: &UsersetExpr,
    plan: &SchemaPlan,
    sources: &SourceIndex<'_>,
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
    sources: &SourceIndex<'_>,
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
    sources: &SourceIndex<'_>,
    db: &DB,
) -> Option<RowDecision> {
    // Nothing the generator emits populates it, so its tuples come from somewhere
    // this analysis cannot see, `pg_role` memberships among them.
    let feeding = sources.get(&(type_name.to_string(), relation.clone()))?;
    if feeding.is_empty() {
        return None;
    }

    // A gate the request completes is decidable in a different way: the row settles one
    // side and the consumer's own value settles the other, so the recipe carries the
    // comparison rather than a subject set. One policy covering several commands records
    // its gate once per command, so the distinct sources are what decides.
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let distinct: Vec<_> = feeding
        .iter()
        .filter(|(source, ..)| seen.insert(source.dedup_key()))
        .collect();
    if distinct
        .iter()
        .any(|(source, ..)| matches!(source, TupleSource::SessionAttributeGate { .. }))
    {
        // A second source beside it would be a composition this cannot describe.
        let [(
            source @ TupleSource::SessionAttributeGate {
                row_parameter,
                request_parameter,
                comparison,
                ..
            },
            owner_type,
            only_own_rows,
        )] = distinct.as_slice()
        else {
            return None;
        };
        let description = describe_tuple_source(source, owner_type, *only_own_rows, db)?;
        return Some(RowDecision::RequestGated {
            relation: relation.clone(),
            shapes: vec![description],
            context_key: row_parameter.parameter().to_string(),
            request_parameter: request_parameter.clone(),
            comparison: *comparison,
        });
    }

    // A caller-set share gate is request-completed the same way: the share row settles the
    // member value and the caller's set settles the rest. A clock composed into it is a
    // second comparison this cannot name, so that case falls back to the model's condition.
    if distinct
        .iter()
        .any(|(source, ..)| matches!(source, TupleSource::CallerSetShareGate { .. }))
    {
        let [(
            source @ TupleSource::CallerSetShareGate {
                row_parameter,
                request_parameter,
                temporal_context,
                ..
            },
            owner_type,
            only_own_rows,
        )] = distinct.as_slice()
        else {
            return None;
        };
        if !temporal_context.is_empty() {
            return None;
        }
        let description = describe_tuple_source(source, owner_type, *only_own_rows, db)?;
        return Some(RowDecision::RequestGated {
            relation: relation.clone(),
            shapes: vec![description],
            context_key: row_parameter.clone(),
            request_parameter: request_parameter.clone(),
            comparison: RequestComparison::CallerSetHolds,
        });
    }

    let mut unique: BTreeSet<String> = BTreeSet::new();
    let mut shapes = Vec::new();
    for (source, owner_type, only_own_rows) in feeding {
        let description = describe_tuple_source(source, owner_type, *only_own_rows, db)?;
        if !row_names_a_user(&description.derivation, type_name, db) {
            return None;
        }
        if unique.insert(source.dedup_key()) {
            shapes.push(description);
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
    let Some(primary_key) = resolve_pk_columns(table, db) else {
        return false;
    };
    if object_columns != primary_key {
        return false;
    }
    // The subject has to be a user the consumer can compare against, named by
    // this row rather than reached through another type's membership.
    if template.subject_type != USER_TYPE {
        return false;
    }
    !matches!(template.subject_key.part(), ValueSource::Literal(_))
}

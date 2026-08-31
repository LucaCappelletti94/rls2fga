//! Compiling one subscription filter, rather than a whole schema's policies.
//!
//! A change stream consumer registers a filter naming a relationship, then has to answer
//! "is this row still in that subscription" for every row that changes. That is the
//! question [`crate::types::RelationShapes`] already answers for a policy, asked of one
//! expression nobody wrote a policy for.
//!
//! The answer names both links of the chain, because the consumer follows them in the
//! record store it already keeps: a changed row of the filtered table moves the first
//! link, and a changed row of the related table moves the second.
//!
//! # Refusing rather than serving a filter that runs two ways
//!
//! One filter has two executors, the SQL it was written as and the records compiled here,
//! and a filter they answer differently is worse than one that is refused. So a filter is
//! refused when the translation says the model disagrees with the database, when the
//! related table's own read rules would decide it (a reader exempt from them gets rows
//! from the SQL that no record carries), and when nothing about the filtered row decides
//! it at all.

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;

use sqlparser::ast::Expr;

use crate::classifier::function_registry::FunctionRegistry;
use crate::classifier::patterns::{
    filter_policies_for_output, ClassifiedExpr, ClassifiedPolicy, ConfidenceLevel, PatternClass,
    PolicyCommand, PolicyMode, UnclassifiedExpr,
};
use crate::classifier::policy_classifier::classify_expr;
use crate::generator::model_generator::{
    build_plan_typing, GeneratorSettings, SchemaPlan, TypeScope, UsersetExpr,
};
use crate::generator::relations::relation_shapes;
use crate::generator::row_naming::row_naming;
use crate::generator::tuple_generator::{generate_tuple_queries_from_plan, UnboundedColumns};
use crate::generator::well_known::can_select_relation;
use crate::parser::names::{lookup_table, resolve_table_id};
use crate::parser::sql_parser::{DatabaseLike, TableLike};
use crate::types::RelationShapes;
use crate::types::TranslationNote;
use crate::types::{RecordDerivation, RecordTemplate, ValueSource};
use crate::types::{RelationName, TableId};

/// What one subscription filter implies, in the vocabulary a change stream consumer
/// already evaluates.
///
/// `#[non_exhaustive]`: a filter shape this learns to serve adds a field.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TermShapes {
    /// The type the filtered table maps to.
    pub object_type: String,
    /// How a row of that type reaches the caller the filter admits it for.
    pub chain: TermChain,
    /// The relations the chain names, with the shapes whose records fill them. Same
    /// meaning as [`crate::translator::Translation::relations`], and exactly the shapes a
    /// consumer's store has to keep current.
    pub relations: Vec<RelationShapes>,
    /// What the translation had to say about itself, none of it a disagreement with the
    /// database. The row identifier budget arrives here, and it decides whether a row
    /// whose key is too long to name is missing from the subscription.
    pub notes: Vec<TranslationNote>,
}

/// How a row reaches the caller the filter admits it for.
///
/// `#[non_exhaustive]`: a longer chain adds a variant, and a caller matching this outside
/// the crate keeps a wildcard arm.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TermChain {
    /// One link: a relation on the filtered row naming the caller.
    Direct {
        /// Relation on the filtered type whose records name the caller.
        relation: RelationName,
    },
    /// Two links: the filtered row names a related row, and that row names the caller.
    Through {
        /// Relation on the filtered type whose subject is `through_type`.
        link: RelationName,
        /// The related type.
        through_type: String,
        /// Relation on `through_type` whose records name the caller.
        member: RelationName,
    },
}

/// Why a filter cannot be compiled, worded for an operator reading a registration error.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct TermRefusal {
    /// The reason, in the wording the crate already uses for the same refusal.
    pub reason: String,
    /// The classification that produced it. Always present, since classification always
    /// answers, `Unknown` included. Boxed because it is the whole pattern tree and this
    /// travels as an error.
    pub classified: Box<ClassifiedExpr>,
}

/// Compile one subscription filter against `db`, or refuse it.
///
/// `guarded_table` needs no policy and no row-level security switched on, since a
/// subscription filter is not a policy.
///
/// # Errors
///
/// Returns the reason the filter cannot be served by compiled records, which the caller
/// reports at registration rather than accepting a filter it can only run one of its two
/// ways.
pub fn describe_membership_term<DB: DatabaseLike>(
    expr: &Expr,
    db: &DB,
    registry: &FunctionRegistry,
    guarded_table: &str,
    min_confidence: ConfidenceLevel,
) -> Result<TermShapes, TermRefusal> {
    let classified = classify_expr(expr, db, registry, guarded_table, PolicyCommand::Select);
    let refuse = |reason: String| TermRefusal {
        reason,
        classified: Box::new(classified.clone()),
    };

    // The classifier's own wording for a filter it cannot read, which is what reaches an
    // operator. Checked before the threshold, since the grade would say less.
    if let PatternClass::Unknown(UnclassifiedExpr { reason, .. }) = &classified.pattern {
        return Err(refuse(reason.clone()));
    }

    let policy = synthetic_policy(guarded_table, expr, &classified, db);
    let bounds = UnboundedColumns::resolve(db);
    let plan = build_plan_typing(
        &filter_policies_for_output(&[policy], min_confidence),
        db,
        registry,
        &GeneratorSettings::default(),
        &bounds,
        TypeScope::AndAlso(guarded_table),
    )
    .map_err(|err| refuse(err.to_string()))?;
    let tuples = generate_tuple_queries_from_plan(&plan, &bounds, db);
    let relations = relation_shapes(&plan, &tuples.descriptions, db);
    // One source for "what is this table called", shared with `Translation::row_naming`,
    // so the type this reports and the type a consumer names the row with cannot differ.
    // A table the model names no row of has no chain either, which is the same refusal.
    let derived = row_naming(&plan, db)
        .into_iter()
        .find(|entry| same_table(db, &entry.table, guarded_table))
        .map_or(Err(0), |entry| {
            derive_chain(
                &relations,
                db,
                guarded_table,
                &entry.type_name,
                plan.well_known.user.as_str(),
            )
            .map(|chain| (entry.type_name, chain))
        });

    // Asked before the notes, since a related table carrying policies of its own makes
    // the plan report a threshold that had nothing to do with it: this surface never
    // classified that table's policies, and under this rule it never has to.
    if let Ok((
        object_type,
        chain @ TermChain::Through {
            through_type,
            member,
            ..
        },
    )) = &derived
    {
        let named = chain_relations(&relations, object_type, chain);
        if let Some(table) = caller_side_table(&named, through_type, member) {
            if lookup_table(db, &table)
                .is_some_and(|found| found.has_row_level_security(db) != Ok(false))
            {
                return Err(refuse(format!(
                    "'{table}' carries its own read rules, so the same filter run as SQL answers \
                     differently for a reader exempt from them"
                )));
            }
        }
    }

    // A note saying the model disagrees with the database is the whole reason this
    // surface exists, so it refuses rather than reporting.
    if let Some(note) = plan
        .notes
        .iter()
        .find(|note| note.severity().diverges_from_database())
    {
        return Err(refuse(note.to_string()));
    }

    let (object_type, chain) = derived.map_err(|links| {
        refuse(if links > 1 {
            format!(
                "a row of '{guarded_table}' satisfies this filter more than one way, and no single \
                 chain of records answers it"
            )
        } else {
            format!(
                "nothing about a row of '{guarded_table}' decides this filter, so no record can \
                 carry it"
            )
        })
    })?;

    // The chain answers the filter only when it is the whole rule. An intersection asks
    // for more than the chain reaches, and a union is satisfied without it, so serving
    // the chain alone is a wrong allow in one direction or a wrong deny in the other.
    if let Some(reason) = rule_beyond_the_chain(&plan, &object_type, &chain) {
        return Err(refuse(reason));
    }
    let named = chain_relations(&relations, &object_type, &chain);
    Ok(TermShapes {
        object_type,
        chain,
        relations: named,
        notes: plan
            .notes
            .into_iter()
            .filter(describes_the_filter)
            .collect(),
    })
}

/// Whether a note says something about the compiled filter rather than about the
/// database's own enforcement.
///
/// A filter is not enforced by row-level security, so which commands a policy covers and
/// who bypasses policies are artifacts of wrapping the filter as one, and reporting them
/// would describe a policy nobody wrote.
fn describes_the_filter(note: &TranslationNote) -> bool {
    !matches!(
        note,
        TranslationNote::NoPermissivePolicy { .. }
            | TranslationNote::TableOwnerBypassesPolicies { .. }
    )
}

/// The policy a filter would be if anyone had written it as one.
fn synthetic_policy<DB: DatabaseLike>(
    table: &str,
    expr: &Expr,
    classified: &ClassifiedExpr,
    db: &DB,
) -> ClassifiedPolicy {
    ClassifiedPolicy {
        name: "subscription filter".to_string(),
        table: table.to_string(),
        resolved_table: resolve_table_id(db, table),
        command: PolicyCommand::Select,
        mode: PolicyMode::Permissive,
        scoped_roles: Vec::new(),
        ddl_time_roles: Vec::new(),
        using: Some(expr.clone()),
        with_check: None,
        using_classification: Some(classified.clone()),
        with_check_classification: None,
        using_filtered_at: None,
        with_check_filtered_at: None,
    }
}

/// Why the compiled rule asks for something the chain does not answer, or `None` when the
/// chain is the whole rule.
///
/// Read off the plan's own expression rather than counted off the shapes: a half of the
/// filter that compiles to a gate rather than to a record leaves the shapes looking
/// complete while the rule says otherwise.
fn rule_beyond_the_chain(
    plan: &SchemaPlan,
    object_type: &str,
    chain: &TermChain,
) -> Option<String> {
    let rule = plan
        .types
        .iter()
        .find(|type_plan| type_plan.type_name.as_str() == object_type)
        .and_then(|type_plan| type_plan.computed_relations.get(&can_select_relation()))?;
    let answered = match (rule, chain) {
        (UsersetExpr::Computed(name), TermChain::Direct { relation }) => name == relation,
        (
            UsersetExpr::TupleToUserset { tupleset, computed },
            TermChain::Through { link, member, .. },
        ) => tupleset == link && computed == member,
        _ => false,
    };
    if answered {
        return None;
    }
    Some(
        match rule {
            UsersetExpr::Intersection(_) => {
                "this filter narrows further than one chain of records answers, so the chain \
             alone admits rows the filter refuses"
            }
            UsersetExpr::Union(_) => {
                "a row satisfies this filter more than one way, and no single chain of records \
             answers it"
            }
            UsersetExpr::Exclusion { .. } => {
                "this filter subtracts from what the chain reaches, and no record can carry a \
             subtraction"
            }
            UsersetExpr::Computed(_) | UsersetExpr::TupleToUserset { .. } => {
                "the rule this filter compiles to is not the chain of records beside it"
            }
        }
        .to_string(),
    )
}

/// The chain out of one row of the filtered table, whose type the caller already knows.
///
/// Read off the shapes the plan produced rather than off the pattern, so the chain and the
/// shapes returned beside it cannot describe different filters. The link out of the
/// filtered row is the shape that reads that table and names an object of its own type.
///
/// `Err` carries how many links were found when that is not exactly one: a filter two
/// chains satisfy is answered by neither of them alone.
fn derive_chain<DB: DatabaseLike>(
    relations: &[RelationShapes],
    db: &DB,
    guarded_table: &str,
    object_type: &str,
    user_type: &str,
) -> Result<TermChain, usize> {
    let mut links: Vec<(RelationName, String)> = Vec::new();
    for entry in relations {
        if entry.type_name.as_str() != object_type {
            continue;
        }
        for shape in &entry.shapes {
            let RecordDerivation::FromRow {
                table, template, ..
            } = &shape.derivation
            else {
                continue;
            };
            if !same_table(db, table, guarded_table) || !links_out_of_its_own_row(entry, template) {
                continue;
            }
            links.push((entry.relation.clone(), template.subject_type.clone()));
        }
    }

    let [(relation, subject_type)] = links.as_slice() else {
        return Err(links.len());
    };
    if subject_type == user_type {
        return Ok(TermChain::Direct {
            relation: relation.clone(),
        });
    }
    let member = member_relation(relations, subject_type, user_type).ok_or(0_usize)?;
    Ok(TermChain::Through {
        link: relation.clone(),
        through_type: subject_type.clone(),
        member,
    })
}

/// Whether a resolved table and a spelling identify one table of `db`.
///
/// A spelling the schema cannot place identifies nothing, since a chain built on a guess
/// would name records the filtered row never reaches.
fn same_table<DB: DatabaseLike>(db: &DB, left: &TableId, right: &str) -> bool {
    resolve_table_id(db, right).is_some_and(|right| *left == right)
}

/// Whether a shape names an object of the type its relation is defined on, from a value
/// the row itself carries.
///
/// A subject named by a fixed value rather than by the row is either the typed wildcard,
/// which grants everyone, or the holder of a filter that admits every row. Neither is a
/// link out of one row. An unknown value source delegates.
fn links_out_of_its_own_row(entry: &RelationShapes, template: &RecordTemplate) -> bool {
    template.object_type == entry.type_name.as_str()
        && matches!(
            template.subject_key.part(),
            ValueSource::Column(_) | ValueSource::ListElements(_) | ValueSource::JsonPath { .. }
        )
}

/// The relation on `type_name` whose records name a caller, when exactly one does.
fn member_relation(
    relations: &[RelationShapes],
    type_name: &str,
    user_type: &str,
) -> Option<RelationName> {
    let mut naming = relations.iter().filter(|entry| {
        entry.type_name.as_str() == type_name
            && entry.shapes.iter().any(|shape| {
                matches!(
                    &shape.derivation,
                    RecordDerivation::FromRow { template, .. }
                        if template.object_type == type_name
                            && template.subject_type == user_type
                )
            })
    });
    let only = naming.next()?;
    naming.next().is_none().then(|| only.relation.clone())
}

/// Only the entries the chain names, since those are the shapes a store keeps current and
/// everything else the plan holds is policy vocabulary the filter never asked for.
fn chain_relations(
    relations: &[RelationShapes],
    object_type: &str,
    chain: &TermChain,
) -> Vec<RelationShapes> {
    let wanted: Vec<(&str, &str)> = match chain {
        TermChain::Direct { relation } => vec![(object_type, relation.as_str())],
        TermChain::Through {
            link,
            through_type,
            member,
        } => vec![
            (object_type, link.as_str()),
            (through_type.as_str(), member.as_str()),
        ],
    };
    wanted
        .into_iter()
        .filter_map(|(type_name, relation)| {
            relations
                .iter()
                .find(|entry| entry.type_name.as_str() == type_name && entry.relation == relation)
                .cloned()
        })
        .collect()
}

/// The table whose rows fill `member` on `type_name`, which is the table the filter's
/// subquery scans.
///
/// Keyed on the relation rather than on the type, since a membership whose parent is the
/// filtered type itself holds both links on one type, and the link out of the row reads
/// the filtered table instead.
fn caller_side_table(
    relations: &[RelationShapes],
    type_name: &str,
    member: &RelationName,
) -> Option<String> {
    relations
        .iter()
        .filter(|entry| entry.type_name.as_str() == type_name && entry.relation == *member)
        .flat_map(|entry| &entry.shapes)
        .find_map(|shape| match &shape.derivation {
            RecordDerivation::FromRow { table, .. } => Some(table.to_string()),
            _ => None,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generator::well_known::WellKnownTypes;
    use crate::types::TypeName;
    use crate::types::{ObjectKey, RecordDescription, SubjectKey};

    fn naming_user(type_name: &str, relation: &str, table: &str) -> RelationShapes {
        naming_user_from_table(
            type_name,
            relation,
            &TableId::from_stored(None, table.to_string()),
        )
    }

    fn naming_user_from_table(type_name: &str, relation: &str, table: &TableId) -> RelationShapes {
        RelationShapes {
            type_name: TypeName::canonicalized(type_name),
            relation: RelationName::canonicalized(relation),
            from_one_row: false,
            shapes: vec![RecordDescription {
                tables: vec![table.clone()],
                derivation: RecordDerivation::FromRow {
                    table: table.clone(),
                    template: Box::new(RecordTemplate {
                        object_type: type_name.to_string(),
                        object_key: ObjectKey::column("id"),
                        relation: RelationName::canonicalized(relation),
                        subject_type: WellKnownTypes::default().user.to_string(),
                        subject_key: SubjectKey::column("user_id"),
                        context: None,
                    }),
                    guards: Vec::new(),
                },
            }],
            decision: None,
            grants_nobody: false,
        }
    }

    /// Two relations naming a caller leave no single second link, so the caller is
    /// reached two ways and neither of them is the answer.
    ///
    /// The plan mints one such relation per filter today, so this is the unit that keeps
    /// the rule honest rather than an end-to-end case.
    #[test]
    fn a_type_naming_the_caller_twice_has_no_single_member_relation() {
        let one = [naming_user("orders", "customer", "orders")];
        assert_eq!(
            member_relation(&one, "orders", WellKnownTypes::default().user().as_str())
                .as_ref()
                .map(RelationName::as_str),
            Some("customer")
        );

        let two = [
            naming_user("orders", "customer", "orders"),
            naming_user("orders", "buyer", "orders"),
        ];
        assert_eq!(
            member_relation(&two, "orders", WellKnownTypes::default().user().as_str()),
            None
        );
    }
    #[test]
    fn a_chain_uses_the_resolved_table_identity() {
        let db = crate::parser::sql_parser::parse_schema(
            r#"
CREATE TABLE public.memberships(id INT PRIMARY KEY, user_id TEXT);
CREATE TABLE public."Memberships"(id INT PRIMARY KEY, user_id TEXT);
"#,
        )
        .expect("schema should parse");
        let stored =
            resolve_table_id(&db, "public.memberships").expect("unquoted table should resolve");
        let quoted =
            resolve_table_id(&db, r#"public."Memberships""#).expect("quoted table should resolve");
        assert_eq!(stored.name(), "memberships");
        assert_eq!(quoted.name(), "Memberships");
        assert!(!same_table(&db, &quoted, "memberships"));
        assert!(!same_table(&db, &quoted, "public.memberships"));
        let user = WellKnownTypes::default();
        let expected = TermChain::Direct {
            relation: RelationName::canonicalized("viewer"),
        };

        for guarded in ["memberships", "public.memberships"] {
            assert_eq!(
                derive_chain(
                    &[naming_user_from_table("memberships", "viewer", &stored,)],
                    &db,
                    guarded,
                    "memberships",
                    user.user().as_str(),
                ),
                Ok(expected.clone())
            );
            assert_eq!(
                derive_chain(
                    &[naming_user_from_table("memberships", "viewer", &quoted,)],
                    &db,
                    guarded,
                    "memberships",
                    user.user().as_str(),
                ),
                Err(0)
            );
        }
    }
}

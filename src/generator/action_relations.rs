//! Which relations answer one action, and which version of the row each judges.
//!
//! A statement is answered by relations the emitted model may or may not define, since a
//! policy writing one condition and a policy writing two produce different relations for
//! the same `UPDATE`. A consumer branching on which ones exist re-derives that mapping,
//! and a later revision emitting them under a further condition makes the branch judge a
//! replacement against one row version, which grants.
//!
//! Reading the relation names off the model is not enough either: nothing in the model
//! text says whether a relation judges the row as it is or as it will be, and a `WITH
//! CHECK` clause only means anything against the second.

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;

use crate::generator::model_generator::{SchemaPlan, TypePlan};
use crate::generator::well_known::{
    can_delete_relation, can_insert_relation, can_insert_returning_relation,
    can_select_for_update_relation, can_select_relation, can_update_check_relation,
    can_update_relation, can_update_using_relation, can_update_without_reading_relation,
};
use crate::parser::identifiers::{RelationName, TypeName};
use crate::parser::names::lookup_table;
use crate::parser::sql_parser::{DatabaseLike, TableLike};

/// Which version of the row a relation judges.
///
/// `#[non_exhaustive]`: a version this learns to report adds a variant, and a caller
/// matching this outside the crate keeps a wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum RowVersion {
    /// The row as it is, which a `USING` clause reads.
    Existing,
    /// The row as it will be, which a `WITH CHECK` clause reads.
    Resulting,
}

/// One relation that must grant, and the version it judges.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ActionJudgement {
    /// Relation to ask, always defined on the entry's type.
    pub relation: RelationName,
    /// Version to ask it about.
    pub version: RowVersion,
}

/// How one action on one type is answered.
///
/// `#[non_exhaustive]`: an answer this learns to give adds a variant, and a caller
/// matching this outside the crate keeps a wildcard arm.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ActionAnswer {
    /// Every judgement must grant. All of them, never any of them.
    Judged(Vec<ActionJudgement>),
    /// The table carries no row-level security, so the database restricts nothing here
    /// and there is nothing to ask.
    Unrestricted,
    /// One relation fuses the two versions, so no single row version answers it.
    ///
    /// `can_update_without_reading` is `USING and WITH CHECK` in one relation, and the
    /// `USING` half exists nowhere else without the read gate a blind update does not
    /// need. Asking it is answering the check clause against the row as it is, which
    /// grants a change the clause was written to refuse.
    NotSeparable {
        /// The relation the model answers this action with.
        relation: RelationName,
    },
}

/// A statement shape the model answers for.
///
/// `#[non_exhaustive]`: a shape this learns to answer adds a variant, and a caller
/// matching this outside the crate keeps a wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum ActionStatement {
    /// `SELECT`.
    Select,
    /// `INSERT`.
    Insert,
    /// `UPDATE` naming the rows it changes.
    Update,
    /// `DELETE`.
    Delete,
    /// A locking read, `SELECT ... FOR UPDATE` and its three siblings, which
    /// `PostgreSQL` filters by the `UPDATE` policies as well.
    SelectForUpdate,
    /// `INSERT ... ON CONFLICT ... DO UPDATE`, which changes the conflicting row.
    InsertOnConflictUpdate,
    /// `INSERT ... RETURNING`, which reads the row it wrote.
    InsertReturning,
    /// `UPDATE` with no `WHERE`, which reads nothing to choose rows, so the `SELECT`
    /// policies do not apply.
    UpdateWithoutWhere,
}

impl ActionStatement {
    /// The SQL command this answers for, as the translation notes spell it.
    #[must_use]
    pub fn command(&self) -> &'static str {
        match self {
            Self::Select | Self::SelectForUpdate => "SELECT",
            Self::Insert | Self::InsertOnConflictUpdate | Self::InsertReturning => "INSERT",
            Self::Update | Self::UpdateWithoutWhere => "UPDATE",
            Self::Delete => "DELETE",
        }
    }
}

/// Every statement an entry is reported for, in the order the entries come.
const EVERY_STATEMENT: [ActionStatement; 8] = [
    ActionStatement::Select,
    ActionStatement::Insert,
    ActionStatement::Update,
    ActionStatement::Delete,
    ActionStatement::SelectForUpdate,
    ActionStatement::InsertOnConflictUpdate,
    ActionStatement::InsertReturning,
    ActionStatement::UpdateWithoutWhere,
];

/// How one statement on one type is answered.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ActionRelations {
    /// Type the action is asked on, as [`RelationShapes`](crate::generator::relations::RelationShapes)
    /// spells it.
    pub type_name: TypeName,
    /// Statement it answers for.
    pub statement: ActionStatement,
    /// What has to grant.
    pub answer: ActionAnswer,
}

fn judge(relation: RelationName, version: RowVersion) -> ActionJudgement {
    ActionJudgement { relation, version }
}

/// The relation the type defines, or the one the model falls back to where it does not.
fn defined_or(plan: &TypePlan, wanted: RelationName, fallback: RelationName) -> RelationName {
    if plan.computed_relations.contains_key(&wanted) {
        wanted
    } else {
        fallback
    }
}

/// Whether this type answers the two `UPDATE` clauses apart, which it does exactly
/// where the policies gave them different rules. Asked once, since a second reading
/// could disagree with the first.
fn clauses_answered_apart(plan: &TypePlan) -> bool {
    plan.computed_relations
        .contains_key(&can_update_using_relation())
}

/// What a replacement has to satisfy: the two halves where the policy's clauses differ,
/// and the one relation twice where a lone `USING` is mirrored onto the result.
fn update_judgements(plan: &TypePlan) -> Vec<ActionJudgement> {
    if clauses_answered_apart(plan) {
        vec![
            judge(can_update_using_relation(), RowVersion::Existing),
            judge(can_update_check_relation(), RowVersion::Resulting),
        ]
    } else {
        vec![
            judge(can_update_relation(), RowVersion::Existing),
            judge(can_update_relation(), RowVersion::Resulting),
        ]
    }
}

/// A blind update applies both clauses without the read gate, which the model spells as
/// one fused relation wherever the clauses differ.
fn blind_update_answer(plan: &TypePlan) -> ActionAnswer {
    let relation = can_update_without_reading_relation();
    if !plan.computed_relations.contains_key(&relation) {
        return ActionAnswer::Judged(update_judgements(plan));
    }
    if clauses_answered_apart(plan) {
        return ActionAnswer::NotSeparable { relation };
    }
    ActionAnswer::Judged(vec![
        judge(relation.clone(), RowVersion::Existing),
        judge(relation, RowVersion::Resulting),
    ])
}

fn answer(plan: &TypePlan, statement: ActionStatement) -> ActionAnswer {
    match statement {
        ActionStatement::Select => {
            ActionAnswer::Judged(vec![judge(can_select_relation(), RowVersion::Existing)])
        }
        ActionStatement::Insert => {
            ActionAnswer::Judged(vec![judge(can_insert_relation(), RowVersion::Resulting)])
        }
        ActionStatement::Update => ActionAnswer::Judged(update_judgements(plan)),
        ActionStatement::Delete => {
            ActionAnswer::Judged(vec![judge(can_delete_relation(), RowVersion::Existing)])
        }
        // The relation named for a locking read carries only what the UPDATE policies
        // add, so the read gate is named beside it rather than assumed.
        ActionStatement::SelectForUpdate => ActionAnswer::Judged(vec![
            judge(can_select_relation(), RowVersion::Existing),
            judge(
                defined_or(
                    plan,
                    can_select_for_update_relation(),
                    can_update_relation(),
                ),
                RowVersion::Existing,
            ),
        ]),
        // `can_upsert` fuses an insert judging the result with an update judging both
        // versions, so its halves are named instead.
        ActionStatement::InsertOnConflictUpdate => {
            let mut required = vec![judge(can_insert_relation(), RowVersion::Resulting)];
            required.extend(update_judgements(plan));
            ActionAnswer::Judged(required)
        }
        // Absent exactly where nothing admits an insert, and the denial answers then.
        ActionStatement::InsertReturning => ActionAnswer::Judged(vec![judge(
            defined_or(plan, can_insert_returning_relation(), can_insert_relation()),
            RowVersion::Resulting,
        )]),
        ActionStatement::UpdateWithoutWhere => blind_update_answer(plan),
    }
}

/// Whether the database is positively known to restrict nothing on this table.
///
/// Only a definite no counts, which is the rule the plan builder itself applies: an
/// unreadable answer must not become a claim that nothing is enforced.
fn restricts_nothing<DB: DatabaseLike>(table: &str, db: &DB) -> bool {
    lookup_table(db, table).is_some_and(|table| table.has_row_level_security(db) == Ok(false))
}

/// One entry per type and statement the model answers, by type name then statement.
///
/// A type nothing keys on a row has no entry, since a consumer never names one of its
/// objects.
pub(crate) fn action_relations<DB: DatabaseLike>(
    plan: &SchemaPlan,
    db: &DB,
) -> Vec<ActionRelations> {
    let mut entries: Vec<ActionRelations> = Vec::new();
    for type_plan in &plan.types {
        let Some(table) = type_plan.source_table.as_ref() else {
            continue;
        };
        let restricted = type_plan
            .computed_relations
            .contains_key(&can_select_relation());
        if !restricted && !restricts_nothing(table, db) {
            continue;
        }
        entries.extend(EVERY_STATEMENT.map(|statement| ActionRelations {
            type_name: type_plan.type_name.clone(),
            statement,
            answer: if restricted {
                answer(type_plan, statement)
            } else {
                ActionAnswer::Unrestricted
            },
        }));
    }
    entries.sort_by(|left, right| {
        left.type_name
            .as_str()
            .cmp(right.type_name.as_str())
            .then(left.statement.cmp(&right.statement))
    });
    entries
}

//! Derive a [`RecordDescription`] from a [`TupleSource`].
//!
//! Deliberately a second reading of the same shape the renderer reads: one
//! produces SQL for a bulk load, the other structure for one row. They are held
//! together by the differential test, which evaluates every description against
//! the rows its own query returns, so a divergence fails rather than drifts.

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use alloc::collections::BTreeSet;

use crate::generator::ir::TupleSource;
use crate::generator::records::{
    BoundQuery, Guard, RecordDerivation, RecordDescription, RecordTemplate, ValueSource,
};
use crate::generator::tuple_generator::{render_tuple_source_inner, resolve_bridge_columns};
use crate::generator::well_known::{
    HOLDER_OBJECT_ID, MEMBER_RELATION, PG_ROLE_TYPE, PUBLIC_RELATION, TEAM_TYPE, USER_TYPE,
};
use crate::parser::sql_parser::DatabaseLike;

/// Sorted, deduplicated table list.
fn tables(names: &[&str]) -> Vec<String> {
    names
        .iter()
        .map(|name| (*name).to_string())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// A description whose records follow from one row of `table`.
fn from_row(
    table: &str,
    object_type: &str,
    object_key: ValueSource,
    relation: &str,
    subject_type: &str,
    subject_key: ValueSource,
    guards: Vec<Guard>,
) -> RecordDescription {
    RecordDescription {
        tables: tables(&[table]),
        derivation: RecordDerivation::FromRow {
            table: table.to_string(),
            template: RecordTemplate {
                object_type: object_type.to_string(),
                object_key,
                relation: relation.to_string(),
                subject_type: subject_type.to_string(),
                subject_key,
            },
            guards,
        },
    }
}

/// Bind the whole-table query to one value, which every joining shape's query
/// ends in a position to accept: each closes with a `WHERE` and a `;`.
fn bind(sql: &str, table: &str, key_column: &str, predicate: &str) -> Option<BoundQuery> {
    let body = sql.strip_suffix(';')?;
    if !body.contains("WHERE ") {
        return None;
    }
    Some(BoundQuery {
        table: table.to_string(),
        key_column: key_column.to_string(),
        sql: format!("{body}\nAND {predicate};"),
    })
}

/// The whole-table query for this one source, which is what a bound query extends.
///
/// `None` where the renderer stands a comment in place of a query, since a comment
/// loads nothing and there is no text to bind.
fn rendered_sql<DB: DatabaseLike>(
    source: &TupleSource,
    owner_type: &str,
    only_own_rows: bool,
    db: &DB,
) -> Option<String> {
    let sql = render_tuple_source_inner(source, owner_type, only_own_rows, db)?.sql;
    (!sql.trim_start().starts_with("--")).then_some(sql)
}

/// Describe the records `source` produces, or `None` where it produces none.
pub(crate) fn describe_tuple_source<DB: DatabaseLike>(
    source: &TupleSource,
    owner_type: &str,
    only_own_rows: bool,
    db: &DB,
) -> Option<RecordDescription> {
    match source {
        TupleSource::DirectOwnership {
            table,
            pk_col,
            owner_col,
            relation,
        } => Some(from_row(
            table,
            owner_type,
            ValueSource::Column(pk_col.clone()),
            relation,
            USER_TYPE,
            ValueSource::Column(owner_col.clone()),
            vec![Guard::NotNull(owner_col.clone())],
        )),

        // One record per element, and the evaluator drops a null element exactly
        // as `WHERE member IS NOT NULL` does.
        TupleSource::ArrayMembership {
            table,
            pk_col,
            array_col,
            relation,
        } => Some(from_row(
            table,
            owner_type,
            ValueSource::Column(pk_col.clone()),
            relation,
            USER_TYPE,
            ValueSource::ListElements(array_col.clone()),
            Vec::new(),
        )),

        TupleSource::JsonbFieldOwnership {
            table,
            pk_col,
            column,
            path,
            relation,
        } => Some(from_row(
            table,
            owner_type,
            ValueSource::Column(pk_col.clone()),
            relation,
            USER_TYPE,
            ValueSource::JsonPath {
                column: column.clone(),
                path: path.clone(),
            },
            Vec::new(),
        )),

        // The owner must appear in the principal table, which the row does not
        // say, so a change to either side moves records.
        TupleSource::RoleOwnerUser {
            table,
            pk_col,
            owner_col,
            user_table,
            user_pk_col,
        } => Some(joined_ownership(
            &rendered_sql(source, owner_type, only_own_rows, db)?,
            table,
            pk_col,
            owner_col,
            user_table,
            user_pk_col,
            "the owner column has to name a row of the user principal table",
        )),

        TupleSource::RoleOwnerTeam {
            table,
            pk_col,
            owner_col,
            team_table,
            team_pk_col,
        } => Some(joined_ownership(
            &rendered_sql(source, owner_type, only_own_rows, db)?,
            table,
            pk_col,
            owner_col,
            team_table,
            team_pk_col,
            "the owner column has to name a row of the team principal table",
        )),

        TupleSource::ExplicitGrants {
            table,
            pk_col,
            grant_table,
            grant_resource_col,
            role_cases,
            user_principal,
            team_principal,
            ..
        } => {
            if role_cases.is_empty() {
                return None;
            }
            let sql = rendered_sql(source, owner_type, only_own_rows, db)?;
            let mut read = vec![table.as_str(), grant_table.as_str()];
            if let Some(principal) = user_principal {
                read.push(principal.table.as_str());
            }
            if let Some(principal) = team_principal {
                read.push(principal.table.as_str());
            }
            Some(RecordDescription {
                tables: tables(&read),
                derivation: RecordDerivation::Joined {
                    queries: [
                        bind(&sql, table, pk_col, &format!("resource.\"{pk_col}\" = $1")),
                        bind(
                            &sql,
                            grant_table,
                            grant_resource_col,
                            &format!("og.\"{grant_resource_col}\" = $1"),
                        ),
                    ]
                    .into_iter()
                    .flatten()
                    .collect(),
                    reason: "a grant row and the resource row it names are separate rows"
                        .to_string(),
                },
            })
        }

        TupleSource::TeamMembership {
            membership_table,
            team_col,
            user_col,
        } => Some(from_row(
            membership_table,
            TEAM_TYPE,
            ValueSource::Column(team_col.clone()),
            MEMBER_RELATION,
            USER_TYPE,
            ValueSource::Column(user_col.clone()),
            vec![
                Guard::NotNull(team_col.clone()),
                Guard::NotNull(user_col.clone()),
            ],
        )),

        // A residual predicate reaches the query as SQL text, which no evaluator
        // here can read, so the shape is only row-decidable without one.
        TupleSource::ExistsMembership {
            join_table,
            fk_col,
            user_col,
            parent_type,
            extra_predicate_sql,
        } => {
            if let Some(predicate) = extra_predicate_sql {
                let sql = rendered_sql(source, owner_type, only_own_rows, db)?;
                return Some(RecordDescription {
                    tables: tables(&[join_table]),
                    derivation: RecordDerivation::Joined {
                        queries: bind(&sql, join_table, fk_col, &format!("\"{fk_col}\" = $1"))
                            .into_iter()
                            .collect(),
                        reason: format!(
                            "the membership row carries a residual predicate only SQL can \
                             evaluate: {predicate}"
                        ),
                    },
                });
            }
            Some(from_row(
                join_table,
                parent_type,
                ValueSource::Column(fk_col.clone()),
                MEMBER_RELATION,
                USER_TYPE,
                ValueSource::Column(user_col.clone()),
                vec![
                    Guard::NotNull(fk_col.clone()),
                    Guard::NotNull(user_col.clone()),
                ],
            ))
        }

        TupleSource::ParentBridge {
            table,
            fk_col,
            parent_type,
            relation,
        } => {
            // The renderer emits a TODO comment rather than a query here, so
            // there are no records to describe.
            let (object_col, parent_ref_col) = resolve_bridge_columns(table, fk_col, db)?;
            Some(from_row(
                table,
                owner_type,
                ValueSource::Column(object_col.clone()),
                relation,
                parent_type,
                ValueSource::Column(parent_ref_col.clone()),
                vec![Guard::NotNull(object_col), Guard::NotNull(parent_ref_col)],
            ))
        }

        TupleSource::PublicFlag {
            table,
            pk_col,
            flag_col,
        } => Some(from_row(
            table,
            owner_type,
            ValueSource::Column(pk_col.clone()),
            PUBLIC_RELATION,
            USER_TYPE,
            ValueSource::Literal("*".to_string()),
            vec![
                Guard::NotNull(pk_col.clone()),
                Guard::IsTrue(flag_col.clone()),
            ],
        )),

        TupleSource::ConstantTrue { table, pk_col } => Some(from_row(
            table,
            owner_type,
            ValueSource::Column(pk_col.clone()),
            PUBLIC_RELATION,
            USER_TYPE,
            ValueSource::Literal("*".to_string()),
            vec![Guard::NotNull(pk_col.clone())],
        )),

        TupleSource::PolicyScope {
            table,
            pk_col,
            scope_relation,
            pg_role,
        } => Some(from_row(
            table,
            owner_type,
            ValueSource::Column(pk_col.clone()),
            scope_relation,
            PG_ROLE_TYPE,
            ValueSource::Literal(pg_role.clone()),
            vec![Guard::NotNull(pk_col.clone())],
        )),

        // The guard reaches the description as structure, so the evaluator applies
        // the same comparison the query puts in its WHERE.
        TupleSource::AttributeGate {
            table,
            pk_col,
            predicate,
        } => Some(from_row(
            table,
            owner_type,
            ValueSource::Column(pk_col.clone()),
            PUBLIC_RELATION,
            USER_TYPE,
            ValueSource::Literal("*".to_string()),
            vec![
                Guard::NotNull(pk_col.clone()),
                Guard::Compare(predicate.clone()),
            ],
        )),

        // The records depend on the request as well as the row, so no row decides
        // them and the flag downstream has to say so.
        TupleSource::ConditionalAttributeGate {
            table,
            column,
            condition,
            ..
        } => {
            let sql = rendered_sql(source, owner_type, only_own_rows, db)?;
            Some(RecordDescription {
                tables: tables(&[table]),
                derivation: RecordDerivation::Joined {
                    queries: bind(&sql, table, column, &format!("\"{column}\" = $1"))
                        .into_iter()
                        .collect(),
                    reason: format!(
                        "the guard on {column} is evaluated by condition {condition} at check \
                         time, so the row alone does not decide the grant"
                    ),
                },
            })
        }

        // Every row of the table points at the one holder object.
        TupleSource::HolderBridge {
            table,
            pk_col,
            relation,
            holder_type,
        } => Some(from_row(
            table,
            owner_type,
            ValueSource::Column(pk_col.clone()),
            relation,
            holder_type,
            ValueSource::Literal(HOLDER_OBJECT_ID.to_string()),
            vec![Guard::NotNull(pk_col.clone())],
        )),

        // The holder is one object, so the object side is fixed and each member row
        // names a user. Two rows naming the same user write one record, which a set
        // of records collapses exactly as the query's DISTINCT does.
        TupleSource::HolderMembers {
            holder_type,
            member_table,
            user_col,
            extra_predicate_sql,
        } => {
            if let Some(predicate) = extra_predicate_sql {
                let sql = rendered_sql(source, owner_type, only_own_rows, db)?;
                return Some(RecordDescription {
                    tables: tables(&[member_table]),
                    derivation: RecordDerivation::Joined {
                        queries: bind(
                            &sql,
                            member_table,
                            user_col,
                            &format!("\"{user_col}\" = $1"),
                        )
                        .into_iter()
                        .collect(),
                        reason: format!(
                            "the member row carries a residual predicate only SQL can \
                             evaluate: {predicate}"
                        ),
                    },
                });
            }
            Some(from_row(
                member_table,
                holder_type,
                ValueSource::Literal(HOLDER_OBJECT_ID.to_string()),
                MEMBER_RELATION,
                USER_TYPE,
                ValueSource::Column(user_col.clone()),
                vec![Guard::NotNull(user_col.clone())],
            ))
        }

        TupleSource::Skipped { .. } => None,
    }
}

/// The two role-ownership shapes differ only in the principal table they filter
/// against, so one place builds both descriptions.
fn joined_ownership(
    sql: &str,
    table: &str,
    pk_col: &str,
    owner_col: &str,
    principal_table: &str,
    principal_pk_col: &str,
    reason: &str,
) -> RecordDescription {
    RecordDescription {
        tables: tables(&[table, principal_table]),
        derivation: RecordDerivation::Joined {
            queries: [
                bind(sql, table, pk_col, &format!("\"{pk_col}\" = $1")),
                bind(
                    sql,
                    principal_table,
                    principal_pk_col,
                    &format!("\"{owner_col}\" = $1"),
                ),
            ]
            .into_iter()
            .flatten()
            .collect(),
            reason: reason.to_string(),
        },
    }
}

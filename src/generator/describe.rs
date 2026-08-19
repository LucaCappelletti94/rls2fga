//! Derive a [`RecordDescription`] from a [`TupleSource`].
//!
//! Deliberately a second reading of the same shape the renderer reads: one
//! produces SQL for a bulk load, the other structure for one row. They are held
//! together by the differential test, which evaluates every description against
//! the rows its own query returns, so a divergence fails rather than drifts.

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use alloc::collections::BTreeSet;

use crate::classifier::patterns::{ResidualGuard, ResidualPredicates};
use crate::generator::ir::TupleSource;
use crate::generator::model_generator::RowParameter;
use crate::generator::records::{
    BoundQuery, Guard, ObjectKey, RecordContext, RecordContextEntry, RecordDerivation,
    RecordDescription, RecordTemplate, ReplayScope, SubjectKey, ValueSource,
};
use crate::generator::tuple_generator::{
    quote_sql_identifier, render_tuple_source_inner, resolve_bridge_columns, TupleQuery,
};
use crate::generator::tuple_generator::{NameContext, UnboundedColumns};
use crate::generator::well_known::{
    member_relation, owner_team_relation, owner_user_relation, public_relation, HOLDER_OBJECT_ID,
    PG_ROLE_TYPE, TEAM_TYPE, USER_TYPE,
};
use crate::parser::identifiers::{ColumnName, RelationName};
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
    object_key: impl Into<ObjectKey>,
    relation: &RelationName,
    subject_type: &str,
    subject_key: impl Into<SubjectKey>,
    guards: Vec<Guard>,
) -> RecordDescription {
    described(
        table,
        RecordTemplate {
            object_type: object_type.to_string(),
            object_key: object_key.into(),
            relation: relation.clone(),
            subject_type: subject_type.to_string(),
            subject_key: subject_key.into(),
            context: None,
        },
        guards,
    )
}

/// A description of records a template already spells out.
///
/// Takes the template rather than its six fields, since the caller that needs a request
/// context is building one anyway and the fields travelling separately made this the
/// widest signature in the module.
fn described(table: &str, template: RecordTemplate, guards: Vec<Guard>) -> RecordDescription {
    RecordDescription {
        tables: tables(&[table]),
        derivation: RecordDerivation::FromRow {
            table: table.to_string(),
            template: Box::new(template),
            guards,
        },
    }
}

/// Bind the whole-table query to one row, which every joining shape's query ends in a
/// position to accept: each closes with a `WHERE` and a `;`.
///
/// Takes the rendered query rather than its text, so the condition its rows carry cannot
/// be separated from the SQL that projects it.
///
/// `None` for an empty key, since a query bound to nothing names every row.
fn bind(
    query: &TupleQuery,
    table: &str,
    key_columns: &[ColumnName],
    predicate: &str,
    scope: ReplayScope,
) -> Option<BoundQuery> {
    let body = query.sql.strip_suffix(';')?;
    if key_columns.is_empty() || !body.contains("WHERE ") {
        return None;
    }
    // The bound predicate filters rows, so it belongs in the WHERE. An aggregated query
    // ends in GROUP BY, so the predicate goes just before it; a plain query ends in its
    // WHERE, so it goes at the end.
    let sql = match body.split_once("\nGROUP BY ") {
        Some((filter, grouping)) => format!("{filter}\nAND {predicate}\nGROUP BY {grouping};"),
        None => format!("{body}\nAND {predicate};"),
    };
    Some(BoundQuery {
        table: table.to_string(),
        key_columns: key_columns.to_vec(),
        sql,
        condition: query.condition.clone(),
        scope,
    })
}

/// The condition [`bind`] appends: every column compared to its own bound value.
///
/// One equality per column, numbered in order, because a compound key names a row only
/// when all of it is given. The only place a bound condition is spelled, and it escapes
/// through the renderer's own [`quote_sql_identifier`] rather than wrapping the name in
/// quotes, because a column whose stored name carries a `"` is not the column `"a"b"`
/// names and `PostgreSQL` does not parse it.
///
/// `qualifier` is the alias the rendered query gave the table, absent where it gave none.
/// It is a generated alias rather than a schema name, so it needs no escaping.
fn bound_eq(qualifier: Option<&str>, columns: &[ColumnName]) -> String {
    columns
        .iter()
        .enumerate()
        .map(|(index, column)| {
            let quoted = quote_sql_identifier(column.as_str());
            let placeholder = index + 1;
            match qualifier {
                Some(alias) => format!("{alias}.{quoted} = ${placeholder}"),
                None => format!("{quoted} = ${placeholder}"),
            }
        })
        .collect::<Vec<String>>()
        .join(" AND ")
}

/// The whole-table query for this one source, which is what a bound query extends.
///
/// `None` where the renderer stands a comment in place of a query, since a comment
/// loads nothing and there is no text to bind.
fn rendered<DB: DatabaseLike>(
    source: &TupleSource,
    owner_type: &str,
    only_own_rows: bool,
    db: &DB,
) -> Option<TupleQuery> {
    // Rendered per source rather than per schema, so the bounds are resolved locally.
    // `describe` runs once per source too, so this is not on the path the cost probe
    // measures.
    let bounds = UnboundedColumns::resolve(db);
    let query = render_tuple_source_inner(
        source,
        owner_type,
        only_own_rows,
        NameContext::new(&bounds, db),
        db,
    )?;
    (!query.sql.trim_start().starts_with("--")).then_some(query)
}

/// One value source per key column, in declared order.
///
/// A missing part makes [`ObjectKey::render`] yield no record, which is why no
/// description carries a `NOT NULL` guard for a key column: the guard would
/// duplicate that and read as load bearing while guarding nothing.
fn key_parts(pk_cols: &[ColumnName]) -> Vec<ValueSource> {
    pk_cols
        .iter()
        .map(|c| ValueSource::Column(c.clone()))
        .collect()
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
            pk_cols,
            owner_col,
            relation,
        } => Some(from_row(
            table,
            owner_type,
            ObjectKey::new(key_parts(pk_cols)),
            relation,
            USER_TYPE,
            ValueSource::Column(owner_col.clone()),
            vec![Guard::NotNull(owner_col.clone())],
        )),

        // One record per element, and the evaluator drops a null element exactly
        // as `WHERE member IS NOT NULL` does.
        TupleSource::ArrayMembership {
            table,
            pk_cols,
            array_col,
            relation,
        } => Some(from_row(
            table,
            owner_type,
            ObjectKey::new(key_parts(pk_cols)),
            relation,
            USER_TYPE,
            ValueSource::ListElements(array_col.clone()),
            Vec::new(),
        )),

        TupleSource::JsonbFieldOwnership {
            table,
            pk_cols,
            column,
            path,
            relation,
        } => Some(from_row(
            table,
            owner_type,
            ObjectKey::new(key_parts(pk_cols)),
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
            pk_cols,
            owner_col,
            user_table,
            user_pk_col,
        } => Some(joined_ownership(
            &rendered(source, owner_type, only_own_rows, db)?,
            table,
            pk_cols,
            owner_col,
            user_table,
            user_pk_col,
            owner_type,
            USER_TYPE,
            &owner_user_relation(),
            "the owner column has to name a row of the user principal table",
        )),

        TupleSource::RoleOwnerTeam {
            table,
            pk_cols,
            owner_col,
            team_table,
            team_pk_col,
        } => Some(joined_ownership(
            &rendered(source, owner_type, only_own_rows, db)?,
            table,
            pk_cols,
            owner_col,
            team_table,
            team_pk_col,
            owner_type,
            TEAM_TYPE,
            &owner_team_relation(),
            "the owner column has to name a row of the team principal table",
        )),

        TupleSource::ExplicitGrants {
            table,
            pk_cols,
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
            let query = rendered(source, owner_type, only_own_rows, db)?;
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
                        bind(
                            &query,
                            table,
                            pk_cols,
                            &bound_eq(Some("resource"), pk_cols),
                            grant_scope(owner_type, role_cases),
                        ),
                        bind(
                            &query,
                            grant_table,
                            core::slice::from_ref(grant_resource_col),
                            &bound_eq(Some("og"), core::slice::from_ref(grant_resource_col)),
                            grant_scope(owner_type, role_cases),
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
            &member_relation(),
            USER_TYPE,
            ValueSource::Column(user_col.clone()),
            vec![
                Guard::NotNull(team_col.clone()),
                Guard::NotNull(user_col.clone()),
            ],
        )),

        // A residual the row image can evaluate becomes guards, so the
        // records stay a function of one membership row and a delete of that
        // row reports its records as removed. A residual only SQL can
        // evaluate leaves the shape joined, and its query is then what keeps
        // the records current.
        TupleSource::ExistsMembership {
            join_table,
            fk_col,
            user_col,
            parent_type,
            extra_predicates,
            gate,
        } => {
            let mut guards = vec![
                Guard::NotNull(fk_col.clone()),
                Guard::NotNull(user_col.clone()),
            ];
            let Some(gate) = gate else {
                let Some(residual) = residual_guards(extra_predicates) else {
                    let predicate = extra_predicates.sql().unwrap_or_default();
                    let query = rendered(source, owner_type, only_own_rows, db)?;
                    return Some(RecordDescription {
                        tables: tables(&[join_table]),
                        derivation: RecordDerivation::Joined {
                            queries: bind(
                                &query,
                                join_table,
                                core::slice::from_ref(fk_col),
                                &bound_eq(None, core::slice::from_ref(fk_col)),
                                ReplayScope::Object {
                                    object_type: parent_type.clone(),
                                    relations: vec![member_relation()],
                                },
                            )
                            .into_iter()
                            .collect(),
                            reason: format!(
                                "the membership row carries a residual predicate only SQL can \
                                 evaluate: {predicate}"
                            ),
                        },
                    });
                };
                guards.extend(residual);
                return Some(from_row(
                    join_table,
                    parent_type,
                    ValueSource::Column(fk_col.clone()),
                    &member_relation(),
                    USER_TYPE,
                    ValueSource::Column(user_col.clone()),
                    guards,
                ));
            };
            if gate.aggregate {
                // Several rows can key the same (object, user), so the latest deadline is
                // read by querying the changed parent's slice; the row alone cannot say it.
                let query = rendered(source, owner_type, only_own_rows, db)?;
                return Some(RecordDescription {
                    tables: tables(&[join_table]),
                    derivation: RecordDerivation::Joined {
                        queries: bind(
                            &query,
                            join_table,
                            core::slice::from_ref(fk_col),
                            &bound_eq(None, core::slice::from_ref(fk_col)),
                            ReplayScope::Object {
                                object_type: parent_type.clone(),
                                relations: vec![member_relation()],
                            },
                        )
                        .into_iter()
                        .collect(),
                        reason: format!(
                            "several membership rows can grant one (object, user), so the \
                             latest deadline is read by querying: condition {}",
                            gate.condition
                        ),
                    },
                });
            }
            // The clock joined the condition, so the member row alone decides the record:
            // its guards are the residual's row-decidable conjuncts, and each carried column
            // enters the context the check reads the clock against.
            guards.extend(
                extra_predicates
                    .row_guards()
                    .into_iter()
                    .map(guard_from_residual),
            );
            let mut entries = Vec::with_capacity(gate.context.len());
            for column in &gate.context {
                guards.push(Guard::NotNull(column.column.clone()));
                entries.push(RecordContextEntry {
                    key: column.parameter.clone(),
                    value: ValueSource::Column(column.column.clone()),
                });
            }
            Some(described(
                join_table,
                RecordTemplate {
                    object_type: parent_type.clone(),
                    object_key: ObjectKey::new(vec![ValueSource::Column(fk_col.clone())]),
                    relation: member_relation(),
                    subject_type: USER_TYPE.to_string(),
                    subject_key: SubjectKey::column(user_col.clone()),
                    context: Some(RecordContext {
                        condition: gate.condition.clone(),
                        entries,
                    }),
                },
                guards,
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
            let (object_cols, parent_ref_col) = resolve_bridge_columns(table, fk_col, db)?;
            let mut guards: Vec<Guard> = object_cols.iter().cloned().map(Guard::NotNull).collect();
            guards.push(Guard::NotNull(parent_ref_col.clone()));
            Some(from_row(
                table,
                owner_type,
                ObjectKey::new(key_parts(&object_cols)),
                relation,
                parent_type,
                SubjectKey::column(parent_ref_col),
                guards,
            ))
        }

        TupleSource::PublicFlag {
            table,
            pk_cols,
            flag_col,
        } => Some(from_row(
            table,
            owner_type,
            ObjectKey::new(key_parts(pk_cols)),
            &public_relation(),
            USER_TYPE,
            SubjectKey::wildcard(),
            vec![Guard::IsTrue(flag_col.clone())],
        )),

        TupleSource::ConstantTrue { table, pk_cols } => Some(from_row(
            table,
            owner_type,
            ObjectKey::new(key_parts(pk_cols)),
            &public_relation(),
            USER_TYPE,
            SubjectKey::wildcard(),
            Vec::new(),
        )),

        TupleSource::PolicyScope {
            table,
            pk_cols,
            scope_relation,
            pg_role,
        } => Some(from_row(
            table,
            owner_type,
            ObjectKey::new(key_parts(pk_cols)),
            scope_relation,
            PG_ROLE_TYPE,
            ValueSource::Literal(pg_role.clone()),
            Vec::new(),
        )),

        // The guard reaches the description as structure, so the evaluator applies
        // the same comparison the query puts in its WHERE.
        TupleSource::AttributeGate {
            table,
            pk_cols,
            predicate,
        } => Some(from_row(
            table,
            owner_type,
            ObjectKey::new(key_parts(pk_cols)),
            &public_relation(),
            USER_TYPE,
            SubjectKey::wildcard(),
            vec![Guard::Compare(predicate.clone())],
        )),

        // The record is a function of the row alone: the comparison happens
        // at check time, and what the row contributes to it travels in the
        // record's context, exactly as the sibling session-attribute gate
        // carries it.
        TupleSource::ConditionalAttributeGate {
            table,
            pk_cols,
            relation,
            condition,
            row_parameter,
            column,
        } => Some(described(
            table,
            RecordTemplate {
                object_type: owner_type.to_string(),
                object_key: ObjectKey::new(key_parts(pk_cols)),
                relation: relation.clone(),
                subject_type: USER_TYPE.to_string(),
                subject_key: SubjectKey::wildcard(),
                context: Some(RecordContext {
                    condition: condition.clone(),
                    entries: vec![RecordContextEntry {
                        key: row_parameter.clone(),
                        value: ValueSource::Column(column.clone()),
                    }],
                }),
            },
            vec![Guard::NotNull(column.clone())],
        )),

        // The row carries its side of the comparison, so the description carries the
        // same key the tuple SQL puts in the context. The request supplies the rest, and
        // the recipe rather than the record says how the two meet.
        TupleSource::SessionAttributeGate {
            table,
            pk_cols,
            relation,
            row_parameter,
            condition,
            ..
        } => {
            let (value, guards) = match row_parameter {
                // The guard is subsumed: `records_from_row` already yields no record
                // when the context value is missing, so removing it kills no test.
                // Kept only because five sibling shapes state the same guard, and
                // dropping one of six would read as an exception rather than a rule.
                RowParameter::Column { column, .. } => (
                    ValueSource::Column(column.clone()),
                    vec![Guard::NotNull(column.clone())],
                ),
                RowParameter::Literal { value, .. } => {
                    (ValueSource::Literal(value.clone()), Vec::new())
                }
            };
            Some(described(
                table,
                RecordTemplate {
                    object_type: owner_type.to_string(),
                    object_key: ObjectKey::new(key_parts(pk_cols)),
                    relation: relation.clone(),
                    subject_type: USER_TYPE.to_string(),
                    subject_key: SubjectKey::wildcard(),
                    context: Some(RecordContext {
                        condition: condition.clone(),
                        entries: vec![RecordContextEntry {
                            key: row_parameter.parameter().to_string(),
                            value,
                        }],
                    }),
                },
                guards,
            ))
        }

        // The record is a function of the share row alone: the object is keyed on the
        // share's own primary key, and the comparison the request completes travels in
        // the record's context, exactly as the sibling session-attribute gate carries it.
        // A residual only SQL can evaluate leaves the shape joined, and its query is then
        // what keeps the records current.
        TupleSource::CallerSetShareGate {
            join_table,
            pk_cols,
            share_type,
            member_col,
            relation,
            condition,
            row_parameter,
            extra_predicates,
            temporal_context,
            ..
        } => {
            let mut entries = vec![RecordContextEntry {
                key: row_parameter.clone(),
                value: ValueSource::Column(member_col.clone()),
            }];
            let mut guards = vec![Guard::NotNull(member_col.clone())];
            if temporal_context.is_empty() {
                let Some(residual) = residual_guards(extra_predicates) else {
                    let predicate = extra_predicates.sql().unwrap_or_default();
                    let query = rendered(source, owner_type, only_own_rows, db)?;
                    return Some(RecordDescription {
                        tables: tables(&[join_table]),
                        derivation: RecordDerivation::Joined {
                            queries: bind(
                                &query,
                                join_table,
                                pk_cols,
                                &bound_eq(None, pk_cols),
                                ReplayScope::Object {
                                    object_type: share_type.clone(),
                                    relations: vec![relation.clone()],
                                },
                            )
                            .into_iter()
                            .collect(),
                            reason: format!(
                                "the share row carries a residual predicate only SQL can \
                                 evaluate: {predicate}"
                            ),
                        },
                    });
                };
                guards.extend(residual);
            } else {
                // The clock joined the condition, so the row alone decides the record: its
                // guards are the residual's row-decidable conjuncts, and each carried column
                // enters the context beside the member the set compares.
                guards.extend(
                    extra_predicates
                        .row_guards()
                        .into_iter()
                        .map(guard_from_residual),
                );
                for gate in temporal_context {
                    guards.push(Guard::NotNull(gate.column.clone()));
                    entries.push(RecordContextEntry {
                        key: gate.parameter.clone(),
                        value: ValueSource::Column(gate.column.clone()),
                    });
                }
            }
            Some(described(
                join_table,
                RecordTemplate {
                    object_type: share_type.clone(),
                    object_key: ObjectKey::new(key_parts(pk_cols)),
                    relation: relation.clone(),
                    subject_type: USER_TYPE.to_string(),
                    subject_key: SubjectKey::wildcard(),
                    context: Some(RecordContext {
                        condition: condition.clone(),
                        entries,
                    }),
                },
                guards,
            ))
        }

        // Each share row links its guarded object to its own share object, so the record
        // follows from the one join row: the object is the guarded row named by the
        // foreign key, the subject the share named by the join table's own key.
        TupleSource::CallerSetShareBridge {
            join_table,
            fk_col,
            pk_cols,
            guarded_type,
            share_type,
            relation,
        } => {
            // An empty key names no share, so the source produces no records to describe.
            let (first, rest) = pk_cols.split_first()?;
            let mut guards = vec![Guard::NotNull(fk_col.clone())];
            guards.extend(pk_cols.iter().cloned().map(Guard::NotNull));
            Some(from_row(
                join_table,
                guarded_type,
                ObjectKey::new(vec![ValueSource::Column(fk_col.clone())]),
                relation,
                share_type,
                SubjectKey::composite(first, rest),
                guards,
            ))
        }

        // Every row of the table points at the one holder object.
        TupleSource::HolderBridge {
            table,
            pk_cols,
            relation,
            holder_type,
        } => Some(from_row(
            table,
            owner_type,
            ObjectKey::new(key_parts(pk_cols)),
            relation,
            holder_type,
            ValueSource::Literal(HOLDER_OBJECT_ID.to_string()),
            Vec::new(),
        )),

        // The holder is one object, so the object side is fixed and each member row
        // names a user. Two rows naming the same user write one record, which a set
        // of records collapses exactly as the query's DISTINCT does. A residual the
        // row image can evaluate becomes guards, and one only SQL can evaluate
        // leaves the shape joined, its query keeping the records current.
        TupleSource::HolderMembers {
            holder_type,
            member_table,
            user_col,
            extra_predicates,
            gate,
        } => {
            let mut guards = vec![Guard::NotNull(user_col.clone())];
            let Some(gate) = gate else {
                let Some(residual) = residual_guards(extra_predicates) else {
                    let predicate = extra_predicates.sql().unwrap_or_default();
                    let query = rendered(source, owner_type, only_own_rows, db)?;
                    return Some(RecordDescription {
                        tables: tables(&[member_table]),
                        derivation: RecordDerivation::Joined {
                            queries: bind(
                                &query,
                                member_table,
                                core::slice::from_ref(user_col),
                                &bound_eq(None, core::slice::from_ref(user_col)),
                                ReplayScope::Subject {
                                    subject_type: USER_TYPE.to_string(),
                                    relation: member_relation(),
                                    object_type: holder_type.clone(),
                                },
                            )
                            .into_iter()
                            .collect(),
                            reason: format!(
                                "the member row carries a residual predicate only SQL can \
                                 evaluate: {predicate}"
                            ),
                        },
                    });
                };
                guards.extend(residual);
                return Some(from_row(
                    member_table,
                    holder_type,
                    ValueSource::Literal(HOLDER_OBJECT_ID.to_string()),
                    &member_relation(),
                    USER_TYPE,
                    ValueSource::Column(user_col.clone()),
                    guards,
                ));
            };
            if gate.aggregate {
                // Several member rows can name one user with different deadlines, and the
                // holder collapses them, so the latest deadline is read by querying that
                // user's slice rather than settled from one row.
                let query = rendered(source, owner_type, only_own_rows, db)?;
                return Some(RecordDescription {
                    tables: tables(&[member_table]),
                    derivation: RecordDerivation::Joined {
                        queries: bind(
                            &query,
                            member_table,
                            core::slice::from_ref(user_col),
                            &bound_eq(None, core::slice::from_ref(user_col)),
                            ReplayScope::Subject {
                                subject_type: USER_TYPE.to_string(),
                                relation: member_relation(),
                                object_type: holder_type.clone(),
                            },
                        )
                        .into_iter()
                        .collect(),
                        reason: format!(
                            "several member rows can name one user, so the latest deadline is \
                             read by querying: condition {}",
                            gate.condition
                        ),
                    },
                });
            }
            // The clock joined the condition, so the member row alone decides the record.
            guards.extend(
                extra_predicates
                    .row_guards()
                    .into_iter()
                    .map(guard_from_residual),
            );
            let mut entries = Vec::with_capacity(gate.context.len());
            for column in &gate.context {
                guards.push(Guard::NotNull(column.column.clone()));
                entries.push(RecordContextEntry {
                    key: column.parameter.clone(),
                    value: ValueSource::Column(column.column.clone()),
                });
            }
            Some(described(
                member_table,
                RecordTemplate {
                    object_type: holder_type.clone(),
                    object_key: ObjectKey::new(vec![ValueSource::Literal(
                        HOLDER_OBJECT_ID.to_string(),
                    )]),
                    relation: member_relation(),
                    subject_type: USER_TYPE.to_string(),
                    subject_key: SubjectKey::column(user_col.clone()),
                    context: Some(RecordContext {
                        condition: gate.condition.clone(),
                        entries,
                    }),
                },
                guards,
            ))
        }

        TupleSource::Skipped { .. } => None,
    }
}

/// The residual as guards, or [`None`] when any conjunct needs SQL.
fn residual_guards(residuals: &ResidualPredicates) -> Option<Vec<Guard>> {
    residuals
        .guards()
        .map(|guards| guards.into_iter().map(guard_from_residual).collect())
}

/// One residual guard as the record guard that decides it.
fn guard_from_residual(guard: ResidualGuard) -> Guard {
    match guard {
        ResidualGuard::IsTrue(column) => Guard::IsTrue(column),
        ResidualGuard::NotNull(column) => Guard::NotNull(column),
        ResidualGuard::Compare(predicate) => Guard::Compare(predicate),
    }
}

/// The slice an `ExplicitGrants` replay determines: every grant relation on the
/// one resource the bound key names, whichever table the change arrived on.
fn grant_scope(owner_type: &str, role_cases: &[(i32, RelationName, String)]) -> ReplayScope {
    ReplayScope::Object {
        object_type: owner_type.to_string(),
        relations: role_cases
            .iter()
            .map(|(_, relation, _)| relation.clone())
            .collect(),
    }
}

/// The two role-ownership shapes differ only in the principal table they filter
/// against, so one place builds both descriptions.
#[expect(
    clippy::too_many_arguments,
    reason = "one call site per principal kind, and a params struct would be built and \
              destructured in the same breath"
)]
fn joined_ownership(
    query: &TupleQuery,
    table: &str,
    pk_cols: &[ColumnName],
    owner_col: &ColumnName,
    principal_table: &str,
    principal_pk_col: &ColumnName,
    owner_type: &str,
    principal_type: &str,
    relation: &RelationName,
    reason: &str,
) -> RecordDescription {
    RecordDescription {
        tables: tables(&[table, principal_table]),
        derivation: RecordDerivation::Joined {
            queries: [
                bind(
                    query,
                    table,
                    pk_cols,
                    &bound_eq(None, pk_cols),
                    ReplayScope::Object {
                        object_type: owner_type.to_string(),
                        relations: vec![relation.clone()],
                    },
                ),
                bind(
                    query,
                    principal_table,
                    core::slice::from_ref(principal_pk_col),
                    &bound_eq(None, core::slice::from_ref(owner_col)),
                    ReplayScope::Subject {
                        subject_type: principal_type.to_string(),
                        relation: relation.clone(),
                        object_type: owner_type.to_string(),
                    },
                ),
            ]
            .into_iter()
            .flatten()
            .collect(),
            reason: reason.to_string(),
        },
    }
}

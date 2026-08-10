use crate::classifier::patterns::{AttributeLiteral, AttributeOperator};
#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;

#[cfg(test)]
use crate::classifier::patterns::{ClassifiedExpr, PatternClass};
use crate::generator::db_lookup::{resolve_pk_columns, table_has_column};
use crate::generator::identity::{
    typed_name_literal, typed_name_sql, MAX_OBJECT_NAME_CHARS, MAX_SUBJECT_NAME_BYTES,
};
use crate::generator::ir::TupleSource;
use crate::generator::model_generator::RowParameter;
use crate::generator::model_generator::SchemaPlan;
use crate::generator::notes::SkippedTuples;
use crate::generator::records::RecordDescription;
use crate::generator::well_known::{
    ARRAY_ELEMENT_ALIAS, HOLDER_OBJECT_ID, OWNER_TEAM_RELATION, OWNER_USER_RELATION, PG_ROLE_TYPE,
    TEAM_TYPE, USER_TYPE,
};
use crate::parser::names::{
    lookup_table, split_qualified_identifier_parts, split_schema_and_relation,
};
use crate::parser::sql_parser::{ColumnLike, DatabaseLike, TableLike};
use alloc::collections::{BTreeMap, BTreeSet};
use core::fmt::Write;

/// A generated tuple query with its descriptive comment.
#[derive(Debug, Clone)]
pub struct TupleQuery {
    /// Human-readable SQL comment describing what this query populates.
    pub comment: String,
    /// SELECT statement that produces (object, relation, subject) triples.
    pub sql: String,
    /// The same records as structure, so a caller holding one row's values
    /// reaches them without a database. `None` where the query produces no
    /// records, which is the `TODO` placeholder alone.
    pub description: Option<RecordDescription>,
    /// Condition the rows carry, when the query yields the two extra columns a
    /// conditional tuple needs. `None` means three columns and no condition, so a
    /// loader knows the shape without parsing the SQL.
    pub condition: Option<String>,
}

/// Format a list of tuple queries into a single SQL string.
pub fn format_tuples(tuples: &[TupleQuery]) -> String {
    let mut out = String::new();
    for query in tuples {
        out.push_str(&query.comment);
        out.push('\n');
        out.push_str(&query.sql);
        out.push_str("\n\n");
    }
    // Normalise to exactly one trailing newline.
    let trimmed = out.trim_end_matches('\n');
    if trimmed.is_empty() {
        return String::new();
    }
    let mut result = trimmed.to_string();
    result.push('\n');
    result
}

/// Generate tuple SQL queries from a pre-built [`SchemaPlan`].
pub(crate) fn generate_tuple_queries_from_plan<DB: DatabaseLike>(
    plan: &SchemaPlan,
    db: &DB,
) -> Vec<TupleQuery> {
    let mut queries = Vec::new();
    let mut generated: BTreeSet<String> = BTreeSet::new();
    // A query for a relation no permission consults implies the model reads it.
    let grantable = crate::generator::model_generator::grantable_relations(&plan.types);
    // Resolved once for the whole schema: asking per source walked every table.
    let bounds = UnboundedColumns::resolve(db);

    for type_plan in &plan.types {
        for source in &type_plan.table_tuple_sources {
            let fed = source.feeds(&type_plan.type_name);
            if !fed.is_empty() && !fed.iter().any(|target| grantable.contains(target)) {
                continue;
            }
            let key = if source.emits_owner_type_objects() {
                format!("{}|{}", type_plan.type_name, source.dedup_key())
            } else {
                source.dedup_key()
            };
            if !generated.insert(key) {
                continue;
            }
            if let Some(query) = render_tuple_source(
                source,
                &type_plan.type_name,
                type_plan.reads_only_its_own_rows,
                NameContext::new(&bounds, db),
                db,
            ) {
                queries.push(query);
            }
        }
    }

    queries
}

/// What identifies the objects a tuple query produces.
#[derive(Clone, Copy)]
struct ObjectSource<'a> {
    table: &'a str,
    /// `OpenFGA` type the objects belong to.
    type_name: &'a str,
    /// Columns supplying the object identifier, in declared order.
    pk_cols: &'a [String],
    /// Read `FROM ONLY`, keeping inheritance children's rows out.
    only_own_rows: bool,
}

/// Each key column quoted, in declared order.
fn quoted_key_parts(pk_cols: &[String]) -> Vec<String> {
    pk_cols.iter().map(|c| quote_sql_identifier(c)).collect()
}

/// `IS NOT NULL` over every part of a key, and the rendered name fitting the
/// target where a value of that type could overrun it.
///
/// A compound key needs every column present: one NULL part leaves the row with
/// no name, exactly as one NULL column left a single-column row unnamed. The
/// length half falls closed rather than shortening the name, since two rows
/// shortened alike become one object holding both grants.
fn row_is_nameable<DB: DatabaseLike>(
    parts: &[String],
    object_sql: &str,
    table: &str,
    columns: &[String],
    names: NameContext<'_, DB>,
) -> String {
    let mut guard = parts
        .iter()
        .map(|part| format!("{part} IS NOT NULL"))
        .collect::<Vec<_>>()
        .join(" AND ");
    if names.any_unbounded(table, columns) {
        let _ = write!(
            guard,
            " AND length({object_sql}) <= {MAX_OBJECT_NAME_CHARS}"
        );
    }
    guard
}

/// `base` extended with the fit guards for a shape whose names both come from a
/// joined table's columns. Returns the extension alone when `base` is empty.
fn join_row_is_nameable<DB: DatabaseLike>(
    base: &str,
    object_sql: &str,
    subject_sql: Option<&str>,
    table: &str,
    object_columns: &[String],
    subject_columns: &[String],
    names: NameContext<'_, DB>,
) -> String {
    let mut out = base.to_string();
    let mut push = |guard: String| {
        if out.is_empty() {
            out = format!("\nAND {guard}");
        } else {
            let _ = write!(out, "\nAND {guard}");
        }
    };
    if names.any_unbounded(table, object_columns) {
        push(format!("length({object_sql}) <= {MAX_OBJECT_NAME_CHARS}"));
    }
    if let Some(subject_sql) = subject_sql {
        if let Some(guard) = subject_fits(subject_sql, table, subject_columns, names) {
            push(guard);
        }
    }
    out
}

/// The subject name fits the target.
///
/// Bytes rather than characters: the two limits differ in unit, and using one
/// for the other drops a fitting non-ASCII subject or lets an over-long one
/// reach the service.
fn subject_fits<DB: DatabaseLike>(
    subject_sql: &str,
    table: &str,
    columns: &[String],
    names: NameContext<'_, DB>,
) -> Option<String> {
    names
        .any_unbounded(table, columns)
        .then(|| format!("octet_length({subject_sql}) <= {MAX_SUBJECT_NAME_BYTES}"))
}

/// What it takes to judge whether a rendered name fits: the schema's column bounds,
/// resolved once, and the schema itself for the spellings the one-pass map misses.
pub(crate) struct NameContext<'a, DB: DatabaseLike> {
    bounds: &'a UnboundedColumns,
    db: &'a DB,
}

// Written out rather than derived: a derived `Copy` demands `DB: Copy`, which no schema
// is, while the context itself is two references and free to copy whatever `DB` is.
impl<DB: DatabaseLike> Copy for NameContext<'_, DB> {}

#[expect(
    clippy::expl_impl_clone_on_copy,
    reason = "deriving it would add a `DB: Copy` bound the schema cannot satisfy"
)]
impl<DB: DatabaseLike> Clone for NameContext<'_, DB> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, DB: DatabaseLike> NameContext<'a, DB> {
    /// Judge names against `bounds`, falling back to `db` for a spelling it misses.
    pub(crate) const fn new(bounds: &'a UnboundedColumns, db: &'a DB) -> Self {
        Self { bounds, db }
    }

    /// Whether any of `columns` could render a name longer than the target accepts.
    fn any_unbounded(&self, table: &str, columns: &[String]) -> bool {
        self.bounds.any_unbounded(table, columns, self.db)
    }
}

/// Columns whose declared type could render a name longer than the target accepts,
/// resolved once for the whole schema.
///
/// Asked per source it went through `lookup_table`, which walks every table and
/// allocates per comparison, and that turned tuple generation from 2.6ms into 24.9ms
/// at 400 tables. One pass over the tables answers every arm instead.
#[derive(Debug, Default)]
pub(crate) struct UnboundedColumns {
    /// Table spelling to the columns of it no bounded type covers. A table absent
    /// here is unknown rather than bounded, so its guard is emitted.
    by_table: BTreeMap<String, BTreeSet<String>>,
}

impl UnboundedColumns {
    /// Resolve every table's unbounded columns in one pass.
    pub(crate) fn resolve<DB: DatabaseLike>(db: &DB) -> Self {
        let mut by_table: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for table in db.tables() {
            let unbounded: BTreeSet<String> = table
                .columns(db)
                .into_iter()
                .flatten()
                .filter(|c| !is_bounded_short_type(&c.data_type(db).to_lowercase()))
                .map(|c| c.stored_column_name().into_owned())
                .collect();
            // Both spellings a source may carry, so the common case needs no fallback.
            let name = table.stored_table_name().into_owned();
            if let Some(schema) = table.stored_table_schema() {
                by_table.insert(format!("{schema}.{name}"), unbounded.clone());
            }
            by_table.insert(name, unbounded);
        }
        Self { by_table }
    }

    /// Whether any of `columns` could render a name longer than the target accepts.
    ///
    /// A table this cannot resolve answers yes: the guard is added on suspicion
    /// rather than left off on it.
    pub(crate) fn any_unbounded<DB: DatabaseLike>(
        &self,
        table: &str,
        columns: &[String],
        db: &DB,
    ) -> bool {
        let known = self.by_table.get(table).or_else(|| {
            // A spelling the one-pass map does not hold, quoted or qualified another
            // way. Correct but slow, so it is the fallback rather than the path.
            lookup_table(db, table)
                .and_then(|found| self.by_table.get(found.stored_table_name().as_ref()))
        });
        let Some(unbounded) = known else {
            return true;
        };
        columns.iter().any(|column| unbounded.contains(column))
    }
}

/// Types whose text form is short enough that no encoding of them can overrun.
fn is_bounded_short_type(data_type: &str) -> bool {
    matches!(
        data_type,
        "uuid"
            | "boolean"
            | "bool"
            | "smallint"
            | "int2"
            | "integer"
            | "int"
            | "int4"
            | "bigint"
            | "int8"
            | "date"
            | "timestamp"
            | "timestamptz"
            | "timestamp with time zone"
            | "timestamp without time zone"
    )
}

fn render_ownership_tuple_source<DB: DatabaseLike>(
    object: ObjectSource<'_>,
    owner_col: &str,
    relation: &str,
    subject_prefix: &str,
    comment: String,
    owner_filter: Option<(&str, &str)>,
    names: NameContext<'_, DB>,
) -> TupleQuery {
    let ObjectSource {
        table,
        type_name: table_type,
        pk_cols,
        only_own_rows,
    } = object;
    let table_sql = owner_table_reference(table, only_own_rows);
    let pk_parts = quoted_key_parts(pk_cols);
    let owner_col_sql = quote_sql_identifier(owner_col);
    let object_sql = typed_name_sql(table_type, pk_parts.iter().map(String::as_str));
    let subject_sql = typed_name_sql(subject_prefix, [owner_col_sql.as_str()]);

    let owner_cols = [owner_col.to_string()];
    let nameable = row_is_nameable(&pk_parts, &object_sql, table, pk_cols, names);
    let subject_guard = subject_fits(&subject_sql, table, &owner_cols, names)
        .map_or_else(String::new, |guard| format!("\nAND {guard}"));
    let where_clause = if let Some((principal_table, principal_pk_col)) = owner_filter {
        let principal_table_sql = quote_sql_identifier(principal_table);
        let principal_pk_col_sql = quote_sql_identifier(principal_pk_col);
        format!(
            "WHERE {owner_col_sql} IN (SELECT {principal_pk_col_sql} FROM {principal_table_sql})\n\
             AND {owner_col_sql} IS NOT NULL\n\
             AND {nameable}{subject_guard};"
        )
    } else {
        format!("WHERE {owner_col_sql} IS NOT NULL\nAND {nameable}{subject_guard};")
    };

    TupleQuery {
        comment,
        sql: format!(
            "SELECT {object_sql} AS object, '{relation}' AS relation, \
             {subject_sql} AS subject\n\
             FROM {table_sql}\n\
             {where_clause}"
        ),
        description: None,
        condition: None,
    }
}

/// Reduce `text` to a single `--` comment line.
///
/// `PostgreSQL` identifiers may contain newlines and comments interpolate table,
/// column, and role names, so without this the tail of an identifier executes as
/// SQL. A missing `--` marker would do the same, so it is restored.
fn single_comment_line(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 3);
    let mut previous_was_space = false;
    for ch in text.chars() {
        let ch = if ch.is_control() { ' ' } else { ch };
        if ch == ' ' {
            if previous_was_space {
                continue;
            }
            previous_was_space = true;
        } else {
            previous_was_space = false;
        }
        out.push(ch);
    }

    let squeezed = out.trim();
    if squeezed.starts_with("--") {
        squeezed.to_string()
    } else {
        format!("-- {squeezed}")
    }
}

/// Enforce the "comments stay comments" invariant. Every [`TupleQuery`] in the
/// crate passes through here, so new [`TupleSource`] variants inherit it.
fn sanitize_tuple_query(mut query: TupleQuery) -> TupleQuery {
    query.comment = single_comment_line(&query.comment);
    // A `Todo` source renders its body as a comment too; a real query never
    // starts with `--`, so this leaves generated SQL untouched.
    if query.sql.trim_start().starts_with("--") {
        query.sql = single_comment_line(&query.sql);
    }
    query
}

/// Render one [`TupleSource`].
///
/// Variants emitting objects of their own table MUST use `owner_type`: re-deriving
/// a name from `table` files one table's tuples under a colliding table's type.
fn render_tuple_source<DB: DatabaseLike>(
    source: &TupleSource,
    owner_type: &str,
    only_own_rows: bool,
    names: NameContext<'_, DB>,
    db: &DB,
) -> Option<TupleQuery> {
    let mut query = sanitize_tuple_query(render_tuple_source_inner(
        source,
        owner_type,
        only_own_rows,
        names,
        db,
    )?);
    // Every query passes through here, so a new variant reaches the describer
    // rather than silently shipping without a description.
    query.description =
        crate::generator::describe::describe_tuple_source(source, owner_type, only_own_rows, db);
    Some(query)
}

pub(crate) fn render_tuple_source_inner<DB: DatabaseLike>(
    source: &TupleSource,
    owner_type: &str,
    only_own_rows: bool,
    names: NameContext<'_, DB>,
    db: &DB,
) -> Option<TupleQuery> {
    match source {
        TupleSource::DirectOwnership {
            table,
            pk_cols,
            owner_col,
            relation,
        } => Some(render_ownership_tuple_source(
            ObjectSource {
                table,
                type_name: owner_type,
                pk_cols,
                only_own_rows,
            },
            owner_col,
            relation,
            USER_TYPE,
            format!("-- User ownership ({owner_col} references users)"),
            None,
            names,
        )),

        TupleSource::ArrayMembership {
            table,
            pk_cols,
            array_col,
            relation,
        } => {
            let table_sql = owner_table_reference(table, only_own_rows);
            let pk_parts = quoted_key_parts(pk_cols);
            let array_col_sql = quote_sql_identifier(array_col);
            let object_sql = typed_name_sql(owner_type, pk_parts.iter().map(String::as_str));
            let subject_sql = typed_name_sql(USER_TYPE, [ARRAY_ELEMENT_ALIAS]);
            let nameable = row_is_nameable(&pk_parts, &object_sql, table, pk_cols, names);
            let subject_guard =
                subject_fits(&subject_sql, table, core::slice::from_ref(array_col), names)
                    .map_or_else(String::new, |guard| format!("\nAND {guard}"));
            Some(TupleQuery {
                comment: format!("-- Array membership (elements of {array_col} reference users)"),
                sql: format!(
                    "SELECT {object_sql} AS object, '{relation}' AS relation, \
                     {subject_sql} AS subject\n\
                     FROM {table_sql}\n\
                     CROSS JOIN UNNEST({array_col_sql}) AS {ARRAY_ELEMENT_ALIAS}\n\
                     WHERE {ARRAY_ELEMENT_ALIAS} IS NOT NULL\n\
                     AND {nameable}{subject_guard};"
                ),
                description: None,
                condition: None,
            })
        }

        TupleSource::JsonbFieldOwnership {
            table,
            pk_cols,
            column,
            path,
            relation,
        } => {
            let table_sql = owner_table_reference(table, only_own_rows);
            let pk_parts = quoted_key_parts(pk_cols);
            let field_sql = render_jsonb_path(&quote_sql_identifier(column), path)?;
            let object_sql = typed_name_sql(owner_type, pk_parts.iter().map(String::as_str));
            let field_operand = format!("({field_sql})");
            let subject_sql = typed_name_sql(USER_TYPE, [field_operand.as_str()]);
            let nameable = row_is_nameable(&pk_parts, &object_sql, table, pk_cols, names);
            let subject_guard =
                subject_fits(&subject_sql, table, core::slice::from_ref(column), names)
                    .map_or_else(String::new, |guard| format!("\nAND {guard}"));
            Some(TupleQuery {
                comment: format!(
                    "-- Jsonb field ownership ({column} -> {} references users)",
                    path.join(" -> ")
                ),
                sql: format!(
                    "SELECT {object_sql} AS object, '{relation}' AS relation, \
                     {subject_sql} AS subject\n\
                     FROM {table_sql}\n\
                     WHERE ({field_sql}) IS NOT NULL\n\
                     AND {nameable}{subject_guard};"
                ),
                description: None,
                condition: None,
            })
        }

        TupleSource::RoleOwnerUser {
            table,
            pk_cols,
            owner_col,
            user_table,
            user_pk_col,
        } => Some(render_ownership_tuple_source(
            ObjectSource {
                table,
                type_name: owner_type,
                pk_cols,
                only_own_rows,
            },
            owner_col,
            OWNER_USER_RELATION,
            USER_TYPE,
            format!("-- User ownership ({owner_col} references {user_table})"),
            Some((user_table, user_pk_col)),
            names,
        )),

        TupleSource::RoleOwnerTeam {
            table,
            pk_cols,
            owner_col,
            team_table,
            team_pk_col,
        } => Some(render_ownership_tuple_source(
            ObjectSource {
                table,
                type_name: owner_type,
                pk_cols,
                only_own_rows,
            },
            owner_col,
            OWNER_TEAM_RELATION,
            TEAM_TYPE,
            format!("-- Team ownership ({owner_col} references {team_table})"),
            Some((team_table, team_pk_col)),
            names,
        )),

        TupleSource::ExplicitGrants {
            table,
            pk_cols,
            grant_join_col,
            grant_table,
            grant_role_col,
            grant_grantee_col,
            grant_resource_col,
            role_cases,
            user_principal,
            team_principal,
        } => {
            if role_cases.is_empty() {
                return None;
            }
            let table_type = owner_type;
            let table_sql = owner_table_reference(table, only_own_rows);
            let pk_parts = quoted_key_parts(pk_cols);
            let grant_join_col_sql = quote_sql_identifier(grant_join_col);
            let grant_table_sql = quote_sql_identifier(grant_table);
            let grant_role_col_sql = quote_sql_identifier(grant_role_col);
            let grant_grantee_col_sql = quote_sql_identifier(grant_grantee_col);
            let grant_resource_col_sql = quote_sql_identifier(grant_resource_col);

            let case_arms: Vec<String> = role_cases
                .iter()
                .map(|(level, grant_rel, _)| format!("    WHEN {level} THEN '{grant_rel}'"))
                .collect();

            let role_ids: Vec<String> = role_cases
                .iter()
                .map(|(level, _, _)| level.to_string())
                .collect();
            let comment_roles: Vec<String> = role_cases
                .iter()
                .map(|(level, _, original)| format!("{level}={original}"))
                .collect();

            let case_expr = format!(
                "CASE og.{grant_role_col_sql}\n{}\n  END",
                case_arms.join("\n")
            );

            let grantee_ref = format!("og.{grant_grantee_col_sql}");
            let user_subject_sql = typed_name_sql(USER_TYPE, [grantee_ref.as_str()]);
            let team_subject_sql = typed_name_sql(TEAM_TYPE, [grantee_ref.as_str()]);
            let resource_refs: Vec<String> = pk_parts
                .iter()
                .map(|part| format!("resource.{part}"))
                .collect();
            let object_sql = typed_name_sql(table_type, resource_refs.iter().map(String::as_str));
            let mut subject_joins: Vec<String> = Vec::new();
            let mut principal_filter: Option<String> = None;
            let subject_expr = match (user_principal.as_ref(), team_principal.as_ref()) {
                (Some(up), Some(tp)) => {
                    let user_tbl_sql = quote_sql_identifier(&up.table);
                    let user_pk_sql = quote_sql_identifier(&up.pk_col);
                    let team_tbl_sql = quote_sql_identifier(&tp.table);
                    let team_pk_sql = quote_sql_identifier(&tp.pk_col);
                    subject_joins.push(format!(
                        "LEFT JOIN {user_tbl_sql} u ON u.{user_pk_sql} = og.{grant_grantee_col_sql}"
                    ));
                    subject_joins.push(format!(
                        "LEFT JOIN {team_tbl_sql} t ON t.{team_pk_sql} = og.{grant_grantee_col_sql}"
                    ));
                    principal_filter = Some(format!(
                        "(u.{user_pk_sql} IS NOT NULL OR t.{team_pk_sql} IS NOT NULL)"
                    ));
                    format!(
                        "CASE\n\
                         \x20   WHEN u.{user_pk_sql} IS NOT NULL THEN {user_subject_sql}\n\
                         \x20   WHEN t.{team_pk_sql} IS NOT NULL THEN {team_subject_sql}\n\
                         \x20 END"
                    )
                }
                (Some(_), None) => user_subject_sql.clone(),
                (None, Some(tp)) => {
                    let team_tbl_sql = quote_sql_identifier(&tp.table);
                    let team_pk_sql = quote_sql_identifier(&tp.pk_col);
                    subject_joins.push(format!(
                        "JOIN {team_tbl_sql} t ON t.{team_pk_sql} = og.{grant_grantee_col_sql}"
                    ));
                    format!("'team:' || og.{grant_grantee_col_sql}")
                }
                (None, None) => {
                    // Fail closed: neither user nor team principal could be resolved.
                    return Some(skipped_query(&SkippedTuples::NoPrincipalTypeForGrants {
                        grant_table: grant_table.clone(),
                    }));
                }
            };

            let subject_join_sql = if subject_joins.is_empty() {
                String::new()
            } else {
                format!("{}\n", subject_joins.join("\n                 "))
            };
            let mut where_predicates = vec![format!(
                "og.{grant_role_col_sql} IN ({})",
                role_ids.join(", ")
            )];
            if let Some(filter) = principal_filter {
                where_predicates.push(filter);
            }

            Some(TupleQuery {
                comment: format!(
                    "-- Explicit grants expanded to {table} rows ({grant_role_col}: {})",
                    comment_roles.join(", ")
                ),
                sql: format!(
                    "SELECT\n\
                     \x20 {object_sql} AS object,\n\
                     \x20 {case_expr} AS relation,\n\
                     \x20 {subject_expr} AS subject\n\
                     FROM {grant_table_sql} og\n\
                     JOIN {table_sql} resource ON resource.{grant_join_col_sql} = og.{grant_resource_col_sql}\n\
                     {subject_join_sql}\
                     WHERE {};",
                    where_predicates.join("\nAND ")
                ),
                description: None,
                condition: None,
            })
        }

        TupleSource::TeamMembership {
            membership_table,
            team_col,
            user_col,
        } => {
            let membership_table_sql = quote_sql_identifier(membership_table);
            let team_col_sql = quote_sql_identifier(team_col);
            let user_col_sql = quote_sql_identifier(user_col);
            let object_sql = typed_name_sql(TEAM_TYPE, [team_col_sql.as_str()]);
            let subject_sql = typed_name_sql(USER_TYPE, [user_col_sql.as_str()]);
            let team_guards = join_row_is_nameable(
                "",
                &object_sql,
                Some(&subject_sql),
                membership_table,
                core::slice::from_ref(team_col),
                core::slice::from_ref(user_col),
                names,
            );
            Some(TupleQuery {
                comment: "-- Team memberships".to_string(),
                sql: format!(
                    "SELECT {object_sql} AS object, 'member' AS relation, \
                     {subject_sql} AS subject\n\
                     FROM {membership_table_sql}\n\
                     WHERE {team_col_sql} IS NOT NULL\n\
                     AND {user_col_sql} IS NOT NULL{team_guards};"
                ),
                description: None,
                condition: None,
            })
        }

        TupleSource::ExistsMembership {
            join_table,
            fk_col,
            user_col,
            parent_type,
            extra_predicate_sql,
        } => {
            let join_table_sql = quote_sql_identifier(join_table);
            let fk_col_sql = quote_sql_identifier(fk_col);
            let user_col_sql = quote_sql_identifier(user_col);
            // The extra predicate joins a conjunction of NULL guards, so it is
            // parenthesised: a disjunction would otherwise break out of the AND.
            let null_guards = format!("{fk_col_sql} IS NOT NULL AND {user_col_sql} IS NOT NULL");
            let object_sql = typed_name_sql(parent_type, [fk_col_sql.as_str()]);
            let subject_sql = typed_name_sql(USER_TYPE, [user_col_sql.as_str()]);
            let null_guards = join_row_is_nameable(
                &null_guards,
                &object_sql,
                Some(&subject_sql),
                join_table,
                core::slice::from_ref(fk_col),
                core::slice::from_ref(user_col),
                names,
            );
            let where_clause = extra_predicate_sql.as_ref().map_or_else(
                || format!("\nWHERE {null_guards}"),
                |e| format!("\nWHERE {null_guards}\nAND ({e})"),
            );
            Some(TupleQuery {
                comment: format!("-- {parent_type} membership from {join_table}"),
                sql: format!(
                    "SELECT {object_sql} AS object, 'member' AS relation, \
                     {subject_sql} AS subject\n\
                     FROM {join_table_sql}{where_clause};"
                ),
                description: None,
                condition: None,
            })
        }

        // The facts are read from the join table while the objects are named after the
        // parent, so one membership row grants one parent object, conditionally.
        TupleSource::SessionAttributeMembershipGate {
            join_table,
            fk_col,
            member_col,
            parent_type,
            relation,
            condition,
            row_parameter,
            extra_predicate_sql,
            ..
        } => {
            let join_table_sql = quote_sql_identifier(join_table);
            let fk_col_sql = quote_sql_identifier(fk_col);
            let member_col_sql = quote_sql_identifier(member_col);
            let parameter_sql = quote_sql_string_literal(row_parameter);
            let null_guards = format!("{fk_col_sql} IS NOT NULL AND {member_col_sql} IS NOT NULL");
            let object_sql = typed_name_sql(parent_type, [fk_col_sql.as_str()]);
            let null_guards = join_row_is_nameable(
                &null_guards,
                &object_sql,
                None,
                join_table,
                core::slice::from_ref(fk_col),
                &[],
                names,
            );
            let where_clause = extra_predicate_sql.as_ref().map_or_else(
                || format!("\nWHERE {null_guards}"),
                |e| format!("\nWHERE {null_guards}\nAND ({e})"),
            );
            Some(TupleQuery {
                comment: format!(
                    "-- Request-scoped gate on {parent_type} carrying {join_table}.{member_col}, \
                     evaluated by condition {condition}"
                ),
                sql: format!(
                    "SELECT {object_sql} AS object, '{relation}' AS relation, \
                     'user:*' AS subject,\n\
                     \x20 '{condition}' AS condition, \
                     jsonb_build_object({parameter_sql}, {member_col_sql}::text) AS context\n\
                     FROM {join_table_sql}{where_clause};"
                ),
                description: None,
                condition: Some(condition.clone()),
            })
        }

        TupleSource::HolderMembers {
            holder_type,
            member_table,
            user_col,
            extra_predicate_sql,
        } => {
            let member_table_sql = quote_sql_identifier(member_table);
            let user_col_sql = quote_sql_identifier(user_col);
            let object_sql = typed_name_literal(holder_type, HOLDER_OBJECT_ID);
            let subject_sql = typed_name_sql(USER_TYPE, [user_col_sql.as_str()]);
            let user_col_sql_guard = subject_fits(
                &subject_sql,
                member_table,
                core::slice::from_ref(user_col),
                names,
            )
            .map_or_else(String::new, |guard| format!("\nAND {guard}"));
            // DISTINCT because the holder is one object: two membership rows for the
            // same user would otherwise write the same tuple twice.
            let where_clause = extra_predicate_sql.as_ref().map_or_else(
                || format!("\nWHERE {user_col_sql} IS NOT NULL{user_col_sql_guard}"),
                |e| format!("\nWHERE {user_col_sql} IS NOT NULL{user_col_sql_guard}\nAND ({e})"),
            );
            Some(TupleQuery {
                comment: format!("-- Everyone listed in {member_table}, held by {holder_type}"),
                sql: format!(
                    "SELECT DISTINCT {object_sql} AS object, \
                     'member' AS relation, {subject_sql} AS subject\n\
                     FROM {member_table_sql}{where_clause};"
                ),
                description: None,
                condition: None,
            })
        }

        TupleSource::HolderBridge {
            table,
            pk_cols,
            relation,
            holder_type,
        } => {
            let table_type = owner_type;
            let table_sql = owner_table_reference(table, only_own_rows);
            let pk_parts = quoted_key_parts(pk_cols);
            let object_sql = typed_name_sql(table_type, pk_parts.iter().map(String::as_str));
            let key_not_null = row_is_nameable(&pk_parts, &object_sql, table, pk_cols, names);
            let subject_sql = typed_name_literal(holder_type, HOLDER_OBJECT_ID);
            Some(TupleQuery {
                comment: format!("-- Every {table} row points at the {holder_type} holder"),
                sql: format!(
                    "SELECT {object_sql} AS object, '{relation}' AS relation, \
                     {subject_sql} AS subject\n\
                     FROM {table_sql}\n\
                     WHERE {key_not_null};"
                ),
                description: None,
                condition: None,
            })
        }

        TupleSource::ParentBridge {
            table,
            fk_col,
            parent_type,
            relation,
        } => {
            let table_type = owner_type;
            let Some((object_cols, parent_ref_col)) = resolve_bridge_columns(table, fk_col, db)
            else {
                return Some(skipped_query(&SkippedTuples::BridgeColumnMissing {
                    table: table.clone(),
                    parent_type: parent_type.clone(),
                    fk_col: fk_col.clone(),
                }));
            };
            let table_sql = owner_table_reference(table, only_own_rows);
            let object_parts = quoted_key_parts(&object_cols);
            let parent_ref_col_sql = quote_sql_identifier(&parent_ref_col);
            let object_sql = typed_name_sql(table_type, object_parts.iter().map(String::as_str));
            let subject_sql = typed_name_sql(parent_type, [parent_ref_col_sql.as_str()]);
            let bridge_guards = join_row_is_nameable(
                "",
                &object_sql,
                Some(&subject_sql),
                table,
                &object_cols,
                core::slice::from_ref(&parent_ref_col),
                names,
            );
            let object_not_null = object_parts
                .iter()
                .map(|part| format!("{part} IS NOT NULL"))
                .collect::<Vec<_>>()
                .join("\nAND ");
            Some(TupleQuery {
                comment: format!("-- {table} to {parent_type} bridge for tuple-to-userset"),
                sql: format!(
                    "SELECT {object_sql} AS object, \
                     '{relation}' AS relation, \
                     {subject_sql} AS subject\n\
                     FROM {table_sql}\n\
                     WHERE {object_not_null}\n\
                     AND {parent_ref_col_sql} IS NOT NULL{bridge_guards};"
                ),
                description: None,
                condition: None,
            })
        }

        TupleSource::PublicFlag {
            table,
            pk_cols,
            flag_col,
        } => {
            let table_type = owner_type;
            let table_sql = owner_table_reference(table, only_own_rows);
            let pk_parts = quoted_key_parts(pk_cols);
            let object_sql = typed_name_sql(table_type, pk_parts.iter().map(String::as_str));
            let key_not_null = row_is_nameable(&pk_parts, &object_sql, table, pk_cols, names);
            let flag_col_sql = quote_sql_identifier(flag_col);
            Some(TupleQuery {
                comment: format!("-- Public access flag ({flag_col})"),
                sql: format!(
                    "SELECT {object_sql} AS object, 'public_viewer' AS relation, \
                     'user:*' AS subject\n\
                     FROM {table_sql}\n\
                     WHERE {key_not_null}\n\
                     AND {flag_col_sql} = TRUE;"
                ),
                description: None,
                condition: None,
            })
        }

        TupleSource::AttributeGate {
            table,
            pk_cols,
            predicate,
        } => {
            let table_type = owner_type;
            let table_sql = owner_table_reference(table, only_own_rows);
            let pk_parts = quoted_key_parts(pk_cols);
            let object_sql = typed_name_sql(table_type, pk_parts.iter().map(String::as_str));
            let key_not_null = row_is_nameable(&pk_parts, &object_sql, table, pk_cols, names);
            let column_sql = quote_sql_identifier(&predicate.column);
            let operator = render_attribute_operator(predicate.operator);
            let value_sql = render_attribute_literal(&predicate.value);
            Some(TupleQuery {
                comment: format!(
                    "-- Attribute gate ({} {operator} {value_sql})",
                    predicate.column
                ),
                sql: format!(
                    "SELECT {object_sql} AS object, 'public_viewer' AS relation, \
                     'user:*' AS subject\n\
                     FROM {table_sql}\n\
                     WHERE {key_not_null}\n\
                     AND {column_sql} {operator} {value_sql};"
                ),
                description: None,
                condition: None,
            })
        }

        // Five columns, not three: the loader needs the condition name and the context
        // the row supplies, since the service cannot know either from the tuple alone.
        TupleSource::ConditionalAttributeGate {
            table,
            pk_cols,
            relation,
            condition,
            row_parameter,
            column,
        } => {
            let table_type = owner_type;
            let table_sql = owner_table_reference(table, only_own_rows);
            let pk_parts = quoted_key_parts(pk_cols);
            let object_sql = typed_name_sql(table_type, pk_parts.iter().map(String::as_str));
            let key_not_null = row_is_nameable(&pk_parts, &object_sql, table, pk_cols, names);
            let column_sql = quote_sql_identifier(column);
            let parameter_sql = quote_sql_string_literal(row_parameter);
            Some(TupleQuery {
                comment: format!(
                    "-- Request-time gate on {column}, evaluated by condition {condition}"
                ),
                sql: format!(
                    "SELECT {object_sql} AS object, '{relation}' AS relation, \
                     'user:*' AS subject,\n\
                     \x20 '{condition}' AS condition, \
                     jsonb_build_object({parameter_sql}, {column_sql}) AS context\n\
                     FROM {table_sql}\n\
                     WHERE {key_not_null}\n\
                     AND {column_sql} IS NOT NULL;"
                ),
                description: None,
                condition: Some(condition.clone()),
            })
        }

        TupleSource::SessionAttributeGate {
            table,
            pk_cols,
            relation,
            condition,
            row_parameter,
            ..
        } => {
            let table_type = owner_type;
            let table_sql = owner_table_reference(table, only_own_rows);
            let pk_parts = quoted_key_parts(pk_cols);
            let object_sql = typed_name_sql(table_type, pk_parts.iter().map(String::as_str));
            let key_not_null = row_is_nameable(&pk_parts, &object_sql, table, pk_cols, names);
            let parameter_sql = quote_sql_string_literal(row_parameter.parameter());
            // A NULL row value matches nothing in PostgreSQL, so it needs no tuple.
            let (carried_sql, carried_filter, what) = match row_parameter {
                RowParameter::Column { column, .. } => {
                    let column_sql = quote_sql_identifier(column);
                    (
                        format!("{column_sql}::text"),
                        format!("\nAND {column_sql} IS NOT NULL"),
                        format!("the row's {column}"),
                    )
                }
                RowParameter::Literal { value, .. } => (
                    quote_sql_string_literal(value),
                    String::new(),
                    format!("the constant {value}"),
                ),
            };
            Some(TupleQuery {
                comment: format!(
                    "-- Request-scoped gate carrying {what}, evaluated by condition {condition}"
                ),
                sql: format!(
                    "SELECT {object_sql} AS object, '{relation}' AS relation, \
                     'user:*' AS subject,\n\
                     \x20 '{condition}' AS condition, \
                     jsonb_build_object({parameter_sql}, {carried_sql}) AS context\n\
                     FROM {table_sql}\n\
                     WHERE {key_not_null}{carried_filter};"
                ),
                description: None,
                condition: Some(condition.clone()),
            })
        }

        TupleSource::ConstantTrue { table, pk_cols } => {
            let table_type = owner_type;
            let table_sql = owner_table_reference(table, only_own_rows);
            let pk_parts = quoted_key_parts(pk_cols);
            let object_sql = typed_name_sql(table_type, pk_parts.iter().map(String::as_str));
            let key_not_null = row_is_nameable(&pk_parts, &object_sql, table, pk_cols, names);
            Some(TupleQuery {
                comment: "-- Constant TRUE policy (all rows are visible)".to_string(),
                sql: format!(
                    "SELECT {object_sql} AS object, 'public_viewer' AS relation, \
                     'user:*' AS subject\n\
                     FROM {table_sql}\n\
                     WHERE {key_not_null};"
                ),
                description: None,
                condition: None,
            })
        }

        TupleSource::PolicyScope {
            table,
            pk_cols,
            scope_relation,
            pg_role,
        } => {
            let table_type = owner_type;
            let table_sql = owner_table_reference(table, only_own_rows);
            let pk_parts = quoted_key_parts(pk_cols);
            let object_sql = typed_name_sql(table_type, pk_parts.iter().map(String::as_str));
            let key_not_null = row_is_nameable(&pk_parts, &object_sql, table, pk_cols, names);
            let subject_sql = typed_name_literal(PG_ROLE_TYPE, pg_role);
            Some(TupleQuery {
                comment: format!(
                    "-- Policy scope: {table} rows require PostgreSQL role '{pg_role}' \
                     via {scope_relation}"
                ),
                sql: format!(
                    "SELECT {object_sql} AS object, \
                     '{scope_relation}' AS relation, \
                     {subject_sql} AS subject\n\
                     FROM {table_sql}\n\
                     WHERE {key_not_null};"
                ),
                description: None,
                condition: None,
            })
        }

        TupleSource::Skipped { reason } => Some(skipped_query(reason)),
    }
}

/// The two comment lines that stand where a tuple query could not be built.
fn skipped_query(reason: &SkippedTuples) -> TupleQuery {
    TupleQuery {
        comment: reason.comment(),
        sql: reason.body(),
        description: None,
        condition: None,
    }
}

/// The columns naming the bridge's two ends: every column identifying a row of `table`,
/// and the one whose value names the parent.
///
/// The parent side stays a single column because a subject is named by one value.
pub(crate) fn resolve_bridge_columns<DB: DatabaseLike>(
    table: &str,
    fk_column: &str,
    db: &DB,
) -> Option<(Vec<String>, String)> {
    let object_cols = resolve_pk_columns(table, db)?;
    if table_has_column(db, table, fk_column) {
        return Some((object_cols, fk_column.to_string()));
    }

    // The FK column isn't a real column of this table, but the inferred parent
    // type matches the table's own name.  Emit the sentinel self-reference tuple
    // (`project:X  project  project:X`) that OpenFGA needs for tuple-to-userset
    // when the membership table FK points back to the same resource type. It names
    // the parent by the row's own key, so it needs that key to be one column.
    match object_cols.as_slice() {
        [object_col] if is_self_parent_bridge(table, fk_column) => {
            Some((vec![object_col.clone()], object_col.clone()))
        }
        _ => None,
    }
}

fn is_self_parent_bridge(table: &str, fk_column: &str) -> bool {
    let parent_type = fk_column.strip_suffix("_id").unwrap_or(fk_column);
    let relation = split_schema_and_relation(table)
        .map_or_else(|| table.to_string(), |(_, relation)| relation);
    let relation = relation.to_ascii_lowercase();
    let parent_type = parent_type.to_ascii_lowercase();
    singular_candidates(&relation)
        .iter()
        .any(|candidate| candidate == &parent_type)
}

fn singular_candidates(relation: &str) -> Vec<String> {
    let mut candidates = vec![relation.to_string()];

    if let Some(stem) = relation.strip_suffix("ies") {
        if !stem.is_empty() {
            candidates.push(format!("{stem}y"));
        }
    }
    if let Some(stem) = relation.strip_suffix("es") {
        if !stem.is_empty() {
            candidates.push(stem.to_string());
        }
    }
    if let Some(stem) = relation.strip_suffix('s') {
        if !stem.is_empty() {
            candidates.push(stem.to_string());
        }
    }

    candidates.sort();
    candidates.dedup();
    candidates
}

/// The `FROM` reference for a query minting this type's objects.
///
/// `ONLY` keeps inheritance children's rows out, since the parent's key does not
/// span them and a shared key value would merge two rows into one object.
fn owner_table_reference(table: &str, only_own_rows: bool) -> String {
    let quoted = quote_sql_identifier(table);
    if only_own_rows {
        format!("ONLY {quoted}")
    } else {
        quoted
    }
}
fn quote_sql_identifier(identifier: &str) -> String {
    split_qualified_identifier_parts(identifier)
        .into_iter()
        .map(|part| quote_sql_identifier_part(&part))
        .collect::<Vec<_>>()
        .join(".")
}

fn quote_sql_identifier_part(part: &str) -> String {
    let trimmed = part.trim();
    if trimmed.is_empty() {
        return "\"\"".to_string();
    }
    // Strip pre-existing outer quotes and re-escape through the normal path.
    // This prevents pre-quoted strings from bypassing validation (e.g. a
    // function_registry.json entry containing `"foo" OR 1=1--`).
    let raw = if trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2 {
        trimmed[1..trimmed.len() - 1].replace("\"\"", "\"")
    } else {
        trimmed.to_string()
    };
    // Always double-quote the identifier: this is semantically equivalent to unquoted
    // lowercase identifiers and avoids the need for an ever-growing reserved-keyword list.
    format!("\"{}\"", raw.replace('"', "\"\""))
}

/// Quote `value` as a SQL string literal.
///
/// With `standard_conforming_strings` on, which `PostgreSQL` has defaulted to since 9.1,
/// a backslash is an ordinary character and doubling the quote is the whole escape.
fn quote_sql_string_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// SQL spelling of an attribute guard's comparison.
fn render_attribute_operator(operator: AttributeOperator) -> &'static str {
    match operator {
        AttributeOperator::Eq => "=",
        AttributeOperator::NotEq => "<>",
        AttributeOperator::Gt => ">",
        AttributeOperator::GtEq => ">=",
        AttributeOperator::Lt => "<",
        AttributeOperator::LtEq => "<=",
    }
}

/// SQL spelling of the literal an attribute guard compares against.
///
/// A number keeps its source spelling, so `priority >= 3` compares against `3` rather
/// than a reformatted value, and the column's own type decides the comparison.
fn render_attribute_literal(value: &AttributeLiteral) -> String {
    match value {
        AttributeLiteral::Text(text) => quote_sql_string_literal(text),
        AttributeLiteral::Number(number) => number.clone(),
        AttributeLiteral::Boolean(flag) => {
            if *flag {
                "TRUE".to_string()
            } else {
                "FALSE".to_string()
            }
        }
    }
}

/// Render a jsonb key chain as an extraction expression on `column_sql`, the last hop
/// as `->>` so the result is text rather than a quoted JSON string.
fn render_jsonb_path(column_sql: &str, path: &[String]) -> Option<String> {
    let (last, leading) = path.split_last()?;
    let mut out = column_sql.to_string();
    for key in leading {
        out.push_str(" -> ");
        out.push_str(&quote_sql_string_literal(key));
    }
    out.push_str(" ->> ");
    out.push_str(&quote_sql_string_literal(last));
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classifier::function_registry::FunctionRegistry;
    use crate::classifier::patterns::{ClassifiedPolicy, ConfidenceLevel};
    use crate::generator::model_generator::GeneratorSettings;
    use crate::parser::names::policy_scope_relation_name;
    use crate::parser::sql_parser::{parse_schema, DatabaseLike};
    use crate::translator::Translation;

    #[test]
    fn format_tuples_ends_with_exactly_one_newline() {
        let tuples = vec![
            TupleQuery {
                comment: "-- one".to_string(),
                sql: "SELECT 1;".to_string(),
                description: None,
                condition: None,
            },
            TupleQuery {
                comment: "-- two".to_string(),
                sql: "SELECT 2;".to_string(),
                description: None,
                condition: None,
            },
        ];
        let formatted = format_tuples(&tuples);
        // Must end with exactly one newline after the last SQL statement.
        assert!(formatted.ends_with("SELECT 2;\n"));
        assert!(!formatted.ends_with("SELECT 2;\n\n"));
    }

    #[test]
    fn format_tuples_empty_input_returns_empty_string() {
        assert_eq!(format_tuples(&[]), String::new());
    }

    #[test]
    fn resolve_bridge_columns_covers_safe_and_skip_paths() {
        let db = parse_schema(
            r"
CREATE TABLE docs(id uuid primary key, project_id uuid);
CREATE TABLE links(resource_uuid uuid, project_uuid uuid);
CREATE TABLE projects(id uuid primary key);
CREATE TABLE status(status uuid primary key);
CREATE TABLE events(label text, event_uuid uuid primary key, project_id uuid);
CREATE TABLE categories(id uuid primary key);
",
        )
        .expect("schema should parse");

        assert_eq!(resolve_bridge_columns("missing", "project_id", &db), None);
        assert_eq!(
            resolve_bridge_columns("docs", "project_id", &db),
            Some((vec!["id".to_string()], "project_id".to_string()))
        );
        // Sentinel self-reference: fk_col not in table columns but parent type
        // matches table name → used for OpenFGA tuple-to-userset navigation.
        assert_eq!(
            resolve_bridge_columns("projects", "project_id", &db),
            Some((vec!["id".to_string()], "id".to_string()))
        );
        assert_eq!(
            resolve_bridge_columns("status", "status_id", &db),
            Some((vec!["status".to_string()], "status".to_string()))
        );
        assert_eq!(
            resolve_bridge_columns("events", "project_id", &db),
            Some((vec!["event_uuid".to_string()], "project_id".to_string()))
        );
        assert_eq!(
            resolve_bridge_columns("categories", "category_id", &db),
            Some((vec!["id".to_string()], "id".to_string()))
        );
        assert_eq!(resolve_bridge_columns("links", "project_id", &db), None);
    }

    #[test]
    fn generate_tuple_queries_reads_using_and_with_check() {
        let db = parse_schema(
            r"
CREATE TABLE docs(id uuid primary key, owner_id uuid, is_public boolean);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
-- FOR ALL so the USING clause also grants reads, without which nothing is reachable.
CREATE POLICY docs_update ON docs FOR ALL
  USING (owner_id = current_user)
  WITH CHECK (owner_id = current_user);
",
        )
        .expect("schema should parse");

        let policy = db.policies().next().expect("policy should exist");
        let mut classified = ClassifiedPolicy::from_policy(policy, &db);
        classified.using_classification = Some(ClassifiedExpr {
            pattern: PatternClass::P3DirectOwnership {
                column: "owner_id".to_string(),
            },
            confidence: ConfidenceLevel::A,
        });
        classified.with_check_classification = Some(ClassifiedExpr {
            pattern: PatternClass::P6BooleanFlag {
                column: "is_public".to_string(),
            },
            confidence: ConfidenceLevel::A,
        });

        let queries = Translation::plan(
            vec![classified],
            &db,
            &FunctionRegistry::new(),
            ConfidenceLevel::D,
            &GeneratorSettings::default(),
        )
        .outputs_accepting_gaps()
        .tuple_queries();
        assert!(queries.iter().any(|q| q
            .comment
            .contains("User ownership (owner_id references users)")));
        assert!(queries
            .iter()
            .any(|q| q.comment.contains("Public access flag (is_public)")));
    }

    #[test]
    fn generate_tuple_queries_emit_policy_scope_tuples_for_non_public_roles() {
        let db = parse_schema(
            r"
CREATE TABLE docs(id uuid primary key, owner_id uuid);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON docs FOR SELECT TO app_user, auditors
  USING (owner_id = current_user);
",
        )
        .expect("schema should parse");

        let classified =
            crate::classifier::policy_classifier::classify_policies(&db, &FunctionRegistry::new());
        let queries = Translation::plan(
            classified.clone(),
            &db,
            &FunctionRegistry::new(),
            ConfidenceLevel::D,
            &GeneratorSettings::default(),
        )
        .outputs_accepting_gaps()
        .tuple_queries();
        let scope_relation = policy_scope_relation_name("docs_select");

        assert!(queries
            .iter()
            .any(|q| q.sql.contains(&format!("'{scope_relation}' AS relation"))));
        assert!(queries
            .iter()
            .any(|q| q.sql.contains("'pg_role:app_user' AS subject")));
        assert!(queries
            .iter()
            .any(|q| q.sql.contains("'pg_role:auditors' AS subject")));
    }

    #[test]
    fn generate_role_threshold_tuples_uses_policy_resource_column_for_grant_join() {
        let db = parse_schema(
            r"
CREATE TABLE users(id uuid primary key);
CREATE TABLE docs(id uuid primary key, owner_id uuid references users(id));
CREATE TABLE object_grants(grantee_id uuid, resource_id uuid, role_level integer);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON docs FOR SELECT
  USING (role_level(auth_current_user_id(), id) >= 2);
",
        )
        .expect("schema should parse");

        let mut registry = FunctionRegistry::new();
        registry
            .load_from_json(
                r#"{
  "role_level": {
    "kind": "role_threshold",
    "user_param_index": 0,
    "resource_param_index": 1,
    "role_levels": {"viewer": 1, "editor": 2},
    "grant_table": "object_grants",
    "grant_grantee_col": "grantee_id",
    "grant_resource_col": "resource_id",
    "grant_role_col": "role_level"
  },
  "auth_current_user_id": {
    "kind": "current_user_accessor",
    "returns": "uuid"
  }
}"#,
            )
            .expect("registry json should parse");

        let classified = crate::classifier::policy_classifier::classify_policies(&db, &registry);
        let queries = Translation::plan(
            classified.clone(),
            &db,
            &registry,
            ConfidenceLevel::D,
            &GeneratorSettings::default(),
        )
        .outputs_accepting_gaps()
        .tuple_queries();

        let explicit_grants = queries
            .iter()
            .find(|q| q.comment.contains("Explicit grants expanded to docs rows"))
            .expect("expected explicit grants tuple query");

        assert!(
            explicit_grants
                .sql
                .contains("JOIN \"docs\" resource ON resource.\"id\" = og.\"resource_id\""),
            "expected grants join to use policy resource column `id`, got:\n{}",
            explicit_grants.sql
        );
    }

    #[test]
    fn generate_role_threshold_tuples_extracts_resource_column_from_composite_classification() {
        let db = parse_schema(
            r"
CREATE TABLE users(id uuid primary key);
CREATE TABLE docs(id uuid primary key, owner_id uuid references users(id), is_public boolean);
CREATE TABLE object_grants(grantee_id uuid, resource_id uuid, role_level integer);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON docs FOR SELECT
  USING ((role_level(auth_current_user_id(), id) >= 2) AND is_public = TRUE);
",
        )
        .expect("schema should parse");

        let mut registry = FunctionRegistry::new();
        registry
            .load_from_json(
                r#"{
  "role_level": {
    "kind": "role_threshold",
    "user_param_index": 0,
    "resource_param_index": 1,
    "role_levels": {"viewer": 1, "editor": 2},
    "grant_table": "object_grants",
    "grant_grantee_col": "grantee_id",
    "grant_resource_col": "resource_id",
    "grant_role_col": "role_level"
  },
  "auth_current_user_id": {
    "kind": "current_user_accessor",
    "returns": "uuid"
  }
}"#,
            )
            .expect("registry json should parse");

        let classified = crate::classifier::policy_classifier::classify_policies(&db, &registry);
        let queries = Translation::plan(
            classified.clone(),
            &db,
            &registry,
            ConfidenceLevel::D,
            &GeneratorSettings::default(),
        )
        .outputs_accepting_gaps()
        .tuple_queries();

        let explicit_grants = queries
            .iter()
            .find(|q| q.comment.contains("Explicit grants expanded to docs rows"))
            .expect("expected explicit grants tuple query");
        assert!(
            explicit_grants
                .sql
                .contains("JOIN \"docs\" resource ON resource.\"id\" = og.\"resource_id\""),
            "expected composite policy extraction to preserve join on `id`, got:\n{}",
            explicit_grants.sql
        );
    }

    #[test]
    fn generate_role_threshold_tuples_emits_todo_when_resource_columns_conflict() {
        let db = parse_schema(
            r"
CREATE TABLE users(id uuid primary key);
CREATE TABLE docs(id uuid primary key, owner_id uuid references users(id), project_id uuid);
CREATE TABLE object_grants(grantee_id uuid, resource_id uuid, role_level integer);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select_id ON docs FOR SELECT
  USING (role_level(auth_current_user_id(), id) >= 2);
CREATE POLICY docs_select_project ON docs FOR SELECT
  USING (role_level(auth_current_user_id(), project_id) >= 2);
",
        )
        .expect("schema should parse");

        let mut registry = FunctionRegistry::new();
        registry
            .load_from_json(
                r#"{
  "role_level": {
    "kind": "role_threshold",
    "user_param_index": 0,
    "resource_param_index": 1,
    "role_levels": {"viewer": 1, "editor": 2},
    "grant_table": "object_grants",
    "grant_grantee_col": "grantee_id",
    "grant_resource_col": "resource_id",
    "grant_role_col": "role_level"
  },
  "auth_current_user_id": {
    "kind": "current_user_accessor",
    "returns": "uuid"
  }
}"#,
            )
            .expect("registry json should parse");

        let classified = crate::classifier::policy_classifier::classify_policies(&db, &registry);
        let queries = Translation::plan(
            classified.clone(),
            &db,
            &registry,
            ConfidenceLevel::D,
            &GeneratorSettings::default(),
        )
        .outputs_accepting_gaps()
        .tuple_queries();

        assert!(
            queries
                .iter()
                .any(|q| q.comment.contains("conflicting resource join columns")),
            "expected conflict TODO when role threshold resource columns disagree"
        );
        assert!(
            !queries
                .iter()
                .any(|q| q.comment.contains("Explicit grants expanded to docs rows")),
            "explicit grants should be skipped when resource join column is ambiguous"
        );
    }

    #[test]
    fn generate_role_threshold_tuples_emits_todo_when_single_policy_has_conflicting_resource_columns(
    ) {
        let db = parse_schema(
            r"
CREATE TABLE users(id uuid primary key);
CREATE TABLE docs(id uuid primary key, owner_id uuid references users(id), project_id uuid);
CREATE TABLE object_grants(grantee_id uuid, resource_id uuid, role_level integer);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON docs FOR SELECT
  USING (
    (role_level(auth_current_user_id(), id) >= 2)
    OR (role_level(auth_current_user_id(), project_id) >= 2)
  );
",
        )
        .expect("schema should parse");

        let mut registry = FunctionRegistry::new();
        registry
            .load_from_json(
                r#"{
  "role_level": {
    "kind": "role_threshold",
    "user_param_index": 0,
    "resource_param_index": 1,
    "role_levels": {"viewer": 1, "editor": 2},
    "grant_table": "object_grants",
    "grant_grantee_col": "grantee_id",
    "grant_resource_col": "resource_id",
    "grant_role_col": "role_level"
  },
  "auth_current_user_id": {
    "kind": "current_user_accessor",
    "returns": "uuid"
  }
}"#,
            )
            .expect("registry json should parse");

        let classified = crate::classifier::policy_classifier::classify_policies(&db, &registry);
        let queries = Translation::plan(
            classified.clone(),
            &db,
            &registry,
            ConfidenceLevel::D,
            &GeneratorSettings::default(),
        )
        .outputs_accepting_gaps()
        .tuple_queries();

        assert!(
            queries
                .iter()
                .any(|q| q.comment.contains("conflicting resource join columns")),
            "expected conflict TODO for mixed resource args in one policy expression"
        );
        assert!(
            !queries
                .iter()
                .any(|q| q.comment.contains("Explicit grants expanded to docs rows")),
            "explicit grants should be skipped when a single policy mixes resource join columns"
        );
    }

    #[test]
    fn aliased_p4_membership_tuples_do_not_leak_correlated_or_current_user_predicates() {
        let db = parse_schema(
            r"
CREATE TABLE docs(id uuid primary key);
CREATE TABLE doc_members(doc_id uuid, user_id uuid, role text);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON docs FOR SELECT USING (
  EXISTS (
    SELECT 1
    FROM doc_members dm
    WHERE dm.doc_id = docs.id
      AND dm.user_id = current_user
      AND dm.role = 'admin'
  )
);
",
        )
        .expect("schema should parse");

        let registry = FunctionRegistry::new();
        let classified = crate::classifier::policy_classifier::classify_policies(&db, &registry);
        let queries = Translation::plan(
            classified.clone(),
            &db,
            &registry,
            ConfidenceLevel::D,
            &GeneratorSettings::default(),
        )
        .outputs_accepting_gaps()
        .tuple_queries();

        let membership_query = queries
            .iter()
            .find(|q| q.comment.contains("-- doc membership from doc_members"))
            .expect("expected doc membership tuple query");

        assert!(
            membership_query.sql.contains("role = 'admin'"),
            "expected role filter to be preserved, got:\n{}",
            membership_query.sql
        );
        assert!(
            !membership_query.sql.contains("docs.id"),
            "correlated outer-table predicate must not leak into tuple SQL, got:\n{}",
            membership_query.sql
        );
        assert!(
            !membership_query.sql.contains("current_user"),
            "current_user predicate should be consumed as subject mapping, got:\n{}",
            membership_query.sql
        );
        assert!(
            !membership_query.sql.contains("dm."),
            "join-table alias should not leak into tuple SQL when FROM has no alias, got:\n{}",
            membership_query.sql
        );
    }

    /// `is_self_parent_bridge` compares in lowercase, never through
    /// `canonical_fga_type_name`, and that is load bearing rather than an oversight.
    ///
    /// Canonicalizing folds every name outside `[a-z0-9_]` onto `resource`, so two
    /// unrelated non-ASCII names would compare equal and mint a self-reference tuple for
    /// tables that have nothing to do with each other.
    #[test]
    fn two_unrelated_non_ascii_names_do_not_bridge() {
        assert!(
            is_self_parent_bridge("projects", "project_id"),
            "a table named for its own foreign key still bridges"
        );
        assert!(
            !is_self_parent_bridge("\u{65e5}\u{672c}", "\u{4e2d}\u{6587}"),
            "two names that both canonicalize to 'resource' are not the same table"
        );
    }

    #[test]
    fn canonical_table_name_is_used_for_tuple_object_prefixes() {
        let db = parse_schema(
            r"
CREATE SCHEMA app;
CREATE TABLE app.docs(id uuid primary key, owner_id uuid);
ALTER TABLE app.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON app.docs USING (owner_id = current_user);
",
        )
        .expect("schema should parse");

        let classified =
            crate::classifier::policy_classifier::classify_policies(&db, &FunctionRegistry::new());
        let queries = Translation::plan(
            classified.clone(),
            &db,
            &FunctionRegistry::new(),
            ConfidenceLevel::D,
            &GeneratorSettings::default(),
        )
        .outputs_accepting_gaps()
        .tuple_queries();

        let ownership_query = queries
            .iter()
            .find(|q| q.comment.contains("User ownership"))
            .expect("expected ownership tuple query");
        assert!(ownership_query.sql.contains("'docs:' ||"));
        assert!(!ownership_query.sql.contains("'app.docs:' ||"));
    }

    #[test]
    fn tuple_sql_quotes_identifiers_for_mixed_case_and_reserved_names() {
        let db = parse_schema(
            r#"
CREATE TABLE "Doc Items"(
  id uuid primary key,
  "OwnerID" uuid
);
ALTER TABLE "Doc Items" ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON "Doc Items" FOR SELECT
  USING ("OwnerID" = current_user);
"#,
        )
        .expect("schema should parse");

        let classified =
            crate::classifier::policy_classifier::classify_policies(&db, &FunctionRegistry::new());
        let queries = Translation::plan(
            classified.clone(),
            &db,
            &FunctionRegistry::new(),
            ConfidenceLevel::D,
            &GeneratorSettings::default(),
        )
        .outputs_accepting_gaps()
        .tuple_queries();

        let ownership_query = queries
            .iter()
            .find(|q| q.comment.contains("User ownership"))
            .expect("expected ownership tuple query");

        assert!(
            ownership_query
                .sql
                .contains(r#"THEN "OwnerID"::text ELSE '~' || encode(convert_to("OwnerID"::text"#),
            "subject column should be quoted everywhere the encoding reads it, got:\n{}",
            ownership_query.sql
        );
        assert!(
            ownership_query.sql.contains("END AS subject"),
            "the subject is the encoded value, not the raw column, got:\n{}",
            ownership_query.sql
        );
        assert!(
            ownership_query.sql.contains("FROM \"Doc Items\""),
            "table name should be quoted, got:\n{}",
            ownership_query.sql
        );
    }

    #[test]
    fn tuple_generation_fails_closed_when_object_identifier_column_is_missing() {
        let db = parse_schema(
            r"
CREATE TABLE docs(doc_uuid uuid, owner_id uuid);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON docs FOR SELECT
  USING (owner_id = current_user);
",
        )
        .expect("schema should parse");

        let registry = FunctionRegistry::new();
        let classified = crate::classifier::policy_classifier::classify_policies(&db, &registry);
        let queries = Translation::plan(
            classified.clone(),
            &db,
            &registry,
            ConfidenceLevel::D,
            &GeneratorSettings::default(),
        )
        .outputs_accepting_gaps()
        .tuple_queries();

        assert!(
            queries
                .iter()
                .any(|q| q.comment.contains("missing object identifier column")),
            "expected explicit TODO when object identifier column cannot be resolved"
        );
        assert!(
            !queries.iter().any(|q| q.comment.contains("User ownership")),
            "ownership tuples should not be emitted without a stable object identifier column"
        );
    }

    #[test]
    fn quote_sql_identifier_part_always_double_quotes() {
        // All identifiers, simple or keyword, are now always double-quoted.
        // This prevents any reserved-word confusion without requiring a keyword list.
        assert_eq!(quote_sql_identifier_part("simple"), "\"simple\"");
        assert_eq!(quote_sql_identifier_part("null"), "\"null\"");
        assert_eq!(quote_sql_identifier_part("with"), "\"with\"");
        assert_eq!(quote_sql_identifier_part("join"), "\"join\"");
        assert_eq!(quote_sql_identifier_part("default"), "\"default\"");
        assert_eq!(quote_sql_identifier_part("case"), "\"case\"");

        // Pre-quoted identifiers are stripped, unescaped, and re-quoted through
        // the normal path to prevent injection via malformed registry entries.
        assert_eq!(
            quote_sql_identifier_part("\"simple\""),
            "\"simple\"",
            "pre-quoted simple identifier should round-trip as double-quoted"
        );
        assert_eq!(
            quote_sql_identifier_part("\"mixed Case\""),
            "\"mixed Case\"",
            "pre-quoted identifier with spaces must be re-quoted"
        );
        // A pre-quoted identifier with inner doubled-quotes (SQL escaping):
        // strip outer quotes → unescape `""` → `"` → re-escape → `""` → re-quote.
        assert_eq!(
            quote_sql_identifier_part("\"with\"\"inner\"\"quotes\""),
            "\"with\"\"inner\"\"quotes\"",
            "inner doubled quotes should be unescaped then properly re-escaped"
        );
    }

    #[test]
    fn explicit_grants_with_no_principal_tables_emits_todo_not_user_prefix() {
        use crate::generator::ir::TupleSource;
        // Build the IR directly and call render_tuple_source.
        // Both user_principal and team_principal are None → fail-closed path.
        let source = TupleSource::ExplicitGrants {
            table: "docs".to_string(),
            pk_cols: vec!["id".to_string()],
            grant_join_col: "doc_id".to_string(),
            grant_table: "doc_grants".to_string(),
            grant_role_col: "role_level".to_string(),
            grant_grantee_col: "grantee_id".to_string(),
            grant_resource_col: "doc_id".to_string(),
            role_cases: vec![(1, "viewer".to_string(), "viewer".to_string())],
            user_principal: None,
            team_principal: None,
        };
        let db = parse_schema("CREATE TABLE docs(id uuid primary key);").expect("parse");
        let query = {
            let bounds = UnboundedColumns::resolve(&db);
            render_tuple_source(&source, "docs", false, NameContext::new(&bounds, &db), &db)
        }
        .expect("should produce a query");
        assert!(
            query.comment.contains("TODO [Level C]"),
            "expected a TODO comment, got: {}",
            query.comment
        );
        assert!(
            query.comment.contains("doc_grants"),
            "TODO should mention the grant table, got: {}",
            query.comment
        );
        assert!(
            !query.sql.contains("'user:'"),
            "should not emit user: prefix when principal is unresolvable, got: {}",
            query.sql
        );
    }

    #[test]
    fn explicit_grants_team_only_does_not_fallback_to_user_prefix() {
        use crate::generator::ir::{PrincipalInfo, TupleSource};

        let source = TupleSource::ExplicitGrants {
            table: "docs".to_string(),
            pk_cols: vec!["id".to_string()],
            grant_join_col: "id".to_string(),
            grant_table: "doc_grants".to_string(),
            grant_role_col: "role_level".to_string(),
            grant_grantee_col: "grantee_id".to_string(),
            grant_resource_col: "doc_id".to_string(),
            role_cases: vec![(1, "grant_viewer".to_string(), "viewer".to_string())],
            user_principal: None,
            team_principal: Some(PrincipalInfo {
                table: "teams".to_string(),
                pk_col: "id".to_string(),
            }),
        };
        let db = parse_schema("CREATE TABLE docs(id uuid primary key);").expect("parse");
        let query = {
            let bounds = UnboundedColumns::resolve(&db);
            render_tuple_source(&source, "docs", false, NameContext::new(&bounds, &db), &db)
        }
        .expect("should produce a query");
        assert!(
            query.sql.contains("'team:'"),
            "team-only explicit grants should emit team subjects, got: {}",
            query.sql
        );
        assert!(
            !query.sql.contains("ELSE 'user:'"),
            "team-only explicit grants should fail closed for non-team rows, got: {}",
            query.sql
        );
    }

    #[test]
    fn explicit_grants_mixed_principals_do_not_fallback_to_user_prefix() {
        use crate::generator::ir::{PrincipalInfo, TupleSource};

        let source = TupleSource::ExplicitGrants {
            table: "docs".to_string(),
            pk_cols: vec!["id".to_string()],
            grant_join_col: "id".to_string(),
            grant_table: "doc_grants".to_string(),
            grant_role_col: "role_level".to_string(),
            grant_grantee_col: "grantee_id".to_string(),
            grant_resource_col: "doc_id".to_string(),
            role_cases: vec![(1, "grant_viewer".to_string(), "viewer".to_string())],
            user_principal: Some(PrincipalInfo {
                table: "users".to_string(),
                pk_col: "id".to_string(),
            }),
            team_principal: Some(PrincipalInfo {
                table: "teams".to_string(),
                pk_col: "id".to_string(),
            }),
        };
        let db = parse_schema("CREATE TABLE docs(id uuid primary key);").expect("parse");
        let query = {
            let bounds = UnboundedColumns::resolve(&db);
            render_tuple_source(&source, "docs", false, NameContext::new(&bounds, &db), &db)
        }
        .expect("should produce a query");
        assert!(
            !query.sql.contains("ELSE 'user:'"),
            "mixed-principal explicit grants should not fail open to user subjects, got: {}",
            query.sql
        );
        assert!(
            query.sql.contains("WHEN u.\"id\" IS NOT NULL")
                && query.sql.contains("WHEN t.\"id\" IS NOT NULL"),
            "mixed-principal grants should branch only on explicit principal joins, got: {}",
            query.sql
        );
    }
}

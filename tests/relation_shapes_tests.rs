//! The shapes a translation reports per relation.
//!
//! A consumer watching a change stream needs both halves together: which records
//! fill a relation, and whether one row decides them. Everything here drives the
//! public surface a second crate would use, so a shape reachable only from inside
//! rls2fga fails.

use std::collections::BTreeSet;

use rls2fga::classifier::function_registry::FunctionRegistry;
use rls2fga::classifier::patterns::ConfidenceLevel;
use rls2fga::classifier::policy_classifier::classify_policies;
use rls2fga::generator::model_generator::GeneratorSettings;
use rls2fga::generator::notes::TranslationNote;
use rls2fga::generator::records::{Guard, RecordDerivation, RecordDescription, ValueSource};
use rls2fga::generator::relations::{RelationShapes, RowDecision};
use rls2fga::generator::well_known::{
    can_select_relation, member_relation, PG_ROLE_TYPE, TEAM_TYPE, USER_TYPE,
};
use rls2fga::parser::identifiers::{ColumnName, RelationName};
use rls2fga::parser::names::lookup_table;
use rls2fga::parser::sql_parser::{
    parse_schema, ColumnLike, DatabaseLike, ParserDB, PolicyLike, TableLike,
};
use rls2fga::translator::Translation;

mod support;

const OWNERSHIP: &str = "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE docs (id TEXT PRIMARY KEY, owner_id TEXT);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING (owner_id = auth_current_user_id());
";

const ACCESSOR_REGISTRY: &str =
    r#"{"auth_current_user_id": {"kind": "current_user_accessor", "returns": "text"}}"#;

/// An uncorrelated membership grants every row of the table at once, so the
/// generator mints a holder object standing for the whole member list.
const HOLDER: &str = "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE staff (user_id TEXT);
CREATE TABLE reviewers (user_id TEXT, active BOOLEAN);
CREATE TABLE docs (id TEXT PRIMARY KEY, owner_id TEXT);
CREATE TABLE memos (id TEXT PRIMARY KEY);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE memos ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_staff ON docs FOR SELECT USING (EXISTS (SELECT 1 FROM staff
    WHERE staff.user_id = auth_current_user_id()));
CREATE POLICY memos_reviewers ON memos FOR SELECT USING (EXISTS (SELECT 1 FROM reviewers
    WHERE reviewers.user_id = auth_current_user_id() AND reviewers.active));
";

/// A role threshold naming a grant table, with neither a users nor a teams table
/// for the grantee to resolve against.
const GRANTS_WITHOUT_PRINCIPALS: &str = "
CREATE TABLE docs (id TEXT PRIMARY KEY, owner_id TEXT);
CREATE TABLE owner_grants (granted_owner_id TEXT, grantee_owner_id TEXT, role_id INT);
CREATE FUNCTION get_owner_role(a TEXT, b TEXT) RETURNS INT LANGUAGE sql STABLE
    AS 'SELECT 1';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (get_owner_role(current_user, id) >= 2);
";

const GRANT_REGISTRY: &str = r#"{
  "get_owner_role": {
    "kind": "role_threshold",
    "user_param_index": 0,
    "resource_param_index": 1,
    "role_levels": {"viewer": 2, "editor": 3, "admin": 4},
    "grant_table": "owner_grants",
    "grant_grantee_col": "grantee_owner_id",
    "grant_resource_col": "granted_owner_id",
    "grant_role_col": "role_id"
  }
}"#;

fn parsed(sql: &str, registry_json: &str) -> (ParserDB, FunctionRegistry) {
    let db = parse_schema(sql).expect("the schema parses");
    let mut registry = FunctionRegistry::new();
    registry
        .load_from_json(registry_json)
        .expect("the registry parses");
    (db, registry)
}

fn translation<'a>(
    db: &'a ParserDB,
    registry: &FunctionRegistry,
    settings: &GeneratorSettings,
) -> Translation<'a> {
    Translation::plan(
        classify_policies(db, registry),
        db,
        registry,
        ConfidenceLevel::B,
        settings,
    )
}

fn shapes_of(sql: &str, registry_json: &str) -> Vec<RelationShapes> {
    let (db, registry) = parsed(sql, registry_json);
    translation(&db, &registry, &GeneratorSettings::default()).relations()
}

fn shapes_at(sql: &str, registry_json: &str, level: ConfidenceLevel) -> Vec<RelationShapes> {
    let (db, registry) = parsed(sql, registry_json);
    Translation::plan(
        classify_policies(&db, &registry),
        &db,
        &registry,
        level,
        &GeneratorSettings::default(),
    )
    .relations()
}

fn model_at(sql: &str, registry_json: &str, level: ConfidenceLevel) -> String {
    let (db, registry) = parsed(sql, registry_json);
    Translation::plan(
        classify_policies(&db, &registry),
        &db,
        &registry,
        level,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps()
    .model()
}

fn entry<'a>(shapes: &'a [RelationShapes], type_name: &str, relation: &str) -> &'a RelationShapes {
    shapes
        .iter()
        .find(|entry| entry.type_name.as_str() == type_name && entry.relation == relation)
        .unwrap_or_else(|| panic!("{type_name}#{relation} should be reported"))
}

/// Fixture names carrying a parseable schema.
fn fixture_names() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir("tests/fixtures")
        .expect("fixtures directory")
        .map(|entry| entry.expect("fixture entry").path())
        .filter(|path| path.join("input.sql").is_file())
        .filter_map(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
        .collect();
    names.sort();
    assert!(names.len() > 20, "the corpus should not have shrunk");
    names
}

/// Assertion 1. One policy, one relation the row fills, one shape.
#[test]
fn a_direct_ownership_relation_carries_one_shape_from_its_own_row() {
    let shapes = shapes_of(OWNERSHIP, ACCESSOR_REGISTRY);

    let filled: Vec<&RelationShapes> = shapes
        .iter()
        .filter(|entry| !entry.shapes.is_empty())
        .collect();
    assert_eq!(
        filled.len(),
        1,
        "one relation takes records from the row: {filled:#?}"
    );

    let owned = filled[0];
    assert!(
        owned.from_one_row,
        "{}#{} takes its records from the row it keys",
        owned.type_name, owned.relation
    );
    assert_eq!(owned.shapes.len(), 1, "one policy, one shape");

    let RecordDerivation::FromRow {
        table, template, ..
    } = &owned.shapes[0].derivation
    else {
        panic!("ownership resolves from the row: {:#?}", owned.shapes[0]);
    };
    assert_eq!(table, "docs");
    assert_eq!(template.object_type, owned.type_name);
    assert_eq!(template.relation, owned.relation);
    assert_eq!(template.object_key.parts(), [ValueSource::column("id")]);
    assert_eq!(template.subject_type, USER_TYPE);
    assert_eq!(
        template.subject_key.part(),
        &ValueSource::column("owner_id")
    );
}

/// The same schema keyed on two columns. Phase 4 taught the whole crate to name such a
/// row, so a recipe over one is as decidable as a recipe over a single-column key: the
/// records still follow from that row and from nothing else.
///
/// The guard on the object's identity kept demanding a single column after the facts
/// started flowing, so ownership on a compound key emitted correct tuples while every
/// relation reported that no row decides them. That is a wrong deny at a consumer
/// answering locally, and it disagreed with the request-gated path, which accepts a
/// compound key because it settles earlier.
const COMPOUND_OWNERSHIP: &str = "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE shares (paper_id TEXT, viewer TEXT, PRIMARY KEY (paper_id, viewer));
CREATE FUNCTION auth_current_user_id() RETURNS TEXT LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE shares ENABLE ROW LEVEL SECURITY;
CREATE POLICY shares_owner ON shares FOR SELECT USING (viewer = auth_current_user_id());
";

#[test]
fn a_compound_key_ownership_relation_is_decided_by_its_own_row() {
    let shapes = shapes_of(COMPOUND_OWNERSHIP, ACCESSOR_REGISTRY);

    let owned = entry(&shapes, "shares", "viewer");
    assert!(
        owned.from_one_row,
        "a key spanning two columns names a row as surely as one does: {owned:#?}"
    );

    let RecordDerivation::FromRow {
        table, template, ..
    } = &owned.shapes[0].derivation
    else {
        panic!("ownership resolves from the row: {:#?}", owned.shapes[0]);
    };
    assert_eq!(table, "shares");
    assert_eq!(
        template.object_key.parts(),
        [
            ValueSource::column("paper_id"),
            ValueSource::column("viewer"),
        ],
        "the object is named by every key column, in declared order"
    );
    assert_eq!(template.subject_key.part(), &ValueSource::column("viewer"));

    assert!(
        entry(&shapes, "shares", "can_select").from_one_row,
        "and the action relation reading it inherits that: {shapes:#?}"
    );
}

/// The guard still has to refuse a record keyed on something that is not the row's
/// identity, which is what it was written for. A foreign column names another object,
/// and a change to this row does not own it.
#[test]
fn a_record_keyed_on_a_foreign_column_is_still_not_decided_by_the_row() {
    let shapes = shapes_of(
        "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE docs (id TEXT PRIMARY KEY, owner_id TEXT);
CREATE TABLE links (id TEXT PRIMARY KEY, doc_id TEXT REFERENCES docs(id), user_id TEXT);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_shared ON docs FOR SELECT USING (
  EXISTS (SELECT 1 FROM links l WHERE l.doc_id = docs.id AND l.user_id = auth_current_user_id()));
",
        ACCESSOR_REGISTRY,
    );

    assert!(
        !entry(&shapes, "docs", "can_select").from_one_row,
        "the grant is recorded on another table, so no row of docs settles it: {shapes:#?}"
    );
}

/// Assertion 2. A relation the model computes carries no shapes and is still answered.
#[test]
fn a_computed_relation_carries_no_shapes_and_keeps_its_own_answer() {
    let shapes = shapes_of(OWNERSHIP, ACCESSOR_REGISTRY);
    let can_select = entry(&shapes, "docs", "can_select");

    assert!(
        can_select.shapes.is_empty(),
        "a computed relation is filled by the relations it reads: {:#?}",
        can_select.shapes
    );
    assert!(
        can_select.from_one_row,
        "it computes from a relation the row decides, so it is decidable too"
    );
}

/// Assertion 3. Nothing the model declares is missing, and nothing carrying records
/// is dropped on the way.
#[test]
fn every_relation_the_model_declares_is_reported() {
    let mut checked = 0usize;

    for fixture in fixture_names() {
        let (classified, db, registry) = support::try_load_fixture_classified(&fixture);
        let planned = Translation::plan(
            classified,
            &db,
            &registry,
            ConfidenceLevel::B,
            &GeneratorSettings::default(),
        );
        let reported: BTreeSet<(String, RelationName)> = planned
            .relations()
            .into_iter()
            .map(|entry| (entry.type_name.to_string(), entry.relation))
            .collect();

        let outputs = planned.clone().outputs_accepting_gaps();
        let declared: BTreeSet<(String, RelationName)> = outputs
            .json_model()
            .type_definitions
            .iter()
            .flat_map(|definition| {
                definition
                    .relations
                    .iter()
                    .flatten()
                    .map(|(relation, _)| (definition.type_name.clone(), relation.clone()))
            })
            .collect();
        assert_eq!(
            reported, declared,
            "{fixture}: the reported relations are the declared ones"
        );

        // A source feeding a relation nobody declares would have its shape dropped
        // silently, so assert the direction the set equality cannot see.
        for query in outputs.tuple_queries() {
            let Some(RecordDescription {
                derivation: RecordDerivation::FromRow { template, .. },
                ..
            }) = query.description.as_ref()
            else {
                continue;
            };
            checked += 1;
            assert!(
                reported.contains(&(template.object_type.clone(), template.relation.clone())),
                "{fixture}: {}#{} produces records yet is not reported",
                template.object_type,
                template.relation
            );
        }
    }

    assert!(checked > 0, "no fixture produced a described tuple query");
}

/// Two type plans can hold the same membership source and the renderer emits its
/// query once, so a consumer must not be handed the same shape twice.
#[test]
fn no_relation_reports_the_same_shape_twice() {
    let mut checked = 0usize;

    for fixture in fixture_names() {
        let (classified, db, registry) = support::try_load_fixture_classified(&fixture);
        let planned = Translation::plan(
            classified,
            &db,
            &registry,
            ConfidenceLevel::B,
            &GeneratorSettings::default(),
        );
        for entry in planned.relations() {
            for (index, shape) in entry.shapes.iter().enumerate() {
                checked += 1;
                assert!(
                    !entry.shapes[..index].contains(shape),
                    "{fixture}: {}#{} reports one shape twice:\n{shape:#?}",
                    entry.type_name,
                    entry.relation
                );
            }
        }
    }

    assert!(checked > 0, "no fixture produced a shape");
}

/// The guarantee the describer owes: a bound query is the whole-table query plus one
/// condition, so the two cannot drift into answering differently.
#[test]
fn a_bound_query_is_its_whole_table_query_plus_one_condition() {
    let mut checked = 0usize;

    for fixture in fixture_names() {
        let (classified, db, registry) = support::try_load_fixture_classified(&fixture);
        let planned = Translation::plan(
            classified,
            &db,
            &registry,
            ConfidenceLevel::B,
            &GeneratorSettings::default(),
        );
        let shapes = planned.relations();
        let whole_table: Vec<String> = planned
            .outputs_accepting_gaps()
            .tuple_queries()
            .into_iter()
            .map(|query| query.sql)
            .collect();

        for entry in &shapes {
            for shape in &entry.shapes {
                let RecordDerivation::Joined { queries, .. } = &shape.derivation else {
                    continue;
                };
                assert!(
                    !queries.is_empty(),
                    "{fixture}: {}#{} joins yet offers no query to run",
                    entry.type_name,
                    entry.relation
                );
                for bound in queries {
                    checked += 1;
                    assert!(
                        whole_table.iter().any(|sql| sql
                            .strip_suffix(';')
                            .is_some_and(|body| bound.sql.starts_with(body))),
                        "{fixture}: {}#{} binds a query no whole-table query begins:\n{}",
                        entry.type_name,
                        entry.relation,
                        bound.sql
                    );
                }
            }
        }
    }

    assert!(checked > 0, "no fixture produced a joining shape");
}

/// A column whose stored name carries a double quote, which `PostgreSQL` accepts and a
/// dump reproduces as `"us""er_id"`.
const QUOTED_MEMBERSHIP: &str = "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE staff (\"us\"\"er_id\" TEXT, active BOOLEAN);
CREATE TABLE doc_members (\"do\"\"c_id\" TEXT, \"us\"\"er_id\" TEXT, role TEXT);
CREATE TABLE docs (id TEXT PRIMARY KEY);
CREATE TABLE memos (id TEXT PRIMARY KEY);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE memos ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_members ON docs FOR SELECT USING (EXISTS (SELECT 1 FROM doc_members
    WHERE doc_members.\"do\"\"c_id\" = docs.id
      AND doc_members.\"us\"\"er_id\" = auth_current_user_id()
      AND doc_members.role = 'admin'));
CREATE POLICY memos_staff ON memos FOR SELECT USING (EXISTS (SELECT 1 FROM staff
    WHERE staff.\"us\"\"er_id\" = auth_current_user_id() AND staff.active));
";

/// The identifier a bound query's appended condition names, with any table alias
/// dropped. `bind` appends its condition last, so the final `AND` is the one to read.
fn appended_predicate_identifier(sql: &str) -> String {
    let predicate = sql
        .rsplit("\nAND ")
        .next()
        .expect("rsplit yields at least one part");
    let column = predicate
        .strip_suffix(';')
        .and_then(|body| body.strip_suffix(" = $1"))
        .unwrap_or_else(|| panic!("a bound condition compares one column to $1: {predicate}"));
    if column.starts_with('"') {
        return column.to_string();
    }
    column
        .split_once('.')
        .map_or_else(|| column.to_string(), |(_, rest)| rest.to_string())
}

/// The other half of the guarantee above. A bound query is the whole-table query plus one
/// condition, and that condition has to spell its column the way the query already spells
/// it. An identifier escaped one way in the query and another way in the condition is not
/// the same column: `PostgreSQL` does not parse `"us"er_id"`, and a name chosen to close
/// the quote rather than break it makes the condition a predicate of someone else's
/// choosing.
#[test]
fn a_bound_condition_quotes_its_column_the_way_the_query_does() {
    let (db, registry) = parsed(QUOTED_MEMBERSHIP, ACCESSOR_REGISTRY);
    let planned = Translation::plan(
        classify_policies(&db, &registry),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    );
    let shapes = planned.relations();
    let whole_table: Vec<String> = planned
        .outputs_accepting_gaps()
        .tuple_queries()
        .into_iter()
        .map(|query| query.sql)
        .collect();

    let mut checked = 0usize;
    let mut escaped = 0usize;
    for entry in &shapes {
        for shape in &entry.shapes {
            let RecordDerivation::Joined { queries, .. } = &shape.derivation else {
                continue;
            };
            for bound in queries {
                let identifier = appended_predicate_identifier(&bound.sql);
                checked += 1;
                if identifier.contains("\"\"") {
                    escaped += 1;
                }
                assert!(
                    whole_table.iter().any(|sql| sql.contains(&identifier)),
                    "{}#{} binds {identifier}, which no whole-table query spells:\n{}",
                    entry.type_name,
                    entry.relation,
                    bound.sql
                );
            }
        }
    }

    assert!(checked > 0, "the schema produces a joining shape");
    assert!(
        escaped > 0,
        "the schema exercises an identifier needing escaping, else this proves nothing"
    );
}

/// Assertion 5. The shapes come from the plan the translation holds, so a setting that
/// changes structure reaches them.
#[test]
fn the_shapes_read_the_plan_the_caller_configured() {
    let schema = "
CREATE TABLE jobs (id TEXT PRIMARY KEY, as_of TIMESTAMPTZ);
ALTER TABLE jobs ENABLE ROW LEVEL SECURITY;
CREATE POLICY jobs_sel ON jobs FOR SELECT USING (as_of > now());
";
    let (db, registry) = parsed(schema, "{}");
    let settings = GeneratorSettings {
        request_time_parameter: "as_of".to_string(),
    };

    let bound: Vec<String> = translation(&db, &registry, &settings)
        .relations()
        .into_iter()
        .flat_map(|entry| entry.shapes)
        .filter_map(|shape| match shape.derivation {
            RecordDerivation::Joined { queries, .. } => Some(queries),
            _ => None,
        })
        .flatten()
        .map(|query| query.sql)
        .collect();

    assert!(!bound.is_empty(), "the request-time gate joins");
    // The caller's name collides with the column, so the plan suffixes the row's
    // parameter. A plan rebuilt from the defaults would not.
    assert!(
        bound
            .iter()
            .all(|sql| !sql.contains("jsonb_build_object('as_of',")),
        "the default plan's parameter name must not appear:\n{bound:#?}"
    );
    assert!(
        bound
            .iter()
            .any(|sql| sql.contains("jsonb_build_object('as_of_")),
        "the configured plan suffixes the row's parameter:\n{bound:#?}"
    );
}

/// Assertion 4. A consumer reproducing "this subject is a concrete user" reads the
/// name from here rather than spelling it again.
#[test]
fn the_well_known_names_are_reachable_from_another_crate() {
    assert_eq!(USER_TYPE, "user");
    assert_eq!(TEAM_TYPE, "team");
    assert_eq!(PG_ROLE_TYPE, "pg_role");
    assert_eq!(member_relation(), "member");
}

/// Assertion 5. A reserved name is a relation name by construction, so nothing can hand
/// one to a place expecting a column or a type.
#[test]
fn a_reserved_name_is_a_relation_name() {
    let selected: RelationName = can_select_relation();
    assert_eq!(selected, "can_select");
    assert_eq!(member_relation(), "member");
}

/// Assertion 6. The column a record reads is a column name, folded the way `PostgreSQL`
/// stores it, so it cannot be handed to a place expecting a relation or a type.
#[test]
fn the_column_a_record_reads_is_a_column_name() {
    let shapes = shapes_of(OWNERSHIP, ACCESSOR_REGISTRY);
    let owner = entry(&shapes, "docs", "owner");
    let RecordDerivation::FromRow { template, .. } = &owner.shapes[0].derivation else {
        panic!("ownership reads the row itself: {owner:?}");
    };
    let ValueSource::Column(column) = template.subject_key.part() else {
        panic!("the subject is the owner column: {template:?}");
    };
    let column: &ColumnName = column;
    assert_eq!(column, "owner_id");
}

/// A holder stands for a whole member list, so both halves of it have to be
/// described: the row pointing at the holder, and the members it holds.
#[test]
fn a_holder_relation_carries_the_shapes_that_fill_it() {
    let shapes = shapes_of(HOLDER, ACCESSOR_REGISTRY);
    let holder_type = entry(&shapes, "docs", "staff_holder")
        .shapes
        .first()
        .map(|shape| match &shape.derivation {
            RecordDerivation::FromRow { template, .. } => template.subject_type.clone(),
            other => panic!("the bridge resolves from the row, got {other:?}"),
        })
        .expect("the bridge to the holder is described");

    let bridge = entry(&shapes, "docs", "staff_holder");
    let RecordDerivation::FromRow {
        table,
        template,
        guards,
    } = &bridge.shapes[0].derivation
    else {
        unreachable!("checked above");
    };
    assert_eq!(table, "docs");
    assert_eq!(template.object_type, bridge.type_name);
    assert_eq!(template.relation, bridge.relation);
    assert_eq!(template.object_key.parts(), [ValueSource::column("id")]);
    assert!(
        guards.is_empty(),
        "the key needs no NOT NULL guard: a missing part already yields no record"
    );
    assert_eq!(template.subject_type, holder_type);
    assert_eq!(
        template.subject_key.part(),
        &ValueSource::Literal("all".to_string()),
        "one holder object stands for the whole list"
    );

    let members = entry(&shapes, &holder_type, member_relation().as_str());
    assert_eq!(members.shapes.len(), 1, "one member source, one shape");
    let RecordDerivation::FromRow {
        table,
        template,
        guards,
    } = &members.shapes[0].derivation
    else {
        panic!("a member list with no residual predicate follows from its own row");
    };
    assert_eq!(table, "staff");
    assert_eq!(template.object_type, members.type_name);
    assert_eq!(template.relation, member_relation());
    assert_eq!(
        template.object_key.parts(),
        [ValueSource::Literal("all".to_string())],
        "every member row names the same holder object"
    );
    assert!(
        matches!(guards.as_slice(), [Guard::NotNull(column)] if column == "user_id"),
        "a null member is dropped exactly as the query's NULL guard drops it: {guards:?}"
    );
    assert_eq!(template.subject_type, USER_TYPE);
    assert_eq!(template.subject_key.part(), &ValueSource::column("user_id"));
}

/// The same member list carrying a predicate no evaluator here can read has to be
/// answered by querying, with a query bound to the changed row.
#[test]
fn a_holder_member_list_with_a_residual_predicate_joins() {
    let shapes = shapes_of(HOLDER, ACCESSOR_REGISTRY);
    let holder = shapes
        .iter()
        .find(|entry| entry.type_name.as_str().starts_with("reviewers_holder"))
        .expect("the reviewers holder is reported");
    let RecordDerivation::Joined { queries, reason } = &holder.shapes[0].derivation else {
        panic!("a residual predicate is not readable from the row: {holder:?}");
    };
    assert!(
        reason.contains("active"),
        "the reason names the predicate: {reason}"
    );
    assert_eq!(queries.len(), 1, "one table carries the change");
    assert_eq!(queries[0].table, "reviewers");
    assert_eq!(queries[0].key_column, "user_id");
    assert!(
        queries[0].sql.contains("\"user_id\" = $1"),
        "the query binds the changed row: {}",
        queries[0].sql
    );
}

/// A shared holder object is not decided by one row of its member table, since a
/// second row naming the same user keeps the record alive.
#[test]
fn a_holder_relation_is_never_decidable_from_one_row() {
    let shapes = shapes_of(HOLDER, ACCESSOR_REGISTRY);
    for entry in &shapes {
        if entry.type_name.as_str().contains("_holder")
            || entry.relation.as_str().contains("_holder")
        {
            assert!(
                !entry.from_one_row,
                "{}#{} holds a shared object, so one row cannot decide it",
                entry.type_name, entry.relation
            );
        }
    }
}

/// A query the loader runs with no shape behind it is a tuple the consumer never
/// learns to maintain, and an empty shape list cannot say so.
#[test]
fn every_query_the_loader_runs_has_a_shape() {
    let mut checked = 0usize;
    let mut cases: Vec<(String, ParserDB, FunctionRegistry)> = Vec::new();
    for fixture in fixture_names() {
        let (_, db, registry) = support::try_load_fixture_classified(&fixture);
        cases.push((fixture, db, registry));
    }
    for (label, sql, registry_json) in [
        ("holder", HOLDER, ACCESSOR_REGISTRY),
        ("ownership", OWNERSHIP, ACCESSOR_REGISTRY),
    ] {
        let (db, registry) = parsed(sql, registry_json);
        cases.push((label.to_string(), db, registry));
    }

    for (label, db, registry) in &cases {
        for query in translation(db, registry, &GeneratorSettings::default())
            .outputs_accepting_gaps()
            .tuple_queries()
        {
            if query.sql.trim_start().starts_with("--") {
                continue;
            }
            checked += 1;
            assert!(
                query.description.is_some(),
                "{label}: a real query must carry a shape:\n{}\n{}",
                query.comment,
                query.sql
            );
        }
    }

    assert!(checked > 0, "no fixture produced a real query");
}

/// A grant whose grantee resolves to no principal renders a comment rather than a
/// query, so there are no records to describe. Answering with a joining shape that
/// carries no query would tell a consumer to query and hand them nothing.
#[test]
fn a_grant_with_no_principal_describes_nothing() {
    let shapes = shapes_of(GRANTS_WITHOUT_PRINCIPALS, GRANT_REGISTRY);
    let graded: Vec<&RelationShapes> = shapes
        .iter()
        .filter(|entry| entry.relation.as_str().starts_with("grant_"))
        .collect();
    assert!(
        !graded.is_empty(),
        "the role threshold still mints its grant relations: {shapes:#?}"
    );
    for entry in graded {
        assert!(
            entry.shapes.is_empty(),
            "{}#{} has no query behind it, so it describes nothing: {:#?}",
            entry.type_name,
            entry.relation,
            entry.shapes
        );
    }
}

/// Every conditional wildcard in a model, as `(type, relation, condition)`.
fn conditional_wildcards(json: &str) -> Vec<(String, String, String)> {
    let model: serde_json::Value = serde_json::from_str(json).expect("the JSON model parses");
    let mut found = Vec::new();
    for definition in model["type_definitions"].as_array().into_iter().flatten() {
        let type_name = definition["type"].as_str().unwrap_or_default().to_string();
        let relations = definition["metadata"]["relations"].as_object();
        for (relation, meta) in relations.into_iter().flatten() {
            for reference in meta["directly_related_user_types"]
                .as_array()
                .into_iter()
                .flatten()
            {
                if let Some(condition) = reference["condition"].as_str().filter(|c| !c.is_empty()) {
                    found.push((type_name.clone(), relation.clone(), condition.to_string()));
                }
            }
        }
    }
    found
}

/// A condition is global to the model while the guard it expresses belongs to one table,
/// so two types sharing one condition means one of them is answering with the other's
/// rule. Nothing about the model itself forbids the sharing, which is why this is checked
/// rather than assumed.
#[test]
fn no_condition_is_shared_by_two_types() {
    let mut checked = 0usize;
    for fixture in fixture_names() {
        let (classified, db, registry) = support::try_load_fixture_classified(&fixture);
        let planned = Translation::plan(
            classified,
            &db,
            &registry,
            ConfidenceLevel::B,
            &GeneratorSettings::default(),
        );
        let json = serde_json::to_string(&planned.outputs_accepting_gaps().json_model())
            .expect("the model serializes");
        let mut owners: std::collections::BTreeMap<String, BTreeSet<String>> =
            std::collections::BTreeMap::new();
        for (type_name, _, condition) in conditional_wildcards(&json) {
            checked += 1;
            owners.entry(condition).or_default().insert(type_name);
        }
        for (condition, types) in owners {
            assert_eq!(
                types.len(),
                1,
                "{fixture}: condition '{condition}' is referenced by {types:?}, so one of them \
                 carries the other's guard"
            );
        }
    }
    assert!(
        checked > 0,
        "no fixture exercises a condition, so this invariant checks nothing"
    );
}

/// A condition reads its row's value under a parameter name, and the tuple supplies that
/// value under a context key. The two are minted apart, and a mismatch denies every check
/// on the type while the model and the SQL each look right alone.
#[test]
fn every_condition_parameter_is_supplied_by_its_own_tuples() {
    let mut checked = 0usize;
    for fixture in fixture_names() {
        let (classified, db, registry) = support::try_load_fixture_classified(&fixture);
        let outputs = Translation::plan(
            classified,
            &db,
            &registry,
            ConfidenceLevel::B,
            &GeneratorSettings::default(),
        )
        .outputs_accepting_gaps();
        let json = serde_json::to_string(&outputs.json_model()).expect("the model serializes");
        let model: serde_json::Value = serde_json::from_str(&json).expect("parses");
        let queries = outputs.tuple_queries();

        for (type_name, relation, condition) in conditional_wildcards(&json) {
            checked += 1;
            let parameters = model["conditions"][&condition]["parameters"]
                .as_object()
                .unwrap_or_else(|| {
                    panic!("{fixture}: {type_name}#{relation} names condition '{condition}', which the model does not declare")
                });
            let query = queries
                .iter()
                .find(|query| {
                    query.sql.contains(&format!("'{relation}' AS relation"))
                        && query.sql.contains(&format!("'{condition}' AS condition"))
                })
                .unwrap_or_else(|| {
                    panic!("{fixture}: nothing loads {type_name}#{relation} under '{condition}'")
                });
            let supplied: BTreeSet<&str> = parameters
                .keys()
                .filter(|name| query.sql.contains(&format!("'{name}',")))
                .map(String::as_str)
                .collect();
            assert_eq!(
                supplied.len(),
                1,
                "{fixture}: condition '{condition}' declares {:?} and its tuples supply {supplied:?}, \
                 so exactly one parameter must come from the row:\n{}",
                parameters.keys().collect::<Vec<_>>(),
                query.sql
            );
        }
    }
    assert!(
        checked > 0,
        "no fixture exercises a condition, so this invariant checks nothing"
    );
}

/// Two ownership columns in one clause. Both spellings of it render
/// `define can_select: owner or editor`.
const OR_COLUMNS: &str = "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE docs (id TEXT PRIMARY KEY, owner_id TEXT, editor_id TEXT);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_read ON docs FOR SELECT
    USING (owner_id = auth_current_user_id() OR editor_id = auth_current_user_id());
";

/// The same grant written as two permissive policies.
const TWO_SELECT_POLICIES: &str = "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE docs (id TEXT PRIMARY KEY, owner_id TEXT, editor_id TEXT);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING (owner_id = auth_current_user_id());
CREATE POLICY docs_editor ON docs FOR SELECT USING (editor_id = auth_current_user_id());
";

/// A barrier beside the ownership grant, rendering `define can_select: owner and editor`.
const RESTRICTIVE_BARRIER: &str = "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE docs (id TEXT PRIMARY KEY, owner_id TEXT, editor_id TEXT);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING (owner_id = auth_current_user_id());
CREATE POLICY docs_barrier ON docs AS RESTRICTIVE FOR SELECT
    USING (editor_id = auth_current_user_id());
";

/// A per-row `DELETE` reads the table, so it renders `define can_delete: editor and
/// can_select` over `define can_select: owner`.
const DELETE_GATED_ON_READ: &str = "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE docs (id TEXT PRIMARY KEY, owner_id TEXT, editor_id TEXT);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING (owner_id = auth_current_user_id());
CREATE POLICY docs_purge ON docs FOR DELETE USING (editor_id = auth_current_user_id());
";

/// The reported entry's own decision shape. Reading the relation off the entry rather
/// than spelling it again is what keeps the two from disagreeing.
fn leaf(entry: &RelationShapes) -> RowDecision {
    RowDecision::Leaf {
        relation: entry.relation.clone(),
        shapes: entry.shapes.clone(),
    }
}

/// One leaf of a recipe, and what makes it decidable.
enum Leaf<'a> {
    /// The subjects are the ones the row names.
    Named {
        relation: &'a str,
        shapes: &'a [RecordDescription],
    },
    /// The row settles one side of a comparison the caller's own value completes, so the
    /// subject is a wildcard and the context is what stops it granting everyone.
    Gated {
        relation: &'a str,
        shapes: &'a [RecordDescription],
        context_key: &'a str,
        request_parameter: &'a str,
    },
}

impl<'a> Leaf<'a> {
    fn relation(&self) -> &'a str {
        match self {
            Self::Named { relation, .. } | Self::Gated { relation, .. } => relation,
        }
    }

    fn shapes(&self) -> &'a [RecordDescription] {
        match self {
            Self::Named { shapes, .. } | Self::Gated { shapes, .. } => shapes,
        }
    }
}

/// Every leaf a recipe reaches, in the order it reaches them.
fn recipe_leaves(decision: &RowDecision) -> Vec<Leaf<'_>> {
    match decision {
        RowDecision::Leaf { relation, shapes } => vec![Leaf::Named {
            relation: relation.as_str(),
            shapes: shapes.as_slice(),
        }],
        RowDecision::RequestGated {
            relation,
            shapes,
            context_key,
            request_parameter,
            ..
        } => vec![Leaf::Gated {
            relation: relation.as_str(),
            shapes: shapes.as_slice(),
            context_key: context_key.as_str(),
            request_parameter: request_parameter.as_str(),
        }],
        RowDecision::Any(children) | RowDecision::All(children) => {
            children.iter().flat_map(recipe_leaves).collect()
        }
        other => panic!("a recipe shape this test cannot read: {other:?}"),
    }
}

/// Assertion 1. The flag and the recipe leave one traversal, so a relation carrying a
/// recipe is exactly one the flag admits. Two answers derived apart could disagree,
/// which is the divergence this surface exists to remove.
#[test]
fn a_recipe_is_reported_exactly_when_the_flag_says_one_row_decides() {
    let mut with_recipe = 0usize;
    let mut without = 0usize;

    let mut check = |label: &str, reported: &[RelationShapes]| {
        for reported in reported {
            assert_eq!(
                reported.decision.is_some(),
                reported.from_one_row,
                "{label}: {}#{} answers the flag and the recipe differently",
                reported.type_name,
                reported.relation
            );
            if reported.decision.is_some() {
                with_recipe += 1;
            } else {
                without += 1;
            }
        }
    };

    for fixture in fixture_names() {
        let (classified, db, registry) = support::try_load_fixture_classified(&fixture);
        let planned = Translation::plan(
            classified,
            &db,
            &registry,
            ConfidenceLevel::B,
            &GeneratorSettings::default(),
        );
        check(&fixture, &planned.relations());
    }
    for (label, sql) in [
        ("or_columns", OR_COLUMNS),
        ("two_select_policies", TWO_SELECT_POLICIES),
        ("restrictive_barrier", RESTRICTIVE_BARRIER),
        ("delete_gated_on_read", DELETE_GATED_ON_READ),
        ("holder", HOLDER),
    ] {
        check(label, &shapes_of(sql, ACCESSOR_REGISTRY));
    }

    assert!(
        with_recipe > 0 && without > 0,
        "the corpus has to exercise both answers, got {with_recipe} with a recipe and {without} without"
    );
}

/// Assertion 2. The relation whose records decide a read is named rather than left to
/// be read out of the DSL text.
#[test]
fn an_ownership_read_names_the_relation_whose_records_decide_it() {
    let shapes = shapes_of(OWNERSHIP, ACCESSOR_REGISTRY);
    let owner = entry(&shapes, "docs", "owner");

    assert!(
        !owner.shapes.is_empty(),
        "the recipe carries these, so an empty list would say nothing"
    );
    assert_eq!(
        entry(&shapes, "docs", "can_select").decision.as_ref(),
        Some(&leaf(owner)),
        "can_select is defined as owner, so its subjects are owner's records"
    );
}

/// Assertion 3. A union of two ownership columns composes, and the composition is a
/// mirror of the model rather than of the spelling: whichever operand order the DSL
/// renders, the recipe reaches its leaves in that order. Two permissive policies and
/// one `OR` clause therefore give the same recipe exactly when they render the same
/// definition, which is the property the flag would otherwise be trusted to imply.
#[test]
fn either_spelling_of_two_ownership_columns_composes_into_any() {
    let shapes = shapes_of(OR_COLUMNS, ACCESSOR_REGISTRY);
    let expected = RowDecision::Any(vec![
        leaf(entry(&shapes, "docs", "owner")),
        leaf(entry(&shapes, "docs", "editor")),
    ]);
    assert_eq!(
        entry(&shapes, "docs", "can_select").decision.as_ref(),
        Some(&expected),
        "either column admits the row, so the recipe is a union of both"
    );

    for (label, sql) in [
        ("one clause", OR_COLUMNS),
        ("two policies", TWO_SELECT_POLICIES),
    ] {
        let (db, registry) = parsed(sql, ACCESSOR_REGISTRY);
        let planned = translation(&db, &registry, &GeneratorSettings::default());
        let reported = planned.relations();
        let named: Vec<&str> = recipe_leaves(
            entry(&reported, "docs", "can_select")
                .decision
                .as_ref()
                .expect("an ownership read decides from the row"),
        )
        .into_iter()
        .map(|leaf| leaf.relation())
        .collect();
        assert_eq!(
            named,
            rendered_operands(&planned.outputs_accepting_gaps().model(), "can_select"),
            "{label}: the recipe reaches the operands the model names, in that order"
        );
    }
}

/// The operands of one relation's rendered definition, which for these schemas is a
/// flat list of relation names.
fn rendered_operands<'a>(dsl: &'a str, relation: &str) -> Vec<&'a str> {
    let definition = format!("define {relation}:");
    dsl.lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix(&definition))
        .unwrap_or_else(|| panic!("{relation} should be defined:\n{dsl}"))
        .split(" or ")
        .map(str::trim)
        .collect()
}

/// Assertion 4. The one that settles the design. A barrier renders `owner and editor`,
/// whose flag is true and whose subjects are an intersection, so a recipe flattened
/// into one list would let an owner who is not the editor read the row.
#[test]
fn a_restrictive_barrier_composes_into_all_rather_than_one_flat_list() {
    let shapes = shapes_of(RESTRICTIVE_BARRIER, ACCESSOR_REGISTRY);
    let can_select = entry(&shapes, "docs", "can_select");

    assert!(
        can_select.from_one_row,
        "both sides of the barrier resolve from the row"
    );
    let expected = RowDecision::All(vec![
        leaf(entry(&shapes, "docs", "owner")),
        leaf(entry(&shapes, "docs", "editor")),
    ]);
    assert_eq!(
        can_select.decision.as_ref(),
        Some(&expected),
        "the barrier removes subjects, so the recipe is an intersection"
    );
}

/// Assertion 5. A recipe names the relations records fill, so a relation the model
/// computes is flattened into whatever it names rather than reported as a hop the
/// consumer has to resolve.
#[test]
fn a_computed_relation_inside_a_recipe_flattens_into_what_it_names() {
    let shapes = shapes_of(DELETE_GATED_ON_READ, ACCESSOR_REGISTRY);
    let expected = RowDecision::All(vec![
        leaf(entry(&shapes, "docs", "editor")),
        leaf(entry(&shapes, "docs", "owner")),
    ]);
    assert_eq!(
        entry(&shapes, "docs", "can_delete").decision.as_ref(),
        Some(&expected),
        "can_delete is `editor and can_select` over `can_select: owner`"
    );
}

/// Assertion 6. What the recipe inherits from the flag: every leaf resolves from the
/// object's own row to a user the consumer can compare against. A literal subject would
/// put `user:*` on the local path, which a subject set cannot express.
#[test]
fn every_leaf_of_every_recipe_names_a_user_from_the_objects_own_row() {
    let mut checked = 0usize;

    for fixture in fixture_names() {
        let (classified, db, registry) = support::try_load_fixture_classified(&fixture);
        let planned = Translation::plan(
            classified,
            &db,
            &registry,
            ConfidenceLevel::B,
            &GeneratorSettings::default(),
        );
        for reported in planned.relations() {
            let Some(decision) = reported.decision.as_ref() else {
                continue;
            };
            let reached = recipe_leaves(decision);
            assert!(
                !reached.is_empty(),
                "{fixture}: {}#{} reports a recipe reaching no leaf, which grants either \
                 nobody or everybody depending on how it composes",
                reported.type_name,
                reported.relation
            );
            for leaf in reached {
                let relation = leaf.relation();
                assert!(
                    !leaf.shapes().is_empty(),
                    "{fixture}: leaf {}#{relation} carries no shape, so it decides nothing",
                    reported.type_name
                );
                for shape in leaf.shapes() {
                    checked += 1;
                    let RecordDerivation::FromRow {
                        table, template, ..
                    } = &shape.derivation
                    else {
                        panic!(
                            "{fixture}: leaf {}#{relation} needs a query: {shape:#?}",
                            reported.type_name
                        );
                    };
                    assert_eq!(
                        template.object_type, reported.type_name,
                        "{fixture}: leaf {relation} keys objects of another type"
                    );
                    assert_eq!(template.relation, relation, "{fixture}: leaf misattributed");
                    let expected_key: Vec<ValueSource> = primary_key_of(table, &db)
                        .into_iter()
                        .map(ValueSource::column)
                        .collect();
                    assert_eq!(
                        template.object_key.parts(),
                        expected_key,
                        "{fixture}: leaf {}#{relation} keys on columns that are not the \
                         row's identity",
                        reported.type_name
                    );
                    assert_eq!(
                        template.subject_type, USER_TYPE,
                        "{fixture}: leaf {}#{relation} names a subject the consumer cannot \
                         compare against",
                        reported.type_name
                    );
                    match &leaf {
                        Leaf::Named { .. } => assert!(
                            !matches!(template.subject_key.part(), &ValueSource::Literal(_)),
                            "{fixture}: leaf {}#{relation} carries a literal subject: {:?}",
                            reported.type_name,
                            template.subject_key
                        ),
                        // A gated leaf grants the wildcard, so the context is the only
                        // thing standing between it and granting everyone. Losing the
                        // context or naming it differently from the recipe is a wrong
                        // allow no DSL assertion can see.
                        Leaf::Gated {
                            context_key,
                            request_parameter,
                            ..
                        } => {
                            assert_eq!(
                                template.subject_key.part(),
                                &ValueSource::Literal("*".to_string()),
                                "{fixture}: gated leaf {}#{relation} grants named subjects \
                                 rather than the wildcard the condition filters",
                                reported.type_name
                            );
                            let context = template.context.as_ref().unwrap_or_else(|| {
                                panic!(
                                    "{fixture}: gated leaf {}#{relation} carries no context, \
                                     so its records grant everyone",
                                    reported.type_name
                                )
                            });
                            assert_eq!(
                                context.key, *context_key,
                                "{fixture}: gated leaf {}#{relation} fills a different \
                                 parameter from the one the recipe names",
                                reported.type_name
                            );
                            assert!(
                                !request_parameter.is_empty(),
                                "{fixture}: gated leaf {}#{relation} names no parameter for \
                                 the caller to supply",
                                reported.type_name
                            );
                        }
                    }
                }
            }
        }
    }

    assert!(
        checked > 0,
        "no fixture reports a recipe, so this checks nothing"
    );
}

/// Every column the crate identifies rows by, in declared order: the declared primary
/// key whatever its arity, or the `id` column it falls back to when a table declares
/// none. This is what an object key holds.
fn primary_key_of(table: &str, db: &ParserDB) -> Vec<String> {
    let columns: Vec<String> = lookup_table(db, table)
        .and_then(|found| found.primary_key_columns(db).ok())
        .map(|columns| {
            columns
                .map(|c| c.stored_column_name().into_owned())
                .collect()
        })
        .unwrap_or_default();
    if columns.is_empty() {
        vec!["id".to_string()]
    } else {
        columns
    }
}

/// An arm nothing can classify, so the threshold drops it while the ownership arm
/// beside it survives. `opaque_gate` is deliberately unregistered and bodyless, so
/// no later vocabulary work can make it recognizable and quietly retire these tests.
const PARTIAL_SELECT_DROP: &str = "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE docs (id TEXT PRIMARY KEY, owner_id TEXT);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING (owner_id = auth_current_user_id());
CREATE POLICY docs_opaque ON docs FOR SELECT USING (opaque_gate(id));
";

/// The same loss spread over every command. Neither policy stores a `WITH CHECK`, so
/// `PostgreSQL` mirrors each `USING` onto the check side and the dropped arm reaches
/// `can_insert` only through that mirror. Storing an explicit check instead would
/// reach `can_insert` through the check arm and leave the mirror untested.
const FOR_ALL_DROP: &str = "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE docs (id TEXT PRIMARY KEY, owner_id TEXT);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR ALL USING (owner_id = auth_current_user_id());
CREATE POLICY docs_opaque ON docs FOR ALL USING (opaque_gate(id));
";

/// One UPDATE policy whose USING survives and whose WITH CHECK does not.
const WITH_CHECK_DROP: &str = "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE docs (id TEXT PRIMARY KEY, owner_id TEXT);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = auth_current_user_id());
CREATE POLICY docs_upd ON docs FOR UPDATE USING (owner_id = auth_current_user_id())
    WITH CHECK (opaque_gate(id));
";

/// A permissive policy `PostgreSQL` resolved to the DDL runner, so a dump cannot say
/// who it binds and the whole policy is dropped beside a surviving arm.
const DDL_ROLE_DROP: &str = "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE docs (id TEXT PRIMARY KEY, owner_id TEXT, team_id TEXT);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING (owner_id = auth_current_user_id());
CREATE POLICY docs_cu ON docs FOR SELECT TO CURRENT_USER
    USING (team_id = auth_current_user_id());
";

/// The attribute half of a permissive conjunction is handed to the application, so
/// the emitted relation is WIDER than the database rather than narrower.
const GUARD_DISCARD: &str = "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE docs (id TEXT PRIMARY KEY, owner_id TEXT, status TEXT);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT
    USING (owner_id = auth_current_user_id() AND status = 'open');
";

/// Phase 1, test 1. A permissive arm the threshold dropped makes the emitted
/// relation narrower than the database, so no row decides it. A consumer answering
/// from the recipe would otherwise hide rows `PostgreSQL` shows.
#[test]
fn a_dropped_permissive_arm_leaves_the_relation_it_narrowed_undecidable() {
    let shapes = shapes_at(PARTIAL_SELECT_DROP, ACCESSOR_REGISTRY, ConfidenceLevel::B);

    let can_select = entry(&shapes, "docs", "can_select");
    assert!(
        !can_select.from_one_row,
        "the dropped arm makes can_select narrower than the database, so one row \
         cannot decide it: {can_select:#?}"
    );
    assert!(
        can_select.decision.is_none(),
        "and the recipe has to agree with the flag"
    );
    assert!(
        entry(&shapes, "docs", "owner").from_one_row,
        "the surviving arm still fills its own relation from the row, so the scar \
         is targeted rather than a blanket refusal"
    );
}

/// Phase 1, test 2. A FOR ALL pair loses every command at once, the INSERT side
/// through the USING to WITH CHECK mirror.
#[test]
fn a_dropped_for_all_arm_undecides_every_action_relation_it_fed() {
    let shapes = shapes_at(FOR_ALL_DROP, ACCESSOR_REGISTRY, ConfidenceLevel::B);

    for relation in [
        "can_select",
        "can_insert",
        "can_update",
        "can_delete",
        "can_update_without_reading",
        "can_select_for_update",
    ] {
        let reported = entry(&shapes, "docs", relation);
        assert!(
            !reported.from_one_row,
            "docs#{relation} lost an arm, so one row cannot decide it"
        );
    }
    assert!(
        entry(&shapes, "docs", "owner").from_one_row,
        "the row still fills owner"
    );
}

/// Phase 1, test 3. Losing the WITH CHECK costs the update, and nothing else. A
/// locking read filters by the UPDATE USING alone, which survived, so it stays
/// decidable and the scar does not spread further than the loss.
#[test]
fn a_dropped_with_check_undecides_the_update_but_not_the_locking_read() {
    let shapes = shapes_at(WITH_CHECK_DROP, ACCESSOR_REGISTRY, ConfidenceLevel::B);

    assert!(
        !entry(&shapes, "docs", "can_update").from_one_row,
        "the check half was lost, so can_update is not decidable"
    );
    assert!(
        entry(&shapes, "docs", "can_select_for_update").from_one_row,
        "a locking read filters by the surviving USING alone, so it stays decidable"
    );
    assert!(
        entry(&shapes, "docs", "can_select").from_one_row,
        "and the SELECT policy was never touched"
    );
}

/// Phase 1, test 7. The scar is metadata. An entry naming a relation the plan never
/// defines reaches nothing: `can_insert_returning` is folded away here because the
/// insert rule already implies the read.
#[test]
fn a_scar_on_a_relation_the_plan_never_defines_is_inert() {
    let shapes = shapes_at(FOR_ALL_DROP, ACCESSOR_REGISTRY, ConfidenceLevel::B);

    assert!(
        !shapes
            .iter()
            .any(|reported| reported.relation == "can_insert_returning"),
        "a scar must not conjure a relation the model does not define"
    );
    assert_eq!(
        model_at(FOR_ALL_DROP, ACCESSOR_REGISTRY, ConfidenceLevel::B),
        "model\n  schema 1.1\n\
         \ntype user\n\
         \ntype docs\n  relations\n\
         \u{20}   define owner: [user]\n\
         \u{20}   define can_delete: owner\n\
         \u{20}   define can_insert: owner\n\
         \u{20}   define can_select: owner\n\
         \u{20}   define can_select_for_update: can_update\n\
         \u{20}   define can_update: owner\n\
         \u{20}   define can_update_without_reading: owner\n",
        "the scar changes no DSL byte"
    );
}

/// Phase 1, test 8a. A policy bound to a role only the DDL knew is dropped whole,
/// which narrows the survivor's relation exactly as a threshold drop does.
#[test]
fn a_policy_bound_to_a_ddl_time_role_undecides_what_it_would_have_widened() {
    let shapes = shapes_at(DDL_ROLE_DROP, ACCESSOR_REGISTRY, ConfidenceLevel::B);

    assert!(
        !entry(&shapes, "docs", "can_select").from_one_row,
        "the dropped TO CURRENT_USER policy granted rows the model no longer does"
    );
}

/// Phase 1, test 8b. A policy naming a table two schemas both bear belongs to one of
/// them and the schema cannot say which, so both candidates lost a grant. Reached
/// through the already-classified door, since `parse_schema` refuses the spelling
/// outright with `TableNotFoundForPolicy`.
#[test]
fn a_policy_whose_table_does_not_resolve_undecides_every_table_that_bears_the_name() {
    let sql = "
CREATE SCHEMA a;
CREATE SCHEMA b;
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE a.docs (id TEXT PRIMARY KEY, owner_id TEXT, team_id TEXT);
CREATE TABLE b.docs (id TEXT PRIMARY KEY, owner_id TEXT, team_id TEXT);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE a.docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE b.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY a_owner ON a.docs FOR SELECT USING (owner_id = auth_current_user_id());
CREATE POLICY b_owner ON b.docs FOR SELECT USING (owner_id = auth_current_user_id());
CREATE POLICY a_team ON a.docs FOR SELECT USING (team_id = auth_current_user_id());
";
    let (db, registry) = parsed(sql, ACCESSOR_REGISTRY);
    let mut classified = classify_policies(&db, &registry);
    for cp in &mut classified {
        if cp.name() == "a_team" {
            cp.table = "docs".to_string();
        }
    }
    let shapes = Translation::plan(
        classified,
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .relations();

    for type_name in ["docs", "docs_09be04be"] {
        assert!(
            !entry(&shapes, type_name, "can_select").from_one_row,
            "{type_name} may be the table the unresolved policy granted, so it \
             cannot claim one row decides its reads"
        );
    }
}

/// Phase 1, test 8c. The one drift that widens. The attribute half is handed to the
/// application, so the model grants rows `PostgreSQL` hides, and a consumer answering
/// locally would allow rather than deny. The DSL is unchanged, so only the scar
/// separates this from a faithful ownership grant.
#[test]
fn a_discarded_attribute_guard_undecides_the_relation_it_widened() {
    let shapes = shapes_at(GUARD_DISCARD, ACCESSOR_REGISTRY, ConfidenceLevel::C);

    assert!(
        !entry(&shapes, "docs", "can_select").from_one_row,
        "the discarded status guard makes the model wider than the database"
    );
    assert!(
        model_at(GUARD_DISCARD, ACCESSOR_REGISTRY, ConfidenceLevel::C)
            .contains("define can_select: owner"),
        "and the emitted model is untouched, so the scar is the only difference"
    );
}

/// Phase 1, test 6. The standing guard that no path can lose a clause silently.
/// Every clause the schema declares either survives into the confidence summary or is
/// named by a machine readable note: keyed on its own policy, or, where the loss
/// belongs to the table's read graph rather than to any one policy, by the recursion
/// note that names the table and the cycle.
///
/// Deliberately not satisfied by a note that merely mentions the table, since
/// `TableOwnerBypassesPolicies` names every RLS-enabled table and would pass this
/// vacuously for the whole corpus.
#[test]
fn every_declared_clause_reaches_the_summary_or_a_note_that_names_it() {
    let mut checked = 0usize;
    let mut unaccounted: Vec<String> = Vec::new();

    for fixture in fixture_names() {
        let (classified, db, registry) = support::try_load_fixture_classified(&fixture);
        let outputs = Translation::plan(
            classified,
            &db,
            &registry,
            ConfidenceLevel::B,
            &GeneratorSettings::default(),
        )
        .outputs_accepting_gaps();

        let surviving: BTreeSet<&str> = outputs
            .confidence_summary()
            .iter()
            .map(|(name, _)| name.as_str())
            .collect();
        let named: BTreeSet<&str> = outputs
            .notes()
            .iter()
            .map(TranslationNote::subject)
            .collect();
        let looping: BTreeSet<&str> = outputs
            .notes()
            .iter()
            .filter_map(|note| match note {
                TranslationNote::PolicyReadRecursion { table, .. } => Some(table.as_str()),
                _ => None,
            })
            .collect();

        for policy in db.policies() {
            let name = policy.name().to_string();
            let table = policy.target_table_name().to_string();
            for (label, stored) in [
                ("USING", policy.using_expression(&db).is_some()),
                ("WITH CHECK", policy.check_expression(&db).is_some()),
            ] {
                if !stored {
                    continue;
                }
                checked += 1;
                let survivor = if label == "USING" {
                    name.clone()
                } else {
                    format!("{name} (WITH CHECK)")
                };
                if surviving.contains(survivor.as_str())
                    || named.contains(name.as_str())
                    || looping.contains(table.as_str())
                {
                    continue;
                }
                unaccounted.push(format!("{fixture}: {name} ({label})"));
            }
        }
    }

    assert!(
        checked > 20,
        "the corpus should not have shrunk, only {checked} clauses seen"
    );
    assert!(
        unaccounted.is_empty(),
        "a clause the database evaluates reaches no machine readable surface: {unaccounted:#?}"
    );
}

/// A barrier the threshold dropped, beside a surviving ownership grant.
const RESTRICTIVE_DROP: &str = "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE docs (id TEXT PRIMARY KEY, owner_id TEXT, is_public BOOLEAN);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_bar ON docs AS RESTRICTIVE FOR SELECT USING (is_public);
";

/// Nothing survives, so the command falls closed outright.
const TOTAL_DROP: &str = "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE docs (id TEXT PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_opaque ON docs FOR SELECT USING (opaque_gate(id));
";

/// Phase 1, test 9. Shapes already non decidable before any scar existed, pinned so
/// the scar is not the only thing holding them up. Three different mechanisms: a
/// barrier that fell closed, a command left with nothing to grant it, and an arm kept
/// at a threshold low enough that it translates into a denial instead of vanishing.
#[test]
fn the_shapes_that_were_already_undecidable_stay_undecidable() {
    for (label, sql, level) in [
        ("a dropped barrier", RESTRICTIVE_DROP, ConfidenceLevel::A),
        ("every arm dropped", TOTAL_DROP, ConfidenceLevel::B),
        (
            "an unrecognized arm kept",
            PARTIAL_SELECT_DROP,
            ConfidenceLevel::D,
        ),
    ] {
        let shapes = shapes_at(sql, ACCESSOR_REGISTRY, level);
        assert!(
            !entry(&shapes, "docs", "can_select").from_one_row,
            "{label}: the model and the database disagree, so no row decides the read"
        );
    }
}

/// Phase 3, test 6. Where the six session-attribute fixtures stand once the request
/// vocabulary exists: each declares the values its deployment carries, and each is
/// translated or scarred accordingly.
///
/// This replaces `the_session_attribute_fixtures_are_refused_and_scarred_today`, phase
/// 2's declared flip target, which pinned all six as refused. Four now translate whole,
/// and `connetto_capability` keeps the two shapes phase 3 did not reach, so the
/// replacement asserts more than the pin it removes rather than less.
#[test]
fn the_session_attribute_fixtures_translate_or_scar_what_is_left() {
    let expected: [(&str, &[&str], &[&str]); 6] = [
        (
            "connetto_or_policy",
            &[],
            &[
                "notes#can_delete",
                "notes#can_insert",
                "notes#can_select",
                "notes#can_select_for_update",
                "notes#can_update",
                "notes#can_update_without_reading",
                "notes#gate_notes_p_dbaa5e0d",
                "notes#owner",
            ],
        ),
        (
            "connetto_two_policy",
            &[],
            &[
                "notes#can_delete",
                "notes#can_insert",
                "notes#can_select",
                "notes#can_select_for_update",
                "notes#can_update",
                "notes#can_update_without_reading",
                "notes#gate_notes_subject_c7ba450d",
                "notes#owner",
            ],
        ),
        // `papers_p` translates whole, the ownership arm and the share arm both, and
        // `shares_insert` translates as delegation to the parent even though connetto
        // declares no key, because the policy states the join itself. Phase 4 gave
        // `paper_shares` a row identity built from its two-column key, so it reports no
        // loss at all and its own reads are decidable, which is what the fixture was
        // added to reach.
        //
        // `papers` reads stay decidable only through ownership: the share arm is
        // recorded on another table, so no row of `papers` settles it.
        (
            "connetto_capability",
            &[],
            &[
                "paper_shares#can_select",
                "paper_shares#gate_shares_read_abbc62d2",
                "papers#owner",
            ],
        ),
        (
            "tenant_setting",
            &[],
            &[
                "documents#can_delete",
                "documents#can_insert",
                "documents#can_select",
                "documents#can_select_for_update",
                "documents#can_update",
                "documents#can_update_without_reading",
                "documents#gate_documents_tenant_78bd68be",
            ],
        ),
        (
            "supabase_mfa_restrictive",
            &[],
            &[
                "documents#can_select",
                "documents#gate_documents_mfa_e65d3d44",
                "documents#owner",
            ],
        ),
        (
            "claims_role_gate",
            &[],
            &[
                "audit_log#can_select",
                "audit_log#gate_audit_admin_02ce9ca4",
            ],
        ),
    ];

    for (fixture, scars, decidable) in expected {
        let (classified, db, registry) = support::try_load_fixture_classified(fixture);
        let planned = Translation::plan(
            classified,
            &db,
            &registry,
            ConfidenceLevel::B,
            &GeneratorSettings::default(),
        );

        let reported: Vec<String> = planned
            .relations()
            .iter()
            .filter(|shape| shape.from_one_row)
            .map(|shape| format!("{}#{}", shape.type_name, shape.relation))
            .collect();
        assert_eq!(
            reported, decidable,
            "{fixture}: the relations the model fills from one row"
        );

        let outputs = planned.outputs_accepting_gaps();
        let mut named: Vec<String> = outputs
            .notes()
            .iter()
            .filter_map(|note| match note {
                TranslationNote::ClauseBelowThreshold { policy, .. } => {
                    Some(format!("ClauseBelowThreshold {policy}"))
                }
                TranslationNote::RowsCannotBeNamed { table, .. } => {
                    Some(format!("RowsCannotBeNamed {table}"))
                }
                _ => None,
            })
            .collect();
        named.sort();
        named.dedup();
        assert_eq!(
            named, scars,
            "{fixture}: what the translation says it lost, and about which policy"
        );
    }
}

/// A grant recorded on a sharing table is not answerable from the guarded row: the
/// deciding fact lives elsewhere. The shape has to say so and carry a query bound to the
/// sharing table, because a consumer that read it as row-derived would take the
/// wildcard subject at face value and grant everyone.
#[test]
fn a_share_recorded_elsewhere_is_reported_as_needing_a_query() {
    let (classified, db, registry) = support::try_load_fixture_classified("connetto_capability");
    let planned = Translation::plan(
        classified,
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    );
    let reported = planned.relations();
    let gate = reported
        .iter()
        .find(|shape| {
            shape.type_name.as_str() == "papers" && shape.relation.as_str().starts_with("gate_")
        })
        .expect("the share arm mints a gate relation on papers");

    assert!(
        !gate.from_one_row,
        "a paper row does not carry its own shares, so no row settles this"
    );
    let [shape] = gate.shapes.as_slice() else {
        panic!(
            "the gate is filled by exactly one shape, got {:?}",
            gate.shapes
        );
    };
    assert_eq!(
        shape.tables,
        vec!["paper_shares".to_string()],
        "the deciding rows live on the sharing table"
    );
    let RecordDerivation::Joined { queries, reason } = &shape.derivation else {
        panic!(
            "a share recorded on another table has to be queried, got {:?}",
            shape.derivation
        );
    };
    assert!(
        reason.contains("paper_shares"),
        "the reason names where the grant is recorded: {reason}"
    );
    let [query] = queries.as_slice() else {
        panic!("one bound query, one table a change may arrive on: {queries:?}");
    };
    assert_eq!(query.table, "paper_shares");
    assert_eq!(
        query.key_column, "paper_id",
        "a changed share row is replayed by the paper it names"
    );
}

/// A value the caller supplies per request is a contract the model itself cannot carry,
/// and getting it wrong is the one place in this feature where a mistake grants rather
/// than denies. Every declared source that reaches the model says so.
#[test]
fn every_request_scoped_gate_states_its_contract_with_the_caller() {
    let mut checked = 0usize;
    for (fixture, expected) in [
        ("connetto_or_policy", vec![("app_subjects", Some(","))]),
        ("connetto_capability", vec![("app_subjects", Some(","))]),
        ("tenant_setting", vec![("app_tenant_id", None)]),
        ("claims_role_gate", vec![("app_roles", Some(","))]),
        (
            "supabase_mfa_restrictive",
            vec![("request_jwt_claims_aal", None)],
        ),
        // A real list carries no delimiter, so the contract states none rather than
        // leaking the delimited string hazard onto a shape that cannot have it.
        ("token_claim_set", vec![("request_jwt_claims_teams", None)]),
        // The wrapper's body does the splitting, so the separator survives the hop.
        ("function_carried_set", vec![("app_teams", Some(","))]),
    ] {
        let (classified, db, registry) = support::try_load_fixture_classified(fixture);
        let outputs = Translation::plan(
            classified,
            &db,
            &registry,
            ConfidenceLevel::B,
            &GeneratorSettings::default(),
        )
        .outputs_accepting_gaps();

        let mut stated: Vec<(String, Option<String>)> = outputs
            .notes()
            .iter()
            .filter_map(|note| match note {
                TranslationNote::CallerSuppliesConditionParameter {
                    parameter,
                    separator,
                    ..
                } => Some((parameter.clone(), separator.clone())),
                _ => None,
            })
            .collect();
        stated.sort();
        stated.dedup();
        let want: Vec<(String, Option<String>)> = expected
            .iter()
            .map(|(p, s)| ((*p).to_string(), s.map(str::to_string)))
            .collect();
        assert_eq!(
            stated, want,
            "{fixture}: the parameters a caller has to send, and how each is split"
        );
        checked += stated.len();

        // The parameter the note names is the one the model declares, or a caller
        // following the note would still have every check refused.
        let json = serde_json::to_string(&outputs.json_model()).expect("the model serializes");
        for (parameter, _) in &stated {
            assert!(
                json.contains(&format!("\"{parameter}\"")),
                "{fixture}: the model declares no parameter named {parameter}"
            );
        }
    }
    assert!(
        checked > 0,
        "no fixture states a contract, so this checks nothing"
    );
}

/// The clock has carried the same contract since it was built and never announced it.
#[test]
fn the_clock_parameter_states_its_contract_too() {
    let sql = "
CREATE TABLE docs (id TEXT PRIMARY KEY, expires_at TIMESTAMPTZ);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_unexpired ON docs FOR SELECT USING (expires_at > now());
";
    let (classified, db, registry) = support::classify_sql(sql, None);
    let outputs = Translation::plan(
        classified,
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps();
    assert!(
        outputs.notes().iter().any(|note| matches!(
            note,
            TranslationNote::CallerSuppliesConditionParameter { parameter, setting_key, .. }
                if parameter == "request_time" && setting_key.is_none()
        )),
        "the clock is a request value like any other: {:?}",
        outputs.notes()
    );
}

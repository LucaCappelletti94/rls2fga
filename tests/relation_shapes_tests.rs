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
use rls2fga::generator::records::{Guard, RecordDerivation, RecordDescription, ValueSource};
use rls2fga::generator::relations::RelationShapes;
use rls2fga::generator::well_known::{MEMBER_RELATION, PG_ROLE_TYPE, TEAM_TYPE, USER_TYPE};
use rls2fga::parser::sql_parser::{parse_schema, ParserDB};
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

fn entry<'a>(shapes: &'a [RelationShapes], type_name: &str, relation: &str) -> &'a RelationShapes {
    shapes
        .iter()
        .find(|entry| entry.type_name == type_name && entry.relation == relation)
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
    assert_eq!(template.object_key, ValueSource::Column("id".to_string()));
    assert_eq!(template.subject_type, USER_TYPE);
    assert_eq!(
        template.subject_key,
        ValueSource::Column("owner_id".to_string())
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
        let reported: BTreeSet<(String, String)> = planned
            .relations()
            .into_iter()
            .map(|entry| (entry.type_name, entry.relation))
            .collect();

        let outputs = planned.clone().outputs_accepting_gaps();
        let declared: BTreeSet<(String, String)> = outputs
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
    assert_eq!(MEMBER_RELATION, "member");
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
    assert_eq!(template.object_key, ValueSource::Column("id".to_string()));
    assert_eq!(guards, &vec![Guard::NotNull("id".to_string())]);
    assert_eq!(template.subject_type, holder_type);
    assert_eq!(
        template.subject_key,
        ValueSource::Literal("all".to_string()),
        "one holder object stands for the whole list"
    );

    let members = entry(&shapes, &holder_type, MEMBER_RELATION);
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
    assert_eq!(template.relation, MEMBER_RELATION);
    assert_eq!(
        template.object_key,
        ValueSource::Literal("all".to_string()),
        "every member row names the same holder object"
    );
    assert_eq!(
        guards,
        &vec![Guard::NotNull("user_id".to_string())],
        "a null member is dropped exactly as the query's NULL guard drops it"
    );
    assert_eq!(template.subject_type, USER_TYPE);
    assert_eq!(
        template.subject_key,
        ValueSource::Column("user_id".to_string())
    );
}

/// The same member list carrying a predicate no evaluator here can read has to be
/// answered by querying, with a query bound to the changed row.
#[test]
fn a_holder_member_list_with_a_residual_predicate_joins() {
    let shapes = shapes_of(HOLDER, ACCESSOR_REGISTRY);
    let holder = shapes
        .iter()
        .find(|entry| entry.type_name.starts_with("reviewers_holder"))
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
        if entry.type_name.contains("_holder") || entry.relation.contains("_holder") {
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
        .filter(|entry| entry.relation.starts_with("grant_"))
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

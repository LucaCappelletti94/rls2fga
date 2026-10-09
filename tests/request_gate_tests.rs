//! What a gate that reads only the request costs the model and the tuple load.
//!
//! The gate has the same truth value for every row, so neither the conditions the
//! model declares nor the tuples a row carries may grow with what it does not read.

use rls2fga::classifier::function_registry::{SessionAttribute, SessionAttributeKind};
use rls2fga::generator::well_known::WellKnownTypes;
use rls2fga::translator::{Outputs, TranslatorBuilder};
use rls2fga::types::{
    ConfidenceLevel, RecordDerivation, RequestComparison, RequestPredicate, RowDecision,
};

mod support;

use support::footgun::{db_of, defines_in_type, gated_tables, relation_definition};

fn outputs_of(sql: &str) -> Outputs {
    TranslatorBuilder::new()
        .with_min_confidence(ConfidenceLevel::B)
        .with_session_attributes([
            SessionAttribute::setting("app.user_id", SessionAttributeKind::CallerId),
            SessionAttribute::setting("app.bot_list", SessionAttributeKind::SetAttribute),
        ])
        .build()
        .translate(&db_of(sql))
        .expect("translation should plan")
        .outputs()
        .expect("every clause translates")
}

fn condition_count(dsl: &str) -> usize {
    dsl.lines()
        .filter(|line| line.starts_with("condition "))
        .count()
}

/// `OpenFGA` refuses a model declaring more than 25 conditions. Every gate here tests
/// the same list the same way, so the model needs one condition however many tables
/// carry the gate.
#[test]
fn thirty_gated_tables_declare_one_condition() {
    let dsl = outputs_of(&gated_tables(30)).model();
    assert_eq!(condition_count(&dsl), 1, "{dsl}");
}

/// The gate reads no column, so a row carries one link to it whatever the number of
/// gates, beside the owner tuple it needs anyway.
#[test]
fn a_gated_row_carries_one_link_whatever_the_number_of_gates() {
    let outputs = outputs_of(&gated_tables(2));
    let per_row: Vec<&str> = outputs
        .tuple_queries()
        .iter()
        .filter(|query| query.sql.contains("FROM \"public\".\"t0\""))
        .map(|query| query.sql.as_str())
        .collect();
    assert_eq!(per_row.len(), 2, "{per_row:#?}");
    assert!(
        per_row.iter().all(|sql| !sql.contains("'user:*'")),
        "no fact read off a row may concern everybody: {per_row:#?}"
    );
}

/// What a gate admits is a fact about the policy, loaded once per table and per
/// distinct entry: `t0:read`, `t0:insert`, `t0:update`, `t0:delete` and `*`.
#[test]
fn gate_entries_are_loaded_once_per_table() {
    let outputs = outputs_of(&gated_tables(2));
    let constant: Vec<&str> = outputs
        .tuple_queries()
        .iter()
        .filter(|query| !query.sql.contains("FROM"))
        .map(|query| query.sql.as_str())
        .collect();
    assert_eq!(constant.len(), 10, "{constant:#?}");
}

/// A gate is reduced to one canonical formula, so reordered and repeated arms are the
/// same gate and reach the same relation.
#[test]
fn equivalent_spellings_of_a_gate_share_one_formula() {
    let set = "string_to_array(current_setting('app.bot_list', true), ',')";
    let schema = |clause: &str| {
        format!(
            "CREATE TABLE docs (id TEXT PRIMARY KEY);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_open ON docs FOR SELECT USING (true);
CREATE POLICY docs_cap ON docs AS RESTRICTIVE FOR SELECT USING ({clause});
"
        )
    };
    let plain = outputs_of(&schema(&format!(
        "'docs:read' = ANY({set}) OR '*' = ANY({set})"
    )))
    .model();
    let shuffled = outputs_of(&schema(&format!(
        "'*' = ANY({set}) OR ('docs:read' = ANY({set}) OR '*' = ANY({set}))"
    )))
    .model();
    assert_eq!(
        relation_definition(&plain, "docs", "can_select"),
        relation_definition(&shuffled, "docs", "can_select"),
        "{plain}\n---\n{shuffled}"
    );
    assert_eq!(plain, shuffled);
}

/// Two tables guarding on the same comparison declare it once.
#[test]
fn identical_guards_on_two_tables_share_one_condition() {
    let table = |name: &str| {
        format!(
            "CREATE TABLE {name} (id UUID PRIMARY KEY, expires_at TIMESTAMPTZ);
ALTER TABLE {name} ENABLE ROW LEVEL SECURITY;
CREATE POLICY {name}_live ON {name} FOR SELECT USING (expires_at > now());
"
        )
    };
    let dsl = outputs_of(&format!("{}{}", table("offers"), table("coupons"))).model();
    assert_eq!(condition_count(&dsl), 1, "{dsl}");
}

/// Policy `a_b` testing `c` and policy `a` testing `b_c` spell their gates alike, yet each
/// constant's tuples may satisfy only its own gate, or a caller holding one passes both.
#[test]
fn gates_on_constants_that_spell_alike_stay_apart() {
    let gate = |policy: &str, value: &str| {
        format!(
            "CREATE POLICY {policy} ON docs AS RESTRICTIVE FOR SELECT USING \
             ('{value}' = ANY(string_to_array(current_setting('app.bot_list', true), ',')));\n"
        )
    };
    let sql = format!(
        "CREATE TABLE docs (id TEXT PRIMARY KEY, owner TEXT NOT NULL);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY own ON docs FOR ALL USING (owner = current_setting('app.user_id', true));
{}{}",
        gate("a_b", "c"),
        gate("a", "b_c"),
    );
    let dsl = outputs_of(&sql).model();
    assert_eq!(defines_in_type(&dsl, "request_gate").len(), 2, "{dsl}");
}

/// The gate's truth comes from the request alone, so the recipe states it as a
/// predicate over the caller's list, beside the owner the row decides.
#[test]
fn a_request_gate_is_decided_by_the_request_alone() {
    let outputs = outputs_of(&gated_tables(1));
    let select = outputs
        .translation()
        .relations()
        .iter()
        .find(|entry| entry.type_name.as_str() == "t0" && entry.relation.as_str() == "can_select")
        .expect("t0 defines can_select");
    let Some(RowDecision::All(children)) = &select.decision else {
        panic!("can_select is decided by the row and the request: {select:#?}");
    };
    let predicates: Vec<&RequestPredicate> = children
        .iter()
        .filter_map(|child| match child {
            RowDecision::Request { predicate, .. } => Some(predicate),
            _ => None,
        })
        .collect();
    let [RequestPredicate::Any(atoms)] = predicates.as_slice() else {
        panic!("one gate, an OR of two entries: {children:#?}");
    };
    let mut values: Vec<&str> = atoms
        .iter()
        .map(|atom| match atom {
            RequestPredicate::Holds(atom) => {
                assert_eq!(atom.request_parameter, "app_bot_list");
                assert_eq!(atom.comparison, RequestComparison::CallerSetHolds);
                atom.value.as_str()
            }
            other => panic!("an entry test, got {other:?}"),
        })
        .collect();
    values.sort_unstable();
    assert_eq!(values, ["*", "t0:read"]);
}

/// The recipe names the link a row reaches its gates through, so a consumer keys it to the
/// table whose rows it judges and checks the row yields the link, and it names the one type
/// the gate admits, so a subject of another type or a userset is refused rather than let in.
#[test]
fn a_request_gate_names_its_link_and_the_type_it_admits() {
    let names = WellKnownTypes::new(
        "principal",
        "team",
        "pg_role",
        "pg_role_scope",
        "request_gate",
        "nobody",
    )
    .expect("the names are valid");
    let outputs = TranslatorBuilder::new()
        .with_min_confidence(ConfidenceLevel::B)
        .with_well_known_types(names)
        .with_session_attributes([
            SessionAttribute::setting("app.user_id", SessionAttributeKind::CallerId),
            SessionAttribute::setting("app.bot_list", SessionAttributeKind::SetAttribute),
        ])
        .build()
        .translate(&db_of(&gated_tables(1)))
        .expect("translation should plan")
        .outputs()
        .expect("every clause translates");
    let relations = outputs.translation().relations();
    let entry = |type_name: &str, relation: &str| {
        relations
            .iter()
            .find(|entry| entry.type_name.as_str() == type_name && entry.relation == relation)
            .unwrap_or_else(|| panic!("{type_name} defines {relation}"))
    };
    let Some(RowDecision::All(children)) = &entry("t0", "can_select").decision else {
        panic!("can_select is decided by the row and the request");
    };
    let [(relation, shapes, subject_type)] = children
        .iter()
        .filter_map(|child| match child {
            RowDecision::Request {
                relation,
                shapes,
                subject_type,
                ..
            } => Some((relation, shapes, subject_type)),
            _ => None,
        })
        .collect::<Vec<_>>()[..]
    else {
        panic!("one gate decides the read: {children:#?}");
    };

    assert!(!shapes.is_empty(), "the link is filled from the row");
    assert_eq!(
        *shapes,
        entry("t0", relation.as_str()).shapes,
        "the shapes are the link relation's own"
    );

    let entry_subjects: Vec<&str> = relations
        .iter()
        .filter(|entry| entry.type_name.as_str() == "request_gate")
        .flat_map(|entry| &entry.shapes)
        .filter_map(|shape| match &shape.derivation {
            RecordDerivation::Constant { record } => record.subject.split_once(':'),
            _ => None,
        })
        .map(|(subject_type, _)| subject_type)
        .collect();
    assert!(!entry_subjects.is_empty(), "the gate entries are reported");
    assert!(
        entry_subjects
            .iter()
            .all(|entry| *entry == subject_type.as_str()),
        "the recipe admits {subject_type}, the entries grant {entry_subjects:?}"
    );
    assert_eq!(subject_type.as_str(), "principal");
}

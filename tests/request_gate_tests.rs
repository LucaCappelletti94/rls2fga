//! What a gate that reads only the request costs the model.
//!
//! The gate has the same truth value for every row, so the conditions the model declares
//! may not grow with what it does not read.

use rls2fga::classifier::function_registry::{SessionAttribute, SessionAttributeKind};
use rls2fga::translator::{Outputs, TranslatorBuilder};
use rls2fga::types::ConfidenceLevel;

mod support;

use support::footgun::{db_of, gated_tables};

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

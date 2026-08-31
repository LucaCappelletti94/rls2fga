#![cfg(not(target_os = "windows"))]

use rls2fga::classifier::function_registry::{SessionAttribute, SessionAttributeKind};
use rls2fga::generator::model_generator::GeneratorSettings;
use rls2fga::generator::well_known::{
    WellKnownTypes, NOBODY_TYPE, PG_ROLE_SCOPE_TYPE, PG_ROLE_TYPE, TEAM_TYPE,
};
use rls2fga::translator::Translation;
use rls2fga::translator::TranslatorBuilder;
use rls2fga::types::ConfidenceLevel;

mod support;

#[tokio::test]
#[ignore = "requires Docker and OpenFGA container"]
async fn openfga_accepts_generated_model_and_checks_pass() {
    // 1. Start OpenFGA container
    let container = support::containers::start_openfga().await;

    let grpc_port = container.get_host_port_ipv4(8081).await.unwrap();
    let mut service_client = support::openfga::connect(grpc_port).await;

    // 2. Create store
    let store_id = support::openfga::create_store(&mut service_client, "integration-test").await;

    // 3. Write authorization model
    let (classified, db, registry) = support::load_fixture_classified("earth_metabolome");
    let model = Translation::plan(
        classified.clone(),
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .expect("translation should plan")
    .outputs_accepting_gaps()
    .json_model();
    let model_id =
        support::openfga::write_authorization_model(&mut service_client, &store_id, &model).await;

    // 4. Create scoped client and write tuples
    let client = service_client.into_client(&store_id, &model_id);

    // doc1 is owned by alice and doc2 by team alpha, so each row points at its owner and the
    // owner carries who it is and what it grants.
    let tuples = vec![
        support::openfga::make_tuple("ownables:doc1", "owner_id", "owner_grants_owner:alice"),
        support::openfga::make_tuple("owner_grants_owner:alice", "owner_user", "user:alice"),
        support::openfga::make_tuple("ownables:doc2", "owner_id", "owner_grants_owner:alpha"),
        support::openfga::make_tuple("owner_grants_owner:alpha", "owner_team", "team:alpha"),
        support::openfga::make_tuple("team:alpha", "member", "user:bob"),
        support::openfga::make_tuple("owner_grants_owner:alice", "grant_editor", "user:carol"),
        support::openfga::make_tuple("owner_grants_owner:alice", "grant_viewer", "team:beta"),
        support::openfga::make_tuple("team:beta", "member", "user:dave"),
        support::openfga::make_tuple("owner_grants_owner:alpha", "grant_admin", "user:eve"),
    ];

    support::openfga::write_tuples(&client, tuples).await;

    // 5. Check assertions
    let checks: Vec<(&str, &str, &str, bool)> = vec![
        // Direct ownership: alice owns doc1 -> admin -> editor -> viewer
        ("user:alice", "can_select", "ownables:doc1", true),
        ("user:alice", "can_insert", "ownables:doc1", true),
        ("user:alice", "can_update", "ownables:doc1", true),
        ("user:alice", "can_delete", "ownables:doc1", true),
        // Team ownership: bob is member of team:alpha which owns doc2
        ("user:bob", "can_select", "ownables:doc2", true),
        ("user:bob", "can_insert", "ownables:doc2", true),
        ("user:bob", "can_update", "ownables:doc2", true),
        ("user:bob", "can_delete", "ownables:doc2", true),
        // Cross-resource isolation: bob has no relation to doc1
        ("user:bob", "can_select", "ownables:doc1", false),
        // Grant escalation: carol has grant_editor on doc1 -> editor -> viewer
        ("user:carol", "can_select", "ownables:doc1", true),
        ("user:carol", "can_insert", "ownables:doc1", true),
        ("user:carol", "can_update", "ownables:doc1", true),
        ("user:carol", "can_delete", "ownables:doc1", false), // editor != admin
        // Team-mediated grant: dave is member of team:beta which has grant_viewer on doc1
        ("user:dave", "can_select", "ownables:doc1", true),
        ("user:dave", "can_insert", "ownables:doc1", false), // viewer != editor
        ("user:dave", "can_update", "ownables:doc1", false), // viewer != editor
        // Admin grant: eve has grant_admin on doc2 -> admin -> editor -> viewer
        ("user:eve", "can_select", "ownables:doc2", true),
        ("user:eve", "can_delete", "ownables:doc2", true),
        // Cross-resource isolation
        ("user:eve", "can_select", "ownables:doc1", false),
        ("user:alice", "can_select", "ownables:doc2", false),
    ];

    let mut failures = Vec::new();
    for (user, relation, object, expected) in &checks {
        let allowed = support::openfga::check_allowed(&client, user, relation, object).await;
        if allowed != *expected {
            failures.push(format!(
                "  {user} {relation} {object}: expected {expected}, got {allowed}"
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "Authorization check failures:\n{}",
        failures.join("\n")
    );
}

#[tokio::test]
#[ignore = "requires Docker and OpenFGA container"]
async fn openfga_accepts_generated_condition_parameter_names() {
    let container = support::containers::start_openfga().await;
    let grpc_port = container.get_host_port_ipv4(8081).await.unwrap();
    let mut client = support::openfga::connect(grpc_port).await;
    let store_id = support::openfga::create_store(&mut client, "condition-parameter-test").await;

    let schema = r#"
CREATE TABLE tenant_docs(id UUID PRIMARY KEY, "tenant-id" TEXT);
CREATE TABLE timed_docs(id UUID PRIMARY KEY, "in" TIMESTAMPTZ);
ALTER TABLE tenant_docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE timed_docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON tenant_docs FOR SELECT
    USING ("tenant-id" = current_setting('app.tenant'));
CREATE POLICY p ON timed_docs FOR SELECT USING ("in" > now());
"#;
    let attribute = SessionAttribute::setting("app.tenant", SessionAttributeKind::ScalarAttribute)
        .with_parameter("TenantValue_2")
        .expect("TenantValue_2 is a valid parameter");
    let well_known = WellKnownTypes::new(
        "Principal-Team/V2.member",
        TEAM_TYPE,
        PG_ROLE_TYPE,
        PG_ROLE_SCOPE_TYPE,
        NOBODY_TYPE,
    )
    .expect("the extended type name should be valid");
    let db = support::footgun::db_of(schema);
    let model = TranslatorBuilder::new()
        .with_request_time_parameter("as_of_2")
        .expect("as_of_2 is a valid parameter")
        .with_well_known_types(well_known)
        .with_session_attributes([attribute])
        .build()
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .json_model();

    let conditions = model.conditions.as_ref().expect("conditions should exist");
    assert!(conditions
        .values()
        .any(|condition| condition.parameters.contains_key("TenantValue_2")));
    assert!(conditions
        .values()
        .any(|condition| condition.parameters.contains_key("_in")));
    support::openfga::write_authorization_model(&mut client, &store_id, &model).await;
}

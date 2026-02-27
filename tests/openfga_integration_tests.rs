#![cfg(not(target_os = "windows"))]

use testcontainers::{
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
    GenericImage, ImageExt,
};

use rls2fga::classifier::patterns::ConfidenceLevel;
use rls2fga::generator::json_model;

mod support;

#[tokio::test]
#[ignore = "requires Docker and OpenFGA container"]
async fn openfga_accepts_generated_model_and_checks_pass() {
    // 1. Start OpenFGA container
    let container = GenericImage::new("openfga/openfga", "v1.11.6")
        .with_exposed_port(8080.tcp())
        .with_exposed_port(8081.tcp())
        .with_wait_for(WaitFor::message_on_stdout("starting HTTP server"))
        .with_cmd(["run"])
        .start()
        .await
        .expect("Failed to start OpenFGA container");

    let grpc_port = container.get_host_port_ipv4(8081).await.unwrap();
    let mut service_client = support::openfga::connect(grpc_port).await;

    // 2. Create store
    let store_id = support::openfga::create_store(&mut service_client, "integration-test").await;

    // 3. Write authorization model
    let (classified, db, registry) = support::load_fixture_classified("earth_metabolome");
    let model = json_model::generate_json_model(&classified, &db, &registry, ConfidenceLevel::B);
    let model_id =
        support::openfga::write_authorization_model(&mut service_client, &store_id, &model).await;

    // 4. Create scoped client and write tuples
    let client = service_client.into_client(&store_id, &model_id);

    let tuples = vec![
        support::openfga::make_tuple("ownables:doc1", "owner_user", "user:alice"),
        support::openfga::make_tuple("ownables:doc2", "owner_team", "team:alpha"),
        support::openfga::make_tuple("team:alpha", "member", "user:bob"),
        support::openfga::make_tuple("ownables:doc1", "grant_editor", "user:carol"),
        support::openfga::make_tuple("ownables:doc1", "grant_viewer", "team:beta"),
        support::openfga::make_tuple("team:beta", "member", "user:dave"),
        support::openfga::make_tuple("ownables:doc2", "grant_admin", "user:eve"),
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

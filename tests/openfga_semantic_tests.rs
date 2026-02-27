#![cfg(not(target_os = "windows"))]

use openfga_client::client::{OpenFgaClient, TupleKey};
use openfga_client::tonic::transport::Channel;
use testcontainers::{
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
    GenericImage, ImageExt,
};

use rls2fga::classifier::patterns::ConfidenceLevel;
use rls2fga::generator::json_model;

mod support;

struct Scenario {
    name: &'static str,
    fixture: &'static str,
    min_confidence: ConfidenceLevel,
    tuples: Vec<(&'static str, &'static str, &'static str)>,
    checks: Vec<(&'static str, &'static str, &'static str, bool)>,
}

#[tokio::test]
#[ignore = "requires Docker and OpenFGA container"]
async fn openfga_semantic_checks_all_patterns() {
    // ── Start shared OpenFGA container ──────────────────────────────────────
    let container = GenericImage::new("openfga/openfga", "v1.11.6")
        .with_exposed_port(8080.tcp())
        .with_exposed_port(8081.tcp())
        .with_wait_for(WaitFor::message_on_stdout("starting HTTP server"))
        .with_cmd(["run"])
        .start()
        .await
        .expect("Failed to start OpenFGA container");

    let grpc_port = container.get_host_port_ipv4(8081).await.unwrap();

    // ── Define scenarios ────────────────────────────────────────────────────
    let scenarios = vec![
        // P1 — EMI role threshold
        Scenario {
            name: "P1_emi_role_threshold",
            fixture: "earth_metabolome",
            min_confidence: ConfidenceLevel::B,
            tuples: vec![
                ("ownables:doc1", "owner_user", "user:alice"),
                ("ownables:doc2", "owner_team", "team:alpha"),
                ("team:alpha", "member", "user:bob"),
                ("ownables:doc1", "grant_editor", "user:carol"),
                ("ownables:doc1", "grant_viewer", "team:beta"),
                ("team:beta", "member", "user:dave"),
                ("ownables:doc2", "grant_admin", "user:eve"),
            ],
            checks: vec![
                // Direct ownership: alice owns doc1
                ("user:alice", "can_select", "ownables:doc1", true),
                ("user:alice", "can_insert", "ownables:doc1", true),
                ("user:alice", "can_update", "ownables:doc1", true),
                ("user:alice", "can_delete", "ownables:doc1", true),
                // Team ownership: bob via team:alpha owns doc2
                ("user:bob", "can_select", "ownables:doc2", true),
                ("user:bob", "can_insert", "ownables:doc2", true),
                ("user:bob", "can_update", "ownables:doc2", true),
                ("user:bob", "can_delete", "ownables:doc2", true),
                // Cross-resource isolation
                ("user:bob", "can_select", "ownables:doc1", false),
                // Grant escalation: carol has grant_editor
                ("user:carol", "can_select", "ownables:doc1", true),
                ("user:carol", "can_insert", "ownables:doc1", true),
                ("user:carol", "can_update", "ownables:doc1", true),
                ("user:carol", "can_delete", "ownables:doc1", false),
                // Team-mediated grant: dave via team:beta grant_viewer
                ("user:dave", "can_select", "ownables:doc1", true),
                ("user:dave", "can_insert", "ownables:doc1", false),
                // Cross-resource isolation
                ("user:eve", "can_select", "ownables:doc1", false),
            ],
        },
        // P2 — Role IN-list
        Scenario {
            name: "P2_role_in_list",
            fixture: "role_in_list",
            min_confidence: ConfidenceLevel::B,
            tuples: vec![
                ("ownables:res1", "owner_user", "user:alice"),
                ("ownables:res1", "owner_team", "team:alpha"),
                ("team:alpha", "member", "user:bob"),
                ("ownables:res1", "grant_viewer", "user:carol"),
                ("ownables:res1", "grant_editor", "user:dave"),
            ],
            checks: vec![
                ("user:alice", "can_select", "ownables:res1", true),
                ("user:bob", "can_select", "ownables:res1", true),
                ("user:carol", "can_select", "ownables:res1", true),
                ("user:dave", "can_select", "ownables:res1", true),
                ("user:nobody", "can_select", "ownables:res1", false),
                ("user:carol", "role_editor", "ownables:res1", false),
                ("user:dave", "role_editor", "ownables:res1", true),
                ("user:alice", "role_admin", "ownables:res1", true),
            ],
        },
        // P3 — Direct ownership
        Scenario {
            name: "P3_simple_ownership",
            fixture: "simple_ownership",
            min_confidence: ConfidenceLevel::B,
            tuples: vec![
                ("resources:r1", "owner", "user:alice"),
                ("resources:r2", "owner", "user:bob"),
            ],
            checks: vec![
                ("user:alice", "can_select", "resources:r1", true),
                ("user:alice", "can_delete", "resources:r1", true),
                ("user:bob", "can_select", "resources:r1", false),
                ("user:bob", "can_delete", "resources:r1", false),
                ("user:bob", "can_select", "resources:r2", true),
                ("user:alice", "can_select", "resources:r2", false),
                ("user:nobody", "can_select", "resources:r1", false),
            ],
        },
        // P4 — EXISTS membership (tuple-to-userset)
        Scenario {
            name: "P4_membership_check",
            fixture: "membership_check",
            min_confidence: ConfidenceLevel::B,
            tuples: vec![
                ("teams:t1", "member", "user:alice"),
                ("teams:t1", "member", "user:bob"),
                ("teams:t2", "member", "user:carol"),
                ("projects:p1", "teams", "teams:t1"),
                ("projects:p2", "teams", "teams:t2"),
            ],
            checks: vec![
                ("user:alice", "can_select", "projects:p1", true),
                ("user:bob", "can_select", "projects:p1", true),
                ("user:carol", "can_select", "projects:p2", true),
                ("user:carol", "can_select", "projects:p1", false),
                ("user:alice", "can_select", "projects:p2", false),
                ("user:nobody", "can_select", "projects:p1", false),
            ],
        },
        // P5 — Parent inheritance (nested tuple-to-userset)
        Scenario {
            name: "P5_parent_inheritance",
            fixture: "parent_inheritance",
            min_confidence: ConfidenceLevel::B,
            tuples: vec![
                ("projects:proj1", "owner", "user:alice"),
                ("projects:proj2", "owner", "user:bob"),
                ("tasks:task1", "projects", "projects:proj1"),
                ("tasks:task2", "projects", "projects:proj1"),
                ("tasks:task3", "projects", "projects:proj2"),
            ],
            checks: vec![
                ("user:alice", "can_select", "tasks:task1", true),
                ("user:alice", "can_select", "tasks:task2", true),
                ("user:alice", "can_select", "projects:proj1", true),
                ("user:alice", "can_select", "tasks:task3", false),
                ("user:bob", "can_select", "tasks:task3", true),
                ("user:bob", "can_select", "tasks:task1", false),
                ("user:nobody", "can_select", "tasks:task1", false),
            ],
        },
        // P6 — Boolean flag (wildcard)
        Scenario {
            name: "P6_public_flag",
            fixture: "public_flag",
            min_confidence: ConfidenceLevel::B,
            tuples: vec![("articles:a1", "public_viewer", "user:*")],
            checks: vec![
                ("user:anyone", "can_select", "articles:a1", true),
                ("user:alice", "can_select", "articles:a1", true),
                ("user:anyone", "can_select", "articles:a2", false),
                ("user:alice", "can_select", "articles:a2", false),
            ],
        },
        // P7 — ABAC AND (relationship + attribute guard)
        Scenario {
            name: "P7_abac_status",
            fixture: "abac_status",
            min_confidence: ConfidenceLevel::C,
            tuples: vec![
                ("ownables:item1", "owner_user", "user:alice"),
                ("ownables:item1", "owner_team", "team:alpha"),
                ("team:alpha", "member", "user:bob"),
                ("ownables:item1", "grant_editor", "user:carol"),
                ("ownables:item1", "grant_viewer", "user:dave"),
            ],
            checks: vec![
                ("user:alice", "can_update", "ownables:item1", true),
                ("user:bob", "can_update", "ownables:item1", true),
                ("user:carol", "can_update", "ownables:item1", true),
                ("user:dave", "can_update", "ownables:item1", false),
                ("user:nobody", "can_update", "ownables:item1", false),
            ],
        },
        // P8 — Compound OR (P3 owner + P6 public)
        Scenario {
            name: "P8_compound_or",
            fixture: "compound_or",
            min_confidence: ConfidenceLevel::B,
            tuples: vec![
                ("documents:doc1", "owner", "user:alice"),
                ("documents:doc1", "public_viewer", "user:*"),
                ("documents:doc2", "owner", "user:bob"),
            ],
            checks: vec![
                ("user:alice", "can_select", "documents:doc1", true),
                ("user:bob", "can_select", "documents:doc2", true),
                ("user:bob", "can_select", "documents:doc1", true),
                ("user:anyone", "can_select", "documents:doc1", true),
                ("user:alice", "can_select", "documents:doc2", false),
                ("user:anyone", "can_select", "documents:doc2", false),
                ("user:nobody", "can_select", "documents:doc2", false),
            ],
        },
        // P10 — Constant bool intersection (permissive TRUE & restrictive FALSE)
        Scenario {
            name: "P10_constant_bool",
            fixture: "constant_bool",
            min_confidence: ConfidenceLevel::B,
            tuples: vec![("docs:d1", "public_viewer", "user:*")],
            checks: vec![
                ("user:anyone", "can_select", "docs:d1", false),
                ("user:alice", "can_select", "docs:d1", false),
            ],
        },
    ];

    // ── Run all scenarios ───────────────────────────────────────────────────
    let mut all_failures = Vec::new();

    for scenario in &scenarios {
        let scenario_failures = run_scenario(grpc_port, scenario).await;
        if !scenario_failures.is_empty() {
            all_failures.push(format!(
                "[{}] {} failure(s):\n{}",
                scenario.name,
                scenario_failures.len(),
                scenario_failures.join("\n")
            ));
        }
    }

    assert!(
        all_failures.is_empty(),
        "Authorization check failures across scenarios:\n\n{}",
        all_failures.join("\n\n")
    );
}

async fn run_scenario(grpc_port: u16, scenario: &Scenario) -> Vec<String> {
    // 1. Fresh client for each scenario (create_store needs &mut)
    let mut service_client = support::openfga::connect(grpc_port).await;

    // 2. Create store
    let store_id = support::openfga::create_store(&mut service_client, scenario.name).await;

    // 3. Generate and upload JSON model
    let (classified, db, registry) = support::try_load_fixture_classified(scenario.fixture);
    let model =
        json_model::generate_json_model(&classified, &db, &registry, scenario.min_confidence);
    let model_id =
        support::openfga::write_authorization_model(&mut service_client, &store_id, &model).await;

    // 4. Create scoped client
    let client: OpenFgaClient<Channel> = service_client.into_client(&store_id, &model_id);

    // 5. Write tuples
    let tuples: Vec<TupleKey> = scenario
        .tuples
        .iter()
        .map(|(obj, rel, user)| support::openfga::make_tuple(obj, rel, user))
        .collect();

    support::openfga::write_tuples(&client, tuples).await;

    // 6. Run checks and collect failures
    let mut failures = Vec::new();
    for (user, relation, object, expected) in &scenario.checks {
        let allowed = support::openfga::check_allowed(&client, user, relation, object).await;
        if allowed != *expected {
            failures.push(format!(
                "  {user} {relation} {object}: expected {expected}, got {allowed}"
            ));
        }
    }

    failures
}

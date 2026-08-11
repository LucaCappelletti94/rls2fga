//! Writing a generated model to a running `OpenFGA` server.
//!
//! The claim under test is the one a consumer cannot check for itself: that the
//! emitted [`AuthorizationModel`] is what the write call accepts, and that the
//! model the server then holds is the one that was sent.

#![cfg(not(target_os = "windows"))]

use testcontainers::{
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
    GenericImage, ImageExt,
};

use rls2fga::classifier::patterns::ConfidenceLevel;
use rls2fga::translator::TranslatorBuilder;

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

#[tokio::test]
#[ignore = "requires Docker and an openfga/openfga container"]
async fn a_written_model_is_the_model_the_server_answers_from() {
    let container = GenericImage::new("openfga/openfga", "v1.11.6")
        .with_exposed_port(8080.tcp())
        .with_exposed_port(8081.tcp())
        .with_wait_for(WaitFor::message_on_stdout("starting HTTP server"))
        .with_cmd(["run"])
        .start()
        .await
        .expect("the OpenFGA container should start");
    let grpc_port = container.get_host_port_ipv4(8081).await.unwrap();
    let mut service = support::openfga::connect(grpc_port).await;
    let store_id = support::openfga::create_store(&mut service, "client-surface").await;

    let db = rls2fga::parser::sql_parser::parse_schema(OWNERSHIP).expect("the schema parses");
    let model = TranslatorBuilder::new()
        .with_min_confidence(ConfidenceLevel::B)
        .with_registry_json(ACCESSOR_REGISTRY)
        .expect("the registry parses")
        .build()
        .translate(&db)
        .outputs_accepting_gaps()
        .json_model();

    let model_id = rls2fga::client::write_authorization_model(&mut service, &store_id, &model)
        .await
        .expect("the server accepts the emitted model");
    assert!(
        !model_id.is_empty(),
        "the write answers with the model's id"
    );

    // The server hands back what it stored, so this compares the emitted model
    // against the one the checks below are answered from.
    let stored =
        support::openfga::read_authorization_model(&mut service, &store_id, &model_id).await;
    let mut stored = serde_json::to_value(&stored).expect("the stored model serializes");
    let stored = stored
        .as_object_mut()
        .expect("a model is an object")
        .remove("type_definitions")
        .expect("a stored model carries its types");
    let sent = serde_json::to_value(&model).expect("the emitted model serializes");
    assert_eq!(
        Some(&stored),
        sent.get("type_definitions"),
        "the server stored something other than what was sent"
    );
    assert!(
        stored.as_array().is_some_and(|types| types.len() >= 2),
        "the comparison is worth making only while the model has types: {stored}"
    );

    let client = service.into_client(&store_id, &model_id);
    support::openfga::write_tuples(
        &client,
        vec![support::openfga::make_tuple(
            "docs:d1",
            "owner",
            "user:alice",
        )],
    )
    .await;

    assert!(
        support::openfga::check_allowed(&client, "user:alice", "can_select", "docs:d1").await,
        "the owner reads the row"
    );
    assert!(
        !support::openfga::check_allowed(&client, "user:bob", "can_select", "docs:d1").await,
        "a stranger does not"
    );
}

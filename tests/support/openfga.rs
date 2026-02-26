use reqwest::Client;
use serde::Serialize;
use serde_json::{json, Value};

pub(crate) async fn create_store(client: &Client, base: &str, name: &str) -> String {
    let response = client
        .post(format!("{base}/stores"))
        .json(&json!({ "name": name }))
        .send()
        .await
        .expect("store creation request should succeed");

    let status = response.status();
    let body: Value = response
        .json()
        .await
        .expect("store creation response should decode");
    assert!(
        status.is_success(),
        "Store creation failed ({status}): {body:#}"
    );

    body["id"].as_str().expect("missing store id").to_string()
}

pub(crate) async fn write_authorization_model<T: Serialize>(
    client: &Client,
    base: &str,
    store_id: &str,
    model: &T,
) -> String {
    let response = client
        .post(format!("{base}/stores/{store_id}/authorization-models"))
        .json(model)
        .send()
        .await
        .expect("authorization model write request should succeed");

    let status = response.status();
    let body: Value = response
        .json()
        .await
        .expect("authorization model response should decode");
    assert!(
        status.is_success(),
        "Model write failed ({status}): {body:#}"
    );

    body["authorization_model_id"]
        .as_str()
        .expect("missing authorization_model_id")
        .to_string()
}

pub(crate) async fn write_tuple_keys(
    client: &Client,
    base: &str,
    store_id: &str,
    model_id: &str,
    tuple_keys: &[Value],
) {
    let response = client
        .post(format!("{base}/stores/{store_id}/write"))
        .json(&json!({
            "authorization_model_id": model_id,
            "writes": { "tuple_keys": tuple_keys }
        }))
        .send()
        .await
        .expect("tuple write request should succeed");

    let status = response.status();
    let body: Value = response
        .json()
        .await
        .expect("tuple write response should decode");
    assert!(
        status.is_success(),
        "Tuple write failed ({status}): {body:#}"
    );
}

pub(crate) async fn check_allowed(
    client: &Client,
    base: &str,
    store_id: &str,
    model_id: &str,
    user: &str,
    relation: &str,
    object: &str,
) -> bool {
    let response = client
        .post(format!("{base}/stores/{store_id}/check"))
        .json(&json!({
            "authorization_model_id": model_id,
            "tuple_key": {
                "user": user,
                "relation": relation,
                "object": object
            }
        }))
        .send()
        .await
        .expect("check request should succeed");

    let status = response.status();
    let body: Value = response.json().await.expect("check response should decode");
    assert!(status.is_success(), "Check failed ({status}): {body:#}");

    body["allowed"].as_bool().expect("missing check result")
}

use openfga_client::client::{
    AuthorizationModel, CreateStoreRequest, OpenFgaClient, OpenFgaServiceClient,
    ReadAuthorizationModelRequest, TupleKey, TupleKeyWithoutCondition,
    WriteAuthorizationModelRequest,
};
use openfga_client::tonic::transport::Channel;

pub(crate) type GrpcClient = OpenFgaServiceClient<Channel>;

pub(crate) async fn connect(grpc_port: u16) -> GrpcClient {
    OpenFgaServiceClient::connect(format!("http://localhost:{grpc_port}"))
        .await
        .expect("gRPC connection to OpenFGA should succeed")
}

pub(crate) async fn create_store(client: &mut GrpcClient, name: &str) -> String {
    let response = client
        .create_store(CreateStoreRequest {
            name: name.to_string(),
        })
        .await
        .expect("store creation should succeed");

    response.into_inner().id
}

pub(crate) async fn write_authorization_model(
    client: &mut GrpcClient,
    store_id: &str,
    model: &rls2fga::generator::json_model::AuthorizationModel,
) -> String {
    let json = serde_json::to_string(model).expect("model should serialize");
    let proto_model: AuthorizationModel =
        serde_json::from_str(&json).expect("model should deserialize into openfga-client type");

    let response = client
        .write_authorization_model(WriteAuthorizationModelRequest {
            store_id: store_id.to_string(),
            type_definitions: proto_model.type_definitions,
            schema_version: proto_model.schema_version,
            conditions: proto_model.conditions,
        })
        .await
        .expect("authorization model write should succeed");

    response.into_inner().authorization_model_id
}

pub(crate) async fn write_tuples(client: &OpenFgaClient<Channel>, tuples: Vec<TupleKey>) {
    if tuples.is_empty() {
        return;
    }
    client
        .write(tuples, None)
        .await
        .expect("tuple write should succeed");
}

pub(crate) async fn check_allowed(
    client: &OpenFgaClient<Channel>,
    user: &str,
    relation: &str,
    object: &str,
) -> bool {
    client
        .check_simple(TupleKeyWithoutCondition {
            user: user.to_string(),
            relation: relation.to_string(),
            object: object.to_string(),
        })
        .await
        .expect("check request should succeed")
}

pub(crate) fn make_tuple(object: &str, relation: &str, user: &str) -> TupleKey {
    TupleKey {
        user: user.to_string(),
        relation: relation.to_string(),
        object: object.to_string(),
        condition: None,
    }
}

pub(crate) async fn read_authorization_model(
    client: &mut GrpcClient,
    store_id: &str,
    model_id: &str,
) -> AuthorizationModel {
    let response = client
        .read_authorization_model(ReadAuthorizationModelRequest {
            store_id: store_id.to_string(),
            id: model_id.to_string(),
        })
        .await
        .expect("read authorization model should succeed");

    response
        .into_inner()
        .authorization_model
        .expect("authorization model should be present")
}

pub mod keytypes;

pub mod types {
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Debug)]
    pub struct OperationRequest {
        pub user_pubkey: Vec<u8>,
        pub operation_type: String,
        pub encrypted_data: Option<Vec<u8>>,
        pub encrypted_sym_key: Option<Vec<u8>>,
        pub nonce: Option<Vec<u8>>,
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub enum ResultType {
        Number,
        String,
        Binary,
    }

    #[derive(Serialize, Deserialize)]
    pub struct OperationResponse {
        pub encrypted_result: Vec<u8>,
        pub result_type: ResultType,
    }

    #[derive(Deserialize)]
    pub struct ApiOperationRequest {
        pub user_pubkey: String,
        pub operation_type: String,
        pub encrypted_data: Option<String>,
        pub encrypted_sym_key: Option<String>,
        pub nonce: Option<String>,
    }

    #[derive(Serialize)]
    pub struct ApiOperationResponse {
        pub encrypted_result: String,
        pub result_type: String,
    }

    #[derive(Serialize)]
    pub struct UserInitResponse {
        pub server_pubkey: String,
        pub user_private_key: String,
        pub user_pubkey: String,
    }
}

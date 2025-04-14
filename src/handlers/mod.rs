pub mod handlers {
    use crate::{
        enclave::enarx::process_with_enarx,
        types::types::{ApiOperationRequest, ApiOperationResponse, ResultType, UserInitResponse},
        utils::utils::{convert_api_to_internal_request, user_init},
    };
    #[cfg(feature = "server")]
    use actix_web::{
        HttpResponse, Responder,
        web::{self},
    };
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use hpke::Serializable;

    #[cfg(feature = "server")]
    pub async fn process_operation(request: web::Json<ApiOperationRequest>) -> HttpResponse {
        let operation = match convert_api_to_internal_request(&request) {
            Ok(op) => op,
            Err(e) => return HttpResponse::BadRequest().body(format!("Invalid request: {}", e)),
        };

        let (result, res_type) = match process_with_enarx(&operation) {
            Ok((res, res_type)) => (res, res_type),
            Err(e) => {
                return HttpResponse::InternalServerError()
                    .body(format!("Processing error: {}", e));
            }
        };

        let api_response = ApiOperationResponse {
            encrypted_result: BASE64.encode(&result),
            result_type: match res_type {
                ResultType::Number => "number".to_string(),
                ResultType::String => "string".to_string(),
                ResultType::Binary => "binary".to_string(),
            },
        };

        HttpResponse::Ok().json(api_response)
    }

    #[cfg(feature = "server")]
    pub async fn user_init_handler() -> impl Responder {
        let (server_pk, user_sk, user_pk) = match user_init() {
            Ok((spk, usk, upk)) => (spk, usk, upk),
            Err(e) => {
                return HttpResponse::InternalServerError()
                    .body(format!("User Initialization error: {}", e));
            }
        };

        let response = UserInitResponse {
            server_pubkey: BASE64.encode(server_pk.to_bytes()),
            user_private_key: BASE64.encode(user_sk.to_bytes()),
            user_pubkey: BASE64.encode(user_pk.to_bytes()),
        };

        HttpResponse::Ok().json(response)
    }
}

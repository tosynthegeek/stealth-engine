use std::env;

use crate::{
    stealth_error::StealthError,
    types::{
        keytypes::KeyType,
        types::{ApiOperationRequest, OperationRequest},
    },
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use hpke::{Kem as KemTrait, kem::X25519HkdfSha256};
use rand::{SeedableRng, rngs::StdRng};
use sha2::{Digest, Sha256};

type Kem = X25519HkdfSha256;

pub fn detect_key_type(public_key: &[u8]) -> KeyType {
    match public_key.len() {
        65 if public_key.starts_with(&[0x04]) => KeyType::Secp256k1,

        33 if public_key.starts_with(&[0x02]) || public_key.starts_with(&[0x03]) => {
            KeyType::Secp256k1
        }

        32 => KeyType::Ed25519,

        _ => KeyType::Unknown,
    }
}

pub fn convert_api_to_internal_request(
    api_req: &ApiOperationRequest,
) -> Result<OperationRequest, String> {
    Ok(OperationRequest {
        user_pubkey: BASE64
            .decode(&api_req.user_pubkey)
            .map_err(|e| format!("Invalid user_pubkey: {}", e))?,
        operation_type: api_req.operation_type.clone(),
        encrypted_data: if let Some(data) = &api_req.encrypted_data {
            Some(
                BASE64
                    .decode(data)
                    .map_err(|e| format!("Invalid encrypted_data: {}", e))?,
            )
        } else {
            None
        },
        encrypted_sym_key: if let Some(sym_key) = &api_req.encrypted_sym_key {
            Some(
                BASE64
                    .decode(sym_key)
                    .map_err(|e| format!("Invalid sym key: {}", e))?,
            )
        } else {
            None
        },
        nonce: if let Some(nonce) = &api_req.nonce {
            Some(
                BASE64
                    .decode(nonce)
                    .map_err(|e| format!("Invalid nonce: {}", e))?,
            )
        } else {
            None
        },
    })
}

pub fn server_init_from_env()
-> Result<(<Kem as KemTrait>::PrivateKey, <Kem as KemTrait>::PublicKey), StealthError> {
    let seed = match env::var("HPKE_SEED") {
        Ok(seed) => seed,
        Err(e) => {
            return Err(StealthError::EnarxError(format!(
                "Failed to read seed from env: {}",
                e
            )));
        }
    };

    let mut hasher = Sha256::new();
    hasher.update(seed.as_bytes());
    let hash = hasher.finalize();

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&hash);

    let mut csprng = StdRng::from_seed(seed);
    Ok(Kem::gen_keypair(&mut csprng))
}

pub fn user_init() -> Result<
    (
        <Kem as KemTrait>::PublicKey,
        <Kem as KemTrait>::PrivateKey,
        <Kem as KemTrait>::PublicKey,
    ),
    StealthError,
> {
    let (_, server_pk) = server_init_from_env()?;
    let mut csprng = StdRng::from_os_rng();
    let (user_sk, user_pk) = Kem::gen_keypair(&mut csprng);

    Ok((server_pk, user_sk, user_pk))
}

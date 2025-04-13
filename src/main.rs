use encryption::hpke::{hpke_decrypt_msg, hpke_encrypt_msg};
use hpke::{Kem as KemTrait, Serializable, kem::X25519HkdfSha256};
use rand::{SeedableRng, rngs::StdRng};
use stealth_error::StealthError;
use types::types::{OperationRequest, ResultType};

pub mod enclave;
pub mod encryption;
pub mod handlers;
pub mod stealth_error;
pub mod types;
pub mod utils;

type Kem = X25519HkdfSha256;

fn main() -> Result<(), StealthError> {
    let (server_privkey, server_pubkey) = server_init();
    let (user_privkey, user_pubkey) = server_init();

    let data = "1, 2, 3, 4, 5";
    let user_pub = &user_pubkey.to_bytes();
    let nonce = server_pubkey.to_bytes();
    let encrypted_data = hpke_encrypt_msg(&data.as_bytes(), &nonce, &server_pubkey.to_bytes())?;
    let mut operation = OperationRequest {
        user_pubkey: user_pub.to_vec(),
        operation_type: "reverse_string".to_string(),
        encrypted_data: Some(encrypted_data),
        nonce: Some(nonce.to_vec()),
    };

    let (res, res_type) = operation.process_encrypted_data(&server_privkey.to_bytes())?;
    let decrypted_res = hpke_decrypt_msg(&user_privkey.to_bytes(), &res, &nonce.to_vec())?;
    match res_type {
        ResultType::Number => {
            let result_bytes: [u8; 8] = decrypted_res.try_into().unwrap();
            let result = f64::from_be_bytes(result_bytes);
            println!("Result: {}", result);
        }
        ResultType::String => {
            let string = String::from_utf8(decrypted_res)
                .map_err(|e| StealthError::DecryptionFailed(format!("Failed to decode: {e}")))?;
            println!("Result: {}", string);
        }
        ResultType::Binary => {
            println!("Result (hex): {}", hex::encode(&decrypted_res));
        }
    }

    Ok(())
}

fn server_init() -> (<Kem as KemTrait>::PrivateKey, <Kem as KemTrait>::PublicKey) {
    let mut csprng = StdRng::from_os_rng();
    Kem::gen_keypair(&mut csprng)
}

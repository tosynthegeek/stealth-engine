use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use stealth_engine::{
    encryption::{
        hpke::{hpke_decrypt_msg, hpke_encrypt_msg},
        symmetric::sym_encrypt_data,
    },
    stealth_error::StealthError,
    types::types::ResultType,
};
pub const USER_PK: &str = "bO/u8m/ldGHn4GRMsxfILCSEjK5ocsa7QSajCZSOQk4=";
pub const NONCE: &str = "QL0VUYJqmBmqiyPZ";
fn main() {
    let res = "c8jYpbpFUjyKPBq4AGBDqKW0aB9p1ADYGfK48EQ5bjclLMU6vXJ/q2FINvrl+Je3EMJGU+EEUp8=";
    let res_type = ResultType::Number;

    if let Err(e) = readable_res(res, res_type) {
        eprintln!("Error: {}", e);
    }
}

/// This would be done on the clientside without any server interaction.
/// The function provides an easy interface to perform client-side encryption during testing.
/// In a real-world scenario, this logic would be 100% executed in the frontend (e.g., browser or mobile client).
pub fn user_encrypt_data(
    data: &str,
    server_pk: &str,
) -> Result<(String, String, String), StealthError> {
    let server_pubkey_bytes = BASE64
        .decode(server_pk)
        .map_err(|e| StealthError::InvalidData(format!("Invalid server public key: {}", e)))?;
    let (key, nonce) = generate_random_symmetric_key_and_nonce();
    let encrypted_data = sym_encrypt_data(data.as_bytes(), &key)?;
    let encrypted_sym_key = hpke_encrypt_msg(&key, &nonce, &server_pubkey_bytes)?;
    Ok((
        BASE64.encode(&encrypted_sym_key),
        BASE64.encode(&encrypted_data),
        BASE64.encode(&nonce),
    ))
}

fn generate_random_symmetric_key_and_nonce() -> (Vec<u8>, Vec<u8>) {
    use rand::Rng;
    let mut rng = rand::rng();
    let mut nonce = [0u8; 12];
    let mut key = [0u8; 32];
    rng.fill(&mut key);
    rng.fill(&mut nonce);
    (key.to_vec(), nonce.to_vec())
}

fn readable_res(data: &str, res_type: ResultType) -> Result<(), StealthError> {
    let user_pubkey = BASE64
        .decode(USER_PK)
        .map_err(|e| StealthError::InvalidKeyFormat(format!("Invalid user_pubkey: {}", e)))?;

    let nonce = BASE64
        .decode(NONCE)
        .map_err(|e| StealthError::InvalidKeyFormat(format!("Invalid nonce: {}", e)))?;
    let encrypted_data = BASE64
        .decode(data)
        .map_err(|e| StealthError::InvalidData(format!("Invalid encrypted_data: {}", e)))?;
    let decrypted_data = hpke_decrypt_msg(&user_pubkey, &encrypted_data, &nonce)?;
    match res_type {
        ResultType::Number => {
            if decrypted_data.len() == 8 {
                let result_bytes: [u8; 8] = decrypted_data.try_into().map_err(|_| {
                    StealthError::DecryptionFailed("Failed to convert bytes to f64".to_string())
                })?;
                let result = f64::from_be_bytes(result_bytes);
                println!("Result (Number): {}", result);
                Ok(())
            } else {
                Err(StealthError::DecryptionFailed(
                    "Invalid byte length for number".to_string(),
                ))
            }
        }
        ResultType::String => {
            let string = String::from_utf8(decrypted_data).map_err(|e| {
                StealthError::DecryptionFailed(format!("Failed to decode to string: {e}"))
            })?;
            println!("Result (String): {}", string);
            Ok(())
        }
        ResultType::Binary => {
            println!("Result (Binary, Hex): {}", hex::encode(&decrypted_data));
            Ok(())
        }
    }
}

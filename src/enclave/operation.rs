use hpke::Serializable;
use sha2::{Digest, Sha256};

use crate::{
    encryption::{
        hpke::{hpke_decrypt_msg, hpke_encrypt_msg},
        symmetric::sym_decrypt_data,
    },
    stealth_error::StealthError,
    types::types::{OperationRequest, ResultType},
    utils::utils::server_init_from_env,
};

impl OperationRequest {
    fn decrypt_data(&self) -> Result<Vec<u8>, StealthError> {
        if let Some(encrypted_sym_key) = &self.encrypted_sym_key {
            let nonce = self.nonce.as_ref().ok_or(StealthError::DecryptionFailed(
                "Nonce is missing for decryption".to_string(),
            ))?;
            let (server_priv, _) = server_init_from_env()?;
            let decrypted_sym_key =
                hpke_decrypt_msg(&server_priv.to_bytes(), encrypted_sym_key, nonce)?;
            if let Some(encrypted_data) = &self.encrypted_data {
                let decrypted_data = sym_decrypt_data(encrypted_data, &decrypted_sym_key)?;
                Ok(decrypted_data)
            } else {
                Err(StealthError::InvalidData(
                    "No encrypted data provided".to_string(),
                ))
            }
        } else {
            Err(StealthError::DecryptionFailed(
                "No encrypted data to decrypt".to_string(),
            ))
        }
    }

    pub fn process_encrypted_data(&mut self) -> Result<(Vec<u8>, ResultType), StealthError> {
        let decrypted_data = self.decrypt_data()?;
        let decrypted_string = String::from_utf8(decrypted_data)
            .map_err(|e| StealthError::DecryptionFailed(format!("Failed to decode: {e}")))?;

        let res = self.execute_operation(decrypted_string)?;
        Ok(res)
    }

    fn execute_operation(
        &self,
        decrypted_string: String,
    ) -> Result<(Vec<u8>, ResultType), StealthError> {
        let params: Vec<String> = decrypted_string
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();

        println!("Operation type: {:?}", self.operation_type);

        match self.operation_type.as_str() {
            "add" => {
                let result = self.add(&params)?;
                println!("Addition Result: {:?}", result);
                return Ok((result, ResultType::Number));
            }
            "average" => {
                let result = self.average(&params)?;
                println!("Average Result: {:?}", result);
                return Ok((result, ResultType::Number));
            }
            "hash_sha256" => {
                let result = self.hash_sha256(&params)?;
                println!("SHA256 Hash: {:?}", result);
                return Ok((result, ResultType::Binary));
            }
            "reverse_string" => {
                let result = self.reverse_string(&params)?;
                println!("Reversed String: {:?}", result);
                return Ok((result, ResultType::String));
            }
            "concat_strings" => {
                let result = self.concat_strings(&params)?;
                println!("Concatenated String: {:?}", result);
                return Ok((result, ResultType::String));
            }
            _ => {
                return Err(StealthError::DecryptionFailed(
                    "Unsupported operation type".to_string(),
                ));
            }
        }
    }

    fn add(&self, params: &[String]) -> Result<Vec<u8>, StealthError> {
        let numbers: Result<Vec<f64>, _> = params.iter().map(|s| s.parse()).collect();
        let numbers = numbers.map_err(|_| {
            StealthError::DecryptionFailed("Invalid numbers in add operation".to_string())
        })?;

        let res = numbers.iter().sum::<f64>();
        let nonce = self.nonce.as_ref().ok_or(StealthError::DecryptionFailed(
            "Nonce is missing for encryption".to_string(),
        ))?;
        let encrypted_res =
            hpke_encrypt_msg(&res.to_be_bytes(), nonce, self.user_pubkey.as_slice()).map_err(
                |e| StealthError::EncryptionFailed(format!("Failed to encrypt result: {e}")),
            )?;
        Ok(encrypted_res)
    }

    fn average(&self, params: &[String]) -> Result<Vec<u8>, StealthError> {
        let numbers: Result<Vec<f64>, _> = params.iter().map(|s| s.parse()).collect();
        let numbers = numbers.map_err(|_| {
            StealthError::DecryptionFailed("Invalid numbers in average operation".to_string())
        })?;

        if numbers.is_empty() {
            return Err(StealthError::DecryptionFailed(
                "Cannot calculate average of empty list".to_string(),
            ));
        }

        let sum: f64 = numbers.iter().sum();
        let count = numbers.len() as f64;
        let res = sum / count;
        let nonce = self.nonce.as_ref().ok_or(StealthError::DecryptionFailed(
            "Nonce is missing for encryption".to_string(),
        ))?;
        let encrypted_res =
            hpke_encrypt_msg(&res.to_be_bytes(), nonce, self.user_pubkey.as_slice()).map_err(
                |e| StealthError::EncryptionFailed(format!("Failed to encrypt result: {e}")),
            )?;
        Ok(encrypted_res)
    }

    fn hash_sha256(&self, input: &Vec<String>) -> Result<Vec<u8>, StealthError> {
        let input_concat = input.concat();
        let mut hasher = Sha256::new();
        hasher.update(input_concat.as_bytes());
        let result = hasher.finalize();

        let nonce = self.nonce.as_ref().ok_or(StealthError::DecryptionFailed(
            "Nonce is missing for encryption".to_string(),
        ))?;
        let encrypted_res =
            hpke_encrypt_msg(&result, nonce, self.user_pubkey.as_slice()).map_err(|e| {
                StealthError::EncryptionFailed(format!("Failed to encrypt result: {e}"))
            })?;

        Ok(encrypted_res)
    }

    fn reverse_string(&self, input: &Vec<String>) -> Result<Vec<u8>, StealthError> {
        let input_concat = input.concat();
        let reversed = input_concat.chars().rev().collect::<String>();

        let nonce = self.nonce.as_ref().ok_or(StealthError::DecryptionFailed(
            "Nonce is missing for encryption".to_string(),
        ))?;
        let encrypted_res =
            hpke_encrypt_msg(reversed.as_bytes(), nonce, self.user_pubkey.as_slice()).map_err(
                |e| StealthError::EncryptionFailed(format!("Failed to encrypt result: {e}")),
            )?;

        Ok(encrypted_res)
    }

    fn concat_strings(&self, strings: &[String]) -> Result<Vec<u8>, StealthError> {
        let res = strings.concat();

        let nonce = self.nonce.as_ref().ok_or(StealthError::DecryptionFailed(
            "Nonce is missing for encryption".to_string(),
        ))?;
        let encrypted_res = hpke_encrypt_msg(res.as_bytes(), nonce, self.user_pubkey.as_slice())
            .map_err(|e| {
                StealthError::EncryptionFailed(format!("Failed to encrypt result: {e}"))
            })?;

        Ok(encrypted_res)
    }
}

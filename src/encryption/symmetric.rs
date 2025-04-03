use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, OsRng, rand_core::RngCore},
};

use crate::{stealth_error::StealthError, utils::constants::NONCE_SIZE};

pub fn sym_encrypt_data(data: &[u8], symmetric_key: &[u8]) -> Result<Vec<u8>, StealthError> {
    let cipher = Aes256Gcm::new_from_slice(symmetric_key).map_err(|e| {
        StealthError::InvalidKeyFormat(format!("Failed to create AES GCM instance, {e}"))
    })?;

    let mut nonce = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);
    let encrypted_data = cipher
        .encrypt(&nonce.into(), data)
        .map_err(|e| StealthError::EncryptionFailed(format!("{e}")))?;

    let mut result = Vec::with_capacity(NONCE_SIZE + encrypted_data.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&encrypted_data);

    Ok(result)
}

pub fn sym_decrypt_data(
    encrypted_data: &[u8],
    symmetric_key: &[u8],
) -> Result<Vec<u8>, StealthError> {
    if encrypted_data.len() < NONCE_SIZE {
        return Err(StealthError::InvalidData(
            "Encrypted data is too short to contain a nonce".to_string(),
        ));
    }

    let cipher = Aes256Gcm::new_from_slice(symmetric_key).map_err(|e| {
        StealthError::InvalidKeyFormat(format!("Failed to create AES GCM instance: {}", e))
    })?;

    let (nonce, ciphertext) = encrypted_data.split_at(NONCE_SIZE);

    let decrypted_data = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|e| StealthError::DecryptionFailed(format!("{e}")))?;

    Ok(decrypted_data)
}

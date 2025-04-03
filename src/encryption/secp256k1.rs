use ecies::{decrypt, encrypt};
use k256::{PublicKey as Secp256k1PublicKey, SecretKey as Secp256k1SecretKey};

use crate::stealth_error::StealthError;

pub fn parse_secp256k1_public_key(key_bytes: &[u8]) -> Result<Secp256k1PublicKey, StealthError> {
    Secp256k1PublicKey::from_sec1_bytes(key_bytes)
        .map_err(|e| StealthError::InvalidKeyFormat(format!("Failed to parse public key: {e}")))
}

pub fn parse_secp256k1_private_key(key_bytes: &[u8]) -> Result<Secp256k1SecretKey, StealthError> {
    Secp256k1SecretKey::from_bytes(key_bytes.into())
        .map_err(|e| StealthError::InvalidKeyFormat(format!("Failed to parse private key: {e}")))
}

pub fn encrypt_with_secp256k1(
    data: &[u8],
    public_key_bytes: &[u8],
) -> Result<Vec<u8>, StealthError> {
    let public_key = parse_secp256k1_public_key(public_key_bytes)?;
    let pub_key_bytes = public_key.to_sec1_bytes();
    encrypt(&pub_key_bytes, data).map_err(|e| StealthError::EncryptionFailed(e.to_string()))
}

pub fn decrypt_with_secp256k1(data: &[u8], private_key: &[u8]) -> Result<Vec<u8>, StealthError> {
    let private_key = parse_secp256k1_private_key(private_key)?;
    let priv_key_bytes = private_key.to_bytes();
    decrypt(&priv_key_bytes, data).map_err(|e| StealthError::DecryptionFailed(e.to_string()))
}

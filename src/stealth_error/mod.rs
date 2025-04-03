use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StealthError {
    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Unsupported key type: {0}")]
    UnsupportedKeyType(String),

    #[error("Symmetric encryption error: {0}")]
    SymmetricError(String),

    #[error("Invalid Data: {0}")]
    InvalidData(String),

    #[error("Key deserialization error: {0}")]
    KeyDeserializationError(String),

    #[error("Context initialization failed: {0}")]
    ContextInitializationFailed(String),

    #[error("Invalid ciphertext: {0}")]
    InvalidCiphertext(String),

    #[error("Invalid AEAD tag format: {0}")]
    InvalidTagFormat(String),

    #[error("Encapsulated key deserialization error: {0}")]
    EncapsulatedKeyDeserializationError(String),
}

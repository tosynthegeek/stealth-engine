use crate::types::keytypes::KeyType;

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

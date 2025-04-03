use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable,
    aead::{AeadTag, ChaCha20Poly1305},
    kdf::HkdfSha384,
    kem::X25519HkdfSha256,
};

use rand::{SeedableRng, rngs::StdRng};

use crate::{stealth_error::StealthError, utils::constants::INFO_STR};

type Kem = X25519HkdfSha256;
type Aead = ChaCha20Poly1305;
type Kdf = HkdfSha384;

pub fn hpke_encrypt_msg(msg: &[u8], nonce: &[u8], pk: &[u8]) -> Result<Vec<u8>, StealthError> {
    if pk.len() != <Kem as KemTrait>::PublicKey::size() {
        return Err(StealthError::InvalidKeyFormat(format!(
            "Public key must be {} bytes",
            <Kem as KemTrait>::PublicKey::size()
        )));
    }

    if nonce.is_empty() {
        return Err(StealthError::EncryptionFailed(
            "Nonce cannot be empty".to_string(),
        ));
    }

    let mut csprng = StdRng::from_os_rng();

    let server_pk = match <Kem as KemTrait>::PublicKey::from_bytes(pk) {
        Ok(pk) => pk,
        Err(e) => {
            return Err(StealthError::KeyDeserializationError(format!(
                "Could not deserialize server public key: {e}"
            )));
        }
    };

    let (encapped_key, mut sender_ctx) = match hpke::setup_sender::<Aead, Kdf, Kem, _>(
        &OpModeS::Base,
        &server_pk,
        INFO_STR,
        &mut csprng,
    ) {
        Ok(result) => result,
        Err(e) => {
            return Err(StealthError::ContextInitializationFailed(format!(
                "Failed to set up sender: {e}"
            )));
        }
    };

    let mut msg_copy = msg.to_vec();
    let tag = match sender_ctx.seal_in_place_detached(&mut msg_copy, nonce) {
        Ok(tag) => tag,
        Err(e) => {
            return Err(StealthError::EncryptionFailed(format!(
                "Encryption failed: {e}"
            )));
        }
    };

    let ciphertext = msg_copy;
    let result = combine_encrypted_data(encapped_key, ciphertext, &tag);

    Ok(result)
}

pub fn hpke_decrypt_msg(
    server_sk_bytes: &[u8],
    data: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, StealthError> {
    if server_sk_bytes.len() != <Kem as KemTrait>::PrivateKey::size() {
        return Err(StealthError::InvalidKeyFormat(format!(
            "Private key must be {} bytes",
            <Kem as KemTrait>::PrivateKey::size()
        )));
    }

    if nonce.is_empty() {
        return Err(StealthError::DecryptionFailed(
            "Nonce cannot be empty".to_string(),
        ));
    }

    let (encapped_key, ciphertext, tag) = match split_encrypted_data(data) {
        Ok(result) => result,
        Err(e) => return Err(e),
    };

    let server_sk = match <Kem as KemTrait>::PrivateKey::from_bytes(server_sk_bytes) {
        Ok(sk) => sk,
        Err(e) => {
            return Err(StealthError::KeyDeserializationError(format!(
                "Could not deserialize server private key: {e}"
            )));
        }
    };

    let mut receiver_ctx = match hpke::setup_receiver::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &server_sk,
        &encapped_key,
        INFO_STR,
    ) {
        Ok(ctx) => ctx,
        Err(e) => {
            return Err(StealthError::ContextInitializationFailed(format!(
                "Failed to set up receiver: {e}"
            )));
        }
    };

    let mut ciphertext_copy = ciphertext.to_vec();
    match receiver_ctx.open_in_place_detached(&mut ciphertext_copy, nonce, &tag) {
        Ok(_) => {}
        Err(e) => {
            return Err(StealthError::DecryptionFailed(format!(
                "Invalid ciphertext: {e}"
            )));
        }
    }

    Ok(ciphertext_copy)
}

pub fn combine_encrypted_data(
    encapped_key: <Kem as KemTrait>::EncappedKey,
    ciphertext: Vec<u8>,
    tag: &AeadTag<Aead>,
) -> Vec<u8> {
    let mut combined_data = Vec::new();

    combined_data.extend(encapped_key.to_bytes());
    combined_data.extend(ciphertext);
    combined_data.extend(tag.to_bytes());

    combined_data
}

pub fn split_encrypted_data(
    combined_data: &[u8],
) -> Result<(<Kem as KemTrait>::EncappedKey, Vec<u8>, AeadTag<Aead>), StealthError> {
    let encapped_key_len = <Kem as KemTrait>::EncappedKey::size();
    let tag_len = AeadTag::<Aead>::size();

    if combined_data.len() < encapped_key_len + tag_len {
        return Err(StealthError::InvalidData(format!(
            "Data too short: expected at least {} bytes, got {}",
            encapped_key_len + tag_len,
            combined_data.len()
        )));
    }

    let encapped_key_bytes = &combined_data[0..encapped_key_len];
    let ciphertext = &combined_data[encapped_key_len..combined_data.len() - tag_len];
    let tag_bytes = &combined_data[combined_data.len() - tag_len..];

    let encapped_key = match <Kem as KemTrait>::EncappedKey::from_bytes(encapped_key_bytes) {
        Ok(key) => key,
        Err(e) => {
            return Err(StealthError::EncapsulatedKeyDeserializationError(format!(
                "Could not deserialize encapsulated key: {e}"
            )));
        }
    };

    let tag = match AeadTag::<Aead>::from_bytes(tag_bytes) {
        Ok(tag) => tag,
        Err(e) => {
            return Err(StealthError::InvalidTagFormat(format!(
                "Could not deserialize AEAD tag: {e}"
            )));
        }
    };

    Ok((encapped_key, ciphertext.to_vec(), tag))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stealth_error::StealthError;

    #[test]
    fn test_invalid_key_format_error() {
        let invalid_key = vec![0u8; 16];

        let result = hpke_encrypt_msg(b"Hello", b"random_nonce", &invalid_key);

        assert!(matches!(result, Err(StealthError::InvalidKeyFormat(_))));
    }

    #[test]
    fn test_encryption_failed_error() {
        let valid_key = vec![0u8; 32];

        let result = hpke_encrypt_msg(b"Hello", b"", &valid_key);

        assert!(matches!(result, Err(StealthError::EncryptionFailed(_))));
    }

    #[test]
    fn test_decryption_failed_error() {
        let mut csprng = StdRng::from_os_rng();
        let (sk, pk) = Kem::gen_keypair(&mut csprng);

        let encrypted = hpke_encrypt_msg(b"Hello", b"random_nonce", &pk.to_bytes()).unwrap();

        let result = hpke_decrypt_msg(&sk.to_bytes(), &encrypted, b"wrong_nonce");

        assert!(matches!(result, Err(StealthError::DecryptionFailed(_))));
    }

    #[test]
    fn test_key_deserialization_error() {
        let malformed_key = vec![0xFFu8; 32];

        let fake_data = vec![0u8; 80];

        let result = hpke_decrypt_msg(&malformed_key, &fake_data, b"nonce");

        assert!(matches!(
            result,
            Err(StealthError::ContextInitializationFailed(_))
        ));
    }

    #[test]
    fn test_context_initialization_failed_error() {
        let zeros_key = vec![0u8; 32];

        let result = hpke_encrypt_msg(b"Hello", b"random_nonce", &zeros_key);

        assert!(matches!(
            result,
            Err(StealthError::ContextInitializationFailed(_))
        ));
    }

    #[test]
    fn test_invalid_data_format() {
        let too_short = vec![0u8; 10];

        let result = split_encrypted_data(&too_short);

        assert!(matches!(result, Err(StealthError::InvalidData(_))));
    }

    #[test]
    fn test_full_encryption_decryption_cycle() {
        let mut rng = StdRng::from_os_rng();
        let (sk, pk) = Kem::gen_keypair(&mut rng);

        let message = b"This is a test message for HPKE encryption";
        let nonce = b"unique_nonce_123";

        let encrypted = hpke_encrypt_msg(message, nonce, &pk.to_bytes()).unwrap();

        let decrypted = hpke_decrypt_msg(&sk.to_bytes(), &encrypted, nonce).unwrap();

        assert_eq!(message, decrypted.as_slice());
    }
}

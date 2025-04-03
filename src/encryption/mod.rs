pub mod hpke;
pub mod secp256k1;
pub mod symmetric;

pub mod encryption {

    use crate::{stealth_error::StealthError, utils::constants::NONCE_SIZE};

    use super::{
        hpke::{hpke_decrypt_msg, hpke_encrypt_msg},
        symmetric::sym_decrypt_data,
    };

    /*
        A randomly generated symmetric key is used to encrypt the main secret from the client and the encrypted data is stored.
        The sym key is encrypted with the server public key using hpke from the client side. The nonce used is added to the encyted sym key before passed to the server.
        The sym key is decrypted within the engine using the server sk and then encrypted then the result is stored.
    */
    pub fn encrypt_server_data(sk: &[u8], data: &[u8], pk: &[u8]) -> Result<Vec<u8>, StealthError> {
        if data.len() < NONCE_SIZE {
            return Err(StealthError::InvalidData(
                "Encrypted data is too short to contain a nonce".to_string(),
            ));
        }

        let (nonce, ciphertext) = data.split_at(NONCE_SIZE);

        let sym_key = hpke_decrypt_msg(sk, ciphertext, nonce)?;

        let result = hpke_encrypt_msg(&sym_key, nonce, pk)?;

        Ok(result)
    }

    pub fn decrypt_server_data(
        sk: &[u8],
        data: &[u8],
        secret: &[u8],
    ) -> Result<Vec<u8>, StealthError> {
        if secret.len() < NONCE_SIZE {
            return Err(StealthError::InvalidData(
                "Encrypted secret is too short to contain a nonce".to_string(),
            ));
        }

        let (nonce, ciphertext) = secret.split_at(NONCE_SIZE);

        let sym_key = hpke_decrypt_msg(sk, data, nonce)?;

        let dec_sec = sym_decrypt_data(ciphertext, &sym_key)?;

        Ok(dec_sec)
    }
}

#[cfg(test)]
mod integration_tests {
    use crate::{
        encryption::{
            hpke::{
                combine_encrypted_data, hpke_decrypt_msg, hpke_encrypt_msg, split_encrypted_data,
            },
            symmetric::{sym_decrypt_data, sym_encrypt_data},
        },
        stealth_error::StealthError,
        utils::constants::NONCE_SIZE,
    };

    use ::hpke::{
        Deserializable, Kem as KemTrait, Serializable,
        aead::{AeadTag, ChaCha20Poly1305},
        kem::X25519HkdfSha256,
    };
    use rand::{SeedableRng, rngs::StdRng};
    use std::vec;

    type Kem = X25519HkdfSha256;
    type Aead = ChaCha20Poly1305;

    #[test]
    fn test_hpke_encrypt_decrypt_roundtrip() {
        let mut csprng = StdRng::from_os_rng();
        let (server_sk, server_pk) = Kem::gen_keypair(&mut csprng);

        let message = b"This is a secret message for testing";
        let nonce = b"unique-nonce-123";

        let encrypted_data = hpke_encrypt_msg(message, nonce, &server_pk.to_bytes())
            .expect("Encryption should succeed");

        let decrypted_data = hpke_decrypt_msg(&server_sk.to_bytes(), &encrypted_data, nonce)
            .expect("Decryption should succeed");

        assert_eq!(decrypted_data, message);
    }

    #[test]
    fn test_hpke_encrypt_invalid_public_key() {
        let message = b"Test message";
        let nonce = b"test-nonce";
        let invalid_pk = vec![0u8; 10]; // Incorrect size for public key

        let result = hpke_encrypt_msg(message, nonce, &invalid_pk);
        assert!(matches!(result, Err(StealthError::InvalidKeyFormat(_))));
    }

    #[test]
    fn test_hpke_encrypt_empty_nonce() {
        let mut csprng = StdRng::from_os_rng();
        let (_, server_pk) = Kem::gen_keypair(&mut csprng);

        let message = b"Test message";
        let empty_nonce = b"";

        let result = hpke_encrypt_msg(message, empty_nonce, &server_pk.to_bytes());
        assert!(matches!(result, Err(StealthError::EncryptionFailed(_))));
    }

    #[test]
    fn test_hpke_decrypt_invalid_private_key() {
        let message = b"Test message";
        let nonce = b"test-nonce";

        let mut csprng = StdRng::from_os_rng();
        let (_, server_pk) = Kem::gen_keypair(&mut csprng);

        let encrypted_data = hpke_encrypt_msg(message, nonce, &server_pk.to_bytes())
            .expect("Encryption should succeed");

        let invalid_sk = vec![0u8; <Kem as KemTrait>::PrivateKey::size() - 1];
        let result = hpke_decrypt_msg(&invalid_sk, &encrypted_data, nonce);
        assert!(matches!(result, Err(StealthError::InvalidKeyFormat(_))));
    }

    #[test]
    fn test_hpke_decrypt_tampered_data() {
        let mut csprng = StdRng::from_os_rng();
        let (server_sk, server_pk) = Kem::gen_keypair(&mut csprng);

        let message = b"Test message";
        let nonce = b"test-nonce";

        let mut encrypted_data = hpke_encrypt_msg(message, nonce, &server_pk.to_bytes())
            .expect("Encryption should succeed");

        if !encrypted_data.is_empty() {
            let len = encrypted_data.len();
            encrypted_data[len / 2] ^= 0xFF;
        }

        let result = hpke_decrypt_msg(&server_sk.to_bytes(), &encrypted_data, nonce);
        assert!(matches!(result, Err(StealthError::DecryptionFailed(_))));
    }

    #[test]
    fn test_hpke_decrypt_wrong_nonce() {
        let mut csprng = StdRng::from_os_rng();
        let (server_sk, server_pk) = Kem::gen_keypair(&mut csprng);

        let message = b"Test message";
        let nonce = b"original-nonce";
        let wrong_nonce = b"different-nonce";

        let encrypted_data = hpke_encrypt_msg(message, nonce, &server_pk.to_bytes())
            .expect("Encryption should succeed");

        let result = hpke_decrypt_msg(&server_sk.to_bytes(), &encrypted_data, wrong_nonce);
        assert!(matches!(result, Err(StealthError::DecryptionFailed(_))));
    }

    #[test]
    fn test_sym_encrypt_decrypt_roundtrip() {
        let data = b"This is sensitive data for symmetric encryption test";
        let symmetric_key = [0x42; 32];

        let encrypted_data =
            sym_encrypt_data(data, &symmetric_key).expect("Symmetric encryption should succeed");

        let decrypted_data = sym_decrypt_data(&encrypted_data, &symmetric_key)
            .expect("Symmetric decryption should succeed");

        assert_eq!(decrypted_data, data);
    }

    #[test]
    fn test_sym_encrypt_invalid_key() {
        let data = b"Test data";
        let invalid_key = [0x42; 16];

        let result = sym_encrypt_data(data, &invalid_key);
        assert!(matches!(result, Err(StealthError::InvalidKeyFormat(_))));
    }

    #[test]
    fn test_sym_decrypt_tampered_data() {
        let data = b"Test data";
        let symmetric_key = [0x42; 32];

        let mut encrypted_data =
            sym_encrypt_data(data, &symmetric_key).expect("Encryption should succeed");

        if encrypted_data.len() > NONCE_SIZE + 1 {
            encrypted_data[NONCE_SIZE + 1] ^= 0xFF;
        }

        let result = sym_decrypt_data(&encrypted_data, &symmetric_key);
        assert!(matches!(result, Err(StealthError::DecryptionFailed(_))));
    }

    #[test]
    fn test_sym_decrypt_wrong_key() {
        let data = b"Test data";
        let encryption_key = [0x42; 32];
        let wrong_key = [0x43; 32];

        let encrypted_data =
            sym_encrypt_data(data, &encryption_key).expect("Encryption should succeed");

        let result = sym_decrypt_data(&encrypted_data, &wrong_key);
        assert!(matches!(result, Err(StealthError::DecryptionFailed(_))));
    }

    #[test]
    fn test_sym_decrypt_truncated_data() {
        let data = b"Test data";
        let symmetric_key = [0x42; 32];

        let encrypted_data =
            sym_encrypt_data(data, &symmetric_key).expect("Encryption should succeed");

        let truncated_data = &encrypted_data[0..NONCE_SIZE - 1];

        let result = sym_decrypt_data(truncated_data, &symmetric_key);
        assert!(matches!(result, Err(StealthError::InvalidData(_))));
    }

    #[test]
    fn test_combined_hpke_and_sym_encryption() {
        let mut csprng = StdRng::from_os_rng();
        let (server_sk, server_pk) = Kem::gen_keypair(&mut csprng);

        let symmetric_key = [0x42; 32];

        let original_data = b"This is sensitive data that will be double-encrypted";
        let hpke_nonce = b"hpke-nonce-123";

        let sym_encrypted = sym_encrypt_data(original_data, &symmetric_key)
            .expect("Symmetric encryption should succeed");

        let hpke_encrypted = hpke_encrypt_msg(&sym_encrypted, hpke_nonce, &server_pk.to_bytes())
            .expect("HPKE encryption should succeed");

        let hpke_decrypted = hpke_decrypt_msg(&server_sk.to_bytes(), &hpke_encrypted, hpke_nonce)
            .expect("HPKE decryption should succeed");

        let final_decrypted = sym_decrypt_data(&hpke_decrypted, &symmetric_key)
            .expect("Symmetric decryption should succeed");

        assert_eq!(final_decrypted, original_data);
    }

    #[test]
    fn test_combine_split_encrypted_data() {
        let mut csprng = StdRng::from_os_rng();

        let (_, server_pk) = Kem::gen_keypair(&mut csprng);

        let (_, encapped_key) =
            Kem::encap(&server_pk, None, &mut csprng).expect("Encap should succeed");

        let ciphertext = b"dummy ciphertext".to_vec();
        let tag_bytes = vec![0xAA; AeadTag::<Aead>::size()];
        let tag = AeadTag::<Aead>::from_bytes(&tag_bytes).expect("Tag creation should succeed");

        // Combine the data
        let combined = combine_encrypted_data(encapped_key.clone(), ciphertext.clone(), &tag);

        // Split the data
        let (recovered_key, recovered_ciphertext, recovered_tag) =
            split_encrypted_data(&combined).expect("Splitting should succeed");

        // Verify all parts match
        assert_eq!(recovered_key.to_bytes(), encapped_key.to_bytes());
        assert_eq!(recovered_ciphertext, ciphertext);
        assert_eq!(recovered_tag.to_bytes(), tag.to_bytes());
    }

    #[test]
    fn test_split_encrypted_data_too_short() {
        let too_short_data = vec![0; 10]; // Definitely too short

        let result = split_encrypted_data(&too_short_data);
        assert!(matches!(result, Err(StealthError::InvalidData(_))));
    }
}

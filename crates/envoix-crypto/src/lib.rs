//! Cryptographic interfaces and implementations.

use envoix_error::CoreError;
use envoix_types::TransferId;

pub type CryptoError = CoreError;

pub trait CryptoProvider: Send + Sync {
    fn encrypt_chunk(
        &self,
        transfer_id: &TransferId,
        chunk_index: u64,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;

    fn decrypt_chunk(
        &self,
        transfer_id: &TransferId,
        chunk_index: u64,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct InsecureNoopCryptoProvider;

impl CryptoProvider for InsecureNoopCryptoProvider {
    fn encrypt_chunk(
        &self,
        _transfer_id: &TransferId,
        _chunk_index: u64,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        Ok(plaintext.to_vec())
    }

    fn decrypt_chunk(
        &self,
        _transfer_id: &TransferId,
        _chunk_index: u64,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        Ok(ciphertext.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insecure_noop_crypto_returns_input_bytes() {
        let provider = InsecureNoopCryptoProvider;
        let transfer_id = TransferId::new("transfer-1");
        let bytes = b"plaintext";

        let encrypted = provider.encrypt_chunk(&transfer_id, 0, bytes).unwrap();
        let decrypted = provider.decrypt_chunk(&transfer_id, 0, &encrypted).unwrap();

        assert_eq!(encrypted, bytes);
        assert_eq!(decrypted, bytes);
    }
}

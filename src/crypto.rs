//! WeChat cryptographic utilities
//!
//! Handles SHA1 signature verification and AES-256-CBC encryption/decryption
//! for WeChat Official Account messages.

use aes::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use anyhow::{Context, Result, anyhow};
use sha1::{Digest, Sha1};

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
#[cfg(test)]
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

/// WeChat cryptographic handler
#[derive(Clone)]
pub struct WechatCrypto {
    encoding_aes_key: [u8; 32], // Decoded 43-char base64 key = 32 bytes
    app_id: String,
}

impl WechatCrypto {
    /// Create from 43-character EncodingAESKey and AppID
    pub fn new(encoding_aes_key: &str, app_id: &str) -> Result<Self> {
        if encoding_aes_key.len() != 43 {
            return Err(anyhow!(
                "EncodingAESKey must be 43 characters, got {}",
                encoding_aes_key.len()
            ));
        }

        // Base64 decode (key has '=' appended for proper padding)
        let key_with_padding = format!("{}=", encoding_aes_key);
        
        // Try standard base64 first, then URL-safe
        let decoded = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &key_with_padding,
        )
        .or_else(|_| {
            base64::Engine::decode(
                &base64::engine::general_purpose::URL_SAFE,
                &key_with_padding,
            )
        })
        .context("Failed to decode EncodingAESKey - invalid base64 characters")?;

        if decoded.len() != 32 {
            return Err(anyhow!(
                "Decoded key must be 32 bytes, got {}",
                decoded.len()
            ));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&decoded);

        Ok(Self {
            encoding_aes_key: key,
            app_id: app_id.to_string(),
        })
    }

    /// Verify WeChat signature
    ///
    /// WeChat sends: signature = SHA1(sort(token, timestamp, nonce))
    pub fn verify(token: &str, timestamp: &str, nonce: &str, signature: &str) -> bool {
        let computed = Self::sign(token, timestamp, nonce);
        computed == signature
    }

    /// Generate signature
    pub fn sign(token: &str, timestamp: &str, nonce: &str) -> String {
        let mut parts = [token, timestamp, nonce];
        parts.sort();

        let combined = parts.join("");
        let hash = Sha1::digest(combined.as_bytes());
        hex::encode(hash)
    }

    /// Verify message signature (for encrypted messages)
    pub fn verify_message(
        token: &str,
        timestamp: &str,
        nonce: &str,
        encrypted_msg: &str,
        msg_signature: &str,
    ) -> bool {
        let mut parts = [token, timestamp, nonce, encrypted_msg];
        parts.sort();

        let combined = parts.join("");
        let hash = Sha1::digest(combined.as_bytes());
        hex::encode(hash) == msg_signature
    }

    /// Decrypt WeChat message
    ///
    /// Format: random(16) + msg_len(4) + msg + app_id
    pub fn decrypt(&self, encrypted: &str) -> Result<String> {
        // Base64 decode
        let encrypted_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encrypted)
                .context("Failed to base64 decode encrypted message")?;

        if encrypted_bytes.len() < 32 {
            return Err(anyhow!("Encrypted message too short"));
        }

        // AES-256-CBC decrypt with key as IV (WeChat uses key as IV)
        // WeChat uses first 16 bytes of key as IV
        let iv = &self.encoding_aes_key[..16];
        let cipher = Aes256CbcDec::new_from_slices(&self.encoding_aes_key, iv)
            .context("Failed to create AES cipher")?;

        // Need to decrypt in place with buffer
        let mut buf = encrypted_bytes.clone();
        let decrypted = cipher
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .map_err(|_| anyhow!("Failed to decrypt message"))?;

        let decrypted = decrypted.to_vec();

        // Parse format: random(16) + msg_len(4) + msg + app_id
        if decrypted.len() < 20 {
            return Err(anyhow!("Decrypted message too short"));
        }

        // Skip 16 bytes random
        let msg_len_bytes = &decrypted[16..20];
        let msg_len = u32::from_be_bytes([
            msg_len_bytes[0],
            msg_len_bytes[1],
            msg_len_bytes[2],
            msg_len_bytes[3],
        ]) as usize;

        if decrypted.len() < 20 + msg_len {
            return Err(anyhow!("Invalid message length"));
        }

        let msg = &decrypted[20..20 + msg_len];
        let app_id_in_msg = &decrypted[20 + msg_len..];

        // Verify app_id
        if app_id_in_msg != self.app_id.as_bytes() {
            return Err(anyhow!("AppID mismatch in decrypted message"));
        }

        String::from_utf8(msg.to_vec()).context("Failed to convert message to UTF-8")
    }

    /// Encrypt message for WeChat
    ///
    /// Format: random(16) + msg_len(4) + msg + app_id
    #[cfg(test)]
    pub fn encrypt(&self, plaintext: &str) -> Result<String> {
        use aes::cipher::BlockEncryptMut;
        use rand::RngCore;

        // Generate 16 random bytes
        let mut random_bytes = [0u8; 16];
        rand::rng().fill_bytes(&mut random_bytes);

        // Build plaintext: random + len + msg + app_id
        let msg_bytes = plaintext.as_bytes();
        let msg_len = msg_bytes.len() as u32;
        let app_id_bytes = self.app_id.as_bytes();

        let total_len = 16 + 4 + msg_bytes.len() + app_id_bytes.len();
        let block_size = 16usize;
        let padded_len = total_len.div_ceil(block_size) * block_size;

        let mut buf = vec![0u8; padded_len];
        buf[..16].copy_from_slice(&random_bytes);
        buf[16..20].copy_from_slice(&msg_len.to_be_bytes());
        buf[20..20 + msg_bytes.len()].copy_from_slice(msg_bytes);
        buf[20 + msg_bytes.len()..total_len].copy_from_slice(app_id_bytes);

        // AES-256-CBC encrypt
        // WeChat uses first 16 bytes of key as IV
        let iv = &self.encoding_aes_key[..16];
        let cipher = Aes256CbcEnc::new_from_slices(&self.encoding_aes_key, iv)
            .context("Failed to create AES cipher")?;

        cipher
            .encrypt_padded_mut::<Pkcs7>(&mut buf, total_len)
            .map_err(|_| anyhow!("Failed to encrypt message"))?;

        Ok(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &buf,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        let token = "ugent_token_2026";
        let timestamp = "1234567890";
        let nonce = "test_nonce";

        let signature = WechatCrypto::sign(token, timestamp, nonce);

        assert!(WechatCrypto::verify(token, timestamp, nonce, &signature));
        assert!(!WechatCrypto::verify(
            token,
            timestamp,
            nonce,
            "invalid_signature"
        ));
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        // WeChat EncodingAESKey is 43 base64 chars = 32 bytes decoded
        // Generate a valid 32-byte key and encode to base64 (43 chars without padding)
        let key_bytes: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let key_43 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD_NO_PAD,
            &key_bytes,
        );
        assert_eq!(key_43.len(), 43, "Key should be 43 chars");

        let app_id = "wx1234567890abcdef";

        let crypto = WechatCrypto::new(&key_43, app_id).unwrap();
        let plaintext = "<xml><Content>Hello</Content></xml>";

        let encrypted = crypto.encrypt(plaintext).unwrap();
        let decrypted = crypto.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext, decrypted);
    }
}

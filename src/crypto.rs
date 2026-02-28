//! WeChat cryptographic utilities
//!
//! Handles SHA1 signature verification and AES-256-CBC encryption/decryption
//! for WeChat Official Account and WeCom messages.

use aes::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use anyhow::{Context, Result, anyhow};
use base64::engine::general_purpose;
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
        // Trim whitespace and invisible characters
        let encoding_aes_key = encoding_aes_key.trim();

        if encoding_aes_key.len() != 43 {
            return Err(anyhow!(
                "EncodingAESKey must be 43 characters, got {} (value: '{}')",
                encoding_aes_key.len(),
                encoding_aes_key
            ));
        }

        // WeChat/WeCom uses a custom base64: 43 chars without standard padding
        // The 43rd character encodes only 2 bits (not a full 6-bit group)
        // Standard base64 decoders fail because they expect trailing bits to be zero
        //
        // Solution: Decode the key manually with lenient handling
        let decoded = Self::decode_wecom_key(encoding_aes_key)?;

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

        /// Decode WeCom's non-standard base64 key
    ///
    /// WeCom uses 43 base64 characters which is non-standard.
    /// Standard base64 encodes 32 bytes as 44 chars (with padding).
    /// WeCom removes the trailing '=' padding, leaving 43 chars.
    ///
    /// Solution: Add back the '=' padding and decode normally.
    fn decode_wecom_key(key: &str) -> Result<Vec<u8>> {
        // Pad with '=' to make valid base64
        let padded = format!("{}=", key);
        
        let decoded = base64::Engine::decode(&general_purpose::STANDARD, &padded)
            .context("Failed to decode EncodingAESKey")?;
        
        if decoded.len() != 32 {
            return Err(anyhow!("Decoded key to {} bytes, expected 32", decoded.len()));
        }

        Ok(decoded)
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
        let encrypted_bytes = base64::Engine::decode(&general_purpose::STANDARD, encrypted)
            .context("Failed to base64 decode encrypted message")?;

        if encrypted_bytes.len() < 32 {
            return Err(anyhow!(
                "Encrypted message too short: {} bytes",
                encrypted_bytes.len()
            ));
        }

        // Check if encrypted length is multiple of 16 (AES block size)
        if encrypted_bytes.len() % 16 != 0 {
            return Err(anyhow!(
                "Encrypted message length not multiple of 16: {} bytes",
                encrypted_bytes.len()
            ));
        }

        // AES-256-CBC decrypt
        // WeChat/WeCom uses IV = first 16 bytes of the key (NOT zeros!)
        // See: https://developer.work.weixin.qq.com/document/path/90968
        let iv = &self.encoding_aes_key[..16];
        let cipher = Aes256CbcDec::new_from_slices(&self.encoding_aes_key, iv)
            .context("Failed to create AES cipher")?;

        // Need to decrypt in place with buffer
        let mut buf = encrypted_bytes.clone();
        let decrypted = cipher
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .map_err(|e| anyhow!("Failed to decrypt message (PKCS7 padding error): {:?}", e))?;

        let decrypted = decrypted.to_vec();

        // Parse format: random(16) + msg_len(4) + msg + app_id
        if decrypted.len() < 20 {
            return Err(anyhow!(
                "Decrypted message too short: {} bytes",
                decrypted.len()
            ));
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
            return Err(anyhow!(
                "Invalid message length: declared {} bytes but only have {} bytes",
                msg_len,
                decrypted.len() - 20
            ));
        }

        let msg = &decrypted[20..20 + msg_len];
        let app_id_in_msg = &decrypted[20 + msg_len..];

        // Verify app_id
        if app_id_in_msg != self.app_id.as_bytes() {
            return Err(anyhow!(
                "AppID mismatch in decrypted message: expected '{}', got '{}'",
                self.app_id,
                String::from_utf8_lossy(app_id_in_msg)
            ));
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

        // AES encrypt
        let iv = &self.encoding_aes_key[..16];
        let cipher = Aes256CbcEnc::new_from_slices(&self.encoding_aes_key, iv)
            .context("Failed to create AES cipher")?;

        let encrypted = cipher
            .encrypt_padded_mut::<Pkcs7>(&mut buf, total_len)
            .map_err(|_| anyhow!("Failed to encrypt message"))?;

        Ok(base64::Engine::encode(
            &general_purpose::STANDARD,
            encrypted,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        let token = "test_token";
        let timestamp = "1234567890";
        let nonce = "abc123";

        let signature = WechatCrypto::sign(token, timestamp, nonce);
        assert!(WechatCrypto::verify(token, timestamp, nonce, &signature));
        assert!(!WechatCrypto::verify(token, timestamp, "wrong", &signature));
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        // Generate a valid 43-char base64 key (like WeCom does)
        // 32 bytes -> base64 no padding = 43 chars (ceil(32*8/6) = 43)
        let real_key: [u8; 32] = [0x11; 32];
        let key_43 = base64::Engine::encode(&general_purpose::STANDARD_NO_PAD, real_key);
        assert_eq!(key_43.len(), 43, "Key should be 43 chars");

        let app_id = "test_app_id";
        let crypto = WechatCrypto::new(&key_43, app_id).expect("Failed to create crypto");

        let plaintext = "Hello, WeChat!";
        let encrypted = crypto.encrypt(plaintext).expect("Failed to encrypt");
        let decrypted = crypto.decrypt(&encrypted).expect("Failed to decrypt");

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_decode_wecom_key() {
        // Generate a valid 43-char base64 key (like WeCom does)
        let real_key: [u8; 32] = [0x11; 32];
        let key_43 = base64::Engine::encode(&general_purpose::STANDARD_NO_PAD, real_key);
        assert_eq!(key_43.len(), 43, "Key should be 43 chars");

        let decoded = WechatCrypto::decode_wecom_key(&key_43);
        assert!(decoded.is_ok());
        assert_eq!(decoded.unwrap().len(), 32);
    }
}

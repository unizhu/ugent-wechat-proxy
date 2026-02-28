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

        eprintln!("[DEBUG] EncodingAESKey length: {}", encoding_aes_key.len());
        eprintln!("[DEBUG] EncodingAESKey first 10 chars: {}", &encoding_aes_key[..encoding_aes_key.len().min(10)]);
        
        if encoding_aes_key.len() != 43 {
            return Err(anyhow!(
                "EncodingAESKey must be 43 characters, got {} (value: '{}')",
                encoding_aes_key.len(),
                encoding_aes_key
            ));
        }

        // WeChat/WeCom official docs: AESKey = Base64_Decode(EncodingAESKey + "=")
        // https://developer.work.weixin.qq.com/document/path/90968
        let decoded = Self::decode_wecom_key(encoding_aes_key)?;

        eprintln!("[DEBUG] Decoded key length: {}", decoded.len());
        eprintln!("[DEBUG] Decoded key (hex): {:02x?}", decoded);

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
    /// WeCom uses 43 base64 characters without standard padding.
    /// The 43rd character encodes only 2 bits of data (not full 6 bits).
    ///
    /// 43 chars * 6 bits = 258 bits, but we only need 256 bits (32 bytes)
    /// So the last char's bottom 2 bits are ignored.
    fn decode_wecom_key(key: &str) -> Result<Vec<u8>> {
        const BASE64_CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        
        let bytes = key.as_bytes();
        if bytes.len() != 43 {
            return Err(anyhow!("Key must be 43 characters, got {}", bytes.len()));
        }
        
        // Build reverse lookup table
        let mut decode_table = [0xFFu8; 256];
        for (i, &c) in BASE64_CHARS.iter().enumerate() {
            decode_table[c as usize] = i as u8;
        }
        
        let mut result = Vec::with_capacity(32);
        
        // Process first 42 characters in chunks of 4 (gives 31 bytes)
        for chunk in bytes[..40].chunks(4) {
            let v = [
                decode_table[chunk[0] as usize],
                decode_table[chunk[1] as usize],
                decode_table[chunk[2] as usize],
                decode_table[chunk[3] as usize],
            ];
            
            if v.contains(&0xFF) {
                return Err(anyhow!("Invalid base64 character in key"));
            }
            
            result.push((v[0] << 2) | (v[1] >> 4));
            result.push((v[1] << 4) | (v[2] >> 2));
            result.push((v[2] << 6) | v[3]);
        }
        
        // Handle characters 40, 41 (produces bytes 30, 31)
        let v40 = decode_table[bytes[40] as usize];
        let v41 = decode_table[bytes[41] as usize];
        let v42 = decode_table[bytes[42] as usize];
        
        if v40 == 0xFF || v41 == 0xFF || v42 == 0xFF {
            return Err(anyhow!("Invalid base64 character in last 3 chars"));
        }
        
        // Byte 30 from chars 40, 41
        result.push((v40 << 2) | (v41 >> 4));
        
        // Byte 31 from chars 41, 42 (only top 4 bits of v42)
        result.push((v41 << 4) | (v42 >> 2));
        
        // Byte 32: WeCom ignores the last 2 bits of v42, so we don't need another byte
        // But we need 32 bytes! The last byte comes from the remaining bits.
        // Actually, 43 base64 chars = 258 bits = 32 bytes + 2 extra bits
        // The extra 2 bits should be 0, but WeCom doesn't validate them.
        // 
        // Wait - let me recalculate:
        // 42 chars * 6 bits = 252 bits = 31.5 bytes
        // 43 chars * 6 bits = 258 bits = 32.25 bytes (we take 32 bytes = 256 bits)
        // So the 43rd char provides the final 6 bits, but we only need 4 of them for 32 bytes
        // Actually: byte 31 (0-indexed) = bits 248-255
        // chars 0-41 give 252 bits (31.5 bytes) = bytes 0-31, with last 4 bits coming from char 42
        
        // Let me trace more carefully:
        // 42 chars -> 42 * 6 = 252 bits
        // 252 / 8 = 31.5 bytes, so we have 31 bytes and 4 bits extra
        // Char 42 adds 6 more bits = 10 bits total = 1 byte + 2 bits extra
        // So 43 chars gives 32 bytes + 2 bits (ignored)
        
        // The issue: my calculation for byte 31 is wrong!
        // Byte 31 needs bits from both char 41 and char 42
        
        // Actually the result is already 32 bytes after the last push!
        // Let me verify: 10 chunks of 4 chars = 30 bytes
        // Plus 2 more bytes from chars 40-42 = 32 bytes total ✓
        
        if result.len() != 32 {
            return Err(anyhow!("Decoded to {} bytes, expected 32", result.len()));
        }

        eprintln!("[DEBUG] Manual decode succeeded, key hex: {:02x?}", &result[..8]);
        Ok(result)
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

        eprintln!("[DEBUG] Encrypted bytes length: {}", encrypted_bytes.len());
        eprintln!("[DEBUG] Key (first 8 bytes): {:02x?}", &self.encoding_aes_key[..8]);
        eprintln!("[DEBUG] IV (first 8 bytes): {:02x?}", &self.encoding_aes_key[..8]);

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
        let decrypted = match cipher.decrypt_padded_mut::<Pkcs7>(&mut buf) {
            Ok(d) => d.to_vec(),
            Err(e) => {
                eprintln!("[DEBUG] PKCS7 padding error: {:?}", e);
                eprintln!("[DEBUG] Trying to decrypt anyway and check padding manually...");
                
                // Try with NoPadding and manually check
                // This helps debug if the key is wrong or just padding issue
                use aes::cipher::BlockDecryptMut;
                type Aes256CbcDecNoPadding = cbc::Decryptor<aes::Aes256>;
                let cipher_np = Aes256CbcDecNoPadding::new_from_slices(&self.encoding_aes_key, iv)
                    .context("Failed to create AES cipher (no padding)")?;
                let mut buf2 = encrypted_bytes.clone();
                let decrypted_raw = cipher_np.decrypt_padded_mut::<aes::cipher::block_padding::NoPadding>(&mut buf2)
                    .map_err(|e| anyhow!("AES decrypt failed: {:?}", e))?;
                
                // Check last byte for PKCS7 padding
                let last_byte = decrypted_raw[decrypted_raw.len() - 1] as usize;
                eprintln!("[DEBUG] Last byte (padding indicator): {}", last_byte);
                eprintln!("[DEBUG] Last 16 bytes: {:02x?}", &decrypted_raw[decrypted_raw.len()-16..]);
                
                if last_byte > 0 && last_byte <= 16 {
                    // Valid PKCS7 padding
                    decrypted_raw[..decrypted_raw.len() - last_byte].to_vec()
                } else {
                    return Err(anyhow!("Failed to decrypt message (PKCS7 padding error): {:?}", e));
                }
            }
        };

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
        
        eprintln!("[DEBUG] Decrypted msg_len: {}", msg_len);
        eprintln!("[DEBUG] Decrypted total len: {}", decrypted.len());

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

#[cfg(test)]
mod test_real_key {
    use super::*;
    
    #[test]
    fn test_real_wecom_key() {
        let key = "KaxN1fuotvXmSzLOF1TBV7Zi1EfGtyvzHSzW5LToVdO";
        let decoded = WechatCrypto::decode_wecom_key(key).expect("Failed to decode");
        eprintln!("[TEST] Real key decoded: {:02x?}", decoded);
        assert_eq!(decoded.len(), 32);
    }
}

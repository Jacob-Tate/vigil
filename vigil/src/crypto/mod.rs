//! AES-256-GCM encryption for notification channel configs.
//!
//! Byte-compatible with server/src/lib/configCrypto.ts — uses the same
//! HKDF-SHA256 key derivation, the same IV/authTag/ciphertext format, and the
//! same "enc:" prefix so existing DB rows can be decrypted without migration.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;

/// Fixed HKDF parameters — must match configCrypto.ts exactly.
const HKDF_SALT: &[u8] = b"vigil-notifications-v1";
const HKDF_INFO: &[u8] = b"aes-256-gcm-key";

fn derive_key(raw_key: &str) -> anyhow::Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), raw_key.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(HKDF_INFO, &mut okm)
        .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;
    Ok(okm)
}

/// Encrypt `plaintext` using the NOTIFICATIONS_ENCRYPTION_KEY.
///
/// Returns a string in the format `enc:<iv_b64>:<tag_b64>:<ciphertext_b64>`.
pub fn encrypt_config(plaintext: &str, raw_key: &str) -> anyhow::Result<String> {
    let key_bytes = derive_key(raw_key)?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // aes-gcm appends the 16-byte auth tag to the ciphertext
    let mut ciphertext_with_tag = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| anyhow::anyhow!("AES-GCM encrypt error: {}", e))?;

    // Split off the trailing 16-byte auth tag
    let auth_tag = ciphertext_with_tag.split_off(ciphertext_with_tag.len() - 16);

    Ok(format!(
        "enc:{}:{}:{}",
        B64.encode(nonce_bytes),
        B64.encode(&auth_tag),
        B64.encode(&ciphertext_with_tag),
    ))
}

/// Decrypt a value produced by `encrypt_config` (or by configCrypto.ts).
///
/// Falls back to returning `ciphertext` as-is if it does not start with `enc:`
/// (backwards-compatible with plain-text rows written before encryption was added).
pub fn decrypt_config(stored: &str, raw_key: &str) -> anyhow::Result<String> {
    if !stored.starts_with("enc:") {
        // Plain-text fallback (legacy rows)
        return Ok(stored.to_string());
    }

    let rest = &stored["enc:".len()..];
    let parts: Vec<&str> = rest.splitn(3, ':').collect();
    if parts.len() != 3 {
        anyhow::bail!("Invalid encrypted config format");
    }

    let iv = B64.decode(parts[0])?;
    let auth_tag = B64.decode(parts[1])?;
    let ciphertext = B64.decode(parts[2])?;

    if iv.len() != 12 {
        anyhow::bail!("Invalid IV length");
    }

    // Re-assemble ciphertext + auth tag as aes-gcm expects
    let mut combined = ciphertext;
    combined.extend_from_slice(&auth_tag);

    let key_bytes = derive_key(raw_key)?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&iv);

    let plaintext = cipher
        .decrypt(nonce, combined.as_slice())
        .map_err(|e| anyhow::anyhow!("AES-GCM decrypt error: {}", e))?;

    Ok(String::from_utf8(plaintext)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = "test-encryption-key-for-unit-tests";
        let plaintext = r#"{"webhookUrl":"https://example.com/hook"}"#;
        let encrypted = encrypt_config(plaintext, key).unwrap();
        assert!(encrypted.starts_with("enc:"), "encrypted value should start with 'enc:'");
        let decrypted = decrypt_config(&encrypted, key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn produces_different_ciphertexts_for_same_plaintext() {
        // Random IV means two calls should never produce identical output
        let key = "test-key";
        let a = encrypt_config("same plaintext", key).unwrap();
        let b = encrypt_config("same plaintext", key).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn legacy_plaintext_passes_through() {
        // Rows written before encryption was added have no "enc:" prefix
        let legacy = r#"{"webhookUrl":"https://example.com"}"#;
        let result = decrypt_config(legacy, "any-key").unwrap();
        assert_eq!(result, legacy);
    }

    #[test]
    fn wrong_key_fails_decryption() {
        let ciphertext = encrypt_config("secret data", "key-a").unwrap();
        let result = decrypt_config(&ciphertext, "key-b");
        assert!(result.is_err(), "decryption with wrong key should fail");
    }

    #[test]
    fn invalid_format_fails() {
        // Three base64 parts required after "enc:", but the values are garbage
        let result = decrypt_config("enc:aaa:bbb", "key");
        assert!(result.is_err(), "only two parts should be an error");
    }

    #[test]
    fn truncated_iv_fails() {
        // A valid base64 IV that is only 6 bytes (not the required 12)
        use base64::{engine::general_purpose::STANDARD as B64, Engine};
        let short_iv = B64.encode([0u8; 6]);
        let fake_tag = B64.encode([0u8; 16]);
        let fake_ct = B64.encode([0u8; 8]);
        let stored = format!("enc:{}:{}:{}", short_iv, fake_tag, fake_ct);
        let result = decrypt_config(&stored, "key");
        assert!(result.is_err(), "short IV should be rejected");
    }
}

//! AES-CBC helper used by the encrypt/decrypt operators.
//!
//! Port of `presidio_anonymizer.operators.aes_cipher.AESCipher`. Layout matches
//! Presidio: a random 16-byte IV is prepended to the ciphertext and the whole
//! blob is Base64-encoded. PKCS7 padding, key length selects AES-128/192/256.

use aes::{Aes128, Aes192, Aes256};
use base64::{engine::general_purpose::STANDARD, Engine};
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use rand::RngCore;

type Enc128 = cbc::Encryptor<Aes128>;
type Enc192 = cbc::Encryptor<Aes192>;
type Enc256 = cbc::Encryptor<Aes256>;
type Dec128 = cbc::Decryptor<Aes128>;
type Dec192 = cbc::Decryptor<Aes192>;
type Dec256 = cbc::Decryptor<Aes256>;

/// True if `len` is a valid AES key length in bytes (16/24/32).
pub fn is_valid_key_size(len: usize) -> bool {
    matches!(len, 16 | 24 | 32)
}

fn encrypt_bytes(key: &[u8], iv: &[u8], data: &[u8]) -> anyhow::Result<Vec<u8>> {
    Ok(match key.len() {
        16 => Enc128::new_from_slices(key, iv)?.encrypt_padded_vec_mut::<Pkcs7>(data),
        24 => Enc192::new_from_slices(key, iv)?.encrypt_padded_vec_mut::<Pkcs7>(data),
        32 => Enc256::new_from_slices(key, iv)?.encrypt_padded_vec_mut::<Pkcs7>(data),
        n => anyhow::bail!("invalid AES key length: {n} bytes (expected 16, 24 or 32)"),
    })
}

fn decrypt_bytes(key: &[u8], iv: &[u8], data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let out = match key.len() {
        16 => Dec128::new_from_slices(key, iv)?.decrypt_padded_vec_mut::<Pkcs7>(data),
        24 => Dec192::new_from_slices(key, iv)?.decrypt_padded_vec_mut::<Pkcs7>(data),
        32 => Dec256::new_from_slices(key, iv)?.decrypt_padded_vec_mut::<Pkcs7>(data),
        n => anyhow::bail!("invalid AES key length: {n} bytes (expected 16, 24 or 32)"),
    }
    .map_err(|e| anyhow::anyhow!("AES decrypt/unpad failed: {e}"))?;
    Ok(out)
}

/// Encrypt `text` with `key`; returns Base64(IV ‖ ciphertext).
pub fn encrypt(key: &[u8], text: &str) -> anyhow::Result<String> {
    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);
    let ct = encrypt_bytes(key, &iv, text.as_bytes())?;
    let mut blob = Vec::with_capacity(16 + ct.len());
    blob.extend_from_slice(&iv);
    blob.extend_from_slice(&ct);
    Ok(STANDARD.encode(blob))
}

/// Reverse of [`encrypt`]: decode Base64, split IV, decrypt, return UTF-8.
pub fn decrypt(key: &[u8], encoded: &str) -> anyhow::Result<String> {
    let blob = STANDARD
        .decode(encoded.trim())
        .map_err(|e| anyhow::anyhow!("invalid base64: {e}"))?;
    if blob.len() <= 16 {
        anyhow::bail!("ciphertext too short");
    }
    let (iv, ct) = blob.split_at(16);
    let pt = decrypt_bytes(key, iv, ct)?;
    Ok(String::from_utf8(pt)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_128() {
        let key = b"1234567890123456"; // 16 bytes
        let enc = encrypt(key, "text_for_encryption").unwrap();
        assert_eq!(decrypt(key, &enc).unwrap(), "text_for_encryption");
    }

    #[test]
    fn roundtrip_256() {
        let key = b"12345678901234561234567890123456"; // 32 bytes
        let enc = encrypt(key, "hello world").unwrap();
        assert_eq!(decrypt(key, &enc).unwrap(), "hello world");
    }
}

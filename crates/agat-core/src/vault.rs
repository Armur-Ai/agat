//! Encrypted on-disk vault for malware samples.
//!
//! Samples are encrypted at rest with AES-256-GCM. The master key is
//! derived from a user-supplied password via Argon2id over a per-vault
//! random salt. The salt and a small ciphertext "check value" are
//! stored in `vault.json`; the password is verified by attempting to
//! decrypt the check value, so a wrong password fails fast and we
//! never silently re-key an existing vault.

use crate::{Error, Result, SampleId};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::Argon2;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

const VAULT_META_FILE: &str = "vault.json";
const NONCE_LEN: usize = 12;
const SALT_LEN: usize = 16;
const KEY_CHECK_PLAINTEXT: &[u8] = b"agat-vault-v1";

#[derive(Serialize, Deserialize)]
struct VaultMeta {
    version: u32,
    salt_hex: String,
    key_check_hex: String,
}

pub struct Vault {
    path: PathBuf,
    key: [u8; 32],
}

impl Vault {
    pub fn open_or_create(path: &Path, password: &str) -> Result<Self> {
        std::fs::create_dir_all(path)?;
        let meta_path = path.join(VAULT_META_FILE);

        if meta_path.exists() {
            let text = std::fs::read_to_string(&meta_path)?;
            let meta: VaultMeta = serde_json::from_str(&text)?;
            let salt = hex::decode(&meta.salt_hex)?;
            let key = derive_key(password, &salt)?;
            let check_bytes = hex::decode(&meta.key_check_hex)?;
            verify_check(&key, &check_bytes)?;
            Ok(Self {
                path: path.to_path_buf(),
                key,
            })
        } else {
            let mut salt = [0u8; SALT_LEN];
            rand::thread_rng().fill_bytes(&mut salt);
            let key = derive_key(password, &salt)?;
            let check = encrypt_check(&key)?;
            let meta = VaultMeta {
                version: 1,
                salt_hex: hex::encode(salt),
                key_check_hex: hex::encode(&check),
            };
            std::fs::write(&meta_path, serde_json::to_string_pretty(&meta)?)?;
            Ok(Self {
                path: path.to_path_buf(),
                key,
            })
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn sample_path(&self, id: &SampleId) -> PathBuf {
        self.path.join(format!("{}.enc", id.to_hex()))
    }

    pub fn store(&self, id: &SampleId, plaintext: &[u8]) -> Result<()> {
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|e| Error::Crypto(format!("cipher init: {e}")))?;
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| Error::Crypto(format!("encrypt: {e}")))?;
        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        std::fs::write(self.sample_path(id), out)?;
        Ok(())
    }

    pub fn load(&self, id: &SampleId) -> Result<Vec<u8>> {
        let bytes = std::fs::read(self.sample_path(id))?;
        if bytes.len() < NONCE_LEN {
            return Err(Error::Vault("sample file truncated".into()));
        }
        let (nonce_bytes, ciphertext) = bytes.split_at(NONCE_LEN);
        let nonce = Nonce::from_slice(nonce_bytes);
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|e| Error::Crypto(format!("cipher init: {e}")))?;
        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| Error::Crypto(format!("decrypt failed: {e}")))
    }

    pub fn has(&self, id: &SampleId) -> bool {
        self.sample_path(id).exists()
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let argon = Argon2::default();
    let mut key = [0u8; 32];
    argon
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| Error::Crypto(format!("argon2: {e}")))?;
    Ok(key)
}

fn encrypt_check(key: &[u8; 32]) -> Result<Vec<u8>> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| Error::Crypto(format!("cipher init: {e}")))?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, KEY_CHECK_PLAINTEXT)
        .map_err(|e| Error::Crypto(format!("encrypt check: {e}")))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn verify_check(key: &[u8; 32], check: &[u8]) -> Result<()> {
    if check.len() < NONCE_LEN {
        return Err(Error::Vault("vault check value truncated".into()));
    }
    let (nonce_bytes, ct) = check.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| Error::Crypto(format!("cipher init: {e}")))?;
    let pt = cipher
        .decrypt(nonce, ct)
        .map_err(|_| Error::Crypto("vault password is wrong".into()))?;
    if pt != KEY_CHECK_PLAINTEXT {
        return Err(Error::Crypto("vault check tamper detected".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_encrypt_decrypt() {
        let tmp = tempdir();
        let vault = Vault::open_or_create(&tmp, "correct horse battery staple").unwrap();
        let id = SampleId::from_bytes(b"hello world");
        vault.store(&id, b"hello world").unwrap();
        let back = vault.load(&id).unwrap();
        assert_eq!(back, b"hello world");
    }

    #[test]
    fn wrong_password_rejected() {
        let tmp = tempdir();
        {
            let _ = Vault::open_or_create(&tmp, "pw-one").unwrap();
        }
        match Vault::open_or_create(&tmp, "pw-two") {
            Err(Error::Crypto(_)) => (),
            Err(e) => panic!("expected Crypto error, got: {e:?}"),
            Ok(_) => panic!("expected wrong-password failure"),
        }
    }

    fn tempdir() -> PathBuf {
        let mut p = std::env::temp_dir();
        let mut rng = rand::thread_rng();
        let mut buf = [0u8; 8];
        rng.fill_bytes(&mut buf);
        p.push(format!("agat-vault-test-{}", hex::encode(buf)));
        p
    }
}

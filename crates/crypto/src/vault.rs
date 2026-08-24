use std::sync::Arc;

use anyhow::{Result, anyhow};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedBlob {
    pub version: u8,
    pub salt: [u8; 16],
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedVaultKey {
    pub version: u8,
    pub salt: [u8; 16],
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

impl EncryptedBlob {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(44 + self.ciphertext.len());
        encoded.extend_from_slice(b"TCB");
        encoded.push(self.version);
        encoded.extend_from_slice(&self.salt);
        encoded.extend_from_slice(&self.nonce);
        encoded.extend_from_slice(&self.ciphertext);
        encoded
    }

    pub fn from_bytes(encoded: &[u8]) -> Result<Self> {
        if !encoded.starts_with(b"TCB") {
            return Ok(serde_json::from_slice(encoded)?);
        }
        if encoded.len() < 44 {
            return Err(anyhow!("truncated encrypted blob"));
        }
        Ok(Self {
            version: encoded[3],
            salt: encoded[4..20]
                .try_into()
                .map_err(|_| anyhow!("invalid encrypted blob salt"))?,
            nonce: encoded[20..44]
                .try_into()
                .map_err(|_| anyhow!("invalid encrypted blob nonce"))?,
            ciphertext: encoded[44..].to_vec(),
        })
    }
}

impl WrappedVaultKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(44 + self.ciphertext.len());
        encoded.extend_from_slice(b"TCW");
        encoded.push(self.version);
        encoded.extend_from_slice(&self.salt);
        encoded.extend_from_slice(&self.nonce);
        encoded.extend_from_slice(&self.ciphertext);
        encoded
    }

    pub fn from_bytes(encoded: &[u8]) -> Result<Self> {
        if !encoded.starts_with(b"TCW") {
            return Ok(serde_json::from_slice(encoded)?);
        }
        if encoded.len() < 44 {
            return Err(anyhow!("truncated wrapped vault key"));
        }
        Ok(Self {
            version: encoded[3],
            salt: encoded[4..20]
                .try_into()
                .map_err(|_| anyhow!("invalid wrapped vault salt"))?,
            nonce: encoded[20..44]
                .try_into()
                .map_err(|_| anyhow!("invalid wrapped vault nonce"))?,
            ciphertext: encoded[44..].to_vec(),
        })
    }
}

#[derive(Clone)]
pub struct VaultKey(Arc<Zeroizing<[u8; 32]>>);

impl VaultKey {
    pub fn create(passphrase: &str) -> Result<(Self, WrappedVaultKey)> {
        let mut data_key = Zeroizing::new([0_u8; 32]);
        let mut salt = [0_u8; 16];
        let mut nonce = [0_u8; 24];
        OsRng.fill_bytes(data_key.as_mut());
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);
        let wrapping_key = derive_key(passphrase, &salt)?;
        let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key.as_slice())
            .map_err(|_| anyhow!("invalid vault wrapping key"))?;
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: data_key.as_slice(),
                    aad: b"tui-chat-vault-key-v2",
                },
            )
            .map_err(|_| anyhow!("failed to wrap local vault key"))?;
        Ok((
            Self(Arc::new(data_key)),
            WrappedVaultKey {
                version: 2,
                salt,
                nonce,
                ciphertext,
            },
        ))
    }

    pub fn unlock(passphrase: &str, wrapped: &WrappedVaultKey) -> Result<Self> {
        if wrapped.version != 2 {
            return Err(anyhow!("unsupported wrapped vault key version"));
        }
        let wrapping_key = derive_key(passphrase, &wrapped.salt)?;
        let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key.as_slice())
            .map_err(|_| anyhow!("invalid vault wrapping key"))?;
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(&wrapped.nonce),
                    Payload {
                        msg: &wrapped.ciphertext,
                        aad: b"tui-chat-vault-key-v2",
                    },
                )
                .map_err(|_| anyhow!("wrong local passphrase or corrupted vault key"))?,
        );
        let key: [u8; 32] = plaintext
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("invalid local vault key length"))?;
        Ok(Self(Arc::new(Zeroizing::new(key))))
    }

    pub fn encrypt(&self, aad: &[u8], plaintext: &[u8]) -> Result<EncryptedBlob> {
        let mut nonce = [0_u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let cipher = XChaCha20Poly1305::new_from_slice(self.0.as_slice())
            .map_err(|_| anyhow!("invalid local vault key"))?;
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| anyhow!("local encryption failed"))?;
        Ok(EncryptedBlob {
            version: 2,
            salt: [0; 16],
            nonce,
            ciphertext,
        })
    }

    pub fn decrypt(&self, aad: &[u8], blob: &EncryptedBlob) -> Result<Vec<u8>> {
        if blob.version != 2 {
            return Err(anyhow!(
                "encrypted blob does not use the unlocked vault key"
            ));
        }
        let cipher = XChaCha20Poly1305::new_from_slice(self.0.as_slice())
            .map_err(|_| anyhow!("invalid local vault key"))?;
        cipher
            .decrypt(
                XNonce::from_slice(&blob.nonce),
                Payload {
                    msg: &blob.ciphertext,
                    aad,
                },
            )
            .map_err(|_| anyhow!("wrong local vault key or corrupted data"))
    }
}

pub fn encrypt_blob(passphrase: &str, aad: &[u8], plaintext: &[u8]) -> Result<EncryptedBlob> {
    let mut salt = [0_u8; 16];
    let mut nonce = [0_u8; 24];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    let key = derive_key(passphrase, &salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(|_| anyhow!("invalid storage key"))?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow!("local encryption failed"))?;
    Ok(EncryptedBlob {
        version: 1,
        salt,
        nonce,
        ciphertext,
    })
}

pub fn decrypt_blob(passphrase: &str, aad: &[u8], blob: &EncryptedBlob) -> Result<Vec<u8>> {
    if blob.version != 1 {
        return Err(anyhow!("unsupported encrypted storage version"));
    }
    let key = derive_key(passphrase, &blob.salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(|_| anyhow!("invalid storage key"))?;
    cipher
        .decrypt(
            XNonce::from_slice(&blob.nonce),
            Payload {
                msg: &blob.ciphertext,
                aad,
            },
        )
        .map_err(|_| anyhow!("wrong local passphrase or corrupted data"))
}

fn derive_key(passphrase: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let params =
        Params::new(64 * 1024, 3, 1, Some(32)).map_err(|error| anyhow!(error.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0_u8; 32]);
    argon
        .hash_password_into(passphrase.as_bytes(), salt, key.as_mut())
        .map_err(|error| anyhow!(error.to_string()))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_round_trip_and_authentication() -> Result<()> {
        let blob = encrypt_blob("correct horse battery", b"messages/1", b"secret")?;
        assert_eq!(
            decrypt_blob("correct horse battery", b"messages/1", &blob)?,
            b"secret"
        );
        assert!(decrypt_blob("wrong password", b"messages/1", &blob).is_err());
        assert!(decrypt_blob("correct horse battery", b"messages/2", &blob).is_err());
        Ok(())
    }

    #[test]
    fn wrapped_vault_key_round_trips_and_binds_aad() -> Result<()> {
        let (key, wrapped) = VaultKey::create("local passphrase")?;
        let reopened = VaultKey::unlock("local passphrase", &wrapped)?;
        let blob = key.encrypt(b"draft/v2/conversation", b"unfinished secret")?;
        assert_eq!(
            reopened.decrypt(b"draft/v2/conversation", &blob)?,
            b"unfinished secret"
        );
        assert!(reopened.decrypt(b"draft/v2/other", &blob).is_err());
        assert!(VaultKey::unlock("wrong passphrase", &wrapped).is_err());
        Ok(())
    }
}

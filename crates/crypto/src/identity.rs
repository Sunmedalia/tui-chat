use anyhow::{Result, anyhow};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tui_chat_protocol::{
    device_certificate_payload,
    v1::{DeviceBundle, OneTimeKey},
};
use vodozemac::olm::Account;
use zeroize::Zeroize;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicDevice {
    pub device_id: String,
    pub device_name: String,
    pub auth_signing_key: Vec<u8>,
    pub olm_ed25519_key: Vec<u8>,
    pub olm_curve25519_key: Vec<u8>,
    pub certificate_signature: Vec<u8>,
}

pub struct DeviceIdentity {
    account_id: String,
    device_id: String,
    device_name: String,
    master: Option<SigningKey>,
    auth: SigningKey,
}

#[derive(Serialize, Deserialize)]
struct IdentityPickle {
    account_id: String,
    device_id: String,
    device_name: String,
    master: Option<[u8; 32]>,
    auth: [u8; 32],
}

impl DeviceIdentity {
    pub fn new(
        account_id: impl Into<String>,
        device_id: impl Into<String>,
        device_name: impl Into<String>,
        first_device: bool,
    ) -> Self {
        Self {
            account_id: account_id.into(),
            device_id: device_id.into(),
            device_name: device_name.into(),
            master: first_device.then(|| SigningKey::generate(&mut OsRng)),
            auth: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn account_id(&self) -> &str {
        &self.account_id
    }
    pub fn device_id(&self) -> &str {
        &self.device_id
    }
    pub fn device_name(&self) -> &str {
        &self.device_name
    }
    pub fn has_master_secret(&self) -> bool {
        self.master.is_some()
    }

    pub fn master_public_key(&self) -> Option<[u8; 32]> {
        self.master
            .as_ref()
            .map(|key| key.verifying_key().to_bytes())
    }

    pub fn install_master_secret(&mut self, secret: [u8; 32]) {
        self.master = Some(SigningKey::from_bytes(&secret));
    }

    pub fn master_secret(&self) -> Option<[u8; 32]> {
        self.master.as_ref().map(SigningKey::to_bytes)
    }

    pub fn sign_auth_challenge(&self, payload: &[u8]) -> Vec<u8> {
        self.auth.sign(payload).to_bytes().to_vec()
    }

    pub fn public_device(&self, olm: &Account) -> Result<PublicDevice> {
        let keys = olm.identity_keys();
        let auth = self.auth.verifying_key().to_bytes().to_vec();
        let ed = keys.ed25519.as_bytes().to_vec();
        let curve = keys.curve25519.to_bytes().to_vec();
        let signature = self
            .master
            .as_ref()
            .map(|master| {
                master
                    .sign(&device_certificate_payload(
                        &self.account_id,
                        &self.device_id,
                        &auth,
                        &ed,
                        &curve,
                    ))
                    .to_bytes()
                    .to_vec()
            })
            .unwrap_or_default();
        Ok(PublicDevice {
            device_id: self.device_id.clone(),
            device_name: self.device_name.clone(),
            auth_signing_key: auth,
            olm_ed25519_key: ed,
            olm_curve25519_key: curve,
            certificate_signature: signature,
        })
    }

    pub fn certify_device(&self, device: &mut PublicDevice) -> Result<()> {
        let master = self
            .master
            .as_ref()
            .ok_or_else(|| anyhow!("account master secret is unavailable"))?;
        device.certificate_signature = master
            .sign(&device_certificate_payload(
                &self.account_id,
                &device.device_id,
                &device.auth_signing_key,
                &device.olm_ed25519_key,
                &device.olm_curve25519_key,
            ))
            .to_bytes()
            .to_vec();
        Ok(())
    }

    pub fn certify_bundle(&self, device: &mut DeviceBundle) -> Result<()> {
        let master = self
            .master
            .as_ref()
            .ok_or_else(|| anyhow!("account master secret is unavailable"))?;
        device.certificate_signature = master
            .sign(&device_certificate_payload(
                &self.account_id,
                &device.device_id,
                &device.auth_signing_key,
                &device.olm_ed25519_key,
                &device.olm_curve25519_key,
            ))
            .to_bytes()
            .to_vec();
        Ok(())
    }

    pub fn sign_roster(&self, revision: u64, device_id: &str) -> Result<Vec<u8>> {
        let master = self
            .master
            .as_ref()
            .ok_or_else(|| anyhow!("account master secret is unavailable"))?;
        let mut payload = b"tui-chat-roster-v1\0".to_vec();
        payload.extend_from_slice(self.account_id.as_bytes());
        payload.push(0);
        payload.extend_from_slice(&revision.to_be_bytes());
        payload.extend_from_slice(device_id.as_bytes());
        Ok(master.sign(&payload).to_bytes().to_vec())
    }

    pub fn sign_prekey(&self, key_id: String, curve25519_key: Vec<u8>) -> OneTimeKey {
        let mut payload = b"tui-chat-prekey-v1\0".to_vec();
        payload.extend_from_slice(key_id.as_bytes());
        payload.push(0);
        payload.extend_from_slice(&curve25519_key);
        OneTimeKey {
            key_id,
            curve25519_key,
            signature: self.auth.sign(&payload).to_bytes().to_vec(),
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut encoded = b"TCI3".to_vec();
        encoded.extend(postcard::to_allocvec(&IdentityPickle {
            account_id: self.account_id.clone(),
            device_id: self.device_id.clone(),
            device_name: self.device_name.clone(),
            master: self.master.as_ref().map(SigningKey::to_bytes),
            auth: self.auth.to_bytes(),
        })?);
        Ok(encoded)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let pickle: IdentityPickle = if let Some(encoded) = bytes.strip_prefix(b"TCI3") {
            postcard::from_bytes(encoded)?
        } else {
            serde_json::from_slice(bytes)?
        };
        Ok(Self {
            account_id: pickle.account_id,
            device_id: pickle.device_id,
            device_name: pickle.device_name,
            master: pickle.master.map(|mut bytes| {
                let key = SigningKey::from_bytes(&bytes);
                bytes.zeroize();
                key
            }),
            auth: SigningKey::from_bytes(&pickle.auth),
        })
    }
}

impl From<PublicDevice> for DeviceBundle {
    fn from(value: PublicDevice) -> Self {
        Self {
            device_id: value.device_id,
            device_name: value.device_name,
            auth_signing_key: value.auth_signing_key,
            olm_ed25519_key: value.olm_ed25519_key,
            olm_curve25519_key: value.olm_curve25519_key,
            certificate_signature: value.certificate_signature,
            revoked: false,
        }
    }
}

pub fn safety_code(user_a: &str, master_a: &[u8], user_b: &str, master_b: &[u8]) -> String {
    let (first_user, first_key, second_user, second_key) = if user_a <= user_b {
        (user_a, master_a, user_b, master_b)
    } else {
        (user_b, master_b, user_a, master_a)
    };
    let mut hash = Sha256::new();
    hash.update(b"tui-chat-safety-code-v1\0");
    hash.update(first_user);
    hash.update([0]);
    hash.update(first_key);
    hash.update(second_user);
    hash.update([0]);
    hash.update(second_key);
    let digest = hash.finalize();
    digest
        .chunks(5)
        .take(6)
        .map(|chunk| {
            let mut value = 0_u64;
            for byte in chunk {
                value = (value << 8) | u64::from(*byte);
            }
            format!("{:05}", value % 100_000)
        })
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn verify_device_bundle(master: &[u8], account_id: &str, device: &DeviceBundle) -> Result<()> {
    let key: [u8; 32] = master
        .try_into()
        .map_err(|_| anyhow!("invalid account master key"))?;
    let signature = Signature::from_slice(&device.certificate_signature)
        .map_err(|_| anyhow!("invalid device certificate"))?;
    VerifyingKey::from_bytes(&key)?.verify_strict(
        &device_certificate_payload(
            account_id,
            &device.device_id,
            &device.auth_signing_key,
            &device.olm_ed25519_key,
            &device.olm_curve25519_key,
        ),
        &signature,
    )?;
    Ok(())
}

pub fn verify_prekey(device: &DeviceBundle, key: &OneTimeKey) -> Result<()> {
    let public: [u8; 32] = device
        .auth_signing_key
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("invalid device signing key"))?;
    let signature =
        Signature::from_slice(&key.signature).map_err(|_| anyhow!("invalid prekey signature"))?;
    let mut payload = b"tui-chat-prekey-v1\0".to_vec();
    payload.extend_from_slice(key.key_id.as_bytes());
    payload.push(0);
    payload.extend_from_slice(&key.curve25519_key);
    VerifyingKey::from_bytes(&public)?.verify_strict(&payload, &signature)?;
    Ok(())
}

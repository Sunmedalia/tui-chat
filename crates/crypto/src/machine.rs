use std::collections::HashMap;

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use vodozemac::{
    Curve25519PublicKey,
    olm::{Account, AccountPickle, OlmMessage, Session, SessionConfig, SessionPickle},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreKeyMaterial {
    pub device_id: String,
    pub identity_key: [u8; 32],
    pub one_time_key: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedOlm {
    pub message_type: u32,
    pub ciphertext: Vec<u8>,
}

pub struct OlmMachine {
    account: Account,
    sessions: HashMap<String, Vec<Session>>,
}

#[derive(Serialize, Deserialize)]
struct MachinePickleV2 {
    account: AccountPickle,
    sessions: HashMap<String, Vec<SessionPickle>>,
}

#[derive(Deserialize)]
struct MachinePickleV1 {
    account: AccountPickle,
    sessions: HashMap<String, SessionPickle>,
}

impl Default for OlmMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl OlmMachine {
    pub fn new() -> Self {
        Self {
            account: Account::new(),
            sessions: HashMap::new(),
        }
    }
    pub fn account(&self) -> &Account {
        &self.account
    }
    pub fn account_mut(&mut self) -> &mut Account {
        &mut self.account
    }

    pub fn generate_prekeys(&mut self, count: usize) {
        let _ = self.account.generate_one_time_keys(count);
    }
    pub fn stored_prekey_count(&self) -> usize {
        self.account.stored_one_time_key_count()
    }

    pub fn unpublished_prekeys(&self) -> Vec<(String, Vec<u8>)> {
        self.account
            .one_time_keys()
            .into_iter()
            .map(|(id, key)| (id.to_base64(), key.to_bytes().to_vec()))
            .collect()
    }

    pub fn mark_prekeys_published(&mut self) {
        self.account.mark_keys_as_published();
    }
    pub fn has_session(&self, device_id: &str) -> bool {
        self.sessions
            .get(device_id)
            .is_some_and(|items| !items.is_empty())
    }

    pub fn encrypt_existing(&mut self, device_id: &str, plaintext: &[u8]) -> Result<EncryptedOlm> {
        let message = self
            .sessions
            .get_mut(device_id)
            .and_then(|sessions| sessions.last_mut())
            .ok_or_else(|| anyhow!("no Olm session for device"))?
            .encrypt(plaintext)?;
        let (message_type, ciphertext) = message.to_parts();
        Ok(EncryptedOlm {
            message_type: message_type as u32,
            ciphertext,
        })
    }

    pub fn encrypt(
        &mut self,
        recipient: &PreKeyMaterial,
        plaintext: &[u8],
    ) -> Result<EncryptedOlm> {
        if !self.has_session(&recipient.device_id) {
            let session = self.account.create_outbound_session(
                SessionConfig::version_1(),
                Curve25519PublicKey::from_bytes(recipient.identity_key),
                Curve25519PublicKey::from_bytes(recipient.one_time_key),
            )?;
            self.sessions
                .entry(recipient.device_id.clone())
                .or_default()
                .push(session);
        }
        let message = self
            .sessions
            .get_mut(&recipient.device_id)
            .and_then(|sessions| sessions.last_mut())
            .context("new Olm session disappeared")?
            .encrypt(plaintext)?;
        let (message_type, ciphertext) = message.to_parts();
        Ok(EncryptedOlm {
            message_type: message_type as u32,
            ciphertext,
        })
    }

    pub fn decrypt(
        &mut self,
        sender_device: &str,
        sender_identity_key: [u8; 32],
        encrypted: &EncryptedOlm,
    ) -> Result<Vec<u8>> {
        let message =
            OlmMessage::from_parts(encrypted.message_type as usize, &encrypted.ciphertext)?;
        if let Some(sessions) = self.sessions.get_mut(sender_device) {
            for session in sessions.iter_mut().rev() {
                if let Ok(plaintext) = session.decrypt(&message) {
                    return Ok(plaintext);
                }
            }
        }
        let OlmMessage::PreKey(prekey) = message else {
            return Err(anyhow!("no matching Olm session"));
        };
        let inbound = self.account.create_inbound_session(
            SessionConfig::version_1(),
            Curve25519PublicKey::from_bytes(sender_identity_key),
            &prekey,
        )?;
        let sessions = self.sessions.entry(sender_device.to_owned()).or_default();
        if !sessions
            .iter()
            .any(|session| session.session_id() == inbound.session.session_id())
        {
            sessions.push(inbound.session);
            if sessions.len() > 5 {
                sessions.remove(0);
            }
        }
        Ok(inbound.plaintext)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut encoded = b"TCM3".to_vec();
        encoded.extend(serde_json::to_vec(&MachinePickleV2 {
            account: self.account.pickle(),
            sessions: self
                .sessions
                .iter()
                .map(|(device, sessions)| {
                    (
                        device.clone(),
                        sessions.iter().map(Session::pickle).collect(),
                    )
                })
                .collect(),
        })?);
        Ok(encoded)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if let Some(encoded) = bytes.strip_prefix(b"TCM3") {
            // vodozemac's pickles contain serde representations that deliberately
            // use `deserialize_any`, which postcard does not support.
            let pickle: MachinePickleV2 = serde_json::from_slice(encoded)?;
            return Ok(Self::from_pickle_v2(pickle));
        }
        if let Ok(pickle) = serde_json::from_slice::<MachinePickleV2>(bytes) {
            return Ok(Self::from_pickle_v2(pickle));
        }
        let pickle: MachinePickleV1 = serde_json::from_slice(bytes)?;
        Ok(Self {
            account: Account::from_pickle(pickle.account),
            sessions: pickle
                .sessions
                .into_iter()
                .map(|(device, session)| (device, vec![Session::from_pickle(session)]))
                .collect(),
        })
    }

    fn from_pickle_v2(pickle: MachinePickleV2) -> Self {
        Self {
            account: Account::from_pickle(pickle.account),
            sessions: pickle
                .sessions
                .into_iter()
                .map(|(device, sessions)| {
                    (
                        device,
                        sessions.into_iter().map(Session::from_pickle).collect(),
                    )
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_olm_round_trip_and_pickle() -> Result<()> {
        let mut alice = OlmMachine::new();
        let mut bob = OlmMachine::new();
        bob.generate_prekeys(1);
        let (_, one_time) = bob
            .unpublished_prekeys()
            .into_iter()
            .next()
            .context("bob prekey")?;
        let recipient = PreKeyMaterial {
            device_id: "bob-device".into(),
            identity_key: bob.account().curve25519_key().to_bytes(),
            one_time_key: one_time.try_into().map_err(|_| anyhow!("key length"))?,
        };
        let encrypted = alice.encrypt(&recipient, b"hello")?;
        let plaintext = bob.decrypt(
            "alice-device",
            alice.account().curve25519_key().to_bytes(),
            &encrypted,
        )?;
        assert_eq!(plaintext, b"hello");
        let alice = OlmMachine::from_bytes(&alice.to_bytes()?)?;
        assert_eq!(
            alice.account().identity_keys(),
            OlmMachine::from_bytes(&alice.to_bytes()?)?
                .account()
                .identity_keys()
        );
        Ok(())
    }
}

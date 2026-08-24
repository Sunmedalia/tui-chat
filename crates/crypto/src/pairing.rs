use anyhow::{Result, anyhow};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use rand::{RngCore, rngs::OsRng};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub struct PairingState {
    secret: StaticSecret,
    public: PublicKey,
}

pub struct PairingChannel {
    key: Zeroizing<[u8; 32]>,
    sas: (u16, u16, u16),
}

impl PairingState {
    pub fn new() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.public.to_bytes()
    }
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    pub fn from_secret(secret: [u8; 32]) -> Self {
        let secret = StaticSecret::from(secret);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn establish(self, peer: [u8; 32], pairing_id: &str) -> Result<PairingChannel> {
        let peer = PublicKey::from(peer);
        let shared = self.secret.diffie_hellman(&peer);
        if !shared.was_contributory() {
            return Err(anyhow!("invalid pairing public key"));
        }
        let (first, second) = if self.public.as_bytes() <= peer.as_bytes() {
            (self.public.as_bytes(), peer.as_bytes())
        } else {
            (peer.as_bytes(), self.public.as_bytes())
        };
        let mut info = b"tui-chat-pairing-v1\0".to_vec();
        info.extend_from_slice(pairing_id.as_bytes());
        info.push(0);
        info.extend_from_slice(first);
        info.extend_from_slice(second);
        let hkdf = Hkdf::<Sha256>::new(None, shared.as_bytes());
        let mut output = Zeroizing::new([0_u8; 38]);
        hkdf.expand(&info, output.as_mut())
            .map_err(|_| anyhow!("pairing key derivation failed"))?;
        let mut key = Zeroizing::new([0_u8; 32]);
        key.copy_from_slice(&output[..32]);
        let sas = (
            ((u16::from(output[32]) << 5) | u16::from(output[33] >> 3)) + 1000,
            (((u16::from(output[33] & 7) << 10)
                | (u16::from(output[34]) << 2)
                | u16::from(output[35] >> 6))
                + 1000),
            (((u16::from(output[35] & 63) << 7) | u16::from(output[36] >> 1)) + 1000),
        );
        Ok(PairingChannel { key, sas })
    }
}

impl Default for PairingState {
    fn default() -> Self {
        Self::new()
    }
}

impl PairingChannel {
    pub fn sas_decimals(&self) -> (u16, u16, u16) {
        self.sas
    }

    pub fn encrypt(&self, pairing_id: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = [0_u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let cipher = XChaCha20Poly1305::new_from_slice(self.key.as_slice())
            .map_err(|_| anyhow!("invalid pairing key"))?;
        let encrypted = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: pairing_id.as_bytes(),
                },
            )
            .map_err(|_| anyhow!("pairing encryption failed"))?;
        Ok([nonce.as_slice(), encrypted.as_slice()].concat())
    }

    pub fn decrypt(&self, pairing_id: &str, payload: &[u8]) -> Result<Vec<u8>> {
        if payload.len() < 24 {
            return Err(anyhow!("truncated pairing payload"));
        }
        let cipher = XChaCha20Poly1305::new_from_slice(self.key.as_slice())
            .map_err(|_| anyhow!("invalid pairing key"))?;
        cipher
            .decrypt(
                XNonce::from_slice(&payload[..24]),
                Payload {
                    msg: &payload[24..],
                    aad: pairing_id.as_bytes(),
                },
            )
            .map_err(|_| anyhow!("pairing payload authentication failed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sas_and_channel_match() -> Result<()> {
        let alice = PairingState::new();
        let bob = PairingState::new();
        let alice_public = alice.public_key();
        let bob_public = bob.public_key();
        let alice = alice.establish(bob_public, "pair-1")?;
        let bob = bob.establish(alice_public, "pair-1")?;
        assert_eq!(alice.sas_decimals(), bob.sas_decimals());
        assert_eq!(
            bob.decrypt("pair-1", &alice.encrypt("pair-1", b"history")?)?,
            b"history"
        );
        Ok(())
    }
}

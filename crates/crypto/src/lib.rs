#![forbid(unsafe_code)]

mod identity;
mod machine;
mod pairing;
mod vault;

pub use identity::{
    DeviceIdentity, PublicDevice, safety_code, verify_device_bundle, verify_prekey,
};
pub use machine::{EncryptedOlm, OlmMachine, PreKeyMaterial};
pub use pairing::{PairingChannel, PairingState};
pub use vault::{EncryptedBlob, VaultKey, WrappedVaultKey, decrypt_blob, encrypt_blob};

#![forbid(unsafe_code)]

use bytes::Bytes;
use prost::Message;
use thiserror::Error;

pub mod v1 {
    include!(concat!(env!("OUT_DIR"), "/tuichat.v1.rs"));
}

pub const PROTOCOL_VERSION: u32 = 2;
pub const MAX_FRAME_BYTES: usize = 256 * 1024;
pub const MAX_TEXT_BYTES: usize = 16 * 1024;
pub const CAPABILITY_OWN_DEVICES: &str = "own_devices_v1";
pub const CAPABILITY_STABLE_ERRORS: &str = "stable_errors_v1";

pub fn client_capabilities() -> Vec<String> {
    vec![
        CAPABILITY_OWN_DEVICES.to_owned(),
        CAPABILITY_STABLE_ERRORS.to_owned(),
    ]
}

pub fn conversation_id(account_a: &str, account_b: &str) -> String {
    use sha2::{Digest, Sha256};
    let (first, second) = if account_a <= account_b {
        (account_a, account_b)
    } else {
        (account_b, account_a)
    };
    let digest = Sha256::digest(
        [
            b"tui-chat-conversation-v1\0".as_slice(),
            first.as_bytes(),
            b"\0",
            second.as_bytes(),
        ]
        .concat(),
    );
    hex_string(&digest)
}

pub fn device_certificate_payload(
    account_id: &str,
    device_id: &str,
    auth_key: &[u8],
    olm_ed25519: &[u8],
    olm_curve25519: &[u8],
) -> Vec<u8> {
    let mut out = b"tui-chat-device-certificate-v1\0".to_vec();
    for field in [
        account_id.as_bytes(),
        device_id.as_bytes(),
        auth_key,
        olm_ed25519,
        olm_curve25519,
    ] {
        out.extend_from_slice(&(field.len() as u32).to_be_bytes());
        out.extend_from_slice(field);
    }
    out
}

pub fn auth_challenge_payload(
    domain: &str,
    username: &str,
    device_id: &str,
    nonce: &[u8],
    expires_at_ms: i64,
) -> Vec<u8> {
    let mut out = b"tui-chat-device-auth-v1\0".to_vec();
    for field in [
        domain.as_bytes(),
        username.as_bytes(),
        device_id.as_bytes(),
        nonce,
    ] {
        out.extend_from_slice(&(field.len() as u32).to_be_bytes());
        out.extend_from_slice(field);
    }
    out.extend_from_slice(&expires_at_ms.to_be_bytes());
    out
}

fn hex_string(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[derive(Debug, Error)]
pub enum CodecError {
    #[error("frame exceeds {MAX_FRAME_BYTES} bytes")]
    TooLarge,
    #[error("invalid protobuf frame: {0}")]
    Decode(#[from] prost::DecodeError),
}

pub fn encode_frame(frame: &v1::Frame) -> Bytes {
    Bytes::from(frame.encode_to_vec())
}

pub fn decode_frame(data: &[u8]) -> Result<v1::Frame, CodecError> {
    if data.len() > MAX_FRAME_BYTES {
        return Err(CodecError::TooLarge);
    }
    Ok(v1::Frame::decode(data)?)
}

pub fn frame(id: impl Into<String>, body: v1::frame::Body) -> v1::Frame {
    v1::Frame {
        protocol_version: PROTOCOL_VERSION,
        id: id.into(),
        body: Some(body),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversation_ids_are_symmetric_and_domain_separated() {
        assert_eq!(
            conversation_id("alice", "bob"),
            conversation_id("bob", "alice")
        );
        assert_ne!(
            conversation_id("alice", "bob"),
            conversation_id("alice", "carol")
        );
    }

    #[test]
    fn codec_enforces_size_and_round_trips() {
        let original = frame(
            "request",
            v1::frame::Body::Ping(v1::Ping { sent_at_ms: 42 }),
        );
        assert_eq!(
            decode_frame(&encode_frame(&original)).expect("valid frame"),
            original
        );
        assert!(matches!(
            decode_frame(&vec![0; MAX_FRAME_BYTES + 1]),
            Err(CodecError::TooLarge)
        ));
    }

    #[test]
    fn device_management_frames_and_capabilities_round_trip() {
        let capabilities = client_capabilities();
        assert!(
            capabilities
                .iter()
                .any(|item| item == CAPABILITY_OWN_DEVICES)
        );
        assert!(
            capabilities
                .iter()
                .any(|item| item == CAPABILITY_STABLE_ERRORS)
        );
        let original = frame(
            "devices",
            v1::frame::Body::OwnDeviceList(v1::OwnDeviceList {
                devices: vec![v1::OwnDeviceInfo {
                    device_id: "device".into(),
                    device_name: "laptop".into(),
                    pending: false,
                    revoked: false,
                    current: true,
                    online: true,
                    created_at_ms: 1,
                    last_authenticated_at_ms: 2,
                }],
            }),
        );
        assert_eq!(
            decode_frame(&encode_frame(&original)).expect("valid device frame"),
            original
        );
    }
}

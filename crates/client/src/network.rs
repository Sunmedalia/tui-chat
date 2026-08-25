use std::{collections::HashMap, sync::Arc};

use anyhow::{Context, Result, anyhow, bail};
use futures_util::{SinkExt, StreamExt};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme,
    client::{
        WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream, connect_async, connect_async_tls_with_config,
    tungstenite::Message,
};
use tui_chat_protocol::{
    PROTOCOL_VERSION, decode_frame, encode_frame, frame,
    v1::{self, frame::Body},
};
use url::{Host, Url};
use uuid::Uuid;

type Socket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

pub struct RawConnection {
    socket: Socket,
}

#[derive(Clone)]
pub struct RpcClient {
    tx: mpsc::Sender<v1::Frame>,
    pending: Arc<Mutex<HashMap<String, oneshot::Sender<v1::Frame>>>>,
}

impl RawConnection {
    pub async fn connect(url: &str, spki_pin: Option<&str>) -> Result<Self> {
        validate_server_url(url)?;
        let connector = spki_pin
            .map(|pin| parse_pin(pin).and_then(pinned_connector))
            .transpose()?;
        let (socket, _) = tokio::time::timeout(std::time::Duration::from_secs(15), async {
            if let Some(connector) = connector {
                connect_async_tls_with_config(url, None, false, Some(connector)).await
            } else {
                connect_async(url).await
            }
        })
        .await
        .map_err(|_| anyhow!("connection timed out"))?
        .with_context(|| format!("failed to connect to {url}"))?;
        Ok(Self { socket })
    }

    pub async fn request(&mut self, body: Body) -> Result<v1::Frame> {
        let id = Uuid::new_v4().to_string();
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            self.socket
                .send(Message::Binary(encode_frame(&frame(&id, body))))
                .await?;
            loop {
                let data = match self.socket.next().await {
                    Some(Ok(Message::Binary(data))) => data,
                    Some(Ok(_)) => continue,
                    Some(Err(error)) => return Err(error.into()),
                    None => bail!("server closed the connection"),
                };
                let response = decode_frame(&data)?;
                if response.protocol_version != PROTOCOL_VERSION {
                    bail!("server protocol version mismatch");
                }
                if response.id == id {
                    if let Some(Body::Error(error)) = &response.body {
                        bail!("{}: {}", error.code, error.message);
                    }
                    return Ok(response);
                }
            }
        })
        .await
        .map_err(|_| anyhow!("request timed out"))?
    }

    pub fn start(self) -> (RpcClient, mpsc::Receiver<v1::Frame>) {
        let (mut sink, mut stream) = self.socket.split();
        let (out_tx, mut out_rx) = mpsc::channel::<v1::Frame>(128);
        let (event_tx, event_rx) = mpsc::channel::<v1::Frame>(256);
        let pending: Arc<Mutex<HashMap<String, oneshot::Sender<v1::Frame>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let reader_pending = pending.clone();
        let writer_event_tx = event_tx.clone();
        tokio::spawn(async move {
            while let Some(frame) = out_rx.recv().await {
                if sink
                    .send(Message::Binary(encode_frame(&frame)))
                    .await
                    .is_err()
                {
                    let _ = writer_event_tx.try_send(connection_closed_frame());
                    break;
                }
            }
        });
        tokio::spawn(async move {
            while let Some(message) = stream.next().await {
                let Ok(Message::Binary(data)) = message else {
                    continue;
                };
                let Ok(frame) = decode_frame(&data) else {
                    continue;
                };
                let waiter = if frame.id.is_empty() {
                    None
                } else {
                    reader_pending.lock().await.remove(&frame.id)
                };
                if let Some(waiter) = waiter {
                    let _ = waiter.send(frame);
                } else if event_tx.send(frame).await.is_err() {
                    break;
                }
            }
            reader_pending.lock().await.clear();
            let _ = event_tx.send(connection_closed_frame()).await;
        });
        (
            RpcClient {
                tx: out_tx,
                pending,
            },
            event_rx,
        )
    }
}

fn connection_closed_frame() -> v1::Frame {
    frame(
        "",
        Body::Error(v1::Error {
            code: "connection_closed".into(),
            message: "connection closed".into(),
            retryable: true,
        }),
    )
}

fn validate_server_url(value: &str) -> Result<Url> {
    let url = Url::parse(value).context("invalid WebSocket URL")?;
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        bail!("WebSocket URL must not contain credentials or a fragment");
    }
    match url.scheme() {
        "wss" => {}
        "ws" => {
            let loopback = match url.host() {
                Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
                Some(Host::Ipv4(ip)) => ip.is_loopback(),
                Some(Host::Ipv6(ip)) => ip.is_loopback(),
                None => false,
            };
            if !loopback {
                bail!("refusing cleartext WebSocket outside an exact loopback host");
            }
        }
        _ => bail!("server URL must use wss:// or loopback ws://"),
    }
    Ok(url)
}

impl RpcClient {
    pub fn try_send_frame(&self, frame: v1::Frame) -> Result<()> {
        self.tx.try_send(frame).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => anyhow!("connection send queue is full"),
            mpsc::error::TrySendError::Closed(_) => anyhow!("connection writer stopped"),
        })
    }

    pub async fn request(&self, body: Body) -> Result<v1::Frame> {
        let id = Uuid::new_v4().to_string();
        self.request_with_id(id, body).await
    }

    pub async fn request_frame(&self, mut frame: v1::Frame) -> Result<v1::Frame> {
        if frame.id.is_empty() {
            frame.id = Uuid::new_v4().to_string();
        }
        let id = frame.id.clone();
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(id.clone(), tx);
        if self.tx.send(frame).await.is_err() {
            self.pending.lock().await.remove(&id);
            bail!("connection writer stopped");
        }
        let response = match tokio::time::timeout(std::time::Duration::from_secs(20), rx).await {
            Ok(Ok(response)) => response,
            Ok(Err(_)) => {
                self.pending.lock().await.remove(&id);
                bail!("connection closed");
            }
            Err(_) => {
                self.pending.lock().await.remove(&id);
                bail!("request timed out");
            }
        };
        if let Some(Body::Error(error)) = &response.body {
            bail!("{}: {}", error.code, error.message);
        }
        Ok(response)
    }

    async fn request_with_id(&self, id: String, body: Body) -> Result<v1::Frame> {
        self.request_frame(frame(id, body)).await
    }

    pub async fn notify(&self, body: Body) -> Result<()> {
        self.tx
            .send(frame("", body))
            .await
            .map_err(|_| anyhow!("connection writer stopped"))
    }
}

#[derive(Debug)]
struct SpkiPinVerifier {
    inner: Arc<WebPkiServerVerifier>,
    expected: [u8; 32],
}

impl ServerCertVerifier for SpkiPinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, TlsError> {
        let verified = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        let (_, certificate) =
            x509_parser::parse_x509_certificate(end_entity.as_ref()).map_err(|_| {
                TlsError::General("failed to parse server certificate for SPKI pinning".into())
            })?;
        let actual = Sha256::digest(certificate.tbs_certificate.subject_pki.raw);
        if actual.as_slice() != self.expected {
            return Err(TlsError::General(
                "server certificate SPKI pin mismatch".into(),
            ));
        }
        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

fn pinned_connector(expected: [u8; 32]) -> Result<Connector> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let inner = WebPkiServerVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|error| anyhow!(error.to_string()))?;
    let verifier = Arc::new(SpkiPinVerifier { inner, expected });
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Ok(Connector::Rustls(Arc::new(config)))
}

fn parse_pin(pin: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(pin.trim()).context("SPKI pin must be hexadecimal")?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("SPKI pin must contain exactly 32 bytes (64 hex characters)"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_strict_spki_pin() {
        assert_eq!(parse_pin(&"ab".repeat(32)).expect("valid pin"), [0xab; 32]);
        assert!(parse_pin("abcd").is_err());
        assert!(parse_pin(&"zz".repeat(32)).is_err());
    }

    #[test]
    fn cleartext_websocket_requires_an_exact_loopback_host() {
        assert!(validate_server_url("ws://127.0.0.1:8080/v2/ws").is_ok());
        assert!(validate_server_url("ws://[::1]:8080/v2/ws").is_ok());
        assert!(validate_server_url("ws://localhost:8080/v2/ws").is_ok());
        assert!(validate_server_url("wss://chat.example.com/v2/ws").is_ok());
        assert!(validate_server_url("ws://127.0.0.1.evil.example/v2/ws").is_err());
        assert!(validate_server_url("ws://localhost.evil.example/v2/ws").is_err());
        assert!(validate_server_url("http://localhost/v2/ws").is_err());
        assert!(validate_server_url("wss://user:pass@example.com/v2/ws").is_err());
    }
}

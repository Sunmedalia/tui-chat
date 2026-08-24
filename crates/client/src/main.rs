#![forbid(unsafe_code)]

mod app;
mod editor;
mod local;
mod network;

use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use directories::ProjectDirs;
use local::{LocalStore, RuntimeProfile, VaultSession};
use network::RawConnection;
use tui_chat_crypto::{DeviceIdentity, OlmMachine, PairingState};
use tui_chat_protocol::{
    auth_challenge_payload,
    v1::{self, BootstrapDevice, DeviceAuth, PasswordAuth, frame::Body},
};
use url::Url;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

#[derive(Parser)]
#[command(
    name = "tui-chat",
    version,
    about = "End-to-end encrypted terminal chat"
)]
struct Args {
    #[arg(long)]
    server: Option<String>,
    #[arg(long)]
    username: Option<String>,
    #[arg(long)]
    data_dir: Option<PathBuf>,
    /// SHA-256 of the server certificate SubjectPublicKeyInfo (64 hex characters).
    #[arg(long)]
    spki_pin: Option<String>,
    /// Disable application mouse handling for terminals that do not support it.
    #[arg(long)]
    no_mouse: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("tui_chat=info")
        .with_writer(std::io::stderr)
        .init();
    let args = Args::parse();
    let data_dir = args.data_dir.unwrap_or_else(default_data_dir);
    let store = LocalStore::open(&data_dir.join("client.db")).await?;
    let local_secret_exists = store.has_vault().await? || store.has_profile().await?;
    let mut passphrase = read_local_passphrase(local_secret_exists)?;
    let vault = store.unlock(&passphrase).await?;
    let existing = store.load_profile(&vault).await?;
    let server_url = args
        .server
        .or_else(|| existing.as_ref().map(|p| p.server_url.clone()))
        .unwrap_or_else(|| "wss://localhost/v2/ws".to_owned());
    let server_url = protocol_v2_url(&server_url)?;
    let username = args
        .username
        .or_else(|| existing.as_ref().map(|p| p.username.clone()))
        .unwrap_or_else(|| prompt_line("Account username: ").unwrap_or_default());
    if username.is_empty() {
        bail!("username is required");
    }
    let spki_pin = args.spki_pin.or_else(|| {
        existing
            .as_ref()
            .and_then(|profile| profile.spki_pin.clone())
    });

    let (raw, profile, pending) =
        authenticate(&store, &vault, existing, &server_url, &username, spki_pin).await?;
    store.save_profile(&vault, &profile).await?;
    passphrase.zeroize();
    let (rpc, events) = raw.start();
    if pending {
        eprintln!(
            "This device is waiting for approval from an existing device. Keep the client open to receive pairing events."
        );
    }
    app::App::new(store, vault, profile, rpc, events, !args.no_mouse)
        .await?
        .run()
        .await
}

async fn authenticate(
    store: &LocalStore,
    vault: &VaultSession,
    existing: Option<RuntimeProfile>,
    server_url: &str,
    username: &str,
    spki_pin: Option<String>,
) -> Result<(RawConnection, RuntimeProfile, bool)> {
    let mut raw = RawConnection::connect(server_url, spki_pin.as_deref()).await?;
    let device_id = existing
        .as_ref()
        .map(|profile| profile.identity.device_id().to_owned())
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    let response = raw
        .request(Body::ClientHello(v1::ClientHello {
            username: username.to_owned(),
            device_id: device_id.clone(),
        }))
        .await?;
    let Some(Body::AuthChallenge(challenge)) = response.body else {
        bail!("server did not send an authentication challenge");
    };
    let domain = Url::parse(server_url)?
        .host_str()
        .ok_or_else(|| anyhow!("server URL has no host"))?
        .to_owned();

    if let Some(mut profile) = existing {
        let stored_server_url = protocol_v2_url(&profile.server_url)?;
        if profile.username != username || stored_server_url != server_url {
            bail!("local encrypted profile belongs to a different username or server");
        }
        profile.server_url = stored_server_url;
        if profile.spki_pin.is_some() && profile.spki_pin != spki_pin {
            bail!("SPKI pin differs from the encrypted local profile");
        }
        if profile.spki_pin.is_none() {
            profile.spki_pin = spki_pin;
        }
        if profile.pending {
            let mut password = Zeroizing::new(rpassword::prompt_password(
                "Account password (device approval pending): ",
            )?);
            let response = raw
                .request(Body::PasswordAuth(PasswordAuth {
                    username: username.to_owned(),
                    password: password.to_string(),
                    device_id: device_id.clone(),
                }))
                .await?;
            password.zeroize();
            let auth = authenticated(response)?;
            if !auth.pending_device || auth.account_id != profile.account_id {
                bail!("pending device state does not match the server");
            }
            return Ok((raw, profile, true));
        }
        let payload = auth_challenge_payload(
            &domain,
            username,
            &device_id,
            &challenge.nonce,
            challenge.expires_at_ms,
        );
        let response = raw
            .request(Body::DeviceAuth(DeviceAuth {
                username: username.to_owned(),
                device_id,
                signature: profile.identity.sign_auth_challenge(&payload),
            }))
            .await?;
        let authenticated = authenticated(response)?;
        if authenticated.account_id != profile.account_id {
            bail!("server account identity does not match the local profile");
        }
        if authenticated.account_master_key != profile.account_master_public {
            bail!("server account master key does not match the local profile");
        }
        if !authenticated.account_master_key.is_empty()
            && profile
                .identity
                .master_public_key()
                .as_ref()
                .is_some_and(|key| key.as_slice() != authenticated.account_master_key)
        {
            bail!("server presented a different account master key");
        }
        if authenticated.password_change_required {
            change_password(&mut raw).await?;
        }
        let missing = 50_usize.saturating_sub(profile.machine.stored_prekey_count());
        if missing > 0 {
            profile.machine.generate_prekeys(missing);
            let keys = profile
                .machine
                .unpublished_prekeys()
                .into_iter()
                .map(|(id, key)| profile.identity.sign_prekey(id, key))
                .collect();
            raw.request(Body::PublishPreKeys(v1::PublishPreKeys { keys }))
                .await?;
            profile.machine.mark_prekeys_published();
            store.save_profile(vault, &profile).await?;
        }
        return Ok((raw, profile, authenticated.pending_device));
    }

    let mut account_password = Zeroizing::new(rpassword::prompt_password("Account password: ")?);
    let response = raw
        .request(Body::PasswordAuth(PasswordAuth {
            username: username.to_owned(),
            password: account_password.to_string(),
            device_id: device_id.clone(),
        }))
        .await?;
    let pre_auth = authenticated(response)?;
    let first_device = pre_auth.account_master_key.is_empty();
    let device_name = hostname::get()
        .ok()
        .and_then(|name| name.into_string().ok())
        .unwrap_or_else(|| "terminal".to_owned());
    let identity = DeviceIdentity::new(&pre_auth.account_id, &device_id, device_name, first_device);
    let mut machine = OlmMachine::new();
    machine.generate_prekeys(50);
    let public = identity.public_device(machine.account())?;
    let one_time_keys = machine
        .unpublished_prekeys()
        .into_iter()
        .map(|(id, key)| identity.sign_prekey(id, key))
        .collect();
    let account_master_key = if first_device {
        identity
            .master_public_key()
            .context("first device did not create an account master key")?
            .to_vec()
    } else {
        if pre_auth.account_master_key.len() != 32 {
            bail!("server did not return the existing account master key");
        }
        pre_auth.account_master_key.clone()
    };
    let pairing = PairingState::new();
    let pairing_secret = (!first_device).then(|| pairing.secret_bytes());
    let response = raw
        .request(Body::BootstrapDevice(BootstrapDevice {
            device_id: device_id.clone(),
            device_name: public.device_name,
            account_master_key,
            auth_signing_key: public.auth_signing_key,
            olm_ed25519_key: public.olm_ed25519_key,
            olm_curve25519_key: public.olm_curve25519_key,
            certificate_signature: public.certificate_signature,
            one_time_keys,
            sas_public_key: pairing.public_key().to_vec(),
        }))
        .await?;
    let authenticated = authenticated(response)?;
    machine.mark_prekeys_published();
    let profile = RuntimeProfile {
        username: username.to_owned(),
        account_id: authenticated.account_id.clone(),
        server_url: server_url.to_owned(),
        identity,
        machine,
        pending: authenticated.pending_device,
        pairing_secret,
        account_master_public: authenticated.account_master_key.clone(),
        spki_pin,
    };
    store.save_profile(vault, &profile).await?;
    if authenticated.password_change_required {
        let new_password = read_new_password()?;
        raw.request(Body::ChangePassword(v1::ChangePassword {
            current_password: account_password.to_string(),
            new_password: new_password.to_string(),
        }))
        .await?;
    }
    account_password.zeroize();
    Ok((raw, profile, authenticated.pending_device))
}

fn authenticated(frame: v1::Frame) -> Result<v1::Authenticated> {
    match frame.body {
        Some(Body::Authenticated(auth)) => Ok(auth),
        _ => bail!("server returned an invalid authentication response"),
    }
}

async fn change_password(raw: &mut RawConnection) -> Result<()> {
    let mut current = Zeroizing::new(rpassword::prompt_password(
        "Account password (password change required): ",
    )?);
    let mut new = read_new_password()?;
    raw.request(Body::ChangePassword(v1::ChangePassword {
        current_password: current.to_string(),
        new_password: new.to_string(),
    }))
    .await?;
    current.zeroize();
    new.zeroize();
    Ok(())
}

fn read_new_password() -> Result<Zeroizing<String>> {
    let first = Zeroizing::new(rpassword::prompt_password(
        "New account password (12+ characters): ",
    )?);
    let characters = first.chars().count();
    if characters < 12 || first.len() > 1024 {
        bail!("new account password must contain 12-1024 characters");
    }
    let second = Zeroizing::new(rpassword::prompt_password("Repeat new account password: ")?);
    if *first != *second {
        bail!("passwords do not match");
    }
    Ok(first)
}

fn read_local_passphrase(existing: bool) -> Result<Zeroizing<String>> {
    let first = Zeroizing::new(rpassword::prompt_password(if existing {
        "Local storage passphrase: "
    } else {
        "Create local storage passphrase (12+ characters): "
    })?);
    let characters = first.chars().count();
    if characters > 1024 || (existing && characters == 0) {
        bail!("local storage passphrase must contain 1-1024 characters");
    }
    if !existing {
        if characters < 12 {
            bail!("local storage passphrase must contain at least 12 characters");
        }
        let second = Zeroizing::new(rpassword::prompt_password(
            "Repeat local storage passphrase: ",
        )?);
        if *first != *second {
            bail!("local storage passphrases do not match");
        }
    }
    Ok(first)
}

fn prompt_line(prompt: &str) -> Result<String> {
    use std::io::Write;
    print!("{prompt}");
    std::io::stdout().flush()?;
    let mut value = String::new();
    std::io::stdin().read_line(&mut value)?;
    Ok(value.trim().to_owned())
}

fn default_data_dir() -> PathBuf {
    ProjectDirs::from("org", "tui-chat", "tui-chat")
        .map(|dirs| dirs.data_local_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from(".tui-chat"))
}

fn protocol_v2_url(value: &str) -> Result<String> {
    let mut url = Url::parse(value)?;
    if url.path() == "/v1/ws" {
        url.set_path("/v2/ws");
    }
    Ok(url.to_string())
}

use anyhow::{Context, Result};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info};

use crate::minecraft::{AcceptedSession, accept_session};
use crate::protocol::{JoinedStream, UpgradedStream};
use crate::vless;

use super::config::ServerConfig;
use super::relay::relay_streams;

pub async fn run_server(config: ServerConfig) -> Result<()> {
    let listener = TcpListener::bind(&config.listen)
        .await
        .with_context(|| format!("binding tunnel listener {}", config.listen))?;

    info!(listen = %config.listen, "server listening for tunnel connections");

    loop {
        let (tunnel, peer) = listener
            .accept()
            .await
            .with_context(|| "accepting tunnel connection")?;

        let config = config.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_server_connection(tunnel, config).await {
                error!(?peer, "failed to handle server connection: {err:#}");
            }
        });
    }
}

pub async fn handle_server_connection(tunnel: TcpStream, config: ServerConfig) -> Result<()> {
    let (r, w) = tokio::io::split(tunnel);
    let mut stream = UpgradedStream {
        read: Box::pin(r),
        write: Box::pin(w),
    };

    if config.expect_preamble {
        let accepted = accept_session(
            stream,
            valence_protocol::MAX_PACKET_SIZE as usize,
            &config.profile,
        )
        .await
        .context("accepting Minecraft session")?;

        match accepted {
            AcceptedSession::Login(login) => {
                info!(
                    protocol_version = login.handshake.protocol_version,
                    server_address = %login.handshake.server_address,
                    server_port = login.handshake.server_port,
                    username = %login.identity.username,
                    uuid = %login.uuid,
                    "accepted Minecraft login"
                );
                stream = login.stream;
            }
            AcceptedSession::Status => {
                debug!("completed Minecraft status request");
                return Ok(());
            }
            AcceptedSession::Rejected(login) => {
                info!(
                    username = %login.identity.username,
                    uuid = %login.uuid,
                    "rejected Minecraft login"
                );
                return Ok(());
            }
        }
    }

    let joined = JoinedStream {
        read: stream.read,
        write: stream.write,
    };

    let mut tls_encrypted_stream = config.tls.accept(joined).await?;

    let request = vless::read_request(&mut tls_encrypted_stream, config.vless_id)
        .await
        .context("reading VLESS request over TLS")?;

    vless::write_response(&mut tls_encrypted_stream, request.version)
        .await
        .context("writing VLESS response")?;

    let target = TcpStream::connect(&request.target.to_string())
        .await
        .with_context(|| format!("connecting to target {}", request.target))?;

    info!(target = %request.target, "server VLESS+TLS tunnel established");

    relay_streams(target, tls_encrypted_stream).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::minecraft::ServerProfile;
    use crate::test_support::TlsFixture;
    use crate::tls::ServerTlsOptions;
    use std::time::Duration;

    #[tokio::test]
    async fn test_run_server_accepts_and_fails_gracefully() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let config = ServerConfig {
            listen: format!("127.0.0.1:{}", port),
            expect_preamble: false,
            profile: ServerProfile {
                motd: "test".to_string(),
                max_players: 10,
                online_players: 0,
                version_name: "1.20.1".to_string(),
                enforce_secure_chat: false,
                view_distance: 10,
                simulation_distance: 10,
                whitelist: crate::whitelist::Whitelist::default(),
                whitelist_message: "not whitelisted".to_string(),
                brand: "xminecraft".to_string(),
                entity_id: 1,
                spawn_y: 64,
                rsa_key: crate::test_support::test_rsa_key().clone(),
                send_play_packets: true,
            },
            vless_id: crate::vless::VlessId::parse("5783a3e7-e373-51cd-8642-c83782b807c5").unwrap(),
            tls: ServerTlsOptions::new(&TlsFixture::new().cert, &TlsFixture::new().key).unwrap(),
        };

        let task = tokio::spawn(run_server(config));

        // Wait for listener to bind
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Connect and drop to simulate tunnel connection
        let _ = TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;
        task.abort();
    }
}

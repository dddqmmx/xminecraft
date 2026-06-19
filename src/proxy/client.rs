use anyhow::{Context, Result};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info};

use crate::minecraft::drain_server_preamble;
use crate::protocol::{JoinedStream, UpgradedStream, write_client_preamble};
use crate::vless;

use super::config::ClientConfig;
use super::local::{ProxyProtocol, handle_local_handshake};
use super::relay::relay_streams;

pub async fn run_client(config: ClientConfig) -> Result<()> {
    let listener = TcpListener::bind(&config.listen)
        .await
        .with_context(|| format!("binding local proxy listener {}", config.listen))?;

    info!(listen = %config.listen, tunnel = %config.tunnel, "client listening for local connections");

    loop {
        let (raw, peer) = listener
            .accept()
            .await
            .with_context(|| "accepting local connection")?;

        let config = config.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_client_connection(raw, config).await {
                error!(?peer, "failed to handle client connection: {err:#}");
            }
        });
    }
}

pub async fn handle_client_connection(mut raw: TcpStream, config: ClientConfig) -> Result<()> {
    let (target, proxy_proto) = if let Some(t) = &config.target {
        (t.clone(), None)
    } else {
        let (t, proto) = handle_local_handshake(&mut raw)
            .await
            .context("handling local proxy handshake")?;
        (t, Some(proto))
    };
    let tunnel = TcpStream::connect(&config.tunnel)
        .await
        .with_context(|| format!("connecting to tunnel server {}", config.tunnel))?;

    let (r, w) = tokio::io::split(tunnel);
    let mut stream = UpgradedStream {
        read: Box::pin(r),
        write: Box::pin(w),
    };

    if let Some(preamble) = &config.preamble {
        stream = write_client_preamble(stream, preamble)
            .await
            .context("writing Minecraft preamble")?;

        drain_server_preamble(&mut stream.read, 1024 * 1024)
            .await
            .context("handling play-state keepalive")?;
    }

    let joined = JoinedStream {
        read: stream.read,
        write: stream.write,
    };

    let mut tls_encrypted_stream = config.tls.connect(joined).await?;

    vless::write_request(&mut tls_encrypted_stream, config.vless_id, &target)
        .await
        .context("sending VLESS request over TLS")?;

    vless::read_response(&mut tls_encrypted_stream)
        .await
        .context("reading VLESS response")?;

    info!(
        raw_peer = ?raw.peer_addr().ok(),
        tunnel = %config.tunnel,
        target = %target,
        "client VLESS+TLS tunnel established"
    );

    if let Some(proto) = proxy_proto {
        match proto {
            ProxyProtocol::Socks5 => {
                tokio::io::AsyncWriteExt::write_all(
                    &mut raw,
                    &[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0],
                )
                .await
                .context("writing socks5 success reply")?;
            }
            ProxyProtocol::Http => {
                tokio::io::AsyncWriteExt::write_all(
                    &mut raw,
                    b"HTTP/1.1 200 Connection Established\r\n\r\n",
                )
                .await
                .context("writing http connect success reply")?;
            }
        }
    }

    relay_streams(raw, tls_encrypted_stream).await
}

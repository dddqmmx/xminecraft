use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use serde_json::json;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::timeout;
use valence_protocol::Packet;
use valence_protocol::packets::status::{QueryPongS2c, QueryRequestC2s, QueryResponseS2c};

use crate::protocol::{read_packet, write_typed_packet};

use super::profile::ServerProfile;

const STATUS_PING_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) async fn handle_status<S>(
    stream: &mut S,
    max_packet_len: usize,
    profile: &ServerProfile,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = read_packet(stream, max_packet_len)
        .await?
        .ok_or_else(|| anyhow!("connection closed before Minecraft status request"))?;
    if request.packet_id != QueryRequestC2s::ID || !request.body.is_empty() {
        bail!(
            "expected empty status request packet id {}, got id {} with {} body bytes",
            QueryRequestC2s::ID,
            request.packet_id,
            request.body.len()
        );
    }

    let json = status_json(profile);
    write_typed_packet(stream, &QueryResponseS2c { json: &json }).await?;

    let ping = match timeout(STATUS_PING_TIMEOUT, read_packet(stream, max_packet_len)).await {
        Ok(Ok(Some(packet))) => packet,
        Ok(Ok(None)) | Err(_) => return Ok(()),
        Ok(Err(err)) => return Err(err).context("reading status ping"),
    };

    if ping.packet_id != QueryPongS2c::ID {
        bail!(
            "expected status ping packet id {}, got {}",
            QueryPongS2c::ID,
            ping.packet_id
        );
    }

    write_typed_packet(
        stream,
        &QueryPongS2c {
            payload: decode_u64_payload(&ping.body)?,
        },
    )
    .await?;

    Ok(())
}

fn status_json(profile: &ServerProfile) -> String {
    json!({
        "version": {
            "name": profile.version_name,
            "protocol": valence_protocol::PROTOCOL_VERSION,
        },
        "players": {
            "max": profile.max_players,
            "online": profile.online_players,
        },
        "description": {
            "text": profile.motd,
        },
        "enforcesSecureChat": profile.enforce_secure_chat,
    })
    .to_string()
}

fn decode_u64_payload(body: &[u8]) -> Result<u64> {
    if body.len() != 8 {
        bail!("status ping payload must be 8 bytes, got {}", body.len());
    }

    Ok(u64::from_be_bytes(
        body.try_into()
            .expect("status ping body length was checked above"),
    ))
}

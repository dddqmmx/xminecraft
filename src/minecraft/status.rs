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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::write_packet;
    use crate::test_support::test_rsa_key;
    use crate::whitelist::Whitelist;
    use valence_protocol::packets::status::{QueryPongS2c, QueryRequestC2s};

    fn test_profile() -> ServerProfile {
        ServerProfile {
            motd: "test".into(),
            max_players: 10,
            online_players: 0,
            version_name: "1.20".into(),
            enforce_secure_chat: false,
            view_distance: 10,
            simulation_distance: 10,
            whitelist: Whitelist::default(),
            whitelist_message: "no".into(),
            brand: "test".into(),
            entity_id: 1,
            spawn_y: 0,
            rsa_key: test_rsa_key().clone(),
            send_play_packets: false,
        }
    }

    #[tokio::test]
    async fn test_handle_status() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        write_packet(&mut client, QueryRequestC2s::ID, &[])
            .await
            .unwrap();
        assert!(
            handle_status(&mut server, 1024, &test_profile())
                .await
                .is_ok()
        );

        let (mut client, mut server) = tokio::io::duplex(1024);
        write_packet(&mut client, QueryRequestC2s::ID, &[])
            .await
            .unwrap();
        assert!(
            handle_status(&mut server, 1024, &test_profile())
                .await
                .is_ok()
        );

        let (mut client, mut server) = tokio::io::duplex(1024);
        write_packet(&mut client, 0x99, &[0; 8]).await.unwrap();
        assert!(
            handle_status(&mut server, 1024, &test_profile())
                .await
                .is_err()
        );

        let (mut client, mut server) = tokio::io::duplex(1024);
        write_packet(&mut client, QueryRequestC2s::ID, &[])
            .await
            .unwrap();
        assert!(
            handle_status(&mut server, 1024, &test_profile())
                .await
                .is_ok()
        );

        let (mut client, mut server) = tokio::io::duplex(1024);
        write_packet(&mut client, QueryPongS2c::ID, &[1, 2, 3, 4])
            .await
            .unwrap();
        assert!(
            handle_status(&mut server, 1024, &test_profile())
                .await
                .is_err()
        );
    }
}

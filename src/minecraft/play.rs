use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::time::sleep;
use tracing::trace;
use valence_protocol::packets::play::KeepAliveC2s;
use valence_protocol::{Decode, Packet};

use crate::protocol::{read_packet, write_typed_packet};

static KEEPALIVE_ID: AtomicI64 = AtomicI64::new(1);

pub async fn handle_play_probes<R, W>(
    reader: &mut R,
    _writer: &mut W,
    max_packet_len: usize,
    keepalive_tx: tokio::sync::mpsc::UnboundedSender<u64>,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    loop {
        let packet = tokio::select! {
            result = read_packet(reader, max_packet_len) => {
                match result {
                    Ok(Some(pkt)) => pkt,
                    Ok(None) => return Ok(()),
                    Err(e) => return Err(e),
                }
            }
            _ = sleep(Duration::from_secs(30)) => {
                trace!("play probe reader timed out");
                return Ok(());
            }
        };

        if packet.packet_id == KeepAliveC2s::ID {
            let mut body = packet.body.as_slice();
            if let Ok(ping) = KeepAliveC2s::decode(&mut body) {
                trace!(id = ping.id, "received play keepalive");
                let _ = keepalive_tx.send(ping.id);
            }
        } else {
            trace!(
                packet_id = packet.packet_id,
                "play reader saw non-keepalive packet"
            );
            return Ok(());
        }
    }
}

pub async fn drain_server_preamble<R>(reader: &mut R, max_packet_len: usize) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    use valence_protocol::packets::play::KeepAliveS2c;

    let deadline = tokio::time::Instant::now() + Duration::from_millis(100);

    for _ in 0..30u32 {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Ok(());
        }

        let packet = tokio::select! {
            result = read_packet(reader, max_packet_len) => {
                match result {
                    Ok(Some(pkt)) => pkt,
                    Ok(None) => return Ok(()),
                    Err(e) => return Err(e),
                }
            }
            _ = sleep(remaining) => {
                return Ok(());
            }
        };

        if packet.packet_id == KeepAliveS2c::ID {
            let mut body = packet.body.as_slice();
            if KeepAliveS2c::decode(&mut body).is_ok() {
                return Ok(());
            }
        }
    }

    Ok(())
}

pub async fn send_keepalive<W>(writer: &mut W) -> Result<u64>
where
    W: AsyncWrite + Unpin,
{
    use valence_protocol::packets::play::KeepAliveS2c;

    let id = KEEPALIVE_ID.fetch_add(1, Ordering::Relaxed) as u64;
    write_typed_packet(writer, &KeepAliveS2c { id }).await?;
    writer.flush().await?;
    Ok(id)
}

pub async fn accept_keepalive_reply(
    reader: &mut (impl AsyncRead + Unpin),
    expected_id: u64,
    max_packet_len: usize,
) -> Result<()> {
    use anyhow::bail;

    let Some(packet) = read_packet(reader, max_packet_len).await? else {
        bail!("connection closed while waiting for keepalive reply");
    };

    if packet.packet_id != KeepAliveC2s::ID {
        bail!(
            "expected keepalive reply packet id {}, got {}",
            KeepAliveC2s::ID,
            packet.packet_id
        );
    }

    let mut body = packet.body.as_slice();
    let reply = KeepAliveC2s::decode(&mut body).context("decoding keepalive reply")?;

    if reply.id != expected_id {
        bail!(
            "keepalive id mismatch: expected {expected_id}, got {}",
            reply.id
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::write_packet;
    use tokio::sync::mpsc;
    use valence_protocol::{
        Encode,
        packets::play::{KeepAliveC2s, KeepAliveS2c},
    };

    async fn write_typed<W: AsyncWrite + Unpin, P: Encode + valence_protocol::Packet>(
        w: &mut W,
        p: P,
    ) {
        let mut body = vec![];
        p.encode(&mut body).unwrap();
        write_packet(w, P::ID, &body).await.unwrap();
    }

    #[tokio::test]
    async fn test_handle_play_probes_valid_keepalive() {
        let (mut client, server) = tokio::io::duplex(1024);
        let (mut server_read, mut server_write) = tokio::io::split(server);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            handle_play_probes(&mut server_read, &mut server_write, 2097151, tx).await
        });
        write_typed(&mut client, KeepAliveC2s { id: 12345 }).await;
        client.write_all(&[0x02, 0x00, 0x00]).await.unwrap();
        assert_eq!(rx.recv().await.unwrap(), 12345);
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn test_handle_play_probes_timeout() {
        let (client, server) = tokio::io::duplex(1024);
        let (mut server_read, mut server_write) = tokio::io::split(server);
        let (tx, _rx) = mpsc::unbounded_channel();
        drop(client);
        assert!(
            handle_play_probes(&mut server_read, &mut server_write, 2097151, tx)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_drain_server_preamble() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let task = tokio::spawn(async move { drain_server_preamble(&mut server, 2097151).await });
        write_typed(&mut client, KeepAliveS2c { id: 777 }).await;
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn test_send_keepalive() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let _id = send_keepalive(&mut server).await.unwrap();
        let pkt = crate::protocol::read_packet(&mut client, 2097151)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pkt.packet_id, KeepAliveS2c::ID);
    }

    #[tokio::test]
    async fn test_accept_keepalive_reply() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        write_typed(&mut client, KeepAliveC2s { id: 42 }).await;
        accept_keepalive_reply(&mut server, 42, 2097151)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_accept_keepalive_reply_wrong() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        write_typed(&mut client, KeepAliveC2s { id: 99 }).await;
        assert!(
            accept_keepalive_reply(&mut server, 42, 2097151)
                .await
                .is_err()
        );
        let (mut client, mut server) = tokio::io::duplex(1024);
        client.write_all(&[0x02, 0x00, 0x00]).await.unwrap();
        assert!(
            accept_keepalive_reply(&mut server, 42, 2097151)
                .await
                .is_err()
        );
        let (client, mut server) = tokio::io::duplex(1024);
        drop(client);
        assert!(
            accept_keepalive_reply(&mut server, 42, 2097151)
                .await
                .is_err()
        );
    }
}

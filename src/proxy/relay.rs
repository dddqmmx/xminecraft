use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, copy_bidirectional};

pub async fn relay_streams<A, B>(mut left: A, mut right: B) -> Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    // Use copy_bidirectional which is optimized and handles full-duplex shutdown.
    copy_bidirectional(&mut left, &mut right)
        .await
        .context("relaying TCP streams")?;

    // Explicitly shutdown both sides to ensure any buffered data (like TLS close_notify) is pushed.
    let _ = tokio::join!(left.shutdown(), right.shutdown());

    Ok(())
}

pub async fn relay_halves<R1, W1, R2, W2>(
    left_read: &mut R1,
    left_write: &mut W1,
    right_read: &mut R2,
    right_write: &mut W2,
) -> Result<()>
where
    R1: AsyncRead + Unpin,
    W1: AsyncWrite + Unpin,
    R2: AsyncRead + Unpin,
    W2: AsyncWrite + Unpin,
{
    tokio::select! {
        res1 = tokio::io::copy(left_read, right_write) => {
            res1.context("copying left to right")?;
            let _ = right_write.shutdown().await;
        }
        res2 = tokio::io::copy(right_read, left_write) => {
            res2.context("copying right to left")?;
            let _ = left_write.shutdown().await;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
    use tokio::time::timeout;

    #[tokio::test]
    async fn test_relay_halves_shutdown() {
        let (mut client, server) = duplex(1024);
        let (mut target_client, target_server) = duplex(1024);

        let (mut server_read, mut server_write) = tokio::io::split(server);
        let (mut target_read, mut target_write) = tokio::io::split(target_server);

        let relay_task = tokio::spawn(async move {
            relay_halves(
                &mut server_read,
                &mut server_write,
                &mut target_read,
                &mut target_write,
            )
            .await
        });

        // Client writes, target reads
        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        target_client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");

        // Target writes, client reads
        target_client.write_all(b"pong").await.unwrap();
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");

        // Client closes the write side (EOF sent to server_read)
        drop(client);

        // The relay task should return immediately without hanging
        timeout(Duration::from_secs(1), relay_task)
            .await
            .expect("relay_halves hung!")
            .unwrap()
            .unwrap();
    }
}

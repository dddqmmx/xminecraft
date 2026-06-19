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

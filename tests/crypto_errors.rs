use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt, ReadBuf};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::io::Error;
use xminecraft::crypto::{Aes128Cfb8Reader, Aes128Cfb8Writer};

pub struct MockStream {
    pub read_data: Vec<u8>,
    pub write_data: Vec<u8>,
    pub read_chunk_size: usize,
    pub write_chunk_size: usize,
    pub read_error: bool,
    pub write_error: bool,
    pub write_zero: bool,
}

impl AsyncRead for MockStream {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.read_error {
            Poll::Ready(Err(Error::other("mock read error")))
        } else {
            Poll::Ready(Ok(()))
        }
    }
}

impl AsyncWrite for MockStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.write_error {
            Poll::Ready(Err(Error::other("mock write error")))
        } else if self.write_zero {
            Poll::Ready(Ok(0))
        } else {
            let amt = std::cmp::min(buf.len(), self.write_chunk_size);
            self.write_data.extend_from_slice(&buf[..amt]);
            Poll::Ready(Ok(amt))
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn test_crypto_read_error() {
    let mock = MockStream {
        read_data: vec![],
        write_data: vec![],
        read_chunk_size: 10,
        write_chunk_size: 10,
        read_error: true,
        write_error: false,
        write_zero: false,
    };
    let key = [0; 16];
    let mut reader = Aes128Cfb8Reader::new(mock, &key);
    let mut buf = [0; 10];
    let res = reader.read(&mut buf).await;
    assert!(res.is_err());
}

#[tokio::test]
async fn test_crypto_write_error() {
    let mock = MockStream {
        read_data: vec![],
        write_data: vec![],
        read_chunk_size: 10,
        write_chunk_size: 10,
        read_error: false,
        write_error: true,
        write_zero: false,
    };
    let key = [0; 16];
    let mut writer = Aes128Cfb8Writer::new(mock, &key);
    let res = writer.write(&[1, 2, 3]).await;
    assert!(res.is_err());
}

#[tokio::test]
async fn test_crypto_partial_write_and_flush() {
    let mock = MockStream {
        read_data: vec![],
        write_data: vec![],
        read_chunk_size: 10,
        write_chunk_size: 2, // Force partial writes
        read_error: false,
        write_error: false,
        write_zero: false,
    };
    let key = [0; 16];
    let mut writer = Aes128Cfb8Writer::new(mock, &key);
    writer.write_all(&[1, 2, 3, 4, 5]).await.unwrap();
    writer.flush().await.unwrap();
}

use std::pin::Pin;
use std::task::{Context, Poll};

use aes::Aes128;
use cfb8::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, generic_array::GenericArray};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

type Encryptor = cfb8::Encryptor<Aes128>;
type Decryptor = cfb8::Decryptor<Aes128>;

pub struct Aes128Cfb8Reader<R> {
    inner: R,
    decryptor: Decryptor,
}

pub struct Aes128Cfb8Writer<W> {
    inner: W,
    encryptor: Encryptor,
    pending: Vec<u8>,
}

impl<R: AsyncRead + Unpin> Aes128Cfb8Reader<R> {
    pub fn new(inner: R, key: &[u8; 16]) -> Self {
        Self {
            inner,
            decryptor: Decryptor::new_from_slices(key, key).expect("invalid key"),
        }
    }
}

impl<W: AsyncWrite + Unpin> Aes128Cfb8Writer<W> {
    pub fn new(inner: W, key: &[u8; 16]) -> Self {
        Self {
            inner,
            encryptor: Encryptor::new_from_slices(key, key).expect("invalid key"),
            pending: Vec::new(),
        }
    }

    fn flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        while !self.pending.is_empty() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.pending) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into()));
                }
                Poll::Ready(Ok(n)) => {
                    self.pending.drain(..n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for Aes128Cfb8Reader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let start_len = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let filled = buf.filled_mut();
                let data = &mut filled[start_len..];
                if !data.is_empty() {
                    for chunk in data.chunks_mut(1) {
                        let gen_arr = GenericArray::from_mut_slice(chunk);
                        this.decryptor.decrypt_block_mut(gen_arr);
                    }
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for Aes128Cfb8Writer<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();

        if this.flush_pending(cx)?.is_pending() {
            return Poll::Pending;
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let n = buf.len();
        let mut encrypted = buf.to_vec();
        for chunk in encrypted.chunks_mut(1) {
            let gen_arr = GenericArray::from_mut_slice(chunk);
            this.encryptor.encrypt_block_mut(gen_arr);
        }

        match Pin::new(&mut this.inner).poll_write(cx, &encrypted) {
            Poll::Ready(Ok(written)) => {
                if written < encrypted.len() {
                    this.pending.extend_from_slice(&encrypted[written..]);
                }
                Poll::Ready(Ok(n))
            }
            Poll::Pending => {
                this.pending.extend_from_slice(&encrypted);
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.flush_pending(cx)?.is_pending() {
            return Poll::Pending;
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.flush_pending(cx)?.is_pending() {
            return Poll::Pending;
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

pub struct Aes128Cfb8Stream<S> {
    inner: S,
    key: [u8; 16],
}

impl<S> Aes128Cfb8Stream<S> {
    pub fn new(inner: S, key: &[u8; 16]) -> Self {
        Self { inner, key: *key }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> Aes128Cfb8Stream<S> {
    pub fn split(
        self,
    ) -> (
        Aes128Cfb8Reader<tokio::io::ReadHalf<S>>,
        Aes128Cfb8Writer<tokio::io::WriteHalf<S>>,
    ) {
        let (r, w) = tokio::io::split(self.inner);
        (
            Aes128Cfb8Reader::new(r, &self.key),
            Aes128Cfb8Writer::new(w, &self.key),
        )
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for Aes128Cfb8Stream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        panic!("Aes128Cfb8Stream must be split before use to avoid deadlocks")
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Aes128Cfb8Stream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        panic!("Aes128Cfb8Stream must be split before use to avoid deadlocks")
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        panic!("Aes128Cfb8Stream must be split before use to avoid deadlocks")
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        panic!("Aes128Cfb8Stream must be split before use to avoid deadlocks")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    #[tokio::test]
    async fn check_block_size() {
        use cfb8::cipher::BlockSizeUser;
        println!("Encryptor block size: {}", Encryptor::block_size());
        println!("Decryptor block size: {}", Decryptor::block_size());
    }

    #[tokio::test]
    async fn aes_stream_round_trips() {
        let key = [0x42; 16];
        let (s1, s2) = duplex(1024);

        let (_, mut w1) = Aes128Cfb8Stream::new(s1, &key).split();
        let (mut r2, _) = Aes128Cfb8Stream::new(s2, &key).split();

        let msg = b"hello encryption world";
        w1.write_all(msg).await.unwrap();
        w1.flush().await.unwrap();

        let mut buf = vec![0; msg.len()];
        r2.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, msg);
    }
}

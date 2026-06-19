use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{
    ClientConfig as RustlsClientConfig, RootCertStore, ServerConfig as RustlsServerConfig,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::server::TlsStream as ServerTlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

#[derive(Clone)]
pub struct ClientTlsOptions {
    pub connector: TlsConnector,
    pub server_name: String,
}

impl std::fmt::Debug for ClientTlsOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientTlsOptions")
            .field("server_name", &self.server_name)
            .finish()
    }
}

#[derive(Clone)]
pub struct ServerTlsOptions {
    pub acceptor: TlsAcceptor,
}

impl std::fmt::Debug for ServerTlsOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerTlsOptions").finish()
    }
}

impl ClientTlsOptions {
    pub fn new(ca_cert: &Path, server_name: String) -> Result<Self> {
        let mut roots = RootCertStore::empty();
        for cert in load_certs(ca_cert)? {
            roots
                .add(cert)
                .map_err(|err| anyhow!("adding CA certificate failed: {err}"))?;
        }

        let config = RustlsClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        Ok(Self {
            connector: TlsConnector::from(Arc::new(config)),
            server_name,
        })
    }

    pub async fn connect<S>(&self, stream: S) -> Result<ClientTlsStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let server_name = ServerName::try_from(self.server_name.clone())
            .with_context(|| format!("invalid TLS server name {}", self.server_name))?;

        self.connector
            .connect(server_name, stream)
            .await
            .context("performing client TLS handshake")
    }
}

impl ServerTlsOptions {
    pub fn new(cert: &Path, key: &Path) -> Result<Self> {
        let certs = load_certs(cert)?;
        if certs.is_empty() {
            bail!("TLS certificate file contains no certificates");
        }

        let key_der = load_private_key(key)?;
        let config = RustlsServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key_der)
            .context("building TLS server config")?;

        Ok(Self {
            acceptor: TlsAcceptor::from(Arc::new(config)),
        })
    }

    pub async fn accept<S>(&self, stream: S) -> Result<ServerTlsStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        self.acceptor
            .accept(stream)
            .await
            .context("performing server TLS handshake")
    }
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file =
        File::open(path).with_context(|| format!("opening certificate file {}", path.display()))?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("reading certificates from {}", path.display()))
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let file =
        File::open(path).with_context(|| format!("opening private key file {}", path.display()))?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .with_context(|| format!("reading private key from {}", path.display()))?
        .ok_or_else(|| anyhow!("private key file {} contains no key", path.display()))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;
    use crate::test_support::TlsFixture;

    #[tokio::test]
    async fn tls_handshake_transfers_bytes() {
        let fixture = TlsFixture::new();
        let server_options = ServerTlsOptions::new(&fixture.cert, &fixture.key).unwrap();
        let client_options = ClientTlsOptions::new(&fixture.cert, "localhost".to_owned()).unwrap();
        let (client_io, server_io) = duplex(4096);

        let server_task = tokio::spawn(async move {
            let mut stream = server_options.accept(server_io).await.unwrap();
            let mut request = [0; 4];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"ping");
            stream.write_all(b"pong").await.unwrap();
            stream.shutdown().await.unwrap();
        });

        let mut stream = client_options.connect(client_io).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0; 4];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");

        tokio::time::timeout(Duration::from_secs(1), server_task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn tls_rejects_wrong_server_name() {
        let fixture = TlsFixture::new();
        let server_options = ServerTlsOptions::new(&fixture.cert, &fixture.key).unwrap();
        let client_options =
            ClientTlsOptions::new(&fixture.cert, "not-localhost".to_owned()).unwrap();
        let (client_io, server_io) = duplex(4096);

        let server_task = tokio::spawn(async move { server_options.accept(server_io).await });

        assert!(client_options.connect(client_io).await.is_err());

        let _ = tokio::time::timeout(Duration::from_secs(1), server_task).await;
    }
}

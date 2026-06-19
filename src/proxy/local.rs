use anyhow::{Result, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::vless::{VlessAddress, VlessTarget};

#[derive(Debug)]
pub enum ProxyProtocol {
    Socks5,
    Http,
}

pub async fn handle_local_handshake(
    stream: &mut TcpStream,
) -> Result<(VlessTarget, ProxyProtocol)> {
    let mut buf = [0u8; 1];
    let n = stream.peek(&mut buf).await?;
    if n == 0 {
        bail!("connection closed before proxy handshake");
    }

    if buf[0] == 0x05 {
        let target = handle_socks5(stream).await?;
        Ok((target, ProxyProtocol::Socks5))
    } else if buf[0] == b'C' {
        let target = handle_http_connect(stream).await?;
        Ok((target, ProxyProtocol::Http))
    } else {
        bail!(
            "unsupported local proxy protocol (not socks5 or http connect), first byte: {:#04x}",
            buf[0]
        );
    }
}

async fn handle_socks5(stream: &mut TcpStream) -> Result<VlessTarget> {
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;
    if buf[0] != 0x05 {
        bail!("not socks5 protocol");
    }

    let nmethods = buf[1] as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;

    if !methods.contains(&0x00) {
        stream.write_all(&[0x05, 0xFF]).await?; // no acceptable methods
        bail!("no acceptable socks5 auth method found (requires NO_AUTH)");
    }

    // Accept NO_AUTH
    stream.write_all(&[0x05, 0x00]).await?;

    // Read request
    let mut req = [0u8; 4];
    stream.read_exact(&mut req).await?;
    if req[0] != 0x05 || req[1] != 0x01 {
        // We only support CONNECT (0x01)
        // Reply with command not supported
        stream
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        bail!("unsupported socks5 command (only CONNECT is supported)");
    }

    let atyp = req[3];
    let target = match atyp {
        0x01 => {
            // IPv4
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            let port = u16::from_be_bytes(port);
            VlessTarget {
                address: VlessAddress::Ip(std::net::IpAddr::V4(std::net::Ipv4Addr::from(ip))),
                port,
            }
        }
        0x03 => {
            // Domain
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            stream.read_exact(&mut domain).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            let port = u16::from_be_bytes(port);
            let domain_str = String::from_utf8(domain)?;
            VlessTarget {
                address: VlessAddress::Domain(domain_str),
                port,
            }
        }
        0x04 => {
            // IPv6
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            let port = u16::from_be_bytes(port);
            VlessTarget {
                address: VlessAddress::Ip(std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip))),
                port,
            }
        }
        _ => {
            // Address type not supported
            stream
                .write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            bail!("unsupported socks5 address type {atyp}");
        }
    };

    Ok(target)
}

async fn handle_http_connect(stream: &mut TcpStream) -> Result<VlessTarget> {
    let mut header = Vec::new();
    let mut buf = [0u8; 1];
    loop {
        stream.read_exact(&mut buf).await?;
        header.push(buf[0]);
        if header.ends_with(b"\r\n\r\n") {
            break;
        }
        if header.len() > 8192 {
            bail!("http connect header too large");
        }
    }

    let header_str = String::from_utf8_lossy(&header);
    let first_line = header_str.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();

    if parts.len() < 2 || parts[0] != "CONNECT" {
        bail!("invalid HTTP CONNECT request: {}", first_line);
    }

    let target = parts[1];
    VlessTarget::parse(target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    async fn setup_connection() -> (
        TcpStream,
        tokio::task::JoinHandle<Result<(VlessTarget, ProxyProtocol)>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            handle_local_handshake(&mut stream).await
        });

        let client_stream = TcpStream::connect(addr).await.unwrap();
        (client_stream, server_task)
    }

    #[tokio::test]
    async fn test_socks5_ipv4() {
        let (mut client, server_task) = setup_connection().await;

        // SOCKS5 Greeting
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [0x05, 0x00]);

        // SOCKS5 Connect IPv4 192.168.1.1:80
        client
            .write_all(&[0x05, 0x01, 0x00, 0x01, 192, 168, 1, 1, 0, 80])
            .await
            .unwrap();

        let result = server_task.await.unwrap().unwrap();
        assert!(matches!(result.1, ProxyProtocol::Socks5));
        assert_eq!(
            result.0.address,
            VlessAddress::Ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
        );
        assert_eq!(result.0.port, 80);
    }

    #[tokio::test]
    async fn test_socks5_domain() {
        let (mut client, server_task) = setup_connection().await;

        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await.unwrap();

        // Connect domain google.com:443
        let domain = b"google.com";
        let mut req = vec![0x05, 0x01, 0x00, 0x03, domain.len() as u8];
        req.extend_from_slice(domain);
        req.extend_from_slice(&[0x01, 0xBB]); // 443
        client.write_all(&req).await.unwrap();

        let result = server_task.await.unwrap().unwrap();
        assert!(matches!(result.1, ProxyProtocol::Socks5));
        assert_eq!(
            result.0.address,
            VlessAddress::Domain("google.com".to_string())
        );
        assert_eq!(result.0.port, 443);
    }

    #[tokio::test]
    async fn test_http_connect() {
        let (mut client, server_task) = setup_connection().await;

        let req = b"CONNECT target.com:8443 HTTP/1.1\r\nHost: target.com:8443\r\n\r\n";
        client.write_all(req).await.unwrap();

        let result = server_task.await.unwrap().unwrap();
        assert!(matches!(result.1, ProxyProtocol::Http));
        assert_eq!(
            result.0.address,
            VlessAddress::Domain("target.com".to_string())
        );
        assert_eq!(result.0.port, 8443);
    }

    #[tokio::test]
    async fn test_http_connect_rejects_huge_header() {
        let (mut client, server_task) = setup_connection().await;

        let req = b"CONNECT target.com:8443 HTTP/1.1\r\n";
        client.write_all(req).await.unwrap();

        // Write 9000 bytes of 'X'
        let huge = vec![b'X'; 9000];
        client.write_all(&huge).await.unwrap();

        let err = server_task.await.unwrap().unwrap_err();
        assert!(err.to_string().contains("http connect header too large"));
    }

    #[tokio::test]
    async fn test_http_connect_rejects_invalid_method() {
        let (mut client, server_task) = setup_connection().await;

        let req = b"CONNECTX / HTTP/1.1\r\nHost: target.com\r\n\r\n";
        client.write_all(req).await.unwrap();

        let err = server_task.await.unwrap().unwrap_err();
        assert!(err.to_string().contains("invalid HTTP CONNECT request"));
    }
}

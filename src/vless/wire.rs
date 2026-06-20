use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::types::{VlessAddress, VlessId, VlessRequest, VlessTarget};

pub const VERSION: u8 = 0;

const COMMAND_TCP: u8 = 0x01;
const ADDRESS_IPV4: u8 = 0x01;
const ADDRESS_DOMAIN: u8 = 0x02;
const ADDRESS_IPV6: u8 = 0x03;

pub async fn write_request<W>(writer: &mut W, id: VlessId, target: &VlessTarget) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut header = Vec::with_capacity(64);
    header.push(VERSION);
    header.extend_from_slice(&id.as_bytes());
    header.push(0); // addons length
    header.push(COMMAND_TCP);
    header.extend_from_slice(&target.port.to_be_bytes());
    encode_address(&mut header, &target.address)?;

    writer
        .write_all(&header)
        .await
        .context("writing VLESS request header")?;
    writer.flush().await.context("flushing VLESS request")?;
    Ok(())
}

pub async fn read_request<R>(reader: &mut R, expected_id: VlessId) -> Result<VlessRequest>
where
    R: AsyncRead + Unpin,
{
    let version = read_u8(reader).await.context("reading VLESS version")?;
    if version != VERSION {
        bail!("unsupported VLESS version {version}; expected {VERSION}");
    }

    let mut id = [0; 16];
    reader
        .read_exact(&mut id)
        .await
        .context("reading VLESS UUID")?;
    if VlessId::from_bytes(id) != expected_id {
        bail!("VLESS UUID authentication failed");
    }

    let addons_len = read_u8(reader)
        .await
        .context("reading VLESS addons length")? as usize;
    discard_exact(reader, addons_len)
        .await
        .context("reading VLESS addons")?;

    let command = read_u8(reader).await.context("reading VLESS command")?;
    if command != COMMAND_TCP {
        bail!("unsupported VLESS command {command}; only TCP is implemented");
    }

    let mut port = [0; 2];
    reader
        .read_exact(&mut port)
        .await
        .context("reading VLESS target port")?;
    let port = u16::from_be_bytes(port);
    if port == 0 {
        bail!("VLESS target port must be greater than zero");
    }

    let address = read_address(reader)
        .await
        .context("reading VLESS target address")?;

    Ok(VlessRequest {
        version,
        target: VlessTarget { address, port },
    })
}

pub async fn write_response<W>(writer: &mut W, version: u8) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer
        .write_all(&[version, 0])
        .await
        .context("writing VLESS response header")?;
    writer.flush().await.context("flushing VLESS response")?;
    Ok(())
}

pub async fn read_response<R>(reader: &mut R) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let version = read_u8(reader)
        .await
        .context("reading VLESS response version")?;
    if version != VERSION {
        bail!("unexpected VLESS response version {version}; expected {VERSION}");
    }

    let addons_len = read_u8(reader)
        .await
        .context("reading VLESS response addons length")? as usize;
    discard_exact(reader, addons_len)
        .await
        .context("reading VLESS response addons")?;
    Ok(())
}

fn encode_address(out: &mut Vec<u8>, address: &VlessAddress) -> Result<()> {
    match address {
        VlessAddress::Ip(IpAddr::V4(ip)) => {
            out.push(ADDRESS_IPV4);
            out.extend_from_slice(&ip.octets());
        }
        VlessAddress::Ip(IpAddr::V6(ip)) => {
            out.push(ADDRESS_IPV6);
            out.extend_from_slice(&ip.octets());
        }
        VlessAddress::Domain(domain) => {
            let len = u8::try_from(domain.len()).context("VLESS domain is too long")?;
            out.push(ADDRESS_DOMAIN);
            out.push(len);
            out.extend_from_slice(domain.as_bytes());
        }
    }
    Ok(())
}

async fn read_address<R>(reader: &mut R) -> Result<VlessAddress>
where
    R: AsyncRead + Unpin,
{
    let address_type = read_u8(reader).await?;
    match address_type {
        ADDRESS_IPV4 => {
            let mut octets = [0; 4];
            reader.read_exact(&mut octets).await?;
            Ok(VlessAddress::Ip(IpAddr::V4(Ipv4Addr::from(octets))))
        }
        ADDRESS_IPV6 => {
            let mut octets = [0; 16];
            reader.read_exact(&mut octets).await?;
            Ok(VlessAddress::Ip(IpAddr::V6(Ipv6Addr::from(octets))))
        }
        ADDRESS_DOMAIN => {
            let len = read_u8(reader).await? as usize;
            if len == 0 {
                bail!("VLESS domain address must not be empty");
            }
            let mut domain = vec![0; len];
            reader.read_exact(&mut domain).await?;
            let domain = String::from_utf8(domain).context("VLESS domain is not UTF-8")?;
            if !domain.is_ascii() {
                bail!("VLESS domain must be ASCII; use punycode for IDN names");
            }
            Ok(VlessAddress::Domain(domain))
        }
        other => bail!("unsupported VLESS address type {other}"),
    }
}

async fn read_u8<R>(reader: &mut R) -> Result<u8>
where
    R: AsyncRead + Unpin,
{
    let mut byte = [0];
    reader.read_exact(&mut byte).await?;
    Ok(byte[0])
}

async fn discard_exact<R>(reader: &mut R, len: usize) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    if len == 0 {
        return Ok(());
    }

    let mut buf = vec![0; len];
    reader.read_exact(&mut buf).await?;
    Ok(())
}

#[cfg(test)]
mod tests_additional {
    use super::*;
    use crate::vless::types::{VlessAddress, VlessId};
    use std::io::Cursor;

    #[tokio::test]
    async fn test_wire_errors() {
        let id = VlessId::parse("5783a3e7-e373-51cd-8642-c83782b807c5").unwrap();
        let mut cursor = Cursor::new(vec![ADDRESS_DOMAIN, 0]);
        assert!(
            read_address(&mut cursor)
                .await
                .unwrap_err()
                .to_string()
                .contains("must not be empty")
        );
        let mut out = vec![];
        assert!(encode_address(&mut out, &VlessAddress::Domain("a".repeat(256))).is_err());
        let mut cursor = Cursor::new(vec![ADDRESS_DOMAIN, 3, 230, 136, 145]);
        assert!(
            read_address(&mut cursor)
                .await
                .unwrap_err()
                .to_string()
                .contains("ASCII")
        );
        let mut cursor = Cursor::new(vec![99]);
        assert!(
            read_address(&mut cursor)
                .await
                .unwrap_err()
                .to_string()
                .contains("unsupported VLESS address type")
        );
        let mut req = vec![VERSION];
        req.extend_from_slice(&id.as_bytes());
        req.extend_from_slice(&[0, COMMAND_TCP, 0, 0, ADDRESS_IPV4, 127, 0, 0, 1]);
        assert!(
            read_request(&mut Cursor::new(req), id)
                .await
                .unwrap_err()
                .to_string()
                .contains("greater than zero")
        );
        let res = vec![1, 0];
        assert!(
            read_response(&mut Cursor::new(res))
                .await
                .unwrap_err()
                .to_string()
                .contains("unexpected VLESS response version")
        );
        discard_exact(&mut Cursor::new(vec![]), 0).await.unwrap();
    }
}

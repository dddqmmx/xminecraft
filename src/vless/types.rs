use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use anyhow::{Context, Result, bail};

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct VlessId([u8; 16]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessTarget {
    pub address: VlessAddress,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VlessAddress {
    Ip(IpAddr),
    Domain(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessRequest {
    pub version: u8,
    pub target: VlessTarget,
}

impl VlessId {
    pub fn parse(input: &str) -> Result<Self> {
        input.parse()
    }

    pub fn as_bytes(self) -> [u8; 16] {
        self.0
    }

    pub(super) fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

impl FromStr for VlessId {
    type Err = anyhow::Error;

    fn from_str(input: &str) -> Result<Self> {
        let cleaned = input.trim().replace('-', "");
        if cleaned.len() != 32 {
            bail!("VLESS id must be a UUID or 32 hex characters");
        }

        let decoded = hex::decode(&cleaned).context("VLESS id must be hex encoded")?;
        let mut id = [0; 16];
        id.copy_from_slice(&decoded);
        Ok(Self(id))
    }
}

impl fmt::Debug for VlessId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for VlessId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (idx, byte) in self.0.iter().enumerate() {
            if matches!(idx, 4 | 6 | 8 | 10) {
                f.write_str("-")?;
            }
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl VlessTarget {
    pub fn parse(input: &str) -> Result<Self> {
        input.parse()
    }
}

impl FromStr for VlessTarget {
    type Err = anyhow::Error;

    fn from_str(input: &str) -> Result<Self> {
        let input = input.trim();
        if input.is_empty() {
            bail!("target must not be empty");
        }

        let (host, port) = split_host_port(input)?;
        if host.is_empty() {
            bail!("target host must not be empty");
        }

        let port = port
            .parse::<u16>()
            .with_context(|| format!("parsing target port in {input}"))?;
        if port == 0 {
            bail!("target port must be greater than zero");
        }

        let address = match host.parse::<IpAddr>() {
            Ok(ip) => VlessAddress::Ip(ip),
            Err(_) => {
                if host.len() > u8::MAX as usize {
                    bail!("target domain is longer than 255 bytes");
                }
                if !host.is_ascii() {
                    bail!("target domain must be ASCII; use punycode for IDN names");
                }
                VlessAddress::Domain(host.to_owned())
            }
        };

        Ok(Self { address, port })
    }
}

impl fmt::Display for VlessTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.address {
            VlessAddress::Ip(IpAddr::V4(ip)) => write!(f, "{ip}:{}", self.port),
            VlessAddress::Ip(IpAddr::V6(ip)) => write!(f, "[{ip}]:{}", self.port),
            VlessAddress::Domain(domain) => write!(f, "{domain}:{}", self.port),
        }
    }
}

fn split_host_port(input: &str) -> Result<(&str, &str)> {
    if let Some(rest) = input.strip_prefix('[') {
        let Some((host, port)) = rest.split_once("]:") else {
            bail!("bracketed IPv6 target must look like [::1]:443");
        };
        return Ok((host, port));
    }

    let Some((host, port)) = input.rsplit_once(':') else {
        bail!("target must include a port, for example example.com:443");
    };
    if host.contains(':') {
        bail!("IPv6 targets must be bracketed, for example [::1]:443");
    }
    Ok((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vless_id_parsing() {
        let raw = "5783a3e7-e373-51cd-8642-c83782b807c5";
        let id = VlessId::parse(raw).unwrap();
        assert_eq!(id.to_string(), raw);
    }

    #[test]
    fn vless_target_parsing() {
        let t1 = VlessTarget::parse("1.2.3.4:80").unwrap();
        assert_eq!(t1.to_string(), "1.2.3.4:80");

        let t2 = VlessTarget::parse("[2001:db8::1]:443").unwrap();
        assert_eq!(t2.to_string(), "[2001:db8::1]:443");

        let t3 = VlessTarget::parse("github.com:22").unwrap();
        assert_eq!(t3.to_string(), "github.com:22");
    }

    #[test]
    fn vless_target_rejects_invalid() {
        assert!(VlessTarget::parse("no-port").is_err());
        assert!(VlessTarget::parse("1.2.3.4:99999").is_err());
        assert!(VlessTarget::parse("::1:80").is_err()); // Needs brackets
    }
}

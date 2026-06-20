use tokio::io::{AsyncWriteExt, duplex};

use super::types::{VlessId, VlessTarget};
use super::wire::VERSION;
const ADDRESS_DOMAIN: u8 = 2;
const COMMAND_TCP: u8 = 1;
use super::*;

#[test]
fn parses_uuid_with_hyphens() {
    let id = VlessId::parse("5783a3e7-e373-51cd-8642-c83782b807c5").unwrap();
    assert_eq!(id.to_string(), "5783a3e7-e373-51cd-8642-c83782b807c5");
}

#[test]
fn parses_domain_and_ipv6_targets() {
    assert_eq!(
        VlessTarget::parse("example.com:443").unwrap().to_string(),
        "example.com:443"
    );
    assert_eq!(
        VlessTarget::parse("[::1]:8443").unwrap().to_string(),
        "[::1]:8443"
    );
}

#[tokio::test]
async fn request_header_round_trips() {
    let id = VlessId::parse("5783a3e7-e373-51cd-8642-c83782b807c5").unwrap();
    let target = VlessTarget::parse("example.com:443").unwrap();
    let (mut client, mut server) = duplex(128);

    write_request(&mut client, id, &target).await.unwrap();
    let request = read_request(&mut server, id).await.unwrap();

    assert_eq!(request.version, VERSION);
    assert_eq!(request.target, target);
}

#[tokio::test]
async fn rejects_wrong_uuid() {
    let id = VlessId::parse("5783a3e7-e373-51cd-8642-c83782b807c5").unwrap();
    let wrong = VlessId::parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap();
    let target = VlessTarget::parse("127.0.0.1:80").unwrap();
    let (mut client, mut server) = duplex(128);

    write_request(&mut client, id, &target).await.unwrap();

    assert!(read_request(&mut server, wrong).await.is_err());
}

#[tokio::test]
async fn response_header_round_trips() {
    let (mut server, mut client) = duplex(16);

    write_response(&mut server, VERSION).await.unwrap();

    read_response(&mut client).await.unwrap();
}

#[tokio::test]
async fn rejects_unsupported_command() {
    let id = VlessId::parse("5783a3e7-e373-51cd-8642-c83782b807c5").unwrap();
    let (mut client, mut server) = duplex(128);

    let mut header = Vec::new();
    header.push(VERSION);
    header.extend_from_slice(&id.as_bytes());
    header.push(0);
    header.push(0xff);
    header.extend_from_slice(&443_u16.to_be_bytes());
    header.push(ADDRESS_DOMAIN);
    header.push(11);
    header.extend_from_slice(b"example.com");
    client.write_all(&header).await.unwrap();

    let err = read_request(&mut server, id).await.unwrap_err().to_string();
    assert!(err.contains("unsupported VLESS command"));
}

#[tokio::test]
async fn accepts_tcp_command() {
    let id = VlessId::parse("5783a3e7-e373-51cd-8642-c83782b807c5").unwrap();
    let (mut client, mut server) = duplex(128);

    let mut header = Vec::new();
    header.push(VERSION);
    header.extend_from_slice(&id.as_bytes());
    header.push(0);
    header.push(COMMAND_TCP);
    header.extend_from_slice(&443_u16.to_be_bytes());
    header.push(ADDRESS_DOMAIN);
    header.push(11);
    header.extend_from_slice(b"example.com");
    client.write_all(&header).await.unwrap();

    let request = read_request(&mut server, id).await.unwrap();
    assert_eq!(
        request.target,
        VlessTarget::parse("example.com:443").unwrap()
    );
}

#[test]
fn target_parser_rejects_ambiguous_ipv6() {
    let err = VlessTarget::parse("::1:443").unwrap_err().to_string();

    assert!(err.contains("IPv6 targets must be bracketed"));
}

#[test]
fn target_parser_handles_ipv4() {
    let target = VlessTarget::parse("127.0.0.1:8080").unwrap();
    assert_eq!(target.to_string(), "127.0.0.1:8080");
}

#[tokio::test]
async fn read_request_rejects_truncated_header() {
    let id = VlessId::parse("5783a3e7-e373-51cd-8642-c83782b807c5").unwrap();
    let (mut client, mut server) = duplex(128);

    client.write_all(&[VERSION]).await.unwrap();
    client.shutdown().await.unwrap();

    assert!(read_request(&mut server, id).await.is_err());
}

#[tokio::test]
async fn read_request_rejects_wrong_version() {
    let id = VlessId::parse("5783a3e7-e373-51cd-8642-c83782b807c5").unwrap();
    let (mut client, mut server) = duplex(128);

    client.write_all(&[0xff]).await.unwrap();
    client.shutdown().await.unwrap();

    let err = read_request(&mut server, id).await.unwrap_err().to_string();
    assert!(err.contains("unsupported VLESS version"));
}

#[test]
fn target_parser_rejects_missing_port() {
    assert!(VlessTarget::parse("example.com").is_err());
}

#[test]
fn vless_id_rejects_invalid_uuid() {
    assert!(VlessId::parse("not-a-uuid").is_err());
}

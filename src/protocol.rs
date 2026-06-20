use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::ReadBuf;

use anyhow::{Context as _, Result, anyhow, bail};
use rsa::pkcs8::DecodePublicKey;
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use valence_protocol::packets::handshaking::HandshakeC2s;
use valence_protocol::packets::handshaking::handshake_c2s::HandshakeNextState as ValenceHandshakeNextState;
use valence_protocol::packets::login::{
    LoginDisconnectS2c, LoginHelloC2s, LoginHelloS2c, LoginKeyC2s, LoginSuccessS2c,
};
use valence_protocol::{Decode, Encode, Packet, VarInt};

use crate::crypto::{Aes128Cfb8Reader, Aes128Cfb8Writer};

pub const HANDSHAKE_PACKET_ID: i32 = 0x00;
pub const LOGIN_NEXT_STATE: i32 = 2;
pub const DEFAULT_CHUNK_PACKET_ID: i32 =
    valence_protocol::packet_id::CHUNK_RENDER_DISTANCE_CENTER_S2C;
pub const DEFAULT_PLAYER_ACTION_PACKET_ID: i32 = valence_protocol::packet_id::PLAYER_ACTION_C2S;
pub const DEFAULT_GAME_STATE_PACKET_ID: i32 = valence_protocol::packet_id::GAME_STATE_CHANGE_S2C;
pub const DEFAULT_ENTITY_EVENT_PACKET_ID: i32 = valence_protocol::packet_id::ENTITY_STATUS_S2C;
pub const DEFAULT_WORLD_TIME_PACKET_ID: i32 = valence_protocol::packet_id::WORLD_TIME_UPDATE_S2C;
pub const DEFAULT_HEALTH_PACKET_ID: i32 = valence_protocol::packet_id::HEALTH_UPDATE_S2C;
pub const DEFAULT_ENTITY_SPAWN_PACKET_ID: i32 = valence_protocol::packet_id::ENTITY_SPAWN_S2C;
pub const DEFAULT_ENTITY_MOVE_PACKET_ID: i32 = valence_protocol::packet_id::ENTITY_POSITION_S2C;

pub const DEFAULT_USERNAME: &str = "xminecraft";

const MAX_STRING_BYTES: usize = 32_767;

pub type BoxedReader = Pin<Box<dyn AsyncRead + Send>>;
pub type BoxedWriter = Pin<Box<dyn AsyncWrite + Send>>;

pub struct UpgradedStream {
    pub read: BoxedReader,
    pub write: BoxedWriter,
}

impl UpgradedStream {
    pub fn new<S>(inner: S) -> Self
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let (r, w) = tokio::io::split(inner);
        Self {
            read: Box::pin(r),
            write: Box::pin(w),
        }
    }
}

impl AsyncRead for UpgradedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.read).poll_read(cx, buf)
    }
}

impl AsyncWrite for UpgradedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.write).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.write).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.write).poll_shutdown(cx)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketFrame {
    pub packet_id: i32,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeInfo {
    pub protocol_version: i32,
    pub server_address: String,
    pub server_port: u16,
    pub next_state: HandshakeNextState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeNextState {
    Status,
    Login,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginIdentity {
    pub username: String,
    pub profile_id: Option<valence_protocol::uuid::Uuid>,
}

pub struct JoinedStream {
    pub read: Pin<Box<dyn AsyncRead + Send>>,
    pub write: Pin<Box<dyn AsyncWrite + Send>>,
}

impl AsyncRead for JoinedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.read.as_mut().poll_read(cx, buf)
    }
}

impl AsyncWrite for JoinedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        self.write.as_mut().poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        self.write.as_mut().poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        self.write.as_mut().poll_shutdown(cx)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientPreambleOptions {
    pub protocol_version: i32,
    pub server_address: String,
    pub server_port: u16,
    pub username: String,
}

pub async fn read_packet<R>(reader: &mut R, max_packet_len: usize) -> Result<Option<PacketFrame>>
where
    R: AsyncRead + Unpin,
{
    let Some(packet_len) = read_varint_from_stream(reader).await? else {
        return Ok(None);
    };

    if packet_len < 0 {
        bail!("negative Minecraft packet length: {packet_len}");
    }

    let packet_len = packet_len as usize;
    if packet_len > max_packet_len {
        bail!("Minecraft packet length {packet_len} exceeds limit {max_packet_len}");
    }

    let mut data = vec![0; packet_len];
    reader
        .read_exact(&mut data)
        .await
        .context("reading Minecraft packet body")?;

    let mut body = data.as_slice();
    let packet_id = decode_varint(&mut body).context("decoding Minecraft packet id")?;

    Ok(Some(PacketFrame {
        packet_id,
        body: body.to_vec(),
    }))
}

pub async fn write_packet<W>(writer: &mut W, packet_id: i32, body: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut packet = Vec::with_capacity(body.len() + 5);
    encode_varint(packet_id, &mut packet).context("encoding Minecraft packet id")?;
    packet.extend_from_slice(body);

    let packet_len = i32::try_from(packet.len()).context("Minecraft packet is too large")?;
    let mut frame = Vec::with_capacity(packet.len() + 5);
    encode_varint(packet_len, &mut frame).context("encoding Minecraft packet length")?;
    frame.extend_from_slice(&packet);

    writer
        .write_all(&frame)
        .await
        .context("writing Minecraft packet")?;
    Ok(())
}

pub async fn write_typed_packet<W, P>(writer: &mut W, packet: &P) -> Result<()>
where
    W: AsyncWrite + Unpin,
    P: Packet + Encode,
{
    let mut data = Vec::new();
    packet
        .encode_with_id(&mut data)
        .map_err(|err| anyhow!("valence packet encode failed: {err}"))?;

    let packet_len = i32::try_from(data.len()).context("Minecraft packet is too large")?;
    let mut frame = Vec::with_capacity(data.len() + 5);
    encode_varint(packet_len, &mut frame).context("encoding Minecraft packet length")?;
    frame.extend_from_slice(&data);

    writer
        .write_all(&frame)
        .await
        .context("writing Minecraft packet")?;
    Ok(())
}

pub async fn write_client_preamble(
    mut stream: UpgradedStream,
    options: &ClientPreambleOptions,
) -> Result<UpgradedStream> {
    let mut handshake = Vec::new();
    encode_varint(options.protocol_version, &mut handshake)?;
    encode_string(&options.server_address, &mut handshake)?;
    handshake.extend_from_slice(&options.server_port.to_be_bytes());
    encode_varint(LOGIN_NEXT_STATE, &mut handshake)?;
    write_packet(&mut stream.write, HANDSHAKE_PACKET_ID, &handshake).await?;

    let mut login_start = Vec::new();
    LoginHelloC2s {
        username: &options.username,
        profile_id: None,
    }
    .encode(&mut login_start)
    .map_err(|err| anyhow!("encoding login-start packet failed: {err}"))?;
    write_packet(&mut stream.write, LoginHelloC2s::ID, &login_start).await?;
    stream.write.flush().await?;

    // Wait for either LoginSuccessS2c, LoginDisconnectS2c, or LoginHelloS2c (EncryptionRequest)
    let packet = read_packet(&mut stream.read, 1024 * 1024)
        .await?
        .ok_or_else(|| anyhow!("connection closed waiting for login response"))?;

    if packet.packet_id == LoginHelloS2c::ID {
        let mut body = packet.body.as_slice();
        let request = LoginHelloS2c::decode(&mut body)
            .map_err(|err| anyhow!("decoding encryption request failed: {err}"))?;

        let pub_key = RsaPublicKey::from_public_key_der(request.public_key)
            .map_err(|err| anyhow!("parsing server public key failed: {err}"))?;

        let shared_secret: [u8; 16] = rand::random();

        let encrypted_secret = pub_key
            .encrypt(&mut rand::thread_rng(), Pkcs1v15Encrypt, &shared_secret)
            .map_err(|err| anyhow!("encrypting shared secret failed: {err}"))?;

        let encrypted_token = pub_key
            .encrypt(
                &mut rand::thread_rng(),
                Pkcs1v15Encrypt,
                request.verify_token,
            )
            .map_err(|err| anyhow!("encrypting verify token failed: {err}"))?;

        write_typed_packet(
            &mut stream.write,
            &LoginKeyC2s {
                shared_secret: &encrypted_secret,
                verify_token: &encrypted_token,
            },
        )
        .await?;
        stream.write.flush().await?;

        // Upgrade halves to AES
        let mut reader = Box::pin(Aes128Cfb8Reader::new(stream.read, &shared_secret));
        let writer = Box::pin(Aes128Cfb8Writer::new(stream.write, &shared_secret));

        // Read LoginSuccessS2c (it should be the next packet, now encrypted)
        let success_packet = read_packet(&mut reader, 1024 * 1024)
            .await?
            .ok_or_else(|| anyhow!("connection closed waiting for login success"))?;

        if success_packet.packet_id == LoginDisconnectS2c::ID {
            let mut body = success_packet.body.as_slice();
            let disconnect = LoginDisconnectS2c::decode(&mut body)?;
            bail!("login failed: {}", disconnect.reason);
        }

        if success_packet.packet_id != LoginSuccessS2c::ID {
            bail!(
                "expected login success packet id {}, got {}",
                LoginSuccessS2c::ID,
                success_packet.packet_id
            );
        }

        Ok(UpgradedStream {
            read: reader,
            write: writer,
        })
    } else if packet.packet_id == LoginSuccessS2c::ID {
        Ok(stream)
    } else if packet.packet_id == LoginDisconnectS2c::ID {
        let mut body = packet.body.as_slice();
        let disconnect = LoginDisconnectS2c::decode(&mut body)?;
        bail!("login failed: {}", disconnect.reason);
    } else {
        bail!("unexpected packet id {} during login", packet.packet_id);
    }
}

pub async fn read_handshake<R>(reader: &mut R, max_packet_len: usize) -> Result<HandshakeInfo>
where
    R: AsyncRead + Unpin,
{
    let handshake = read_packet(reader, max_packet_len)
        .await?
        .ok_or_else(|| anyhow!("connection closed before Minecraft handshake"))?;

    if handshake.packet_id != HandshakeC2s::ID {
        bail!(
            "expected Minecraft handshake packet id {}, got {}",
            HandshakeC2s::ID,
            handshake.packet_id
        );
    }

    let mut body = handshake.body.as_slice();
    let handshake = HandshakeC2s::decode(&mut body)
        .map_err(|err| anyhow!("decoding Minecraft handshake failed: {err}"))?;
    if !body.is_empty() {
        bail!("Minecraft handshake has {} trailing bytes", body.len());
    }

    let next_state = match handshake.next_state {
        ValenceHandshakeNextState::Status => HandshakeNextState::Status,
        ValenceHandshakeNextState::Login => HandshakeNextState::Login,
    };

    Ok(HandshakeInfo {
        protocol_version: handshake.protocol_version.0,
        server_address: handshake.server_address.to_owned(),
        server_port: handshake.server_port,
        next_state,
    })
}

pub async fn read_login_identity<R>(reader: &mut R, max_packet_len: usize) -> Result<LoginIdentity>
where
    R: AsyncRead + Unpin,
{
    let login_start = read_packet(reader, max_packet_len)
        .await?
        .ok_or_else(|| anyhow!("connection closed before Minecraft login-start packet"))?;

    if login_start.packet_id != LoginHelloC2s::ID {
        bail!(
            "expected Minecraft login-start packet id {}, got {}",
            LoginHelloC2s::ID,
            login_start.packet_id
        );
    }

    let mut body = login_start.body.as_slice();
    let login = LoginHelloC2s::decode(&mut body)
        .map_err(|err| anyhow!("decoding Minecraft login-start packet failed: {err}"))?;
    if !body.is_empty() {
        bail!(
            "Minecraft login-start packet has {} trailing bytes",
            body.len()
        );
    }

    Ok(LoginIdentity {
        username: login.username.to_owned(),
        profile_id: login.profile_id,
    })
}

pub fn encode_varint(value: i32, out: &mut Vec<u8>) -> Result<()> {
    VarInt(value)
        .encode(out)
        .map_err(|err| anyhow!("valence VarInt encode failed: {err}"))
}

pub fn decode_varint(input: &mut &[u8]) -> Result<i32> {
    Ok(VarInt::decode(input)
        .map_err(|err| anyhow!("valence VarInt decode failed: {err}"))?
        .0)
}

pub fn encode_string(value: &str, out: &mut Vec<u8>) -> Result<()> {
    let bytes = value.as_bytes();
    if bytes.len() > MAX_STRING_BYTES {
        bail!(
            "Minecraft string is {} bytes, exceeding limit {MAX_STRING_BYTES}",
            bytes.len()
        );
    }

    let len = i32::try_from(bytes.len()).context("Minecraft string is too large")?;
    encode_varint(len, out)?;
    out.extend_from_slice(bytes);
    Ok(())
}

#[cfg(test)]
fn decode_string(input: &mut &[u8]) -> Result<String> {
    let len = decode_varint(input).context("decoding Minecraft string length")?;
    if len < 0 {
        bail!("negative Minecraft string length: {len}");
    }

    let len = len as usize;
    if len > MAX_STRING_BYTES {
        bail!("Minecraft string length {len} exceeds limit {MAX_STRING_BYTES}");
    }
    if input.len() < len {
        bail!(
            "Minecraft string length {len} exceeds remaining packet bytes {}",
            input.len()
        );
    }

    let (raw, rest) = input.split_at(len);
    *input = rest;
    Ok(std::str::from_utf8(raw)
        .context("Minecraft string is not valid UTF-8")?
        .to_owned())
}

async fn read_varint_from_stream<R>(reader: &mut R) -> Result<Option<i32>>
where
    R: AsyncRead + Unpin,
{
    let mut value = 0i32;

    for byte_index in 0..5 {
        let mut byte = [0u8; 1];
        let read = reader
            .read(&mut byte)
            .await
            .context("reading Minecraft VarInt")?;

        if read == 0 {
            if byte_index == 0 {
                return Ok(None);
            }

            bail!("unexpected EOF inside Minecraft VarInt");
        }

        let byte = byte[0];
        value |= ((byte & 0x7f) as i32) << (byte_index * 7);

        if byte & 0x80 == 0 {
            return Ok(Some(value));
        }
    }

    bail!("Minecraft VarInt is longer than 5 bytes");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_round_trip() {
        let mut out = Vec::new();
        encode_string("hello", &mut out).unwrap();

        let mut input = out.as_slice();
        assert_eq!(decode_string(&mut input).unwrap(), "hello");
        assert!(input.is_empty());
    }

    #[test]
    fn varint_round_trips() {
        let values = [0, 1, 127, 128, 255, 256, i32::MAX, -1, -128, i32::MIN];
        for v in values {
            let mut buf = Vec::new();
            encode_varint(v, &mut buf).unwrap();
            let mut input = buf.as_slice();
            assert_eq!(decode_varint(&mut input).unwrap(), v);
            assert!(input.is_empty());
        }
    }

    #[test]
    fn encode_string_rejects_huge_payload() {
        let huge = "a".repeat(40000);
        let mut buf = Vec::new();
        assert!(encode_string(&huge, &mut buf).is_err());
    }

    #[tokio::test]
    async fn read_packet_handles_empty_stream() {
        let mut empty = tokio::io::empty();
        assert!(read_packet(&mut empty, 1024).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn read_packet_rejects_oversized() {
        let mut data = Vec::new();
        encode_varint(100, &mut data).unwrap();
        data.extend_from_slice(&[0; 100]);
        let mut reader = data.as_slice();
        assert!(read_packet(&mut reader, 10).await.is_err());
    }
}
#[cfg(test)]
mod tests_additional {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn test_protocol_errors() {
        // String too large
        let mut out = vec![];
        assert!(encode_string(&"a".repeat(32768), &mut out).is_err());

        let cur = Cursor::new(vec![255, 255, 3]);
        let cur_slice = cur.into_inner();
        let mut slice = cur_slice.as_slice();
        assert!(
            decode_string(&mut slice)
                .unwrap_err()
                .to_string()
                .contains("exceeds limit")
        );

        // Oversized packet
        let mut cur = Cursor::new(vec![255, 255, 255, 127]);
        assert!(
            read_packet(&mut cur, 1024)
                .await
                .unwrap_err()
                .to_string()
                .contains("exceeds limit")
        );

        // Negative packet length
        let mut cur = Cursor::new(vec![255, 255, 255, 255, 15]);
        assert!(
            read_packet(&mut cur, 1024)
                .await
                .unwrap_err()
                .to_string()
                .contains("negative Minecraft packet length")
        );

        // Empty packet
        let mut cur = Cursor::new(vec![]);
        assert!(read_packet(&mut cur, 1024).await.unwrap().is_none());

        // Handshake wrong packet id
        let mut p = vec![];
        write_packet(&mut p, 99, &[]).await.unwrap();
        assert!(read_handshake(&mut Cursor::new(p), 1024).await.is_err());

        // Login identity wrong id
        let mut p = vec![];
        write_packet(&mut p, 99, &[]).await.unwrap();
        assert!(
            read_login_identity(&mut Cursor::new(p), 1024)
                .await
                .is_err()
        );

        // VarInt EOF
        assert!(
            read_varint_from_stream(&mut Cursor::new(vec![128]))
                .await
                .is_err()
        );
    }
}

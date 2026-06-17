use std::borrow::Cow;

use anyhow::{Result, anyhow, bail};
use rsa::Pkcs1v15Encrypt;
use rsa::pkcs8::EncodePublicKey;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use valence_protocol::math::DVec3;
use valence_protocol::packets::login::{
    LoginDisconnectS2c, LoginHelloS2c, LoginKeyC2s, LoginSuccessS2c,
};
use valence_protocol::packets::play::{
    ChunkLoadDistanceS2c, CommandTreeS2c, CustomPayloadS2c, DifficultyS2c, ExperienceBarUpdateS2c,
    FeaturesS2c, GameJoinS2c, GameStateChangeS2c, HealthUpdateS2c, KeepAliveS2c,
    PlayerAbilitiesS2c, PlayerPositionLookS2c, PlayerSpawnPositionS2c, ServerMetadataS2c,
    SimulationDistanceS2c, SynchronizeTagsS2c, WorldTimeUpdateS2c,
    command_tree_s2c::{Node, NodeData},
    game_state_change_s2c::GameEventKind,
    player_abilities_s2c::PlayerAbilitiesFlags,
    player_position_look_s2c::PlayerPositionLookFlags,
};
use valence_protocol::{
    BlockPos, Decode, Difficulty, GameMode, Ident, Packet, Property, RawBytes, Text, VarInt,
};

use crate::crypto::{Aes128Cfb8Reader, Aes128Cfb8Writer};
use crate::protocol::{
    HandshakeInfo, LoginIdentity, UpgradedStream, encode_string, read_login_identity, read_packet,
    write_typed_packet,
};

use super::identity::resolve_player_uuid;
use super::profile::ServerProfile;
use super::registry::registry_codec;
use super::session::{AcceptedLogin, AcceptedSession};

pub(super) async fn accept_login(
    mut stream: UpgradedStream,
    max_packet_len: usize,
    profile: &ServerProfile,
    handshake: HandshakeInfo,
) -> Result<AcceptedSession> {
    let identity = read_login_identity(&mut stream.read, max_packet_len).await?;

    let priv_key = &profile.rsa_key;
    let mut stream = {
        let verify_token: [u8; 4] = rand::random();
        let pub_key_der = priv_key
            .to_public_key()
            .to_public_key_der()
            .map_err(|err| anyhow!("encoding RSA public key to DER failed: {err}"))?
            .to_vec();

        write_typed_packet(
            &mut stream.write,
            &LoginHelloS2c {
                server_id: "",
                public_key: &pub_key_der,
                verify_token: &verify_token,
            },
        )
        .await?;
        stream.write.flush().await?;

        let response_packet = read_packet(&mut stream.read, max_packet_len)
            .await?
            .ok_or_else(|| anyhow!("connection closed during encryption handshake"))?;

        if response_packet.packet_id != LoginKeyC2s::ID {
            bail!(
                "expected encryption response packet id {}, got {}",
                LoginKeyC2s::ID,
                response_packet.packet_id
            );
        }

        let mut body = response_packet.body.as_slice();
        let response = LoginKeyC2s::decode(&mut body)
            .map_err(|err| anyhow!("decoding encryption response failed: {err}"))?;

        let shared_secret: [u8; 16] = priv_key
            .decrypt(Pkcs1v15Encrypt, response.shared_secret)
            .map_err(|err| anyhow!("decrypting shared secret failed: {err}"))?
            .try_into()
            .map_err(|_| anyhow!("decrypted shared secret has invalid length"))?;

        let decrypted_verify_token = priv_key
            .decrypt(Pkcs1v15Encrypt, response.verify_token)
            .map_err(|err| anyhow!("decrypting verify token failed: {err}"))?;

        if decrypted_verify_token != verify_token {
            bail!("encryption handshake verify token mismatch");
        }

        UpgradedStream {
            read: Box::pin(Aes128Cfb8Reader::new(stream.read, &shared_secret)),
            write: Box::pin(Aes128Cfb8Writer::new(stream.write, &shared_secret)),
        }
    };

    let uuid = resolve_player_uuid(&identity);

    if !profile.whitelist.allows(&identity.username, &uuid) {
        write_login_disconnect(&mut stream.write, &profile.whitelist_message).await?;
        stream.write.flush().await?;
        return Ok(AcceptedSession::Rejected(AcceptedLogin {
            handshake,
            identity,
            uuid,
            stream,
        }));
    }

    write_login_success(&mut stream.write, &identity, uuid).await?;

    if profile.send_play_packets {
        write_initial_play_packets(&mut stream.write, profile).await?;
    }
    stream.write.flush().await?;

    Ok(AcceptedSession::Login(AcceptedLogin {
        handshake,
        identity,
        uuid,
        stream,
    }))
}

async fn write_login_success<S>(
    stream: &mut S,
    identity: &LoginIdentity,
    uuid: valence_protocol::uuid::Uuid,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let empty_properties: &[Property] = &[];

    write_typed_packet(
        stream,
        &LoginSuccessS2c {
            uuid,
            username: &identity.username,
            properties: Cow::Borrowed(empty_properties),
        },
    )
    .await
}

async fn write_login_disconnect<S>(stream: &mut S, reason: &str) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    write_typed_packet(
        stream,
        &LoginDisconnectS2c {
            reason: Cow::Owned(Text::text(reason.to_owned())),
        },
    )
    .await
}

async fn write_initial_play_packets<S>(stream: &mut S, profile: &ServerProfile) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    write_typed_packet(
        stream,
        &FeaturesS2c {
            features: vec![ident("minecraft:vanilla")],
        },
    )
    .await?;
    write_typed_packet(
        stream,
        &GameJoinS2c {
            entity_id: profile.entity_id,
            is_hardcore: false,
            game_mode: GameMode::Survival,
            previous_game_mode: -1,
            dimension_names: vec![ident("minecraft:overworld")],
            registry_codec: Cow::Owned(registry_codec()),
            dimension_type_name: ident("minecraft:overworld"),
            dimension_name: ident("minecraft:overworld"),
            hashed_seed: 0,
            max_players: VarInt(profile.max_players),
            view_distance: VarInt(profile.view_distance),
            simulation_distance: VarInt(profile.simulation_distance),
            reduced_debug_info: false,
            enable_respawn_screen: true,
            is_debug: false,
            is_flat: false,
            last_death_location: None,
            portal_cooldown: VarInt(0),
        },
    )
    .await?;

    let brand_payload = brand_payload(&profile.brand)?;
    write_typed_packet(
        stream,
        &CustomPayloadS2c {
            channel: ident("minecraft:brand"),
            data: RawBytes(&brand_payload),
        },
    )
    .await?;

    let motd = Text::text(profile.motd.clone());

    write_typed_packet(
        stream,
        &ServerMetadataS2c {
            motd: Cow::Owned(motd),
            icon: None,
            enforce_secure_chat: profile.enforce_secure_chat,
        },
    )
    .await?;
    write_typed_packet(
        stream,
        &DifficultyS2c {
            difficulty: Difficulty::Normal,
            locked: false,
        },
    )
    .await?;
    write_typed_packet(
        stream,
        &CommandTreeS2c {
            commands: vec![Node {
                children: vec![],
                data: NodeData::Root,
                executable: false,
                redirect_node: None,
            }],
            root_index: VarInt(0),
        },
    )
    .await?;
    write_typed_packet(
        stream,
        &SynchronizeTagsS2c {
            registries: Cow::Owned(vec![]),
        },
    )
    .await?;
    write_typed_packet(
        stream,
        &ChunkLoadDistanceS2c {
            view_distance: VarInt(profile.view_distance),
        },
    )
    .await?;
    write_typed_packet(
        stream,
        &SimulationDistanceS2c {
            simulation_distance: VarInt(profile.simulation_distance),
        },
    )
    .await?;
    write_typed_packet(
        stream,
        &PlayerAbilitiesS2c {
            flags: PlayerAbilitiesFlags::new(),
            flying_speed: 0.05,
            fov_modifier: 0.1,
        },
    )
    .await?;
    write_typed_packet(
        stream,
        &PlayerSpawnPositionS2c {
            position: BlockPos::new(0, profile.spawn_y, 0),
            angle: 0.0,
        },
    )
    .await?;
    write_typed_packet(
        stream,
        &PlayerPositionLookS2c {
            position: DVec3::new(0.0, f64::from(profile.spawn_y + 1), 0.0),
            yaw: 0.0,
            pitch: 0.0,
            flags: PlayerPositionLookFlags::new(),
            teleport_id: VarInt(1),
        },
    )
    .await?;
    write_typed_packet(
        stream,
        &HealthUpdateS2c {
            health: 20.0,
            food: VarInt(20),
            food_saturation: 5.0,
        },
    )
    .await?;
    write_typed_packet(
        stream,
        &ExperienceBarUpdateS2c {
            bar: 0.0,
            level: VarInt(0),
            total_xp: VarInt(0),
        },
    )
    .await?;
    write_typed_packet(
        stream,
        &GameStateChangeS2c {
            kind: GameEventKind::EnableRespawnScreen,
            value: 0.0,
        },
    )
    .await?;
    write_typed_packet(
        stream,
        &WorldTimeUpdateS2c {
            world_age: 0,
            time_of_day: 6_000,
        },
    )
    .await?;
    write_typed_packet(stream, &KeepAliveS2c { id: 1 }).await?;

    Ok(())
}

fn ident(value: &'static str) -> Ident<Cow<'static, str>> {
    Ident::new(Cow::Borrowed(value)).expect("static Minecraft identifiers are valid")
}

fn brand_payload(brand: &str) -> Result<Vec<u8>> {
    let mut payload = Vec::new();
    encode_string(brand, &mut payload)?;
    Ok(payload)
}

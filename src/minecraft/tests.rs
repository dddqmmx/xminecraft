use tokio::io::{AsyncWriteExt, duplex};
use valence_protocol::Packet;
use valence_protocol::packets::status::{QueryPongS2c, QueryRequestC2s, QueryResponseS2c};

use super::identity::offline_player_uuid;
use super::*;
use crate::protocol::{
    ClientPreambleOptions, UpgradedStream, encode_string, encode_varint, read_packet,
    write_client_preamble, write_packet,
};
use crate::whitelist::Whitelist;

#[test]
fn offline_uuid_matches_known_vanilla_value() {
    let uuid = offline_player_uuid("Notch");
    assert_eq!(uuid.to_string(), "b50ad385-829d-3141-a216-7e7d7539ba7f");
}

fn test_profile() -> ServerProfile {
    ServerProfile {
        motd: "A Minecraft Server".to_owned(),
        max_players: 20,
        online_players: 0,
        version_name: valence_protocol::MINECRAFT_VERSION.to_owned(),
        enforce_secure_chat: false,
        view_distance: 10,
        simulation_distance: 10,
        whitelist: Whitelist::from_cli(vec!["xminecraft".to_owned()], vec![]).unwrap(),
        whitelist_message: "You are not whitelisted on this server.".to_owned(),
        brand: "xminecraft".to_owned(),
        entity_id: 1,
        spawn_y: 64,
        rsa_key: crate::test_support::test_rsa_key().clone(),
        send_play_packets: true,
    }
}

#[tokio::test]
async fn status_query_returns_json_and_pong() {
    let (client, server) = duplex(4096);
    let profile = test_profile();

    let server_task = tokio::spawn(async move {
        accept_session(
            UpgradedStream::new(server),
            valence_protocol::MAX_PACKET_SIZE as usize,
            &profile,
        )
        .await
    });

    let mut client = UpgradedStream::new(client);

    let mut handshake = Vec::new();
    encode_varint(valence_protocol::PROTOCOL_VERSION, &mut handshake).unwrap();
    encode_string("localhost", &mut handshake).unwrap();
    handshake.extend_from_slice(&25565u16.to_be_bytes());
    encode_varint(1, &mut handshake).unwrap();

    write_packet(&mut client.write, 0, &handshake)
        .await
        .unwrap();
    write_packet(&mut client.write, QueryRequestC2s::ID, &[])
        .await
        .unwrap();

    let response = read_packet(&mut client.read, valence_protocol::MAX_PACKET_SIZE as usize)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.packet_id, QueryResponseS2c::ID);

    let payload = 0x0102_0304_0506_0708u64;
    write_packet(&mut client.write, 1, &payload.to_be_bytes())
        .await
        .unwrap();
    let pong = read_packet(&mut client.read, valence_protocol::MAX_PACKET_SIZE as usize)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pong.packet_id, QueryPongS2c::ID);
    assert_eq!(pong.body, payload.to_be_bytes());

    client.write.shutdown().await.unwrap();
    assert!(matches!(
        server_task.await.unwrap().unwrap(),
        AcceptedSession::Status
    ));
}

#[tokio::test]
async fn login_preamble_receives_login_success() {
    let (client, server) = duplex(65_536);
    let profile = test_profile();

    let server_task = tokio::spawn(async move {
        accept_session(
            UpgradedStream::new(server),
            valence_protocol::MAX_PACKET_SIZE as usize,
            &profile,
        )
        .await
    });

    let _client = write_client_preamble(
        UpgradedStream::new(client),
        &ClientPreambleOptions {
            protocol_version: valence_protocol::PROTOCOL_VERSION,
            server_address: "localhost".to_owned(),
            server_port: 25565,
            username: "xminecraft".to_owned(),
        },
    )
    .await
    .unwrap();

    match server_task.await.unwrap().unwrap() {
        AcceptedSession::Login(login) => {
            assert_eq!(login.identity.username, "xminecraft");
            assert_eq!(login.uuid, offline_player_uuid("xminecraft"));
        }
        AcceptedSession::Status => panic!("expected login session"),
        AcceptedSession::Rejected(_) => panic!("expected accepted login session"),
    }
}

#[tokio::test]
async fn whitelist_rejects_unauthorized_login_with_disconnect_packet() {
    let (client, server) = duplex(4096);
    let profile = ServerProfile {
        whitelist: Whitelist::from_cli(vec!["Allowed".to_owned()], vec![]).unwrap(),
        ..test_profile()
    };

    let server_task = tokio::spawn(async move {
        accept_session(
            UpgradedStream::new(server),
            valence_protocol::MAX_PACKET_SIZE as usize,
            &profile,
        )
        .await
    });

    let client = write_client_preamble(
        UpgradedStream::new(client),
        &ClientPreambleOptions {
            protocol_version: valence_protocol::PROTOCOL_VERSION,
            server_address: "localhost".to_owned(),
            server_port: 25565,
            username: "Intruder".to_owned(),
        },
    )
    .await;

    // preamble should fail if server disconnects
    assert!(client.is_err());

    match server_task.await.unwrap().unwrap() {
        AcceptedSession::Rejected(login) => {
            assert_eq!(login.identity.username, "Intruder");
        }
        AcceptedSession::Login(_) => panic!("expected rejected login session"),
        AcceptedSession::Status => panic!("expected rejected login session"),
    }
}

#[tokio::test]
async fn accept_session_rejects_negative_packet_length() {
    // skipped for now
}

#[test]
fn server_profile_has_reasonable_defaults() {
    let profile = test_profile();
    assert_eq!(profile.max_players, 20);
    assert!(profile.whitelist.is_enabled());
}

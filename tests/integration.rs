use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use tracing_subscriber::EnvFilter;

use xminecraft::protocol::{ClientPreambleOptions, DEFAULT_USERNAME};
use xminecraft::proxy::client::handle_client_connection;
use xminecraft::proxy::config::{ClientConfig, ServerConfig};
use xminecraft::proxy::server::handle_server_connection;
use xminecraft::test_support::TlsFixture;
use xminecraft::tls::{ClientTlsOptions, ServerTlsOptions};
use xminecraft::vless::{VlessId, VlessTarget};

#[tokio::test]
async fn integration_1to1_replica_vpn_traffic_simulation() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    tokio::time::timeout(Duration::from_secs(60), async {
        tracing::info!("Starting 1:1 VPN Traffic Replica Simulation");

        let fixture = TlsFixture::new();
        let vless_id = VlessId::parse("5783a3e7-e373-51cd-8642-c83782b807c5").unwrap();

        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();
        let tunnel_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tunnel_addr = tunnel_listener.local_addr().unwrap();
        let local_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = local_listener.local_addr().unwrap();

        // 1. Target Server (Mock HTTP)
        let target_task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = target_listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0; 1024];
                    let _ = stream.read(&mut buf).await;
                    let body = "minecraft vpn works";
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });

        // 2. xminecraft Server (Online Mode + TLS + VLESS)
        let server_config = ServerConfig {
            listen: tunnel_addr.to_string(),
            expect_preamble: true,

            profile: xminecraft::minecraft::ServerProfile {
                motd: "A Minecraft Server".to_owned(),
                max_players: 20,
                online_players: 0,
                version_name: valence_protocol::MINECRAFT_VERSION.to_owned(),
                enforce_secure_chat: false,
                view_distance: 10,
                simulation_distance: 10,
                whitelist: xminecraft::whitelist::Whitelist::from_cli(vec!["xmc_vpn_test".to_owned(), "xminecraft".to_owned()], vec![]).unwrap(),
                whitelist_message: "You are not whitelisted on this server.".to_owned(),
                brand: "xminecraft".to_owned(),
                entity_id: 1,
                spawn_y: 64,
                send_play_packets: true,
                rsa_key: xminecraft::test_support::test_rsa_key().clone(),
            },
            vless_id,
            tls: ServerTlsOptions::new(&fixture.cert, &fixture.key).unwrap(),
        };
        let server_main_task = tokio::spawn(async move {
            while let Ok((tunnel, _)) = tunnel_listener.accept().await {
                let config = server_config.clone();
                tokio::spawn(async move {
                    let _ = handle_server_connection(tunnel, config).await;
                });
            }
        });

        // 3. xminecraft Client
        let client_config = ClientConfig {
            listen: local_addr.to_string(),
            tunnel: tunnel_addr.to_string(),
            target: Some(VlessTarget::parse(&target_addr.to_string()).unwrap()),
            preamble: Some(ClientPreambleOptions {
                protocol_version: valence_protocol::PROTOCOL_VERSION,
                server_address: "localhost".to_owned(),
                server_port: 25565,
                username: "xmc_vpn_test".to_owned(),
            }),

            vless_id,
            tls: ClientTlsOptions::new(&fixture.cert, "localhost".to_owned()).unwrap(),
        };
        let client_main_task = tokio::spawn(async move {
            while let Ok((raw, _)) = local_listener.accept().await {
                let config = client_config.clone();
                tokio::spawn(async move {
                    let _ = handle_client_connection(raw, config).await;
                });
            }
        });

        // Wait for servers to settle
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Perform the HTTP request
        let mut app = TcpStream::connect(local_addr).await.unwrap();
        app.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        app.shutdown().await.unwrap();

        let mut response = Vec::new();
        app.read_to_end(&mut response).await.unwrap();
        assert!(String::from_utf8_lossy(&response).contains("minecraft vpn works"));

        target_task.abort();
        server_main_task.abort();
        client_main_task.abort();
    })
    .await
    .expect("1:1 VPN Simulation timed out");
}

#[tokio::test]
async fn integration_full_stack_vless_tls_minecraft() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    tokio::time::timeout(Duration::from_secs(10), async {
        let fixture = TlsFixture::new();
        let vless_id = VlessId::parse("5783a3e7-e373-51cd-8642-c83782b807c5").unwrap();

        let tunnel_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tunnel_addr = tunnel_listener.local_addr().unwrap();
        let local_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = local_listener.local_addr().unwrap();
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();

        let server_config = ServerConfig {
            listen: tunnel_addr.to_string(),
            expect_preamble: true,

            profile: xminecraft::minecraft::ServerProfile {
                motd: "A Minecraft Server".to_owned(),
                max_players: 20,
                online_players: 0,
                version_name: valence_protocol::MINECRAFT_VERSION.to_owned(),
                enforce_secure_chat: false,
                view_distance: 10,
                simulation_distance: 10,
                whitelist: xminecraft::whitelist::Whitelist::from_cli(vec!["xmc_vpn_test".to_owned(), "xminecraft".to_owned()], vec![]).unwrap(),
                whitelist_message: "You are not whitelisted on this server.".to_owned(),
                brand: "xminecraft".to_owned(),
                entity_id: 1,
                spawn_y: 64,
                send_play_packets: true,
                rsa_key: xminecraft::test_support::test_rsa_key().clone(),
            },
            vless_id,
            tls: ServerTlsOptions::new(&fixture.cert, &fixture.key).unwrap(),
        };

        let server_task = tokio::spawn(async move {
            if let Ok((tunnel, _)) = tunnel_listener.accept().await {
                handle_server_connection(tunnel, server_config).await
            } else {
                Ok(())
            }
        });

        let client_config = ClientConfig {
            listen: local_addr.to_string(),
            tunnel: tunnel_addr.to_string(),
            target: Some(VlessTarget::parse(&target_addr.to_string()).unwrap()),
            preamble: Some(ClientPreambleOptions {
                protocol_version: valence_protocol::PROTOCOL_VERSION,
                server_address: "localhost".to_owned(),
                server_port: 25565,
                username: DEFAULT_USERNAME.to_owned(),
            }),

            vless_id,
            tls: ClientTlsOptions::new(&fixture.cert, "localhost".to_owned()).unwrap(),
        };

        let client_task = tokio::spawn(async move {
            if let Ok((raw, _)) = local_listener.accept().await {
                handle_client_connection(raw, client_config).await
            } else {
                Ok(())
            }
        });

        let target_task = tokio::spawn(async move {
            let (mut target, _) = target_listener.accept().await.unwrap();
            let mut request = [0; 11];
            target.read_exact(&mut request).await.unwrap();
            assert_eq!(&request[..], &b"hello world"[..11]);
            target.write_all(b"bye").await.unwrap();
            target.shutdown().await.unwrap();
        });

        let mut app = TcpStream::connect(local_addr).await.unwrap();
        app.write_all(b"hello world").await.unwrap();
        app.shutdown().await.unwrap();

        let mut response = Vec::new();
        app.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"bye");

        target_task.await.unwrap();
        client_task.await.unwrap().unwrap();
        server_task.await.unwrap().unwrap();
    })
    .await
    .expect("Test timed out");
}

#[tokio::test]
async fn integration_http_connect_proxy_mode() {
    tokio::time::timeout(Duration::from_secs(60), async {
        tracing::info!("Starting HTTP CONNECT Proxy Mode Simulation");

        let fixture = TlsFixture::new();
        let vless_id = VlessId::parse("5783a3e7-e373-51cd-8642-c83782b807c5").unwrap();

        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();
        let tunnel_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tunnel_addr = tunnel_listener.local_addr().unwrap();
        let local_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = local_listener.local_addr().unwrap();

        // 1. Target Server (Echoes back)
        let target_task = tokio::spawn(async move {
            let (mut target, _) = target_listener.accept().await.unwrap();
            let mut request = [0; 5];
            target.read_exact(&mut request).await.unwrap();
            assert_eq!(&request[..], &b"hello"[..5]);
            target.write_all(b"world").await.unwrap();
            target.shutdown().await.unwrap();
        });

        // 2. xminecraft Server
        let server_config = ServerConfig {
            listen: tunnel_addr.to_string(),
            expect_preamble: false,
            profile: xminecraft::minecraft::ServerProfile {
                motd: "A Minecraft Server".to_owned(),
                max_players: 20,
                online_players: 0,
                version_name: valence_protocol::MINECRAFT_VERSION.to_owned(),
                enforce_secure_chat: false,
                view_distance: 10,
                simulation_distance: 10,
                whitelist: xminecraft::whitelist::Whitelist::from_cli(vec!["xmc_vpn_test".to_owned(), "xminecraft".to_owned()], vec![]).unwrap(),
                whitelist_message: "You are not whitelisted on this server.".to_owned(),
                brand: "xminecraft".to_owned(),
                entity_id: 1,
                spawn_y: 64,
                send_play_packets: true,
                rsa_key: xminecraft::test_support::test_rsa_key().clone(),
            },
            vless_id,
            tls: ServerTlsOptions::new(&fixture.cert, &fixture.key).unwrap(),
        };
        let server_task = tokio::spawn(async move {
            if let Ok((tunnel, _)) = tunnel_listener.accept().await {
                handle_server_connection(tunnel, server_config).await
            } else {
                Ok(())
            }
        });

        // 3. xminecraft Client in proxy mode (target = None)
        let client_config = ClientConfig {
            listen: local_addr.to_string(),
            tunnel: tunnel_addr.to_string(),
            target: None, // Important: dynamically parse target from handshake
            preamble: None,
            vless_id,
            tls: ClientTlsOptions::new(&fixture.cert, "localhost".to_owned()).unwrap(),
        };

        let client_task = tokio::spawn(async move {
            if let Ok((raw, _)) = local_listener.accept().await {
                handle_client_connection(raw, client_config).await
            } else {
                Ok(())
            }
        });

        // 4. Client Application sending HTTP CONNECT
        let mut app = TcpStream::connect(local_addr).await.unwrap();
        let connect_req = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
            target_addr, target_addr
        );
        app.write_all(connect_req.as_bytes()).await.unwrap();

        // Read the 200 Connection Established response
        let mut resp_buf = [0; 39]; // "HTTP/1.1 200 Connection Established\r\n\r\n"
        app.read_exact(&mut resp_buf).await.unwrap();
        assert_eq!(
            &resp_buf[..],
            b"HTTP/1.1 200 Connection Established\r\n\r\n"
        );

        app.write_all(b"hello").await.unwrap();
        app.shutdown().await.unwrap();

        let mut response = Vec::new();
        app.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"world");

        target_task.await.unwrap();
        client_task.await.unwrap().unwrap();
        server_task.await.unwrap().unwrap();
    })
    .await
    .expect("Test timed out");
}

#[tokio::test]
async fn integration_socks5_connect_proxy_mode() {
    tokio::time::timeout(Duration::from_secs(60), async {
        tracing::info!("Starting SOCKS5 CONNECT Proxy Mode Simulation");

        let fixture = TlsFixture::new();
        let vless_id = VlessId::parse("5783a3e7-e373-51cd-8642-c83782b807c5").unwrap();

        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();
        let tunnel_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tunnel_addr = tunnel_listener.local_addr().unwrap();
        let local_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = local_listener.local_addr().unwrap();

        let target_task = tokio::spawn(async move {
            let (mut target, _) = target_listener.accept().await.unwrap();
            let mut request = [0; 5];
            target.read_exact(&mut request).await.unwrap();
            assert_eq!(&request[..], &b"socks"[..5]);
            target.write_all(b"works").await.unwrap();
            target.shutdown().await.unwrap();
        });

        let server_config = ServerConfig {
            listen: tunnel_addr.to_string(),
            expect_preamble: false,
            profile: xminecraft::minecraft::ServerProfile {
                motd: "A Minecraft Server".to_owned(),
                max_players: 20,
                online_players: 0,
                version_name: valence_protocol::MINECRAFT_VERSION.to_owned(),
                enforce_secure_chat: false,
                view_distance: 10,
                simulation_distance: 10,
                whitelist: xminecraft::whitelist::Whitelist::from_cli(vec!["xmc_vpn_test".to_owned(), "xminecraft".to_owned()], vec![]).unwrap(),
                whitelist_message: "You are not whitelisted on this server.".to_owned(),
                brand: "xminecraft".to_owned(),
                entity_id: 1,
                spawn_y: 64,
                send_play_packets: true,
                rsa_key: xminecraft::test_support::test_rsa_key().clone(),
            },
            vless_id,
            tls: ServerTlsOptions::new(&fixture.cert, &fixture.key).unwrap(),
        };
        let server_task = tokio::spawn(async move {
            if let Ok((tunnel, _)) = tunnel_listener.accept().await {
                handle_server_connection(tunnel, server_config).await
            } else {
                Ok(())
            }
        });

        let client_config = ClientConfig {
            listen: local_addr.to_string(),
            tunnel: tunnel_addr.to_string(),
            target: None,
            preamble: None,
            vless_id,
            tls: ClientTlsOptions::new(&fixture.cert, "localhost".to_owned()).unwrap(),
        };

        let client_task = tokio::spawn(async move {
            if let Ok((raw, _)) = local_listener.accept().await {
                handle_client_connection(raw, client_config).await
            } else {
                Ok(())
            }
        });

        let mut app = TcpStream::connect(local_addr).await.unwrap();
        // SOCKS5 Auth request
        app.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut auth_resp = [0; 2];
        app.read_exact(&mut auth_resp).await.unwrap();
        assert_eq!(&auth_resp, &[0x05, 0x00]);

        // SOCKS5 Connect request
        let mut connect_req = vec![0x05, 0x01, 0x00, 0x01]; // IPv4
        let ip = match target_addr.ip() {
            std::net::IpAddr::V4(v4) => v4.octets(),
            _ => panic!("Expected IPv4"),
        };
        connect_req.extend_from_slice(&ip);
        connect_req.extend_from_slice(&target_addr.port().to_be_bytes());
        app.write_all(&connect_req).await.unwrap();

        // SOCKS5 Connect response
        let mut conn_resp = [0; 10];
        app.read_exact(&mut conn_resp).await.unwrap();
        assert_eq!(&conn_resp[..4], &[0x05, 0x00, 0x00, 0x01]);

        app.write_all(b"socks").await.unwrap();
        app.shutdown().await.unwrap();

        let mut response = Vec::new();
        app.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"works");

        target_task.await.unwrap();
        client_task.await.unwrap().unwrap();
        server_task.await.unwrap().unwrap();
    })
    .await
    .expect("Test timed out");
}

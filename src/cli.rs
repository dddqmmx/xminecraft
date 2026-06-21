use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing::info;
use tracing_subscriber::EnvFilter;
use valence_protocol::uuid::Uuid;

use crate::minecraft::ServerProfile;
use crate::protocol::{ClientPreambleOptions, DEFAULT_USERNAME};
use crate::proxy::{ClientConfig, ServerConfig, run_client, run_server};
use crate::tls::{ClientTlsOptions, ServerTlsOptions};
use crate::vless::{VlessId, VlessTarget};
use crate::whitelist::{Whitelist, parse_uuid};

const DEFAULT_MAX_PACKET_LEN: usize = valence_protocol::MAX_PACKET_SIZE as usize;
const DEFAULT_WHITELIST_MESSAGE: &str = "You are not whitelisted on this server.";

#[derive(Debug, Parser)]
#[command(author, version, about)]
struct Cli {
    #[arg(
        long,
        default_value_t = DEFAULT_MAX_PACKET_LEN,
        global = true,
        help = "Maximum Minecraft packet length to accept"
    )]
    max_packet_len: usize,

    #[arg(
        long,
        default_value_t = valence_protocol::PROTOCOL_VERSION,
        global = true,
        help = "Protocol version written in the Minecraft handshake preamble"
    )]
    protocol_version: i32,

    #[arg(
        long,
        default_value = DEFAULT_USERNAME,
        global = true,
        help = "Username written in the Minecraft login-start preamble"
    )]
    username: String,

    #[arg(
        long,
        global = true,
        help = "Skip the small Minecraft handshake/login preamble used between xminecraft endpoints"
    )]
    no_preamble: bool,

    #[arg(
        long,
        env = "XMINECRAFT_VLESS_ID",
        value_parser = VlessId::parse,
        help = "VLESS UUID used to authenticate clients"
    )]
    vless_id: VlessId,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    #[command(about = "Accept local TCP and send it through a Minecraft chunk-loading tunnel")]
    Client {
        #[arg(long, default_value = "127.0.0.1:1080")]
        listen: String,

        #[arg(long)]
        tunnel: String,

        #[arg(long, value_parser = VlessTarget::parse)]
        target: Option<VlessTarget>,

        #[arg(long)]
        tls_ca_cert: PathBuf,

        #[arg(long)]
        tls_server_name: String,

        #[arg(long, default_value = "xminecraft.local")]
        server_address: String,

        #[arg(long, default_value_t = 25565)]
        server_port: u16,
    },

    #[command(about = "Accept a Minecraft chunk-loading tunnel carrying VLESS+TLS")]
    Server {
        #[arg(long, default_value = "0.0.0.0:25565")]
        listen: String,

        #[arg(long)]
        tls_cert: PathBuf,

        #[arg(long)]
        tls_key: PathBuf,

        #[arg(long)]
        whitelist_file: Option<PathBuf>,

        #[arg(long = "whitelist-user")]
        whitelist_users: Vec<String>,

        #[arg(long = "whitelist-uuid", value_parser = parse_uuid)]
        whitelist_uuids: Vec<Uuid>,

        #[arg(long, default_value = DEFAULT_WHITELIST_MESSAGE)]
        whitelist_message: String,

        #[arg(long, default_value = "A Minecraft Server")]
        motd: String,

        #[arg(long, default_value_t = 20)]
        max_players: i32,

        #[arg(long, default_value_t = 0)]
        online_players: i32,

        #[arg(long, default_value_t = 10)]
        view_distance: i32,

        #[arg(long, default_value_t = 10)]
        simulation_distance: i32,

        #[arg(long, default_value = "xminecraft")]
        brand: String,

        #[arg(long, default_value_t = 1)]
        entity_id: i32,

        #[arg(long, default_value_t = 64)]
        spawn_y: i32,
    },
}

pub async fn run() -> Result<()> {
    init_logging();

    let cli = Cli::parse();
    info!(
        minecraft_version = valence_protocol::MINECRAFT_VERSION,
        protocol_version = cli.protocol_version,
        "starting xminecraft"
    );

    match cli.command {
        Command::Client {
            listen,
            tunnel,
            target,
            tls_ca_cert,
            tls_server_name,
            server_address,
            server_port,
        } => {
            let preamble = (!cli.no_preamble).then_some(ClientPreambleOptions {
                protocol_version: cli.protocol_version,
                server_address,
                server_port,
                username: cli.username,
            });

            run_client(ClientConfig {
                listen,
                tunnel,
                target,
                preamble,
                vless_id: cli.vless_id,
                tls: ClientTlsOptions::new(&tls_ca_cert, tls_server_name)?,
            })
            .await
        }
        Command::Server {
            listen,
            tls_cert,
            tls_key,
            whitelist_file,
            whitelist_users,
            whitelist_uuids,
            whitelist_message,
            motd,
            max_players,
            online_players,
            view_distance,
            simulation_distance,
            brand,
            entity_id,
            spawn_y,
        } => {
            let whitelist = load_whitelist(whitelist_file, whitelist_users, whitelist_uuids)?;
            if whitelist.is_empty() {
                tracing::warn!("Minecraft whitelist is empty. All incoming connections will be rejected.");
            } else {
                info!(entries = whitelist.len(), "Minecraft whitelist enabled");
            }

            let rsa_key = if !cli.no_preamble {
                info!("Generating ephemeral 1024-bit RSA keypair for Minecraft encryption...");
                let mut rng = rand::thread_rng();
                rsa::RsaPrivateKey::new(&mut rng, 1024).context("generating RSA keypair")?
            } else {
                // If preamble is disabled, the connection logic skips login entirely,
                // but we still need a key to satisfy the struct. We can just use the test key
                // or generate a fast dummy key. Generating one takes ~50ms.
                let mut rng = rand::thread_rng();
                rsa::RsaPrivateKey::new(&mut rng, 1024).context("generating RSA keypair")?
            };

            let profile = ServerProfile {
                motd,
                max_players,
                online_players,
                version_name: valence_protocol::MINECRAFT_VERSION.to_owned(),
                enforce_secure_chat: false,
                view_distance,
                simulation_distance,
                whitelist,
                whitelist_message,
                brand,
                entity_id,
                spawn_y,
                rsa_key,
                send_play_packets: true,
            };

            run_server(ServerConfig {
                listen,
                expect_preamble: !cli.no_preamble,
                profile,
                vless_id: cli.vless_id,
                tls: ServerTlsOptions::new(&tls_cert, &tls_key)?,
            })
            .await
        }
    }
}

fn load_whitelist(
    file: Option<PathBuf>,
    users: Vec<String>,
    uuids: Vec<Uuid>,
) -> Result<Whitelist> {
    let mut whitelist = Whitelist::from_cli(users, uuids)?;
    if let Some(path) = file {
        whitelist.extend(Whitelist::load_json(&path)?);
    }
    Ok(whitelist)
}

fn init_logging() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;

    #[test]
    fn test_load_whitelist() {
        let temp_dir = std::env::temp_dir();
        let path = temp_dir.join("test_whitelist.json");
        let mut file = File::create(&path).unwrap();
        let json = r#"
        [
            {
                "uuid": "00000000-0000-0000-0000-000000000001",
                "name": "jeb_"
            }
        ]
        "#;
        file.write_all(json.as_bytes()).unwrap();

        let users = vec!["Notch".to_string()];
        let test_uuid = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
        let uuids = vec![test_uuid];

        let whitelist = load_whitelist(Some(path.clone()), users, uuids.clone()).unwrap();

        assert!(whitelist.is_enabled());
        assert!(whitelist.allows(
            "Notch",
            &Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap()
        )); // by name
        assert!(whitelist.allows("unknown", &test_uuid)); // by cli uuid
        assert!(whitelist.allows(
            "jeb_",
            &Uuid::parse_str("00000000-0000-0000-0000-000000000004").unwrap()
        )); // from file

        std::fs::remove_file(path).unwrap();
    }
}

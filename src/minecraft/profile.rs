use crate::whitelist::Whitelist;
use rsa::RsaPrivateKey;

#[derive(Debug, Clone)]
pub struct ServerProfile {
    pub motd: String,
    pub max_players: i32,
    pub online_players: i32,
    pub version_name: String,
    pub enforce_secure_chat: bool,
    pub view_distance: i32,
    pub simulation_distance: i32,
    pub whitelist: Whitelist,
    pub whitelist_message: String,
    pub brand: String,
    pub entity_id: i32,
    pub spawn_y: i32,
    pub rsa_key: RsaPrivateKey,
    pub send_play_packets: bool,
}

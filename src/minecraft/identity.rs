use md5::{Digest, Md5};
use valence_protocol::uuid::{Builder as UuidBuilder, Uuid};

use crate::protocol::LoginIdentity;

pub(super) fn offline_player_uuid(username: &str) -> Uuid {
    let digest = Md5::digest(format!("OfflinePlayer:{username}").as_bytes());
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&digest);
    UuidBuilder::from_md5_bytes(bytes).into_uuid()
}

pub(super) fn resolve_player_uuid(identity: &LoginIdentity) -> Uuid {
    identity
        .profile_id
        .unwrap_or_else(|| offline_player_uuid(&identity.username))
}

use std::fmt;

use anyhow::{Context, Result};
use valence_protocol::uuid::Uuid;

use crate::protocol::{
    HandshakeInfo, HandshakeNextState, LoginIdentity, UpgradedStream, read_handshake,
};

use super::login::accept_login;
use super::profile::ServerProfile;
use super::status::handle_status;

pub struct AcceptedLogin {
    pub handshake: HandshakeInfo,
    pub identity: LoginIdentity,
    pub uuid: Uuid,
    pub stream: UpgradedStream,
}

pub enum AcceptedSession {
    Status,
    Login(AcceptedLogin),
    Rejected(AcceptedLogin),
}

impl fmt::Debug for AcceptedLogin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AcceptedLogin")
            .field("handshake", &self.handshake)
            .field("identity", &self.identity)
            .field("uuid", &self.uuid)
            .finish()
    }
}

impl fmt::Debug for AcceptedSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Status => write!(f, "Status"),
            Self::Login(l) => f.debug_tuple("Login").field(l).finish(),
            Self::Rejected(l) => f.debug_tuple("Rejected").field(l).finish(),
        }
    }
}

pub async fn accept_session(
    mut stream: UpgradedStream,
    max_packet_len: usize,
    profile: &ServerProfile,
) -> Result<AcceptedSession> {
    let handshake = read_handshake(&mut stream.read, max_packet_len).await?;

    match handshake.next_state {
        HandshakeNextState::Status => {
            handle_status(&mut stream, max_packet_len, profile).await?;
            Ok(AcceptedSession::Status)
        }
        HandshakeNextState::Login => accept_login(stream, max_packet_len, profile, handshake)
            .await
            .context("accepting Minecraft login"),
    }
}

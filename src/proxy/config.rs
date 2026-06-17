use crate::minecraft::ServerProfile;
use crate::protocol::ClientPreambleOptions;
use crate::tls::{ClientTlsOptions, ServerTlsOptions};
use crate::vless::{VlessId, VlessTarget};

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub listen: String,
    pub tunnel: String,
    pub target: Option<VlessTarget>,
    pub preamble: Option<ClientPreambleOptions>,
    pub vless_id: VlessId,
    pub tls: ClientTlsOptions,
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub listen: String,
    pub expect_preamble: bool,
    pub profile: ServerProfile,
    pub vless_id: VlessId,
    pub tls: ServerTlsOptions,
}

# xminecraft

`xminecraft` is a Rust-based TCP tunnel that encapsulates VLESS-over-TLS traffic within Minecraft packet framing. It is designed to bypass network filters by appearing as legitimate Minecraft traffic while providing a secure and authenticated tunnel for arbitrary TCP data.

## Project Overview

- **Purpose**: Secure TCP tunneling over Minecraft protocol.
- **Topology**: `TCP Client -> xminecraft Client -> Minecraft Framing -> TLS -> VLESS -> xminecraft Server -> Target TCP`.
- **Primary Technologies**:
  - **Rust**: Language of implementation (2024 edition).
  - **Tokio**: Asynchronous runtime for high-performance I/O.
  - **Rustls**: Modern TLS implementation for encryption and server validation.
  - **valence_protocol**: Used for low-level Minecraft VarInt and packet encoding/decoding.
  - **Clap**: Robust command-line argument parsing.

## Architecture & Protocol Stack

The project implements a layered protocol stack:

1.  **Minecraft Preamble**: Standard handshake, status, and login phases to simulate a real Minecraft server. Supports whitelisting.
2.  **TLS Layer (`src/tls.rs`)**: Established over the native Minecraft AES stream to provide confidentiality and integrity.
3.  **VLESS Layer (`src/vless/`)**: Provides client authentication (via UUID) and target destination routing.
4.  **Proxy Layer (`src/proxy/`)**: Manages listeners, connection handling, and byte relaying. Includes `local.rs` for dynamic SOCKS5 and HTTP CONNECT proxy protocol sniffing on the client side.

## Building and Running

### Prerequisites
- Rust 1.75+ (Edition 2024)
- TLS certificates for the server endpoint.

### Commands

- **Build**: `cargo build`
- **Run (Server)**:
  ```bash
  cargo run -- --vless-id <UUID> server --listen 0.0.0.0:25565 --tls-cert cert.pem --tls-key key.pem
  ```
- **Run (Client)**:
  ```bash
  # Run as a dynamic SOCKS5 / HTTP Proxy (recommended)
  cargo run -- --vless-id <UUID> client --listen 127.0.0.1:1080 --tunnel server:25565 --tls-ca-cert ca.pem --tls-server-name server.name

  # Run as a static port forwarder
  cargo run -- --vless-id <UUID> client --listen 127.0.0.1:2222 --tunnel server:25565 --target target:port --tls-ca-cert ca.pem --tls-server-name server.name
  ```
- **Test**: `cargo test`

## Development Conventions

- **Asynchronous I/O**: All network logic is async using `tokio`. Avoid blocking calls in the main loop.
- **Error Handling**: Use `anyhow::Result` for application-level errors and `.context()` to provide trace information.
- **Logging**: Use the `tracing` crate. Logs are initialized in `src/cli.rs` and can be controlled via `RUST_LOG`.
- **Testing**:
  - Unit tests are located within module files (e.g., `tests.rs` or `mod tests`).
  - Integration tests are in the `tests/` directory (e.g., `tests/integration.rs`).
  - Use `cargo test` to run all tests with built-in timeouts and extensive coverage of protocol edge cases.
  - Always verify protocol round-trips when modifying packet logic.
- **Formatting**: Adhere to `cargo fmt` standards.

## Module Guide

- `src/main.rs`: Entry point, dispatches to `cli::run()`.
- `src/cli.rs`: CLI definition, config assembly, and logging initialization.
- `src/protocol.rs`: Minecraft packet framing and low-level I/O.
- `src/minecraft/`: Implements the "fake" Minecraft server behavior (Status, Login, Play bootstrap).
- `src/proxy/`: High-level proxy server and client implementation.
- `src/vless/`: VLESS protocol implementation (request/response parsing).
- `src/tls.rs`: Rustls configuration helpers for client and server.
- `src/whitelist.rs`: Minecraft whitelist loading and verification logic.

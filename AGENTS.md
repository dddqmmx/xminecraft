# AGENTS.md - xminecraft

This file helps AI agents work effectively in this repository.

## Build & Test Commands

```bash
# Build
cargo build

# Run all unit tests (fast)
cargo test --lib

# Run integration tests (may be flaky in parallel)
cargo test --test integration integration_full_stack_vless_tls_minecraft -- --nocapture

# Run all tests (including potentially flaky VPN sim)
cargo test

# Lint (recommended before committing)
cargo clippy --all-targets -- -D warnings

# Format
cargo fmt --all --check

# Full CI check
cargo clippy --all-targets -- -D warnings && cargo test --lib && cargo fmt --all --check
```

## Architecture Overview

**xminecraft** is a Rust TCP tunnel encapsulating VLESS-over-TLS inside Minecraft packet framing:
```
TCP Client -> xminecraft Client -> Minecraft Framing -> TLS -> VLESS -> xminecraft Server -> Target TCP
```

**Layer stack:**
1. **Minecraft Preamble** (`src/minecraft/`) - Handshake, status, login, play bootstrap with whitelist
2. **TLS Layer** (`src/tls.rs`) - rustls client/server over native Minecraft AES stream
3. **VLESS Layer** (`src/vless/`) - UUID auth + target routing
4. **Proxy Layer** (`src/proxy/`) - Listeners, connection handling, byte relay

## Key Entry Points

- `src/main.rs` - Entry point, calls `cli::run()`
- `src/cli.rs` - CLI parsing, config assembly, logging init
- `src/proxy/client.rs` - `run_client()`, `handle_client_connection()`
- `src/proxy/server.rs` - `run_server()`, `handle_server_connection()`

## Developer Workflow Gotchas

### 1. ThreadRng and Send Safety
`rand::thread_rng()` returns `ThreadRng` which is not `Send`. Do not use it across `tokio::spawn` boundaries or `.await` points. Use `StdRng::from_entropy()` instead.

### 2. Edition 2024 Keyword Conflicts
`gen` is a reserved keyword in Rust 2024 edition. Use `rng.r#gen()` or `rand::random::<T>()` instead of `rng.gen()`.

### 3. Flaky VPN Integration Test
`integration_1to1_replica_vpn_traffic_simulation` may timeout (60s) when run in parallel with other tests. Run in isolation:
```bash
cargo test integration_1to1_replica_vpn_traffic_simulation -- --nocapture
```

### 4. Test TLS Fixtures Use Weak Keys
`src/test_support.rs` embeds a 1024-bit RSA test certificate. **Do not use in production.**

## Testing Notes

- Unit tests live in `#[cfg(test)] mod tests` within each module
- Integration tests: `tests/integration.rs` (spawns real TCP listeners, uses `TlsFixture`)
- Run single test: `cargo test integration_1to1_replica_vpn_traffic_simulation -- --nocapture`
- Tests use `tokio::time::timeout` (60s for VPN sim, 10s for basic)
- `integration_full_stack_vless_tls_minecraft` is more reliable than the VPN simulation test

## Common Pitfalls

| Issue | Location | Fix |
|-------|----------|-----|
| TLS cert validation fails | Client `--tls-server-name` must match cert SAN | Use exact hostname from cert |
| Whitelist rejects valid users | Case-sensitive username match | Whitelist usernames compared case-insensitively (`whitelist.rs:71`) |

## Non-Obvious Behavior

- **Offline-mode UUIDs**: If `profile_id` not in `LoginHelloC2s`, server derives UUID via MD5(`OfflinePlayer:<username>`) per `src/minecraft/identity.rs`
- **VLESS target parsing**: IPv6 requires brackets (`[::1]:443`), domains must be ASCII (`src/vless/types.rs:130-145`)
- **Protocol version**: Hardcoded to `valence_protocol::PROTOCOL_VERSION` (763 for 1.20.1) but configurable via `--protocol-version`
- **Whitelist**: The whitelist is default-deny. If no whitelist is provided, all incoming Minecraft login attempts are rejected.

## Missing/Recommended Infrastructure

- No CI/CD (GitHub Actions, GitLab CI, etc.)
- No pre-commit hooks
- No `rust-toolchain.toml` (requires Rust 1.75+ for edition 2024)
- No `clippy.toml` or `rustfmt.toml` for consistent style
- No benchmarking setup

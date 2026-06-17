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
2. **Carrier Layer** (`src/carrier/`) - Encodes binary frames into Minecraft play-state packets
3. **TLS Layer** (`src/tls.rs`) - rustls client/server over carrier stream
4. **VLESS Layer** (`src/vless/`) - UUID auth + target routing
5. **Proxy Layer** (`src/proxy/`) - Listeners, connection handling, byte relay

## Key Entry Points

- `src/main.rs` - Entry point, calls `cli::run()`
- `src/cli.rs` - CLI parsing, config assembly, logging init
- `src/proxy/client.rs` - `run_client()`, `handle_client_connection()`
- `src/proxy/server.rs` - `run_server()`, `handle_server_connection()`

## Critical Configuration

All carrier packet IDs **must match** between client and server:
```bash
--chunk-packet-id 0x54 --player-action-packet-id 0x20 --game-state-packet-id 0x1F
```

Defaults come from `valence_protocol::packet_id::*` constants in `src/protocol.rs`.

## Traffic Realism

### Realistic Packet Distribution (`src/carrier/traffic.rs`)
Packet types selected with weighted distribution matching real gameplay:
- Chunk (~55%), PlayerAction (~12%), GameState (~10%), EntityEvent (~8%), WorldTime (~5%), Health (~4%), EntitySpawn (~3%), EntityMove (~3%)

### Monotonic PlayerAction Sequence (`src/carrier/signal.rs:23`)
`PLAYER_ACTION_SEQ` atomic counter replaces `rand::random()`, producing realistic monotonic sequences.

### Entity Lifecycle (`src/carrier/entity.rs`)
EntityManager tracks entity IDs with spawn/move/despawn lifecycle, avoiding random IDs.

### Deterministic Field Generation (`src/carrier/signal.rs`)
Fields derived deterministically from payload data instead of `rand::random()`:
- EntitySpawn/EntityMove: entity ID from atomic counter, positions/yaws from payload bytes
- Health: food/saturation derived from health value
- WorldTime: world_age derived from time_of_day

### Traffic Shaping (`src/proxy/carrier_stream.rs`)
`after_data_delay()` adds 2-20ms per 4KB transferred to simulate network jitter.

## Developer Workflow Gotchas

### 1. ThreadRng and Send Safety
`rand::thread_rng()` returns `ThreadRng` which is not `Send`. Do not use it across `tokio::spawn` boundaries or `.await` points. Use `StdRng::from_entropy()` instead (see `carrier_stream.rs`).

### 2. Edition 2024 Keyword Conflicts
`gen` is a reserved keyword in Rust 2024 edition. Use `rng.r#gen()` or `rand::random::<T>()` instead of `rng.gen()`.

### 3. Flaky VPN Integration Test
`integration_1to1_replica_vpn_traffic_simulation` may timeout (60s) when run in parallel with other tests. Run in isolation:
```bash
cargo test integration_1to1_replica_vpn_traffic_simulation -- --nocapture
```

### 4. Test TLS Fixtures Use Weak Keys
`src/test_support.rs` embeds a 1024-bit RSA test certificate. **Do not use in production.**

### 5. Commented Idle Traffic Code
`src/proxy/carrier_stream.rs` has simplified traffic shaping. Original commented-out idle packet logic has been replaced with lightweight post-write delays.

### 6. Frame Decoder Resync Logic
`src/carrier/frame.rs:108-112` - `find_magic()` scans for `MAGIC` (`XMC1`) to recover from desync. This could be slow on large buffers.

## Testing Notes

- Unit tests live in `#[cfg(test)] mod tests` within each module
- Integration tests: `tests/integration.rs` (spawns real TCP listeners, uses `TlsFixture`)
- Run single test: `cargo test integration_1to1_replica_vpn_traffic_simulation -- --nocapture`
- Tests use `tokio::time::timeout` (60s for VPN sim, 10s for basic)
- `integration_full_stack_vless_tls_minecraft` is more reliable than the VPN simulation test

## Common Pitfalls

| Issue | Location | Fix |
|-------|----------|-----|
| Carrier packet IDs mismatch | CLI defaults vs server config | Verify both ends use identical `--*-packet-id` values |
| TLS cert validation fails | Client `--tls-server-name` must match cert SAN | Use exact hostname from cert |
| Whitelist rejects valid users | Case-sensitive username match | Whitelist usernames compared case-insensitively (`whitelist.rs:71`) |
| Connection hangs on idle | No carrier keepalive | Consider implementing idle frames in `carrier_stream.rs` |

## Non-Obvious Behavior

- **Offline-mode UUIDs**: If `profile_id` not in `LoginHelloC2s`, server derives UUID via MD5(`OfflinePlayer:<username>`) per `src/minecraft/identity.rs`
- **VLESS target parsing**: IPv6 requires brackets (`[::1]:443`), domains must be ASCII (`src/vless/types.rs:130-145`)
- **Frame padding**: Carrier frames padded to 8-byte boundary (`padded_len()` in `frame.rs:197`)
- **Protocol version**: Hardcoded to `valence_protocol::PROTOCOL_VERSION` (763 for 1.20.1) but configurable via `--protocol-version`

## Missing/Recommended Infrastructure

- No CI/CD (GitHub Actions, GitLab CI, etc.)
- No pre-commit hooks
- No `rust-toolchain.toml` (requires Rust 1.75+ for edition 2024)
- No `clippy.toml` or `rustfmt.toml` for consistent style
- No benchmarking setup

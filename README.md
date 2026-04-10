# Emberlink

Local-first identity brokerage with cryptographic multi-root identities, persona-scoped credentials, social trust, guardian recovery, privacy-preserving selective disclosure, and encrypted peer storage.

## Architecture

The Rust workspace contains the protocol, runtime, domain, CLI, relay, and application crates listed in `Cargo.toml`.

## Build and test

```bash
cargo build                    # Build all crates
cargo test                     # Run all tests
cargo clippy --workspace       # Lint (must be zero warnings)
```

## CLI

Interactive shell for identity management, credential brokerage, and peer sync.

```bash
cargo run -p emberlink-cli
```

### Getting started

```bash
# First-launch guided setup (root + device + persona)
init --name "Alice"

# Or create components individually
root create --name "Alice"
device add --root alice --label laptop
persona create --root alice --label Work --template professional
```

### Key command categories

| Category | Examples |
|----------|---------|
| **Identity** | `root create`, `device add`, `persona create`, `persona grant-device` |
| **Trust** | `trust attest`, `trust revoke`, `show trust` |
| **Vault & Disclosure** | `vault write-record`, `vault issue`, `disclose --from --to --template` |
| **Credentials** | `claim store`, `claim list`, `claim disclose` |
| **Passkeys** | `passkey register`, `passkey authenticate`, `passkey list` |
| **Services** | `service bind`, `service list`, `service unbind` |
| **Import** | `import passwords --format bitwarden\|1password --file export.csv` |
| **Recovery** | `recovery guardian-enroll`, `recovery request`, `recovery execute` |
| **Sync** | `sync send`, `sync receive`, `sync mutual`, `sync relay-cycle` |
| **Storage** | `vault store --file`, `vault export-file`, `storage audit` |
| **Invites** | `invite create`, `invite accept` |

Run `help` inside the shell for the full command reference.

## Relay

Headless daemon for asynchronous peer-to-peer message delivery.

```bash
cargo run -p emberlink-relay -- --mode open
cargo run -p emberlink-relay -- --mode trust-gated --threshold 0.5
cargo run -p emberlink-relay -- --mode network-scoped --allow persona-alice
```

Supports TLS (self-signed by default, or bring your own certs), per-peer and global mailbox quotas, and graceful shutdown. See `--help` for all options.

## License

MIT OR Apache-2.0

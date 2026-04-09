# Emberlink

Local-first identity brokerage, social trust, recovery, and reciprocal encrypted peer storage.

This repository contains the Emberlink protocol types, core libraries, and application surfaces.

## Minimal client

The repository includes a Rust-only terminal shell client in `crates/emberlink-cli`. It is still useful for manual testing, but the protocol foundation is now being moved into the core crates.

Run the interactive client:

```bash
cargo run -p emberlink-cli
```

Run a specific screen directly:

```bash
cargo run -p emberlink-cli -- show broker
cargo run -p emberlink-cli -- show state
cargo run -p emberlink-cli -- show recovery
```

Create test data directly from the client:

```bash
cargo run -p emberlink-cli -- root create --name Research Root
cargo run -p emberlink-cli -- device add --root root-a --label laptop
cargo run -p emberlink-cli -- persona create --root root-a --label Operations --template professional
cargo run -p emberlink-cli -- persona create --root root-a --label Alias --profile persona.custom
cargo run -p emberlink-cli -- persona grant-device --persona persona-professional --device laptop
```

Interactive commands:

```text
show broker
show state
show recovery
root create --name <display name>
device add --root <root-id-or-name> --label <device label>
persona create --root <root-id-or-name> --label <persona label> --template <professional|friends|pseudonymous>
persona create --root <root-id-or-name> --label <persona label> --profile <profile-id>
persona grant-device --persona <persona-id-or-label> --device <device-id-or-label>
persona revoke-device --persona <persona-id-or-label> --device <device-id-or-label>
quit
```

Verify the foundation and client:

```bash
cargo test -p core-types -p core-events -p core-state
cargo test -p emberlink-cli
cargo test
```

Reset the local demo state:

```bash
cargo run -p emberlink-cli -- reset
```

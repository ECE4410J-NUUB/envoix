# Packaging the relay (Debian/Ubuntu)

Build a `.deb` with [`cargo-deb`](https://crates.io/crates/cargo-deb):

```sh
cargo install cargo-deb        # once
cargo deb -p envoix-relay-server
# -> target/debian/envoix-relay-server_<version>_<arch>.deb
```

The package installs:

- `/usr/bin/envoix-relay-server`
- `/etc/envoix-relay/config.toml` (conffile; edit then `systemctl restart envoix-relay`)
- `/lib/systemd/system/envoix-relay.service`

and enables the service (it does not start it, so you can edit the config
first). The master key is generated on first start under
`/var/lib/envoix-relay/` (`StateDirectory`).

Typical first run:

```sh
sudo apt install ./envoix-relay-server_*.deb
sudo envoix-relay-server test      # preflight: port, firewall, clock
sudo envoix-relay-server up        # enable on boot + start
envoix-relay-server status         # live stats
```

## Static binary (any Linux, no `.deb`)

A fully static `musl` build runs on any x86_64 Linux with no libc
dependency:

```sh
rustup target add x86_64-unknown-linux-musl     # once
cargo build --release --target x86_64-unknown-linux-musl -p envoix-relay-server
# -> target/x86_64-unknown-linux-musl/release/envoix-relay-server
strip target/x86_64-unknown-linux-musl/release/envoix-relay-server   # optional, ~3.0M
```

Install it by hand:

```sh
sudo install -m755 target/x86_64-unknown-linux-musl/release/envoix-relay-server /usr/bin/
sudo install -Dm644 dist/config.toml /etc/envoix-relay/config.toml
sudo install -Dm644 dist/envoix-relay.service /etc/systemd/system/envoix-relay.service
sudo systemctl daemon-reload
sudo envoix-relay-server test && sudo envoix-relay-server up
```


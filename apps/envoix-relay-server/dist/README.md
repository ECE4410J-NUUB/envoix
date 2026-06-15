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

For systems without `.deb`, use the static binary
(`x86_64-unknown-linux-musl`) and install the unit + config by hand.

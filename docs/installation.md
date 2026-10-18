# Installation and first run

[Documentation index](README.md) · [EmberGate overview](../README.md)

## Run locally

Install a current stable Rust toolchain (at least 1.89 for the locked dependencies), a C/C++ build toolchain, CMake, pkg-config, Perl, and OpenSSL development headers. Pingora targets Linux; see [its build requirements](../pingora/README.md).

On Debian/Ubuntu, the native packages are:

```sh
sudo apt-get install build-essential pkg-config libssl-dev cmake clang
```

On Arch/Garuda:

```sh
sudo pacman -S --needed base-devel cmake clang openssl perl
```

If this terminal was open before Rust was installed, load its shell environment first with `source "$HOME/.cargo/env"` in Bash, or `source "$HOME/.cargo/env.fish"` in Fish.

Clone this repository with `git clone --recurse-submodules https://github.com/karlocizma/EmberGate.git`. For an existing checkout, run `git submodule update --init --recursive` from the repository root. Pingora is pinned as a submodule; a source ZIP alone does not include its source.

From the repository root:

```sh
cd gateway
cargo run --locked
```

Open **http://127.0.0.1:9090**. On a fresh installation, the terminal prints a **one-time setup code**. Enter it on the setup page, choose an administrator password of at least 12 characters, and confirm it. Your username is **admin**. Setup saves an Argon2 hash in the existing local SQLite database and signs you in; future launches use that saved account. An incomplete setup gets a new code on restart. Setup closes once the administrator exists, and simultaneous setup submissions cannot create or overwrite a second administrator. No database server or frontend installation is needed.

Existing environment-based installations still work. **GATEWAY_ADMIN_PASSWORD** is an optional runtime recovery override; its hash seeds the saved admin account if that account does not exist. To switch an existing installation to WebGUI password management, first run this version once with your current admin variable, stop it, then remove that variable and restart. Your original password now works from the saved account. In Fish, use `set --erase GATEWAY_ADMIN_PASSWORD`; in Bash, use `unset GATEWAY_ADMIN_PASSWORD`. Also remove any persisted setting from shell startup files or your service configuration so it is not restored on the next launch. While an override is active, the UI explains why password changes are disabled.

The proxy listens on **127.0.0.1:8080**. The application executable is now `embergate`; update any external service command that still launches `pingora-gateway`.

For a first upstream, run this in another terminal:

```sh
python3 -m http.server 9000 --bind 127.0.0.1
```

Add a host in the dashboard:

| Field | Value |
| --- | --- |
| Name | Local website |
| Hostname | app.localhost |
| Path prefix | / |
| Upstream | http://127.0.0.1:9000 |
| Status | Active |

Then send traffic:

```sh
curl -H 'Host: app.localhost' http://127.0.0.1:8080/
```

The dashboard updates every five seconds. Active means a route is enabled. When health checks are configured, the dashboard shows verified backend health and pool availability separately.
## Docker

The Docker build uses this checkout of Pingora and installs the `embergate` executable. From the repository root:

```sh
docker compose up --build -d
docker compose logs gateway
```

Use the setup code from the logs to create the administrator in the browser. The admin password environment variable is optional. If provided, it acts as the same recovery override described above.

The image build requires the initialized Pingora submodule described above.

The same dashboard and proxy ports are bound to the host's loopback interface. Routes persist in the `gateway-data` volume. Inside a container, `127.0.0.1` refers to that container: use a reachable upstream address or another Compose service name.

Pingora uses a five-minute grace period for SIGTERM shutdowns; Compose allows 310 seconds for draining. Ctrl+C (SIGINT) stops the local process quickly. The integration test uses SIGINT after its requests finish to verify loading saved routes without waiting through the drain period.

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

GitHub Actions builds, tests, and publishes the Linux amd64 image to `ghcr.io/karlocizma/embergate`. Download [compose.yaml](../compose.yaml) and [.env.example](../.env.example) into a deployment directory; no source checkout, submodules, or compiler is needed on the server:

```sh
cp .env.example .env
# Edit .env before starting the containers.
docker compose pull
docker compose up -d --no-build
docker compose logs gateway
```

Use the setup code from the logs to create the administrator in the browser. The admin password environment variable is optional. If provided, it acts as the same recovery override described above.

Repeat `docker compose pull` and `docker compose up -d --no-build` to update. Existing named volumes are retained. The `latest` tag tracks successful builds of `main`; Git tags beginning with `v` also publish the matching image tag, and every published build has a `sha-<full commit SHA>` tag. Pin a release or commit in `.env`, for example `EMBERGATE_IMAGE=ghcr.io/karlocizma/embergate:v0.3.1` once that release exists. To roll back, select a previous image tag and run the same pull/start commands.

After the first workflow publication, make the package public in GitHub's package settings to allow anonymous pulls. If you keep it private, first run `docker login ghcr.io -u YOUR_GITHUB_USERNAME` with a personal access token (classic) with `read:packages` and access to the package.

For the two-node example, download both [cluster-compose.yaml](../deploy/cluster-compose.yaml) and [haproxy.cfg](../deploy/haproxy.cfg) into the same directory, then run `docker compose -f cluster-compose.yaml up -d --pull always --no-build`. Both gateway services use `EMBERGATE_IMAGE` in the same way.

To build from source instead, initialize the Pingora submodule as described above, run `docker build -t embergate:local .` from the repository root, then run `EMBERGATE_IMAGE=embergate:local docker compose up -d --no-build`.

The dashboard and proxy ports default to the host's loopback interface. For a Docker VM, set `GATEWAY_BIND_ADDRESS` in `.env` to its LAN IP, or `0.0.0.0` to listen on all IPv4 interfaces. Allow access through the VM firewall and restrict admin port 9090 to your trusted network. The VM network must be reachable from your LAN. This bind setting applies to the single-node `compose.yaml`; edit published port addresses separately in the cluster example. Routes persist in the `gateway-data` volume. Inside a container, `127.0.0.1` refers to that container: use a reachable upstream address or another Compose service name.

Pingora uses a five-minute grace period for SIGTERM shutdowns; Compose allows 310 seconds for draining. Ctrl+C (SIGINT) stops the local process quickly. The integration test uses SIGINT after its requests finish to verify loading saved routes without waiting through the drain period.

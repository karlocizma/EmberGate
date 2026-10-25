# EmberGate

**A self-hosted reverse proxy with a modern management dashboard. Powered by Pingora.**

Manage proxy hosts, certificates, traffic policies, and backups from one web UI.
EmberGate is built in Rust, embeds its dashboard in the binary, and stores its
state locally. No frontend build or database server is required.

[Website](https://embergate.niftyisle1.chatgpt.site) · [Documentation](docs/README.md) · [Roadmap](ROADMAP.md) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)

## Features

- **Proxy management:** live host changes, path routing, upstream pools, health checks, load balancing, and safe failover.
- **Docker containers:** see running containers on the Docker host and expose one as a proxy host in a click, through a read-only socket proxy.
- **HTTPS automation:** upload certificates or issue and renew them with Let's Encrypt and Cloudflare DNS-01.
- **Traffic controls:** caching, Brotli/gzip compression, rate limits, IP rules, application login protection, OpenID Connect single sign-on, redirects, rewrites, and security headers.
- **Threat protection:** CrowdSec decisions with a custom ban page and Cloudflare Turnstile challenges, plus an nginx-format access log CrowdSec can analyze.
- **Visibility:** persistent analytics, request logs, diagnostics, Prometheus metrics, and Discord/webhook alerts.
- **Administration:** accounts, passkeys, two-factor authentication, scoped API tokens with a command-line client, host templates, configuration history, and encrypted backups with scheduled offsite copies.
- **Multiple instances:** encrypted primary/follower route and certificate replication with readiness checks and a failover deployment example.
- **Dashboard:** responsive light/dark themes, dedicated settings pages, and built-in searchable documentation.

## Quick start

Use Linux with stable Rust (1.89+) and the native build dependencies. On Debian/Ubuntu:

```sh
sudo apt-get install build-essential pkg-config libssl-dev cmake clang perl

git clone --recurse-submodules https://github.com/karlocizma/EmberGate.git
cd EmberGate/gateway
cargo run --locked
```

Open **http://127.0.0.1:9090**. Enter the one-time setup code printed in the
terminal, then create your administrator password. The username is **admin**.

The HTTP proxy listens on **127.0.0.1:8080** by default. Add a proxy host in the
dashboard to route traffic to your application. Cloudflare credentials can be
saved in **Settings → Cloudflare DNS**.

See the [installation guide](docs/installation.md) for other Linux distributions,
a first upstream example, and existing-installation setup. Already cloned?
Run `git submodule update --init --recursive` to fetch Pingora.

## Docker

Clone the repository to get the deployment files. Prebuilt images require no submodules or compiler:

```sh
git clone https://github.com/karlocizma/EmberGate.git
cd EmberGate
cp .env.example .env
# Edit .env to select the image version and optional integrations.
docker compose pull
docker compose up -d --no-build
docker compose logs gateway
```

Use the setup code from the logs at **http://YOUR_SERVER_IP:9090**. The supplied Compose
configuration publishes HTTP on port **80**, HTTPS on **443**, and management on
**9090** using plain Docker port mappings on all host interfaces. Restrict management
port 9090 to your trusted network. State persists in a named volume.
See [Docker deployment details](docs/installation.md#docker).

## Documentation

Guides are also available inside EmberGate under **Help & documentation**, with contextual links from settings.

- [Proxy hosts and traffic policies](docs/proxy.md)
- [HTTPS and Cloudflare certificates](docs/certificates.md)
- [Settings, accounts, and backups](docs/administration.md)
- [Monitoring and diagnostics](docs/monitoring.md)
- [Testing and verification](docs/testing.md)

## Project status

EmberGate is under active development. See the [roadmap](ROADMAP.md) for planned
features and remaining release validation, and [GitHub Actions](https://github.com/karlocizma/EmberGate/actions)
for CI results.

EmberGate is an independent project, not an official Cloudflare product.
Licensed under [Apache 2.0](LICENSE). Pingora and other dependencies retain their
own licenses and notices; see [third-party notices](THIRD_PARTY_NOTICES.md).

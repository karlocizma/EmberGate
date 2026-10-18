# EmberGate

**A self-hosted reverse proxy with a modern management dashboard. Powered by Pingora.**

Manage proxy hosts, certificates, traffic policies, and backups from one web UI.
EmberGate is built in Rust, embeds its dashboard in the binary, and stores its
state locally. No frontend build or database server is required.

[Documentation](docs/README.md) · [Roadmap](ROADMAP.md) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)

## Features

- **Proxy management:** live host changes, path routing, upstream pools, health checks, load balancing, and safe failover.
- **HTTPS automation:** upload certificates or issue and renew them with Let's Encrypt and Cloudflare DNS-01.
- **Traffic controls:** caching, Brotli/gzip compression, rate limits, IP rules, redirects, rewrites, and security headers.
- **Visibility:** persistent analytics, request logs, diagnostics, Prometheus metrics, and Discord/webhook alerts.
- **Administration:** accounts, two-factor authentication, host templates, configuration history, and encrypted backups with scheduled offsite copies.
- **Dashboard:** responsive light/dark themes and dedicated settings pages.

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

From a checkout with submodules initialized:

```sh
docker compose up --build -d
docker compose logs gateway
```

Use the setup code from the logs at **http://127.0.0.1:9090**. The supplied Compose
configuration binds ports to loopback and persists state in a named volume.
See [Docker deployment details](docs/installation.md#docker).

## Documentation

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

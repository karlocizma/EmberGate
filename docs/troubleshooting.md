# Troubleshooting

[Documentation index](README.md) · [EmberGate overview](../README.md)

## The dashboard will not open

Check that EmberGate is running and read its startup output. The default dashboard address is **http://127.0.0.1:9090**. With Compose, use `docker compose logs gateway`. A listener already in use prevents startup; choose a free address with `GATEWAY_ADMIN_ADDR` or stop the conflicting service. The supplied Compose ports bind to loopback, so a remote browser cannot reach them directly.

## Rust or native dependencies are missing

Install the dependencies in the [installation guide](installation.md). If Rust was just installed, open a new terminal or load its shell environment. Run `cargo run --locked` from `gateway/`; the compiled program is named `embergate`. Initialize the framework with `git submodule update --init --recursive` from the repository root if Pingora source files are missing.

## Signing in or changing a password fails

On a fresh installation, enter the one-time setup code from the current process's startup output. Restarting before completing setup replaces that code. Existing installations use their saved administrator account. An active `GATEWAY_ADMIN_PASSWORD` environment override disables dashboard password changes for that account; follow the migration steps in the [installation guide](installation.md). If two-factor authentication is enabled, use the authenticator or an unused recovery code and check that the device clock is correct.

## A proxy host returns an error

Check that the host is enabled and that the request hostname and path match its route. For a local test, use `curl -H 'Host: app.localhost' http://127.0.0.1:8080/`. Use **Diagnostics** as an administrator to preview routing and test a saved backend, then inspect **Traffic logs**. Check for maintenance mode, access rules, rate limits, and a pool with no eligible backends. Health-checked backends need a successful probe after startup; drained backends do not receive new requests.

A container's `127.0.0.1` is the container itself. Use a reachable upstream address or another Compose service name. HTTPS upstreams must present a certificate valid for the configured hostname. See [proxy hosts](proxy.md) and [monitoring](monitoring.md) for policy behavior and diagnostics limits.

## A Cloudflare certificate request fails

Open **Settings → Cloudflare DNS** and check that a token is configured with the required zone permissions. Review the certificate order status, zone access, domain names, and DNS propagation. Use Let's Encrypt staging first while testing. A working token does not guarantee that public DNS has propagated yet. See the [certificate guide](certificates.md#automatic-certificates-with-cloudflare-dns) before retrying or switching to production.

## Caching or compression does not activate

Both are opt-in per host. Private, authenticated, cookie-bearing, or otherwise ineligible responses can bypass caching or compression. Review the origin's headers, response type, configured size limits, and the visitor's Accept-Encoding header. Streaming event responses and already encoded responses are excluded from compression. **Caching** shows storage and per-host activity; the [proxy guide](proxy.md#response-caching) explains admission rules.

## Backups need attention after a restore

A full restore is queued for the next restart and pauses management edits and automation until it completes or is cancelled. Restoring signs out existing sessions. Sign in with an account from the backup and its authenticator or recovery code when required. Scheduled backup encryption passphrases are deliberately excluded from exported snapshots, so re-enter one before resuming automatic backups. See the [backup guide](administration.md#full-backup-and-restore).

## Collecting information for a bug report

Include the EmberGate version or commit, operating system, installation method, steps to reproduce, and sanitized logs. Remove passwords, API tokens, setup/recovery codes, certificate private keys, and private host information. Do not attach the data directory or full backups. Report suspected vulnerabilities privately as described in the repository's [security policy](../SECURITY.md).

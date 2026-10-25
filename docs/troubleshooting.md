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

A container's `127.0.0.1` is the container itself. Use a reachable upstream address or another Compose service name. HTTPS upstreams must present a certificate valid for the configured hostname unless you explicitly disable **Verify upstream TLS certificate** in the host editor for that host. That exception accepts untrusted and mismatched certificates; use it only on a private network. See [proxy hosts](proxy.md) and [monitoring](monitoring.md) for policy behavior and diagnostics limits.

## A certificate request fails

For **HTTP validation**, check that port 80 for the name reaches EmberGate from the internet: run `curl -i http://<name>/.well-known/acme-challenge/test` from outside your network (for example on a phone without Wi-Fi). The answer should come from EmberGate or the application behind it, not from a router page, a timeout, or another server. A CDN or proxy in front of the name must pass that path through to EmberGate. Wildcard names always need DNS validation.

For **DNS validation**, open **Settings → DNS provider** and check that a provider is configured. The certificate order's error names the step that failed:

- **No zone found:** the credential cannot see the zone, or the name is not hosted by that provider. Check the token's permissions and, for RFC 2136, the **Zones** field.
- **API rejected the request:** the credential is wrong, expired, or lacks write access. Errors show the HTTP status only, never the response body.
- **Not delegated to acme-dns:** add the `_acme-challenge` CNAME shown in the error and wait until `dig CNAME _acme-challenge.<name>` returns it.
- **RFC 2136 refused or TSIG key not accepted:** check the key name, algorithm, secret, the server's update policy, and that the gateway's clock is correct.
- **Propagation timed out:** the record was written but public DNS did not return it in time. Check that the zone's authoritative servers serve it, then retry.

Use Let's Encrypt staging first while testing. See the [certificate guide](certificates.md#choosing-a-dns-provider) before retrying or switching to production.

## Caching or compression does not activate

Both are opt-in per host. Private, authenticated, cookie-bearing, or otherwise ineligible responses can bypass caching or compression. Review the origin's headers, response type, configured size limits, and the visitor's Accept-Encoding header. Streaming event responses and already encoded responses are excluded from compression. **Caching** shows storage and per-host activity; the [proxy guide](proxy.md#response-caching) explains admission rules.

## Backups need attention after a restore

A full restore is queued for the next restart and pauses management edits and automation until it completes or is cancelled. Restoring signs out existing sessions. Sign in with an account from the backup and its authenticator or recovery code when required. Scheduled backup encryption passphrases are deliberately excluded from exported snapshots, so re-enter one before resuming automatic backups. See the [backup guide](administration.md#full-backup-and-restore).

## Single sign-on fails

- **The provider reports a redirect URI mismatch:** register the exact address EmberGate lists in **Settings → Single sign-on**, including `https://` and, for hosts, the path prefix: `https://<host><path prefix>/.well-known/embergate/oidc/callback`. Dashboard sign-in uses the **Dashboard address** you entered, so open the dashboard at that address.
- **"No enabled EmberGate account matches your identity":** the dashboard needs an existing, enabled account named after the identity's email. Check that the provider sends `email` with `email_verified: true` and that the `email` scope is requested.
- **"Your account uses EmberGate two-factor authentication":** sign in with your password, or turn on **The provider enforces two-factor authentication** if it really does.
- **A host shows "not allowed":** the visitor signed in, but no rule matched. Email rules need a verified email; group rules compare the claim named in **Groups claim** case-sensitively. Many providers only include groups when a `groups` scope or mapper is configured.
- **"The identity provider could not be reached":** check that EmberGate can resolve and reach the issuer over HTTPS. Add a private CA under [Private certificate authorities](proxy.md#private-certificate-authorities) if the provider uses one.

## CrowdSec does not block anyone

Open **Settings → Threat protection**. If the CrowdSec status shows an error, check the Local API URL and bouncer key (`cscli bouncers list`). If it shows zero decisions, check `cscli decisions list` on the CrowdSec side. Blocks need the real visitor address: behind another proxy or Cloudflare, configure **Trusted proxies** first. Decision types other than `ban` and `captcha` are counted but not enforced.

If the agent never creates decisions from EmberGate traffic, make sure the access log is turned on, the log directory is mounted into the CrowdSec container, and the acquisition file uses `type: nginx`. CrowdSec only follows files that exist when it starts, so restart it once after first enabling the log. `cscli metrics` shows whether it reads lines. See [CrowdSec threat protection](administration.md#crowdsec-threat-protection).

## An API token or the command-line client is refused

`401` (CLI exit code `3`) means the token is missing, mistyped, revoked, or expired, or its account is disabled. Send it as `Authorization: Bearer eg_…`. `403` means the token is valid but not allowed: read-only tokens cannot change anything, and no token can manage accounts, sessions, passwords, two-factor authentication, passkeys, or tokens. `429` means too many invalid tokens came from your address; wait a minute. See [API tokens](administration.md#api-tokens).

## Collecting information for a bug report

Include the EmberGate version or commit, operating system, installation method, steps to reproduce, and sanitized logs. Remove passwords, API tokens, setup/recovery codes, certificate private keys, and private host information. Do not attach the data directory or full backups. Report suspected vulnerabilities privately as described in the repository's [security policy](../SECURITY.md).

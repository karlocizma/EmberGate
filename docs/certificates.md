# HTTPS and certificate automation

[Documentation index](README.md) · [EmberGate overview](../README.md)

## HTTPS and certificates

Local runs keep HTTPS disabled unless a listener address is set. In Fish, from `gateway/` after signing in to the dashboard:

```fish
set -gx GATEWAY_HTTPS_ADDR 127.0.0.1:8443
cargo run --locked
```

In Bash, use `export GATEWAY_HTTPS_ADDR=127.0.0.1:8443` before running. Compose enables the HTTPS listener on port 8443 automatically.

Open **Certificates** in the dashboard and upload a PEM certificate chain and its matching unencrypted PEM private key. The leaf certificate comes first, followed by any intermediate certificates. Certificates must have DNS subject alternative names and be currently valid. The gateway checks key matching, chain signatures, and validity dates before saving. A certificate's issuer must still be trusted by clients; uploading a self-signed certificate does not make it publicly trusted.

The proxy selects a certificate using the client's SNI hostname. Exact DNS names take priority over wildcard certificates; `*.example.com` matches `app.example.com`, but not `example.com` or `a.b.example.com`. Uploading duplicate DNS names is rejected; use **Replace** to renew an existing certificate. Upload, replacement, and deletion apply to new TLS connections immediately. Existing connections continue. Missing, unknown, or expired certificates cause TLS handshakes to fail. Changing the HTTPS listener address requires a restart.

Certificate metadata includes domain names, validity, expiry, and a SHA-256 fingerprint. Private keys are stored unencrypted in `certificates.json` with Unix permissions `0600`; API responses and route exports contain no key material. Certificates persist across restarts.

To load an updated dashboard or application, stop your running instance with Ctrl+C, run `cargo run --locked` again, and refresh the browser. Dashboard assets are embedded in the binary.
## Automatic certificates with Cloudflare DNS

Create a [Cloudflare API token](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/) with **Zone → DNS → Edit** and **Zone → Zone → Read**. Scope its resources to only the zones the gateway should manage. DNS Edit allows challenge creation/removal; Zone Read allows the gateway to find the correct zone for each name.

Open **Settings → Cloudflare DNS**, paste the API token, and select **Save token**. Saving or replacing a token applies immediately to the running certificate engine and persists across restart. Saving validates token formatting; its actual zone permissions are checked when certificate automation accesses Cloudflare. The input is cleared after saving, and saved values are never returned to the browser or included in audit events/configuration exports.

Use **Remove token** to pause issuance and renewal. Changes are blocked while a certificate operation is running; removal is also blocked while DNS cleanup records remain pending. A replacement token can be saved after a failed operation to recover cleanup, but it must have access to the same zones.

Set the optional TLS listener at startup if clients connect directly to this gateway. In Fish:

```fish
set -gx GATEWAY_HTTPS_ADDR 127.0.0.1:8443
cargo run --locked
```

Environment-based deployments remain supported: **GATEWAY_CLOUDFLARE_API_TOKEN_FILE** overrides **GATEWAY_CLOUDFLARE_API_TOKEN**, which overrides the saved token. While either environment source is active, web credential editing is disabled. To switch to web settings, remove those variables (Fish: `set --erase GATEWAY_CLOUDFLARE_API_TOKEN GATEWAY_CLOUDFLARE_API_TOKEN_FILE`; Bash: `unset GATEWAY_CLOUDFLARE_API_TOKEN GATEWAY_CLOUDFLARE_API_TOKEN_FILE`), restart, and save the token in Settings. Environment tokens are not automatically copied into the database. Compose passes the optional token variable through.

The saved token lives in **management.sqlite3**, protected by Unix permissions 0600. Unlike passwords, it must remain retrievable for DNS API calls, so it is stored **unencrypted at rest**. Protect the gateway's data directory and backups. Certificate private keys and ACME account credentials already use the same private local-storage model. No external database server is required.

In **Certificates → Request certificate**:

1. Enter a name, contact email, and DNS names such as `example.com` and `*.example.com`.
2. Leave **Let's Encrypt staging** selected for the first test. Staging certificates are not browser trusted.
3. Enable automatic renewal and accept the subscriber agreement.
4. Submit and follow progress in **Automatic certificates**.
5. After a successful staging request, use **Use production** to request a trusted certificate for the same names. Confirm the production request and subscriber agreement. The current certificate remains installed until the replacement is ready. You can also select production when creating a new request.

DNS-01 supports wildcard certificates and does not require exposing the proxy's HTTP port for validation. The domain must have public DNS hosted in an accessible Cloudflare zone. [Let's Encrypt DNS-01 documentation](https://letsencrypt.org/docs/challenge-types/#dns-01-challenge)

The gateway creates only `_acme-challenge` TXT records, waits until public DNS returns each challenge value, validates the order, and installs the resulting certificate and key atomically. Multiple values at the same name are preserved, including when issuing an apex and wildcard together. Cleanup removes only records carrying this request's ownership marker and exact value. It preserves unrelated TXT records. Direct Cloudflare challenge records are supported; CNAME-delegated challenge zones and other DNS providers are not supported in this version.

Renewal is scheduled one-third of the certificate lifetime before expiry, capped at a 30-day lead time. The worker checks schedules at least once per minute while running. Failures keep the installed certificate and schedule retries after 1, 2, 4, 8, then at most 16 hours. **Renew now** requests an earlier replacement. **Stop management** stops issuance/renewal but leaves an installed certificate available for manual management. Stop management before manually replacing or deleting a managed certificate; conflicting manual uploads are rejected.

ACME account credentials and request/DNS recovery state are stored in `acme-account-*.json` and `acme.json` with Unix permissions `0600`. They are unencrypted at rest. Account credentials are reused across restarts, with separate accounts for different directory URLs/contact emails. Interrupted requests recover ownership records and retry cleanup after restart. Keep the gateway running and its data volume persistent for automatic renewal. A SIGTERM during an in-progress request can interrupt it; recovery runs on the next start.

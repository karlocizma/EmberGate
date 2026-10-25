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

## Choosing a validation method

Let's Encrypt only issues a certificate after EmberGate proves it controls each name. Choose the method per certificate under **Validation** in **Certificates → Request certificate**:

| | HTTP validation | DNS validation |
| --- | --- | --- |
| Needs | Port 80 reachable from the internet for each name | Credentials for a [supported DNS provider](#choosing-a-dns-provider) |
| Wildcards (`*.example.com`) | No | Yes |
| Names only reachable on your LAN or through a tunnel | No | Yes |
| Credentials stored on the gateway | None | DNS provider credentials |

HTTP validation is the simplest choice for public sites. Use DNS validation for wildcards, internal names, or when port 80 is not forwarded to EmberGate.

## Automatic certificates with HTTP validation

1. Point each name's public DNS record at the address where EmberGate receives traffic, and forward port **80** to EmberGate's HTTP listener (the Compose file maps host port 80). Port 443 alone is not enough.
2. In **Certificates → Request certificate**, enter the names, choose **HTTP · EmberGate answers on port 80**, keep **Let's Encrypt staging** for the first test, and submit.
3. After the staging certificate is active, select **Use production**.

Let's Encrypt then requests `http://<name>/.well-known/acme-challenge/<token>` from several locations. EmberGate answers those requests itself before routing, so the name does not need a proxy host yet, and HTTPS redirects, maintenance pages, access rules, and CrowdSec decisions on existing hosts do not interfere. Tokens are answered only for the name being validated and only while the request runs. Nothing is written to DNS.

Validation fails when port 80 is closed or forwarded elsewhere, when an upstream proxy or CDN answers the path itself instead of passing it to EmberGate, or when the name resolves to a different address. Let's Encrypt follows redirects to HTTPS on port 443, and EmberGate answers there as well. The request's error then shows the certificate authority's reason. Renewals use the same method automatically. With [multiple instances](administration.md#multiple-instances), the primary runs certificate requests, so port 80 traffic for the name must reach the primary during validation.

## Choosing a DNS provider

DNS validation needs one DNS provider, configured in **Settings → DNS provider**. Pick the one that hosts your domain's DNS:

| Provider | Use it when | Section |
| --- | --- | --- |
| Cloudflare | Your zone is on Cloudflare | [Cloudflare DNS](#automatic-certificates-with-cloudflare-dns) |
| Hetzner, deSEC, DigitalOcean, Porkbun, Gandi, IONOS | Your zone is hosted there | [DNS provider APIs](#dns-provider-apis) |
| RFC 2136 | You run your own DNS server (BIND, PowerDNS, Knot, Technitium) | [RFC 2136 dynamic updates](#rfc-2136-dynamic-updates) |
| acme-dns | Any other registrar, or you don't want zone credentials on the gateway | [acme-dns](#acme-dns) |

Only one provider is active at a time. Saving a provider applies immediately, replaces the previous one, and persists across restarts. Secret fields are never shown again; leave one blank to keep its saved value when you change other fields. The provider cannot be switched or removed while DNS cleanup is pending for an earlier request. Credentials live unencrypted in `management.sqlite3` (see below) and are included in full backups, but not in configuration exports.

## Automatic certificates with Cloudflare DNS

Create a [Cloudflare API token](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/) with **Zone → DNS → Edit** and **Zone → Zone → Read**. Scope its resources to only the zones the gateway should manage. DNS Edit allows challenge creation/removal; Zone Read allows the gateway to find the correct zone for each name.

Open **Settings → DNS provider**, choose **Cloudflare**, paste the API token, and select **Save provider**. Saving or replacing a token applies immediately to the running certificate engine and persists across restart. Saving validates token formatting; its actual zone permissions are checked when certificate automation accesses Cloudflare. The input is cleared after saving, and saved values are never returned to the browser or included in audit events/configuration exports.

Use **Remove provider** to pause DNS-validated issuance and renewal. Changes are blocked while a certificate operation is running; removal is also blocked while DNS cleanup records remain pending. A replacement token can be saved after a failed operation to recover cleanup, but it must have access to the same zones.

Set the optional TLS listener at startup if clients connect directly to this gateway. In Fish:

```fish
set -gx GATEWAY_HTTPS_ADDR 127.0.0.1:8443
cargo run --locked
```

Environment-based deployments remain supported: **GATEWAY_CLOUDFLARE_API_TOKEN_FILE** overrides **GATEWAY_CLOUDFLARE_API_TOKEN**, which overrides the saved token. While either environment source is active, web credential editing is disabled. To switch to web settings, remove those variables (Fish: `set --erase GATEWAY_CLOUDFLARE_API_TOKEN GATEWAY_CLOUDFLARE_API_TOKEN_FILE`; Bash: `unset GATEWAY_CLOUDFLARE_API_TOKEN GATEWAY_CLOUDFLARE_API_TOKEN_FILE`), restart, and save the token in Settings. Environment tokens are not automatically copied into the database. Compose passes the optional token variable through.

The saved token lives in **management.sqlite3**, protected by Unix permissions 0600. Unlike passwords, it must remain retrievable for DNS API calls, so it is stored **unencrypted at rest**. Protect the gateway's data directory and backups. Certificate private keys and ACME account credentials already use the same private local-storage model. No external database server is required.

In **Certificates → Request certificate**:

1. Enter a name, contact email, and DNS names such as `example.com` and `*.example.com`, and choose **DNS · temporary TXT record** under **Validation**.
2. Leave **Let's Encrypt staging** selected for the first test. Staging certificates are not browser trusted.
3. Enable automatic renewal and accept the subscriber agreement.
4. Submit and follow progress in **Automatic certificates**.
5. After a successful staging request, use **Use production** to request a trusted certificate for the same names. Confirm the production request and subscriber agreement. The current certificate remains installed until the replacement is ready. You can also select production when creating a new request.

DNS-01 supports wildcard certificates and does not require exposing the proxy's HTTP port for validation. The domain's public DNS must be hosted by the configured provider, or delegated to acme-dns. [Let's Encrypt DNS-01 documentation](https://letsencrypt.org/docs/challenge-types/#dns-01-challenge)

The gateway creates only `_acme-challenge` TXT records, waits until public DNS returns each challenge value, validates the order, and installs the resulting certificate and key atomically. Multiple values at the same name are preserved, including when issuing an apex and wildcard together. Cleanup removes only records carrying this request's ownership marker and exact value. It preserves unrelated TXT records. With Cloudflare, a challenge name that is a CNAME is refused, because the TXT record would be ignored; use [acme-dns](#acme-dns) for delegated names.

Renewal is scheduled one-third of the certificate lifetime before expiry, capped at a 30-day lead time. The worker checks schedules at least once per minute while running. Failures keep the installed certificate and schedule retries after 1, 2, 4, 8, then at most 16 hours. **Renew now** requests an earlier replacement. **Stop management** stops issuance/renewal but leaves an installed certificate available for manual management. Stop management before manually replacing or deleting a managed certificate; conflicting manual uploads are rejected.

ACME account credentials and request/DNS recovery state are stored in `acme-account-*.json` and `acme.json` with Unix permissions `0600`. They are unencrypted at rest. Account credentials are reused across restarts, with separate accounts for different directory URLs/contact emails. Interrupted requests recover ownership records and retry cleanup after restart. Keep the gateway running and its data volume persistent for automatic renewal. A SIGTERM during an in-progress request can interrupt it; recovery runs on the next start.

## DNS provider APIs

Choose the provider in **Settings → DNS provider**, enter its credentials, and select **Save provider**. EmberGate finds the zone for each name, adds one `_acme-challenge` TXT value, and removes exactly that value afterwards; other TXT values at the same name stay. Give each credential the least access the provider allows:

| Provider | Credential | Least privilege |
| --- | --- | --- |
| Hetzner | API token from the [Hetzner Console](https://console.hetzner.com/) project that holds the zones (**Security → API tokens**, read & write) | Put DNS zones in their own project so the token cannot touch servers. Zones still on the old dns.hetzner.com service must be migrated to the Console first. |
| deSEC | Token from [desec.io](https://desec.io/tokens) | Add a token policy that allows writing only `_acme-challenge` TXT records. |
| DigitalOcean | Personal access token with custom scopes | `domain:read`, `domain:create`, `domain:update`, `domain:delete` only. |
| Porkbun | API key and secret API key | Turn on **API access** for each domain; keys work only for domains where it is on. |
| Gandi | Personal access token | Restrict it to the domains you use, with **Manage domain name technical configurations**. |
| IONOS | API key as `<public prefix>.<secret>` from the [developer portal](https://developer.hosting.ionos.com/) | IONOS keys cover every zone in the account; use a separate account for the domains if that matters. |

Minimum TTLs differ: challenge records use 60 seconds where allowed, 300 on Gandi, 600 on Porkbun, and 3600 on deSEC. A long TTL does not slow validation, because the record is new. Route 53 and OVH are planned on request; until then use [acme-dns](#acme-dns).

## RFC 2136 dynamic updates

For a DNS server you run yourself, EmberGate sends signed dynamic updates (RFC 2136 with TSIG) over TCP to the primary server. Create a key and allow it to update only TXT records. For BIND:

```text
key "embergate." { algorithm hmac-sha256; secret "<base64 secret>"; };
zone "example.com" {
  type primary; file "example.com.zone";
  update-policy { grant embergate. subdomain example.com. TXT; };
};
```

Generate the secret with `tsig-keygen -a hmac-sha256 embergate.` (BIND) or your server's key tool. PowerDNS needs `dnsupdate=yes` and a TSIG key allowed for the zone (`pdnsutil generate-tsig-key` and `ALLOW-DNSUPDATE-FROM`/`TSIG-ALLOW-DNSUPDATE` metadata); Knot uses an `acl` with `action: update` and `update-type: TXT`; Technitium has **Zone Options → Dynamic Updates (RFC 2136)** with a TSIG key.

In **Settings → DNS provider**, choose **RFC 2136** and enter the server (`ns1.example.com` or `192.0.2.53:53`), the zones the key may update (comma-separated), the key name, the algorithm (`hmac-sha256` or `hmac-sha512`), and the base64 secret. EmberGate verifies the server's signature on every answer. Updates are refused when the gateway's clock is more than five minutes off, so keep NTP running. The public DNS check still applies: the zone must be served publicly, because Let's Encrypt resolves it from the internet.

## acme-dns

[acme-dns](https://github.com/joohoi/acme-dns) is a small DNS server that only serves challenge records. Your main zone gets a one-time CNAME, and EmberGate only holds credentials for the acme-dns account, which cannot change anything else. This works with any registrar.

1. Run acme-dns or use a server you trust, and register an account: `curl -X POST https://auth.example.net/register`. Keep the `username`, `password`, `subdomain`, and `fulldomain` it returns.
2. At your DNS host, add `_acme-challenge.example.com CNAME <fulldomain>` for each name. One account can serve a name and its wildcard (`example.com` and `*.example.com` share `_acme-challenge.example.com`).
3. In **Settings → DNS provider**, choose **acme-dns** and enter the server URL, username, password, and subdomain.

Before each challenge EmberGate checks in public DNS that the CNAME points at the account's subdomain and explains what to add if not. acme-dns keeps the two newest values per account, so a certificate may contain at most two names; request separate certificates for more names, or use another provider. Old values need no cleanup.

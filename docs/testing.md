# Testing and verification

[Documentation index](README.md) · [EmberGate overview](../README.md)

## CI caches

GitHub Actions caches Cargo downloads and dependency build artifacts for `gateway/target` with `Swatinem/rust-cache`. The cache is keyed by the Rust toolchain and dependency manifests; Cargo still checks which sources need rebuilding. It is saved even if a later check fails.

Container builds use Docker Buildx with the GitHub Actions layer cache in `mode=max`, including intermediate builder layers. The built image is loaded into Docker for the existing Compose smoke tests and only published after they pass. Source changes invalidate affected Docker layers, so a changed Rust source layer still requires a release build. Caches speed up warm runs; the first run, toolchain changes, and cache eviction can require a cold build. Tests continue running on every workflow.

## Checks

```sh
cd gateway
npm test
npm run check
cargo test --locked
cargo build --locked
python3 tests/proxy-smoke.py
python3 tests/pools-smoke.py
python3 tests/rate-limit-smoke.py
python3 tests/policy-smoke.py
python3 tests/cache-smoke.py
python3 tests/tls-smoke.py
python3 tests/accounts-alerts-smoke.py
python3 tests/credentials-smoke.py
python3 tests/reliability-balancing-smoke.py
python3 tests/routing-smoke.py
python3 tests/pages-smoke.py
python3 tests/monitoring-smoke.py
python3 tests/backup-smoke.py
python3 tests/mfa-smoke.py
python3 tests/diagnostics-smoke.py
python3 tests/scheduled-backups-smoke.py
python3 tests/config-history-smoke.py
python3 tests/templates-smoke.py
python3 tests/compression-smoke.py
```

The backup integration check uses temporary data, a local origin, and generated local certificates. It verifies encrypted backups larger than 1 MiB, wrong-passphrase/tamper rejection, role/CSRF enforcement, review ownership/staleness, queue/cancel behavior, process locking, restart restoration of accounts/routes/TLS keys/ACME credentials/secrets/analytics, token restoration, session invalidation, recovery export, and private permissions. Rust tests also reject paths/links/triggers and simulate an interrupted restore and marker cleanup.

The CLI integration check creates read-only and full API tokens against a real gateway, then runs every `embergate-cli` command: host apply/show/enable/disable/delete, cache purge, history, containers, and backup export with private, non-overwriting output. It checks that read-only, invalid, and missing tokens and usage mistakes return their documented exit codes.

The private CA integration check runs a real HTTPS backend signed by a temporary private root, without any system trust changes. It verifies bundle validation (non-PEM, leaf certificates, private keys, size), administrator-only changes, that health checks and Diagnostics fail before the root is added and pass immediately after, persistence across restart, inclusion in backups, and removal.

The monitoring integration check validates scrape authentication/rotation/revocation, bounded labels and histogram/counter values, restart behavior, role/CSRF enforcement, Discord test/open/recovery messages, mention suppression, Retry-After, destination changes, generic compatibility, and secret redaction using temporary data/local receivers. It does not contact Discord.

The pages integration check verifies maintenance before cache/origin selection, access/redirect/rate precedence, HTML/plain negotiation, escaping, HEAD/body behavior, generated framing/security headers, 200/503 status choices, read-only enforcement, durable maintenance logs, restart persistence, recovery, and gateway versus application error responses. It uses only temporary data and local origins.

The routing integration check verifies literal prefix stripping/replacement, encoded paths and queries, header overrides/removals, body preservation, failover transformations, cache invalidation, public access/redirect/log behavior, invalid configuration rejection, and restart persistence using temporary local origins.

The reliability/balancing integration check verifies connect/read/TLS-handshake timeouts, safe distinct-backend failover, unsafe/body/upgrade/certificate/HTTP-response exclusions, partial-response handling, rate budgets, cache fills after failover, attempt logs, proportional weights, trusted-IP affinity, least-active selection, graceful draining, and persistence using temporary local backends.

The credentials integration check verifies setup-code and CSRF protection, simultaneous first-run submissions, database administrator login/password rotation, live token save/replace/remove, role restrictions, restart persistence, secret redaction, and recovery overrides. A Rust test uses a local DNS API receiver to verify that a token rotation changes authorization on live DNS requests and that an active operation blocks rotation.

The accounts/alerts integration check uses temporary databases and a local HTTP receiver. It checks API role enforcement, session ownership/revocation, password changes, restart persistence, audit redaction, backend/error-rate alert recovery, acknowledgement, webhook opt-in, restart deduplication, and all five failed delivery attempts.

No npm install is necessary. Rust tests cover routing, configuration and certificate validation, authentication, CSRF request headers, persistence, and revision conflicts. The proxy integration check starts the compiled proxy and a local upstream. The pool integration check uses two local HTTP backends to verify balancing, health gating, failure/recovery, redirect rejection, 503 responses, per-origin and preserved Host headers, live changes, logging, and restart persistence. The rate-limit integration check verifies burst/refill, retry headers, blocked HEAD/POST requests, forwarded-header spoof resistance, client/route isolation, concurrent budgets, live policy changes, upstream 429 classification, and persistence. The policy check verifies trusted/untrusted identities, XFF chain boundaries, per-visitor rate limits, allow/block rules, redirect/header behavior, spoofing and header-injection rejection, analytics filters, private database permissions, and restart persistence. The cache integration check verifies MISS/HIT/Age/HEAD behavior, private/auth/cookie bypasses, Vary and key isolation, size/streaming limits, expiry, query opt-in, collapsed fills, only-if-cached, URL/route purge races, write invalidation, policy precedence, origin-down hits, logs/counters, and restart behavior. The TLS check also verifies HSTS/security headers and HTTPS redirects with a real TLS connection and generates a temporary private CA and intermediate, then verifies real TLS handshakes, chain delivery, hostname matching, certificate replacement/deletion, private key permissions/redaction, and persistence. It requires the `openssl` CLI and never contacts a certificate service. When curl with HTTP/2 support is available, it also verifies real TLS HTTP/2 cache misses/hits using :authority without Host.

For dashboard interaction checks with an installed Chromium browser and Node 22+:

```sh
BROWSER_BIN=/usr/bin/chromium npm run test:browser
```

That browser test uses an isolated mock management API. It exercises login/logout, host management, logs, certificate upload/replacement/deletion, dark page/card/dialog/input surfaces, theme persistence, mobile navigation, first-run setup, Cloudflare credential controls, account creation/editing, read-only controls, password changes, audit entries, and alert preferences/acknowledgement. Screenshots are saved to `/tmp/embergate-dashboard.png` and `/tmp/embergate-dashboard-dark.png`. It does not substitute for the real proxy and TLS integration checks.

For an end-to-end DNS-01 test with the official [Pebble ACME test server](https://github.com/letsencrypt/pebble):

```sh
PEBBLE_BIN=/path/to/pebble python3 tests/acme-smoke.py
```

The ACME check uses a local Cloudflare API fixture, local UDP/TCP DNS server, private transport CA, and Pebble's real ACME protocol implementation. It checks apex/wildcard issuance, production promotion, live TLS activation, scheduled renewal, credential permissions/redaction, account reuse, restart cleanup, failure backoff, and managed-certificate controls. It never contacts public DNS or a public certificate authority. `GATEWAY_ACME_DIRECTORY`, `GATEWAY_ACME_CA_ROOT`, `GATEWAY_CLOUDFLARE_API_BASE`, and `GATEWAY_DNS_CHECK_URL` are advanced server-side overrides used by this test; leave them unset for normal Let's Encrypt/Cloudflare use.

### Verification

The scheduled-backup integration check uses isolated local storage and webhook fixtures. It verifies immediate/due/restart/interrupted jobs, encryption/download/restore, retention and private permissions, bearer/Basic uploads, redirects and local fallback, failure/recovery notifications, concurrent management edits, role/CSRF/version validation, restore pause, recovery exports, and secret redaction. A Rust test checks that both current and obsolete automation passphrases are absent from exported database bytes.

The compression integration check requires the Python `brotli` module, OpenSSL, and curl with HTTP/2 support. It uses local fixtures to decode real gzip/Brotli streams, exercise quality/wildcard/multiple-field negotiation, identity/406 and privacy/range/SSE/no-transform bypasses, digest/validator/trailer handling, incremental output, cache hits/conditional responses/invalidation, HTTP/1.0 passthrough, HTTP/2 over TLS, policy validation, templates/history, restart and encrypted restoration. Browser checks cover controls, both modes, nested validation, saved policy round trips, templates/duplication, and mobile dark mode.

The host-template integration check verifies independent policy capture, create/edit/recapture/delete, source and library conflicts, name validation, roles/CSRF, private restart persistence, corrupt/link rejection, audit redaction, restore freezes/review invalidation, manual/automatic encrypted snapshots, complete backup restoration, and older backups without templates. Browser checks cover independent paused duplication, template creation/editing, stale forms, escaping, review/apply without live changes, saved policies, deletion, mobile dark mode, and role visibility.

The configuration-history integration check verifies field comparisons, live rollback, stale reviews, roles/CSRF, failed saves, restart persistence, bounded private storage, corrupt-data rejection, encrypted restore, and compatibility with older backups without history. Browser checks cover comparisons, escaping, stale-review handling, rollback, role visibility, and mobile dark mode.

The diagnostics integration check uses local HTTP/TLS servers and a temporary private CA. It verifies route selection, previews without network traffic, path/header handling, certificate validation, redirects, HEAD errors, bounded timeouts/concurrency, configuration changes during probes, backup review/freeze compatibility, roles/CSRF, audit redaction, and unchanged proxy counters/logs/backend health.

The MFA integration check uses an isolated local server and independent Python TOTP generation. It verifies enrollment ownership, CSRF, password proof, TOTP/recovery replay rejection, session revocation, administrator enforcement, read-only enrollment, restart persistence, environment-admin protection, recovery replacement, disabling, deletion, encrypted backup validation/restoration, and audit redaction.

Verified locally with Rust 1.99: all 71 Rust tests, twenty dashboard tests, JavaScript syntax check, Rust formatting check, real proxy/pool/rate-limit/policy/cache/TLS/accounts-alerts/credentials/reliability-balancing/routing/pages/monitoring/backup/MFA/diagnostics/scheduled-backups/config-history/templates/compression/forward-auth/cluster integration checks, and dashboard/passkey browser interaction checks pass. The local Pebble DNS-01 integration check passed previously and was not rerun for the WebGUI credential change (the Pebble executable is no longer available locally). The browser check uses an installed Chromium-compatible browser, verifies separate Settings pages, desktop/mobile navigation, bookmarkable links, Back/Forward, reloads, permissions, and MFA recovery-code preservation, tests caching controls and purge scopes, trusted proxies, access/response policies, persisted analytics views, pool/health and rate-limit configuration, and ACME request/production/renew/stop controls, and confirms the mobile page does not overflow. `gateway/Cargo.lock` records the resolved dependencies and Docker builds use it. Live Cloudflare/Let's Encrypt issuance requires your token and domains and was not exercised. The release Dockerfile and documented Compose service have been built and smoke-tested locally with Podman; hosted Docker verification awaits the current release CI run.

Help checks cover embedded Markdown rendering, unsafe HTML/link/image handling, internal-link targets, authenticated access for both roles, search, retry, contextual links, topic/section history and reloads, mobile navigation, and theme layout.

## Additional release checks

```sh
# From gateway/, after building the binary:
python3 tests/forward-auth-smoke.py
BROWSER_BIN=/usr/bin/chromium node tests/passkeys-browser-smoke.mjs
python3 tests/load-check.py --seconds 120 --concurrency 8 --binary target/release/embergate --output ../docs/benchmarks/release-local.json

# From the repository root, after building an image:
python3 gateway/tests/container-smoke.py --engine podman --image localhost/embergate:roadmap
```

Forward-auth checks exercise fail-closed allow/deny/redirect/timeout behavior, identity spoofing, request metadata, body preservation, cache/compression bypass, templates, and persistence. Passkey checks use a Chromium virtual authenticator against a real isolated gateway; they verify registration/sign-in, required UV, replay/CSRF rejection, labels, private credential responses, removal/session revocation, full encrypted restoration, restart, and role/mobile controls. This verifies the WebAuthn protocol path without claiming coverage of every physical authenticator or browser platform.

The container check uses a unique Compose project, loopback ports, and a disposable named volume. It removes only those test resources. The load tool runs uncached, cached, and cached-gzip phases, records percentiles/RSS/origin counts, verifies response bodies, then checks an in-flight response and exit status during the five-second SIGTERM drain window. Results depend on the origin, client, build profile, CPU, and concurrent machine activity; they are reproducible development measurements, not advertised capacity.

Multi-instance verification uses `python3 tests/cluster-smoke.py --engine podman` for paired real gateways and a real HAProxy container. The shipped deployment is exercised separately from the repository root with `python3 gateway/tests/cluster-compose-smoke.py --engine podman --image localhost/embergate:roadmap`. Both checks use isolated state/ports/volumes and clean up owned test resources. See [the design](cluster-design.md).

The [recorded release measurement](benchmarks/README.md) completed all three 120-second traffic phases with zero errors across 2.44 million requests, measured latency/cache/memory, and passed normal graceful shutdown. Its raw JSON and reproduction command are included. The [hosted CI run](https://github.com/karlocizma/EmberGate/actions/runs/39224335793) passed the complete suite, including container and Compose checks. Live Cloudflare/Let's Encrypt issuance and renewal remain unverified because they require a real test domain and credentials.


## Host setup wizard

Dashboard browser checks exercise destination validation, Back/Continue and submit-key progression, the unified preset picker, policy on/off badges, HTTPS certificate warnings, review escaping, mobile destination/review layouts, and optional backend checks after creation. They also cover direct editing without repeating setup, preservation of existing HTTPS/header settings, paused duplication and policy templates, and revealing invalid fields inside advanced groups. Certificate hint unit tests cover valid exact names, case normalization, one-label wildcards, and expired certificates. Category selections are guidance, not application-specific compatibility certification.

Native gRPC transport: after `cargo build --locked`, run
`node tests/grpc-smoke.mjs` from `gateway/`. This uses a local HTTP/2 fixture to
check prior-knowledge h2c, bidirectional streaming before request completion,
message bytes, metadata, success/error trailers, legacy protocol rejection, verified
TLS HTTP/2 in both directions, mixed HTTP/1.1 traffic and IP access enforcement.

Run `python3 tests/timing-smoke.py` from `gateway/` after building to verify header
readiness independently of delayed response bodies and grouping of event streams
and ActiveSync requests in logs, live metrics and persisted analytics.

Run `python3 tests/shutdown-smoke.py` from `gateway/` after building to verify a
real SIGTERM exit within 15 seconds while preserving a short in-flight response.

CI runs isolated Python integration suites with three workers using
`python3 tests/run-integrations.py --jobs 3` from `gateway/`. Every suite has its
own log and a five-minute timeout; any failure fails the job. Use `--jobs 1` for
serial debugging, or supply suite names to run a subset. CI uploads the logs.
The container build and smoke tests run alongside the Rust/dashboard job. A
separate publishing job waits for both to pass, then publishes the exact tested
image transferred as an artifact. Pull requests never publish. Rust and Docker
build caches remain enabled; cold builds and cache misses can still take longer.

# EmberGate roadmap

## Implemented

- [x] **Timeouts and safe failover:** per-host DNS/connect, read, and write timeouts; bounded retries to distinct available backends for bodyless GET/HEAD requests before a response starts; durable attempt history.
- [x] **Advanced load balancing:** weighted round robin, weighted least-active-request selection, verified-client-IP affinity, and backend draining with active-request counts. Configure everything in the host editor.
- [x] **Routing tools:** literal path-prefix replacement and stripping, validated request-header overrides/removals, and a live upstream-request preview in the host editor. Original public URLs remain the basis for access policies, redirects, caching, and logs.

- [x] **Maintenance and error pages:** per-route maintenance with custom text, 503/200 status and Retry-After, live previews and host-table controls, and branded gateway error pages with HTML/plain-text negotiation. Policies and maintenance logs persist; application errors remain unchanged.

- [x] **Prometheus and Discord:** token-protected metrics with traffic/latency, route/backend/cache/certificate/notification gauges and counters; Discord alert/recovery/test embeds through the durable delivery queue. Configure scrape tokens and webhook destinations in Alerts.

- [x] **Full backup and restore:** passphrase-encrypted complete snapshots, consistent SQLite backups, strict file/schema/configuration validation, a session-bound review, restart-time replacement with a durable journal, and a downloadable local recovery snapshot. Includes accounts, routes, certificates/ACME credentials, saved secrets, settings, analytics, audit history, and alerts.

The original roadmap is complete. Slack notifications are outside the current scope. Route-only import/export remains available alongside full backups.

## Next phase — implementation order

- [x] **Two-factor authentication:** authenticator-app enrollment, single-use recovery codes, administrator enforcement, dashboard controls, session revocation, replay protection, and encrypted-backup support. Passkeys are a later extension.
- [x] **Diagnostics panel:** route matching and rewritten-path previews, public certificate selection, bounded DNS/TCP/TLS/HEAD checks and timings for saved backends, host-row shortcuts, stale-configuration notices, and administrator-only dashboard controls.
- [x] **Scheduled encrypted backups:** durable interval scheduling, encrypted local snapshots with retention/download/removal, immediate runs, restart recovery, failure/recovery alerts, optional HTTPS/WebDAV offsite copies with bearer/Basic authentication, and restore-time passphrase re-entry.
- [x] **Configuration history:** up to 50 earlier revisions within a 32 MiB budget, per-host field comparisons and trusted-proxy changes, reviewed live rollback as a new revision, stale-review protection, private atomic persistence, administrator controls, and encrypted-backup/legacy-restore support.
- [x] **Host templates and duplication:** independent paused duplicate drafts with new identities, an administrator policy-template library with create/edit/recapture/delete, reviewed draft-only application, source/library conflict checks, private bounded persistence, and full encrypted-backup/legacy-restore support.
- [x] **Response compression:** per-host automatic Brotli/gzip or gzip-only controls, bounded levels/declared-size thresholds, quality-aware negotiation, incremental downstream encoding after cache lookup, privacy/range/no-transform/already-encoded bypasses, safe validators/digests/framing, HTTP/2 validation, and templates/history/encrypted-backup support.

The next-phase features above are implemented. Larger planned features and release validation remain below.

## Dashboard and repository polish

- [x] **In-app documentation:** shared Markdown guides embedded in the binary, authenticated read-only Help for all roles, full-text guide search, desktop/mobile topic navigation, section links with reload/Back/Forward support, themed articles, and contextual links from complex settings.

- [x] **Documentation:** concise project README with setup and feature highlights; detailed installation, proxy, certificate, administration, monitoring, testing, and repository guides in `docs/`.

- [x] **Settings navigation:** ten focused pages, secondary desktop navigation, a mobile section selector, bookmarkable URLs, reload/Back/Forward support, role filtering, safe dialog navigation, and aligned footer content.
- [x] **GitHub preparation:** top-level repository with pinned Pingora submodule, runtime/secret/build exclusions, contributor and security guidance, attribution, issue/PR templates, and a CI workflow for Rust/dashboard/integration/browser checks and container builds.
- [ ] **First hosted CI run:** verify all jobs pass in `karlocizma/EmberGate`. The repository is private; enable private vulnerability reporting before making it public.
- [x] **EmberGate license:** Apache 2.0, with a root license file, copyright/attribution notice, package metadata, and documentation. Pingora keeps its existing upstream license.

## Larger features

- [x] **Public product and documentation website:** product overview, dashboard screenshot, installation guidance, and searchable shared Markdown guides at https://embergate.niftyisle1.chatgpt.site. Standalone source/build and desktop/mobile browser checks live in `website/`.

- [x] **Application login protection:** per-host forward authentication, verified original-request metadata, allowlisted identity headers with spoof removal, optional sign-in redirects, bounded fail-closed checks, cache/compression bypass, host-editor controls, templates/history/import/backup support, and real proxy/browser checks. Direct OIDC is outside this forward-auth implementation.
- [x] **Passkeys:** WebAuthn sign-in with required user verification, pinned origin, server-held one-use ceremonies, per-account device enrollment/removal, session revocation, password/TOTP recovery paths, encrypted backups, and real virtual-authenticator browser checks.
- [x] **Multiple EmberGate instances:** single writable primary with encrypted, challenge-bound live route/TLS replication to pinned followers; local accounts/analytics; GUI role/token/status controls; durable generations and recovery journal; stale fail-closed readiness; primary-only renewals; and HAProxy traffic failover. Design and operational limits are documented in `docs/cluster-design.md` and `docs/administration.md`.

## Release validation

- [x] **Container builds:** release Dockerfile image built with Podman; documented Compose service smoke-tested for non-root execution, authentication, Help, real forwarding, and restart/volume persistence. The reusable check also runs with Docker in CI; the hosted Docker job still needs verification.
- [ ] **Sustained load tests:** measure throughput, latency, memory, cache behavior, and graceful shutdown under traffic; document reproducible results.
- [ ] **Live Cloudflare / Let’s Encrypt validation:** issue and renew a certificate with a user-provided token and domain. This needs a real test domain and credentials; local ACME fixtures remain part of regression checks.

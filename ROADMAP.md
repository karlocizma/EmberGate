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

- [x] **Two-factor authentication:** authenticator-app enrollment, single-use recovery codes, administrator enforcement, dashboard controls, session revocation, replay protection, and encrypted-backup support. Passkeys are also available; see Larger features below.
- [x] **Diagnostics panel:** route matching and rewritten-path previews, public certificate selection, bounded DNS/TCP/TLS/HEAD checks and timings for saved backends, host-row shortcuts, stale-configuration notices, and administrator-only dashboard controls.
- [x] **Scheduled encrypted backups:** durable interval scheduling, encrypted local snapshots with retention/download/removal, immediate runs, restart recovery, failure/recovery alerts, optional HTTPS/WebDAV offsite copies with bearer/Basic authentication, and restore-time passphrase re-entry.
- [x] **Configuration history:** up to 50 earlier revisions within a 32 MiB budget, per-host field comparisons and trusted-proxy changes, reviewed live rollback as a new revision, stale-review protection, private atomic persistence, administrator controls, and encrypted-backup/legacy-restore support.
- [x] **Host templates and duplication:** independent paused duplicate drafts with new identities, an administrator policy-template library with create/edit/recapture/delete, reviewed draft-only application, source/library conflict checks, private bounded persistence, and full encrypted-backup/legacy-restore support.
- [x] **Response compression:** per-host automatic Brotli/gzip or gzip-only controls, bounded levels/declared-size thresholds, quality-aware negotiation, incremental downstream encoding after cache lookup, privacy/range/no-transform/already-encoded bypasses, safe validators/digests/framing, HTTP/2 validation, and templates/history/encrypted-backup support.

The next-phase and larger product features are implemented. Release validation remains below.

## Dashboard and repository polish

- [x] **In-app documentation:** shared Markdown guides embedded in the binary, authenticated read-only Help for all roles, full-text guide search, desktop/mobile topic navigation, section links with reload/Back/Forward support, themed articles, and contextual links from complex settings.

- [x] **Documentation:** concise project README with setup and feature highlights; detailed installation, proxy, certificate, administration, monitoring, testing, and repository guides in `docs/`.

- [x] **Settings navigation:** ten focused pages, secondary desktop navigation, a mobile section selector, bookmarkable URLs, reload/Back/Forward support, role filtering, safe dialog navigation, and aligned footer content.
- [x] **GitHub preparation:** top-level repository with pinned Pingora submodule, runtime/secret/build exclusions, contributor and security guidance, attribution, issue/PR templates, and a CI workflow for Rust/dashboard/integration/browser checks and container builds.
- [x] **First hosted CI run:** all Rust, dashboard/browser, passkey, website, local integration, container build, and Compose smoke-test jobs passed on [run 39224335793](https://github.com/karlocizma/EmberGate/actions/runs/39224335793) (`f2020fc`). The repository remains private; enable private vulnerability reporting before making it public.
- [x] **EmberGate license:** Apache 2.0, with a root license file, copyright/attribution notice, package metadata, and documentation. Pingora keeps its existing upstream license.

## Larger features

- [x] **CrowdSec bouncer integration (initial):** GUI-managed Local API URL and encrypted bouncer key, periodic decision-stream synchronization, IPv4/IPv6 IP and CIDR ban matching against verified visitor identities, local request-path enforcement, degraded sync status with last-good decisions retained, and disconnect controls. CrowdSec remains the detection engine; enriched acquisition/log shipping and remediation actions remain planned.

- [x] **Public product and documentation website:** product overview, dashboard screenshot, installation guidance, and searchable shared Markdown guides at https://embergate.niftyisle1.chatgpt.site. Standalone source/build and desktop/mobile browser checks live in `website/`.

- [x] **Application login protection:** per-host forward authentication, verified original-request metadata, allowlisted identity headers with spoof removal, optional sign-in redirects, bounded fail-closed checks, cache/compression bypass, host-editor controls, templates/history/import/backup support, and real proxy/browser checks. Direct OIDC is outside this forward-auth implementation.
- [x] **Passkeys:** WebAuthn sign-in with required user verification, pinned origin, server-held one-use ceremonies, per-account device enrollment/removal, session revocation, password/TOTP recovery paths, encrypted backups, and real virtual-authenticator browser checks.
- [x] **Multiple EmberGate instances:** single writable primary with encrypted, challenge-bound live route/TLS replication to pinned followers; local accounts/analytics; GUI role/token/status controls; durable generations and recovery journal; stale fail-closed readiness; primary-only renewals; and HAProxy traffic failover. Design and operational limits are documented in `docs/cluster-design.md` and `docs/administration.md`.
- [x] **Docker container discovery (v0.5.0):** administrator-only, read-only listing of running containers through `DOCKER_HOST` or the local socket (Docker or Podman), a Containers page with one-click **Expose** into the host wizard, preset suggestions from the image name, a container picker in the wizard, and exposure status per container. The gateway's own container, the Docker API container, and API ports are never offered. Recommended setup uses a read-only socket proxy: `deploy/docker-discovery-compose.yaml`.
- [ ] **Container discovery follow-ups:** keep **Expose** reachable on phone layouts. (Done: the `embergate.host` label pre-fills the public domain, and a gateway outside Docker or on host networking uses published host ports.)

## Dashboard UX findings (pending rework)

Host editor cleanup is in progress; these were found during that review and are not yet scheduled.

- [x] **Host editor overwhelms on edit.** Editing shows the basics plus each policy group directly, every policy with an On/Off badge and summary, and a jump bar to each group. The HTTPS redirect is set only under Connection, presets stay hidden until requested, the save footer stays in view, and unsaved edits ask before closing. New hosts keep the 3-step wizard.
- [x] **Three overlapping "pick a preset" mechanisms in the host dialog, two of which silently clobber each other.** "What are you hosting" is cosmetic text only. "Application starter settings" (built-in presets) overwrites protocol/timeouts/preserve_host and clears cache+compression. "Host templates" (user-saved presets) overwrites the entire policy set and deletes any policy key absent from the template. Applying both in either order clears fields the other set, with no warning. Plan: merge into one concept — a single preset picker (built-in + user templates in one list) with one "Apply to draft" action.
- [x] **"Template" means different things in different places.** Terms are now consistent: a **preset** is anything in the host editor's preset picker, which offers **built-in presets** and your saved **host templates**; configuration history uses **revisions**. Docs and dashboard labels follow these terms.
- [x] **Overlap between manual and automatic backups.** Both produced the same encrypted snapshot on separate pages, and restoring a scheduled backup meant downloading and re-uploading it. They now share one **Backups** page; saved backups restore directly through the same passphrase check and review. The old automatic-backups link opens the combined page, and the routes-only export is labeled **Route import / export**.
- [x] **Sign-in settings:** password, two-factor and passkeys already share one Settings page, now named **Sign-in methods**. Cloudflare DNS credentials are not sign-in settings and stay on their own page.

## Release validation

- [x] **Live proxy-login validation:** Nextcloud local login and Authentik SSO loops traced to split HTTP/2 `cookie` fields being forwarded as separate `Cookie:` lines to HTTP/1.1 upstreams; fixed in v0.4.3 and confirmed live on the maintainer's setup.
- [x] **Container builds:** release Dockerfile image built with Podman and Docker; documented Compose service smoke-tested locally and in [hosted CI](https://github.com/karlocizma/EmberGate/actions/runs/39224335793) for non-root execution, authentication, Help, real forwarding, and restart/volume persistence.
- [x] **Sustained load tests:** release-build uncached, cached, and cached-gzip phases at eight concurrent clients for 120 seconds each; 2.44 million validated requests with zero errors; measured percentiles/RSS/origin counts and preserved an in-flight response through normal five-minute SIGTERM shutdown. Reproduction and limits: [load report](docs/benchmarks/README.md).
- [x] **Live Cloudflare / Let’s Encrypt validation:** certificate issuance with a Cloudflare token and a real domain was tested live and worked (maintainer-reported); local ACME fixtures remain part of regression checks.

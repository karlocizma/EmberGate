# EmberGate — Powered by Pingora

EmberGate is a reverse proxy with a local management dashboard, built around the Pingora source in `pingora/`. Application code lives in `gateway/`; the upstream framework is unchanged.

EmberGate is under active development. See [ROADMAP.md](ROADMAP.md) for completed work, planned features, and remaining release validation. This is an independent project, not an official Cloudflare product.

[Getting started](#run-locally) · [Docker](#docker) · [Settings](#settings-navigation) · [Checks](#checks) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)

The gateway includes:

- Domain and path-prefix routing to HTTP or HTTPS upstreams.
- Add, edit, pause, enable, and delete hosts without restarting the proxy.
- Up to 16 origins per host with round-robin/weighted/least-active balancing, verified-client-IP affinity, graceful draining, optional health checks, and live backend activity.
- Per-host connection/read/write timeouts and opt-in safe transport failover with durable attempt history.
- Per-host streaming Brotli/gzip response compression with quality-aware negotiation and downstream cache coordination.
- Opt-in Pingora response caching with conservative origin admission, bounded memory storage, per-route controls, cache statistics, and URL/route/global purges.
- Per-route/client IP rate limits with configurable sustained rates and bursts, 429 retry responses, live policy changes, and blocked-request metrics/logs.
- Trusted Cloudflare/custom proxy networks with verified visitor IPs and optional protocol forwarding.
- Per-route IPv4/IPv6 allowlists/blocklists, HTTPS redirects, HSTS, security headers, and custom response headers.
- Persistent SQLite analytics with 24-hour/7-day/30-day views, per-route filtering, status-code summaries, and durable request logs.
- Web-based first-run administrator setup, administrator/read-only accounts, Argon2 password hashing, two-factor authentication with recovery codes, and session revocation.
- Cloudflare DNS credentials managed in the dashboard, with immediate token rotation and optional environment recovery overrides.
- Durable management audit trail, dashboard alerts, and opt-in webhook notifications with retry delivery.
- Validated configuration saves, optimistic revision checks, atomic file replacement, and a previous-revision backup.
- On-demand routing diagnostics with DNS/TCP/TLS/HEAD checks, per-stage timings, certificate status, and backend failure details.
- Request totals, average request duration, server error rate, and a 60-minute traffic chart.
- The latest 200 request logs, search, configuration import/export, and light/dark themes.
- Separate settings pages with a secondary navigation menu, mobile section selector, bookmarkable URLs, and browser Back/Forward support.
- Responsive Cloudflare-inspired dashboard with orange branding, grouped navigation, neutral panels, and light/dark themes. Assets are embedded in the Rust binary, with no frontend dependency installation or external asset services.
- Optional client HTTPS with HTTP/2, live certificate upload/replacement/deletion, SNI selection, wildcard support, and expiry details.
- Let's Encrypt ACME issuance and automatic renewal through Cloudflare DNS-01, with staging/production controls, renewal progress, and DNS cleanup recovery.

## Run locally

Install a current stable Rust toolchain (at least 1.89 for the locked dependencies), a C/C++ build toolchain, CMake, pkg-config, Perl, and OpenSSL development headers. Pingora targets Linux; see [its build requirements](pingora/README.md).

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

The Docker build uses this checkout of Pingora and installs the `embergate` executable. From the repository root:

```sh
docker compose up --build -d
docker compose logs gateway
```

Use the setup code from the logs to create the administrator in the browser. The admin password environment variable is optional. If provided, it acts as the same recovery override described above.

The image build requires the initialized Pingora submodule described above.

The same dashboard and proxy ports are bound to the host's loopback interface. Routes persist in the `gateway-data` volume. Inside a container, `127.0.0.1` refers to that container: use a reachable upstream address or another Compose service name.

Pingora uses a five-minute grace period for SIGTERM shutdowns; Compose allows 310 seconds for draining. Ctrl+C (SIGINT) stops the local process quickly. The integration test uses SIGINT after its requests finish to verify loading saved routes without waiting through the drain period.

## Proxy host editor

The host editor starts with the connection details, **Load balancing & health checks**, and **HTTPS & response headers**. **Advanced settings** groups caching, path/header rewrites, IP access rules, rate limits, timeouts/failover, maintenance/error pages, and Preserve Host. Sections start collapsed for both new and existing hosts; configured sections are labeled, and the Advanced summary lists the saved policies. Opening a host preserves every configured value. Cache configuration shortcuts open Advanced and the caching section directly. Invalid fields inside collapsed sections are revealed automatically when saving.

## Trusted proxies

Open **Settings → Trusted proxies → Configure trusted proxies**. Add an IP or CIDR, choose the visitor header that proxy overwrites, and optionally trust its **X-Forwarded-Proto** value. Saves apply live and use the same revision checks, atomic persistence, and backups as route changes. The default list is empty, so upgrades keep using connection IPs.

**Load Cloudflare networks** retrieves the current IPv4/IPv6 ranges from [Cloudflare's public IP API](https://developers.cloudflare.com/api/resources/ips/methods/list/). Review the entries and save to enable **CF-Connecting-IP** and protocol forwarding from those networks. This lookup needs no token, does not change DNS, and is only performed when requested. The saved list is a snapshot; reload/review it when updating provider ranges. Header behavior follows [Cloudflare's HTTP header documentation](https://developers.cloudflare.com/fundamentals/reference/http-headers/).

For your own reverse proxy, select **X-Forwarded-For** and ensure it appends the connecting address. Chains are processed from right to left through configured X-Forwarded-For networks, stopping at the first untrusted hop. The untrusted hop's claimed left side is ignored. Every address must parse; chains are limited to 32 hops and 2048 bytes. CF-Connecting-IP must contain exactly one IP. Missing, malformed, or duplicate IP headers fall back to the socket IP. Duplicate, chained, or invalid protocol values are ignored. Forwarded protocol accepts only a single `http` or `https` from a network with that option enabled; otherwise the actual connection protocol is used.

Only trust proxy networks whose configured header behavior you control or have verified. Overlapping networks and whole-Internet `/0` trust are rejected; up to 64 networks are supported. IPv4-mapped IPv6 addresses/networks are normalized. The same resolved visitor IP drives rate limiting, access rules, forwarded headers, and traffic logs. Logs also retain the socket peer and identity source. Management login/session behavior is unchanged; trusted proxy settings apply to the traffic proxy.

## IP access rules

Edit a host and expand **IP access rules**. Enable either **Allow only these networks** or **Block these networks**, and enter one IP/CIDR per line. Both IPv4 and IPv6 are supported, with up to 256 entries per route. An allowlist admits matching verified visitors; a blocklist rejects matching visitors. Missing client identity fails closed. Empty enabled policies are rejected.

Rules apply to the matched host/path route, before redirects, rate limiting, or upstream selection. Denials return **403**, never contact an upstream, and are labeled **Access denied** in traffic logs and counted in historical analytics. Other configured routes keep their own policies. Removing the policy restores unrestricted access for that route. These controls affect proxy traffic, so they cannot block the management API through its separate listener.

## HTTPS redirects and response headers

Edit a host and expand **HTTPS & response headers**, then enable a policy:

- **HTTP → HTTPS** uses **308**, preserving the method, hostname, path, and query. Set the public HTTPS port (443 by default). Provide a working TLS listener/certificate or a trusted HTTPS edge before enabling redirects. Effective HTTPS comes from the TLS connection or explicitly trusted forwarded protocol, preventing redirect loops behind a configured TLS proxy.
- **HSTS** accepts 0–31536000 seconds and optional includeSubDomains. A positive value is emitted only for effective HTTPS. Zero stops adding gateway HSTS and leaves any upstream HSTS unchanged. Browser-cached HSTS persists for its max age; removing the gateway policy cannot instantly clear browser state.
- Security switches set **X-Content-Type-Options: nosniff**, **X-Frame-Options: DENY**, and **Referrer-Policy: strict-origin-when-cross-origin**.
- Add up to 32 custom **Name: Value** headers. Matching upstream headers are replaced; values are at most 4096 bytes and cannot contain line breaks. Custom values apply after security switches. Connection/framing headers, Content-Length/Encoding/Range, Host, Location, Set-Cookie, and Strict-Transport-Security cannot be overridden through this editor.

Policies apply to upstream responses and the gateway's route-level 403/429/503/308 responses. Locally generated responses keep Cache-Control: no-store. Unmatched requests and framework-generated transport errors do not use a route response policy. All controls default off and apply live when saved.

## Persistent analytics

Open **Analytics** for hourly charts, totals, average duration, status-code counts, and traffic by route. Choose **24 hours**, **7 days**, or **30 days**, and optionally select one current or historical route. The selected period includes the current partial hour. Historical traffic remains visible after a route is removed. Unmatched requests are tracked separately. Gateway blocks count access denials and gateway rate limits, while 5xx counts server errors. An upstream's own 403/429 response is counted by status without being classified as a gateway block.

The database is **analytics.sqlite3** in GATEWAY_DATA_DIR. It uses SQLite WAL transactions, full synchronous commits, and Unix permissions 0600. A dedicated writer keeps SQL off proxy workers and batches queued records, with a 4096-command bound and backpressure instead of silent drops. Storage write failures are logged and retried; analytics queries time out with a service error if storage cannot respond. The newest queued/uncommitted records can be lost during a forced process stop; committed transactions survive restart. Existing in-memory history from an older gateway version cannot be recovered retroactively.

Hourly aggregates and status counts are retained for 30 days. At most 10000 recent request records are stored within that retention period; **Traffic logs** shows the latest 200, now including verified visitor IP, connection peer, source, and policy outcome. Query strings, request bodies, cookies, and authorization headers are not stored. IP addresses and paths are retained locally, so protect/back up the data directory accordingly. Retention cleanup runs on startup and during activity; the SQLite file can retain reusable free space after rows expire. Stop the gateway before copying its data directory, including any SQLite WAL files, for a filesystem backup.

The overview intentionally keeps its since-start counters and 60-minute chart. Use **Analytics** for durable history. Route exports contain configuration only, including trusted proxies and per-route policies; the analytics database is separate. The authenticated API is `/api/analytics?hours=24&route_id=<uuid>` (omit route_id for all traffic; use `unmatched` for unmatched requests). `/api/logs` returns the latest persisted request records.

## Upstream pools and health checks

Add or edit a proxy host and expand **Load balancing & health checks**. Keep the first origin in **Upstream origin**, then enter additional origins one per line. Round robin is the default; each new request rotates to the next eligible backend. Choose another traffic distribution strategy, set per-origin weights, or mark individual origins as draining in the same editor. Each host supports up to 16 unique HTTP/HTTPS origins, including mixed protocols. The request path/query, upstream Host header, TLS SNI, and certificate verification follow the selected origin. Existing single-origin configurations need no migration.

Enable **HTTP health checks**, choose a path such as `/health`, and configure:

| Setting | Default in dashboard | Range |
| --- | --- | --- |
| Interval after each completed check | 10 seconds | 5–300 seconds |
| Probe timeout | 3 seconds | 1–10 seconds |
| Consecutive failures before exclusion | 2 | 1–10 |
| Consecutive successes before use/recovery | 1 | 1–10 |

Probes send GET directly to each configured origin; only 2xx responses pass. Redirects are not followed, proxy environment variables are ignored, and HTTPS probes verify certificates using the probe client's bundled public CA roots; private CA roots are not configurable for probes yet. Use a cheap endpoint that reports application readiness. With **Preserve the incoming Host header** enabled, probes send the route hostname; for a `*` route they use each origin's hostname. Probes do not count toward traffic metrics or request logs.

A newly configured or restarted monitored pool waits for successful probes before receiving traffic. **Healthy** means every non-draining backend is available; **Degraded** means some are available; **Unavailable** means none passed. **Drained** means every backend is intentionally excluded. With no eligible backends the proxy returns **503**. A failure between probes can still cause a request to fail before the failure threshold is reached. Optional safe transport failover can try another eligible backend under the policy below. Unmonitored pools treat every non-draining origin as available; use health checks for proactive exclusion.

Backend dots show health; hover for the last result, check time, and probe duration. Traffic logs record the final selected origin and ordered attempted origins; search for `failover` to find requests with multiple attempts. Pool and probe changes apply live; changing origins, probe settings, or host-header behavior clears the pool's previous health results. Paused routes are not probed. Health state and rotation reset on process restart; configuration persists and is included in import/export and revision backups. Existing connections finish normally.

The monitor allows up to 256 configured health-checked origins across all hosts, runs up to 32 concurrent probes, and schedules due probes about once per second. Under heavy probe load, the effective interval can be longer than configured. The authenticated `/api/upstreams` endpoint returns per-route origin status, weight, draining flag, active-request count, and the matching configuration revision. Draining origins continue to be probed, but do not generate backend-failure alerts until resumed.

## Timeouts and safe failover

Edit a host and expand **Timeouts & safe failover**. Existing routes keep 5-second connection, 60-second read, and 60-second write limits, with retries disabled. Enable the policy to customize:

| Setting | Default | Range |
| --- | --- | --- |
| DNS/TCP/TLS connection budget per attempt | 5 seconds | 1–120 seconds |
| Individual upstream read wait | 60 seconds | 1–3600 seconds |
| Individual upstream write wait | 60 seconds | 1–3600 seconds |
| Additional failover attempts | 0 | 0–3 |

The connection budget includes DNS lookup and the remaining TCP/TLS setup. Read/write limits bound individual I/O waits; they do not cap the lifetime of a streaming response. A terminal upstream timeout returns **504** if no response has started. Other terminal upstream transport failures return **502**, and an empty eligible pool returns **503**. Route response/header policies apply to generated errors.

Failover is opt-in. It only retries bodyless **GET/HEAD** requests after DNS/connect/TLS-timeout or transport failures before any upstream/downstream response has started. Each origin is tried at most once, and retries skip unhealthy, draining, and previously attempted backends. Request bodies (including HTTP/2 streams that are not ended), writes such as POST/PUT/DELETE, upgrades, HTTP error responses, protocol errors, and certificate verification failures are not retried. A partial response is closed rather than replayed. Use retries only for services where GET/HEAD follow safe read semantics: the first origin may already have processed a request before a transport failure.

Retries do not rerun IP access checks or consume another rate-limit token. Host rewriting and forwarded identity still follow each selected origin. Cache hits do not make upstream attempts, and eligible misses can fill the cache after failover. Each request retains its admitted timeout/retry policy; subsequent selections honor current pool health, weights, draining, and strategy. Changing/removing its origin pool or disabling its route stops further selection into that pool. Configurations, backups, and route exports preserve the policy. Server retry/error summaries omit query strings, as do durable logs.

## Advanced load balancing and draining

**Traffic distribution** supports:

| Strategy | Behavior |
| --- | --- |
| Round robin | Equal turns across eligible origins; weights are ignored. |
| Weighted round robin | Smooth proportional distribution; weights 3 and 1 yield approximately 75% and 25% of requests. |
| Least active requests | Select the smallest active-request count divided by its weight; ties rotate. Counts refer to HTTP requests, rather than idle TCP connections. |
| Client IP affinity | Weighted rendezvous hashing of the verified visitor IP and origin; the same IP selects the same eligible backend without setting a cookie. |

Weights range from **1–100**, one per origin, and default to 1. Affinity uses the trusted-proxy identity rules; spoofed headers from untrusted peers do not change selection. Clients sharing a NAT/proxy IP share affinity. A changed IP, weight, pool, or availability can move a client. If an IP is unavailable, selection falls back to round robin. Affinity is independent of application session cookies, and weighted hashing describes distribution across visitor IPs rather than exact request counts.

Check **Drain** beside an origin and save to exclude it from new selections. Existing requests retain their backend and finish normally. Health checks continue, so resuming uses current health state. The backend row shows **Draining** and its observed active-request count (updated on the dashboard poll). If all origins are draining, uncached requests return **503**. Counts are released on completion, failure, or cancellation and are shared across workers in one process. Weight/strategy/draining changes preserve probe results; activity accounting also survives a probe-policy change. Load-balancer runtime counters/scores reset on restart, while configuration persists.

## Path rewrites and request headers

In the proxy host editor, open **Path rewrites & request headers** and enable **Customize upstream requests**. Choose to preserve the public path, strip the matched route prefix, or replace it with an upstream prefix. For example, a route matching `/api` can forward `/api/items?limit=10` as `/items?limit=10` or `/internal/items?limit=10`. The live preview shows the resulting path, primary origin, Host, and configured header changes without making a request. A load-balanced request may select another configured origin.

Matching uses the existing **literal prefix** rule: `/api` also matches `/apiv2`; use `/api/` when you want the trailing slash to participate in matching. Empty stripped paths become `/`. Replacement joins insert a slash if neither side supplies one, or merge one slash if both sides supply one. Other slashes, percent escapes, and the query remain unchanged; paths are not decoded or normalized. Replacement prefixes start with a single `/`, contain at most 1024 ASCII bytes, and exclude queries, fragments, whitespace, and backslashes. Percent-encode non-ASCII characters.

Set headers using one `Name: Value` per line, or remove headers using one name per line. Overrides replace all existing values. Each list supports up to 32 entries; names are case-insensitive and unique across both lists. Values are limited to 4096 ASCII bytes and cannot contain newlines. Host uses the separate **Preserve incoming Host** control. Authentication/cookie, forwarding identity, connection/framing, body/accept encoding, cache/conditional, and WebSocket handshake headers are protected. These settings are ordinary route configuration, visible to configuration readers and included in exports; keep secrets out of them.

The original public URL determines route selection, IP access, rate budgets, HTTPS redirects, cache keys/purges, and traffic logs. Routing policy edits invalidate that route’s cache. The method and body remain intact. Every failover attempt derives its transformation from the original request, so prefixes are not stripped or replaced twice. Health probes continue to use their separately configured health-check path and headers. Existing routes without a routing policy retain their behavior.

Configuration example:

```json
"routing": {
  "strip_prefix": false,
  "rewrite_prefix": "/internal",
  "set_headers": [{ "name": "x-application", "value": "EmberGate" }],
  "remove_headers": ["x-debug"]
}
```

## Maintenance and gateway error pages

In **Edit proxy host → Maintenance & error pages**, enable maintenance and configure a title, message, status, and **Retry-After** hint. A shield action in the host table also starts or ends maintenance after confirmation, keeping the saved page settings. Maintenance is persisted with the route and survives restarts. It affects that host/path route; paused hosts remain unmatched, and unrelated routes continue normally.

Maintenance stops new cache hits and upstream requests **after IP access rules, HTTPS redirects, and rate limiting**. Existing requests finish normally and health probes continue. The default response is **503 Service Unavailable**, which counts in existing error metrics and can trigger error-rate alerts. Choose **200** only for an intentional holding page that should report success. Retry-After accepts 1–86400 seconds; it does not schedule the end of maintenance or automatically refresh a browser. Turn maintenance off to resume forwarding. Page-policy changes invalidate the route’s cache namespace.

Titles support 1–120 Unicode characters; messages support 1–2000. These are plain text, escaped in the HTML page, and included in route imports/exports. A live preview uses the dashboard theme. Visitor pages use the visitor’s system theme, work on mobile, and load no external resources. Responses include `Cache-Control: no-store`, `Vary: Accept`, the correct body length, and Retry-After. HEAD sends the same headers without a body. Plain responses contain the configured message; the title appears on the HTML page. Maintenance requests are labeled **Maintenance** in traffic logs and have no selected/attempted backend.

EmberGate also renders branded pages for **gateway-generated** errors, including unmatched hosts (404), access blocks (403), rate limits (429), unavailable backends (503), failed connections (502), and timeouts/cache misses requiring a cached response (504). HTML requires an explicit acceptable `text/html` entry in the request’s Accept header; absent headers, wildcards, JSON requests, and `text/html;q=0` retain plain text. Turn off **Show branded gateway error pages** for a route to force its gateway errors to plain text. Maintenance still offers HTML when accepted. Application responses, including application 4xx/5xx pages and partial responses, pass through unchanged.

Local HTML pages carry a restrictive Content-Security-Policy, MIME-sniff protection, and no-referrer policy. Route response policies still apply, with generated content type, framing, no-store, representation variation, and HTML security protections taking precedence. Pages do not expose backend error details or reflect request paths/query strings.

Configuration example:

```json
"pages": {
  "maintenance": true,
  "status": 503,
  "title": "We’ll be back shortly",
  "message": "We are upgrading this service. Please try again later.",
  "retry_after_seconds": 300,
  "branded_errors": true
}
```

## Rate limiting

Add or edit a proxy host, expand **Rate limiting**, and enable a policy. Set the sustained request allowance, interval in seconds, and burst allowance. The default form suggests **60 requests per 60 seconds**, with a **20-request burst**. Existing hosts are unlimited until a policy is enabled.

Each route/client IP pair has a separate token bucket. It starts with the burst allowance and refills continuously at `requests / window_seconds` tokens per second, up to the burst size. Each request uses one token. For example, 60 requests per 60 seconds with burst 20 allows 20 immediately, then replenishes one per second. This is a sustained rate with burst control, not a fixed calendar window quota. Burst must be at least 1, at most 100,000, and no greater than requests per interval. Allowances support 1–1,000,000 requests per 1–3,600 seconds.

Requests without a token receive **429 Too Many Requests**, a whole-second **Retry-After** estimate, and **Cache-Control: no-store**. They never reach an upstream or consume its pool rotation. All methods use the same budget, including HEAD and POST. Limits apply after route matching and before backend selection, so requests to an unavailable pool also consume the allowance. Unknown routes keep returning 404. Management API requests and health probes do not use proxy rate budgets.

Rate limits use the verified visitor IP described under **Trusted proxies**. Without a matching trusted network, this is the socket connection IP. Forwarded headers from other connections are ignored. IP addresses sharing a NAT also share a budget. A wildcard host or multiple paths matching the same route share that route's budget; separately configured routes have separate budgets.

The overview shows gateway-blocked requests and enabled policies. Host rows summarize their limit. In traffic logs, gateway blocks show **Gateway limit**; searching for `rate limited` finds them. An upstream's own 429 response is logged normally and does not increment the gateway's blocked count or the 5xx server error counter.

Policy changes and disabling take effect live. Changing a policy resets its token budgets; unrelated route edits and configuration saves preserve them. Removing a policy or pausing/deleting its route clears its budgets. Policies persist through restart, import/export, and revision backups. Token budgets and overview counters reset on restart; historical blocked counts are retained in Analytics. Budgets are shared by workers within one gateway process, independently of other gateway instances.

The limiter retains at most 100,000 live route/client buckets. Fully replenished buckets are periodically reclaimed during traffic. At capacity, new identities receive 429 rather than displacing existing clients' budgets. Retry-After is an estimate; concurrent traffic or bucket capacity can delay admission further.

## Response caching

Open **Caching → Configure** on a route, or edit a proxy host and expand **Response caching**. Enable it only for public content. Cache policies persist in routes.json and participate in live saves, revision checks, import/export, and backups. Cache bodies and counters are in memory and reset on restart.

| Setting | Form default | Range |
| --- | --- | --- |
| Maximum freshness | 300 seconds | 1–86400 seconds |
| Maximum response body | 1024 KiB | 1–4096 KiB |
| Cache URLs with query strings | Off | Opt in per route |

The gateway uses Pingora's native cache hooks with a bounded LRU storage implementation. Only **GET** responses with status **200** and a positive explicit **Cache-Control: s-maxage** or **max-age** are admitted. s-maxage takes precedence. The policy caps the origin's freshness lifetime; Age, Date, and response delay reduce its remaining lifetime. No default/forced freshness is invented. Missing freshness, Expires-only responses, invalid or duplicate directives, and private/no-store/no-cache responses bypass storage. Stale objects are removed; this version does not deliberately serve stale content or retain bodies for revalidation.

**HEAD** may use an existing GET object but never fills an object on a miss. Requests with **Authorization**, **Proxy-Authorization**, **Cookie**, Range, conditional headers, request bodies, Upgrade, or Pragma bypass caching. Request Cache-Control directives also bypass, except **only-if-cached**, which can use an eligible hit and returns **504** if no usable cached response exists. Cookie/authenticated requests remain excluded even when an origin marks its response public. Responses carrying Set-Cookie, Content-Range, or Trailer are not admitted. Vary is supported only for Accept-Encoding; Vary: * and all other dimensions bypass rather than risk mixing variants.

Keys include the route, verified HTTP/HTTPS scheme, request authority, exact path/query, and Accept-Encoding values. HTTP/2 :authority is supported when Host is absent. Query strings are excluded by default; when enabled, every parameter and its ordering remains part of the key. Queries are never ignored or logged. Caching pooled origins assumes they serve interchangeable public representations. Origins must accurately declare freshness and Vary; use a separate noncached route for personalized content.

Access rules, HTTPS redirects, and rate limits run **before cache lookup**. Cache hits therefore cannot bypass these policies or their request budgets. Response policies apply to hits as well as origin responses. Fresh cached objects can be served even when no healthy origin is available; a miss still requires an eligible backend. Successful unsafe requests (for example POST, PUT, PATCH, DELETE) invalidate the entire matched route's cache. Invalidating outside this gateway requires an explicit purge or waiting for freshness to expire.

The shared store accounts for up to **64 MiB**, including allocated body/metadata buffers and entry overhead, with at most **4096 entries**. Up to **16 fills** buffer responses concurrently, each limited to the configured body maximum (at most 4 MiB) and 64 KiB of serialized metadata. These temporary buffers and bytes held by active readers are additional to committed storage accounting. LRU entries are evicted to make room. Oversized responses continue streaming to the client without being stored. Concurrent misses for a key use Pingora's cache lock, waiting up to two seconds before falling back to independent fetches; fill capacity errors fail open to normal proxying.

**Caching** shows per-route hits, misses, bypasses, object counts, accounted bytes, and the hit ratio `hits / (hits + misses)`. A miss records an eligible lookup that went to origin; it does not guarantee the final response was stored, for example if a streaming body exceeds its limit or a fill is invalidated. Bypasses cover excluded requests/responses. Gatekeeping responses before cache lookup do not affect these counters. Removing/pausing a cache policy clears its runtime namespace/counters. Ordinary policy edits invalidate content while retaining counters. Traffic logs persist each request's cache outcome; clients also receive **X-EmberGate-Cache: HIT**, **MISS**, **BYPASS**, or **OFF** on regular proxied and route-generated responses. Hits include Age. The former X-Current-Cache header is also emitted for existing integrations.

Use **Purge** on a route or **Purge cache** for the global scope. Leave the URL field empty to remove every object in scope, enter an exact path/query to remove its host/encoding variants, or enter a full HTTP(S) URL to select its scheme and authority too. URI query ordering and escaping matter; use an exact path for unusual literal request paths. URL purges preserve other stored URLs. All purges invalidate older in-flight fills for the selected route(s), so those fills cannot repopulate the store. Requests already reading a hit may finish. Changing a route or trusted proxy configuration invalidates affected cache namespaces; changing unrelated routes preserves other objects.

Management endpoints are authenticated: **GET /api/cache** returns counters/storage usage and **POST /api/cache/purge** accepts optional route_id and url fields (null means all routes/URLs). Purge requires the same request verification header as other management mutations. Client-side PURGE requests do not trigger management actions.

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

## Settings navigation

Click **Settings** in the main sidebar to open a second navigation panel beside it. Each option shows its own page: **Instance details**, **Password & two-factor**, **Cloudflare DNS**, **Trusted proxies**, **Host templates**, **Configuration import / export**, **Configuration history**, **Full backup & restore**, and **Automatic backups**. Password and authenticator controls share the security page. Only the selected section is shown, and the last selected section is remembered while using the dashboard.

On smaller screens, the second panel becomes a **Settings section** dropdown above the selected page. Administrator-only sections are excluded for read-only accounts; existing read-only controls and API permissions still apply. Opening an unavailable administrator section redirects to Instance details.

Pages have bookmarkable URLs such as `http://127.0.0.1:9090/#/settings/cloudflare`, `#/settings/security`, and `#/settings/automatic-backups`. Reloading, browser Back/Forward, and opening a settings link in another tab retain the selected section after sign-in. Ordinary dialog requests are cancelled when leaving their page; authentication dialogs preserve their recovery-code acknowledgement requirements.

## Response compression

Open a host's **Advanced settings → Response compression** and enable it. Choose **Automatic** (Brotli preferred when client qualities tie, with gzip fallback) or **Gzip only**, compression level **1–6**, and a minimum declared response size of **256–1048576 bytes**. Defaults are automatic, level 4, and 1024 bytes. Save the host to apply changes live. Compression is disabled on existing hosts until enabled.

Compression applies to proxied **public GET responses with status 200** over HTTP/1.1 and HTTP/2. Supported content types are text (except event streams), JSON and `+json`, JavaScript, XML and `+xml`, SVG, and WebAssembly. Known-length responses below the threshold pass through; supported text streams without a Content-Length compress incrementally without whole-response buffering. Higher levels use more CPU.

Requests containing Cookie, Authorization, Range, If-Range, or Upgrade headers bypass compression. Responses containing Content-Encoding (including `identity`), Content-Range, Set-Cookie, `Cache-Control: private` or `no-store`, and request/response `no-transform` also bypass it. Images other than SVG, archives, PDFs, fonts, audio/video, binary downloads, event streams, other statuses, HTTP/1.0, and non-GET methods pass through. HEAD preserves the origin/cache metadata. Local maintenance/error responses use their existing path. Existing upstream encodings are forwarded without decompression or re-encoding; the origin remains responsible for negotiating encodings it generates.

Negotiation handles quality values, explicit exclusions, wildcards, case-insensitive tokens, and multiple Accept-Encoding fields. An explicit higher preference for identity is respected; absent or empty Accept-Encoding uses identity. Unsupported algorithms do not enable proxy compression. Conflicting duplicate preferences use the lower quality. For an enabled host's unencoded 200 GET response, forbidding identity when no eligible supported encoding is available produces an empty **406 Not Acceptable**, marked `no-store`.

Responses that can vary by selected coding include **Vary: Accept-Encoding**, including their identity variant and conditional 304 responses, while preserving existing Vary fields and `Vary: *`. Transforming a body removes its original Content-Length and Accept-Ranges, weakens strong ETags, and removes body digests from headers/trailers so they cannot describe different bytes. HTTP/1.1 uses chunked framing; HTTP/2 uses DATA frames without Transfer-Encoding. The Brotli writer flushes incremental chunks and finishes its stream explicitly. Pingora's gzip encoder handles gzip; the existing Brotli library supplies Brotli finalization.

Compression runs **after** Pingora's cache pipeline on both misses and hits. The cache keeps the origin representation, retains Accept-Encoding isolation for origin variants, and compresses the selected response for each visitor. Compression policy changes invalidate that host's cache namespace. The policy is preserved in route exports, configuration-history rollback, host duplication, policy templates, and manual/automatic full encrypted backups.

Example route field:

```json
"compression": {
  "mode": "auto",
  "level": 4,
  "min_bytes": 1024
}
```

Omit the field or set it to `null` to disable compression. Existing history and backups without it remain compatible.

## Host templates and duplication

Use the **Duplicate** icon on a host row to open an independent copy in the editor. The copy gets a new UUID, a blank hostname, and a paused status. Enter a different hostname or path and review it before saving. The upstream pool, weights, drain flags, maintenance page settings, and all host policies are copied; the source is unchanged. Nothing is saved until **Save host**. A duplicate uses the normal version/conflict checks and configuration history. Enable the new host when ready.

Open **Settings → Host templates → Create template** as an administrator, enter a unique name and optional description, then choose a saved source host. Templates include compression, caching, IP access rules, HTTPS/response headers, rate limiting, timeouts/failover, request rewriting/headers, health checks, Preserve Host, and branded gateway errors. They exclude host identity, match hostname/path, enabled status, upstream origins, balancing weights/drain flags, maintenance state/page text, certificates, global trusted proxies, and credentials. Unsaved changes in a host editor are excluded.

The library shows each template's policies, last editor, and update time. **Edit** can rename it or replace its policy copy from another saved host; leave **Copy policies from** on **Keep saved policies** for a metadata-only change. Source configuration and template-library versions are checked when saving. If another session changes them, close and reopen the form before trying again. Deleting or updating a template leaves existing hosts unchanged.

In the add/edit/duplicate host dialog, open **Use a policy template**, select a template, and choose **Review & apply**. The picker appears once templates exist. Review the policy values and confirm **Apply to draft**. All reusable policy fields are replaced, including clearing fields that are absent in the template. Identity, enabled status, upstream origins/weights/drain flags, and maintenance settings stay as entered. Review the draft and **Save host** to make it live. Templates are independent copies, with no ongoing inheritance or synchronization.

Up to **50 templates** are stored within **2 MiB** in **data/host-templates.json**, atomically replaced with Unix permissions 0600. The library is administrator-only and may contain custom policy headers. Full encrypted backups include and validate it; restore reviews show the template count. Restoring an older backup without templates clears a newer library. Route-only exports and configuration-history rollback cover saved host policy copies, without changing the template library.

The administrator API is `GET /api/host-templates`, `POST /api/host-templates`, and `DELETE /api/host-templates/{id}` with the normal session/CSRF header. POST accepts `name`, optional `description`, `expected_version` (library version), optional `id` to edit, and `source_route_id` plus `expected_config_version` to copy saved policies. A new template requires a source; edits may omit it to keep policies. DELETE requires JSON `{"expected_version": <library version>}`. Stale versions return 409. Writes pause while a complete restore is queued. These operations do not change the active route configuration.

## Configuration history

Administrators can open **Settings → Configuration history** to compare an earlier revision with the live configuration. Open a changed host to see the current and proposed values for each changed field. Added/removed hosts, trusted proxy changes, and host ordering are also shown. **Confirm rollback** replaces the complete route and trusted-proxy configuration immediately as a new, increasing revision. The previous configuration is retained, and the audit trail records the rollback source. If the configuration changed after the comparison, close the review and compare again.

History starts with configuration saves after upgrading. Each save archives the configuration that was active before replacing it, including revision 0 on a new installation. The table's time and username identify when a revision was archived and who replaced it, rather than its original creation time or author. Up to **50 earlier configurations** are retained within **32 MiB**; older entries are removed first. A failed save can retain a snapshot of the still-active configuration, but never records the failed candidate as active. The current configuration is omitted from the earlier-revision table.

Revisions live in **data/configuration-history.json**, atomically replaced with Unix permissions 0600. They can contain old hostnames, upstreams, policies, and custom headers, so listing, comparison, and rollback require an administrator. Damaged history blocks configuration saves until repaired instead of silently discarding earlier revisions. Certificates, accounts, credentials, analytics, and listener settings use their own management controls and are unaffected by route rollback.

Full encrypted backups include retained revisions and validate their contents and hashes. Older backups without a history file remain supported; restoring one clears the newer history. Route-only JSON exports contain the selected current configuration, without earlier revisions. Restore previews show the number of included revisions.

The administrator API is `GET /api/config/history`, `GET /api/config/history/{id}`, and `POST /api/config/history/{id}/rollback` with JSON `{"expected_version": <version returned by comparison>, "confirm": "ROLLBACK"}` and the normal session/CSRF header. Revision IDs are content hashes; a pruned revision returns 404, and an outdated comparison returns 409. Configuration writes pause while a full restore is queued.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `GATEWAY_ADMIN_PASSWORD` | Unset | Optional recovery override; at least 12 characters, at most 1024 UTF-8 bytes |
| `GATEWAY_ADMIN_ADDR` | `127.0.0.1:9090` | Management listen address |
| `GATEWAY_PROXY_ADDR` | `127.0.0.1:8080` | Client HTTP listen address |
| `GATEWAY_HTTPS_ADDR` | Disabled | Optional client HTTPS listen address, for example `127.0.0.1:8443` |
| `GATEWAY_DATA_DIR` | `data` relative to working directory | Configuration storage |
| `GATEWAY_SECURE_COOKIE` | `false` | Set to `true` when accessing the dashboard through HTTPS |
| `GATEWAY_CLOUDFLARE_API_TOKEN` | Unset | Optional override for the saved DNS-01 token |
| `GATEWAY_CLOUDFLARE_API_TOKEN_FILE` | Unset | Read the token from a secret file instead |
| `GATEWAY_DNS_PROPAGATION_TIMEOUT` | `300` | DNS propagation wait in seconds, from 5 to 1800 |
| `RUST_LOG` | Logging library default | Use `info` for application logs |

`routes.json` holds the active configuration. Each save writes `routes.previous.json` before replacing the active file. Invalid saves and stale revisions leave active routes intact. Invalid configuration on startup fails startup. Only run one gateway process per data directory.

Exact hostnames take priority over the `*` fallback. Within a hostname, the longest matching literal path prefix wins. `/api` also matches `/apiv2`; use `/api/` for slash-bounded routes. Paths and queries are forwarded unchanged. By default the upstream Host header follows its URL; enable "Preserve the incoming Host header" when the upstream needs the public hostname. Upstream TLS uses the upstream URL hostname for SNI and certificate verification. DNS is resolved per request and uses the first returned address.

Management listens locally by default. If you access it remotely, place it behind HTTPS and enable secure cookies. Richer cache variation policies are future work. Sessions, token budgets, overview counters, and the overview minute chart reset on restart. Analytics history and recent request logs persist locally; logs omit query strings. Average latency covers full request completion; the server error rate counts 5xx responses. Counters cover all requests through the proxy, including unmatched hosts. Forwarding headers are rebuilt using the verified client IP and protocol. Upstream-facing CF-Connecting-IP, CF-Connecting-IPv6, True-Client-IP, and incoming X-Real-IP values are removed; X-Forwarded-For and X-Real-IP contain the verified visitor address.

## Scheduled encrypted backups

Open **Settings → Automatic backups**. Choose an interval of **1–168 hours** and retain **1–30 local backups**, open **Encryption passphrase**, enter and confirm a passphrase of at least 12 characters, enable the schedule, and save. Saving starts the next interval; **Back up now** queues an immediate snapshot using the saved settings, even if the automatic schedule is disabled. The gateway runs the scheduler itself; the browser can be closed. A missed interval runs once after restart, without replaying every missed interval.

Automatic files use the same encrypted `.embergate` full-backup format and size limits as manual exports. They include routes, accounts, certificates and private keys, saved credentials, MFA, analytics, audit history, and alert state. Files are stored in **data/.embergate-backups/scheduled/** (0700 directory, 0600 files on Unix). After a new encrypted file is safely saved, retention removes older owned files while preserving the new copy. Unrelated files are left alone. The local table supports download and confirmed removal. To restore a downloaded file, use **Full backup & restore** and its normal validation/review/restart flow.

For unattended encryption, EmberGate saves the automation passphrase **unencrypted in its private management database**, as it already does for credentials that must be retrievable. Protect the data directory and keep a separate copy of the passphrase. Exported snapshots, including previous-state recovery exports, deliberately omit this passphrase and rebuild the copied database to remove obsolete values from free SQLite pages. Restoring a snapshot therefore requires re-entering an automation passphrase before scheduled backups resume. Schedule settings, offsite credentials, and recent scheduler state are included; queued/running jobs are cleared from exports. The local archive collection is not included recursively. A local pre-restore recovery directory still contains the previous private database and must be protected accordingly.

Replacing the passphrase affects future archives; older archives still require their original passphrase. **Forget the saved passphrase and disable this schedule** removes the saved credential. Saved secrets are never returned by the schedule API, account lists, or audit records. Normal backups continue to include all other supported credentials. Manual exports can use their own passphrase.

For an optional offsite copy, open **Offsite copy**, enable uploading, and provide an existing **HTTPS / WebDAV folder URL ending in /**. The destination must support [HTTP PUT](https://www.rfc-editor.org/rfc/rfc4918.html#section-9.7). Choose no authentication, a bearer token, or Basic authentication with a username and password/app password. The server appends a unique archive filename and uploads only encrypted bytes. It does not create folders, follow redirects, or use environment HTTP proxies. Uploads have a 10-second connect limit and a 30-second total limit. HTTP is accepted only for loopback fixtures. URL credentials, queries, fragments, and URLs longer than 2048 bytes are rejected; changing a destination requires explicitly selecting its authentication again. The UI shows the saved destination's origin, never its private path or credentials. Configure remote retention with your storage provider; EmberGate's retention only removes local files.

A failed offsite upload keeps the local encrypted backup. The status distinguishes the latest local copy from the last fully successful local/offsite run. Failed enabled schedules retry after five minutes. Interrupted runs get a one-minute retry deadline after restart. Scheduled jobs defer to an existing backup operation, and new automatic work pauses while a full restore is queued. Settings and local deletions are blocked while a scheduled job is running; configuration/account edits can continue during uploads. Saving settings cancels a queued run, but cannot change an active one. An upload already in progress may finish before a queued restore is applied.

Enable **Show failure alerts and send through enabled notifications** to report failures in **Alerts**. Notifications use the existing opt-in Discord/generic webhook destination and delivery queue. An open failure remains open during a retry and resolves after success. Backup actions and system runs are audited without passphrases, destination paths, upload credentials, or response bodies. Schedule management, file downloads, and removals require an administrator session and honor MFA. Mutations also require `X-Gateway-Request: 1`.

The endpoints are **GET/PUT /api/backups/schedule**, **POST /api/backups/schedule/run**, and **GET/DELETE /api/backups/scheduled/{name}**. Settings updates use their own revision number. The scheduler checks for due work every five seconds; queued work may take a few seconds to begin. No additional database service is required.

## Diagnostics

Open **Diagnostics** in the sidebar, or use the magnifying-glass action on a proxy host. Choose a saved host or enter a visitor hostname (optionally with its port) and a URL path. For a wildcard host, replace the example hostname with the actual visitor hostname you want to inspect.

**Check routing** takes a snapshot of the current configuration and shows the same exact-host/wildcard/longest-prefix match used by the proxy, the rewritten upstream path, paused matches excluded from routing, the Host-header policy, and the configured traffic timeouts. It also shows the currently valid certificate selected for that visitor hostname and whether the HTTPS listener is enabled. This preview sends no network requests.

**Run backend checks** resolves and checks every saved origin on the matched active route, including draining origins. Each backend card shows resolved addresses, the selected address, separate DNS/TCP/TLS/HTTP timings, the sent Host header, and the last monitored health status. HTTPS checks verify the certificate chain and the origin hostname with OpenSSL's configured trust store; successful checks show certificate expiry and days remaining. Upstream SNI uses the origin hostname even when the HTTP Host header preserves the visitor hostname.

A probe sends **HEAD** over a new HTTP/1.1 connection to the rewritten path, retaining the original query and configured request-header overrides/removals. It copies no dashboard cookies or authorization headers, follows no redirects, sends no body, and reads only response headers. A 4xx/5xx response means the backend responded with an application error; 405 may mean the application does not support HEAD. DNS resolution uses the first returned address, matching the proxy's current selection. The preview hostname chooses a saved route; it never becomes an arbitrary outbound target.

Probes bypass visitor IP access rules, rate limits, HTTPS redirects, maintenance responses, and the response cache. Notes call out those policies so the report is not mistaken for a complete visitor request test. Diagnostics do not update monitored backend health, balancing activity, proxy traffic counters, analytics, or logs. HEAD requests can still appear in the upstream application's own logs. Route names, notes, and diagnostic values are rendered as escaped text.

Diagnostic limits are separate from traffic timeouts: **3 seconds DNS, 5 seconds TCP, 5 seconds TLS, and 5 seconds HTTP**, with **two reports and four backend connections** running at once. Each report has a **30-second deadline** and a 16 KiB/64-header response limit. When the report deadline is reached, completed backend results remain available and a note identifies unfinished checks. A report marks configuration changes made during its run. Long probes do not block management saves, and routing/probing remains available while a full restore is queued.

The **POST /api/diagnostics** endpoint accepts `{ "host": "app.example.com", "path": "/health", "probe": false }` (use `true` for backend checks). It requires an administrator session, any enforced two-factor enrollment, and `X-Gateway-Request: 1`. Diagnostic actions are audited without saving request bodies, queries, credentials, or response headers. Read-only accounts cannot run diagnostics; reports are transient and are cleared on logout.

## Accounts and audit trail

Open **Accounts** to add up to 50 managed accounts. Usernames use 3–48 letters, digits, dots, underscores, or hyphens and are normalized to lowercase. Passwords require at least 12 characters (at most 1024 UTF-8 bytes). Each account has one role:

| Role | Access |
| --- | --- |
| Administrator | View and change proxy configuration, certificates, caches, accounts, alert preferences, and all sessions; view the audit trail. |
| Read-only | View gateway status, configuration, certificates, analytics, logs, and alerts; manage its own password and two-factor authentication, and revoke its own sessions. |

The reserved **admin** primary administrator cannot be renamed, disabled, or removed. Set its password on the first-run setup screen; afterward, change it in **Settings → Your password** or **Accounts → Change my password**. Managed users can change their own passwords through the same controls. Password changes require the current password and sign out all sessions for that account. An active **GATEWAY_ADMIN_PASSWORD** recovery override takes precedence over the saved admin password and disables web password changes; removing it restores the saved credential. API login requests still default to admin; enrolled accounts also require an authentication or recovery code.

Accounts, Argon2 hashes, and saved DNS credentials persist in **management.sqlite3**, with Unix permissions 0600 and SQLite WAL/full synchronous transactions. Account lists never return hashes. Route exports do not include accounts or management history; use the encrypted full backup feature or a stopped-process data-directory backup.

Sessions last 12 hours and reset on restart. Account edits, disabling, deletion, and password changes revoke all that account's sessions; an already-running request may still finish. Session lists return a separate revocation identifier, never the authentication cookie. Login attempts are limited to 20 per minute per management socket IP; forwarded visitor headers do not affect this limit. People sharing a management proxy IP share its login budget.

**Audit trail** shows the latest 200 management events, retained for 90 days or 10,000 entries. It records actor, socket peer, method, path, target identifier where available, success/failure, and configuration revisions with up to 25 changed route identifiers. Passwords, keys, request bodies, cookies, and query strings are excluded. Login outcomes and rejected authenticated writes are included. Mutations reserve a durable pending entry before running; unavailable audit storage blocks changes with 503 (logout remains available). If completion storage fails or the process stops during a change, the pending entry remains for review; it does not prove whether the change committed. Completion failure also returns **X-Gateway-Audit-Pending: 1**.

## Two-factor authentication

Open **Settings → Two-factor authentication → Set up authenticator**. Confirm your current password, add a time-based EmberGate account to your authenticator using the displayed setup key, and enter its six-digit code. Enrollment expires after ten minutes and is bound to your session. EmberGate uses [RFC 6238 TOTP](https://www.rfc-editor.org/rfc/rfc6238) with SHA-1, six digits, and a 30-second period; keep the gateway and authenticator clocks synchronized. A one-step clock tolerance is accepted, but a used time step cannot be reused.

Save or download the **ten recovery codes** shown after enrollment. Each contains 128 bits of random data, works once, and is stored only as a SHA-256 hash. Codes are never shown again. **Replace recovery codes** revokes all previous codes and requires your password plus an unused authentication/recovery code. **Disable** requires the same proof. Enrollment, replacement, and disabling revoke other sessions for your account; your current session remains available. Read-only accounts can manage their own authenticator.

Administrators who have enrolled can use **Change administrator policy** to require two-factor authentication for every administrator. Changing the policy requires your password and an unused authentication/recovery code. Existing and new administrators who have not enrolled can access only enrollment, session identity, and logout until setup is complete. An administrator cannot disable their factor while enforcement is enabled. The optional **GATEWAY_ADMIN_PASSWORD** override changes the password only; it does not bypass an enrolled authenticator or the enforcement policy. Keep recovery codes outside the gateway.

Sign-in accepts an authenticator or recovery code after password verification. API clients send `code` alongside `username` and `password` to **POST /api/login**. There is no authenticated session before both factors succeed. Factor attempts share the management socket-IP budget and have an additional per-account limit of 20 per minute. A code used to finish enrollment cannot immediately be reused for login or another sensitive action; wait for a new code or use a recovery code.

Authenticator secrets must remain retrievable to verify TOTP and use the same private, unencrypted local database storage model as other saved credentials. Full encrypted backups include authenticator secrets, recovery-code hashes, replay state, and the enforcement policy; route-only exports exclude them. Restoring an older backup also restores that older authentication state, so replace recovery codes after a rollback. Setup keys, codes, and passwords are excluded from audit records, account lists, and backup reviews. This feature protects EmberGate dashboard accounts; application authentication and passkeys are separate roadmap items.

## Alerts and webhook delivery

**Alerts** monitors enabled backend health checks, certificate issuance/renewal and DNS cleanup failures, and the proxy's recent 5xx rate. Checks run about every ten seconds. The default traffic threshold is 10% with at least 20 requests in a five-minute window; preferences allow 1–100%, 1–100,000 minimum requests, and 1–60 minutes. Traffic monitoring uses minute buckets and starts fresh on restart. Pending backend probes and queued/issuing certificate retries preserve existing alerts until the condition is known again.

Active alerts persist across restarts and are deduplicated by condition. Acknowledge an alert to mark it reviewed; it stays active until recovery. A fresh failure after recovery creates a new alert. Disabling a monitoring category resolves its active alerts. The dashboard shows up to 200 active/recent alerts; resolved history is retained for 90 days or 1,000 entries. Active alerts are retained independently.

Dashboard monitoring works without an external service. In **Alerts**, choose **Discord** or **Generic JSON webhook**, paste the webhook URL under **Webhook destination**, and save it. Then enable webhook delivery and **Save preferences**. Saving a destination saves its selected format but does not itself send a test. **Send test notification** explicitly queues a test. Administrators can change/remove destinations; read-only users can view status. The URL is never returned to browsers or audit logs and is stored unencrypted in the private management database. HTTPS is required; HTTP is accepted only for loopback fixtures. URL credentials, fragments, whitespace, and URLs over 2048 bytes are rejected.

**GATEWAY_ALERT_WEBHOOK_URL** remains an optional server override. It takes precedence over the saved destination and disables browser URL editing until removed and the server restarted. The notification format is still chosen in Alerts; old saved preferences default to generic JSON. Docker Compose already passes the optional environment variable through.

Discord uses incoming webhook URLs such as `https://discord.com/api/webhooks/ID/TOKEN`, with optional numeric `thread_id` for an existing thread. Messages contain an EmberGate embed, opened/recovered/test status, timestamp, and alert identifier where available. Mentions are disabled, and text is capped to fit the payload. Requests set `wait=true` to request confirmation. Supported Discord hosts are discord.com, canary.discord.com, and ptb.discord.com; local fixtures are also allowed. See the [official Discord webhook documentation](https://docs.discord.com/developers/resources/webhook#execute-webhook).

Generic receivers continue to receive JSON containing an `event` of `opened`, `resolved`, or `test`, a timestamp, and an alert object with identifier, source, title, and message. Tests use a simple message instead. Raw certificate errors, account credentials, and request data are excluded; configured service names and backend origins may appear. Email notification formatting is not implemented.

HTTP redirects and environment HTTP proxies are disabled. A 2xx response counts as delivered. Network/non-2xx failures retry up to five total attempts with 30/60/120/240-second delays and a ten-second request timeout. A numeric HTTP 429 Retry-After can extend a delay, bounded to one day. Response bodies and webhook URLs are never logged. Delivery is at least once: a lost response or crash after acceptance may produce duplicates. Generic receivers can deduplicate by alert identifier/event; Discord embeds include that identifier for reference. See [Discord rate-limit behavior](https://docs.discord.com/developers/topics/rate-limits).

Enabling delivery sends future transitions rather than replaying old alerts. Disabling delivery, changing its format, or replacing/removing the destination cancels pending messages; a request already in flight may finish. Removing a saved destination also disables delivery. The durable queue holds at most 1,000 pending messages and about 1,000 recent completed rows. Failed delivery counts remain visible. An absent environment destination pauses delivery if no saved URL is available.

## Prometheus metrics

In **Alerts → Prometheus metrics**, select **Generate scrape token**. Copy the token before clearing it; it is returned only on generation and its SHA-256 hash is stored in the management database. Machine scrapes use **GET /metrics** on the management listener with `Authorization: Bearer TOKEN`. Scraping is disabled until a token exists. Rotate it to revoke the previous token immediately, or disable scraping to revoke it entirely. Tokens persist across restarts. Administrator controls require an authenticated session and request verification; read-only users cannot generate or revoke tokens. **View metrics** uses the session-protected **GET /api/metrics**, also available to read-only accounts.

The exporter emits [Prometheus text format 0.0.4](https://prometheus.io/docs/instrumenting/exposition_formats/). Configure Prometheus with a local token file, for example:

```yaml
scrape_configs:
  - job_name: embergate
    scrape_interval: 15s
    metrics_path: /metrics
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/embergate.token
    static_configs:
      - targets: ['127.0.0.1:9090']
```

Put only the generated token in that file and restrict access to it. The example assumes both processes share a local network namespace. For a separate host/container, use its reachable management address; use HTTPS through your management reverse proxy for remote scrapes. The exporter adds no new listener. See the [Prometheus scrape configuration reference](https://prometheus.io/docs/prometheus/latest/configuration/configuration/#scrape_config).

| Metrics | Meaning |
| --- | --- |
| `embergate_requests_total`, `embergate_errors_total` | Completed proxy requests and 5xx responses; management traffic/scrapes are excluded. |
| `embergate_http_responses_total` | Requests by a bounded method and status-class vocabulary. Unknown methods use OTHER. |
| `embergate_request_duration_seconds`, `embergate_route_request_duration_seconds` | Global/per-route cumulative latency histograms, including cache hits and gateway responses; buckets from 5 ms to 10 s plus infinity. |
| `embergate_route_requests_total`, `embergate_route_errors_total` | Per-route request and 5xx totals. |
| `embergate_rate_limited_requests_total`, `embergate_access_denied_requests_total`, `embergate_maintenance_requests_total` | Gateway policy responses, including 200 maintenance holding pages. |
| `embergate_upstream_attempts_total`, `embergate_failovers_total` | Actual upstream attempts and additional distinct-backend attempts. |
| `embergate_uptime_seconds`, `embergate_config_revision`, `embergate_routes` | Process uptime, configuration revision, and configured route count. |
| `embergate_route_enabled`, `embergate_route_maintenance` | Current route state. |
| `embergate_backend_available`, `embergate_backend_active_requests`, `embergate_backend_draining`, `embergate_backend_weight` | Current backend eligibility, activity, drain state, and weight. Availability excludes maintenance, paused routes, draining origins, and unhealthy/pending checked backends. |
| `embergate_cache_used_bytes`, `embergate_cache_capacity_bytes`, `embergate_cache_entries` | Shared-cache storage gauges. |
| `embergate_cache_hits_total`, `embergate_cache_misses_total`, `embergate_cache_bypasses_total`, `embergate_cache_purges_total`, `embergate_route_cache_bytes` | Per-route cache counters/storage. |
| `embergate_certificate_days_remaining` | Whole days remaining for installed certificates, negative after expiry. |
| `embergate_active_alerts`, `embergate_notification_queue` | Unresolved alerts and retained outbox rows by pending/delivered/failed/cancelled state. Queue counts are gauges, not lifetime delivery counters. |

Labels use configured route/certificate UUIDs and zero-based backend indexes in origin order. Metrics exclude hostnames, origin URLs, paths, query strings, client IPs, usernames, headers, and secrets. Cardinality is bounded by the validated configuration and fixed method/status vocabularies. Route IDs can be mapped through the dashboard or authenticated configuration API. Process traffic counters/histograms reset on restart; per-route counters disappear when a route is removed. Cache counters can reset when a cache policy is removed/re-created. Storage/queue gauges reflect current retained state; scrapes take sequential snapshots rather than a transaction across all components. Use `rate()`/`increase()` for counters.

## Full backup and restore

Open **Settings → Full backup & restore** as an administrator. **Create encrypted backup** downloads an `.embergate` file after you choose and confirm a passphrase of at least 12 characters (up to 1024 UTF-8 bytes). Keep the passphrase separately; it is not stored and cannot be recovered. Backups include:

- Routes, retained configuration history and the previous saved revision when available, trusted proxies, host policy templates, and every proxy policy.
- Accounts and Argon2 password hashes.
- Certificates, private keys, managed-certificate/DNS recovery state, and saved ACME account credentials.
- Cloudflare credentials, notification destinations/preferences, and Prometheus scrape-token hashes.
- Analytics databases, audit history, alerts, and notification delivery history.

Live exports snapshot SQLite through its backup API rather than copying a database while WAL writes are active. Route/certificate changes and ACME state are coordinated during capture; busy certificate issuance/DNS cleanup returns a retry message. Analytics remains live and its database is independently consistent at its snapshot point. The active administrator password hash and Cloudflare/webhook environment credential overrides are materialized into the encrypted snapshot, without changing the live database. Listener addresses, server environment settings, custom CA-root files, memory caches, rate budgets, metrics, and sessions are not archived.

The file uses AES-256-GCM with random salt/nonce and PBKDF2-HMAC-SHA256 (600,000 iterations). The header is authenticated. It is a versioned encrypted container of fixed-name files, with no compressed archive extraction or user-selected filesystem paths. Limits are **64 MiB** of decoded persistent data, **96 MiB** for the encrypted file, and at most 100 saved ACME account files. The app supports its current database schema; incompatible schemas are rejected. Use a stopped-process filesystem backup for installations beyond these limits.

To restore:

1. Choose **Restore backup**, select the file, and enter its passphrase.
2. Review the routes, accounts, certificate validity/domains, managed certificates, credential types, and current environment overrides. Validation checks authenticated encryption, required/unique fixed filenames, SQLite schema/integrity, account hash bounds, route policies, certificates/keys, and ACME credentials/recovery records. It does not replace current data.
3. Type **RESTORE** and select **Queue restore for restart**. The review is bound to your session, expires after 15 minutes, and becomes stale after another successful management edit. Current outstanding DNS cleanup must finish before queueing a replacement. At most five reviews are staged; a new review from the same session replaces its previous review.
4. Restart EmberGate using your usual launch method (or `docker compose restart gateway`). Restore applies before databases/listeners open. All sessions end; sign in with an account/password from the backup and its authenticator or recovery code if enrolled. Current environment overrides still take precedence.

While queued, management edits and new certificate/alert automation pause. Proxy traffic continues, including cached responses; work already in flight may finish. **Cancel queued restore** resumes normal management without replacing data. Backups can still be downloaded while a restore is queued. Uploaded review data, temporary snapshots, and recovery copies use private directories (0700) and files (0600 on Unix); staged plaintext contains the same sensitive material as the private data directory. Expired reviews are cleaned up during later backup operations.

Before replacement, startup saves a consistent local recovery copy under the data directory and writes a durable restore journal. An interruption during replacement resumes the same replacement on the next start; the server does not start with partial data. A committed receipt makes marker cleanup idempotent. A data-directory process lock prevents a second EmberGate instance from restoring over a live process. A validation or filesystem failure stops startup for repair, retaining the journal and recovery data. Restore records a success event in the restored audit database; existing queued notification sends are cancelled to avoid replaying old messages. Saved notification preferences and certificate automation resume afterward.

After a successful restore, **Download previous state** exports the recovery copy as another passphrase-encrypted backup. Validate/review/queue that backup to restore the previous saved installation. Recovery preserves the previous saved data; external environment settings remain managed separately. Recovery snapshots are retained locally; protect this directory and retain a separate downloaded backup. The review never displays hashes, tokens, private keys, DNS challenge values, or passphrases. Read-only accounts cannot access full backup endpoints.

Existing **Export configuration / Choose JSON file** controls remain route-only operations. See [ROADMAP.md](ROADMAP.md): the original and next-phase features are implemented; larger planned features and release validation remain. Slack notifications are outside the current scope.

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

Verified locally with Rust 1.99: the Rust tests, seventeen dashboard tests, JavaScript syntax check, Rust formatting check, real proxy/pool/rate-limit/policy/cache/TLS/accounts-alerts/credentials/reliability-balancing/routing/pages/monitoring/backup/MFA/diagnostics/scheduled-backups/config-history/templates/compression integration checks, and browser interaction check pass. The local Pebble DNS-01 integration check passed previously and was not rerun for the WebGUI credential change (the Pebble executable is no longer available locally). The browser check uses an installed Chromium-compatible browser, verifies separate Settings pages, desktop/mobile navigation, bookmarkable links, Back/Forward, reloads, permissions, and MFA recovery-code preservation, tests caching controls and purge scopes, trusted proxies, access/response policies, persisted analytics views, pool/health and rate-limit configuration, and ACME request/production/renew/stop controls, and confirms the mobile page does not overflow. `gateway/Cargo.lock` records the resolved dependencies and Docker builds use it. Live Cloudflare/Let's Encrypt issuance requires your token and domains and was not exercised. Docker image builds have not been verified.

## GitHub repository

**Application license:** pending the project owner's selection. No root license has been assigned to EmberGate's own code. Pingora retains its existing Apache 2.0 license; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Select the application license before public release.

The repository keeps EmberGate at the top level and pins unmodified Cloudflare Pingora as the `pingora/` Git submodule. Clone with submodules as described above. Commit `gateway/Cargo.lock`, `.gitmodules`, and the Pingora submodule pointer along with application changes. Runtime state, environment files, private keys, exported backups, build outputs, and local tooling directories are excluded by `.gitignore`. Keep deployment secrets in private environment/service configuration or the dashboard, never in repository files.

GitHub Actions runs formatting, Rust tests/builds, dashboard checks, local integration suites, browser interactions, Compose configuration validation, and a container image build on pushes and pull requests. Browser screenshots are retained as workflow artifacts. The workflow does not publish images or deploy anything. Pebble DNS-01 tests and live Cloudflare/Let’s Encrypt checks require separate setup and are excluded from CI. A successful workflow run is still required after the first push; adding CI does not establish that the container or hosted runner checks have passed.

The repository is hosted at [karlocizma/EmberGate](https://github.com/karlocizma/EmberGate). Clone it with:

```sh
git clone --recurse-submodules https://github.com/karlocizma/EmberGate.git
cd EmberGate
```

For an existing checkout, initialize the framework with `git submodule update --init --recursive`. Contributions and subsequent changes can be reviewed with `git diff` before committing and pushing.

The repository was created as private. Enable private vulnerability reporting before making it public. Contribution guidelines and issue/PR templates are included. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for Pingora attribution and dependency notices.

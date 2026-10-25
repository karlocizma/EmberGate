# Proxy hosts and traffic policies

[Documentation index](README.md) · [EmberGate overview](../README.md)

## Proxy host editor

New hosts use a three-step setup:

1. **Destination:** enter a name, public domain, and the application's HTTP/HTTPS address as reachable from EmberGate. The optional application category explains suitable settings for general web applications, streaming/live updates, static content, APIs, or custom applications. Categories offer guidance without silently changing policies.
2. **Access:** allow HTTP or redirect HTTP to HTTPS. Allowing HTTP does not disable HTTPS when a valid matching certificate exists. The wizard checks the loaded certificate metadata and warns about missing certificates or a disabled HTTPS listener; a matching certificate does not prove browser trust. Add or request certificates under **Certificates** before enabling HTTPS for visitors.
3. **Review:** inspect the destination, visitor access, status, and optional policies. **Create host** saves the route. For active hosts with a specific hostname, **Create & check connection** saves first, then opens Diagnostics and sends bounded HEAD checks to the saved route's backends. This checks backend reachability, not public DNS or firewall port forwarding. Paused copies remain paused unless you explicitly change their status.

**Advanced settings** is optional on the review step and groups controls by purpose:

- **Access:** external application login, IP rules, rate limiting, and HTTPS/response headers.
- **Performance:** compression and caching. Start with caching off for personal or signed-in content.
- **Routing:** public path prefix, path/header rewriting, and preserving the incoming Host header.
- **Availability:** host status, backend pools, health checks, timeouts/failover, upstream HTTPS verification, and maintenance/error pages.

**Upstream HTTPS verification** is enabled by default. Turn off **Verify upstream TLS certificate** in the host editor basics only for a private HTTPS origin whose certificate EmberGate cannot trust, such as a self-signed certificate. TLS encryption remains active, but EmberGate will accept any certificate and hostname; an attacker able to intercept that network connection could impersonate the origin. The setting applies to proxy traffic, backend health checks, and Diagnostics for every HTTPS origin in that host's pool. Prefer installing your private CA in EmberGate's system trust store when practical; health checks, Diagnostics, and external login checks can also trust it through [Private certificate authorities](#private-certificate-authorities).

Built-in presets and your saved host templates share one **Start from a preset** picker in the destination section. Editing an existing host opens its destination and access settings directly, with section shortcuts and optional advanced controls; it does not require repeating the wizard. Each advanced section shows an On/Off badge, and opening a host preserves every configured value. Cache shortcuts open Advanced and the caching section directly. Validation reveals the relevant wizard step and any collapsed section before focusing an invalid field. Back and Continue preserve the unsaved draft; nothing is saved before creation is confirmed.

## Docker containers

When EmberGate runs on a Docker host, administrators can open **Containers** in the sidebar to see the running containers and expose one in a click. **Expose** opens the new-host wizard with the container's name as the application address (for example `http://photos:2283`) and, when the image matches one, a built-in preset to review. You still choose the public domain and confirm each step; nothing is published until you create the host. The wizard's destination step also offers the same containers under **Running container**.

When EmberGate runs directly on the host, or in a container with host networking, it cannot reach containers by name. **Expose** then uses the ports a container publishes, such as `http://127.0.0.1:8081` for `-p 8081:3000`; ports bound to a specific address use that address. Containers without published ports show as unavailable. Sharing a Docker network is still preferred, because a published port can change.

EmberGate finds its own container from the container ID that Docker and Podman record for `/etc/hostname`, so a custom `hostname:` is fine. If it runs in a container that the configured engine does not list, for example because `DOCKER_HOST` points at a different engine, it offers no host-port addresses and the Containers page explains why.

To pre-fill the public domain too, add an `embergate.host` label to the container, for example `embergate.host: photos.example.com`. Values that are not a plain host name are ignored, and a domain you already typed is kept.

Name-based addresses keep working when a container is recreated with a new IP address, but only when EmberGate and the container share a Docker network. Containers on other networks are listed as **Not on EmberGate's network** and cannot be exposed until you attach them to EmberGate's network. Each row also shows which saved hosts already use the container.

EmberGate only ever lists containers; it never starts, stops, or changes them. Access to the Docker API is still powerful, so connect EmberGate through a read-only socket proxy rather than mounting the socket directly:

- [deploy/docker-discovery-compose.yaml](../deploy/docker-discovery-compose.yaml) runs [docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy) with only `CONTAINERS=1` on a private network and sets `DOCKER_HOST=tcp://docker-socket-proxy:2375` for EmberGate. Applications join the shared `embergate` network.
- `DOCKER_HOST` accepts `unix:///path/to/docker.sock` or `tcp://host:port`. TLS endpoints are not supported.
- Without `DOCKER_HOST`, EmberGate uses `/var/run/docker.sock` when it exists. Mounting it, even read-only (`/var/run/docker.sock:/var/run/docker.sock:ro`), lets EmberGate send any request to Docker, which is equivalent to root access on the host.

The container that serves `DOCKER_HOST` and any Docker API port (2375, 2376) are never offered for exposure. Followers in a cluster list their own local containers; hosts you create replicate from the primary as usual. Podman's Docker-compatible socket also works.


## Private certificate authorities

Home labs often sign internal HTTPS services with their own CA. Open **Certificates → Private certificate authorities**, paste the PEM certificate of each CA, and choose **Save CA bundle**. Health checks, Diagnostics, and forward-auth (external login) checks trust these authorities in addition to the public roots right away, without a restart.

- Paste CA certificates only, up to 32 in one bundle. Server (leaf) certificates and private keys are refused, because a CA is what lets EmberGate verify every certificate it issues.
- Proxy traffic still uses the system trust store. For proxied requests to a private origin, install the CA in the EmberGate container's trust store, or turn off **Verify upstream TLS certificate** for that host.
- **Replace CA bundle** swaps the whole bundle; **Remove all** stops trusting them immediately. Only administrators can change the bundle; read-only accounts can see it.
- The bundle is part of encrypted full backups and is not replicated to follower instances.

## Trusted proxies

Open **Settings → Trusted proxies → Configure trusted proxies**. Add an IP or CIDR, choose the visitor header that proxy overwrites, and optionally trust its **X-Forwarded-Proto** value. Saves apply live and use the same revision checks, atomic persistence, and backups as route changes. The default list is empty, so upgrades keep using connection IPs.

**Load Cloudflare networks** retrieves the current IPv4/IPv6 ranges from [Cloudflare's public IP API](https://developers.cloudflare.com/api/resources/ips/methods/list/). Review the entries and save to enable **CF-Connecting-IP** and protocol forwarding from those networks. This lookup needs no token, does not change DNS, and is only performed when requested. The saved list is a snapshot; reload/review it when updating provider ranges. Header behavior follows [Cloudflare's HTTP header documentation](https://developers.cloudflare.com/fundamentals/reference/http-headers/).

For your own reverse proxy, select **X-Forwarded-For** and ensure it appends the connecting address. Chains are processed from right to left through configured X-Forwarded-For networks, stopping at the first untrusted hop. The untrusted hop's claimed left side is ignored. Every address must parse; chains are limited to 32 hops and 2048 bytes. CF-Connecting-IP must contain exactly one IP. Missing, malformed, or duplicate IP headers fall back to the socket IP. Duplicate, chained, or invalid protocol values are ignored. Forwarded protocol accepts only a single `http` or `https` from a network with that option enabled; otherwise the actual connection protocol is used.

Only trust proxy networks whose configured header behavior you control or have verified. Overlapping networks and whole-Internet `/0` trust are rejected; up to 64 networks are supported. IPv4-mapped IPv6 addresses/networks are normalized. The same resolved visitor IP drives rate limiting, access rules, forwarded headers, and traffic logs. Logs also retain the socket peer and identity source. Management login/session behavior is unchanged; trusted proxy settings apply to the traffic proxy.
## IP access rules

Edit a host and expand **IP access rules**. Enable either **Allow only these networks** or **Block these networks**, and enter one IP/CIDR per line. Both IPv4 and IPv6 are supported, with up to 256 entries per route. An allowlist admits matching verified visitors; a blocklist rejects matching visitors. Missing client identity fails closed. Empty enabled policies are rejected.

Rules apply to the matched host/path route, before redirects, rate limiting, or upstream selection. Denials return **403**, never contact an upstream, and are labeled **Access denied** in traffic logs and counted in historical analytics. Other configured routes keep their own policies. Removing the policy restores unrestricted access for that route. These controls affect proxy traffic, so they cannot block the management API through its separate listener.
## HTTPS redirects and response headers

Set the redirect under **Connection** in the host editor, and response headers under **Security headers**:

- **HTTP → HTTPS**: choose **Redirect HTTP to HTTPS** as the visitor connection. Redirects use **308**, preserving the method, hostname, path, and query. Set the public HTTPS port (443 by default). Provide a working TLS listener/certificate or a trusted HTTPS edge before enabling redirects. Effective HTTPS comes from the TLS connection or explicitly trusted forwarded protocol, preventing redirect loops behind a configured TLS proxy.
- **HSTS** accepts 0–31536000 seconds and optional includeSubDomains. A positive value is emitted only for effective HTTPS. Zero stops adding gateway HSTS and leaves any upstream HSTS unchanged. Browser-cached HSTS persists for its max age; removing the gateway policy cannot instantly clear browser state.
- Security switches set **X-Content-Type-Options: nosniff**, **X-Frame-Options: DENY**, and **Referrer-Policy: strict-origin-when-cross-origin**.
- Add up to 32 custom **Name: Value** headers. Matching upstream headers are replaced; values are at most 4096 bytes and cannot contain line breaks. Custom values apply after security switches. Connection/framing headers, Content-Length/Encoding/Range, Host, Location, Set-Cookie, and Strict-Transport-Security cannot be overridden through this editor.

Policies apply to upstream responses and the gateway's route-level 403/429/503/308 responses. Locally generated responses keep Cache-Control: no-store. Unmatched requests and framework-generated transport errors do not use a route response policy. All controls default off and apply live when saved.
## Upstream pools and health checks

Add or edit a proxy host and expand **Load balancing & health checks**. Keep the first origin in **Application address**, then enter additional origins one per line. Round robin is the default; each new request rotates to the next eligible backend. Choose another traffic distribution strategy, set per-origin weights, or mark individual origins as draining in the same editor. Each host supports up to 16 unique HTTP/HTTPS origins, including mixed protocols. The request path/query, upstream Host header, TLS SNI, and certificate verification follow the selected origin. Existing single-origin configurations need no migration.

Enable **HTTP health checks**, choose a path such as `/health`, and configure:

| Setting | Default in dashboard | Range |
| --- | --- | --- |
| Interval after each completed check | 10 seconds | 5–300 seconds |
| Probe timeout | 3 seconds | 1–10 seconds |
| Consecutive failures before exclusion | 2 | 1–10 |
| Consecutive successes before use/recovery | 1 | 1–10 |

Probes send GET directly to each configured origin; only 2xx responses pass. Redirects are not followed, proxy environment variables are ignored, and HTTPS probes verify certificates using the probe client's bundled public CA roots plus any [private certificate authorities](#private-certificate-authorities) you add. Use a cheap endpoint that reports application readiness. With **Preserve the incoming Host header** enabled, probes send the route hostname; for a `*` route they use each origin's hostname. Probes do not count toward traffic metrics or request logs.

A newly configured or restarted monitored pool waits for successful probes before receiving traffic. **Healthy** means every non-draining backend is available; **Degraded** means some are available; **Unavailable** means none passed. **Drained** means every backend is intentionally excluded. With no eligible backends the proxy returns **503**. A failure between probes can still cause a request to fail before the failure threshold is reached. Optional safe transport failover can try another eligible backend under the policy below. Unmonitored pools treat every non-draining origin as available; use health checks for proactive exclusion.

Backend dots show health; hover for the last result, check time, and probe duration. Traffic logs record the final selected origin and ordered attempted origins; search for `failover` to find requests with multiple attempts. Pool and probe changes apply live; changing origins, probe settings, or host-header behavior clears the pool's previous health results. Paused routes are not probed. Health state and rotation reset on process restart; configuration persists and is included in import/export and revision backups. Existing connections finish normally.

The monitor allows up to 256 configured health-checked origins across all hosts, runs up to 32 concurrent probes, and schedules due probes about once per second. Under heavy probe load, the effective interval can be longer than configured. The authenticated `/api/upstreams` endpoint returns per-route origin status, weight, draining flag, active-request count, and the matching configuration revision. Draining origins continue to be probed, but do not generate backend-failure alerts until resumed.
## Session request ordering

Some applications mishandle concurrent requests that share one session. Most login loops are not this: check that cookies reach the application intact first (EmberGate joins split HTTP/2 cookie fields into one line since v0.4.3). Edit a host and open **Advanced settings → Session request ordering** to queue requests that share a Cookie header so they reach the application one at a time. Requests without cookies are never queued, and different cookies stay parallel. The queue is released as soon as the application starts its response, so WebSockets and streams do not block later requests, and a request that waits more than 10 seconds receives 503 with `Retry-After: 1`. It is off by default and saved as `serialize_by_session` in the route.

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
## Response compression

Open a host's **Advanced settings → Response compression** and enable it. Choose **Automatic** (Brotli preferred when client qualities tie, with gzip fallback) or **Gzip only**, compression level **1–6**, and a minimum declared response size of **256–1048576 bytes**. Defaults are automatic, level 4, and 1024 bytes. Save the host to apply changes live. Compression is disabled on existing hosts until enabled.

Compression applies to proxied **public GET responses with status 200** over HTTP/1.1 and HTTP/2. Supported content types are text (except event streams), JSON and `+json`, JavaScript, XML and `+xml`, SVG, and WebAssembly. Known-length responses below the threshold pass through; supported text streams without a Content-Length compress incrementally without whole-response buffering. Higher levels use more CPU.

Requests containing Cookie, Authorization, Range, If-Range, or Upgrade headers bypass compression. Responses containing Content-Encoding (including `identity`), Content-Range, Set-Cookie, `Cache-Control: private` or `no-store`, and request/response `no-transform` also bypass it. Images other than SVG, archives, PDFs, fonts, audio/video, binary downloads, event streams, other statuses, HTTP/1.0, and non-GET methods pass through. HEAD preserves the origin/cache metadata. Local maintenance/error responses use their existing path. Existing upstream encodings are forwarded without decompression or re-encoding; the origin remains responsible for negotiating encodings it generates.

Negotiation handles quality values, explicit exclusions, wildcards, case-insensitive tokens, and multiple Accept-Encoding fields. An explicit higher preference for identity is respected; absent or empty Accept-Encoding uses identity. Unsupported algorithms do not enable proxy compression. Conflicting duplicate preferences use the lower quality. For an enabled host's unencoded 200 GET response, forbidding identity when no eligible supported encoding is available produces an empty **406 Not Acceptable**, marked `no-store`.

Responses that can vary by selected coding include **Vary: Accept-Encoding**, including their identity variant and conditional 304 responses, while preserving existing Vary fields and `Vary: *`. Transforming a body removes its original Content-Length and Accept-Ranges, weakens strong ETags, and removes body digests from headers/trailers so they cannot describe different bytes. HTTP/1.1 uses chunked framing; HTTP/2 uses DATA frames without Transfer-Encoding. The Brotli writer flushes incremental chunks and finishes its stream explicitly. Pingora's gzip encoder handles gzip; the existing Brotli library supplies Brotli finalization.

Compression runs **after** Pingora's cache pipeline on both misses and hits. The cache keeps the origin representation, retains Accept-Encoding isolation for origin variants, and compresses the selected response for each visitor. Compression policy changes invalidate that host's cache namespace. The policy is preserved in route exports, configuration-history rollback, host duplication, host templates, and manual/automatic full encrypted backups.

Example route field:

```json
"compression": {
  "mode": "auto",
  "level": 4,
  "min_bytes": 1024
}
```

Omit the field or set it to `null` to disable compression. Existing history and backups without it remain compatible.

## Application login protection

Edit a host and open **Advanced settings → Application login protection**. Enable an external authentication check and enter a trusted HTTP/HTTPS GET endpoint, such as Authelia's `/api/authz/forward-auth`. A 2xx response allows the original request; 401 requires sign-in; 403 denies access. Timeouts, connection/TLS errors, redirects, unexpected statuses, and capacity exhaustion fail closed with 503. The timeout is 1–30 seconds (default 5), with up to 64 concurrent checks per instance. Keep the identity provider's own login route outside this protection to avoid authentication loops.

By default, only the visitor's Cookie and Authorization headers are sent to the check service. You can change the bounded header allowlist. EmberGate rebuilds `X-Forwarded-Method`, `X-Forwarded-Proto`, `X-Forwarded-Host`, `X-Forwarded-Uri`, `X-Forwarded-For`, and `X-Original-URL` from the original public request and verified visitor identity. Request bodies are not sent to the check service, and the original method/body continue to the application after approval. Authentication clients do not use proxy environment variables or follow redirects. Use HTTPS when crossing an untrusted network; certificate verification stays enabled.

Choose which successful-response identity headers your application trusts. Defaults are Remote-User, Remote-Name, Remote-Email, and Remote-Groups. Visitor-supplied values of configured identity headers and common Remote-/X-Auth-Request identity headers are removed, including values introduced by request-header rewrites; only the provider's approved values are applied. The provider's body, Set-Cookie, and arbitrary headers are not forwarded to the visitor. The provider handles browser sessions and its login UI separately.

An optional **Sign-in URL** changes a 401 into a 303 redirect for GET/HEAD requests. The original URL is encoded in one `rd` query parameter; other methods retain 401. EmberGate uses the configured sign-in URL, never a provider-supplied Location. Without a sign-in URL, unauthenticated requests receive 401 directly.

Checks run after IP/HTTPS/rate/maintenance policies and before upstream/cache selection. Protected routes bypass shared response caching and compression, even when those policies remain configured. There is no authorization-result cache, so revocation takes effect on the next request. Direct upstream health checks and administrator diagnostics still contact backends independently. This protects proxied applications; EmberGate management keeps its own authentication.

The `forward_auth` route policy persists through configuration import/export, duplication, templates, history, and encrypted backups. URLs cannot embed credentials or fragments; authorization-check endpoints cannot contain query strings. Do not put provider secrets in URL paths or forwarded header names. For provider setup, see [Authelia's forwarded-header contract](https://www.authelia.com/integration/proxies/forwarded-headers/).

## Single sign-on

EmberGate can sign visitors in with an OpenID Connect provider such as Authentik, Keycloak, Authelia, Zitadel, or Google, both for the dashboard and in front of proxied applications. Unlike [application login protection](#application-login-protection), no separate forward-auth service is needed: EmberGate runs the sign-in itself.

### Connect a provider

1. At your provider, create an OpenID Connect web application (confidential client) and note its issuer URL, client ID, and client secret.
2. In **Settings → Single sign-on**, enter a button label, the issuer, client ID, and secret, then **Save provider**. EmberGate reads the provider's discovery document right away, so a wrong issuer is reported before anything is saved.
3. Register the redirect URIs EmberGate lists after saving:
   - Dashboard: `https://<dashboard address>/api/oidc/callback`
   - Each protected host: `https://<host><path prefix>/.well-known/embergate/oidc/callback`

The issuer and its endpoints must use HTTPS; plain HTTP is accepted only for `localhost`. Providers with a private CA work once the CA is added under [Private certificate authorities](#private-certificate-authorities). Changing the issuer or client ID signs every host session out.

### Dashboard sign-in

Turn on **Dashboard sign-in** and enter the dashboard address visitors use, such as `https://gateway.example.com`. The sign-in page then shows **Sign in with …**. Sign-in only works for an existing, enabled EmberGate account whose username equals the identity's verified email address or preferred username, so create the account first (usernames may be email addresses). The account keeps its EmberGate role; nothing is created automatically. Accounts with EmberGate two-factor authentication must keep using their password unless you turn on **The provider enforces two-factor authentication**. Password and passkey sign-in keep working, so a provider outage never locks you out.

### Protect a host

In the host editor, open **Access rules → Single sign-on** and turn on **Require sign-in with your identity provider**. Optionally restrict who may enter:

- **Allowed email addresses** and **Allowed email domains** match the identity's email only when the provider marks it verified.
- **Allowed groups** match the provider's groups claim (usually `groups`, set in Settings), case-sensitively.
- With all three empty, everyone the provider signs in may enter. Otherwise any one match is enough. Rules are checked again on every request, so tightening them applies to visitors who are already signed in.

Browsers asking for a page are sent to the provider and back; other requests, such as API calls, get `401`. After sign-in, EmberGate keeps an encrypted, host-only `HttpOnly` cookie for the chosen number of hours (1 to 168) and sends the application these headers, removing any copies the visitor sent:

| Header | Value |
| --- | --- |
| `X-Auth-Request-User` | The provider's stable subject identifier |
| `X-Auth-Request-Email` | The verified email address, when present |
| `X-Auth-Request-Preferred-Username` | The preferred username, when present |
| `X-Auth-Request-Groups` | Groups, comma-separated |

EmberGate's own sign-in cookies are removed before requests reach the application. Visiting `<path prefix>/.well-known/embergate/oidc/logout` signs out of the host and continues to the provider's sign-out page when it has one. Like application login protection, single sign-on hosts bypass shared caching and compression, and a host uses either single sign-on or external login, not both.

Sign-ins use the authorization code flow with PKCE, a one-use state bound to the browser by a short-lived cookie, and a nonce. ID tokens are checked for signature (RS256, RS384, RS512, PS256, ES256, or ES384 from the provider's published keys), issuer, audience, expiry, and nonce. Host sessions survive EmberGate restarts. The provider settings, client secret, and session key are part of encrypted full backups; they are not replicated to follower instances, so configure the provider on each instance (visitors sign in again after a failover).

## Native gRPC and built-in application presets

In the host wizard, choose an entry under **Built-in presets** in **Start from a preset**, review the preview,
then apply it. Built-in presets cover management dashboards (EmberGate, Poweradmin,
OPNsense, Patchmon), identity (Authentik, Passbolt, UCS), consoles and transfers
(AMP, PVE, PBS, UNAS), Dockhand, Nextcloud AIO, Grommunio and NetBird.
They preserve the incoming Host, disable shared caching and compression, set
conservative I/O timeouts and disable failover retries. Existing access rules,
authentication, response rules, health checks and addresses stay configured.
Application trusted-proxy and public-URL settings still need configuring separately.
Grommunio clients that need three-hour long polls exceed the current one-hour
maximum I/O timeout. SMTP, IMAP and UDP traffic need separate listeners / mappings.

Under **Advanced → Availability → Upstream protocol**:

- **HTTP/1.1** preserves existing behavior for websites and WebSockets.
- **Auto** uses HTTP/2 for native `application/grpc` requests and HTTP/1.1 for
  ordinary HTTP and WebSockets. The backend must support each selected protocol.
- **HTTP/2 only** always uses HTTP/2 upstream. An `https://` origin negotiates
  `h2` using TLS ALPN; an `http://` origin uses prior-knowledge h2c.

The configuration field is `upstream_protocol`: `http1` (default), `auto`, or
`http2`. Saved host templates and configuration exports preserve it.

Native gRPC clients must use HTTP/2 downstream. The HTTPS listener supports h2
and the HTTP listener accepts prior-knowledge h2c alongside ordinary HTTP/1.1.
Streaming bodies, metadata and gRPC trailers pass through. Native gRPC bypasses
shared cache and response compression and is never automatically replayed.
Gateway failures use gRPC status headers; upstream gRPC status trailers pass
through unchanged. HTTP statistics do not interpret application gRPC statuses.
This supports native gRPC, without gRPC-Web translation or TLS passthrough.

HTTP health checks use HTTP/1.1. Disable them on HTTP/2-only routes; use Auto only
if the backend also serves the configured HTTP/1.1 health endpoint. Diagnostics
use HEAD, cannot validate gRPC methods, and skip HTTP/TLS checks for HTTP/2-only
origins. Verify those with your application's client or grpcurl.

### NetBird example

Use the actual LAN origin at `10.0.0.5`, never the public hostname that resolves
back to EmberGate. Determine the dashboard and server ports from your NetBird
Compose configuration first. For the combined NetBird server (0.65 or newer),
create these routes on the same public hostname, preserving paths and Host:

| Path prefix | Backend | Upstream protocol |
| --- | --- | --- |
| `/` | Dashboard origin | HTTP/1.1 |
| `/api/` and `/oauth2/` | Server origin (one route per prefix) | Auto |
| `/relay` | Server origin | Auto |
| `/ws-proxy/signal` and `/ws-proxy/management` | Server origin | Auto |
| `/signalexchange.SignalExchange/` | Server origin | HTTP/2 only |
| `/management.ManagementService/` | Server origin | HTTP/2 only |
| `/management.ProxyService/` | Server origin | HTTP/2 only |

Choose the NetBird preset for these routes, select HTTP/2 only where indicated,
and leave HTTP health checks off. Public HTTPS needs a matching certificate.
Expose STUN UDP 3478 directly to NetBird as required by your deployment; it does
not pass through an HTTP proxy. Older split-server installations have different
backend ports. NetBird's separate reverse-proxy feature may require TLS passthrough,
which EmberGate does not provide.
See [NetBird's external reverse proxy guide](https://docs.netbird.io/selfhosted/external-reverse-proxy)
for deployment-specific paths and ports.

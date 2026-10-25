export function formatDuration(ms) {
  if(!Number.isFinite(ms))return '—';
  if(ms<1000)return `${ms.toFixed(1)} ms`;
  if(ms<60000)return `${(ms/1000).toFixed(1)} s`;
  return `${(ms/60000).toFixed(1)} min`;
}
export function responseTimingSummary(timing={}) {
  const format=formatDuration;
  const success=timing.success||{};
  return {headers:format(success.avg_headers_ms),duration:format(success.avg_duration_ms),p95:success.p95_overflow?'>120000 ms':Number.isFinite(success.p95_headers_upper_ms)?`≤${success.p95_headers_upper_ms} ms`:'—'};
}
export function latencySummary(stats) {
  const format=formatDuration;
  return {success:format(stats.success_avg_latency_ms),failed:format(stats.failed_avg_latency_ms)};
}
export function newHostId(source = globalThis.crypto) {
  if (typeof source.randomUUID === 'function') return source.randomUUID();
  // getRandomValues also works on HTTP LAN origins, unlike randomUUID.
  const bytes=source.getRandomValues(new Uint8Array(16));
  bytes[6]=(bytes[6]&0x0f)|0x40;
  bytes[8]=(bytes[8]&0x3f)|0x80;
  const hex=Array.from(bytes,byte=>byte.toString(16).padStart(2,'0')).join('');
  return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
}
export function matchingHostCertificate(hostname, certificates) {
  const host=hostname.trim().toLowerCase().replace(/\.$/,'');
  const valid=certificates.filter(certificate=>certificate.valid);
  return valid.find(certificate=>certificate.domains.some(domain=>domain.toLowerCase()===host))||valid.find(certificate=>certificate.domains.some(domain=>{
    const name=domain.toLowerCase();
    return name.startsWith('*.')&&host.endsWith(name.slice(1))&&host.split('.').length===name.split('.').length;
  }))||null;
}
export const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
export const matchingHosts = (routes, search, filter) => routes.filter(r =>
  `${r.name} ${r.host} ${r.path_prefix} ${r.upstream} ${(r.additional_upstreams || []).join(" ")}`.toLowerCase().includes(search.toLowerCase())
  && (filter === 'all' || r.enabled === (filter === 'active')));
export function duplicateHost(route, id = newHostId()) {
  const draft=structuredClone(route);draft.id=id;draft.host='';draft.enabled=false;
  draft.name='Copy of '+route.name;
  while(new TextEncoder().encode(draft.name).length>80) draft.name=Array.from(draft.name).slice(0,-1).join('');
  return draft;
}
export function applyHostTemplate(route, policies) {
  const draft=structuredClone(route);
  for(const key of ['forward_auth','compression','cache','access','response','rate_limit','reliability','routing','health_check']) {
    if(policies[key]!=null)draft[key]=structuredClone(policies[key]);else delete draft[key];
  }
  draft.upstream_protocol=policies.upstream_protocol||'http1';
  draft.preserve_host=Boolean(policies.preserve_host);
  draft.verify_upstream_tls=policies.verify_upstream_tls!==false;
  draft.pages={...validatePages(route.pages || {}),branded_errors:policies.branded_errors!==false};
  return draft;
}
export const starterHostTemplates = [
  {id:'management',name:'Management dashboards',apps:'EmberGate, Poweradmin, OPNsense, Patchmon',timeout:120,note:'Keep an IP allowlist for private administration. Configure trusted proxies / alternate hostnames in the application.'},
  {id:'identity',name:'Identity and passwords',apps:'Authentik, Passbolt, UCS',timeout:300,note:'Set the public HTTPS URL and trusted proxies in the application. Keep application authentication enabled.'},
  {id:'consoles',name:'Consoles and file transfers',apps:'AMP, PVE, PBS, UNAS',timeout:3600,note:'Long I/O waits support consoles and transfers. WebSockets work automatically. Restrict administrative services to trusted networks.'},
  {id:'containers',name:'Container management',apps:'Dockhand',timeout:600,note:'Allows longer container operations and streaming logs. Keep an IP allowlist.'},
  {id:'nextcloud',name:'Nextcloud AIO',apps:'Nextcloud',timeout:3600,note:'Use the AIO Apache origin on port 11000, configure trusted proxies and the public HTTPS URL. Large transfers may need application-side limits adjusted.'},
  {id:'mail',name:'Mail and groupware',apps:'Grommunio',timeout:3600,note:'Web traffic only; SMTP and IMAP need separate ports. Some long-poll mail clients need longer than the supported one-hour I/O timeout.'},
  {id:'netbird',name:'NetBird',apps:'NetBird dashboard and server',timeout:3600,protocol:'auto',note:'Auto selects HTTP/2 for native gRPC and HTTP/1.1 for web / WebSockets. Dashboard and server may need separate path routes. Use the actual server port at 10.0.0.5; STUN UDP 3478 is separate.'},
  {id:'grpc',name:'Native gRPC',apps:'HTTP/2 services',timeout:3600,protocol:'http2',note:'HTTP/2 only upstream: HTTPS uses ALPN, HTTP uses prior-knowledge h2c. Disable HTTP health checks. This does not translate gRPC-Web.'}
];
export function applyStarterTemplate(route, id) {
  const starter=starterHostTemplates.find(item=>item.id===id);
  if(!starter)throw new Error('Unknown built-in preset.');
  const draft=structuredClone(route);
  draft.upstream_protocol=starter.protocol||'http1';draft.preserve_host=true;
  draft.reliability={connect_timeout_seconds:5,read_timeout_seconds:starter.timeout,write_timeout_seconds:starter.timeout,retries:0};
  delete draft.cache;delete draft.compression;
  return draft;
}
export function poolState(route, statuses = []) {
  if (!route.enabled) return {label:'Paused', className:'paused'};
  if(route.pages?.maintenance) return {label:'Maintenance',className:'paused'};
  const draining=new Set(route.balancing?.draining || []);
  const available=statuses.filter(status=>!status.draining && !draining.has(status.upstream));
  const total = Math.max(0,1 + (route.additional_upstreams || []).length - Math.max(draining.size,statuses.filter(status=>status.draining).length));
  if(total===0) return {label:'Drained',className:'paused'};
  if (!route.health_check) return {label:'Active', className:''};
  const healthy = available.filter(s => s.status === 'healthy').length;
  if (healthy === total) return {label:'Healthy', className:''};
  if (healthy > 0) return {label:`Degraded · ${healthy}/${total}`, className:'degraded'};
  if (available.length !== total || available.some(s => s.status === 'pending')) return {label:'Checking', className:'paused'};
  return {label:'Unavailable', className:'unhealthy'};
}
export const responseHasHeaders = response => Boolean(response?.hsts_max_age || response?.hsts_include_subdomains || response?.nosniff || response?.frame_deny || response?.referrer_policy || response?.custom_headers?.length);
export function upstreamOrigin(value) {
  const url = new URL(value.trim());
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password
    || url.pathname !== '/' || url.search || url.hash) throw new Error('Use HTTP or HTTPS origins without paths, queries, or credentials.');
  return url.origin;
}
export function rateLimitSummary(limit) {
  return `${Number(limit.requests).toLocaleString()} / ${Number(limit.window_seconds).toLocaleString()}s · burst ${Number(limit.burst).toLocaleString()}`;
}
export function validateRateLimit(limit) {
  if (!limit || typeof limit !== 'object'
    || !Number.isInteger(limit.requests) || limit.requests < 1 || limit.requests > 1000000
    || !Number.isInteger(limit.window_seconds) || limit.window_seconds < 1 || limit.window_seconds > 3600
    || !Number.isInteger(limit.burst) || limit.burst < 1 || limit.burst > 100000 || limit.burst > limit.requests) {
    throw new Error('Use 1–1,000,000 requests per 1–3,600 seconds and a burst of 1–100,000, no greater than the request allowance.');
  }
  return limit;
}
export function validateCachePolicy(policy) {
  if (!policy || !Number.isInteger(policy.max_ttl_seconds) || policy.max_ttl_seconds<1 || policy.max_ttl_seconds>86400
    || !Number.isInteger(policy.max_object_bytes) || policy.max_object_bytes<1024 || policy.max_object_bytes>4194304
    || typeof policy.cache_query_strings !== 'boolean') throw new Error('Use a cache TTL of 1–86400 seconds and an object limit of 1–4096 KiB.');
  return policy;
}
export function validateCompression(policy) {
  if(!policy || !['auto','gzip'].includes(policy.mode) || !Number.isInteger(policy.level) || policy.level<1 || policy.level>6 || !Number.isInteger(policy.min_bytes) || policy.min_bytes<256 || policy.min_bytes>1048576)throw new Error('Use automatic Brotli/gzip or gzip, level 1–6, and a minimum declared size of 256–1048576 bytes.');
  return policy;
}
export function validateReliability(policy) {
  if(!policy || !Number.isInteger(policy.connect_timeout_seconds) || policy.connect_timeout_seconds<1 || policy.connect_timeout_seconds>120 || ['read_timeout_seconds','write_timeout_seconds'].some(key=>!Number.isInteger(policy[key]) || policy[key]<1 || policy[key]>3600) || !Number.isInteger(policy.retries) || policy.retries<0 || policy.retries>3) throw new Error('Use 1–120s connect, 1–3600s read/write, and 0–3 failover retries.');
  return policy;
}
const strategyLabels={round_robin:'Round robin',weighted_round_robin:'Weighted round robin',least_connections:'Least active requests',client_ip_hash:'Client IP affinity'};
export function validateBalancing(policy,origins) {
  if(!policy || !Object.hasOwn(strategyLabels,policy.strategy) || !Array.isArray(policy.weights) || policy.weights.length!==origins.length || policy.weights.some(weight=>!Number.isInteger(weight) || weight<1 || weight>100) || !Array.isArray(policy.draining) || new Set(policy.draining).size!==policy.draining.length || policy.draining.some(origin=>!origins.includes(origin))) throw new Error('Choose a supported strategy, a weight of 1–100 per origin, and valid draining backends.');
  return policy;
}
export function validatePages(input) {
  if(!input || typeof input!=='object' || Array.isArray(input) || Object.keys(input).some(key=>!['maintenance','status','title','message','retry_after_seconds','branded_errors'].includes(key))) throw new Error('Invalid maintenance/page policy.');
  const policy={maintenance:false,status:503,title:'We’ll be back shortly',message:'This service is temporarily undergoing maintenance. Please try again later.',retry_after_seconds:300,branded_errors:true,...input};
  if(typeof policy.maintenance!=='boolean' || typeof policy.branded_errors!=='boolean' || ![200,503].includes(policy.status) || !Number.isInteger(policy.retry_after_seconds) || policy.retry_after_seconds<1 || policy.retry_after_seconds>86400) throw new Error('Use maintenance status 503 or 200 and Retry-After of 1–86400 seconds.');
  for(const [key,max] of [['title',120],['message',2000]]) {
    if(typeof policy[key]!=='string' || !policy[key].trim() || [...policy[key].trim()].length>max || /[\x00-\x08\x0b-\x1f\x7f-\x9f]/.test(policy[key])) throw new Error('Use a title of 1–120 characters and a message of 1–2000 characters without control characters.');
    policy[key]=policy[key].trim();
  }
  return policy;
}
const protectedRequestHeader = name => name.startsWith('x-forwarded-') || name.startsWith('sec-websocket-') || ['host','connection','keep-alive','proxy-authenticate','proxy-authorization','te','trailer','transfer-encoding','upgrade','content-length','expect','proxy-connection','content-encoding','accept-encoding','cache-control','pragma','range','if-range','if-match','if-none-match','if-modified-since','if-unmodified-since','forwarded','cf-connecting-ip','cf-connecting-ipv6','true-client-ip','x-real-ip','authorization','cookie'].includes(name);
export function validateRouting(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).some(key=>!['strip_prefix','rewrite_prefix','set_headers','remove_headers'].includes(key))) throw new Error('Invalid routing policy.');
  const policy={strip_prefix:false,rewrite_prefix:null,set_headers:[],remove_headers:[],...input};
  if(typeof policy.strip_prefix!=='boolean' || (policy.strip_prefix && policy.rewrite_prefix!=null)) throw new Error('Choose either prefix stripping or prefix replacement.');
  if(policy.rewrite_prefix!=null && (typeof policy.rewrite_prefix!=='string' || !/^\/(?!\/)[\x21-\x7e]*$/.test(policy.rewrite_prefix) || /[?#\\]/.test(policy.rewrite_prefix) || policy.rewrite_prefix.length>1024)) throw new Error('Use a replacement URL path starting with a single /, up to 1024 ASCII characters, without queries, fragments, backslashes, or whitespace.');
  if(!Array.isArray(policy.set_headers) || !Array.isArray(policy.remove_headers) || policy.set_headers.length>32 || policy.remove_headers.length>32) throw new Error('Use at most 32 header overrides and 32 removals.');
  const seen=new Set();
  const name=value=>{
    if(typeof value!=='string') throw new Error('Invalid request header name.');
    value=value.trim().toLowerCase();
    if(!/^[!#$%&'*+.^_`|~0-9a-z-]+$/.test(value)) throw new Error('Invalid request header name.');
    if(protectedRequestHeader(value)) throw new Error(`${value} is protected and cannot be changed here.`);
    if(seen.has(value)) throw new Error('Request headers must be unique across overrides and removals.');
    seen.add(value);return value;
  };
  policy.remove_headers=policy.remove_headers.map(name);
  policy.set_headers=policy.set_headers.map(rule=>{
    if(!rule || typeof rule!=='object' || Object.keys(rule).some(key=>!['name','value'].includes(key)) || typeof rule.value!=='string' || rule.value.length>4096 || /[^\x20-\x7e\t]/.test(rule.value)) throw new Error('Use request header values with at most 4096 ASCII characters and no newlines.');
    return {name:name(rule.name),value:rule.value};
  });
  return policy;
}
export function previewRouting(target, matchedPrefix, input={}) {
  const policy=validateRouting(input);
  if(typeof target!=='string' || !/^\/[\x21-\x7e]*$/.test(target) || target.includes('#') || target.includes('\\') || target.length>8192) throw new Error('Enter an example URL path and optional query, up to 8192 ASCII characters.');
  if(typeof matchedPrefix!=='string' || !matchedPrefix.startsWith('/') || !target.split('?')[0].startsWith(matchedPrefix)) throw new Error('The example path must match this route’s literal path prefix.');
  if(!policy.strip_prefix && policy.rewrite_prefix==null) return target;
  const queryIndex=target.indexOf('?'),path=queryIndex<0?target:target.slice(0,queryIndex),query=queryIndex<0?'':target.slice(queryIndex);
  const suffix=path.slice(matchedPrefix.length),prefix=policy.rewrite_prefix ?? '';
  let result=prefix.endsWith('/') && suffix.startsWith('/') ? prefix+suffix.slice(1) : prefix && suffix && !prefix.endsWith('/') && !suffix.startsWith('/') ? `${prefix}/${suffix}` : prefix+suffix;
  if(!result.startsWith('/')) result='/'+result;
  return result+query;
}
export function chartPoints(buckets) {
  const max = Math.max(10, ...buckets.map(b => b.requests));
  const points = buckets.map((b, i) => `${(i * 600 / Math.max(1, buckets.length - 1)).toFixed(2)},${(159 - b.requests / max * 150).toFixed(2)}`);
  const line = points.length ? `M${points.join(' L')}` : 'M0,159 L600,159';
  return { max, line, area: `${line} L600,160 L0,160 Z` };
}
export function validateForwardAuth(input) {
  const policy={timeout_seconds:5,sign_in_url:null,request_headers:['cookie','authorization'],response_headers:['remote-user','remote-name','remote-email','remote-groups'],...input};
  for(const key of ['url','sign_in_url']) {
    if(key==='sign_in_url'&&(policy[key]===null||policy[key]==='')){policy[key]=null;continue;}
    let url;try{url=new URL(policy[key]);}catch{throw new Error('Enter an absolute HTTP or HTTPS authentication URL.');}
    if(typeof policy[key]!=='string'||policy[key].length>2048||/[\u0000-\u001f\u007f]/.test(policy[key])||!['http:','https:'].includes(url.protocol)||url.username||url.password||url.hash||(key==='url'&&url.search))throw new Error('Authentication URLs cannot contain credentials or fragments; check endpoints cannot have query strings.');
    policy[key]=url.href;
  }
  if(!Number.isInteger(policy.timeout_seconds)||policy.timeout_seconds<1||policy.timeout_seconds>30)throw new Error('Authentication timeout must be 1–30 seconds.');
  const reserved=new Set(['host','connection','content-length','content-type','transfer-encoding','te','trailer','upgrade','keep-alive','proxy-authorization','proxy-authenticate','set-cookie','forwarded','x-original-url','x-forwarded-uri','x-forwarded-host','x-forwarded-method','x-forwarded-for','x-forwarded-proto','x-real-ip']);
  for(const key of ['request_headers','response_headers']) {
    if(!Array.isArray(policy[key])||policy[key].length>16||policy[key].some(name=>typeof name!=='string'))throw new Error('Use at most 16 authentication headers per list.');
    policy[key]=policy[key].map(name=>name.trim().toLowerCase());
    if(new Set(policy[key]).size!==policy[key].length||policy[key].some(name=>!name||name.length>128||!/^[!#$%&'*+.^_`|~0-9a-z-]+$/.test(name)||reserved.has(name)||(key==='response_headers'&&['cookie','authorization','location','www-authenticate','cache-control','content-encoding'].includes(name))))throw new Error('Use unique, non-reserved authentication header names.');
  }
  return policy;
}
export function importConfig(text, currentVersion) {
  const config = JSON.parse(text);
  if (!config || !Array.isArray(config.routes) || config.routes.length > 500) throw new Error('Choose a configuration containing a routes array with at most 500 hosts.');
  for (const route of config.routes) {
    if (!route || ['id', 'name', 'host', 'path_prefix', 'upstream'].some(key => typeof route[key] !== 'string')
      || typeof route.enabled !== 'boolean' || typeof route.preserve_host !== 'boolean') throw new Error('The file contains an invalid route.');
    if(route.forward_auth!=null)validateForwardAuth(route.forward_auth);
    if(route.pages!=null) validatePages(route.pages);
    if(route.routing!=null) validateRouting(route.routing);
    if(route.reliability!=null) validateReliability({...{connect_timeout_seconds:5,read_timeout_seconds:60,write_timeout_seconds:60,retries:0},...route.reliability});
    if(route.balancing!=null) {const origins=[route.upstream,...(route.additional_upstreams || [])];validateBalancing({strategy:'round_robin',weights:origins.map(()=>1),draining:[],...route.balancing,weights:route.balancing.weights?.length ? route.balancing.weights : origins.map(()=>1)},origins);}
    if(route.compression!=null)validateCompression({mode:'auto',level:4,min_bytes:1024,...route.compression});
    if (route.cache != null) validateCachePolicy({...route.cache,cache_query_strings:route.cache.cache_query_strings ?? false});
    if (route.access != null && (!['allow','block'].includes(route.access.mode) || !Array.isArray(route.access.networks) || route.access.networks.some(n => typeof n !== 'string'))) throw new Error('Invalid access policy.');
    if (route.response != null && (typeof route.response !== 'object' || Array.isArray(route.response))) throw new Error('Invalid response policy.');
    if (route.rate_limit !== undefined && route.rate_limit !== null) validateRateLimit(route.rate_limit);
    if (route.upstream_protocol!=null && !['http1','auto','http2'].includes(route.upstream_protocol)) throw new Error('Invalid upstream protocol.');
    if (route.additional_upstreams !== undefined && (!Array.isArray(route.additional_upstreams)
      || route.additional_upstreams.length > 15 || route.additional_upstreams.some(origin => typeof origin !== 'string'))) throw new Error('The file contains an invalid upstream pool.');
    if (route.health_check !== undefined && route.health_check !== null) {
      const health = route.health_check;
      if (typeof health !== 'object' || typeof health.path !== 'string'
        || ['interval_seconds','timeout_seconds','failure_threshold','recovery_threshold'].some(key => !Number.isInteger(health[key]))) throw new Error('The file contains an invalid health check.');
    }
  }
  const result = { version: currentVersion, routes: config.routes };
  if (config.trusted_proxies !== undefined) {
    if (!Array.isArray(config.trusted_proxies) || config.trusted_proxies.length > 64 || config.trusted_proxies.some(p => !p || typeof p.network !== 'string' || !['cloudflare','x_forwarded_for'].includes(p.header) || typeof p.trust_proto !== 'boolean')) throw new Error('Invalid trusted proxy configuration.');
    result.trusted_proxies = config.trusted_proxies;
  }
  return result;
}

export const settingsPages = [
  {id:'instance',label:'Instance details',description:'View listener addresses, protocols, and your EmberGate version.',icon:'info'},
  {id:'instances',label:'Instances',description:'Manage primary/follower synchronization and gateway readiness.',icon:'nodes',admin:true},
  {id:'security',label:'Sign-in methods',description:'Manage your password, authenticator, passkeys, and recovery options.',icon:'lock'},
  {id:'cloudflare',label:'Cloudflare DNS',description:'Manage the DNS credentials used for automatic certificates.',icon:'cloud'},
  {id:'threat-protection',label:'Threat protection',description:'Connect CrowdSec to block known malicious IP addresses.',icon:'ban'},
  {id:'trusted-proxies',label:'Trusted proxies',description:'Configure which proxies can supply visitor identity and protocol.',icon:'shield'},
  {id:'templates',label:'Host templates',description:'Create and manage reusable copies of host policies.',icon:'copy',admin:true},
  {id:'configuration',label:'Configuration import / export',description:'Export your routes or review a configuration to import.',icon:'download'},
  {id:'history',label:'Configuration history',description:'Compare earlier configurations and review a rollback.',icon:'clock',admin:true},
  {id:'backups',label:'Full backup & restore',description:'Create encrypted snapshots or review a complete restore.',icon:'archive',admin:true},
  {id:'automatic-backups',label:'Automatic backups',description:'Schedule encrypted snapshots and manage retained copies.',icon:'refresh',admin:true}
];
export const helpTopics = ['getting-started','proxy-hosts','certificates','security','administration','backups','monitoring','troubleshooting'];
export function searchGuides(guides, query) {
  const terms=query.trim().toLowerCase().slice(0,160).split(/\s+/).filter(Boolean);
  return guides.filter(guide=>{const text=[guide.title,guide.description,guide.text].join(' ').toLowerCase();return terms.every(term=>text.includes(term));});
}
const dashboardViews=['help','overview','hosts','cache','analytics','diagnostics','traffic','certificates','accounts','audit','alerts','settings'];
export function dashboardRoute(hash) {
  const parts=hash.replace(/^#\/?/,'').split('/');
  const view=dashboardViews.includes(parts[0])?parts[0]:'overview';
  if(view==='help')return {view,section:helpTopics.includes(parts[1])?parts[1]:'getting-started',anchor:/^[a-z0-9][a-z0-9-]{0,159}$/.test(parts[2]||'')?parts[2]:''};
  const section=view==='settings'&&settingsPages.some(page=>page.id===parts[1])?parts[1]:'instance';
  return {view,section};
}

if (typeof document !== 'undefined') initialize();
function initialize() {
  const $ = id => document.getElementById(id);
  const icon = name => `<svg aria-hidden="true"><use href="#i-${name}"/></svg>`;
  const number = value => Number(value || 0).toLocaleString();
  let config = {version: 0, routes: []}, logs = [], view = 'overview', settingsPage='instance';
  let clusterInfo=null,isFollowerNode=false;
  let passkeysInfo=null,passkeyMode='register',passkeyRemoveId=null,passkeyRequest=0,passkeyController=null;
  let helpPage='getting-started',helpAnchor='',helpInfo=null,helpLoading=false,helpError='',helpRequest=0;
  let certificates = [], httpsAddress = null, certificateRequest = 0, certificatesChanging = false;
  let upstreamInfo = {version:-1,routes:{}};
  let acmeInfo = {configured:false,orders:[]}, automationRequest = 0;
  let authenticated = false, refreshing = false, changing = false, toastTimer, editingConfig;
  let confirmCallback, trustedDraft, editingRoute;
  let cacheInfo={routes:[],used_bytes:0,capacity_bytes:67108864,entries:0}, cacheRequest=0, cacheChanging=false;
  let historyRequest=0, diagnosticsRequest=0, diagnosticsController=null;
  let backendDraft=new Map();
  let currentUser=null, users=[], alertInfo=null, userVersion=0, managementRequest=0, passwordEditable=false, credentialInfo=null, prometheusInfo=null, backupInfo=null, backupMode='export', restoreReview=null, backupRequest=0;
  let templatesInfo=null, templateRequest=0, templateDialogRequest=0, templateDialogOpening=0;
  let configReview=null, configReviewRequest=0;
  let scheduleInfo=null, scheduleChanging=false, scheduleRequest=0;
  let mfaInfo=null, mfaMode='setup', mfaStep='proof', mfaGate=false, mfaRequest=0;
  const isAdmin=()=>currentUser?.role==='administrator';
  const titles = {overview: ['Overview', 'Monitor traffic, host health, and gateway status.'],
    hosts: ['Proxy hosts', 'Manage the hostnames and paths that route to your upstream services.'],
    cache: ['Caching', 'Manage public response caching, storage, and purges.'],
    analytics: ['Analytics', 'Explore traffic history, status codes, and host activity.'],
    diagnostics:['Diagnostics','Trace routing and check connections to your saved backends.'],
    traffic: ['Traffic logs', 'Inspect recent requests, response codes, and request duration.'],
    certificates: ['Certificates', 'Manage TLS certificates for secure connections to your gateway.'],
    accounts: ['Accounts', 'Manage team access and active sign-in sessions.'],
    audit: ['Audit trail', 'Review management activity and configuration changes.'],
    alerts: ['Alerts', 'Keep track of availability and notification delivery.'],
    help: ['Help & documentation', 'Guides for your installed version of EmberGate.'],
    settings: ['Settings', 'Manage credentials, instance settings, and configuration backups.']};

  $('settings-navigation').innerHTML=settingsPages.map(page=>`<a class="settings-nav-link" data-settings-link="${page.id}" href="#/settings/${page.id}" aria-controls="settings-page-${page.id}">${icon(page.icon)}<span>${escapeHtml(page.label)}</span></a>`).join('');
  for(const page of settingsPages)$('settings-page-'+page.id).setAttribute('aria-label',page.label);
  function renderSettingsNavigation() {
    const allowed=settingsPages.filter(page=>!page.admin || !currentUser || isAdmin());
    if(!allowed.some(page=>page.id===settingsPage))settingsPage='instance';
    const active=settingsPages.find(page=>page.id===settingsPage);
    $('app').classList.toggle('settings-open',view==='settings');$('settings-sidebar').hidden=view!=='settings';
    for(const link of document.querySelectorAll('[data-settings-link]')) {
      link.hidden=!allowed.some(page=>page.id===link.dataset.settingsLink);
      const selected=view==='settings' && link.dataset.settingsLink===settingsPage;
      link.classList.toggle('active',selected);
      if(selected)link.setAttribute('aria-current','page');else link.removeAttribute('aria-current');
    }
    const role=isAdmin()?'administrator':currentUser?'read_only':'unknown';
    if($('settings-section').dataset.role!==role){$('settings-section').innerHTML=allowed.map(page=>`<option value="${page.id}">${escapeHtml(page.label)}</option>`).join('');$('settings-section').dataset.role=role;}
    $('settings-section').value=settingsPage;
    for(const panel of document.querySelectorAll('[data-settings-page]'))panel.hidden=view!=='settings'||panel.dataset.settingsPage!==settingsPage;
    if(view==='settings') {
      $('breadcrumb').textContent='Settings / '+active.label;$('page-title').textContent=active.label;$('page-description').textContent=active.description;
    }
  }
  function navigateFromLocation(options={}) {
    const route=dashboardRoute(location.hash);navigate(route.view,route.section,{...options,anchor:route.anchor||'',fromLocation:true});
  }
  function focusHelpAnchor() {
    if(view!=='help'||!helpAnchor||$('help-article').hidden)return;
    const heading=$('help-'+helpPage+'-'+helpAnchor);
    if(heading){heading.scrollIntoView({block:'start'});heading.focus({preventScroll:true});}
  }
  async function loadHelp() {
    if(helpInfo||helpLoading||!authenticated)return;
    const request=++helpRequest;helpLoading=true;helpError='';renderHelp();
    try {
      const result=await api('documentation');
      if(request!==helpRequest||!authenticated)return;
      helpInfo=result;
    } catch(error) {if(request===helpRequest)helpError=error.message;}
    finally {if(request===helpRequest){helpLoading=false;if(view==='help'){renderHelp();focusHelpAnchor();}}}
  }
  function renderHelp() {
    const guides=helpInfo?.guides||[];
    $('help-version').textContent=helpInfo?'Included with EmberGate v'+helpInfo.version:'Included with your EmberGate installation';
    $('help-loading').hidden=Boolean(helpInfo)||Boolean(helpError);
    $('help-error').hidden=!helpError;$('help-error-message').textContent=helpError;
    const guide=guides.find(guide=>guide.id===helpPage);
    $('help-navigation').innerHTML=guides.map(guide=>`<a class="help-topic${guide.id===helpPage?' active':''}" href="#/help/${guide.id}"${guide.id===helpPage?' aria-current="page"':''}>${escapeHtml(guide.title)}</a>`).join('');
    $('help-topic-select').innerHTML=guides.map(guide=>`<option value="${guide.id}">${escapeHtml(guide.title)}</option>`).join('');$('help-topic-select').value=helpPage;
    const query=$('help-search').value.trim();
    $('help-results').hidden=!query||!helpInfo;
    $('help-article').hidden=!guide||Boolean(query);
    $('help-search-clear').hidden=!query;
    if(query&&helpInfo) {
      const matches=searchGuides(guides,query);
      $('help-search-status').textContent=matches.length+' '+(matches.length===1?'guide':'guides')+' found';
      $('help-results-list').innerHTML=matches.length?matches.map(guide=>{
        const first=query.toLowerCase().split(/\s+/)[0],index=guide.text.toLowerCase().indexOf(first);
        const start=Math.max(0,index-60),excerpt=guide.text.slice(start,start+220);
        return `<a class="help-search-result" href="#/help/${guide.id}"><strong>${escapeHtml(guide.title)}</strong><span>${escapeHtml(guide.description)}</span><p>${start?'…':''}${escapeHtml(excerpt)}…</p></a>`;
      }).join(''):'<p class="help-no-results">No matching guides. Try a shorter phrase or browse a topic.</p>';
    } else $('help-search-status').textContent=helpInfo?'Search all '+guides.length+' guides':'';
    if(guide&&!query) {
      $('help-article-title').textContent=guide.title;$('help-article-description').textContent=guide.description;
      $('help-outline').innerHTML=guide.headings.map(heading=>`<a href="#/help/${guide.id}/${heading.id}">${escapeHtml(heading.title)}</a>`).join('');
      // HTML is rendered from embedded Markdown by the server; raw HTML and unsafe links are disabled there.
      $('help-article-body').innerHTML=guide.html;
      for(const link of $('help-article-body').querySelectorAll('a[href]')) {
        if(/^https?:\/\//.test(link.getAttribute('href'))){link.target='_blank';link.rel='noopener noreferrer';}
      }
    }
  }
  function clearHelpSearch() {$('help-search').value='';renderHelp();}
  $('help-search').addEventListener('input',renderHelp);
  $('help-search').addEventListener('keydown',event=>{if(event.key==='Escape'){clearHelpSearch();event.preventDefault();}});
  $('help-search-clear').addEventListener('click',()=>{clearHelpSearch();$('help-search').focus();});
  $('help-retry').addEventListener('click',loadHelp);
  $('help-topic-select').addEventListener('change',()=>{const topic=$('help-topic-select').value;clearHelpSearch();navigate('help',topic);});
  document.addEventListener('click',event=>{
    const link=event.target.closest('a[href^="#/help/"]');
    if(!link||link.target==='_blank'||event.button!==0||event.ctrlKey||event.metaKey||event.shiftKey||event.altKey)return;
    event.preventDefault();const route=dashboardRoute(link.getAttribute('href'));clearHelpSearch();navigate('help',route.section,{anchor:route.anchor});
  });
  function applyTheme(theme) {
    document.documentElement.dataset.theme = theme === 'dark' ? 'dark' : 'light';
    $('theme').setAttribute('aria-pressed', String(theme === 'dark'));
    $('theme').setAttribute('aria-label', theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme');
    $('theme').title = theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme';
  }
  const systemTheme = () => matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  let savedTheme = null;
  try { savedTheme = localStorage.getItem('embergate-theme') || localStorage.getItem('current-theme'); if (savedTheme) localStorage.setItem('embergate-theme',savedTheme); } catch {}
  applyTheme(savedTheme || systemTheme());
  $('theme').addEventListener('click', () => {
    const theme = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
    applyTheme(theme);
    try { localStorage.setItem('embergate-theme', theme); } catch {}
  });

  async function api(path, options = {}) {
    let response;
    try { response = await fetch(`/api/${path}`, {credentials: 'same-origin', ...options,
      headers: {'Content-Type': 'application/json', 'X-Gateway-Request': '1', ...options.headers}}); }
    catch { throw new Error('Cannot reach your gateway. Check that it is running.'); }
    const body = await response.json().catch(() => ({}));
    if(response.headers.get('x-gateway-audit-pending')==='1') toast('Audit completion is pending. An administrator can review the audit trail.');
    if (!response.ok) {
      if (response.status === 401 && path !== 'login' && !path.startsWith('passkeys/login/')) showLogin();
      const error = new Error(body.error || `Request failed (${response.status}).`);
      error.status = response.status;
      error.mfaRequired=Boolean(body.mfa_required);
      error.mfaEnrollmentRequired=Boolean(body.mfa_enrollment_required);
      throw error;
    }
    return body;
  }
  function showLogin() {
    clusterInfo=null;isFollowerNode=false;$('cluster-form').reset();$('cluster-editor').disabled=true;delete $('cluster-form').dataset.dirty;$('cluster-token-value').value='';$('cluster-token-result').hidden=true;
    passkeyRequest++;passkeyController?.abort();passkeyController=null;passkeysInfo=null;$('passkey-dialog').close();$('passkey-form').reset();
    templateRequest++;templateDialogRequest++;templatesInfo=null;$('template-dialog').close();$('template-form').reset();$('templates-list').replaceChildren();$('host-preset-templates').replaceChildren();$('host-preset-templates').hidden=true;

    configReviewRequest++;configReview=null;$('config-history-dialog').close();$('config-history-diff').replaceChildren();$('config-history-body').replaceChildren();

    scheduleRequest++;$('backup-schedule-form').reset();delete $('backup-schedule-form').dataset.dirty;scheduleInfo=null;
    diagnosticsRequest++;diagnosticsController?.abort();diagnosticsController=null;$('diagnostics-form').reset();$('diagnostics-results').replaceChildren();
    mfaGate=false; mfaRequest++; $('mfa-dialog').close(); $('mfa-form').reset(); $('mfa-recovery-codes').textContent=''; $('mfa-secret').value=''; $('password').value=''; $('login-mfa-code').value=''; $('login-mfa-field').hidden=true;
    helpRequest++;helpLoading=false;helpInfo=null;helpError='';$('help-search').value='';$('help-article-body').replaceChildren();
    authenticated = false; $('login').hidden = false; $('app').hidden = true; $('cloudflare-token-form').reset();
    loadSetup().catch(error=>$('login-error').textContent=error.message);
    backupRequest++;$('backup-dialog').close();$('backup-form').reset();$('restore-review-dialog').close();restoreReview=null;
    $('host-dialog').close(); $('confirm-dialog').close(); $('certificate-dialog').close();
    $('certificate-form').reset();
    $('prometheus-token').value='';$('prometheus-token-result').hidden=true;$('webhook-destination-form').reset();
    $('user-dialog').close(); $('password-dialog').close(); $('user-form').reset(); $('password-form').reset(); currentUser=null; managementRequest++; delete $('alert-settings-form').dataset.dirty;
    $('acme-dialog').close(); $('trusted-dialog').close(); $('cache-purge-dialog').close(); cacheRequest++; historyRequest++;
  }
  async function enter() {
    const identity=await api('session'); currentUser=identity.user; passwordEditable=identity.password_editable ?? Boolean(currentUser.managed);
    if(identity.mfa_enrollment_required){authenticated=false;mfaGate=true;$('login').hidden=true;$('app').hidden=true;openMfa('setup');return;}
    mfaGate=false;
    $('profile-name').textContent=currentUser.username; $('profile-role').textContent=isAdmin() ? 'Administrator' : 'Read-only';
    navigateFromLocation({replace:true,load:false,focus:false});
    config = {version: 0, routes: []}; logs = []; upstreamInfo = {version:-1,routes:{}};
    authenticated = true; $('login').hidden = true; $('app').hidden = false;
    applyPermissions();if(view==='help')loadHelp(); await refresh();
  }
  function toast(message) {
    clearTimeout(toastTimer); $('toast').textContent = message; $('toast').classList.add('visible');
    toastTimer = setTimeout(() => { $('toast').classList.remove('visible'); $('toast').textContent = ''; }, 4500);
  }
  function connected(online) {
    $('connection').classList.toggle('offline', !online);
    $('connection').innerHTML = `<span class="status-dot"></span>${online ? 'EmberGate connected' : 'Connection lost'}`;
  }
  async function refresh() {
    if (!authenticated || refreshing) return;
    refreshing = true;
    try {
      const certRequest = certificateRequest;
      const autoRequest = automationRequest;
      const cachePoll=cacheRequest;
      const [nextConfig, stats, traffic, tls, automation, upstreams, caching] = await Promise.all([api('config'), api('stats'), api('logs'), api('certificates'), api('acme'), api('upstreams'), api('cache')]);
      // Do not replace a just-saved configuration with an older in-flight poll.
      if (nextConfig.version >= config.version) config = nextConfig;
      upstreamInfo = upstreams;
      logs = traffic.logs; renderHosts(); renderStats(stats); renderLogs(); renderTrustedSummary();if(view==='diagnostics')renderDiagnosticsHosts();
      if (cachePoll===cacheRequest && !cacheChanging) {cacheInfo=caching;renderCache();}
      if (view === 'analytics') loadHistory();
      if (autoRequest === automationRequest) { acmeInfo = automation; renderAutomation(); }
      if (certRequest === certificateRequest) { certificates = tls.certificates; httpsAddress = tls.https_addr; renderCertificates(); }
      await loadManagement(); applyPermissions();
      connected(true); $('connection-error').hidden = true;
    } catch (error) {
      if(error.mfaEnrollmentRequired){await enter();return;}
      connected(false); $('connection-error').textContent = error.message;
      $('connection-error').hidden = false;
    } finally { refreshing = false; }
  }
  function navigate(next, section=next==='help'?helpPage:settingsPage, options={}) {
    if(!dashboardViews.includes(next))next='overview';
    if(next==='help'){if(!helpTopics.includes(section))section=helpPage;}
    else if(!settingsPages.some(page=>page.id===section))section='instance';
    if(next==='settings' && currentUser && !isAdmin() && settingsPages.find(page=>page.id===section)?.admin)section='instance';
    if (currentUser && ['audit','diagnostics'].includes(next) && !isAdmin()) next='overview';
    const moved=next!==view || (next==='settings' && section!==settingsPage) || (next==='help' && (section!==helpPage || (options.anchor||'')!==helpAnchor));
    // Authentication dialogs keep their own cancellation and recovery-code acknowledgement rules.
    if(moved && authenticated) {
      templateDialogRequest++;configReviewRequest++;
      if(view==='settings'&&settingsPage==='instances'&&(next!=='settings'||section!=='instances')){$('cluster-token-value').value='';$('cluster-token-result').hidden=true;}
      document.querySelectorAll('dialog[open]').forEach(dialog=>{if(dialog.id!=='mfa-dialog')dialog.close();});
    }
    if(moved)managementRequest++;
    if(next==='settings')settingsPage=section;
    if(next==='help'){helpPage=section;helpAnchor=options.anchor||'';}
    if(view==='diagnostics' && next!==view){diagnosticsRequest++;diagnosticsController?.abort();diagnosticsController=null;$('diagnostics-preview').disabled=false;$('diagnostics-run').disabled=false;$('diagnostics-progress').hidden=true;}
    view = next;
    for (const button of document.querySelectorAll('[data-view]')) {
      button.classList.toggle('active', button.dataset.view === view);
      if (button.dataset.view === view) button.setAttribute('aria-current', 'page'); else button.removeAttribute('aria-current');
    }
    $('breadcrumb').textContent = titles[view][0]; $('page-title').textContent = titles[view][0];
    $('page-description').textContent = titles[view][1];
    $('overview-view').hidden = view !== 'overview'; $('hosts-section').hidden = view !== 'hosts';
    $('diagnostics-view').hidden=view!=='diagnostics';if(view==='diagnostics')renderDiagnosticsHosts();
    $('cache-view').hidden=view!=='cache';
    $('analytics-view').hidden = view !== 'analytics';
    if (view === 'analytics') loadHistory();
    $('traffic-view').hidden = view !== 'traffic'; $('settings-view').hidden = view !== 'settings';
    $('certificates-view').hidden = view !== 'certificates'; $('add-certificate').hidden = view !== 'certificates';
    $('request-certificate').hidden = view !== 'certificates';
    $('add-host').hidden = !['overview', 'hosts'].includes(view);
    for(const name of ['accounts','audit','alerts']) $(name+'-view').hidden=view!==name;
    renderSettingsNavigation();
    $('help-view').hidden=view!=='help';
    if(view==='help'){renderHelp();if(authenticated)loadHelp();}
    const hash='#/'+view+(view==='settings'?'/'+settingsPage:view==='help'?'/'+helpPage+(helpAnchor?'/'+helpAnchor:''):'');
    if(location.hash!==hash) {
      if(options.fromLocation||options.replace)history.replaceState(null,'',hash);else history.pushState(null,'',hash);
    }
    if(authenticated && options.load!==false) {loadManagement().catch(error=>toast(error.message));applyPermissions();}
    if(moved && options.focus!==false && authenticated){window.scrollTo({top:0,behavior:'auto'});$('page-title').focus({preventScroll:true});if(view==='help')focusHelpAnchor();}

    $('sidebar').classList.remove('open'); $('mobile-menu').setAttribute('aria-expanded', 'false');
  }
  $('settings-navigation').addEventListener('click',event=>{
    const link=event.target.closest('[data-settings-link]');if(!link||event.button!==0||event.ctrlKey||event.metaKey||event.shiftKey||event.altKey)return;
    event.preventDefault();navigate('settings',link.dataset.settingsLink);
  });
  $('settings-section').addEventListener('change',()=>navigate('settings',$('settings-section').value));
  const restoreNavigation=()=>{
    const route=dashboardRoute(location.hash);
    const canonical='#/'+route.view+(route.view==='settings'?'/'+route.section:route.view==='help'?'/'+route.section+(route.anchor?'/'+route.anchor:''):'');
    if(route.view!==view || (route.view==='settings' && route.section!==settingsPage) || (route.view==='help' && (route.section!==helpPage||route.anchor!==helpAnchor)) || location.hash!==canonical)navigateFromLocation();
  };
  window.addEventListener('popstate',restoreNavigation);window.addEventListener('hashchange',restoreNavigation);
  document.querySelectorAll('[data-view]').forEach(button => button.addEventListener('click', () => navigate(button.dataset.view)));
  $('mobile-menu').addEventListener('click', () => {
    const open = $('sidebar').classList.toggle('open'); $('mobile-menu').setAttribute('aria-expanded', String(open));
  });
  document.addEventListener('click', event => {
    if (!$('sidebar').contains(event.target) && !$('mobile-menu').contains(event.target)) {
      $('sidebar').classList.remove('open'); $('mobile-menu').setAttribute('aria-expanded', 'false');
    }
  });
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape') { $('sidebar').classList.remove('open'); $('mobile-menu').setAttribute('aria-expanded', 'false'); }
  });

  function renderHosts() {
    const active = config.routes.filter(r => r.enabled).length;
    $('nav-count').textContent = config.routes.length; $('host-count').textContent = config.routes.length;
    $('stat-hosts').textContent = active;
    $('limited-hosts').textContent = config.routes.filter(r => r.enabled && r.rate_limit).length;
    $('stat-hosts-note').textContent = config.routes.length ? `${config.routes.length - active} paused · ${config.routes.length} total` : 'No hosts configured';
    $('config-version').textContent = `Revision ${config.version}`;
    const states = config.routes.filter(r => r.enabled).map(r => poolState(r, upstreamInfo.version === config.version ? upstreamInfo.routes[r.id] || [] : []));
    const unavailable = states.filter(s => s.label === 'Unavailable').length;
    const degraded = states.filter(s => s.className === 'degraded').length;
    const checking = states.filter(s => s.label === 'Checking').length;
    const maintenance=states.filter(s=>s.label==='Maintenance').length;
    const drained=states.filter(s=>s.label==='Drained').length;
    $('gateway-status-title').textContent = unavailable || degraded ? 'Backends need attention' : drained ? 'Backends are draining' : checking ? 'Checking backends' : maintenance ? 'Maintenance in progress' : active ? 'Routes are active' : 'Ready to connect';
    $('gateway-status-description').textContent = active ? [`${active} enabled ${active === 1 ? 'host' : 'hosts'}`, maintenance ? `${maintenance} in maintenance` : '', unavailable ? `${unavailable} unavailable` : '', degraded ? `${degraded} degraded` : '', drained ? `${drained} drained` : '', checking ? `${checking} checking` : ''].filter(Boolean).join(' · ') : 'Add a host to give your traffic a destination.';
    const routes = matchingHosts(config.routes, $('host-search').value, $('host-filter').value);
    $('hosts-body').innerHTML = routes.map(route => {
      const origins = [route.upstream, ...(route.additional_upstreams || [])];
      const statuses = upstreamInfo.version === config.version ? upstreamInfo.routes[route.id] || [] : [];
      const state = poolState(route, statuses);
      const backends = origins.map(origin => {
        const status = statuses.find(s => s.upstream === origin);
        const health = !route.enabled ? 'paused' : route.balancing?.draining?.includes(origin) ? 'draining' : status?.status || (route.health_check ? 'pending' : 'unchecked');
        const label = {healthy:'Healthy',unhealthy:'Unhealthy',pending:'Checking',unchecked:'Not monitored',paused:'Paused',draining:'Draining'}[health] || 'Checking';
        const detail = [label, `Weight ${status?.weight || 1}`, status ? `${status.active_requests || 0} active requests` : 'Activity awaiting status update', status?.detail, status?.latency_ms == null ? '' : `${status.latency_ms.toFixed(1)} ms`, status?.checked_at ? `Checked ${new Date(status.checked_at * 1000).toLocaleTimeString()}` : ''].filter(Boolean).join(' · ');
        return `<div class="pool-backend" title="${escapeHtml(detail)}"><span class="backend-dot ${health}" role="img" aria-label="${label}"></span><span class="mono">${escapeHtml(origin)}</span>${health==='draining' ? `<span class="soft-tag">${status ? `${Number(status.active_requests || 0)} active` : 'Updating'}</span>` : ''}</div>`;
      }).join('');
      return `<tr><td><div class="host-cell"><span class="host-badge">${icon('host')}</span><div><strong>${escapeHtml(route.host)}<span class="mono">${escapeHtml(route.path_prefix === '/' ? '' : route.path_prefix)}</span></strong><small>${escapeHtml(route.name)}</small>${route.routing ? `<small class="policy-note">${route.routing.strip_prefix ? 'Strip prefix' : route.routing.rewrite_prefix!=null ? `Rewrite → ${escapeHtml(route.routing.rewrite_prefix)}` : 'Request header policy'}</small>` : ''}${route.compression ? `<span class="soft-tag">${route.compression.mode==='gzip'?'Gzip':'Brotli / gzip'}</span>` : ''}${route.cache ? `<small class="policy-note">Cache · up to ${Number(route.cache.max_ttl_seconds)}s</small>` : ''}${route.access ? `<small class="policy-note">${route.access.mode === 'allow' ? 'Allowlist' : 'Blocklist'} · ${route.access.networks.length} networks</small>` : ''}${route.response ? `<small class="policy-note">${route.response.redirect_https ? 'HTTPS redirect · ' : ''}Response policy</small>` : ''}${route.rate_limit ? `<small class="host-rate-note">Limit ${escapeHtml(rateLimitSummary(route.rate_limit))} per IP</small>` : ''}</div></div></td><td>${backends}<small class="pool-note">${origins.length > 1 ? `${strategyLabels[route.balancing?.strategy || 'round_robin']} · ` : ''}${route.health_check ? `GET ${escapeHtml(route.health_check.path)} · every ${Number(route.health_check.interval_seconds)}s` : 'Health checks off'}</small></td><td><span class="status-badge ${state.className}"><span class="status-dot"></span>${state.label}</span></td><td><div class="row-actions"><button class="icon-button" data-action="edit" data-id="${escapeHtml(route.id)}" title="Edit ${escapeHtml(route.name)}" aria-label="Edit ${escapeHtml(route.name)}">${icon('edit')}</button><button class="icon-button" data-action="duplicate" data-id="${escapeHtml(route.id)}" title="Duplicate ${escapeHtml(route.name)}" aria-label="Duplicate ${escapeHtml(route.name)}">${icon('copy')}</button><button class="icon-button" data-action="toggle" data-id="${escapeHtml(route.id)}" title="${route.enabled ? 'Pause' : 'Enable'} ${escapeHtml(route.name)}" aria-label="${route.enabled ? 'Pause' : 'Enable'} ${escapeHtml(route.name)}">${icon('power')}</button><button class="icon-button" data-action="maintenance" data-id="${escapeHtml(route.id)}" title="${route.pages?.maintenance ? 'End maintenance' : 'Enable maintenance'}" aria-label="${route.pages?.maintenance ? 'End maintenance' : 'Enable maintenance'} for ${escapeHtml(route.name)}">${icon('shield')}</button><button class="icon-button" data-action="diagnostics" data-id="${escapeHtml(route.id)}" title="Diagnose ${escapeHtml(route.name)}" aria-label="Diagnose ${escapeHtml(route.name)}">${icon('search')}</button><button class="icon-button delete" data-action="delete" data-id="${escapeHtml(route.id)}" title="Delete ${escapeHtml(route.name)}" aria-label="Delete ${escapeHtml(route.name)}">${icon('trash')}</button></div></td></tr>`;
    }).join('');
    $('hosts-empty').hidden = routes.length > 0;
    $('hosts-empty').querySelector('h3').textContent = config.routes.length ? 'No matching hosts.' : 'No proxy hosts yet';
    $('hosts-empty').querySelector('p').textContent = config.routes.length ? 'Try another search or status filter.' : 'Add your first proxy host to connect a domain to an upstream service.';
    $('empty-add').hidden = config.routes.length > 0;
    $('hosts-footer').textContent = `${routes.length} of ${config.routes.length} hosts`;
  }
  function renderResponseTiming(timing={},prefix) {
    const labels={success:'Successful web requests',long_lived:'Live streams & mail push',server_error:'Server errors · 5xx',client_error:'Client / access errors · 4xx',cancelled:'Client disconnects / errors',transport_error:'No HTTP response'};
    const format=formatDuration;
    $(prefix+'-timing-rows').innerHTML=Object.entries(labels).map(([key,label])=>{const group=timing[key]||{};return `<tr><td>${label}</td><td>${number(group.requests||0)}</td><td>${escapeHtml(format(group.avg_headers_ms))}</td><td>${escapeHtml(format(group.avg_duration_ms))}</td></tr>`;}).join('');
    $(prefix+'-timing-samples').textContent=`${number(timing.success?.header_samples||0)} successful web header samples`;
  }
  function renderStats(stats) {
    $('stat-requests').textContent = number(stats.requests);
    $('stat-limited').textContent = number(stats.rate_limited);
    renderResponseTiming(stats.timing,'overview');
    $('stat-latency').textContent=responseTimingSummary(stats.timing).headers;
    $('stat-failed-latency').textContent=responseTimingSummary(stats.timing).p95;
    $('stat-errors').innerHTML = stats.requests ? `${(stats.errors / stats.requests * 100).toFixed(2)}<small>%</small>` : '—';
    $('proxy-address').textContent = stats.proxy_addr;
    const minutes = Math.floor(stats.uptime_seconds / 60);
    $('uptime').textContent = minutes < 1 ? 'Less than a minute' : minutes < 60 ? `${minutes} min` : `${Math.floor(minutes / 60)}h ${minutes % 60}m`;
    isFollowerNode=stats.cluster_role==='follower';$('cluster-notice').hidden=!isFollowerNode;
    $('cluster-notice').textContent=isFollowerNode?(stats.cluster_ready===false?'This follower is waiting for a fresh primary snapshot. Proxy traffic is paused.':'This node follows a primary. Change shared routes and certificates on the primary; local accounts and analytics remain independent.'):'';
    $('engine-version').textContent = `v${stats.version}`; $('settings-version').textContent = stats.version;
    $('settings-proxy').textContent = stats.proxy_addr; $('settings-admin').textContent = stats.admin_addr;
    $('settings-https').textContent = stats.https_addr || 'Disabled';
    $('settings-protocols').textContent = stats.https_addr ? 'HTTP / HTTPS' : 'HTTP';
    const chart = chartPoints(stats.buckets);
    $('chart-line').setAttribute('d', chart.line); $('chart-area').setAttribute('d', chart.area);
    $('chart-max').textContent = number(chart.max); $('chart-mid').textContent = number(chart.max / 2);
    const total = stats.buckets.reduce((sum, b) => sum + b.requests, 0);
    $('chart-empty').hidden = total > 0; $('chart-total').textContent = `${number(total)} requests in the last hour`;
    $('traffic-chart').setAttribute('aria-label', `${number(total)} requests in the last hour. Peak ${Math.max(0, ...stats.buckets.map(b => b.requests))} requests per minute.`);
  }
  function renderLogs() {
    const search = $('log-search').value.toLowerCase();
    const rows = logs.filter(l => `${l.method} ${l.path} ${l.host} ${l.status} ${l.route || ''} ${l.upstream || ''} ${l.client_ip || ''} ${l.peer_ip || ''} ${l.cache_status || ''} ${(l.attempted_upstreams || []).join(' ')} ${(l.attempted_upstreams || []).length>1 ? 'failover' : ''} ${l.access_denied ? 'access denied' : ''} ${l.rate_limited ? 'rate limited' : ''} ${l.maintenance ? 'maintenance' : ''}`.toLowerCase().includes(search));
    $('logs-body').innerHTML = rows.map(l => `<tr><td class="mono">${escapeHtml(new Date(l.timestamp * 1000).toLocaleTimeString())}</td><td class="request-cell"><strong>${escapeHtml(l.method)}</strong><span>${escapeHtml(l.path)}</span></td><td class="mono">${escapeHtml(l.host)}${l.upstream ? `<small class="request-upstream">${escapeHtml(l.upstream)}</small>` : ''}${(l.attempted_upstreams || []).length>1 ? `<small class="request-upstream" title="${escapeHtml(l.attempted_upstreams.join(' → '))}">Failover · ${l.attempted_upstreams.length} attempts</small>` : ''}</td><td class="mono" title="${escapeHtml(`Connection: ${l.peer_ip || 'unknown'} · ${l.identity_source || 'connection'}`)}">${escapeHtml(l.client_ip || '—')}</td><td><span class="status-code ${l.status >= 500 ? 'bad' : l.status >= 400 ? 'warn' : ''}">${Number(l.status)}</span>${l.cache_status && l.cache_status!=='OFF' ? `<small class="cache-log-note ${l.cache_status==='HIT' ? 'hit' : l.cache_status==='MISS' ? 'miss' : ''}">Cache ${escapeHtml(l.cache_status)}</small>` : ''}${l.maintenance ? '<small class="limit-log-note">Maintenance</small>' : ''}${l.rate_limited ? '<small class="limit-log-note">Gateway limit</small>' : l.access_denied ? '<small class="limit-log-note">Access denied</small>' : ''}</td><td class="mono">${Number(l.latency_ms).toFixed(1)} ms<small class="request-upstream">Headers: ${l.header_latency_ms==null?'—':Number(l.header_latency_ms).toFixed(1)+' ms'}</small>${l.client_cancelled?'<small class="request-upstream">Client disconnected / error</small>':l.long_lived?'<small class="request-upstream">Live stream / mail push</small>':''}</td></tr>`).join('');
    $('logs-empty').hidden = rows.length > 0;
    $('logs-empty').querySelector('h3').textContent = logs.length ? 'No matching requests.' : 'No requests recorded';
  }
  $('host-search').addEventListener('input', renderHosts); $('host-filter').addEventListener('change', renderHosts);
  $('log-search').addEventListener('input', renderLogs);

  function renderCertificates() {
    if($('host-dialog').open)renderHostReview();
    $('nav-cert-count').textContent = certificates.length; $('certificate-count').textContent = certificates.length;
    $('certificates-empty').hidden = certificates.length > 0;
    $('https-notice').textContent = httpsAddress
      ? `HTTPS is listening on ${httpsAddress}. New TLS connections use the current matching certificate.`
      : 'HTTPS is disabled. To enable it, set GATEWAY_HTTPS_ADDR (for example 127.0.0.1:8443) and restart the gateway. You can upload certificates now.';
    $('certificates-body').innerHTML = certificates.map(cert => {
      const managed = acmeInfo.orders.some(order => order.id === cert.id);
      const actions = managed ? '<span class="soft-tag">ACME managed</span>' : `<button class="icon-button" data-cert-action="replace" data-id="${escapeHtml(cert.id)}" title="Replace ${escapeHtml(cert.name)}" aria-label="Replace ${escapeHtml(cert.name)}">${icon('edit')}</button><button class="icon-button delete" data-cert-action="delete" data-id="${escapeHtml(cert.id)}" title="Delete ${escapeHtml(cert.name)}" aria-label="Delete ${escapeHtml(cert.name)}">${icon('trash')}</button>`;
      return `<tr><td><strong>${escapeHtml(cert.name)}</strong><small>${cert.domains.map(escapeHtml).join(' · ')}</small></td><td><span>${escapeHtml(cert.expires_at)}</span><small>${cert.days_remaining < 0 ? 'Expired' : `${Number(cert.days_remaining)} days remaining`}</small></td><td><span class="status-badge ${!cert.valid || cert.days_remaining < 30 ? 'paused' : ''}">${!cert.valid ? 'Invalid / expired' : cert.days_remaining < 30 ? 'Expires soon' : 'Valid'}</span></td><td><div class="row-actions">${actions}</div></td></tr>`;
    }).join('');
  }

  function renderAutomation() {
    $('managed-count').textContent = acmeInfo.orders.length;
    $('managed-empty').hidden = acmeInfo.orders.length > 0;
    $('request-certificate').disabled = !acmeInfo.configured;
    $('acme-provider-notice').textContent = acmeInfo.configured
      ? 'Cloudflare token configured on the gateway. Request a staging certificate first to verify DNS permissions. The API never returns the token.'
      : 'Automatic issuance needs a server-side Cloudflare token. Add a token in Settings → Cloudflare DNS. Grant Zone Read and DNS Edit for only the zones you want to manage.';
    const date = value => value ? new Date(value * 1000).toLocaleString() : 'After issuance';
    $('managed-body').innerHTML = acmeInfo.orders.map(order => {
      const busy = ['issuing','queued'].includes(order.status);
      const label = order.status === 'ready' ? 'Active' : order.status === 'error' ? 'Failed' : order.status === 'queued' ? 'Queued' : 'Issuing';
      return `<tr><td><strong>${escapeHtml(order.name)}</strong><small>${order.domains.map(escapeHtml).join(' · ')}</small></td><td>${order.environment === 'production' ? 'Production' : 'Staging'}<small>${order.environment === 'production' ? "Let's Encrypt" : 'Test · not browser trusted'}</small></td><td><span class="status-badge ${order.status === 'ready' ? '' : 'paused'}">${label}</span><small>${escapeHtml(order.phase)}</small>${order.last_error ? `<small class="job-error">${escapeHtml(order.last_error)}</small>` : ''}</td><td>${order.status === 'error' ? 'Retry' : order.auto_renew ? 'Auto renew' : 'Auto renewal off'}<small>${escapeHtml(order.status === 'error' ? date(order.next_attempt) : order.auto_renew ? date(order.renew_at) : 'Manual renewal available')}</small></td><td><div class="row-actions"><button class="button secondary" data-acme-action="renew" data-id="${escapeHtml(order.id)}" ${busy || !acmeInfo.configured ? 'disabled' : ''}>Renew now</button>${order.environment === 'staging' ? `<button class="button secondary" data-acme-action="production" data-id="${escapeHtml(order.id)}" ${order.status !== 'ready' || order.cleanup_pending || !acmeInfo.configured ? 'disabled' : ''}>Use production</button>` : ''}<button class="icon-button" data-acme-action="stop" data-id="${escapeHtml(order.id)}" ${order.status === 'issuing' || order.cleanup_pending ? 'disabled' : ''} title="Stop automatic management" aria-label="Stop automatic management for ${escapeHtml(order.name)}">${icon('power')}</button></div></td></tr>`;
    }).join('');
  }
  $('request-certificate').addEventListener('click', () => {
    $('acme-form').reset(); $('acme-error').textContent = ''; $('acme-dialog').showModal(); $('acme-name').focus();
  });
  document.querySelectorAll('.close-acme').forEach(button => button.addEventListener('click', () => $('acme-dialog').close()));
  $('acme-form').addEventListener('submit', async event => {
    event.preventDefault(); const button = event.submitter; button.disabled = true; $('acme-error').textContent = ''; automationRequest++;
    try {
      const order = await api('acme/orders', {method:'POST',body:JSON.stringify({name:$('acme-name').value.trim(),domains:$('acme-domains').value.split(/[\s,]+/).filter(Boolean),email:$('acme-email').value.trim(),environment:$('acme-environment').value,auto_renew:$('acme-renew').checked,agree_to_terms:$('acme-terms').checked})});
      acmeInfo.orders.push(order); renderAutomation(); $('acme-dialog').close(); toast('Certificate request queued. Follow progress under Automatic certificates.');
    } catch (error) { $('acme-error').textContent = error.message; }
    finally { automationRequest++; button.disabled = false; }
  });
  $('managed-body').addEventListener('click', event => {
    const button = event.target.closest('[data-acme-action]'); if (!button) return;
    const order = acmeInfo.orders.find(order => order.id === button.dataset.id); if (!order) return;
    const production = button.dataset.acmeAction === 'production';
    const renew = button.dataset.acmeAction === 'renew';
    confirm(production ? 'Issue a production certificate?' : renew ? 'Renew this certificate now?' : 'Stop automatic management?', production
      ? `Request a publicly trusted Let's Encrypt certificate for ${order.domains.join(', ')}? By confirming, you agree to Let's Encrypt's subscriber agreement. The current certificate stays active until the replacement is ready.` : renew
      ? `Request a new ${order.environment} certificate for ${order.domains.join(', ')} now? Your current certificate stays active until a replacement is ready.`
      : `Stop issuance and automatic renewals for ${order.name}? An installed certificate will keep serving until it expires or you delete it.`, production ? 'Issue production' : renew ? 'Renew now' : 'Stop management', async () => {
      automationRequest++;
      try {
        await api(`acme/orders/${encodeURIComponent(order.id)}${production ? '/production' : renew ? '/renew' : ''}`, {method:production || renew ? 'POST' : 'DELETE', ...(production ? {body:JSON.stringify({agree_to_terms:true})} : {})});
        if (production || renew) { order.status='queued'; order.phase=production ? 'Production certificate queued' : 'Renewal queued'; if (production) order.environment='production'; }
        else acmeInfo.orders = acmeInfo.orders.filter(old => old.id !== order.id);
        renderAutomation(); renderCertificates(); toast(production ? 'Production issuance queued.' : renew ? 'Renewal queued.' : 'Automatic management stopped.');
      } finally { automationRequest++; }
    });
  });
  function openCertificate(cert) {
    $('certificate-form').reset(); $('certificate-error').textContent = '';
    $('certificate-id').value = cert?.id || ''; $('certificate-name').value = cert?.name || '';
    $('certificate-dialog-title').textContent = cert ? 'Replace certificate' : 'Add certificate';
    $('certificate-dialog').showModal(); $('certificate-name').focus();
  }
  $('add-certificate').addEventListener('click', () => openCertificate());
  $('empty-add-certificate').addEventListener('click', () => openCertificate());
  document.querySelectorAll('.close-certificate').forEach(button => button.addEventListener('click', () => $('certificate-dialog').close()));
  $('certificate-dialog').addEventListener('close', () => $('certificate-form').reset());
  async function changeCertificate(path, options) {
    if (certificatesChanging) throw new Error('A certificate change is already in progress.');
    certificatesChanging = true; certificateRequest++;
    try { const tls = await api(path, options); certificates = tls.certificates; httpsAddress = tls.https_addr; renderCertificates(); }
    finally { certificatesChanging = false; certificateRequest++; }
  }
  $('certificate-form').addEventListener('submit', async event => {
    event.preventDefault(); const button = event.submitter; button.disabled = true; $('certificate-error').textContent = '';
    try {
      const chain = $('certificate-chain').files[0], key = $('certificate-key').files[0];
      if (!chain || !key) throw new Error('Choose both the certificate chain and private key.');
      if (chain.size > 256 * 1024 || key.size > 64 * 1024) throw new Error('Certificate chains must be under 256 KB and private keys under 64 KB.');
      const id = $('certificate-id').value;
      await changeCertificate(id ? `certificates/${encodeURIComponent(id)}` : 'certificates', {method: id ? 'PUT' : 'POST', body: JSON.stringify({name:$('certificate-name').value.trim(), certificate_pem:await chain.text(), private_key_pem:await key.text()})});
      $('certificate-dialog').close(); toast('Certificate saved. New TLS connections use it immediately.');
    } catch (error) { $('certificate-error').textContent = error.message; }
    finally { button.disabled = false; }
  });
  $('certificates-body').addEventListener('click', event => {
    const button = event.target.closest('[data-cert-action]'); if (!button) return;
    const cert = certificates.find(c => c.id === button.dataset.id); if (!cert) return;
    if (button.dataset.certAction === 'replace') return openCertificate(cert);
    confirm('Delete this certificate?', `New HTTPS connections for ${cert.domains.join(', ')} will fail unless another matching certificate is available.`, 'Delete certificate', async () => {
      await changeCertificate(`certificates/${encodeURIComponent(cert.id)}`, {method:'DELETE'}); toast('Certificate deleted.');
    });
  });

  async function save(next) {
    if (changing) throw new Error('A configuration change is already in progress.');
    changing = true;
    try {
      config = await api('config', {method: 'PUT', body: JSON.stringify(next)});
      renderHosts(); renderTrustedSummary(); renderCache();
    } catch (error) {
      if (error.status === 409) await refresh();
      throw error;
    } finally { changing = false; }
  }
  let hostCreating=false,hostStep=0,hostSaving=false,presetsRevealed=false;
  $('host-preset-builtin').innerHTML=starterHostTemplates.map(item=>`<option value="starter:${item.id}">${escapeHtml(item.name)} · ${escapeHtml(item.apps)}</option>`).join('');
  function selectedPreset(){
    const value=$('host-preset').value;
    if(value.startsWith('starter:')){const item=starterHostTemplates.find(item=>item.id===value.slice(8));return item?{kind:'starter',item}:null;}
    if(value.startsWith('template:')){const item=templatesInfo?.templates.find(t=>t.id===value.slice(9));return item?{kind:'template',item}:null;}
    return null;
  }
  function presetPreview(preset){
    if(!preset)return 'Presets fill the draft only. Nothing is saved until you save the host.';
    if(preset.kind==='template')return `${policyNames(preset.item.policies)} Replaces all reusable policies in this draft; policies absent from the template are cleared.`;
    const item=preset.item;
    return `${item.note} Sets: preserve Host; ${item.protocol||'http1'} upstream; connect 5s, read/write ${item.timeout}s; retries 0; caching and compression off. Access, authentication, response rules, rate limits and health checks stay as configured.`;
  }
  $('host-preset').addEventListener('change',()=>{const preset=selectedPreset();$('host-preset-apply').disabled=!preset;$('host-preset-note').textContent=presetPreview(preset);});
  $('host-preset-apply').addEventListener('click',()=>{
    const preset=selectedPreset();if(!preset)return;
    if(preset.kind==='starter'){
      confirm('Apply built-in preset?',presetPreview(preset),'Apply to draft',async()=>{
        const draft=applyStarterTemplate({},preset.item.id);
        $('route-preserve').checked=true;$('route-upstream-protocol').value=draft.upstream_protocol;
        $('route-reliability').checked=true;$('route-connect-timeout').value=5;$('route-read-timeout').value=preset.item.timeout;$('route-write-timeout').value=preset.item.timeout;$('route-retries').value=0;
        $('route-cache').checked=false;$('route-compression').checked=false;
        for(const id of ['route-reliability','route-cache','route-compression'])$(id).dispatchEvent(new Event('change'));
        toast('Preset applied to draft. Review and save the host.');
      });
      return;
    }
    const template=preset.item;
    confirm('Apply host template?',`Replace the reusable policies in this draft with “${template.name}”? Policies absent from the template are cleared. Host identity, upstream origins, weights, drain flags, and maintenance settings stay as entered. Review the host and save it to make changes live.`,'Apply to draft',async()=>{
      fillHostPolicies({...applyHostTemplate({pages:readPages(),serialize_by_session:$('route-serialize').checked},template.policies),path_prefix:$('route-path').value});
      renderPolicyBadges();toast('Template applied to draft. Review and save the host.');
    },JSON.stringify(template.policies,null,2));
  });
  function hostCertificateNote(){
    const hostname=$('route-host').value.trim();
    if(!httpsAddress)return 'The gateway HTTPS listener is disabled. Configure HTTPS before redirecting visitors, or verify that another proxy terminates HTTPS in front of EmberGate.';
    if(hostname==='*')return 'A catch-all route needs a valid certificate for each hostname visitors use. Add certificates for the domains you intend to serve.';
    const certificate=matchingHostCertificate(hostname,certificates);
    return certificate?`A currently valid certificate matches this domain: ${certificate.name}. The client must also trust its issuer; matching alone does not verify browser trust.`:'No currently valid certificate matches this domain. Add or request one under Certificates before using HTTPS. Redirecting now may send visitors to a failed TLS connection.';
  }
  function renderHostReview(){
    $('host-certificate-status').textContent=hostCertificateNote();
    const redirected=$('route-redirect').checked;
    const policies=[['route-forward-auth','External application login'],['route-access','IP access rules'],['route-limit','Rate limiting'],['route-cache','Caching'],['route-compression','Compression'],['route-routing','Path / header changes'],['route-health','Health checks'],['route-reliability','Custom timeouts / failover'],['route-maintenance','Maintenance mode'],['route-preserve','Incoming Host header']].filter(([id])=>$(id).checked).map(([,label])=>label);
    const additional=$('route-additional').value.split(/\r?\n/).filter(line=>line.trim()).length;
    if(additional)policies.push(`${additional+1} backends`);
    if(redirected)policies.push('HTTPS redirect');if($('route-response').checked)policies.push('Security headers');
    const rows=[['Name',$('route-name').value.trim()],['Public address',`${redirected?'https':'http'}://${$('route-host').value.trim()}${redirected&&Number($('route-https-port').value)!==443?':'+$('route-https-port').value:''}${$('route-path').value.trim()}`],['Application address',$('route-upstream').value.trim()],['Upstream protocol',$('route-upstream-protocol').selectedOptions[0].textContent],['Visitor access',redirected?'HTTP redirects to HTTPS':'HTTP allowed; HTTPS also works with a matching certificate'],['Access restrictions',[$('route-forward-auth').checked?'External login required':'',$('route-access').checked?'IP rules apply; review the Access group':''].filter(Boolean).join(' · ')||'No gateway login or IP restrictions; the application may require its own sign-in'],['Status',$('route-status').value==='paused'?'Paused · saved without receiving traffic':'Active · receives matching traffic'],['Optional features',policies.join(' · ')||'Defaults · no caching, compression, rate limits, or path changes']];
    $('host-review-summary').replaceChildren(...rows.flatMap(([label,value])=>{const dt=document.createElement('dt'),dd=document.createElement('dd');dt.textContent=label;dd.textContent=value;return [dt,dd];}));
    const warnings=[];
    if(redirected&&(!httpsAddress||!matchingHostCertificate($('route-host').value,certificates)))warnings.push(hostCertificateNote());
    if($('route-maintenance').checked)warnings.push('Maintenance mode is enabled. Visitors receive the maintenance page instead of the application.');
    if($('route-cache').checked)warnings.push('Caching is enabled. Use it only for public content that can be shared between visitors.');
    if($('route-forward-auth').checked&&($('route-cache').checked||$('route-compression').checked))warnings.push('External login protection bypasses shared caching and compression.');
    $('host-review-warning').hidden=!warnings.length;$('host-review-warning').textContent=warnings.join(' ');
    $('host-save-check').hidden=!hostCreating||hostStep!==2||$('route-status').value!=='active'||$('route-host').value.trim()==='*';
    $('host-check-note').hidden=!hostCreating||$('route-status').value!=='active'||$('route-host').value.trim()==='*';
  }
  function showHostStep(step,focus=true){
    hostStep=step;$('host-form').dataset.step=String(step);$('host-form').dataset.mode=hostCreating?'create':'edit';
    $('host-destination').hidden=hostCreating&&step!==0;
    $('host-access').hidden=hostCreating&&step!==1;
    $('host-review').hidden=!hostCreating||step!==2;
    $('host-preset-section').hidden=hostCreating?step!==0:!presetsRevealed;
    $('advanced-options').hidden=hostCreating&&step!==2;
    $('host-steps').hidden=!hostCreating;$('host-edit-sections').hidden=hostCreating;
    $('host-next').hidden=!hostCreating||step===2;$('host-back').hidden=!hostCreating||step===0;
    $('host-save').hidden=hostCreating&&step!==2;
    $('host-save').innerHTML=hostCreating?'Create host <svg aria-hidden="true"><use href="#i-arrow"/></svg>':'Save changes <svg aria-hidden="true"><use href="#i-arrow"/></svg>';
    $('host-next').textContent=step===0?'Continue to access':'Review host';
    Array.from($('host-steps').children).forEach((item,index)=>{if(index===step)item.setAttribute('aria-current','step');else item.removeAttribute('aria-current');item.dataset.complete=String(index<step);});
    renderHostReview();
    if(focus){$('host-dialog').scrollTop=0;$(hostCreating?['host-destination-title','host-access-title','host-review-title'][step]:'host-destination-title').focus();}
  }
  function revealHostField(field){
    if(hostCreating)showHostStep($('host-destination').contains(field)||$('host-preset-section').contains(field)?0:$('host-access').contains(field)?1:2,false);
    for(let parent=field.parentElement;parent&&parent!==$('host-form');parent=parent.parentElement)if(parent.tagName==='DETAILS')parent.open=true;
  }
  const hostFieldIds=['route-name','route-host','route-upstream','route-path'];
  function rejectField(id,errorId,message){
    const field=$(id);field.setAttribute('aria-invalid','true');field.dataset.errorFor=errorId;field.setAttribute('aria-describedby',errorId);field.focus();throw new Error(message);
  }
  function clearField(field){
    if(!field.dataset?.errorFor)return;
    field.removeAttribute('aria-invalid');if(field.getAttribute('aria-describedby')===field.dataset.errorFor)field.removeAttribute('aria-describedby');delete field.dataset.errorFor;
  }
  document.addEventListener('input',event=>clearField(event.target));
  const rejectHostField=(id,message)=>rejectField(id,'host-error',message);
  function validateHostDestination(){
    for(const id of hostFieldIds)if(!$(id).checkValidity()){$(id).reportValidity();return false;}
    if(!$('route-name').value.trim())rejectHostField('route-name','Give this host a name so you can find it later.');
    const hostname=$('route-host').value.trim();
    if(/[\s/?#@]/.test(hostname)||(hostname.includes(':')&&!/^\[[0-9a-f:.]+\]$/i.test(hostname)))rejectHostField('route-host','Enter a public hostname without a scheme, port, path, or spaces.');
    try{upstreamOrigin($('route-upstream').value);}catch(error){rejectHostField('route-upstream',error instanceof TypeError?'Enter a full address such as http://192.168.1.20:2283.':error.message);}
    return true;
  }
  function nextHostStep(){
    $('host-error').textContent='';
    try{if(hostStep===0&&!validateHostDestination())return;showHostStep(Math.min(2,hostStep+1));}catch(error){$('host-error').textContent=error.message;}
  }
  function syncHostAccess(){
    $('route-redirect').checked=$('host-access-mode').value==='https';
    syncHttpsPort();renderHostReview();renderPolicyBadges();
  }
  $('host-next').addEventListener('click',nextHostStep);
  $('host-back').addEventListener('click',()=>{$('host-error').textContent='';showHostStep(Math.max(0,hostStep-1));});
  function syncHttpsPort(){const off=!$('route-redirect').checked;$('host-https-port-field').hidden=off;$('route-https-port').disabled=off;}
  $('host-access-mode').addEventListener('change',syncHostAccess);
  $('host-edit-sections').addEventListener('click',event=>{const button=event.target.closest('[data-host-section]');if(!button)return;const section=$(button.dataset.hostSection);if(section.id==='host-preset-section'){presetsRevealed=true;section.hidden=false;}if(section.tagName==='DETAILS')section.open=true;section.scrollIntoView({block:'start'});(section.querySelector(':scope > h3, :scope > h4')||section.querySelector('summary,select')||section).focus();});
  $('host-form').addEventListener('input',()=>{if(!hostSaving)renderHostReview();});
  $('host-form').addEventListener('change',event=>{if(!hostSaving)renderHostReview();});

  const count=id=>$(id).value.split(/\r?\n/).filter(line=>line.trim()).length;
  const policyIcons={'forward-auth-options':'i-lock','access-options':'i-ban','rate-options':'i-clock','response-options':'i-shield','compression-options':'i-archive','cache-options':'i-layers','routing-options':'i-route','pool-options':'i-nodes','reliability-options':'i-refresh','serialize-options':'i-flow','pages-options':'i-power'};
  const policySummaries={
    'forward-auth-options':()=>$('route-auth-url').value||'External authentication check',
    'access-options':()=>`${$('route-access-mode').value==='block'?'Block':'Allow only'} ${count('route-access-networks')} ${count('route-access-networks')===1?'network':'networks'}`,
    'rate-options':()=>`${$('route-limit-requests').value} requests per ${$('route-limit-window').value}s · burst ${$('route-limit-burst').value}`,
    'response-options':()=>[Number($('route-hsts').value)>0?'HSTS':'',$('route-nosniff').checked||$('route-frame-deny').checked||$('route-referrer').checked?'Security headers':'',count('route-response-headers')?`${count('route-response-headers')} custom headers`:''].filter(Boolean).join(' · ')||'HTTPS / header policy',
    'compression-options':()=>`${$('route-compression-mode').value==='gzip'?'Gzip':'Brotli / gzip'} · level ${$('route-compression-level').value}`,
    'cache-options':()=>`Max freshness ${$('route-cache-ttl').value}s · max object ${$('route-cache-size').value} KiB`,
    'routing-options':()=>`${{preserve:'Preserve path',strip:'Strip prefix',replace:'Replace prefix'}[$('route-path-mode').value]} · ${count('route-request-headers')} set · ${count('route-remove-headers')} removed headers`,
    'pool-options':()=>[`${count('route-additional')+1} ${count('route-additional')?'backends':'backend'}`,$('route-strategy').value.replaceAll('_',' '),$('route-health').checked?'health checks':''].filter(Boolean).join(' · '),
    'reliability-options':()=>`Connect ${$('route-connect-timeout').value}s · read ${$('route-read-timeout').value}s · write ${$('route-write-timeout').value}s · ${$('route-retries').value} retries`,
    'serialize-options':()=>'Same-cookie requests queued in order',
    'pages-options':()=>`Maintenance mode · HTTP ${$('route-maintenance-status').value}`
  };
  const policyBadges={
    'forward-auth-options':()=>$('route-forward-auth').checked,
    'access-options':()=>$('route-access').checked,
    'rate-options':()=>$('route-limit').checked,
    'response-options':()=>$('route-response').checked,
    'compression-options':()=>$('route-compression').checked,
    'cache-options':()=>$('route-cache').checked,
    'routing-options':()=>$('route-routing').checked,
    'pool-options':()=>$('route-health').checked||Boolean($('route-additional').value.trim())||$('route-strategy').value!=='round_robin',
    'reliability-options':()=>$('route-reliability').checked,
    'pages-options':()=>$('route-maintenance').checked,
    'serialize-options':()=>$('route-serialize').checked
  };
  function renderPolicyBadges(){
    for(const [id,active] of Object.entries(policyBadges)){
      const summary=$(id).querySelector(':scope > summary');
      let badge=summary.querySelector(':scope > .policy-badge');
      if(!badge){badge=document.createElement('span');summary.append(badge);}
      const on=active();
      badge.textContent=on?'On':'Off';
      badge.className='policy-badge'+(on?' on':'');
      let icon=summary.querySelector(':scope > .policy-icon');
      if(!icon){icon=document.createElementNS('http://www.w3.org/2000/svg','svg');icon.setAttribute('class','policy-icon');icon.setAttribute('aria-hidden','true');const use=document.createElementNS('http://www.w3.org/2000/svg','use');use.setAttribute('href','#'+policyIcons[id]);icon.append(use);summary.prepend(icon);}
      let sub=summary.querySelector(':scope > .policy-sub');
      if(!sub){sub=document.createElement('small');sub.className='policy-sub';summary.append(sub);}
      sub.textContent=on?policySummaries[id]():'Not configured for this host';
    }
  }
  $('host-form').addEventListener('input',renderPolicyBadges);$('host-form').addEventListener('change',renderPolicyBadges);
  function openHost(route, duplicated=false) {
    hostCreating=!route||duplicated;hostStep=0;hostSaving=false;presetsRevealed=false;
    editingConfig = structuredClone(config);
    editingRoute=route?structuredClone(route):null;
    $('host-form').reset(); $('host-error').textContent = ''; hostFieldIds.forEach(id=>clearField($(id)));
    $('dialog-title').textContent = duplicated?'Duplicate proxy host':route ? 'Edit proxy host' : 'Add proxy host';
    $('duplicate-host-note').hidden=!duplicated;
    $('route-id').value = route?.id || '';
    $('route-name').value = route?.name || ''; $('route-host').value = route?.host || '';
    $('route-path').value = route?.path_prefix || '/'; $('route-upstream').value = route?.upstream || '';
    $('route-status').value = route?.enabled === false ? 'paused' : 'active';
    $('route-preserve').checked = route?.preserve_host || false;
    $('route-additional').value = (route?.additional_upstreams || []).join('\n');
    backendDraft.clear();$('backend-controls').replaceChildren();
    $('route-strategy').value=route?.balancing?.strategy || 'round_robin';
    renderBackendControls(route);
    $('host-preset').value='';$('host-preset-apply').disabled=true;$('host-preset-note').textContent=presetPreview(null);
    fillHostPolicies(route);
    loadHostTemplates();
    $('host-intro').textContent=hostCreating?'Connect your domain to an application in three short steps.':'Update the destination directly, or open the section you need. Existing policies are kept until you change them.';
    $('host-access-mode').value=$('route-redirect').checked?'https':'http';
    showHostStep(0,false);
    $('host-dialog').showModal();
    $('host-dialog').scrollTop=0;
    $('route-name').focus();
    hostBaseline=hostSnapshot();
  }
  let hostBaseline='';
  const hostSnapshot=()=>JSON.stringify(Array.from($('host-form').elements,field=>field.type==='checkbox'||field.type==='radio'?field.checked:field.value));
  function requestHostClose(){
    if(hostSaving)return;
    if(hostSnapshot()===hostBaseline){$('host-dialog').close();return;}
    confirm('Discard changes to this host?','Your edits have not been saved. Closing now discards them.','Discard changes',async()=>$('host-dialog').close());
  }
  $('host-dialog').addEventListener('cancel',event=>{event.preventDefault();requestHostClose();});
  function fillHostPolicies(route) {
    $('route-upstream-protocol').value=route?.upstream_protocol||'http1';
    $('route-preserve').checked=route?.preserve_host || false;
    const pages=validatePages(route?.pages || {});
    $('route-maintenance').checked=pages.maintenance;$('route-branded-errors').checked=pages.branded_errors;
    $('route-maintenance-status').value=String(pages.status);$('route-maintenance-title').value=pages.title;
    $('route-maintenance-message').value=pages.message;$('route-maintenance-retry').value=pages.retry_after_seconds;
    toggleMaintenance();
    const routing=route?.routing;
    $('route-routing').checked=Boolean(routing);
    $('route-path-mode').value=routing?.strip_prefix?'strip':routing?.rewrite_prefix!=null?'replace':'preserve';
    $('route-rewrite-prefix').value=routing?.rewrite_prefix ?? '/';
    $('route-request-headers').value=(routing?.set_headers || []).map(rule=>`${rule.name}: ${rule.value}`).join('\n');
    $('route-remove-headers').value=(routing?.remove_headers || []).join('\n');
    $('route-preview-path').value=route?.path_prefix || '/';toggleRouting();
    $('route-reliability').checked=Boolean(route?.reliability);
    $('route-verify-upstream-tls').checked=route?.verify_upstream_tls!==false;
    $('route-serialize').checked=Boolean(route?.serialize_by_session);
    $('route-connect-timeout').value=route?.reliability?.connect_timeout_seconds ?? 5;
    $('route-read-timeout').value=route?.reliability?.read_timeout_seconds ?? 60;
    $('route-write-timeout').value=route?.reliability?.write_timeout_seconds ?? 60;
    $('route-retries').value=route?.reliability?.retries ?? 0;toggleReliability();
    $('route-health').checked = Boolean(route?.health_check);
    const health = route?.health_check;
    $('route-health-path').value = health?.path || '/';
    $('route-health-interval').value = health?.interval_seconds ?? 10;
    $('route-health-timeout').value = health?.timeout_seconds ?? 3;
    $('route-health-failures').value = health?.failure_threshold ?? 2;
    $('route-health-recovery').value = health?.recovery_threshold ?? 1;
    toggleHealthFields();
    $('route-limit').checked = Boolean(route?.rate_limit);
    $('route-limit-requests').value = route?.rate_limit?.requests ?? 60;
    $('route-limit-window').value = route?.rate_limit?.window_seconds ?? 60;
    $('route-limit-burst').value = route?.rate_limit?.burst ?? 20;
    toggleRateFields();
    $('route-access').checked = Boolean(route?.access);
    $('route-access-mode').value = route?.access?.mode || 'allow';
    $('route-access-networks').value = (route?.access?.networks || []).join('\n');
    const response=route?.response;
    $('route-response').checked = Boolean(response) && responseHasHeaders(response);
    $('route-redirect').checked = response?.redirect_https || false;
    $('route-https-port').value = response?.https_port ?? 443;
    $('route-hsts').value = response?.hsts_max_age ?? 0;
    $('route-hsts-subdomains').checked = response?.hsts_include_subdomains || false;
    $('route-nosniff').checked = response?.nosniff || false;
    $('route-frame-deny').checked = response?.frame_deny || false;
    $('route-referrer').checked = response?.referrer_policy || false;
    $('route-response-headers').value = (response?.custom_headers || []).map(h => `${h.name}: ${h.value}`).join('\n');
    syncHttpsPort();
    togglePolicyFields();
    $('route-forward-auth').checked=Boolean(route?.forward_auth);
    $('route-auth-url').value=route?.forward_auth?.url||'';
    $('route-auth-timeout').value=route?.forward_auth?.timeout_seconds??5;
    $('route-auth-login').value=route?.forward_auth?.sign_in_url||'';
    $('route-auth-request-headers').value=(route?.forward_auth?.request_headers||['cookie','authorization']).join('\n');
    $('route-auth-response-headers').value=(route?.forward_auth?.response_headers||['remote-user','remote-name','remote-email','remote-groups']).join('\n');toggleForwardAuthFields();
    $('route-compression').checked=Boolean(route?.compression);
    $('route-compression-mode').value=route?.compression?.mode ?? 'auto';
    $('route-compression-level').value=route?.compression?.level ?? 4;
    $('route-compression-min').value=route?.compression?.min_bytes ?? 1024;toggleCompressionFields();
    $('route-cache').checked=Boolean(route?.cache);
    $('route-cache-ttl').value=route?.cache?.max_ttl_seconds ?? 300;
    $('route-cache-size').value=(route?.cache?.max_object_bytes ?? 1048576)/1024;
    $('route-cache-query').checked=route?.cache?.cache_query_strings ?? false;
    toggleCacheFields();
    const optionPolicies={'serialize-options':Boolean(route?.serialize_by_session),'forward-auth-options':Boolean(route?.forward_auth),'pool-options':Boolean(route?.health_check || $('route-additional').value.trim() || $('route-strategy').value!=='round_robin' || Array.from($('backend-controls').querySelectorAll('[data-draining]')).some(el=>el.checked) || Array.from($('backend-controls').querySelectorAll('[data-weight]')).some(el=>Number(el.value)!==1)),'response-options':Boolean(route?.response),'compression-options':Boolean(route?.compression),'cache-options':Boolean(route?.cache),'routing-options':Boolean(route?.routing),'access-options':Boolean(route?.access),'rate-options':Boolean(route?.rate_limit),'reliability-options':Boolean(route?.reliability),'pages-options':Boolean(route?.pages)};
    for(const [id,configured] of Object.entries(optionPolicies)) {$(id).open=false;$(id).dataset.configured=String(configured);}
    const advancedNames=[['forward_auth','Application login'],['compression','Compression'],['cache','Caching'],['routing','Path / headers'],['access','Access rules'],['rate_limit','Rate limiting'],['reliability','Timeouts / failover'],['pages','Maintenance / pages']].filter(([key])=>route?.[key]).map(([,label])=>label);
    if(route?.preserve_host) advancedNames.push('Preserve Host');
    if(route?.serialize_by_session) advancedNames.push('Session ordering');
    if(route?.verify_upstream_tls===false) advancedNames.push('Upstream TLS verification disabled');
    $('advanced-options').open=!hostCreating;
    if(responseHasHeaders(route?.response))advancedNames.push('Security headers');
    if($('pool-options').dataset.configured==='true')advancedNames.push('Backends / health');
    $('advanced-options').dataset.configured=String(advancedNames.length>0);
    $('host-access-mode').value=$('route-redirect').checked?'https':'http';
    renderHostReview();renderPolicyBadges();
    $('advanced-summary').textContent=advancedNames.length?`${advancedNames.length} configured · ${advancedNames.join(' · ')}`:'Access, performance, routing and availability';
  }
  function toggleHealthFields() {
    $('health-fields').hidden = !$('route-health').checked;
    $('health-fields').disabled = !$('route-health').checked;
  }
  function readRateLimit() {
    return {requests:Number($('route-limit-requests').value), window_seconds:Number($('route-limit-window').value), burst:Number($('route-limit-burst').value)};
  }
  function rateExample() {
    try {
      const limit = validateRateLimit(readRateLimit());
      $('rate-example').textContent = `Allow up to ${limit.burst} immediately per IP. Refill continuously at ${limit.requests} requests per ${limit.window_seconds} seconds. Excess requests receive 429 with a retry delay.`;
    } catch (error) { $('rate-example').textContent = error.message; }
  }
  function toggleRateFields() {
    $('rate-fields').hidden = !$('route-limit').checked;
    $('rate-fields').disabled = !$('route-limit').checked;
    rateExample();
  }
  $('route-limit').addEventListener('change', toggleRateFields);
  ['route-limit-requests','route-limit-window','route-limit-burst'].forEach(id => $(id).addEventListener('input', rateExample));
  function togglePolicyFields() {
    $('access-fields').hidden = !$('route-access').checked;
    $('access-fields').disabled = !$('route-access').checked;
    $('response-fields').hidden = !$('route-response').checked;
    $('response-fields').disabled = !$('route-response').checked;
  }
  function renderBackendControls(route=null) {
    for(const row of $('backend-controls').querySelectorAll('[data-backend-origin]')) backendDraft.set(row.dataset.backendOrigin,{weight:Number(row.querySelector('[data-weight]').value),draining:row.querySelector('[data-draining]').checked});
    let origins;try {origins=[$('route-upstream').value,...$('route-additional').value.split(/\r?\n/).filter(value=>value.trim())].map(upstreamOrigin);if(new Set(origins).size!==origins.length || origins.length>16)throw new Error();}
    catch {$('backend-controls').textContent='Enter valid, unique upstream origins to configure backend weights and draining.';return;}
    const configured=route ? [route.upstream,...(route.additional_upstreams || [])] : [];
    $('backend-controls').innerHTML=origins.map(origin=>{
      const index=configured.indexOf(origin),saved=route && index>=0 ? {weight:route.balancing?.weights?.[index] || 1,draining:route.balancing?.draining?.includes(origin) || false} : backendDraft.get(origin) || {weight:1,draining:false};
      return `<div class="backend-control" data-backend-origin="${escapeHtml(origin)}"><span class="mono">${escapeHtml(origin)}</span><label>Weight<input type="number" data-weight min="1" max="100" value="${Number(saved.weight)}" required aria-label="Weight for ${escapeHtml(origin)}"></label><label class="checkbox-label"><input type="checkbox" data-draining ${saved.draining ? 'checked' : ''} aria-label="Drain ${escapeHtml(origin)}"><span>Drain</span></label></div>`;
    }).join('');
  }
  function readPages() {
    return validatePages({maintenance:$('route-maintenance').checked,status:Number($('route-maintenance-status').value),title:$('route-maintenance-title').value,message:$('route-maintenance-message').value,retry_after_seconds:Number($('route-maintenance-retry').value),branded_errors:$('route-branded-errors').checked});
  }
  function renderMaintenancePreview() {
    $('maintenance-preview-title').textContent=$('route-maintenance-title').value;
    $('maintenance-preview-message').textContent=$('route-maintenance-message').value;
    $('maintenance-preview-status').textContent=`HTTP ${$('route-maintenance-status').value}`;
  }
  function toggleMaintenance() {
    const enabled=$('route-maintenance').checked;$('maintenance-fields').hidden=!enabled;$('maintenance-fields').disabled=!enabled;renderMaintenancePreview();
  }
  $('route-maintenance').addEventListener('change',toggleMaintenance);
  ['route-maintenance-title','route-maintenance-message','route-maintenance-status'].forEach(id=>$(id).addEventListener('input',renderMaintenancePreview));
  function readRouting() {
    return validateRouting({strip_prefix:$('route-path-mode').value==='strip',rewrite_prefix:$('route-path-mode').value==='replace'?$('route-rewrite-prefix').value:null,
      set_headers:$('route-request-headers').value.split(/\r?\n/).filter(line=>line.trim()).map(line=>{const colon=line.indexOf(':');if(colon<=0) throw new Error('Use Name: Value for each request header override.');return {name:line.slice(0,colon).trim(),value:line.slice(colon+1).trim()};}),
      remove_headers:$('route-remove-headers').value.split(/\r?\n/).map(line=>line.trim()).filter(Boolean)});
  }
  function renderRoutingPreview() {
    try {
      const policy=$('route-routing').checked?readRouting():{};
      const target=previewRouting($('route-preview-path').value,$('route-path').value,policy);
      const origin=upstreamOrigin($('route-upstream').value);
      const host=$('route-preserve').checked?`Incoming authority (${$('route-host').value==='*'?'any matched hostname':$('route-host').value}; may include a port)`:new URL(origin).host;
      $('route-preview').textContent=`Upstream path: ${target}\nOrigin: ${origin} (selected backend may vary)\nHost: ${host}\n`+(policy.set_headers || []).map(rule=>`Set ${rule.name}: ${rule.value}`).join('\n')+((policy.remove_headers || []).length?`\nRemove: ${policy.remove_headers.join(', ')}`:'');
      $('route-preview-error').textContent='';
    } catch(error) {$('route-preview').textContent='';$('route-preview-error').textContent=error.message;}
  }
  function toggleRouting() {
    const enabled=$('route-routing').checked;
    $('routing-fields').hidden=!enabled;$('routing-fields').disabled=!enabled;
    const replace=$('route-path-mode').value==='replace';
    $('route-rewrite-prefix').disabled=!enabled || !replace;$('route-rewrite-field').hidden=!replace;
    renderRoutingPreview();
  }
  $('route-routing').addEventListener('change',toggleRouting);$('route-path-mode').addEventListener('change',toggleRouting);
  ['route-rewrite-prefix','route-request-headers','route-remove-headers','route-preview-path','route-path','route-host','route-upstream','route-preserve'].forEach(id=>$(id).addEventListener('input',renderRoutingPreview));
  function toggleReliability() {$('reliability-fields').hidden=!$('route-reliability').checked;$('reliability-fields').disabled=!$('route-reliability').checked;}
  $('route-reliability').addEventListener('change',toggleReliability);
  for(const id of ['route-upstream','route-additional']) $(id).addEventListener('change',()=>renderBackendControls());
  function toggleForwardAuthFields() {$('forward-auth-fields').hidden=!$('route-forward-auth').checked;$('forward-auth-fields').disabled=!$('route-forward-auth').checked;}
  $('route-forward-auth').addEventListener('change',toggleForwardAuthFields);
  function toggleCompressionFields() {$('compression-fields').hidden=!$('route-compression').checked;$('compression-fields').disabled=!$('route-compression').checked;}
  $('route-compression').addEventListener('change',toggleCompressionFields);
  function toggleCacheFields() {
    $('cache-fields').hidden=!$('route-cache').checked;
    $('cache-fields').disabled=!$('route-cache').checked;
  }
  $('route-cache').addEventListener('change',toggleCacheFields);
  $('route-access').addEventListener('change',togglePolicyFields);
  $('route-response').addEventListener('change',togglePolicyFields);
  $('route-health').addEventListener('change', toggleHealthFields);
  $('add-host').addEventListener('click', () => openHost()); $('empty-add').addEventListener('click', () => openHost());
  document.querySelectorAll('.close-dialog').forEach(button => button.addEventListener('click', () => {const dialog=button.closest('dialog');if(dialog.id==='host-dialog')requestHostClose();else dialog.close();}));
  // Reveal invalid controls before the browser attempts to focus them.
  $('host-form').addEventListener('invalid',event=>{
    revealHostField(event.target);
  },true);
  $('host-form').addEventListener('submit', async event => {
    event.preventDefault(); $('host-error').textContent = '';
    if(hostSaving)return;
    if(hostCreating&&hostStep<2){nextHostStep();return;}
    const invalid=Array.from($('host-form').elements).find(field=>field.willValidate&&!field.validity.valid);
    if(invalid){revealHostField(invalid);invalid.reportValidity();return;}
    const button = event.submitter||$('host-save'),checkAfter=button.id==='host-save-check';
    hostSaving=true;$('host-save').disabled=true;$('host-save-check').disabled=true;
    try {
      if(!validateHostDestination())return;
      const upstream = upstreamOrigin($('route-upstream').value);
      const additional = $('route-additional').value.split(/\r?\n/).map(s => s.trim()).filter(Boolean).map(upstreamOrigin);
      if (additional.length > 15) throw new Error('A host supports up to 16 upstream origins.');
      if (new Set([upstream, ...additional]).size !== additional.length + 1) throw new Error('Upstream origins must be unique.');
      const route = {id: $('route-id').value || newHostId(), name: $('route-name').value.trim(),
        host: $('route-host').value.trim(), path_prefix: $('route-path').value.trim(), upstream,
        enabled: $('route-status').value === 'active', preserve_host: $('route-preserve').checked,
        verify_upstream_tls:$('route-verify-upstream-tls').checked};
      if($('route-serialize').checked)route.serialize_by_session=true;
      if($('route-upstream-protocol').value!=='http1')route.upstream_protocol=$('route-upstream-protocol').value;
      if (additional.length) route.additional_upstreams = additional;
      const origins=[upstream,...additional];let rows=Array.from($('backend-controls').querySelectorAll('[data-backend-origin]'));
      if(rows.length!==origins.length || rows.some((row,index)=>row.dataset.backendOrigin!==origins[index])) {renderBackendControls();rows=Array.from($('backend-controls').querySelectorAll('[data-backend-origin]'));}
      const balancing=validateBalancing({strategy:$('route-strategy').value,weights:rows.map(row=>Number(row.querySelector('[data-weight]').value)),draining:rows.filter(row=>row.querySelector('[data-draining]').checked).map(row=>row.dataset.backendOrigin)},origins);
      if(balancing.strategy!=='round_robin' || balancing.draining.length || balancing.weights.some(weight=>weight!==1)) route.balancing=balancing;
      const pages=readPages();if(pages.maintenance || !pages.branded_errors || editingRoute?.pages) route.pages=pages;
      if($('route-routing').checked) route.routing=readRouting();
      if($('route-reliability').checked) route.reliability=validateReliability({connect_timeout_seconds:Number($('route-connect-timeout').value),read_timeout_seconds:Number($('route-read-timeout').value),write_timeout_seconds:Number($('route-write-timeout').value),retries:Number($('route-retries').value)});
      if ($('route-health').checked) route.health_check = {
        path: $('route-health-path').value.trim(), interval_seconds: Number($('route-health-interval').value),
        timeout_seconds: Number($('route-health-timeout').value), failure_threshold: Number($('route-health-failures').value),
        recovery_threshold: Number($('route-health-recovery').value)
      };
      if ($('route-limit').checked) route.rate_limit = validateRateLimit(readRateLimit());
      if($('route-forward-auth').checked)route.forward_auth=validateForwardAuth({url:$('route-auth-url').value.trim(),timeout_seconds:Number($('route-auth-timeout').value),sign_in_url:$('route-auth-login').value.trim()||null,request_headers:$('route-auth-request-headers').value.split('\n').map(name=>name.trim()).filter(Boolean),response_headers:$('route-auth-response-headers').value.split('\n').map(name=>name.trim()).filter(Boolean)});
      if($('route-compression').checked)route.compression=validateCompression({mode:$('route-compression-mode').value,level:Number($('route-compression-level').value),min_bytes:Number($('route-compression-min').value)});
      if ($('route-cache').checked) route.cache=validateCachePolicy({max_ttl_seconds:Number($('route-cache-ttl').value),max_object_bytes:Number($('route-cache-size').value)*1024,cache_query_strings:$('route-cache-query').checked});
      if ($('route-access').checked) route.access = {mode:$('route-access-mode').value, networks:$('route-access-networks').value.split(/\r?\n/).map(n => n.trim()).filter(Boolean)};
      const headers=$('route-response').checked;
      if (headers || $('route-redirect').checked) route.response = {
        redirect_https:$('route-redirect').checked, https_port:Number($('route-https-port').value),
        hsts_max_age:headers?Number($('route-hsts').value):0, hsts_include_subdomains:headers&&$('route-hsts-subdomains').checked,
        nosniff:headers&&$('route-nosniff').checked, frame_deny:headers&&$('route-frame-deny').checked, referrer_policy:headers&&$('route-referrer').checked,
        custom_headers:!headers?[]:$('route-response-headers').value.split(/\r?\n/).filter(line => line.trim()).map(line => {
          const colon=line.indexOf(':'); if (colon<=0) throw new Error('Use Name: Value for each custom response header.');
          return {name:line.slice(0,colon).trim(),value:line.slice(colon+1).trim()};
        })
      };
      const next = structuredClone(editingConfig);
      const index = next.routes.findIndex(r => r.id === route.id);
      if (index >= 0) next.routes[index] = route; else next.routes.push(route);
      await save(next); $('host-dialog').close(); toast(route.enabled?'Host saved. Your routes are live.':'Host saved in paused mode.');
      if(checkAfter){navigate('diagnostics');$('diagnostics-route').value=route.id;fillDiagnosticsHost(route);$('diagnostics-form').requestSubmit($('diagnostics-run'));}
    } catch (error) { $('host-error').textContent = error.message; }
    finally {hostSaving=false;$('host-save').disabled=false;$('host-save-check').disabled=false;}
  });
  function confirm(title, description, action, callback, preview = '') {
    $('confirm-title').textContent = title; $('confirm-description').textContent = description;
    $('confirm-action').textContent = action; $('confirm-action').classList.toggle('danger', action.startsWith('Delete ')||action==='Discard changes');
    $('confirm-error').textContent = ''; $('import-preview').textContent = preview; $('import-preview').hidden = !preview;
    confirmCallback = callback; $('confirm-dialog').showModal();
  }
  document.querySelectorAll('.close-confirm').forEach(button => button.addEventListener('click', () => $('confirm-dialog').close()));
  $('confirm-action').addEventListener('click', async () => {
    $('confirm-action').disabled = true;
    try { await confirmCallback(); $('confirm-dialog').close(); }
    catch (error) { $('confirm-error').textContent = error.message; }
    finally { $('confirm-action').disabled = false; }
  });
  $('hosts-body').addEventListener('click', async event => {
    const button = event.target.closest('[data-action]'); if (!button) return;
    const route = config.routes.find(r => r.id === button.dataset.id); if (!route) return;
    const next = structuredClone(config);
    if (button.dataset.action === 'edit') return openHost(route);
    if(button.dataset.action==='duplicate')return openHost(duplicateHost(route),true);
    if(button.dataset.action==='diagnostics'){navigate('diagnostics');$('diagnostics-route').value=route.id;fillDiagnosticsHost(route);return;}
    if(button.dataset.action==='maintenance') return confirm(route.pages?.maintenance?'End maintenance?':'Enable maintenance?',route.pages?.maintenance?'New requests will resume normal proxying.':'New requests will receive the configured maintenance response after access rules, HTTPS redirects, and rate limits. Existing requests finish normally.',route.pages?.maintenance?'End maintenance':'Enable maintenance',async()=>{
      const updated=next.routes.find(r=>r.id===route.id);updated.pages=validatePages({...validatePages(updated.pages || {}),maintenance:!updated.pages?.maintenance});
      await save(next);toast(updated.pages.maintenance?'Maintenance enabled.':'Normal proxying resumed.');
    });
    if (button.dataset.action === 'delete') return confirm('Delete this host?', `Requests to ${route.host}${route.path_prefix} will no longer use “${route.name}”.`, 'Delete host', async () => {
      next.routes = next.routes.filter(r => r.id !== route.id); await save(next); toast('Proxy host deleted.');
    });
    button.disabled = true;
    try {
      next.routes.find(r => r.id === route.id).enabled = !route.enabled;
      await save(next); toast(route.enabled ? 'Host paused.' : 'Host enabled.');
    } catch (error) { toast(error.message); }
    finally { button.disabled = false; }
  });
  const memory=value=>Number(value || 0)<1048576 ? `${(Number(value || 0)/1024).toFixed(1)} KiB` : `${(Number(value)/1048576).toFixed(1)} MiB`;
  function renderCache() {
    const rows=cacheInfo.routes || [];
    const hits=rows.reduce((sum,r)=>sum+r.hits,0), misses=rows.reduce((sum,r)=>sum+r.misses,0);
    $('cache-hit-ratio').textContent=hits+misses ? `${(hits/(hits+misses)*100).toFixed(1)}%` : '—';
    $('cache-hits').textContent=number(hits); $('cache-entries').textContent=number(cacheInfo.entries);
    $('cache-memory').textContent=memory(cacheInfo.used_bytes); $('cache-capacity').textContent=`${memory(cacheInfo.capacity_bytes)} shared capacity`;
    $('cache-enabled').textContent=`${config.routes.filter(r=>r.enabled && r.cache).length} enabled`;
    $('cache-empty').hidden=config.routes.length>0;
    $('cache-body').innerHTML=config.routes.map(route=>{
      const row=rows.find(r=>r.route_id===route.id) || {hits:0,misses:0,bypasses:0,entries:0,bytes:0};
      const policy=route.cache;
      return `<tr><td><strong>${escapeHtml(route.host)}${escapeHtml(route.path_prefix==='/' ? '' : route.path_prefix)}</strong><small>${escapeHtml(route.name)}</small><small>${policy ? `${route.enabled ? 'Enabled' : 'Paused'} · up to ${Number(policy.max_ttl_seconds)}s · ${(policy.max_object_bytes/1024).toLocaleString()} KiB${policy.cache_query_strings ? ' · queries included' : ''}` : 'Caching off'}</small></td><td>${number(row.hits)} / ${number(row.misses)}</td><td>${number(row.bypasses)}</td><td>${number(row.entries)}<small>${memory(row.bytes)}</small></td><td><div class="row-actions"><button class="button secondary" data-cache-action="edit" data-id="${escapeHtml(route.id)}">Configure</button><button class="button secondary" data-cache-action="purge" data-id="${escapeHtml(route.id)}">Purge</button></div></td></tr>`;
    }).join('');
  }
  function openCachePurge(routeId='') {
    $('cache-purge-form').reset(); $('cache-purge-error').textContent='';
    $('cache-purge-route').innerHTML='<option value="">All hosts</option>'+config.routes.map(r=>`<option value="${escapeHtml(r.id)}">${escapeHtml(r.name)} · ${escapeHtml(r.host)}</option>`).join('');
    $('cache-purge-route').value=routeId; $('cache-purge-dialog').showModal();
  }
  $('open-cache-purge').addEventListener('click',()=>openCachePurge());
  document.querySelectorAll('.close-cache-purge').forEach(button=>button.addEventListener('click',()=>$('cache-purge-dialog').close()));
  $('cache-body').addEventListener('click',event=>{
    const button=event.target.closest('[data-cache-action]'); if (!button) return;
    if (button.dataset.cacheAction==='purge') return openCachePurge(button.dataset.id);
    const route=config.routes.find(r=>r.id===button.dataset.id); if (!route) return;
    openHost(route); ['pool-options','reliability-options','routing-options','pages-options','access-options','rate-options','response-options'].forEach(id=>$(id).open=false); $('advanced-options').open=true; $('cache-options').open=true; $('cache-options').scrollIntoView({block:'start'});
  });
  $('cache-purge-form').addEventListener('submit',async event=>{
    event.preventDefault(); const button=event.submitter; button.disabled=true; $('cache-purge-error').textContent=''; cacheChanging=true; cacheRequest++;
    try {
      const result=await api('cache/purge',{method:'POST',body:JSON.stringify({route_id:$('cache-purge-route').value || null,url:$('cache-purge-url').value.trim() || null})});
      cacheInfo=await api('cache');renderCache(); $('cache-purge-dialog').close(); toast(`Purged ${number(result.removed)} cached responses.`);
    } catch(error) { $('cache-purge-error').textContent=error.message; }
    finally {button.disabled=false;cacheChanging=false;cacheRequest++;}
  });
  function renderTrustedSummary() {
    const proxies=config.trusted_proxies || [];
    $('trusted-summary').textContent=proxies.length ? `${proxies.length} trusted networks. Verified visitor IPs are used for access rules, rate limits, forwarding, and logs.` : 'No trusted networks. Visitor identity uses the connection IP.';
  }
  function trustedRow(proxy={network:'',header:'cloudflare',trust_proto:false}) {
    const row=document.createElement('div'); row.className='trusted-row';
    row.innerHTML=`<label>Network<input class="proxy-network" required placeholder="192.0.2.0/24" value="${escapeHtml(proxy.network)}"></label><label>Visitor header<select class="proxy-header"><option value="cloudflare">CF-Connecting-IP</option><option value="x_forwarded_for">X-Forwarded-For</option></select></label><button type="button" class="icon-button remove-trusted" aria-label="Remove network" title="Remove network">${icon('trash')}</button><label class="checkbox-label"><input type="checkbox" class="proxy-proto"><span>Trust forwarded HTTP/HTTPS protocol</span></label>`;
    row.querySelector('.proxy-header').value=proxy.header;
    row.querySelector('.proxy-proto').checked=proxy.trust_proto;
    row.querySelector('.remove-trusted').addEventListener('click',()=>row.remove());
    $('trusted-rows').append(row);
  }
  $('edit-trusted').addEventListener('click',()=>{
    trustedDraft=structuredClone(config); $('trusted-rows').replaceChildren(); $('trusted-error').textContent='';
    (config.trusted_proxies || []).forEach(trustedRow); $('trusted-dialog').showModal();
  });
  $('add-trusted').addEventListener('click',()=>trustedRow());
  document.querySelectorAll('.close-trusted').forEach(button=>button.addEventListener('click',()=>$('trusted-dialog').close()));
  $('cloudflare-trusted').addEventListener('click',async event=>{
    const button=event.currentTarget; button.disabled=true; $('trusted-error').textContent='';
    try {
      const {networks}=await api('cloudflare/networks');
      if (!$('trusted-dialog').open) return;
      const existing=new Set([...$('trusted-rows').querySelectorAll('.proxy-network')].map(input=>input.value.trim()));
      networks.filter(network=>!existing.has(network)).forEach(network=>trustedRow({network,header:'cloudflare',trust_proto:true}));
    } catch(error) { $('trusted-error').textContent=error.message; }
    finally {button.disabled=false;}
  });
  $('trusted-form').addEventListener('submit',async event=>{
    event.preventDefault(); const button=event.submitter; button.disabled=true; $('trusted-error').textContent='';
    try {
      const next=structuredClone(trustedDraft);
      next.trusted_proxies=[...$('trusted-rows').querySelectorAll('.trusted-row')].map(row=>({network:row.querySelector('.proxy-network').value.trim(),header:row.querySelector('.proxy-header').value,trust_proto:row.querySelector('.proxy-proto').checked}));
      await save(next); $('trusted-dialog').close(); toast('Trusted proxy configuration is live.');
    } catch(error) { $('trusted-error').textContent=error.message; }
    finally {button.disabled=false;}
  });
  async function loadHistory() {
    if (!authenticated) return;
    const request=++historyRequest;
    const selected=$('analytics-host').value, hours=$('analytics-period').value;
    try {
      const data=await api(`analytics?hours=${hours}${selected ? `&route_id=${encodeURIComponent(selected)}` : ''}`);
      if (request!==historyRequest || !authenticated) return;
      $('analytics-error').textContent='';
      const available=new Map((data.hosts || []).map(host=>[host.route_id || 'unmatched',host.name]));
      for (const route of config.routes) available.set(route.id,route.name);
      if (selected && !available.has(selected)) available.set(selected,'Historical route');
      $('analytics-host').innerHTML='<option value="">All hosts</option>'+[...available].map(([id,name])=>`<option value="${escapeHtml(id)}">${escapeHtml(name)}</option>`).join('');
      $('analytics-host').value=selected;
      const totals=data.totals;
      $('history-requests').textContent=number(totals.requests); $('history-errors').textContent=number(totals.errors);
      $('history-blocked').textContent=number(totals.rate_limited+totals.access_denied);
      renderResponseTiming(totals.timing,'history');
      $('history-latency').textContent=responseTimingSummary(totals.timing).headers;
      $('history-failed-latency').textContent=responseTimingSummary(totals.timing).p95;
      const chart=chartPoints(data.buckets); $('history-line').setAttribute('d',chart.line); $('history-area').setAttribute('d',chart.area);
      $('history-peak').textContent=`Peak ${number(Math.max(0,...data.buckets.map(b=>b.requests)))} / hour`;
      $('history-chart').setAttribute('aria-label',`${number(totals.requests)} requests across ${hours} hourly buckets`);
      $('history-start').textContent=data.buckets.length ? new Date(data.buckets[0].timestamp*1000).toLocaleString() : '—';
      $('history-end').textContent='Current hour';
      const hosts=selected ? data.hosts.filter(h=>(h.route_id || 'unmatched')===selected) : data.hosts;
      $('history-hosts').innerHTML=hosts.map(host=>`<tr><td>${escapeHtml(config.routes.find(r=>r.id===host.route_id)?.name || host.name)}</td><td>${number(host.requests)}</td><td>${number(host.errors)}</td><td>${number(host.rate_limited+host.access_denied)}</td></tr>`).join('');
      $('history-empty').hidden=hosts.length>0;
      $('history-codes').innerHTML=data.status_codes.map(code=>`<div><span class="status-code ${code.status>=500 ? 'bad' : code.status>=400 ? 'warn' : ''}">${Number(code.status)}</span><small>${number(code.requests)} requests</small></div>`).join('') || '<p class="automation-empty">No responses recorded.</p>';
    } catch(error) {if (request===historyRequest) $('analytics-error').textContent=error.message;}
  }
  $('analytics-period').addEventListener('change',loadHistory); $('analytics-host').addEventListener('change',loadHistory);
  function renderBackupStatus(){
    $('backup-status').textContent=backupInfo?.pending?'Restore queued. Restart EmberGate to apply it, or cancel to resume management edits.':backupInfo?.last_restore?`Last restored ${dateTime(backupInfo.last_restore.restored_at)}. A recovery copy of the previous saved state is available.`:'No restore is queued.';
    $('upload-full-backup').disabled=Boolean(backupInfo?.pending);$('cancel-full-restore').hidden=!backupInfo?.pending;$('download-recovery-backup').hidden=!backupInfo?.recovery_available;
  }
  function openBackup(mode){
    backupRequest++;backupMode=mode;$('backup-form').reset();$('backup-dialog-error').textContent='';
    const restoring=mode==='restore';$('backup-dialog-title').textContent=restoring?'Validate a backup':mode==='recovery'?'Download previous state':'Create encrypted backup';
    $('backup-dialog-description').textContent=restoring?'Choose your encrypted backup and its passphrase. Validation shows a review; it does not replace any current data.':'This download contains private keys and credentials. It is encrypted with the passphrase you choose below.';
    $('backup-upload-field').hidden=!restoring;$('full-backup-file').required=restoring;$('backup-confirm-field').hidden=restoring;$('backup-passphrase-confirm').required=!restoring;
    $('backup-submit').textContent=restoring?'Validate & review':'Download backup';$('backup-dialog').showModal();
  }
  $('download-full-backup').addEventListener('click',()=>openBackup('export'));$('upload-full-backup').addEventListener('click',()=>openBackup('restore'));$('download-recovery-backup').addEventListener('click',()=>openBackup('recovery'));
  document.querySelectorAll('.close-backup').forEach(button=>button.addEventListener('click',()=>{$('backup-dialog').close();$('backup-form').reset();}));
  $('backup-dialog').addEventListener('close',()=>{backupRequest++;$('backup-form').reset();});
  document.querySelectorAll('.close-restore-review').forEach(button=>button.addEventListener('click',()=>{$('restore-review-dialog').close();restoreReview=null;}));
  $('backup-form').addEventListener('submit',async event=>{
    event.preventDefault();const request=++backupRequest;$('backup-submit').disabled=true;$('backup-dialog-error').textContent='';
    try {
      const passphrase=$('backup-passphrase').value;
      if(backupMode==='restore'){
        const file=$('full-backup-file').files[0];if(!file || file.size>96*1024*1024)throw new Error('Choose an EmberGate backup no larger than 96 MiB.');
        const bytes=new Uint8Array(await file.arrayBuffer());let binary='';for(let i=0;i<bytes.length;i+=8192)binary+=String.fromCharCode(...bytes.subarray(i,i+8192));
        restoreReview=await api('backups/preview',{method:'POST',body:JSON.stringify({archive:btoa(binary),passphrase})});
        if(request!==backupRequest || !authenticated){restoreReview=null;return;}
        const s=restoreReview.summary;
        $('restore-review-summary').textContent=`Backup created: ${dateTime(restoreReview.created_at)}\nReview expires: ${dateTime(restoreReview.expires_at)}\n\n${s.routes.length} routes\n`+s.routes.map(r=>`  ${r.name} · ${r.host}${r.path_prefix}`).join('\n')+`\n\n${s.accounts.length} ${s.accounts.length===1?'account':'accounts'}\n`+s.accounts.map(a=>`  ${a.username} · ${a.role==='administrator'?'Administrator':'Read-only'}${a.enabled?'':' · disabled'}`).join('\n')+`\n\n${s.certificates.length} installed ${s.certificates.length===1?'certificate':'certificates'}\n`+s.certificates.map(c=>`  ${c.name} · ${c.domains.join(', ')} · ${c.valid?c.days_remaining+' days left':'expired / not current'}`).join('\n')+`\n\n${Number(s.configuration_revisions||0)} retained configuration revisions\n${Number(s.host_templates||0)} host templates\n${s.managed_certificates} managed certificates\n${s.pending_dns_records} saved DNS cleanup records\nCredentials: ${s.credential_types.map(key=>({cloudflare_token:'Cloudflare API token',alert_webhook_url:'Notification webhook',prometheus_token_sha256:'Prometheus scrape token',backup_schedule:'Automatic backup settings',backup_schedule_state:'Automatic backup history',backup_schedule_auth:'Offsite upload credentials',two_factor_authentication:'Authenticator secrets and recovery hashes',mfa_policy:'Administrator authentication policy'}[key] || key)).join(', ') || 'none'}\nAnalytics, audit history, alert settings, and delivery history included.`;
        $('restore-overrides-note').textContent=restoreReview.environment_overrides.length?`Current environment overrides still take precedence: ${restoreReview.environment_overrides.join(', ')}.`:'';
        $('restore-confirm-text').value='';$('restore-review-error').textContent='';$('backup-dialog').close();$('restore-review-dialog').showModal();
      } else {
        if(passphrase!==$('backup-passphrase-confirm').value)rejectField('backup-passphrase-confirm','backup-dialog-error','The passphrases do not match.');
        const response=await fetch('/api/backups/export',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-Gateway-Request':'1'},body:JSON.stringify({passphrase,recovery:backupMode==='recovery'})});
        if(!response.ok){const result=await response.json().catch(()=>({}));throw new Error(result.error || 'Could not create backup.');}
        const blob=await response.blob();if(request!==backupRequest || !authenticated)return;
        const url=URL.createObjectURL(blob);const link=document.createElement('a');link.href=url;link.download=`embergate-full-${Math.floor(Date.now()/1000)}.embergate`;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
        $('backup-dialog').close();toast('Encrypted backup downloaded. Keep its passphrase safe.');
      }
    }catch(error){$('backup-dialog-error').textContent=error.message;}finally{$('backup-passphrase').value='';$('backup-passphrase-confirm').value='';$('backup-submit').disabled=false;}
  });
  $('restore-review-form').addEventListener('submit',async event=>{
    event.preventDefault();$('restore-review-submit').disabled=true;$('restore-review-error').textContent='';
    try{await api('backups/restore',{method:'POST',body:JSON.stringify({id:restoreReview.id,confirm:$('restore-confirm-text').value})});$('restore-review-dialog').close();restoreReview=null;await loadManagement();toast('Restore queued. Restart EmberGate to apply it.');}
    catch(error){$('restore-review-error').textContent=error.message;}finally{$('restore-review-submit').disabled=false;}
  });
  $('cancel-full-restore').addEventListener('click',()=>confirm('Cancel queued restore?','The current installation will continue normally.','Cancel restore',async()=>{await api('backups/cancel',{method:'POST'});await loadManagement();toast('Queued restore cancelled.');}));
  $('export').addEventListener('click', () => {
    const url = URL.createObjectURL(new Blob([JSON.stringify(config, null, 2)], {type: 'application/json'}));
    const link = document.createElement('a'); link.href = url; link.download = `embergate-routes-r${config.version}.json`;
    link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); toast('Configuration exported.');
  });
  $('import-file').addEventListener('change', async event => {
    const file = event.target.files[0]; if (!file) return;
    try {
      if (file.size > 1024 * 1024) throw new Error('Configuration files must be smaller than 1 MB.');
      const next = importConfig(await file.text(), config.version);
      const routePreview = next.routes.map(r => `${r.enabled ? 'Active' : 'Paused'} · ${r.name}\n${r.host}${r.path_prefix} → ${[r.upstream, ...(r.additional_upstreams || [])].join(', ')}${r.health_check ? `\nHealth check: GET ${r.health_check.path}` : ''}${r.rate_limit ? `\nRate limit: ${rateLimitSummary(r.rate_limit)} per IP` : ''}${r.cache ? `\nCache: up to ${r.cache.max_ttl_seconds}s, ${r.cache.max_object_bytes} bytes` : ''}${r.access ? `\nAccess: ${r.access.mode} ${r.access.networks.join(', ')}` : ''}${r.response ? `\nResponse policy: ${r.response.redirect_https ? 'HTTPS redirect; ' : ''}${r.response.custom_headers?.length || 0} custom headers` : ''}`).join('\n\n') || 'No routes. This will remove every proxy host.';
      const trustedPreview=(next.trusted_proxies || []).map(p=>`${p.network} · ${p.header} · forwarded protocol ${p.trust_proto ? 'trusted' : 'ignored'}`).join('\n') || 'None: use connection identities';
      const preview=`Trusted proxies:\n${trustedPreview}\n\n${routePreview}`;
      confirm('Restore configuration?', `Replace your ${config.routes.length} current hosts with ${next.routes.length} imported hosts and replace trusted proxy settings? The previous configuration will be backed up.`, 'Restore routes', async () => {
        await save(next); toast('Configuration restored. Your routes are live.');
      }, preview);
    } catch (error) { toast(error.message); }
    event.target.value = '';
  });

  function applyPermissions() {
    renderSettingsNavigation();
    const admin=isAdmin();
    document.querySelectorAll('[data-admin-nav]').forEach(el=>el.hidden=!admin);
    const ids=['add-host','empty-add','add-certificate','empty-add-certificate','request-certificate','edit-trusted','import-file','open-cache-purge','add-user'];
    for(const id of ids) if($(id)) $(id).disabled=!admin;
    document.querySelectorAll('[data-action],[data-cert-action],[data-acme-action],[data-cache-action]').forEach(el=>{if(!admin)el.disabled=true;});
    if(isFollowerNode){
      for(const id of ['add-host','empty-add','add-certificate','empty-add-certificate','request-certificate','edit-trusted','import-file','save-cloudflare-token','remove-cloudflare-token'])if($(id))$(id).disabled=true;
      document.querySelectorAll('[data-action],[data-cert-action],[data-acme-action]').forEach(el=>{if(el.dataset.action!=='diagnostics')el.disabled=true;});
      document.querySelectorAll('[data-cache-action=edit]').forEach(el=>el.disabled=true);
    }

    document.querySelectorAll('.import-label').forEach(el=>el.hidden=!admin);
    $('diagnostics-preview').disabled=!admin || Boolean(diagnosticsController);$('diagnostics-run').disabled=!admin || Boolean(diagnosticsController);
    $('backup-schedule-card').hidden=!admin;$('backup-schedule-fields').disabled=!admin||scheduleChanging||Boolean(scheduleInfo?.running||backupInfo?.pending);
    $('backup-schedule-run').disabled=!admin||scheduleChanging||!scheduleInfo?.passphrase_configured||Boolean(scheduleInfo?.running||scheduleInfo?.runtime.requested||backupInfo?.pending);
    $('full-backup-card').hidden=!admin;
    $('config-history-card').hidden=!admin;
    $('host-templates-card').hidden=!admin;
    $('create-template').disabled=!admin || !templatesInfo || !config.routes.length || Boolean(backupInfo?.pending);
    if(!admin||backupInfo?.pending)$('template-save').disabled=true;
    for(const el of document.querySelectorAll('[data-edit-template],[data-delete-template]'))el.disabled=!admin||Boolean(backupInfo?.pending);
    $('config-history-apply').disabled=!admin || !configReview || changing || Boolean(backupInfo?.pending);
    $('users-card').hidden=!admin; $('change-password').hidden=!passwordEditable;
    $('recovery-password-note').hidden=passwordEditable;
    $('settings-change-password').hidden=!passwordEditable;
    $('cloudflare-token-fields').disabled=!admin || !credentialInfo?.cloudflare.editable;
    $('alert-settings-fields').disabled=!admin; $('save-alert-settings').hidden=!admin;
    $('test-webhook').hidden=!admin;
    $('webhook-destination-fields').disabled=!admin || alertInfo?.webhook_editable===false;
    for(const id of ['save-webhook-destination','remove-webhook-destination','generate-prometheus-token','disable-prometheus']) $(id).hidden=!admin;
  }
  function policyNames(policies) {
    const names=[['upstream_protocol','Upstream protocol'],['forward_auth','Application login'],['compression','Compression'],['cache','Caching'],['access','IP access'],['response','HTTPS / headers'],['rate_limit','Rate limit'],['reliability','Timeouts / failover'],['routing','Path / headers'],['health_check','Health checks']].filter(([key])=>policies[key]!=null).map(([,name])=>name);
    names.push(policies.preserve_host?'Preserve Host':'Origin Host',policies.branded_errors?'Branded errors':'Plain errors');if(policies.verify_upstream_tls===false)names.push('Unverified upstream HTTPS');return names.join(' · ');
  }
  function renderTemplates(info) {
    $('templates-error').textContent=info.error||'';
    if(info.error){templatesInfo=null;$('templates-list').replaceChildren();return;}
    if(templatesInfo && info.version<templatesInfo.version)return;
    templatesInfo=info;
    $('templates-list').innerHTML=info.templates.length?info.templates.map(template=>`<article class="template-item"><div class="template-item-heading"><div><h3>${escapeHtml(template.name)}</h3><p>${escapeHtml(template.description||'Reusable host policies')}</p></div><div class="row-actions"><button class="button secondary" data-edit-template="${escapeHtml(template.id)}">Edit</button><button class="icon-button delete" data-delete-template="${escapeHtml(template.id)}" aria-label="Delete ${escapeHtml(template.name)}">${icon('trash')}</button></div></div><p>${escapeHtml(policyNames(template.policies))}</p><small>Updated ${escapeHtml(dateTime(template.updated_at))} by ${escapeHtml(template.updated_by)}</small><details class="pool-options"><summary>Policy contents</summary><pre class="template-policy-preview">${escapeHtml(JSON.stringify(template.policies,null,2))}</pre></details></article>`).join(''):'<p class="settings-note">No templates yet. Copy policies from a saved host to get started.</p>';
  }
  async function loadHostTemplates() {
    const request=++templateRequest;$('host-preset-templates').replaceChildren();$('host-preset-templates').hidden=true;
    try {
      const result=await api('host-templates');if(request!==templateRequest||!authenticated||!isAdmin()||!$('host-dialog').open)return;
      templatesInfo=result;$('host-preset-templates').hidden=!result.templates.length;
      $('host-preset-templates').innerHTML=result.templates.map(t=>`<option value="template:${escapeHtml(t.id)}">${escapeHtml(t.name)}</option>`).join('');
    } catch(error){if(request===templateRequest)$('host-preset-note').textContent=`Saved host templates unavailable: ${error.message}`;}
  }
  $('host-dialog').addEventListener('close',()=>{templateRequest++;});
  async function openTemplateDialog(id=null) {
    const request=++templateDialogRequest;templateDialogOpening=request;$('templates-error').textContent='';
    try {
      const [info,latest]=await Promise.all([api('host-templates'),api('config')]);
      if(request!==templateDialogRequest||!authenticated||!isAdmin())return;
      const template=id?info.templates.find(t=>t.id===id):null;if(id&&!template)throw new Error('Template no longer exists.');
      renderTemplates(info);if(latest.version>=config.version)config=latest;
      $('template-form').reset();$('template-form').dataset.version=info.version;$('template-form').dataset.configVersion=latest.version;
      $('template-id').value=id||'';$('template-name').value=template?.name||'';$('template-description').value=template?.description||'';
      $('template-source').innerHTML=(id?'<option value="">Keep saved policies</option>':'<option value="">Choose a source host</option>')+latest.routes.map(r=>`<option value="${escapeHtml(r.id)}">${escapeHtml(r.name)} · ${escapeHtml(r.host+r.path_prefix)}</option>`).join('');
      $('template-source').required=!id;$('template-error').textContent='';$('template-save').disabled=false;$('template-dialog-title').textContent=id?'Edit host template':'Create host template';$('template-dialog').showModal();
    } catch(error){if(request===templateDialogRequest)$('templates-error').textContent=error.message;}
    finally{if(templateDialogOpening===request)templateDialogOpening=0;}
  }
  $('create-template').addEventListener('click',()=>openTemplateDialog());
  // A close event is queued: a subsequent edit may already be loading or open.
  $('template-dialog').addEventListener('close',()=>{if(templateDialogOpening||$('template-dialog').open)return;templateDialogRequest++;$('template-form').reset();});
  $('template-form').addEventListener('submit',async event=>{
    event.preventDefault();const request=templateDialogRequest;let stale=false;$('template-save').disabled=true;$('template-error').textContent='';
    try {
      const result=await api('host-templates',{method:'POST',body:JSON.stringify({id:$('template-id').value||null,name:$('template-name').value,description:$('template-description').value,source_route_id:$('template-source').value||null,expected_config_version:Number($('template-form').dataset.configVersion),expected_version:Number($('template-form').dataset.version)})});
      if(request!==templateDialogRequest||!authenticated)return;
      renderTemplates(result);$('template-dialog').close();applyPermissions();toast('Host template saved. Existing hosts are unchanged.');
    } catch(error){if(request===templateDialogRequest){$('template-error').textContent=error.message;stale=error.status===409;}}
    finally{if(request===templateDialogRequest)$('template-save').disabled=stale;}
  });
  $('templates-list').addEventListener('click',event=>{
    const edit=event.target.closest('[data-edit-template]');if(edit)return openTemplateDialog(edit.dataset.editTemplate);
    const remove=event.target.closest('[data-delete-template]');if(!remove||!templatesInfo)return;
    const template=templatesInfo.templates.find(t=>t.id===remove.dataset.deleteTemplate);if(!template)return;
    const version=templatesInfo.version;
    confirm('Delete host template?',`Remove “${template.name}” from the library? Hosts that used this template keep their saved policies.`,'Delete template',async()=>{
      const result=await api('host-templates/'+encodeURIComponent(template.id),{method:'DELETE',body:JSON.stringify({expected_version:version})});if(!authenticated||!isAdmin())return;renderTemplates(result);applyPermissions();toast('Host template removed.');
    });
  });
  function renderConfigHistory(info) {
    $('config-history-error').textContent=info.error||'';
    if(info.error){$('config-history-body').replaceChildren();$('config-history-status').textContent='History is unavailable.';return;}
    $('config-history-status').textContent=`Live revision ${Number(info.current_version)} · ${info.revisions.length} earlier ${info.revisions.length===1?'revision':'revisions'} retained`;
    $('config-history-body').innerHTML=info.revisions.length?info.revisions.map(entry=>`<tr><td><strong>Revision ${Number(entry.version)}</strong></td><td>${escapeHtml(dateTime(entry.archived_at))}</td><td>${escapeHtml(entry.archived_by)}</td><td>${Number(entry.hosts)}</td><td class="align-right"><button class="button secondary" data-review-config="${escapeHtml(entry.id)}">Compare &amp; roll back</button></td></tr>`).join(''):'<tr><td colspan="5">Earlier revisions appear after you save a configuration change.</td></tr>';
  }
  function renderConfigComparison(comparison) {
    const value=v=>v===null?'—':typeof v==='string'?v:JSON.stringify(v,null,2);
    const change=(label,before,after)=>`<div class="config-change"><h4>${escapeHtml(label)}</h4><div class="config-change-values"><div><small>CURRENT</small><pre>${escapeHtml(value(before))}</pre></div><div><small>AFTER ROLLBACK</small><pre>${escapeHtml(value(after))}</pre></div></div></div>`;
    return `${comparison.trusted_proxies?`<section class="config-diff-section"><h3>Trusted proxies</h3>${change('Trusted networks',comparison.trusted_proxies.before,comparison.trusted_proxies.after)}</section>`:''}${comparison.route_order_changed?`<details class="pool-options config-diff-section"><summary>Host order</summary><p>Host display order will be restored.</p>${change('Host order',comparison.route_order.before,comparison.route_order.after)}</details>`:''}${comparison.routes.map(route=>`<details class="pool-options config-diff-section"><summary><span>${escapeHtml(route.name)}</span><span class="soft-tag">${escapeHtml(route.action)}</span></summary>${route.changes.map(c=>change(c.field==='/'?'Entire host':c.field.slice(1).replaceAll('/',' › ').replaceAll('_',' '),c.before,c.after)).join('')}</details>`).join('')}${!comparison.routes.length&&!comparison.trusted_proxies&&!comparison.route_order_changed?'<p class="notice">Routes and trusted proxies already match this revision.</p>':''}`;
  }
  $('config-history-body').addEventListener('click',async event=>{
    const button=event.target.closest('[data-review-config]');if(!button||!isAdmin())return;
    const request=++configReviewRequest;button.disabled=true;$('config-history-error').textContent='';
    try {
      const result=await api('config/history/'+encodeURIComponent(button.dataset.reviewConfig));
      if(request!==configReviewRequest||!authenticated||!isAdmin()||view!=='settings')return;
      configReview=result;$('config-history-title').textContent=`Roll back to revision ${Number(result.version)}?`;
      $('config-history-description').textContent=`Compare live revision ${Number(result.expected_version)} with revision ${Number(result.version)}. Confirming replaces all routes and trusted proxies immediately, creating revision ${Number(result.expected_version)+1}. Open each changed host to inspect its settings.`;
      $('config-history-diff').innerHTML=renderConfigComparison(result.comparison);$('config-history-review-error').textContent='';applyPermissions();$('config-history-dialog').showModal();
    } catch(error){if(request===configReviewRequest)$('config-history-error').textContent=error.message;} finally{button.disabled=false;}
  });
  $('config-history-dialog').addEventListener('close',()=>{configReview=null;configReviewRequest++;$('config-history-diff').replaceChildren();});
  $('config-history-apply').addEventListener('click',async()=>{
    const review=configReview;if(!review||changing)return;
    changing=true;$('config-history-apply').disabled=true;
    try {
      const result=await api('config/history/'+encodeURIComponent(review.id)+'/rollback',{method:'POST',body:JSON.stringify({expected_version:review.expected_version,confirm:'ROLLBACK'})});
      if(!authenticated)return;
      if(result.version>=config.version)config=result;
      $('config-history-dialog').close();renderHosts();await loadManagement();toast('Configuration rolled back. Revision '+Number(result.version)+' is live.');
    } catch(error){$('config-history-review-error').textContent=error.status===409?'Configuration changed since this review. Close this window and compare again.':error.message;if(error.status===409)configReview=null;}
    finally{changing=false;applyPermissions();}
  });
  const dateTime=value=>value ? new Date(value*1000).toLocaleString() : '—';
  async function loadManagement() {
    const request=++managementRequest, page=view;
    const results=await Promise.all([api('alerts'), ...(page==='accounts' ? [api('sessions'),...(isAdmin() ? [api('users')] : [])] : []),...(page==='audit' && isAdmin() ? [api('audit')] : []),...(page==='settings' ? [api('credentials'),...(isAdmin() ? [api('backups/status'),api('backups/schedule'),api('config/history').catch(error=>({error:error.message})),api('host-templates').catch(error=>({error:error.message}))] : [])] : []),...(page==='alerts' ? [api('integrations/prometheus')] : [])]);
    if(request!==managementRequest || !authenticated) return;
    alertInfo=results[0]; $('alert-count').textContent=number(alertInfo.unacknowledged_active);
    if(page==='alerts') {prometheusInfo=results.at(-1);renderAlerts();renderPrometheus();}
    if(page==='settings') {credentialInfo=results[1];if(isAdmin()){backupInfo=results[2];scheduleInfo=results[3];renderBackupStatus();renderSchedule();renderConfigHistory(results[4]);renderTemplates(results[5]);}renderCredentials();}
    if(page==='accounts') {
      const sessions=results[1].sessions;
      $('sessions-body').innerHTML=sessions.length ? sessions.map(session=>`<tr><td><strong>${escapeHtml(session.user.username)} ${session.current ? '<span class="soft-tag">This session</span>' : ''}</strong><small>${escapeHtml(session.peer)}</small></td><td>${escapeHtml(dateTime(session.created_at))}</td><td>${escapeHtml(dateTime(session.expires_at))}</td><td><button class="button secondary" data-end-session="${escapeHtml(session.id)}">Revoke</button></td></tr>`).join('') : '<tr><td colspan="4">No active sessions.</td></tr>';
      if(isAdmin()) {
        users=results[2].users;
        $('users-body').innerHTML=users.map(user=>`<tr><td><strong>${escapeHtml(user.username)}</strong><small>${user.managed ? 'Managed account' : 'Primary administrator'}</small></td><td>${user.role==='administrator' ? 'Administrator' : 'Read-only'}</td><td><span class="status-badge ${user.enabled ? '' : 'paused'}">${user.enabled ? 'Enabled' : 'Disabled'}</span></td><td><div class="row-actions">${user.managed ? `<button class="button secondary" data-edit-user="${escapeHtml(user.id)}">Edit</button><button class="icon-button delete" data-delete-user="${escapeHtml(user.id)}" aria-label="Delete ${escapeHtml(user.username)}">${icon('trash')}</button>` : '<span class="soft-tag">Primary</span>'}</div></td></tr>`).join('');
      }
    }
    if(page==='audit') $('audit-body').innerHTML=results[1].events.length ? results[1].events.map(event=>`<tr><td>${escapeHtml(dateTime(event.timestamp))}</td><td><strong>${escapeHtml(event.actor.username || 'Unknown')}</strong><small>${escapeHtml(event.actor.peer)}</small></td><td><span class="mono">${escapeHtml(event.method)} ${escapeHtml(event.path)}</span>${event.target ? `<small>${escapeHtml(event.target)}</small>` : ''}${event.details.configuration_version_after!==event.details.configuration_version_before ? `<small>Revision ${Number(event.details.configuration_version_before)} → ${Number(event.details.configuration_version_after)}</small>` : ''}</td><td><span class="status-badge ${event.phase==='success' ? '' : 'paused'}">${escapeHtml(event.phase)} ${event.status || ''}</span></td></tr>`).join('') : '<tr><td colspan="4">No activity recorded yet.</td></tr>';
    if(page==='settings'){const [mfa,passkeys]=await Promise.all([api('mfa'),api('passkeys')]);if(request!==managementRequest || !authenticated)return;mfaInfo=mfa;passkeysInfo=passkeys;renderMfa();renderPasskeys();}
    if(page==='settings'&&isAdmin()){const info=await api('cluster');if(request!==managementRequest||!authenticated)return;clusterInfo=info;renderCluster();}
    applyPermissions();
  }
  function renderAlerts() {
    $('alerts-active').textContent=number(alertInfo.unacknowledged_active);
    for(const state of ['pending','delivered','failed']) $('alerts-'+state).textContent=number(alertInfo.delivery[state]);
    $('alerts-list').innerHTML=alertInfo.alerts.length ? alertInfo.alerts.map(alert=>`<article class="alert-entry"><span class="status-badge ${alert.resolved_at ? '' : 'unhealthy'}">${alert.resolved_at ? 'Recovered' : alert.acknowledged ? 'Acknowledged' : 'Active'}</span><div><h3>${escapeHtml(alert.title)}</h3><p>${escapeHtml(alert.message)}</p><small>Opened ${escapeHtml(dateTime(alert.opened_at))}${alert.resolved_at ? ' · Recovered '+escapeHtml(dateTime(alert.resolved_at)) : ''}</small></div>${!alert.resolved_at && !alert.acknowledged && isAdmin() ? `<button class="button secondary" data-ack-alert="${escapeHtml(alert.id)}">Acknowledge</button>` : ''}</article>`).join('') : '<div class="automation-empty">All clear. Alerts will appear here when the gateway needs attention.</div>';
    // Preserve preferences while the user is editing the form.
    if(!$('alert-settings-form').contains(document.activeElement) && !$('alert-settings-form').dataset.dirty) {
      const settings=alertInfo.settings;
      for(const [id,key] of [['alert-backends','backend_failures'],['alert-certificates','certificate_failures'],['alert-errors','error_rate'],['alert-webhook','webhook_enabled']]) $(id).checked=settings[key];
      $('alert-threshold').value=settings.error_threshold_percent; $('alert-minimum').value=settings.minimum_requests; $('alert-window').value=settings.window_minutes;
      $('alert-webhook-format').value=settings.webhook_format || 'generic';
      $('alert-settings-form').dataset.version=settings.version;
    }
    $('webhook-notice').textContent=alertInfo.webhook_configured ? `Destination configured (${alertInfo.webhook_source || 'server'}). Enable delivery to send notifications.` : 'Save a webhook destination below, then enable delivery.';
    $('save-webhook-destination').disabled=alertInfo.webhook_editable===false;
    $('remove-webhook-destination').disabled=!alertInfo.webhook_configured || alertInfo.webhook_editable===false;
    $('alert-webhook').disabled=!alertInfo.webhook_configured;
    $('test-webhook').disabled=!alertInfo.settings.webhook_enabled || !alertInfo.webhook_configured;
  }
  $('alert-settings-form').addEventListener('input',()=>{$('alert-settings-form').dataset.dirty='1';});
  $('alert-settings-form').addEventListener('submit',async event=>{
    event.preventDefault();const button=event.submitter;button.disabled=true;$('alert-settings-error').textContent='';
    try {await api('alerts/settings',{method:'PUT',body:JSON.stringify({backend_failures:$('alert-backends').checked,certificate_failures:$('alert-certificates').checked,error_rate:$('alert-errors').checked,webhook_enabled:$('alert-webhook').checked,webhook_format:$('alert-webhook-format').value,error_threshold_percent:Number($('alert-threshold').value),minimum_requests:Number($('alert-minimum').value),window_minutes:Number($('alert-window').value),version:Number($('alert-settings-form').dataset.version)})});delete $('alert-settings-form').dataset.dirty;button.blur();await loadManagement();toast('Alert preferences saved.');}
    catch(error){$('alert-settings-error').textContent=error.message;}finally{button.disabled=false;}
  });
  $('webhook-destination-form').addEventListener('submit',async event=>{
    event.preventDefault();event.submitter.disabled=true;$('webhook-destination-error').textContent='';
    try {const result=await api('alerts/destination',{method:'PUT',body:JSON.stringify({url:$('webhook-url').value,webhook_format:$('alert-webhook-format').value,version:Number($('alert-settings-form').dataset.version)})});$('webhook-url').value='';$('alert-settings-form').dataset.version=result.settings.version;await loadManagement();toast('Webhook destination saved.');}
    catch(error){$('webhook-destination-error').textContent=error.message;}finally{event.submitter.disabled=alertInfo?.webhook_editable===false;}
  });
  $('remove-webhook-destination').addEventListener('click',()=>confirm('Remove notification destination?','Delivery will be disabled and pending notifications cancelled.','Remove destination',async()=>{await api('alerts/destination',{method:'DELETE'});$('webhook-url').value='';delete $('alert-settings-form').dataset.dirty;await loadManagement();}));
  function renderPrometheus(){
    $('prometheus-status').textContent=prometheusInfo?.configured?'Scrape token configured. Metrics are available to authorized scrapers.':'Scraping is disabled. Generate a token to enable it.';
    $('disable-prometheus').disabled=!prometheusInfo?.configured;
    $('generate-prometheus-token').textContent=prometheusInfo?.configured?'Rotate scrape token':'Generate scrape token';
  }
  async function generatePrometheus(){
    $('prometheus-error').textContent='';$('generate-prometheus-token').disabled=true;$('prometheus-token').value='';$('prometheus-token-result').hidden=true;
    try {const result=await api('integrations/prometheus',{method:'POST'});$('prometheus-token').value=result.token;$('prometheus-token-result').hidden=false;await loadManagement();toast('Scrape token generated. Copy it now.');}
    catch(error){$('prometheus-error').textContent=error.message;}finally{$('generate-prometheus-token').disabled=false;}
  }
  $('generate-prometheus-token').addEventListener('click',()=>prometheusInfo?.configured?confirm('Rotate scrape token?','The current token will stop working immediately. Update your Prometheus configuration with the new token.','Rotate token',generatePrometheus):generatePrometheus());
  $('disable-prometheus').addEventListener('click',()=>confirm('Disable Prometheus scraping?','The current scrape token will be revoked.','Disable scraping',async()=>{await api('integrations/prometheus',{method:'DELETE'});$('prometheus-token').value='';$('prometheus-token-result').hidden=true;await loadManagement();}));
  $('dismiss-prometheus-token').addEventListener('click',()=>{$('prometheus-token').value='';$('prometheus-token-result').hidden=true;});
  $('test-webhook').addEventListener('click',async()=>{try{await api('alerts/test',{method:'POST'});toast('Test notification queued.');await loadManagement();}catch(error){toast(error.message);}});
  $('alerts-list').addEventListener('click',async event=>{const button=event.target.closest('[data-ack-alert]');if(!button)return;button.disabled=true;try{await api('alerts/'+encodeURIComponent(button.dataset.ackAlert)+'/ack',{method:'POST'});await loadManagement();}catch(error){toast(error.message);button.disabled=false;}});
  function editUser(user=null) {
    $('user-form').reset();$('user-id').value=user?.id || '';userVersion=user?.version || 0;
    $('user-title').textContent=user ? 'Edit account' : 'Add account';$('user-name').value=user?.username || '';
    $('user-role').value=user?.role || 'read_only';$('user-enabled').checked=user?.enabled ?? true;$('user-enabled').disabled=!user;
    $('user-password').required=!user;$('user-password-help').textContent=user ? 'Leave blank to keep the current password. Changes sign out all sessions.' : 'At least 12 characters.';
    $('user-error').textContent='';$('user-dialog').showModal();
  }
  $('add-user').addEventListener('click',()=>editUser());
  $('users-body').addEventListener('click',event=>{
    const edit=event.target.closest('[data-edit-user]'),remove=event.target.closest('[data-delete-user]');
    if(edit)editUser(users.find(user=>user.id===edit.dataset.editUser));
    if(remove){const user=users.find(user=>user.id===remove.dataset.deleteUser);confirm('Remove account?',`Remove ${user.username} and sign out all its sessions?`,'Remove account',async()=>{await api('users/'+encodeURIComponent(user.id),{method:'DELETE'});await loadManagement();toast('Account removed.');});}
  });
  $('user-form').addEventListener('submit',async event=>{
    event.preventDefault();const button=event.submitter;button.disabled=true;$('user-error').textContent='';
    const id=$('user-id').value,body={username:$('user-name').value,role:$('user-role').value,enabled:$('user-enabled').checked,version:userVersion,password:$('user-password').value};
    try{await api('users'+(id ? '/'+encodeURIComponent(id) : ''),{method:id ? 'PUT' : 'POST',body:JSON.stringify(body)});$('user-dialog').close();$('user-form').reset();await loadManagement();toast('Account saved.');}catch(error){$('user-error').textContent=error.message;}finally{button.disabled=false;}
  });
  $('sessions-body').addEventListener('click',event=>{const button=event.target.closest('[data-end-session]');if(!button)return;confirm('Revoke session?','This session will need to sign in again.','Revoke session',async()=>{const result=await api('sessions/'+encodeURIComponent(button.dataset.endSession),{method:'DELETE'});if(result.sign_in_required)showLogin();else await loadManagement();});});
  document.querySelectorAll('[data-close]').forEach(button=>button.addEventListener('click',()=>$(button.dataset.close).close()));
  function openPassword() {$('password-form').reset();$('password-error').textContent='';$('password-dialog').showModal();}
  $('change-password').addEventListener('click',openPassword);$('settings-change-password').addEventListener('click',openPassword);
  $('password-form').addEventListener('submit',async event=>{event.preventDefault();const button=event.submitter;button.disabled=true;try{await api('password',{method:'POST',body:JSON.stringify({current_password:$('current-password').value,new_password:$('new-password').value})});$('password-form').reset();showLogin();toast('Password changed. Sign in again.');}catch(error){$('password-error').textContent=error.message;}finally{button.disabled=false;}});

  function scheduleFields(){
    const on=$('backup-schedule-offsite').checked,kind=$('backup-schedule-auth').value;
    $('backup-schedule-offsite-fields').hidden=!on;$('backup-schedule-offsite-fields').disabled=!on;
    $('backup-schedule-url').required=on&&!scheduleInfo?.offsite_configured;
    $('backup-schedule-user-field').hidden=kind!=='basic';$('backup-schedule-user').required=on&&kind==='basic';
    $('backup-schedule-secret-field').hidden=!['basic','bearer'].includes(kind);$('backup-schedule-secret').required=on&&['basic','bearer'].includes(kind);$('backup-schedule-secret-label').textContent=kind==='bearer'?'Bearer token':'Password / app password';
    const forget=$('backup-schedule-forget').checked;$('backup-schedule-passphrase').disabled=forget;$('backup-schedule-confirm').disabled=forget;
    $('backup-schedule-passphrase').required=$('backup-schedule-enabled').checked&&!scheduleInfo?.passphrase_configured&&!forget;
    $('backup-schedule-confirm').required=Boolean($('backup-schedule-passphrase').value)&&!forget;
  }
  function renderSchedule(){
    if(!scheduleInfo)return;const {settings,runtime}=scheduleInfo;
    $('backup-schedule-badge').textContent=scheduleInfo.paused_for_restore?'Paused for restore':scheduleInfo.running?'Running':runtime.requested?'Queued':settings.enabled?(!scheduleInfo.passphrase_configured?'Needs passphrase':'Enabled'):'Disabled';
    $('backup-schedule-status').textContent=`Last complete backup: ${dateTime(runtime.last_success)} · Last local copy: ${dateTime(runtime.last_local_at)} · Next run: ${settings.enabled||runtime.requested?dateTime(runtime.next_run_at):'Not scheduled'}${runtime.last_offsite_success?' · Last offsite copy: '+dateTime(runtime.last_offsite_success):''}`;
    $('backup-schedule-error-summary').textContent=runtime.last_error||'';
    $('backup-schedule-passphrase-status').textContent=scheduleInfo.passphrase_configured?'A passphrase is saved. Enter a new one only to replace it.':'No automation passphrase is saved. Set one before enabling backups.';
    $('backup-schedule-destination-status').textContent=scheduleInfo.offsite_configured?`Destination saved for ${scheduleInfo.offsite_origin}. Leave the folder URL blank to keep it.`:'No offsite destination saved.';
    const form=$('backup-schedule-form');
    if(!form.contains(document.activeElement)&&!form.dataset.dirty&&!scheduleChanging){
      $('backup-schedule-enabled').checked=settings.enabled;$('backup-schedule-hours').value=settings.interval_hours;$('backup-schedule-retain').value=settings.retain_count;$('backup-schedule-notify').checked=settings.notify_failures;
      $('backup-schedule-offsite').checked=scheduleInfo.offsite_configured;$('backup-schedule-auth').value=scheduleInfo.offsite_configured?'keep':'none';form.dataset.version=settings.version;scheduleFields();
    }
    $('backup-schedule-files').innerHTML=scheduleInfo.files.map(file=>`<tr><td>${escapeHtml(dateTime(file.created_at))}<small class="mono">${escapeHtml(file.name)}</small></td><td>${(file.bytes/1048576).toFixed(2)} MiB</td><td><div class="row-actions"><button class="button secondary" data-scheduled-download="${escapeHtml(file.name)}">Download</button><button class="icon-button delete" data-scheduled-remove="${escapeHtml(file.name)}" ${scheduleInfo.running||scheduleInfo.paused_for_restore?'disabled':''} aria-label="Remove backup from ${escapeHtml(dateTime(file.created_at))}">${icon('trash')}</button></div></td></tr>`).join('');
    $('backup-schedule-empty').hidden=scheduleInfo.files.length>0;
  }
  $('backup-schedule-form').addEventListener('invalid',event=>{let panel=event.target.closest('details');while(panel){panel.open=true;panel=panel.parentElement.closest('details');}},true);
  $('backup-schedule-form').addEventListener('input',()=>{$('backup-schedule-form').dataset.dirty='1';scheduleFields();});
  $('backup-schedule-offsite').addEventListener('change',scheduleFields);$('backup-schedule-auth').addEventListener('change',scheduleFields);
  $('backup-schedule-forget').addEventListener('change',()=>{if($('backup-schedule-forget').checked){$('backup-schedule-enabled').checked=false;$('backup-schedule-passphrase').value='';$('backup-schedule-confirm').value='';}scheduleFields();});
  $('backup-schedule-form').addEventListener('submit',async event=>{
    event.preventDefault();const request=++scheduleRequest;scheduleChanging=true;applyPermissions();$('backup-schedule-error').textContent='';
    try{
      const passphrase=$('backup-schedule-passphrase').value;if(passphrase!==$('backup-schedule-confirm').value)rejectField('backup-schedule-confirm','backup-schedule-error','The backup passphrases do not match.');
      const on=$('backup-schedule-offsite').checked,kind=$('backup-schedule-auth').value;
      const auth=on&&kind!=='keep'?{kind,username:kind==='basic'?$('backup-schedule-user').value:'',secret:['basic','bearer'].includes(kind)?$('backup-schedule-secret').value:''}:null;
      await api('backups/schedule',{method:'PUT',body:JSON.stringify({enabled:$('backup-schedule-enabled').checked,interval_hours:Number($('backup-schedule-hours').value),retain_count:Number($('backup-schedule-retain').value),notify_failures:$('backup-schedule-notify').checked,version:Number($('backup-schedule-form').dataset.version),passphrase:passphrase||null,remove_passphrase:$('backup-schedule-forget').checked,offsite_url:on?($('backup-schedule-url').value.trim()||null):'',auth})});
      if(request!==scheduleRequest||!authenticated)return;
      $('backup-schedule-form').reset();delete $('backup-schedule-form').dataset.dirty;event.submitter.blur();scheduleChanging=false;await loadManagement();toast('Backup schedule saved.');
    }catch(error){if(request===scheduleRequest)$('backup-schedule-error').textContent=error.message;}
    finally{$('backup-schedule-passphrase').value='';$('backup-schedule-confirm').value='';$('backup-schedule-secret').value='';scheduleChanging=false;scheduleFields();applyPermissions();}
  });
  $('backup-schedule-run').addEventListener('click',async()=>{
    scheduleChanging=true;applyPermissions();$('backup-schedule-error').textContent='';
    try{await api('backups/schedule/run',{method:'POST'});await loadManagement();toast('Encrypted backup queued.');}catch(error){$('backup-schedule-error').textContent=error.message;}finally{scheduleChanging=false;applyPermissions();}
  });
  $('backup-schedule-files').addEventListener('click',async event=>{
    const download=event.target.closest('[data-scheduled-download]'),remove=event.target.closest('[data-scheduled-remove]');
    if(remove){const name=remove.dataset.scheduledRemove;confirm('Remove local backup?','This permanently removes the selected local encrypted file. Offsite copies stay with your storage provider.','Remove backup',async()=>{await api('backups/scheduled/'+encodeURIComponent(name),{method:'DELETE'});await loadManagement();},name);return;}
    if(download){const request=scheduleRequest;download.disabled=true;try{const response=await fetch('/api/backups/scheduled/'+encodeURIComponent(download.dataset.scheduledDownload),{credentials:'same-origin'});if(!response.ok){const body=await response.json().catch(()=>({}));throw new Error(body.error||'Could not download backup.');}const blob=await response.blob();if(!authenticated||request!==scheduleRequest)return;const url=URL.createObjectURL(blob),link=document.createElement('a');link.href=url;link.download=download.dataset.scheduledDownload;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}catch(error){toast(error.message);}finally{download.disabled=false;}}
  });

  function renderDiagnosticsHosts(){
    const selected=$('diagnostics-route').value;
    $('diagnostics-route').innerHTML='<option value="">Enter hostname and path</option>'+config.routes.map(route=>`<option value="${escapeHtml(route.id)}">${escapeHtml(route.name)} · ${escapeHtml(route.host+route.path_prefix)}${route.enabled?'':' · paused'}</option>`).join('');
    $('diagnostics-route').value=config.routes.some(r=>r.id===selected)?selected:'';
  }
  function fillDiagnosticsHost(route){
    $('diagnostics-host').value=route.host==='*'?'example.com':route.host;$('diagnostics-path').value=route.path_prefix;$('diagnostics-error').textContent='';
  }
  $('diagnostics-route').addEventListener('change',()=>{const route=config.routes.find(r=>r.id===$('diagnostics-route').value);if(route)fillDiagnosticsHost(route);});
  function renderDiagnostics(report){
    const route=report.route;
    const notices=[...(report.notes||[]),...(report.configuration_changed?['Configuration changed while this report was running. Run another check for the latest routing.']:[])];
    const steps=backend=>[['DNS',backend.dns],['TCP',backend.tcp],['TLS',backend.tls],['HTTP',backend.http]].map(([label,step])=>`<div class="diagnostic-step ${escapeHtml(step.status)}"><span class="diagnostic-step-mark" aria-hidden="true">${step.status==='passed'?'✓':step.status==='failed'?'!':'—'}</span><div><strong>${label}</strong><p>${escapeHtml(step.detail)}</p>${label==='DNS'&&backend.addresses.length?`<small class="mono">${backend.addresses.map(escapeHtml).join(' · ')}</small>`:''}</div><span class="diagnostic-timing">${step.elapsed_ms==null?'—':Number(step.elapsed_ms).toFixed(1)+' ms'}</span></div>`).join('');
    const publicTls=report.public_certificate;
    $('diagnostics-results').innerHTML=`<article class="card diagnostics-summary"><div class="card-heading"><div><h2>${route?'Route matched':'No active route matched'}</h2><p>Revision ${Number(report.configuration_version)} · ${escapeHtml(dateTime(report.checked_at))}</p></div><span class="status-badge ${route?'':'paused'}">${route?'Matched':'Unmatched'}</span></div><div class="diagnostics-summary-content"><div class="diagnostic-flow"><div><small>VISITOR REQUEST</small><strong class="mono">${escapeHtml(report.host)}</strong><span class="mono">${escapeHtml(report.path)}</span></div><span class="diagnostic-flow-arrow" aria-hidden="true">→</span><div><small>PROXY ROUTE</small><strong>${escapeHtml(route?.name||'No match')}</strong><span>${route?escapeHtml(route.host+route.path_prefix):'EmberGate returns 404 for unmatched requests.'}</span></div><span class="diagnostic-flow-arrow" aria-hidden="true">→</span><div><small>UPSTREAM PATH</small><strong class="mono">${escapeHtml(route?.upstream_path||'—')}</strong><span>${route?route.upstreams.length+' configured '+(route.upstreams.length===1?'backend':'backends'):'No backend contacted'}</span></div></div><p class="diagnostic-certificate"><strong>Visitor TLS:</strong> ${!report.https_listener_configured?'HTTPS listener is disabled.':publicTls?`${escapeHtml(publicTls.name)} · ${Number(publicTls.days_remaining)} days remaining · expires ${escapeHtml(publicTls.expires_at)}`:'No currently valid certificate matches this hostname.'}</p>${route?`<p class="diagnostic-certificate"><strong>Host header:</strong> ${route.preserve_host?'Preserves the visitor hostname and port.':'Uses each backend’s configured authority.'} <strong>Traffic timeouts:</strong> connect ${Number(route.reliability.connect_timeout_seconds)}s · read ${Number(route.reliability.read_timeout_seconds)}s · write ${Number(route.reliability.write_timeout_seconds)}s. Diagnostic limits are separate.</p>`:''}${report.paused_matches.length?`<p class="diagnostic-certificate"><strong>Paused matches excluded:</strong> ${report.paused_matches.map(r=>escapeHtml(r.name)).join(', ')}.</p>`:''}${notices.map(note=>`<p class="notice diagnostics-notice">${escapeHtml(note)}</p>`).join('')}</div></article>${report.probe&&route?`<div class="diagnostics-backend-heading"><h2>Backend checks</h2><p>${report.backends.length} of ${route.upstreams.length} checked · HEAD only · redirects are not followed</p></div>`:route?'<p class="notice diagnostics-notice">Routing preview only. Run backend checks to test DNS, TCP, TLS, and HTTP.</p>':''}${report.backends.map(backend=>{const failed=[backend.dns,backend.tcp,backend.tls,backend.http].some(s=>s.status==='failed');const warning=backend.http_status>=400;return `<article class="card diagnostic-backend"><div class="card-heading"><div><h2 class="mono">${escapeHtml(backend.origin)}</h2><p>${escapeHtml(backend.connected_address||'No connection established')} · ${Number(backend.total_ms).toFixed(1)} ms total${backend.draining?' · draining':''} · monitored: ${escapeHtml(backend.monitored_status)}</p></div><span class="status-badge ${failed?'unhealthy':warning?'degraded':''}">${failed?'Check failed':warning?'HTTP '+Number(backend.http_status):'Reachable'}</span></div><div class="diagnostic-steps">${steps(backend)}</div><div class="diagnostic-backend-footer"><p><strong>Sent Host:</strong> <span class="mono">${escapeHtml(backend.host_header)}</span></p>${backend.certificate?`<p><strong>Backend certificate:</strong> expires ${escapeHtml(backend.certificate.expires_at)} · ${Number(backend.certificate.days_remaining)} days remaining</p>`:''}${warning?`<p class="diagnostics-warning">The backend responded, but returned HTTP ${Number(backend.http_status)}. Check application routing or permissions; 405 can mean HEAD is not supported.</p>`:''}</div></article>`;}).join('')}`;
  }
  $('diagnostics-form').addEventListener('submit',async event=>{
    event.preventDefault();const request=++diagnosticsRequest;diagnosticsController?.abort();const controller=new AbortController();diagnosticsController=controller;
    const probe=event.submitter?.id==='diagnostics-run';$('diagnostics-preview').disabled=true;$('diagnostics-run').disabled=true;$('diagnostics-error').textContent='';$('diagnostics-progress').hidden=false;$('diagnostics-progress').textContent=probe?'Checking saved backends… This can take up to 30 seconds.':'Checking route matching…';
    try{const report=await api('diagnostics',{method:'POST',signal:controller.signal,body:JSON.stringify({host:$('diagnostics-host').value.trim(),path:$('diagnostics-path').value,probe})});if(request!==diagnosticsRequest||!authenticated)return;renderDiagnostics(report);}
    catch(error){if(request===diagnosticsRequest&&!controller.signal.aborted){if(error.mfaEnrollmentRequired)await enter();else $('diagnostics-error').textContent=error.message;}}
    finally{if(request===diagnosticsRequest){$('diagnostics-preview').disabled=!isAdmin();$('diagnostics-run').disabled=!isAdmin();$('diagnostics-progress').hidden=true;diagnosticsController=null;}}
  });

  function toggleClusterFields() {
    const follower=$('cluster-role').value==='follower';$('cluster-follower-fields').hidden=!follower;$('cluster-follower-fields').disabled=!follower;
    $('cluster-peer').required=follower;$('cluster-primary-id').required=follower;
    const replacing=follower&&(clusterInfo?.settings.role!=='follower'||$('cluster-primary-id').value.trim()!==clusterInfo?.settings.expected_primary_id);
    $('cluster-confirm-field').hidden=!replacing;$('cluster-confirm').required=replacing;
    $('cluster-rotate').disabled=$('cluster-role').value!=='primary'||clusterInfo?.settings.role!=='primary';
  }
  function renderCluster() {
    if(!clusterInfo)return;
    $('cluster-editor').disabled=false;
    $('cluster-instance-id').textContent=clusterInfo.instance_id;
    $('cluster-state').textContent=clusterInfo.settings.role==='follower'?(clusterInfo.ready?'Synchronized follower':'Waiting for synchronization'):clusterInfo.settings.role==='primary'?'Writable primary':'Standalone';
    $('cluster-last-sync').textContent=clusterInfo.last_success_at?dateTime(clusterInfo.last_success_at):'Not synchronized';
    $('cluster-sync-error').textContent=clusterInfo.last_error||'';$('cluster-sync-error').hidden=!clusterInfo.last_error;
    $('cluster-received').textContent=clusterInfo.received?'Generation '+clusterInfo.received.generation+' · '+clusterInfo.received.source:'No received snapshot';
    $('cluster-sync-now').disabled=clusterInfo.settings.role!=='follower';
    $('cluster-token').placeholder=clusterInfo.token_configured?'Saved token configured; leave blank to keep it':'Paste the primary’s shared token';
    if(!$('cluster-form').dataset.dirty&&!$('cluster-form').contains(document.activeElement)) {
      const settings=clusterInfo.settings;$('cluster-role').value=settings.role;$('cluster-peer').value=settings.peer_url||'';$('cluster-primary-id').value=settings.expected_primary_id||'';$('cluster-interval').value=settings.interval_seconds;$('cluster-stale').value=settings.stale_after_seconds;$('cluster-form').dataset.version=settings.version;toggleClusterFields();
    }
    $('cluster-code-field').hidden=!mfaInfo?.enabled;$('cluster-code').required=Boolean(mfaInfo?.enabled);
    $('cluster-peers').innerHTML=(clusterInfo.followers||[]).length?clusterInfo.followers.map(peer=>`<div class="cluster-peer"><span class="mono">${escapeHtml(peer.instance_id)}</span><small>Last seen ${escapeHtml(dateTime(peer.last_seen))}</small></div>`).join(''):'<p class="settings-note">No follower heartbeats recorded in this process.</p>';
  }
  $('cluster-form').addEventListener('input',()=>{$('cluster-form').dataset.dirty='true';toggleClusterFields();});
  $('cluster-role').addEventListener('change',toggleClusterFields);
  $('cluster-form').addEventListener('submit',async event=>{
    event.preventDefault();const rotate=event.submitter.id==='cluster-rotate';event.submitter.disabled=true;$('cluster-error').textContent='';
    try {
      const proof={current_password:$('cluster-password').value,code:$('cluster-code').value};
      if(rotate){const result=await api('cluster/token',{method:'POST',body:JSON.stringify(proof)});$('cluster-token-value').value=result.token;$('cluster-token-result').hidden=false;toast('Token rotated. Update each follower with the new token.');}
      else {
        const settings={role:$('cluster-role').value,peer_url:$('cluster-peer').value.trim()||null,expected_primary_id:$('cluster-primary-id').value.trim()||null,interval_seconds:Number($('cluster-interval').value),stale_after_seconds:Number($('cluster-stale').value),version:Number($('cluster-form').dataset.version)};
        await api('cluster',{method:'PUT',body:JSON.stringify({...proof,settings,confirm_replace:$('cluster-confirm').checked,token:$('cluster-token').value.trim()||null})});delete $('cluster-form').dataset.dirty;$('cluster-form').dataset.version=String(settings.version+1);$('cluster-token').value='';$('cluster-token-value').value='';$('cluster-token-result').hidden=true;$('cluster-confirm').checked=false;toast('Instance settings saved.');
      }
      await loadManagement();await refresh();
    }catch(error){$('cluster-error').textContent=error.message;}
    finally{$('cluster-password').value='';$('cluster-code').value='';event.submitter.disabled=false;toggleClusterFields();}
  });
  $('cluster-sync-now').addEventListener('click',async()=>{try{await api('cluster/sync',{method:'POST',body:'{}'});toast('Synchronization queued.');await loadManagement();}catch(error){toast(error.message);}});
  $('cluster-copy-token').addEventListener('click',async()=>{try{await navigator.clipboard.writeText($('cluster-token-value').value);toast('Synchronization token copied.');}catch{toast('Select the token and copy it manually.');}});
  function decodeCredential(value) {
    const binary=atob(value.replace(/-/g,'+').replace(/_/g,'/'));return Uint8Array.from(binary,c=>c.charCodeAt(0)).buffer;
  }
  function encodeCredential(value) {
    return btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  }
  function credentialOptions(options,registration) {
    const key=structuredClone(options.publicKey);key.challenge=decodeCredential(key.challenge);
    if(registration){key.user.id=decodeCredential(key.user.id);for(const item of key.excludeCredentials||[])item.id=decodeCredential(item.id);}
    else for(const item of key.allowCredentials||[])item.id=decodeCredential(item.id);
    return {publicKey:key,signal:passkeyController.signal};
  }
  function credentialJson(credential) {
    if(credential.toJSON)return credential.toJSON();
    const response=credential.response,result={id:credential.id,rawId:encodeCredential(credential.rawId),type:credential.type,clientExtensionResults:credential.getClientExtensionResults(),response:{clientDataJSON:encodeCredential(response.clientDataJSON)}};
    if(response.attestationObject){result.response.attestationObject=encodeCredential(response.attestationObject);result.response.transports=response.getTransports?.()||[];}
    else {result.response.authenticatorData=encodeCredential(response.authenticatorData);result.response.signature=encodeCredential(response.signature);result.response.userHandle=response.userHandle?encodeCredential(response.userHandle):null;}
    return result;
  }
  function renderPasskeys() {
    if(!passkeysInfo)return;
    const keys=passkeysInfo.keys||[],supported=Boolean(window.PublicKeyCredential&&navigator.credentials&&window.isSecureContext);
    $('passkeys-status').textContent=passkeysInfo.origin?`${keys.length} registered ${keys.length===1?'passkey':'passkeys'} · ${passkeysInfo.origin}`:'An administrator must configure the dashboard origin before passkeys can be registered.';
    $('passkeys-list').innerHTML=keys.map(key=>`<div class="passkey-item"><div><strong>${escapeHtml(key.name)}</strong><small>Added ${escapeHtml(dateTime(key.created_at))} · ${key.last_used?'Last used '+escapeHtml(dateTime(key.last_used)):'Not used yet'}</small></div><button type="button" class="button secondary" data-remove-passkey="${escapeHtml(key.id)}">Remove</button></div>`).join('');
    $('passkey-configure').hidden=!isAdmin();$('passkey-add').disabled=!supported||!passkeysInfo.origin||passkeysInfo.origin!==location.origin||keys.length>=16;
    $('passkey-add').title=!supported?'Use a WebAuthn-compatible browser over HTTPS or localhost.':passkeysInfo.origin!==location.origin?'Open the configured dashboard origin before adding a passkey.':'';
  }
  function openPasskey(mode,id=null) {
    passkeyRequest++;passkeyController?.abort();passkeyMode=mode;passkeyRemoveId=id;$('passkey-form').reset();$('passkey-submit').disabled=false;$('passkey-error').textContent='';
    $('passkey-title').textContent={register:'Add a passkey',origin:'Configure dashboard origin',remove:'Remove this passkey?'}[mode];
    $('passkey-description').textContent=mode==='register'?'Confirm your password, then follow your browser’s device prompt.':mode==='origin'?'Set the stable address you use to access EmberGate. Remove all registered passkeys before changing it.':'Removing a passkey signs out your existing sessions. You can sign in with another passkey or your password.';
    $('passkey-origin-field').hidden=mode!=='origin';$('passkey-origin').required=mode==='origin';$('passkey-origin').value=passkeysInfo?.origin||(location.protocol==='http:'&&['127.0.0.1','[::1]'].includes(location.hostname)?'http://localhost'+(location.port?':'+location.port:''):location.origin);
    $('passkey-name-field').hidden=mode!=='register';$('passkey-name').required=mode==='register';$('passkey-code-field').hidden=!mfaInfo?.enabled;$('passkey-code').required=Boolean(mfaInfo?.enabled);$('passkey-submit').textContent=mode==='remove'?'Remove passkey':mode==='origin'?'Save origin':'Register device';$('passkey-dialog').showModal();
  }
  $('passkey-add').addEventListener('click',()=>openPasskey('register'));$('passkey-configure').addEventListener('click',()=>openPasskey('origin'));
  $('passkeys-list').addEventListener('click',event=>{const button=event.target.closest('[data-remove-passkey]');if(button)openPasskey('remove',button.dataset.removePasskey);});
  document.querySelectorAll('.close-passkey').forEach(button=>button.addEventListener('click',()=>$('passkey-dialog').close()));
  $('passkey-dialog').addEventListener('close',()=>{passkeyRequest++;passkeyController?.abort();passkeyController=null;$('passkey-form').reset();});
  $('passkey-form').addEventListener('submit',async event=>{
    event.preventDefault();const request=++passkeyRequest;$('passkey-submit').disabled=true;$('passkey-error').textContent='';
    try {
      const proof={current_password:$('passkey-password').value,code:$('passkey-code').value};
      if(passkeyMode==='origin')await api('passkeys/config',{method:'PUT',body:JSON.stringify({...proof,origin:$('passkey-origin').value.trim()})});
      else if(passkeyMode==='remove')await api('passkeys/'+encodeURIComponent(passkeyRemoveId),{method:'DELETE',body:JSON.stringify(proof)});
      else {
        const start=await api('passkeys/register/start',{method:'POST',body:JSON.stringify({...proof,name:$('passkey-name').value.trim()})});
        $('passkey-password').value='';$('passkey-code').value='';if(request!==passkeyRequest||!$('passkey-dialog').open)return;
        passkeyController=new AbortController();const credential=await navigator.credentials.create(credentialOptions(start.options,true));
        if(request!==passkeyRequest||!$('passkey-dialog').open||!credential)return;
        await api('passkeys/register/finish',{method:'POST',body:JSON.stringify({id:start.id,credential:credentialJson(credential)})});
      }
      if(request!==passkeyRequest)return;const removed=passkeyMode==='remove';$('passkey-dialog').close();
      if(removed){showLogin();toast('Passkey removed. Sign in again.');}else{await loadManagement();toast(passkeyMode==='origin'?'Passkey origin saved.':'Passkey registered.');}
    }catch(error){if(request===passkeyRequest&&$('passkey-dialog').open)$('passkey-error').textContent=error.name==='NotAllowedError'?'The device prompt was cancelled or timed out. Try again when ready.':error.message;}
    finally{if(request===passkeyRequest||!$('passkey-dialog').open){$('passkey-password').value='';$('passkey-code').value='';$('passkey-submit').disabled=false;}}
  });
  const passkeysSupported=Boolean(window.PublicKeyCredential&&navigator.credentials&&window.isSecureContext);
  $('login-passkey').disabled=!passkeysSupported;
  $('login-passkey').addEventListener('click',async()=>{
    if(!$('login-username').value.trim()){$('login-error').textContent='Enter your username to use a passkey.';return;}
    const request=++passkeyRequest;$('login-passkey').disabled=true;$('login-error').textContent='';
    try {
      const start=await api('passkeys/login/start',{method:'POST',body:JSON.stringify({username:$('login-username').value.trim()})});if(request!==passkeyRequest)return;
      passkeyController=new AbortController();const credential=await navigator.credentials.get(credentialOptions(start.options,false));if(request!==passkeyRequest||!credential)return;
      await api('passkeys/login/finish',{method:'POST',body:JSON.stringify({id:start.id,credential:credentialJson(credential)})});if(request!==passkeyRequest)return;
      $('password').value='';$('login-mfa-code').value='';$('login-mfa-field').hidden=true;await enter();
    }catch(error){if(request===passkeyRequest)$('login-error').textContent=error.name==='NotAllowedError'?'No passkey was used. Try again or sign in with your password.':error.message;}
    finally{$('login-passkey').disabled=false;passkeyController=null;}
  });
  function renderMfa(){
    const on=mfaInfo.enabled;
    $('mfa-status').textContent=on?`Enabled · ${mfaInfo.recovery_codes_remaining} recovery codes remaining.`:'Not enabled. Add an authenticator to protect your sign-in.';
    $('mfa-enable').hidden=on;$('mfa-disable').hidden=!on;$('mfa-recovery').hidden=!on;
    $('mfa-disable').disabled=isAdmin()&&mfaInfo.require_administrators;
    $('mfa-policy-controls').hidden=!isAdmin();$('mfa-policy').disabled=!on;
    $('mfa-policy-status').textContent=mfaInfo.require_administrators?'All administrators must use two-factor authentication.':'Administrator enforcement is optional. Enable your own authenticator before changing this policy.';
  }
  function openMfa(mode){
    mfaRequest++;mfaMode=mode;mfaStep='proof';$('mfa-form').reset();$('mfa-error').textContent='';$('mfa-secret').value='';$('mfa-recovery-codes').textContent='';
    $('mfa-title').textContent={setup:'Set up two-factor authentication',disable:'Disable two-factor authentication',recovery:'Replace recovery codes',policy:'Administrator authentication policy'}[mode];
    $('mfa-description').textContent=mfaGate?'Your administrator must enroll before accessing EmberGate. Confirm your password to start.':mode==='setup'?'Confirm your password, then add EmberGate to your authenticator app.':'Confirm your password and an unused authentication or recovery code to make this change.';
    $('mfa-proof-fields').hidden=false;$('mfa-password').required=true;$('mfa-existing-code-field').hidden=mode==='setup';$('mfa-existing-code').required=mode!=='setup';
    $('mfa-policy-field').hidden=mode!=='policy';$('mfa-require-admins').checked=Boolean(mfaInfo?.require_administrators);
    $('mfa-enrollment-fields').hidden=true;$('mfa-confirm-code').required=false;$('mfa-recovery-result').hidden=true;$('mfa-saved-codes').required=false;
    $('mfa-submit').textContent=mode==='setup'?'Continue':mode==='disable'?'Disable':'Save';$('mfa-cancel').textContent=mfaGate?'Sign out':'Cancel';$('mfa-dialog').showModal();
  }
  function showRecoveryCodes(codes){
    $('mfa-title').textContent='Save your recovery codes';$('mfa-description').textContent='Your authenticator is enabled. Keep these codes available if you lose access to your device.';
    mfaStep='saved';$('mfa-proof-fields').hidden=true;$('mfa-password').required=false;$('mfa-password').value='';$('mfa-existing-code').required=false;$('mfa-existing-code').value='';
    $('mfa-enrollment-fields').hidden=true;$('mfa-secret').value='';$('mfa-confirm-code').required=false;$('mfa-confirm-code').value='';$('mfa-recovery-result').hidden=false;$('mfa-recovery-codes').textContent=codes.join('\n');$('mfa-saved-codes').required=true;$('mfa-submit').textContent='Done';
  }
  $('mfa-enable').addEventListener('click',()=>openMfa('setup'));$('mfa-disable').addEventListener('click',()=>openMfa('disable'));$('mfa-recovery').addEventListener('click',()=>openMfa('recovery'));$('mfa-policy').addEventListener('click',()=>openMfa('policy'));
  async function closeMfa(){if(mfaStep==='saved'){$('mfa-form').requestSubmit($('mfa-submit'));return;}if(mfaGate && mfaStep!=='saved'){try{await api('logout',{method:'POST'});}catch{}showLogin();}else $('mfa-dialog').close();}
  document.querySelectorAll('.close-mfa').forEach(button=>button.addEventListener('click',closeMfa));
  $('mfa-dialog').addEventListener('cancel',event=>{event.preventDefault();if(mfaStep==='saved')toast('Save your recovery codes before closing.');else closeMfa();});
  $('mfa-dialog').addEventListener('close',()=>{mfaRequest++;$('mfa-form').reset();$('mfa-secret').value='';$('mfa-recovery-codes').textContent='';});
  $('mfa-copy-secret').addEventListener('click',async()=>{try{await navigator.clipboard.writeText($('mfa-secret').value);toast('Setup key copied.');}catch{toast('Select the setup key and copy it manually.');}});
  $('mfa-download-codes').addEventListener('click',()=>{const url=URL.createObjectURL(new Blob([`EmberGate recovery codes for ${currentUser.username}\nEach code works once. Store securely.\n\n${$('mfa-recovery-codes').textContent}\n`],{type:'text/plain'}));const link=document.createElement('a');link.href=url;link.download='embergate-recovery-codes.txt';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});
  $('mfa-form').addEventListener('submit',async event=>{
    event.preventDefault();const request=++mfaRequest;$('mfa-submit').disabled=true;$('mfa-error').textContent='';
    try{
      if(mfaStep==='saved'){const gated=mfaGate;$('mfa-dialog').close();if(gated)await enter();else await loadManagement();return;}
      if(mfaStep==='confirm'){
        const result=await api('mfa/confirm',{method:'POST',body:JSON.stringify({code:$('mfa-confirm-code').value})});
        if(request!==mfaRequest || !$('mfa-dialog').open)return;showRecoveryCodes(result.recovery_codes);
      }else{
        const proof={current_password:$('mfa-password').value,code:$('mfa-existing-code').value};
        if(mfaMode==='setup'){
          const result=await api('mfa/setup',{method:'POST',body:JSON.stringify(proof)});if(request!==mfaRequest || !$('mfa-dialog').open)return;
          mfaStep='confirm';$('mfa-secret').value=result.secret;$('mfa-proof-fields').hidden=true;$('mfa-password').required=false;$('mfa-password').value='';$('mfa-enrollment-fields').hidden=false;$('mfa-confirm-code').required=true;$('mfa-submit').textContent='Enable & get recovery codes';$('mfa-confirm-code').focus();
        }else{
          const result=await api(mfaMode==='disable'?'mfa':mfaMode==='policy'?'mfa/policy':'mfa/recovery',{method:mfaMode==='disable'?'DELETE':mfaMode==='policy'?'PUT':'POST',body:JSON.stringify(mfaMode==='policy'?{...proof,require_administrators:$('mfa-require-admins').checked}:proof)});
          if(request!==mfaRequest || !$('mfa-dialog').open)return;
          if(result.recovery_codes)showRecoveryCodes(result.recovery_codes);else{$('mfa-dialog').close();await loadManagement();toast('Authentication settings saved.');}
        }
      }
    }catch(error){if(request===mfaRequest)$('mfa-error').textContent=error.message;}finally{$('mfa-password').value='';$('mfa-existing-code').value='';$('mfa-submit').disabled=false;}
  });

  async function loadSetup() {
    const status=await api('setup');
    if(authenticated) return;
    $('setup-form').hidden=!status.setup_required;$('login-form').hidden=status.setup_required;
  }
  $('setup-form').addEventListener('submit',async event=>{
    event.preventDefault();const button=event.submitter;button.disabled=true;$('setup-error').textContent='';
    try {
      const password=$('setup-password').value;
      if(password!==$('setup-confirm').value)rejectField('setup-confirm','setup-error','Passwords do not match.');
      await api('setup',{method:'POST',body:JSON.stringify({setup_code:$('setup-code').value,password})});
      $('setup-form').reset();$('setup-form').hidden=true;$('login-form').hidden=false;$('login-username').value='admin';
      await api('login',{method:'POST',body:JSON.stringify({username:'admin',password})});await enter();toast('EmberGate is ready.');
    }catch(error){$('setup-error').textContent=error.message;if(error.status===409){await loadSetup();$('login-error').textContent='Setup is complete. Sign in with your administrator password.';}}
    finally{button.disabled=false;}
  });
  function renderCredentials() {
    const cf=credentialInfo.cloudflare;
    const cs=credentialInfo.crowdsec||{};
    $('crowdsec-state').textContent=!cs.configured?'Not connected':cs.connected?'Connected':'Degraded';
    $('crowdsec-status').textContent=!cs.configured?'CrowdSec is not connected.':cs.connected?`${number(cs.decisions||0)} active decisions · last sync ${dateTime(cs.last_sync)}.`:`Connection issue: ${cs.error||'waiting for the first successful sync'}. ${number(cs.decisions||0)} cached decisions remain active.`;
    $('crowdsec-remove').disabled=!cs.configured||!isAdmin();
    $('crowdsec-form').querySelectorAll('input,button[type="submit"]').forEach(el=>el.disabled=!isAdmin());
    $('cloudflare-token-status').textContent=cf.source==='environment' ? 'An environment variable or token file overrides this credential. Remove it and restart to use web settings.' : cf.configured ? 'A saved token is configured. Paste a new token to replace it.' : 'No token configured. Add one to enable Cloudflare DNS-01 certificates.';
    $('remove-cloudflare-token').disabled=!cf.editable || !cf.configured || !isAdmin();
    $('settings-password-status').textContent=passwordEditable ? 'Your password is stored as an Argon2 hash. You can change it here.' : 'Your administrator password is overridden by GATEWAY_ADMIN_PASSWORD. Remove that variable and restart to manage the saved password here.';
    applyPermissions();
  }
  $('cloudflare-token-form').addEventListener('submit',async event=>{
    event.preventDefault();const button=event.submitter;button.disabled=true;$('cloudflare-token-error').textContent='';
    try{await api('credentials/cloudflare',{method:'PUT',body:JSON.stringify({token:$('cloudflare-token').value})});$('cloudflare-token-form').reset();await loadManagement();toast('Cloudflare token saved. Certificate automation can use it now.');document.dispatchEvent(new Event('visibilitychange'));}
    catch(error){$('cloudflare-token-error').textContent=error.message;}finally{button.disabled=false;}
  });
  $('remove-cloudflare-token').addEventListener('click',()=>confirm('Remove Cloudflare token?','Automatic certificate issuance and renewal will pause until a token is configured again.','Remove token',async()=>{await api('credentials/cloudflare',{method:'DELETE'});$('cloudflare-token-form').reset();await loadManagement();toast('Cloudflare token removed.');document.dispatchEvent(new Event('visibilitychange'));}));
  $('crowdsec-form').addEventListener('submit',async event=>{event.preventDefault();const button=event.submitter;button.disabled=true;$('crowdsec-error').textContent='';try{await api('integrations/crowdsec',{method:'PUT',body:JSON.stringify({url:$('crowdsec-url').value.trim(),api_key:$('crowdsec-key').value})});$('crowdsec-form').reset();await loadManagement();toast('CrowdSec connection saved.');}catch(error){$('crowdsec-error').textContent=error.message;}finally{button.disabled=false;applyPermissions();}});
  $('crowdsec-remove').addEventListener('click',()=>confirm('Disconnect CrowdSec?','This clears the local decision cache and stops CrowdSec blocking.','Disconnect',async()=>{await api('integrations/crowdsec',{method:'DELETE'});$('crowdsec-form').reset();await loadManagement();toast('CrowdSec disconnected.');}));
  $('login-form').addEventListener('submit', async event => {
    event.preventDefault();passkeyRequest++;passkeyController?.abort();passkeyController=null; const button = event.submitter; button.disabled = true; $('login-error').textContent = '';
    try { await api('login', {method: 'POST', body: JSON.stringify({username:$('login-username').value,password: $('password').value,code:$('login-mfa-code').value})}); $('password').value = ''; $('login-mfa-code').value='';$('login-mfa-field').hidden=true;await enter(); }
    catch (error) { $('login-error').textContent = error.message; if(error.mfaRequired){$('login-mfa-field').hidden=false;$('login-mfa-code').focus();} }
    finally { button.disabled = false; }
  });
  $('logout').addEventListener('click', async () => {
    try { await api('logout', {method: 'POST'}); config = {version:0,routes:[]}; logs = []; showLogin(); }
    catch (error) { toast(error.message); }
  });
  // Complete the initial session check before accepting a sign-in attempt.
  const loginSubmit=$('login-form').querySelector('button[type=submit]');
  loginSubmit.disabled=true;$('login-passkey').disabled=true;$('login-form').setAttribute('aria-busy','true');
  loadSetup().then(()=>api('session')).then(enter).catch(error => { if (error.status !== 401) $('login-error').textContent = error.message; }).finally(()=>{
    loginSubmit.disabled=false;$('login-passkey').disabled=!passkeysSupported;$('login-form').setAttribute('aria-busy','false');
  });
  setInterval(() => { if (!document.hidden) refresh(); }, 5000);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh(); });
  navigateFromLocation({replace:true,load:false,focus:false});
}

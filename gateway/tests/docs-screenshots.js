// Regenerates the screenshots in docs/images from the real gateway binary.
// Seeds realistic example data through the management API, with local stand-ins
// for Docker, CrowdSec, and an identity provider. No network access needed.
// Run `cargo build` first; requires Node 22+ and a Chromium browser (BROWSER_BIN).
import {createServer, request as httpRequest} from 'node:http';
import {createServer as createTcpServer} from 'node:net';
import {mkdtempSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawn} from 'node:child_process';
import {setTimeout as delay} from 'node:timers/promises';

const output = new URL('../../docs/images/', import.meta.url);
const listen = server => new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
const freePort = async () => { const server = createTcpServer(); const port = await listen(server); server.close(); return port; };
const json = (response, data) => { response.setHeader('Content-Type', 'application/json'); response.end(JSON.stringify(data)); };

// Example applications behind the proxy.
const origin = createServer((request, response) => {
  response.statusCode = request.url.startsWith('/missing') ? 404 : 200;
  response.setHeader('Content-Type', 'text/html'); response.end('<p>ok</p>');
});
const originPort = await listen(origin);

// Docker Engine API: EmberGate only sends GET /v1.41/containers/json over HTTP/1.0.
const container = (id, name, image, status, ports, networks, labels = {}) => ({
  Id: id.repeat(16), Names: ['/' + name], Image: image, State: 'running', Status: status, Labels: labels,
  Ports: ports.map(([private_, public_]) => ({PrivatePort: private_, ...(public_ ? {PublicPort: public_, IP: '0.0.0.0'} : {}), Type: 'tcp'})),
  NetworkSettings: {Networks: Object.fromEntries(networks.map((network, i) => [network, {IPAddress: `172.20.0.${i + 10}`}]))},
});
const containers = [
  container('a', 'immich', 'ghcr.io/immich-app/immich-server:release', 'Up 3 days', [[2283, 2283]], ['proxy']),
  container('b', 'nextcloud', 'nextcloud:30-apache', 'Up 3 days', [[80, 8081]], ['proxy'], {'embergate.host': 'cloud.example.com'}),
  container('c', 'grafana', 'grafana/grafana:11.3.0', 'Up 26 hours', [[3000, 3000]], ['proxy', 'monitoring']),
  container('d', 'vaultwarden', 'vaultwarden/server:latest', 'Up 5 hours', [[80, 8082]], ['proxy'], {'embergate.host': 'vault.example.com'}),
  container('e', 'postgres', 'postgres:17', 'Up 3 days', [[5432]], ['internal']),
];
const docker = createTcpServer(socket => socket.once('data', () => {
  const body = JSON.stringify(containers);
  socket.end(`HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`);
}));
const dockerPort = await listen(docker);

// CrowdSec Local API decision stream.
const decision = (value, type, scenario) => ({scope: 'Ip', value, type, scenario, duration: '3h59m', origin: 'crowdsec'});
let crowdsecStarted = false;
const crowdsec = createServer((_request, response) => {
  const startup = !crowdsecStarted; crowdsecStarted = true;
  json(response, startup ? {new: [
    decision('203.0.113.24', 'ban', 'crowdsecurity/http-probing'), decision('198.51.100.7', 'ban', 'crowdsecurity/http-sensitive-files'),
    decision('192.0.2.81', 'ban', 'crowdsecurity/nginx-req-limit-exceeded'), decision('203.0.113.140', 'captcha', 'crowdsecurity/http-crawl-non_statics'),
  ], deleted: null} : {new: null, deleted: null});
});
const crowdsecPort = await listen(crowdsec);

// OpenID Connect discovery only: screenshots never complete a sign-in.
const provider = createServer((request, response) => {
  const issuer = `http://localhost:${providerPort}`;
  if (request.url === '/.well-known/openid-configuration') return json(response, {issuer, authorization_endpoint: issuer + '/authorize', token_endpoint: issuer + '/token', jwks_uri: issuer + '/jwks'});
  json(response, {keys: []});
});
const providerPort = await listen(provider);

const data = mkdtempSync(join(tmpdir(), 'embergate-docs-'));
const [admin, proxy] = [await freePort(), await freePort()];
const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('GATEWAY_')));
const gateway = spawn(new URL('../target/debug/embergate', import.meta.url).pathname, [], {stdio: 'ignore', env: {
  ...env, GATEWAY_ADMIN_PASSWORD: 'docs-screenshots-password', GATEWAY_DATA_DIR: data,
  GATEWAY_ADMIN_ADDR: `127.0.0.1:${admin}`, GATEWAY_PROXY_ADDR: `127.0.0.1:${proxy}`, DOCKER_HOST: `tcp://127.0.0.1:${dockerPort}`,
}});
let browser, profile;
try {
  const base = `http://localhost:${admin}`;
  for (let i = 0; ; i++) {
    try { if ((await fetch(base + '/api/setup')).ok) break; } catch {}
    if (i > 100 || gateway.exitCode !== null) throw new Error('EmberGate did not start; run cargo build first.');
    await delay(100);
  }
  const login = await fetch(base + '/api/login', {method: 'POST', headers: {'Content-Type': 'application/json', 'X-Gateway-Request': '1'}, body: JSON.stringify({username: 'admin', password: 'docs-screenshots-password'})});
  const cookie = login.headers.get('set-cookie').split(';')[0];
  const call = async (path, method = 'GET', body) => {
    const response = await fetch(base + '/api/' + path, {method, headers: {'Content-Type': 'application/json', 'X-Gateway-Request': '1', Cookie: cookie}, body: body && JSON.stringify(body)});
    if (!response.ok) throw new Error(`${method} ${path}: ${response.status} ${await response.text()}`);
    return response.status === 204 ? null : response.json();
  };

  await call('integrations/oidc', 'PUT', {name: 'Authentik', issuer: `http://localhost:${providerPort}`, client_id: 'embergate', client_secret: 'example-client-secret',
    scopes: ['openid', 'email', 'profile'], groups_claim: 'groups', dashboard_enabled: true, dashboard_origin: base, trust_provider_mfa: false});
  const upstream = `http://127.0.0.1:${originPort}`;
  const host = (name, hostname, extra = {}) => ({id: crypto.randomUUID(), name, host: hostname, path_prefix: '/', upstream, enabled: true, preserve_host: false, ...extra});
  const routes = [
    host('Photos', 'photos.example.com', {cache: {max_ttl_seconds: 3600, max_object_bytes: 4194304}}),
    host('Nextcloud', 'cloud.example.com', {compression: {}}),
    host('Grafana', 'grafana.example.com', {oidc: {allowed_emails: [], allowed_domains: ['example.com'], allowed_groups: ['monitoring'], session_hours: 12}}),
    host('Home Assistant', 'home.example.com'),
    host('Wiki', 'wiki.example.com', {enabled: false}),
  ];
  const config = await call('config');
  await call('config', 'PUT', {...config, routes, trusted_proxies: [{network: '127.0.0.1/32', header: 'x_forwarded_for'}]});
  await call('integrations/access-log', 'PUT', {enabled: true});
  await call('integrations/crowdsec', 'PUT', {url: `http://127.0.0.1:${crowdsecPort}`, api_key: 'example-bouncer-key'});
  await call('integrations/crowdsec/remediation', 'PUT', {ban_message: 'Your address was blocked after suspicious requests. Email admin@example.com if this is a mistake.', provider: 'turnstile', site_key: '0x4AAAAAAAexample', secret_key: '0x4AAAAAAAexample-secret'});
  for (const [name, scope, expires_in_days] of [['Uptime Kuma', 'read_only', 365], ['Backup script', 'full', 90], ['Deploy pipeline', 'full', 30]]) await call('tokens', 'POST', {name, scope, expires_in_days});

  // Traffic for the analytics and traffic views.
  const hosts = ['photos.example.com', 'cloud.example.com', 'home.example.com', 'grafana.example.com'];
  for (let i = 0; i < 160; i++) {
    const hostname = hosts[i % 4 === 3 ? 3 : i % 3], path = i % 17 === 0 ? '/missing' : ['/', '/api/assets', '/index.php/apps/files', '/api/states'][i % 4];
    // fetch() cannot set Host, so use node:http.
    await new Promise(resolve => httpRequest({host: '127.0.0.1', port: proxy, path, headers: {Host: hostname, Accept: 'text/html', 'X-Forwarded-For': `198.51.100.${10 + (i % 23)}`, 'User-Agent': 'Mozilla/5.0'}}, response => response.resume().on('end', resolve)).on('error', resolve).end());
  }
  for (let i = 0; i < 40; i++) if ((await call('integrations/crowdsec')).decisions >= 4) break; else await delay(250);
  // Traffic is recorded; show the addresses a Docker setup would use.
  const addresses = ['http://immich:2283', 'http://nextcloud:80', 'http://grafana:3000', 'http://192.168.1.20:8123', 'http://wiki:3000'];
  const saved = await call('config');
  await call('config', 'PUT', {...saved, routes: saved.routes.map((route, i) => ({...route, upstream: addresses[i]}))});

  profile = mkdtempSync(join(tmpdir(), 'embergate-docs-browser-'));
  const browserBin = process.env.BROWSER_BIN || '/usr/bin/vivaldi';
  const browserEnv = {...process.env}; delete browserEnv.DBUS_SESSION_BUS_ADDRESS;
  browser = spawn(browserBin, ['--password-store=basic', '--disable-vivaldi', '--headless=new', '--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage', '--no-first-run', '--no-default-browser-check', '--hide-scrollbars', '--remote-debugging-port=0', `--user-data-dir=${profile}`, 'about:blank'], {stdio: 'ignore', env: browserEnv});
  let debugPort;
  for (let i = 0; !debugPort; i++) {
    try { debugPort = readFileSync(join(profile, 'DevToolsActivePort'), 'utf8').split('\n')[0]; } catch {}
    if (i > 600) throw new Error(`Browser did not start. BROWSER_BIN=${browserBin}`);
    await delay(100);
  }
  const pages = await (await fetch(`http://127.0.0.1:${debugPort}/json/list`)).json();
  const socket = new WebSocket(pages.find(p => p.type === 'page').webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { socket.onopen = resolve; socket.onerror = reject; });
  let sequence = 0; const pending = new Map();
  socket.onmessage = event => { const message = JSON.parse(event.data); const done = pending.get(message.id); if (done) { pending.delete(message.id); message.error ? done.reject(new Error(message.error.message)) : done.resolve(message.result); } };
  const cdp = (method, params = {}) => new Promise((resolve, reject) => { const id = ++sequence; pending.set(id, {resolve, reject}); socket.send(JSON.stringify({id, method, params})); });
  const evaluate = async expression => {
    const result = await cdp('Runtime.evaluate', {expression, returnByValue: true, awaitPromise: true});
    if (result.exceptionDetails) throw new Error(`${expression}: ${result.exceptionDetails.exception?.description || result.exceptionDetails.text}`);
    return result.result.value;
  };
  const wait = async expression => { for (let i = 0; i < 100; i++) { if (await evaluate(expression)) return; await delay(100); } throw new Error(`Timed out: ${expression}`); };
  const settle = () => delay(400);

  await cdp('Page.enable');
  await cdp('Emulation.setDeviceMetricsOverride', {width: 1360, height: 860, deviceScaleFactor: 1, mobile: false});
  await cdp('Emulation.setEmulatedMedia', {features: [{name: 'prefers-color-scheme', value: 'light'}, {name: 'prefers-reduced-motion', value: 'reduce'}]});
  await cdp('Page.navigate', {url: base + '/'});
  await wait("document.readyState==='complete'");
  await evaluate(`fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json','X-Gateway-Request':'1'},body:JSON.stringify({username:'admin',password:'docs-screenshots-password'})}).then(r=>r.ok)`);
  await cdp('Page.reload');
  await wait("!document.getElementById('app').hidden");

  const shots = [];
  // Saves the page, or one element of it, as docs/images/<name>.png.
  const shoot = async (name, selector, prepare) => {
    await settle();
    if (prepare) await evaluate(prepare);
    const clip = selector ? await evaluate(`(()=>{const r=document.querySelector(${JSON.stringify(selector)}).getBoundingClientRect();return {x:r.x,y:r.y,width:Math.floor(r.width),height:Math.floor(r.height),scale:1};})()`) : undefined;
  const result = await cdp('Page.captureScreenshot', {format: 'png', captureBeyondViewport: true, ...(clip ? {clip} : {})});
    writeFileSync(new URL(name + '.png', output), Buffer.from(result.data, 'base64'));
    shots.push(name);
  };
  const view = async name => {
    await evaluate(`document.querySelector('[data-view=${name}]').click()`);
    await wait(`location.hash.startsWith('#/${name}')`);
  };
  const settings = async section => {
    await view('settings');
    await evaluate(`document.querySelector('[data-settings-link=${section}]').click()`);
    await wait(`!document.getElementById('settings-page-${section}').hidden`);
  };

  await view('overview'); await shoot('overview');
  await view('hosts'); await wait("document.querySelectorAll('[data-action=edit]').length===5"); await shoot('hosts', 'main');
  await evaluate("document.querySelector('[data-action=edit][data-id]').click()");
  await wait("document.getElementById('host-dialog').open"); await shoot('host-editor', '#host-dialog');
  await evaluate("document.getElementById('host-dialog').close()");
  const grafana = routes[2].id;
  await evaluate(`document.querySelector('[data-action=edit][data-id="${grafana}"]').click()`);
  await wait("document.getElementById('host-dialog').open && document.getElementById('route-oidc').checked");
  await evaluate("document.querySelector('[data-host-section=host-group-access]').click()");
  await evaluate("document.getElementById('route-oidc').closest('details')?.setAttribute('open','');document.getElementById('route-oidc').scrollIntoView({block:'start'})");
  await shoot('host-single-sign-on', '#host-dialog');
  await evaluate("document.getElementById('host-dialog').close()");
  await view('containers'); await wait("document.querySelectorAll('#containers-table tbody tr').length>=4"); await shoot('containers', 'main');
  await view('analytics'); await shoot('analytics', 'main');
  await settings('api-tokens'); await shoot('api-tokens', 'main');
  await settings('threat-protection'); await wait("document.getElementById('access-log-status').textContent.includes('access.log')");
  // Show the container's default log path rather than this run's temporary directory.
  await shoot('threat-protection', 'main', `(s=>{s.textContent=s.textContent.replace(${JSON.stringify(data)},'/data')})(document.getElementById('access-log-status'))`);
  // Show public example addresses instead of this run's local ports.
  await settings('single-sign-on'); await shoot('single-sign-on', 'main', `(()=>{
    const swap=text=>text.replaceAll(${JSON.stringify(base)},'https://gateway.example.com').replaceAll('http://localhost:${providerPort}','https://auth.example.com/application/o/embergate/');
    for(const id of ['oidc-issuer','oidc-origin'])if(document.getElementById(id))document.getElementById(id).value=swap(document.getElementById(id).value);
    const walker=document.createTreeWalker(document.getElementById('settings-page-single-sign-on'),NodeFilter.SHOW_TEXT);
    while(walker.nextNode())walker.currentNode.textContent=swap(walker.currentNode.textContent);
  })()`);
  console.log(`Saved ${shots.length} screenshots to docs/images: ${shots.join(', ')}`);
} finally {
  const exited = child => new Promise(resolve => child.exitCode !== null || child.signalCode ? resolve() : child.once('exit', resolve));
  browser?.kill('SIGKILL'); gateway.kill('SIGINT');
  await Promise.all([gateway, browser].filter(Boolean).map(exited));
  for (const server of [origin, docker, crowdsec, provider]) server.close();
  rmSync(data, {recursive: true, force: true}); if (profile) rmSync(profile, {recursive: true, force: true});
}

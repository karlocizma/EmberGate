// Real-browser dashboard checks against a deliberately isolated API fixture.
// No dependency downloads. Requires Node 22+ and an installed Chromium browser.
import {createServer} from 'node:http';
import {readFileSync, writeFileSync, mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawn} from 'node:child_process';
import assert from 'node:assert/strict';
import {setTimeout as delay} from 'node:timers/promises';
import {helpTopics} from '../web/app.js';

const helpFixture=process.env.HELP_FIXTURE?JSON.parse(readFileSync(process.env.HELP_FIXTURE,'utf8')):{version:'0.3.0',guides:helpTopics.map(id=>{
  const topics={ 'getting-started':['Getting started','run-locally'], 'proxy-hosts':['Proxy hosts','response-caching'],certificates:['Certificates','automatic-certificates-with-cloudflare-dns'],security:['Security','two-factor-authentication'],administration:['Settings & configuration','configuration'],backups:['Backups & restore','full-backup-and-restore'],monitoring:['Monitoring','prometheus-metrics'],troubleshooting:['Troubleshooting','the-dashboard-will-not-open'] };
  const [title,anchor]=topics[id],text=id==='certificates'?'Cloudflare DNS challenges and automatic certificate renewal.':'Read the '+title+' guide.';
  return {id,title,description:text,text,headings:[{id:anchor,title}],html:`<h2 id="help-${id}-${anchor}" tabindex="-1">${title}</h2><p>${text}</p><pre><code>cargo run --locked</code></pre><table><thead><tr><th>Setting</th><th>Value</th></tr></thead><tbody><tr><td>Proxy</td><td>127.0.0.1:8080</td></tr></tbody></table><p><a href="https://example.test/guide">Reference</a></p>`};
})};
let helpFailure=true,helpLoads=0;
let config = {version:0, routes:[]};
let templateStore={version:0,templates:[]};
let certificates = [], certificateInput;
let managedOrders = [], backupPending=false, backupExportInput=null, backupReviewInput=null;
const clusterFixture={instance_id:'00000000-0000-4000-8000-000000000001',settings:{role:'standalone',peer_url:null,expected_primary_id:null,interval_seconds:5,stale_after_seconds:300,version:0},token_configured:false,ready:true,last_success_at:null,last_error:null,received:null,followers:[]};
let loggedIn = false, mfaPolicy=false;
const mfaEnabledUsers=new Set();
let setupRequired=true, cloudflareToken=null;
let scheduleLastInput=null;
let schedule={settings:{enabled:false,interval_hours:24,retain_count:7,notify_failures:true,version:0},passphrase_configured:false,offsite_configured:false,offsite_origin:null,auth_kind:'none',runtime:{next_run_at:0,requested:false,running:false,last_attempt:null,last_success:null,last_local_at:null,last_file:null,last_offsite_success:null,last_error:null},running:false,files:[]};
let diagnosticInputs=[];
let cachePurges=[], prometheusConfigured=false, webhookDestination=null;
let currentUser={id:'bootstrap',username:'admin',role:'administrator',managed:false};
let teamUsers=[currentUser];
let alertSettings={backend_failures:true,certificate_failures:true,error_rate:true,error_threshold_percent:10,minimum_requests:20,window_minutes:5,webhook_enabled:false,version:0};
let alerts=[{id:'alert-test',source:'backend',title:'Backend unavailable',message:'Service health check failed.',opened_at:Date.now()/1000,resolved_at:null,acknowledged:false}];
const server = createServer(async (request, response) => {
  let body = ''; for await (const chunk of request) body += chunk;
  response.setHeader('Content-Type','application/json');
  response.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
  const send = data => response.end(JSON.stringify(data));
  if(request.url==='/api/setup') {if(request.method==='POST'){const input=JSON.parse(body);assert.equal(input.setup_code,'fixture-setup-code');assert.equal(input.password,'setup-password-123');setupRequired=false;response.statusCode=201;return send({ok:true});}return send({setup_required:setupRequired});}
  if (request.url === '/api/login') {
    const input=JSON.parse(body),name=input.username;
    const user=name==='reader'?{id:'reader',username:'reader',role:'read_only',managed:true}:name==='new-admin'?{id:'new-admin',username:'new-admin',role:'administrator',managed:true}:teamUsers[0];
    if(mfaEnabledUsers.has(user.id)&&input.code!=='654321'){response.statusCode=401;return send({error:'Enter an authenticator code or an unused recovery code.',mfa_required:true});}
    loggedIn=true;currentUser=user;return send({ok:true,user:currentUser});
  }
  if (request.url === '/api/logout') { loggedIn = false; return send({ok:true}); }
  if (request.url.startsWith('/api/')) {
    if (!loggedIn) { response.statusCode = 401; return send({error:'Please sign in.'}); }
    if(request.url==='/api/cluster'){
      if(request.method==='PUT'){const input=JSON.parse(body);assert.equal(input.current_password,'setup-password-123');assert.equal(input.settings.version,clusterFixture.settings.version);if(input.settings.role==='follower')assert.equal(input.confirm_replace,true);clusterFixture.settings={...input.settings,version:input.settings.version+1};clusterFixture.last_success_at=input.settings.role==='follower'?Math.floor(Date.now()/1000):null;return send({ok:true});}
      return send(clusterFixture);
    }
    if(request.url==='/api/cluster/token'){assert.equal(JSON.parse(body).current_password,'setup-password-123');clusterFixture.token_configured=true;return send({token:'a'.repeat(64)});}
    if(request.url==='/api/cluster/sync')return send({queued:true});
    if(request.url==='/api/passkeys')return send({origin:null,keys:[]});
    if(request.url==='/api/documentation'){helpLoads++;if(helpFailure){helpFailure=false;response.statusCode=503;return send({error:'Documentation temporarily unavailable.'});}return send(helpFixture);}
    // Restore controls must update before unrelated security requests finish.
    if(request.url==='/api/mfa'){if(backupPending)await delay(1000);if(request.method==='DELETE'){mfaEnabledUsers.delete(currentUser.id);return send({ok:true});}return send({enabled:mfaEnabledUsers.has(currentUser.id),recovery_codes_remaining:mfaEnabledUsers.has(currentUser.id)?10:0,require_administrators:mfaPolicy,enrollment_required:false});}
    if(request.url==='/api/mfa/setup'){assert.equal(JSON.parse(body).current_password,'setup-password-123');return send({secret:'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',expires_in_seconds:600});}
    if(request.url==='/api/mfa/confirm'){assert.equal(JSON.parse(body).code,'123456');mfaEnabledUsers.add(currentUser.id);return send({ok:true,recovery_codes:Array.from({length:10},(_,i)=>String(i).padStart(32,'0'))});}
    if(request.url==='/api/mfa/policy'){mfaPolicy=JSON.parse(body).require_administrators;return send({ok:true});}
    if(request.url==='/api/mfa/recovery')return send({ok:true,recovery_codes:Array.from({length:10},(_,i)=>String(i+10).padStart(32,'0'))});
    if (request.url === '/api/session') return send({ok:true,user:currentUser,password_editable:true,mfa_enrollment_required:mfaPolicy&&currentUser.role==='administrator'&&!mfaEnabledUsers.has(currentUser.id)});
    if(request.url==='/api/backups/schedule'){
      if(request.method==='PUT'){
        const input=JSON.parse(body);scheduleLastInput=input;
        assert.equal(input.version,schedule.settings.version);
        schedule.settings={enabled:input.enabled,interval_hours:input.interval_hours,retain_count:input.retain_count,notify_failures:input.notify_failures,version:input.version+1};
        if(input.passphrase)schedule.passphrase_configured=true;if(input.remove_passphrase)schedule.passphrase_configured=false;
        if(input.offsite_url){schedule.offsite_configured=true;schedule.offsite_origin=new URL(input.offsite_url).origin;schedule.auth_kind=input.auth?.kind||'none';}
        if(input.offsite_url===''){schedule.offsite_configured=false;schedule.offsite_origin=null;schedule.auth_kind='none';}
        schedule.runtime.next_run_at=input.enabled?Math.floor(Date.now()/1000)+input.interval_hours*3600:0;return send({ok:true});
      }
      return send({...schedule,paused_for_restore:backupPending});
    }
    if(request.url==='/api/backups/schedule/run'){
      const name='embergate-auto-00000001760708600000-00000000-0000-4000-8000-000000000001.embergate';
      schedule.files=[{name,created_at:Date.now()/1000,bytes:2097152}];schedule.runtime.last_success=schedule.runtime.last_local_at=Date.now()/1000;response.statusCode=202;return send({queued:true});
    }
    if(request.url.startsWith('/api/backups/scheduled/')){if(request.method==='DELETE'){schedule.files=[];return send({ok:true});}response.setHeader('Content-Type','application/octet-stream');return response.end(Buffer.from('EMBERGATE-BACKUP\0\x01fixture'));}
    if(request.url==='/api/host-templates'){
      if(request.method==='POST'){
        const input=JSON.parse(body);
        if(input.expected_version!==templateStore.version || (input.source_route_id && input.expected_config_version!==config.version)){response.statusCode=409;return send({error:'Host configuration or templates changed. Close and reopen this form.'});}
        let item=input.id?templateStore.templates.find(t=>t.id===input.id):{id:'template-'+(templateStore.version+1)};
        Object.assign(item,{name:input.name,description:input.description||'',updated_at:Math.floor(Date.now()/1000),updated_by:'admin'});
        if(input.source_route_id){const route=config.routes.find(r=>r.id===input.source_route_id);item.policies={preserve_host:route.preserve_host,branded_errors:route.pages?.branded_errors!==false};for(const key of ['forward_auth','compression','cache','access','response','rate_limit','reliability','routing','health_check'])item.policies[key]=structuredClone(route[key]??null);}
        if(!input.id)templateStore.templates.push(item);templateStore.version++;
      }
      return send(templateStore);
    }
    if(request.url.startsWith('/api/host-templates/')){assert.equal(JSON.parse(body).expected_version,templateStore.version);templateStore.templates=templateStore.templates.filter(t=>t.id!==request.url.split('/').at(-1));templateStore.version++;return send(templateStore);}
    if(request.url==='/api/config/history')return send({current_version:config.version,limit:50,revisions:[{id:'fixture-revision',version:0,archived_at:Date.now()/1000,archived_by:'admin <safe>',hosts:1}]});
    if(request.url==='/api/config/history/fixture-revision')return send({id:'fixture-revision',version:0,expected_version:config.version,comparison:{routes:[{name:'Host <script>bad</script>',action:'changed',changes:[{field:'/enabled',before:true,after:false},{field:'/routing/rewrite_prefix',before:'/<img src=x onerror=alert(1)>',after:'/old'}]}],trusted_proxies:{before:[],after:[{network:'127.0.0.1/32',header:'x_forwarded_for',trust_proto:false}]},route_order_changed:true,route_order:{before:[{name:'Current host'}],after:[{name:'Restored host'}]}}});
    if(request.url==='/api/config/history/fixture-revision/rollback'){
      const input=JSON.parse(body);assert.equal(input.confirm,'ROLLBACK');
      if(input.expected_version!==config.version){response.statusCode=409;return send({error:'Configuration changed.'});}
      config={...config,version:config.version+1};return send(config);
    }
    // Keep the old 'No restore is queued' text visible while status refreshes.
    if(request.url==='/api/backups/status'){if(backupPending)await delay(400);return send({pending:backupPending,last_restore:null,recovery_available:false,maximum_data_bytes:67108864,encrypted:true});}
    if(request.url==='/api/backups/export'){backupExportInput=JSON.parse(body);response.setHeader('Content-Type','application/octet-stream');return response.end(Buffer.from('EMBERGATE-BACKUP\0\x01fixture'));}
    if(request.url==='/api/backups/preview'){backupReviewInput=JSON.parse(body);return send({id:'fixture-review',created_at:Date.now()/1000,expires_at:Date.now()/1000+900,requires_restart:true,environment_overrides:[],summary:{routes:config.routes,accounts:[{username:'admin',role:'administrator',enabled:true}],certificates:[{name:'Fixture certificate',domains:['test.local'],valid:true,days_remaining:30}],managed_certificates:0,pending_dns_records:0,credential_types:['cloudflare_token'],analytics:true,audit_and_alerts:true}});}
    if(request.url==='/api/backups/restore'){assert.equal(JSON.parse(body).confirm,'RESTORE');backupPending=true;return send({queued:true,requires_restart:true});}
    if(request.url==='/api/backups/cancel'){backupPending=false;return send({queued:false});}
    if(request.url==='/api/credentials') return send({cloudflare:{configured:Boolean(cloudflareToken),source:cloudflareToken ? 'database' : 'none',editable:true},admin_password:{source:'database',editable:true}});
    if(request.url==='/api/credentials/cloudflare'){cloudflareToken=request.method==='DELETE' ? null : JSON.parse(body).token;return send({configured:Boolean(cloudflareToken),source:cloudflareToken ? 'database' : 'none',editable:true});}
    if (request.url === '/api/users') {
      if(request.method==='POST'){const input=JSON.parse(body);teamUsers.push({id:'new-user',username:input.username,role:input.role,enabled:true,version:1,managed:true});return send({user:teamUsers.at(-1)});}
      return send({users:teamUsers});
    }
    if (request.url.startsWith('/api/users/')) {if(request.method==='PUT'){const input=JSON.parse(body);teamUsers[1]={...teamUsers[1],username:input.username,role:input.role,enabled:input.enabled,version:2};}else teamUsers.splice(1,1);return send({ok:true});}
    if (request.url==='/api/sessions') return send({sessions:[{id:'fixture-session',user:currentUser,created_at:Date.now()/1000,expires_at:Date.now()/1000+43200,peer:'127.0.0.1',current:true}]});
    if (request.url.startsWith('/api/sessions/')) return send({ok:true,sign_in_required:true});
    if (request.url==='/api/password') return send({ok:true,sign_in_required:true});
    if (request.url==='/api/audit') return send({events:[{timestamp:Date.now()/1000,actor:{username:'admin',peer:'127.0.0.1'},method:'PUT',path:'/api/config',phase:'success',status:200,details:{configuration_version_before:1,configuration_version_after:2}}]});
    if (request.url==='/api/alerts') return send({settings:alertSettings,webhook_configured:true,webhook_source:'database',webhook_editable:true,alerts,unacknowledged_active:alerts.filter(a=>!a.acknowledged).length,delivery:{pending:0,delivered:2,failed:0}});
    if(request.url==='/api/integrations/prometheus'){if(request.method==='POST'){prometheusConfigured=true;return send({configured:true,token:'a'.repeat(64),path:'/metrics'});}if(request.method==='DELETE')prometheusConfigured=false;return send({configured:prometheusConfigured,path:'/metrics'});}
    if(request.url==='/api/alerts/destination'){if(request.method==='PUT'){const input=JSON.parse(body);webhookDestination=input.url;alertSettings={...alertSettings,webhook_format:input.webhook_format,version:alertSettings.version+1};return send({configured:true,settings:alertSettings});}webhookDestination=null;alertSettings={...alertSettings,webhook_enabled:false,version:alertSettings.version+1};return send({configured:false});}
    if (request.url==='/api/alerts/settings') {alertSettings={...JSON.parse(body),version:alertSettings.version+1};return send({settings:alertSettings});}
    if (request.url==='/api/alerts/test') return send({ok:true,queued:true});
    if (request.url.endsWith('/ack')) {alerts[0].acknowledged=true;return send({ok:true});}
    if (request.url === '/api/acme') return send({configured:true,provider:'cloudflare',orders:managedOrders});
    if (request.url === '/api/acme/orders' && request.method === 'POST') {
      const input = JSON.parse(body);
      assert.equal(input.agree_to_terms,true);
      const order = {...input,id:'managed-test',status:'queued',phase:'Waiting to issue',last_error:null,renew_at:null,next_attempt:Date.now()/1000};
      managedOrders.push(order); response.statusCode=202; return send(order);
    }
    if (request.url.startsWith('/api/acme/orders/')) {
      if (request.method === 'DELETE') managedOrders=[];
      else if (request.method === 'POST') {managedOrders[0].status='queued';managedOrders[0].phase='Renewal queued';if(request.url.endsWith('/production'))managedOrders[0].environment='production';}
      return send({ok:true});
    }
    if (request.url.startsWith('/api/certificates')) {
      if (request.method === 'DELETE') certificates = [];
      if (request.method === 'POST' || request.method === 'PUT') {
        certificateInput = JSON.parse(body);
        certificates = [{id:'test-certificate',name:certificateInput.name,domains:['test.local'],expires_at:'Jan 1 00:00:00 2027 GMT',days_remaining:60,valid:true,fingerprint:'AB:CD'}];
      }
      return send({certificates,https_addr:'127.0.0.1:8443'});
    }
    if(request.url==='/api/diagnostics'){
      const input=JSON.parse(body);diagnosticInputs.push(input);
      const host=input.host.toLowerCase().split(':')[0],path=input.path.split('?')[0];
      const route=config.routes.filter(r=>r.enabled&&(r.host===host||r.host==='*')&&path.startsWith(r.path_prefix)).sort((a,b)=>Number(b.host!=='*')-Number(a.host!=='*')||b.path_prefix.length-a.path_prefix.length)[0];
      const origins=route?[route.upstream,...(route.additional_upstreams||[])]:[];
      const stage=(status,detail,time=.5)=>({status,detail,elapsed_ms:status==='skipped'?null:time});
      return send({checked_at:Date.now()/1000,configuration_version:config.version,configuration_changed:false,probe:input.probe,host,path:input.path,route:route?{...route,upstream_path:input.path,upstreams:origins,reliability:route.reliability||{connect_timeout_seconds:5,read_timeout_seconds:60,write_timeout_seconds:60,retries:0}}:null,paused_matches:[],https_listener_configured:true,public_certificate:{name:'Fixture visitor certificate',days_remaining:30,expires_at:'Nov 1 2026'},notes:['<script>Diagnostics values stay plain text.</script>'],backends:input.probe?origins.map((origin,i)=>({origin,host_header:host,draining:false,monitored_status:'unchecked',addresses:['127.0.0.1:9000'],connected_address:i?null:'127.0.0.1:9000',dns:stage('passed','Address resolved'),tcp:stage(i?'failed':'passed',i?'Connection refused':'Connected'),tls:stage('skipped','HTTP origin · TLS is not used'),http:stage(i?'skipped':'passed',i?'Connection did not succeed':'HTTP 200 · HEAD response headers received'),http_status:i?null:200,certificate:null,total_ms:2})):[]});
    }
    if (request.url === '/api/config') {
      if (request.method === 'PUT') {
        const next = JSON.parse(body);
        if (next.version !== config.version) { response.statusCode = 409; return send({error:'Refresh and try again.'}); }
        config = {...next, version:next.version+1};
      }
      return send(config);
    }
    if (request.url === '/api/cache') return send({capacity_bytes:67108864,used_bytes:cachePurges.length ? 0 : 4194304,entries:cachePurges.length ? 0 : 5,routes:config.routes.map(r=>({route_id:r.id,name:r.name,enabled:Boolean(r.enabled && r.cache),hits:8,misses:2,bypasses:1,entries:cachePurges.length?0:5,bytes:cachePurges.length?0:4194304,hit_ratio:.8,purges:cachePurges.length}))});
    if (request.url === '/api/cache/purge') {cachePurges.push(JSON.parse(body));return send({removed:5});}
    if (request.url === '/api/cloudflare/networks') return send({networks:['173.245.48.0/20','2400:cb00::/32']});
    if (request.url.startsWith('/api/analytics?')) {
      const query=new URL(request.url,'http://fixture').searchParams, hours=Number(query.get('hours') || 24);
      return send({hours,retention_days:30,totals:{requests:12,errors:1,rate_limited:3,access_denied:2,avg_latency_ms:820.1,success_requests:6,failed_requests:6,success_avg_latency_ms:4.2,failed_avg_latency_ms:60000,timing:{success:{requests:6,header_samples:6,avg_headers_ms:4.2,avg_duration_ms:3072.7,p95_headers_upper_ms:10},long_lived:{requests:2,avg_headers_ms:20000,avg_duration_ms:60000},server_error:{requests:1,avg_headers_ms:60000,avg_duration_ms:60000},cancelled:{requests:3,avg_duration_ms:10000}}},buckets:Array.from({length:hours},(_,i)=>({timestamp:Math.floor(Date.now()/3600000)*3600-(hours-1-i)*3600,requests:i===hours-1?12:0,errors:0})),hosts:config.routes.map(r=>({route_id:r.id,name:r.name,requests:12,errors:1,rate_limited:3,access_denied:2})),status_codes:[{status:200,requests:6},{status:403,requests:2},{status:429,requests:3},{status:502,requests:1}]});
    }
    if (request.url === '/api/upstreams') return send({version:config.version,routes:Object.fromEntries(config.routes.map(route=>[route.id,[route.upstream,...(route.additional_upstreams || [])].map((upstream,i)=>({upstream,status:!route.enabled ? 'paused' : route.balancing?.draining?.includes(upstream) ? 'draining' : route.health_check ? i ? 'unhealthy' : 'healthy' : 'unchecked',draining:Boolean(route.balancing?.draining?.includes(upstream)),weight:route.balancing?.weights?.[i] || 1,active_requests:0,checked_at:Date.now()/1000,latency_ms:3,detail:i ? 'HTTP 503' : null}))]))});
    if (request.url === '/api/stats') return send({cluster_role:clusterFixture.settings.role,cluster_ready:true,requests:2, errors:0, rate_limited:3, avg_latency_ms:820.1,success_requests:6,failed_requests:6,success_avg_latency_ms:4.2,failed_avg_latency_ms:60000,timing:{success:{requests:6,header_samples:6,avg_headers_ms:4.2,avg_duration_ms:3072.7,p95_headers_upper_ms:10},long_lived:{requests:2,avg_headers_ms:20000,avg_duration_ms:60000},server_error:{requests:1,avg_headers_ms:60000,avg_duration_ms:60000},cancelled:{requests:3,avg_duration_ms:10000}}, uptime_seconds:65, proxy_addr:'127.0.0.1:8080', admin_addr:'127.0.0.1:9090', version:'0.2.0', buckets:Array.from({length:60}, (_,i)=>({timestamp:i*60,requests:i===59 ? 2 : 0,errors:0}))});
    if (request.url === '/api/logs') return send({logs:[{timestamp:Date.now()/1000,method:'GET',host:'test.local',path:'/<script>alert(1)</script>',status:429,rate_limited:true,access_denied:false,client_ip:'203.0.113.5',peer_ip:'127.0.0.1',identity_source:'cloudflare',cache_status:'HIT',latency_ms:4.2}]});
  }
  const asset = {'/':'index.html','/style.css':'style.css','/app.js':'app.js'}[request.url];
  if (!asset) {response.statusCode = 404; return response.end();}
  response.setHeader('Content-Type', asset.endsWith('.html') ? 'text/html' : asset.endsWith('.css') ? 'text/css' : 'text/javascript');
  response.end(readFileSync(new URL(`../web/${asset}`, import.meta.url)));
});
await new Promise((resolve,reject) => { server.once('error',reject); server.listen(0,'127.0.0.1',resolve); });
const url = `http://127.0.0.1:${server.address().port}`;
const profile = mkdtempSync(join(tmpdir(),'embergate-browser-'));
let browser, socket;
try {
  browser = spawn(process.env.BROWSER_BIN || '/usr/bin/vivaldi', ['--password-store=basic','--disable-vivaldi','--headless=new','--no-sandbox','--disable-gpu','--disable-dev-shm-usage','--no-first-run','--no-default-browser-check','--remote-debugging-port=0',`--user-data-dir=${profile}`,'about:blank'], {stdio:['ignore','ignore','pipe']});
  let browserStderr='';
  browser.stderr.on('data',chunk=>{browserStderr=(browserStderr+chunk.toString()).slice(-8192);});
  let spawnError;
  browser.on('error',error => { spawnError = error; });
  let port;
  const startupDeadline=Date.now()+30000;
  while (Date.now()<startupDeadline) {
    try { port = readFileSync(join(profile,'DevToolsActivePort'),'utf8').split('\n')[0]; break; } catch {}
    if (spawnError) throw spawnError;
    if (browser.exitCode !== null) throw new Error(`Browser exited with code ${browser.exitCode}: ${browserStderr}`);
    await delay(100);
  }
  if (!port) throw new Error(`Browser did not start within 30 seconds. BROWSER_BIN=${process.env.BROWSER_BIN || '/usr/bin/vivaldi'}. ${browserStderr}`);
  const pages = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
  socket = new WebSocket(pages.find(p=>p.type==='page').webSocketDebuggerUrl);
  await new Promise((resolve,reject)=>{socket.onopen=resolve;socket.onerror=reject;});
  let sequence=0; const pending=new Map(), errors=[];
  socket.onmessage = event => {
    const message=JSON.parse(event.data);
    if(message.id) { const cb=pending.get(message.id);pending.delete(message.id); if(cb) message.error ? cb.reject(new Error(message.error.message)) : cb.resolve(message.result); }
    if(message.method==='Runtime.exceptionThrown') errors.push(message.params.exceptionDetails.text);
  };
  const call=(method,params={})=>new Promise((resolve,reject)=>{
    const id=++sequence;
    const timer=setTimeout(()=>{pending.delete(id);reject(new Error(`Browser command timed out: ${method}`));},10000);
    pending.set(id,{resolve:value=>{clearTimeout(timer);resolve(value);},reject:error=>{clearTimeout(timer);reject(error);}});
    socket.send(JSON.stringify({id,method,params}));
  });
  const evaluate=async expression=>{
    const result=await call('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});
    if(result.exceptionDetails) throw new Error(JSON.stringify(result.exceptionDetails));
    return result.result.value;
  };
  const wait=async expression=>{for(let i=0;i<60;i++){if(await evaluate(expression)) return;await delay(100);}throw new Error(`Timed out: ${expression}`);};
  const reload=async()=>{const previous=await evaluate('performance.timeOrigin');await call('Page.reload');await wait(`performance.timeOrigin!==${previous} && document.readyState==='complete'`);};
  const openSettings=async section=>{
    await evaluate(`document.querySelector('[data-view=settings]').click();if(innerWidth<=1100){document.getElementById('settings-section').value='${section}';document.getElementById('settings-section').dispatchEvent(new Event('change'));}else{document.querySelector('[data-settings-link=${section}]').click();}`);
    await wait(`!document.getElementById('settings-page-${section}').hidden && location.hash==='#/settings/${section}'`);
  };
  await call('Runtime.enable'); await call('Page.enable');
  // Model HTTP LAN browsers where randomUUID is unavailable, including after reloads.
  await call('Page.addScriptToEvaluateOnNewDocument',{source:"Object.defineProperty(Crypto.prototype,'randomUUID',{value:undefined,configurable:true});"});
  await call('Emulation.setEmulatedMedia',{features:[{name:'prefers-reduced-motion',value:'reduce'}]});
  await call('Emulation.setDeviceMetricsOverride',{width:1440,height:1080,deviceScaleFactor:1,mobile:false});
  await call('Emulation.setEmulatedMedia',{features:[{name:'prefers-color-scheme',value:'light'}]});
  await call('Page.navigate',{url});
  await wait("document.getElementById('password') !== null && performance.getEntriesByType('resource').some(r => r.name.endsWith('/api/session'))");
  async function screenshot(name) {
    const result=await call('Page.captureScreenshot',{format:'png',captureBeyondViewport:true});
    writeFileSync(join(tmpdir(),name),Buffer.from(result.data,'base64'));
  }
  await wait("!document.getElementById('setup-form').hidden");
  assert.equal(await evaluate("typeof crypto.randomUUID"),'undefined');
  assert.equal(await evaluate('document.title'),'EmberGate · Powered by Pingora');
  assert.equal(await evaluate("Array.from(document.querySelectorAll('.brand')).every(el=>el.textContent.includes('EmberGate'))"),true);
  assert.equal(await evaluate("document.querySelector('.login-foot').textContent"),'EmberGate · Powered by Pingora.');
  assert.deepEqual(await evaluate("Array.from(document.querySelectorAll('table:not(.help-prose table)')).filter(table=>!document.getElementById(table.getAttribute('aria-labelledby'))?.textContent.trim()).map(table=>table.querySelector('tbody')?.id)"),[],'every data table is named by its heading');
  await screenshot('embergate-setup.png');
  await evaluate("document.getElementById('setup-code').value='fixture-setup-code';document.getElementById('setup-password').value='setup-password-123';document.getElementById('setup-confirm').value='different-password';document.getElementById('setup-form').requestSubmit(document.querySelector('#setup-form button[type=submit]'))");
  await wait("document.getElementById('setup-error').textContent.includes('do not match')");
  assert.equal(await evaluate("document.activeElement.id"),'setup-confirm');
  assert.equal(await evaluate("document.getElementById('setup-confirm').getAttribute('aria-invalid')+' '+document.getElementById('setup-confirm').getAttribute('aria-describedby')"),'true setup-error');
  await evaluate("document.getElementById('setup-confirm').dispatchEvent(new Event('input',{bubbles:true}))");
  assert.equal(await evaluate("document.getElementById('setup-confirm').hasAttribute('aria-invalid')||document.getElementById('setup-confirm').hasAttribute('aria-describedby')"),false,'typing clears the field error');
  await evaluate("document.getElementById('setup-confirm').value='setup-password-123';document.getElementById('setup-form').requestSubmit(document.querySelector('#setup-form button[type=submit]'))");
  await wait("document.getElementById('app') && !document.getElementById('app').hidden && document.getElementById('stat-requests').textContent === '2'");
  assert.equal(await evaluate("document.querySelector('#sidebar > .brand').scrollWidth<=document.querySelector('#sidebar > .brand').clientWidth"),true,'EmberGate wordmark overflows the sidebar');
  await evaluate("document.getElementById('add-host').click()");
  assert.equal(await evaluate("document.getElementById('host-form').dataset.step"),'0');
  assert.equal(await evaluate("document.getElementById('host-access').hidden && document.getElementById('host-review').hidden && document.getElementById('advanced-options').hidden"),true);
  await screenshot('embergate-add-host-simple.png');
  await evaluate("document.getElementById('host-next').click()");
  assert.equal(await evaluate("document.getElementById('host-form').dataset.step"),'0','empty destination must not advance');
  await evaluate("document.getElementById('route-name').value='Browser test';document.getElementById('route-host').value='test.local';document.getElementById('route-upstream').value='http://127.0.0.1:9000/path';document.getElementById('host-next').click()");
  assert.equal(await evaluate("document.getElementById('host-form').dataset.step"),'0','application origins must not include paths');
  assert.ok(await evaluate("document.getElementById('host-error').textContent.length>0"));
  assert.equal(await evaluate("document.activeElement.id+' '+document.getElementById('route-upstream').getAttribute('aria-invalid')+' '+document.getElementById('route-upstream').getAttribute('aria-describedby')"),'route-upstream true host-error');
  await evaluate("document.getElementById('host-preset').value='starter:netbird';document.getElementById('host-preset').dispatchEvent(new Event('change'));document.getElementById('host-preset-apply').click()");
  assert.equal(await evaluate("document.getElementById('route-upstream-protocol').value"),'http1','preview must not mutate the draft');
  await evaluate("document.getElementById('confirm-action').click()");
  await wait("!document.getElementById('confirm-dialog').open");
  assert.equal(await evaluate("document.getElementById('route-upstream-protocol').value"),'auto');
  assert.equal(await evaluate("Number(document.getElementById('route-read-timeout').value)"),3600);
  assert.equal(await evaluate("document.getElementById('route-preserve').checked"),true);
  // Restore defaults so the existing general-purpose wizard assertions stay meaningful.
  await evaluate("document.getElementById('route-upstream-protocol').value='http1';document.getElementById('route-preserve').checked=false;document.getElementById('route-reliability').checked=false;document.getElementById('route-reliability').dispatchEvent(new Event('change'))");
  await evaluate("document.getElementById('route-upstream').value='http://127.0.0.1:9000';document.getElementById('host-form').requestSubmit(document.getElementById('host-save'))");
  assert.equal(await evaluate("document.getElementById('host-form').dataset.step"),'1');
  await evaluate("document.getElementById('host-access-mode').value='https';document.getElementById('host-access-mode').dispatchEvent(new Event('change'))");
  assert.equal(await evaluate("document.getElementById('route-response').checked && document.getElementById('route-redirect').checked"),true);
  assert.ok(await evaluate("document.getElementById('host-certificate-status').textContent.includes('No currently valid certificate')"));
  await screenshot('embergate-host-wizard-access.png');
  await evaluate("document.getElementById('host-next').click()");
  assert.equal(await evaluate("document.getElementById('host-review-warning').hidden"),false);
  assert.equal(config.routes.length,0,'reviewing a host must not save it');
  await evaluate("document.getElementById('host-back').click();document.getElementById('host-back').click()");
  assert.equal(await evaluate("document.getElementById('route-upstream').value"),'http://127.0.0.1:9000');
  await evaluate("document.getElementById('host-next').click();document.getElementById('host-access-mode').value='http';document.getElementById('host-access-mode').dispatchEvent(new Event('change'));document.getElementById('host-next').click()");
  assert.equal(await evaluate("document.getElementById('host-form').dataset.step"),'2');
  assert.equal(await evaluate("document.getElementById('advanced-options').open"),false);
  assert.deepEqual(await evaluate("Array.from(document.querySelectorAll('.host-option-group>h4')).map(el=>el.textContent)"),['Access','Performance','Routing','Availability']);
  assert.ok(await evaluate("document.getElementById('host-review-summary').textContent.includes('http://test.local/')"));
  await screenshot('embergate-host-wizard-review.png');
  await evaluate("document.getElementById('host-form').requestSubmit(document.getElementById('host-save'))");
  await wait("!document.getElementById('host-dialog').open && document.getElementById('stat-hosts').textContent==='1'");
  assert.equal(config.routes[0].host,'test.local');
  assert.equal(config.routes[0].response,undefined,'returning to HTTP should retain conservative defaults');
  await evaluate("document.querySelector('[data-view=help]').click()");
  await wait("!document.getElementById('help-error').hidden");
  await evaluate("document.getElementById('help-retry').click()");
  await wait("!document.getElementById('help-article').hidden && document.querySelectorAll('#help-navigation a').length===8");
  assert.equal(await evaluate("location.hash"),'#/help/getting-started');
  await evaluate("document.getElementById('help-search').value='cloudflare dns';document.getElementById('help-search').dispatchEvent(new Event('input'))");
  await wait("!document.getElementById('help-results').hidden");
  assert.equal(await evaluate("Boolean(document.querySelector('#help-results-list a[href=\"#/help/certificates\"]'))"),true);
  await evaluate("document.querySelector('#help-results-list a[href=\"#/help/certificates\"]').click()");
  await wait("document.getElementById('help-article-title').textContent==='Certificates' && !document.getElementById('help-article').hidden");
  await evaluate("document.getElementById('help-search').value='<img src=x onerror=alert(1)>';document.getElementById('help-search').dispatchEvent(new Event('input'))");
  assert.equal(await evaluate("document.querySelector('#help-results-list img')===null && document.getElementById('help-results-list').textContent.includes('No matching guides')"),true);
  await evaluate("document.getElementById('help-search-clear').click();document.getElementById('help-outline').querySelector('a').click()");
  await wait("document.activeElement.id.startsWith('help-certificates-')");
  const helpLink=await evaluate("location.hash");
  await reload();
  await wait("document.getElementById('app') && !document.getElementById('app').hidden && !document.getElementById('help-article').hidden && document.getElementById('help-article-title').textContent==='Certificates'");
  assert.equal(await evaluate("location.hash"),helpLink);
  await screenshot('embergate-help-light.png');
  await evaluate("document.querySelector('#help-navigation a[href=\"#/help/security\"]').click();history.back()");
  await wait("document.getElementById('help-article-title').textContent==='Certificates'");
  await evaluate("history.forward()");
  await wait("document.getElementById('help-article-title').textContent==='Security'");
  const cachedHelpLoads=helpLoads;
  await evaluate("document.querySelector('#help-navigation a[href=\"#/help/backups\"]').click()");
  await wait("document.getElementById('help-article-title').textContent==='Backups & restore'");
  assert.equal(helpLoads,cachedHelpLoads,'switching guides uses embedded content already loaded');
  await evaluate("document.querySelector('[data-view=hosts]').click();document.querySelector('[data-action=edit]').click();document.getElementById('advanced-options').open=true;document.getElementById('forward-auth-options').open=true;document.getElementById('route-forward-auth').click();document.getElementById('route-auth-url').value='http://auth.test/check?token=unsafe';document.getElementById('host-form').requestSubmit(document.querySelector('#host-form button[type=submit]'))");
  await wait("document.getElementById('host-error').textContent.includes('query strings')");
  assert.equal(config.routes[0].forward_auth,undefined);
  await evaluate("document.getElementById('route-auth-url').value='http://auth.test/check';document.getElementById('route-auth-login').value='https://login.test/';document.getElementById('host-form').requestSubmit(document.querySelector('#host-form button[type=submit]'))");
  await wait("!document.getElementById('host-dialog').open && Boolean(document.querySelector('[data-action=edit]'))");
  assert.equal(config.routes[0].forward_auth.url,'http://auth.test/check');
  await evaluate("document.querySelector('[data-action=edit]').click();document.getElementById('advanced-options').open=true;document.getElementById('forward-auth-options').open=true");
  assert.equal(await evaluate("document.getElementById('route-forward-auth').checked && document.getElementById('route-auth-login').value==='https://login.test/'"),true);
  await screenshot('embergate-forward-auth.png');
  await evaluate("document.getElementById('route-forward-auth').click();document.getElementById('host-form').requestSubmit(document.querySelector('#host-form button[type=submit]'))");
  await wait("!document.getElementById('host-dialog').open");assert.equal(config.routes[0].forward_auth,undefined);
  // Cluster actions refresh management and permissions before clearing the password.
  // Wait for completion before filling credentials for the next action.
  await openSettings('instances');
  await wait("document.getElementById('cluster-state').textContent==='Standalone' && document.getElementById('cluster-form').dataset.version==='0'");
  await evaluate("document.getElementById('cluster-role').value='primary';document.getElementById('cluster-role').dispatchEvent(new Event('change'));document.getElementById('cluster-password').value='setup-password-123';document.getElementById('cluster-form').requestSubmit(document.getElementById('cluster-save'))");
  await wait("document.getElementById('cluster-state').textContent==='Writable primary' && document.getElementById('cluster-password').value==='' && !document.getElementById('cluster-save').disabled");
  await evaluate("document.getElementById('cluster-password').value='setup-password-123';document.getElementById('cluster-form').requestSubmit(document.getElementById('cluster-rotate'))");
  await wait("!document.getElementById('cluster-token-result').hidden && document.getElementById('cluster-password').value===''");
  assert.equal(await evaluate("document.getElementById('cluster-token-value').value"),'a'.repeat(64));
  await evaluate("document.getElementById('cluster-role').value='follower';document.getElementById('cluster-role').dispatchEvent(new Event('change'));document.getElementById('cluster-peer').value='https://primary.test';document.getElementById('cluster-primary-id').value='00000000-0000-4000-8000-000000000002';document.getElementById('cluster-token').value='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';document.getElementById('cluster-password').value='setup-password-123';document.getElementById('cluster-form').requestSubmit(document.getElementById('cluster-save'))");
  assert.equal(clusterFixture.settings.role,'primary','joining must require replacement confirmation');
  await screenshot('embergate-instances.png');
  await evaluate("document.getElementById('cluster-confirm').checked=true;document.getElementById('cluster-form').requestSubmit(document.getElementById('cluster-save'))");
  await wait("document.getElementById('cluster-state').textContent==='Synchronized follower' && !document.getElementById('cluster-notice').hidden && document.getElementById('cluster-password').value==='' && !document.getElementById('cluster-save').disabled");
  assert.equal(await evaluate("document.getElementById('add-host').disabled"),true);
  assert.equal(await evaluate("document.getElementById('cluster-token').value==='' && document.getElementById('cluster-token-value').value===''"),true);
  await evaluate("document.getElementById('cluster-role').value='standalone';document.getElementById('cluster-role').dispatchEvent(new Event('change'));document.getElementById('cluster-password').value='setup-password-123';document.getElementById('cluster-form').requestSubmit(document.getElementById('cluster-save'))");
  await wait("document.getElementById('cluster-state').textContent==='Standalone' && document.getElementById('cluster-notice').hidden && document.getElementById('cluster-password').value==='' && !document.getElementById('cluster-save').disabled");
  await openSettings('instance');
  assert.equal(await evaluate("document.getElementById('settings-sidebar').getBoundingClientRect().left===document.getElementById('sidebar').getBoundingClientRect().right"),true);
  assert.equal(await evaluate("getComputedStyle(document.getElementById('settings-sidebar')).display!=='none'"),true);
  await openSettings('security');
  assert.deepEqual(await evaluate("Array.from(document.querySelectorAll('[data-settings-page]')).filter(el=>!el.hidden).map(el=>el.dataset.settingsPage)"),['security']);
  assert.equal(await evaluate("document.getElementById('mfa-card').getClientRects().length>0 && document.getElementById('password-settings-card').getClientRects().length>0 && document.getElementById('cloudflare-settings-card').getClientRects().length===0"),true);
  await openSettings('cloudflare');
  await evaluate("history.back()");await wait("location.hash==='#/settings/security' && !document.getElementById('settings-page-security').hidden");
  await evaluate("history.forward()");await wait("location.hash==='#/settings/cloudflare' && !document.getElementById('settings-page-cloudflare').hidden");
  await reload();
  await wait("document.getElementById('app') && !document.getElementById('app').hidden && !document.getElementById('settings-page-cloudflare').hidden && document.getElementById('cloudflare-token-status').textContent.includes('No token')");
  assert.equal(await evaluate("document.querySelector('[data-settings-link=cloudflare]').getAttribute('aria-current')"),'page');
  assert.equal(await evaluate("document.querySelector('#settings-navigation [aria-current=page]').textContent"),'Cloudflare DNS');
  await screenshot('embergate-settings-navigation-light.png');
  await evaluate("document.querySelector('#cloudflare-settings-card .help-context-link').click()");
  await wait("location.hash==='#/help/certificates/automatic-certificates-with-cloudflare-dns' && !document.getElementById('help-article').hidden");
  assert.equal(await evaluate("document.activeElement.id"),'help-certificates-automatic-certificates-with-cloudflare-dns');

  await evaluate("document.querySelector('[data-view=overview]').click()");
  assert.equal(await evaluate("document.getElementById('settings-sidebar').hidden && !document.getElementById('app').classList.contains('settings-open') && document.getElementById('hosts-section').hidden"),true);
  await evaluate("document.querySelector('[data-view=hosts]').click()");
  assert.equal(await evaluate("!document.getElementById('hosts-section').hidden"),true);

  await evaluate("document.querySelector('[data-action=toggle]').click()");
  await wait("document.getElementById('stat-hosts').textContent==='0'");
  assert.equal(config.routes[0].enabled,false);
  await evaluate("document.querySelector('[data-action=edit]').click();document.getElementById('route-name').value='Edited host';document.getElementById('host-form').requestSubmit(document.querySelector('#host-form button[type=submit]'))");
  await wait("!document.getElementById('host-dialog').open && document.getElementById('hosts-body').textContent.includes('Edited host')");
  await evaluate("document.querySelector('[data-action=edit]').click();document.getElementById('advanced-options').open=true;document.getElementById('pool-options').open=true;document.getElementById('route-additional').value='http://127.0.0.1:9001';document.getElementById('route-health').click();document.getElementById('route-health-path').value='/health';document.getElementById('route-status').value='active'");
  await screenshot('embergate-pool-settings.png');
  await evaluate("document.getElementById('host-form').requestSubmit(document.querySelector('#host-form button[type=submit]'))");
  await wait("!document.getElementById('host-dialog').open && document.getElementById('hosts-body').textContent.includes('Degraded')");
  assert.deepEqual(config.routes[0].additional_upstreams,['http://127.0.0.1:9001']);
  assert.equal(config.routes[0].health_check.path,'/health');
  await evaluate("document.querySelector('[data-action=edit]').click();document.getElementById('route-strategy').value='weighted_round_robin';document.querySelectorAll('[data-weight]')[0].value='3';document.querySelectorAll('[data-draining]')[1].checked=true;document.getElementById('route-reliability').click();document.getElementById('route-connect-timeout').value='2';document.getElementById('route-read-timeout').value='3';document.getElementById('route-write-timeout').value='4';document.getElementById('route-retries').value='1';document.getElementById('route-verify-upstream-tls').click();document.getElementById('host-form').requestSubmit(document.querySelector('#host-form button[type=submit]'))");
  await wait("!document.getElementById('host-dialog').open && document.getElementById('hosts-body').textContent.includes('Healthy')");
  assert.deepEqual(config.routes[0].balancing,{strategy:'weighted_round_robin',weights:[3,1],draining:['http://127.0.0.1:9001']});
  assert.deepEqual(config.routes[0].reliability,{connect_timeout_seconds:2,read_timeout_seconds:3,write_timeout_seconds:4,retries:1});
  assert.equal(config.routes[0].verify_upstream_tls,false);
  await evaluate("document.querySelector('[data-action=edit]').click();document.getElementById('advanced-options').open=true;document.getElementById('reliability-options').open=true");
  assert.equal(await evaluate("document.querySelectorAll('[data-draining]')[1].checked"),true);
  assert.equal(await evaluate("document.getElementById('route-retries').value"),'1');
  assert.equal(await evaluate("document.getElementById('route-verify-upstream-tls').checked"),false);
  await screenshot('embergate-reliability-settings.png');
  await evaluate("document.querySelectorAll('[data-draining]')[1].checked=false;document.getElementById('host-form').requestSubmit(document.querySelector('#host-form button[type=submit]'))");
  await wait("!document.getElementById('host-dialog').open && document.getElementById('hosts-body').textContent.includes('Degraded')");

  await evaluate("document.querySelector('[data-action=edit]').click();document.getElementById('advanced-options').open=true;document.getElementById('routing-options').open=true;document.getElementById('route-routing').click();document.getElementById('route-path-mode').value='replace';document.getElementById('route-path-mode').dispatchEvent(new Event('change'));document.getElementById('route-rewrite-prefix').value='/internal';document.getElementById('route-request-headers').value='X-App: EmberGate';document.getElementById('route-remove-headers').value='X-Debug';document.getElementById('route-preview-path').value='/api/items?x=%2f';document.getElementById('route-preview-path').dispatchEvent(new Event('input'))");
  assert.ok(await evaluate("document.getElementById('route-preview').textContent.includes('/internal/api/items?x=%2f')"));
  await evaluate("document.getElementById('route-remove-headers').value='Host';document.getElementById('host-form').requestSubmit(document.querySelector('#host-form button[type=submit]'))");
  await wait("document.getElementById('host-error').textContent.includes('protected')");
  await evaluate("document.getElementById('route-remove-headers').value='X-Debug';document.getElementById('route-remove-headers').dispatchEvent(new Event('input'));document.getElementById('routing-fields').scrollIntoView({block:'center'})");
  await screenshot('embergate-routing-settings.png');
  await evaluate("document.getElementById('host-form').requestSubmit(document.querySelector('#host-form button[type=submit]'))");
  await wait("!document.getElementById('host-dialog').open");
  assert.deepEqual(config.routes[0].routing,{strip_prefix:false,rewrite_prefix:'/internal',set_headers:[{name:'x-app',value:'EmberGate'}],remove_headers:['x-debug']});
  await evaluate("document.querySelector('[data-action=edit]').click()");
  assert.equal(await evaluate("document.getElementById('route-rewrite-prefix').value"),'/internal');
  await evaluate("document.getElementById('host-dialog').close()");
  await evaluate("document.querySelector('[data-action=edit]').click()");
  assert.equal(await evaluate("document.getElementById('route-additional').value"),'http://127.0.0.1:9001');
  assert.equal(await evaluate("document.getElementById('route-health').checked"),true);
  await evaluate("document.getElementById('host-dialog').close()");
  await evaluate("document.querySelector('[data-action=edit]').click();document.getElementById('pool-options').open=false;document.getElementById('advanced-options').open=true;document.getElementById('rate-options').open=true;document.getElementById('route-limit').click();document.getElementById('route-limit-requests').value='60';document.getElementById('route-limit-window').value='60';document.getElementById('route-limit-burst').value='10';document.getElementById('route-limit-burst').dispatchEvent(new Event('input'))");
  await evaluate("document.getElementById('rate-fields').scrollIntoView({block:'center'})");
  assert.ok(await evaluate("document.getElementById('rate-example').textContent.includes('10 immediately')"));
  await screenshot('embergate-rate-settings.png');
  await evaluate("document.getElementById('host-form').requestSubmit(document.querySelector('#host-form button[type=submit]'))");
  await wait("!document.getElementById('host-dialog').open && document.getElementById('hosts-body').textContent.includes('burst 10')");
  assert.deepEqual(config.routes[0].rate_limit,{requests:60,window_seconds:60,burst:10});
  assert.equal(await evaluate("document.getElementById('limited-hosts').textContent"),'1');
  assert.equal(await evaluate("document.getElementById('stat-limited').textContent"),'3');
  await evaluate("document.querySelector('[data-action=edit]').click()");
  assert.equal(await evaluate("document.getElementById('route-limit').checked"),true);
  assert.equal(await evaluate("document.getElementById('route-limit-burst').value"),'10');
  await evaluate("document.getElementById('host-dialog').close()");
  await evaluate("document.querySelector('[data-view=settings]').click();document.querySelector('[data-settings-link=trusted-proxies]').click();document.getElementById('edit-trusted').click();document.getElementById('cloudflare-trusted').click()");
  await wait("document.querySelectorAll('.trusted-row').length===2");
  await screenshot('embergate-trusted-proxies.png');
  await evaluate("document.getElementById('trusted-form').requestSubmit(document.querySelector('#trusted-form button[type=submit]'))");
  await wait("!document.getElementById('trusted-dialog').open && document.getElementById('trusted-summary').textContent.includes('2 trusted')");
  assert.equal(config.trusted_proxies[0].header,'cloudflare');
  assert.equal(config.trusted_proxies[0].trust_proto,true);
  await evaluate("document.querySelector('[data-view=hosts]').click();document.querySelector('[data-action=edit]').click();document.getElementById('pool-options').open=false;document.getElementById('rate-options').open=false;document.getElementById('advanced-options').open=true;document.getElementById('access-options').open=true;document.getElementById('route-access').click();document.getElementById('route-access-networks').value='203.0.113.0/24';document.getElementById('response-options').open=true;document.getElementById('route-response').click();document.getElementById('route-redirect').checked=true;document.getElementById('route-nosniff').checked=true;document.getElementById('route-hsts').value='300';document.getElementById('route-response-headers').value='X-App: EmberGate';document.getElementById('response-options').scrollIntoView({block:'start'})");
  await screenshot('embergate-response-policy.png');
  await evaluate("document.getElementById('host-form').requestSubmit(document.querySelector('#host-form button[type=submit]'))");
  await wait("!document.getElementById('host-dialog').open && document.getElementById('hosts-body').textContent.includes('Allowlist')");
  assert.equal(config.routes[0].access.mode,'allow');
  assert.deepEqual(config.routes[0].response.custom_headers,[{name:'X-App',value:'EmberGate'}]);
  await evaluate("document.querySelector('[data-action=edit]').click()");
  assert.equal(await evaluate("document.getElementById('host-steps').hidden && !document.getElementById('host-edit-sections').hidden"),true,'existing hosts should edit directly');
  assert.equal(await evaluate("document.querySelectorAll('#advanced-options summary > .policy-badge').length>=10 && document.querySelector('#rate-options > summary > .policy-badge').textContent"),'On','each policy section should show an on/off badge');
  await evaluate("document.getElementById('host-access-mode').value='http';document.getElementById('host-access-mode').dispatchEvent(new Event('change'));document.getElementById('host-access-mode').value='https';document.getElementById('host-access-mode').dispatchEvent(new Event('change'))");
  assert.equal(await evaluate("document.getElementById('route-response').checked && document.getElementById('route-nosniff').checked && document.getElementById('route-response-headers').value==='X-App: EmberGate'"),true,'access changes must preserve existing response headers');
  assert.equal(await evaluate("document.getElementById('route-hsts').value"),'300');
  assert.equal(await evaluate("document.getElementById('route-serialize').checked"),false,'session ordering is off by default');
  assert.equal(await evaluate("document.querySelector('#serialize-options > summary > .policy-badge').textContent"),'Off');
  await evaluate("document.getElementById('route-serialize').click()");
  assert.equal(await evaluate("document.querySelector('#serialize-options > summary > .policy-badge').textContent"),'On','badge follows the toggle');
  await evaluate("document.getElementById('host-form').requestSubmit(document.querySelector('#host-form button[type=submit]'))");
  await wait("!document.getElementById('host-dialog').open");
  assert.equal(config.routes[0].serialize_by_session,true,'toggle must persist serialize_by_session');
  await evaluate("document.querySelector('[data-action=edit]').click()");
  assert.equal(await evaluate("document.getElementById('route-serialize').checked"),true,'saved setting reloads into the editor');
  assert.ok(await evaluate("document.getElementById('advanced-summary').textContent.includes('Session ordering')"));
  await evaluate("document.getElementById('route-serialize').click();document.getElementById('host-form').requestSubmit(document.querySelector('#host-form button[type=submit]'))");
  await wait("!document.getElementById('host-dialog').open");
  assert.equal('serialize_by_session' in config.routes[0],false,'disabled toggle must omit the field');
  await evaluate("document.querySelector('[data-action=edit]').click()");
  assert.equal(await evaluate("document.getElementById('route-access-networks').value"),'203.0.113.0/24');
  await evaluate("document.getElementById('host-dialog').close();document.querySelector('[data-view=analytics]').click()");
  await wait("document.getElementById('history-requests').textContent==='12'");
  assert.equal(await evaluate("document.getElementById('history-latency').textContent"),'4.2 ms');
  assert.equal(await evaluate("document.getElementById('history-failed-latency').textContent"),'≤10 ms');
  assert.equal(await evaluate("document.getElementById('stat-latency').textContent"),'4.2 ms');
  assert.ok(await evaluate("document.getElementById('overview-timing-rows').textContent.includes('1.0 min')"));
  assert.ok(await evaluate("document.getElementById('history-timing-rows').textContent.includes('Client disconnects')"));
  assert.equal(await evaluate("document.getElementById('overview-timing-samples').textContent"),'6 successful web header samples');
  assert.equal(await evaluate("document.getElementById('history-blocked').textContent"),'5');
  await screenshot('embergate-analytics.png');
  await evaluate("document.getElementById('analytics-period').value='168';document.getElementById('analytics-period').dispatchEvent(new Event('change'))");
  await wait("document.getElementById('history-chart').getAttribute('aria-label').includes('168 hourly')");
  await evaluate("document.getElementById('analytics-host').selectedIndex=1;document.getElementById('analytics-host').dispatchEvent(new Event('change'))");
  await wait("document.querySelectorAll('#history-hosts tr').length===1");
  await evaluate("document.querySelector('[data-view=cache]').click();document.querySelector('[data-cache-action=edit]').click();document.getElementById('route-cache').click();document.getElementById('route-cache-ttl').value='120';document.getElementById('route-cache-size').value='512';document.getElementById('route-cache-query').checked=true");
  await screenshot('embergate-cache-settings.png');
  await evaluate("document.getElementById('host-form').requestSubmit(document.querySelector('#host-form button[type=submit]'))");
  await wait("!document.getElementById('host-dialog').open && document.getElementById('cache-body').textContent.includes('120s')");
  assert.deepEqual(config.routes[0].cache,{max_ttl_seconds:120,max_object_bytes:524288,cache_query_strings:true});
  await evaluate("document.querySelector('[data-view=hosts]').click();document.querySelector('[data-action=edit]').click();document.getElementById('advanced-options').open=true;document.getElementById('compression-options').open=true;document.getElementById('route-compression').click();document.getElementById('route-compression-level').value='3';document.getElementById('route-compression-min').value='2048'");
  await screenshot('embergate-compression-settings.png');
  const beforeCompressionInvalid=config.version;
  await evaluate("document.getElementById('advanced-options').open=false;document.getElementById('compression-options').open=false;document.getElementById('route-compression-level').value='7';document.getElementById('host-form').requestSubmit(document.querySelector('#host-form button[type=submit]'))");
  assert.equal(config.version,beforeCompressionInvalid);
  assert.equal(await evaluate("document.getElementById('advanced-options').open && document.getElementById('compression-options').open"),true);
  await evaluate("document.getElementById('route-compression-level').value='3';document.getElementById('host-form').requestSubmit(document.querySelector('#host-form button[type=submit]'))");
  await wait("!document.getElementById('host-dialog').open && document.getElementById('hosts-body').textContent.includes('Brotli / gzip')");
  assert.deepEqual(config.routes[0].compression,{mode:'auto',level:3,min_bytes:2048});
  await evaluate("document.querySelector('[data-action=edit]').click();document.getElementById('route-compression-mode').value='gzip';document.getElementById('host-form').requestSubmit(document.querySelector('#host-form button[type=submit]'))");
  await wait("!document.getElementById('host-dialog').open");
  assert.equal(config.routes[0].compression.mode,'gzip');

  await evaluate("document.querySelector('[data-view=hosts]').click();document.querySelector('[data-action=edit]').click()");
  assert.equal(await evaluate("document.getElementById('advanced-options').open"),false);
  assert.ok(await evaluate("document.getElementById('advanced-summary').textContent.includes('Caching')"));
  const beforeHiddenValidation=config.version;
  await evaluate("document.getElementById('route-cache-ttl').value='';document.getElementById('host-form').requestSubmit(document.querySelector('#host-form button[type=submit]'))");
  assert.equal(config.version,beforeHiddenValidation);
  assert.equal(await evaluate("document.getElementById('advanced-options').open && document.getElementById('cache-options').open"),true,'invalid nested fields must be revealed');
  await evaluate("document.getElementById('route-cache-ttl').value='120';document.getElementById('host-dialog').close();document.querySelector('[data-view=cache]').click()");
  assert.equal(await evaluate("document.getElementById('cache-hit-ratio').textContent"),'80.0%');
  await screenshot('embergate-caching.png');
  await evaluate("document.querySelector('[data-cache-action=purge]').click();document.getElementById('cache-purge-url').value='/assets/app.js?v=2';document.getElementById('cache-purge-form').requestSubmit(document.querySelector('#cache-purge-form button[type=submit]'))");
  await wait("!document.getElementById('cache-purge-dialog').open && document.getElementById('cache-entries').textContent==='0'");
  assert.equal(cachePurges[0].route_id,config.routes[0].id);assert.equal(cachePurges[0].url,'/assets/app.js?v=2');
  await evaluate("document.getElementById('open-cache-purge').click();document.getElementById('cache-purge-form').requestSubmit(document.querySelector('#cache-purge-form button[type=submit]'))");
  await wait("!document.getElementById('cache-purge-dialog').open");
  assert.deepEqual(cachePurges[1],{route_id:null,url:null});
  await evaluate("document.querySelector('[data-view=hosts]').click();document.querySelector('[data-action=diagnostics]').click()");
  assert.equal(await evaluate("document.getElementById('diagnostics-view').hidden"),false);
  assert.equal(await evaluate("document.getElementById('diagnostics-route').value"),config.routes[0].id);
  assert.equal(diagnosticInputs.length,0,'opening diagnostics must not probe');
  await evaluate("document.getElementById('diagnostics-form').requestSubmit(document.getElementById('diagnostics-preview'))");
  await wait("document.getElementById('diagnostics-results').textContent.includes('Route matched') && document.getElementById('diagnostics-progress').hidden");
  assert.equal(diagnosticInputs.at(-1).probe,false);assert.equal(await evaluate("document.querySelectorAll('.diagnostic-backend').length"),0);
  assert.equal(await evaluate("document.querySelector('#diagnostics-results script')"),null,'diagnostics injected markup');
  assert.ok(await evaluate("document.getElementById('diagnostics-results').textContent.includes('<script>Diagnostics values stay plain text.</script>')"));
  await evaluate("document.getElementById('diagnostics-form').requestSubmit(document.getElementById('diagnostics-run'))");
  await wait("document.querySelectorAll('.diagnostic-backend').length===2 && document.getElementById('diagnostics-progress').hidden");
  assert.equal(diagnosticInputs.at(-1).probe,true);assert.ok(await evaluate("document.getElementById('diagnostics-results').textContent.includes('Connection refused')"));
  await screenshot('embergate-diagnostics.png');
  await evaluate("document.getElementById('diagnostics-host').value='unmatched.test';document.getElementById('diagnostics-form').requestSubmit(document.getElementById('diagnostics-preview'))");
  await wait("document.getElementById('diagnostics-results').textContent.includes('No active route matched')");
  await evaluate("document.querySelector('[data-view=hosts]').click()");
  await call('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:true});
  await evaluate("document.getElementById('add-host').click()");
  assert.equal(await evaluate("document.getElementById('host-dialog').scrollWidth<=document.getElementById('host-dialog').clientWidth"),true,'destination must fit mobile');
  await screenshot('embergate-host-wizard-destination-mobile.png');
  await evaluate("document.getElementById('route-name').value='<script>Check host</script>';document.getElementById('route-host').value='wizard-check.test';document.getElementById('route-upstream').value='http://127.0.0.1:9000';document.getElementById('host-next').click();document.getElementById('host-next').click()");
  assert.equal(await evaluate("document.querySelector('#host-review-summary script')===null && document.getElementById('host-review-summary').textContent.includes('<script>Check host</script>')"),true,'review text must escape untrusted input');
  await call('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:true});
  assert.equal(await evaluate("document.getElementById('host-dialog').scrollWidth<=document.getElementById('host-dialog').clientWidth"),true,'wizard review must fit mobile');
  await screenshot('embergate-host-wizard-mobile.png');
  await evaluate("document.getElementById('host-form').requestSubmit(document.getElementById('host-save-check'))");
  await wait("!document.getElementById('host-dialog').open && !document.getElementById('diagnostics-view').hidden && document.getElementById('diagnostics-results').textContent.includes('wizard-check.test') && document.getElementById('diagnostics-progress').hidden");
  assert.equal(config.routes.length,2);assert.equal(diagnosticInputs.at(-1).probe,true);
  assert.equal(await evaluate("document.querySelector('.diagnostic-backend').textContent.includes('Reachable')"),true);
  const checkedHost=config.routes.find(route=>route.host==='wizard-check.test');
  await evaluate(`document.querySelector('[data-view=hosts]').click();document.querySelector('[data-action=delete][data-id="${checkedHost.id}"]').click();document.getElementById('confirm-action').click()`);
  await wait("!document.getElementById('confirm-dialog').open && document.querySelectorAll('[data-action=edit]').length===1");
  await call('Emulation.setDeviceMetricsOverride',{width:1440,height:1080,deviceScaleFactor:1,mobile:false});
  await evaluate("document.querySelector('[data-view=hosts]').click();document.querySelector('[data-action=edit]').click();document.getElementById('advanced-options').open=true;document.getElementById('pages-options').open=true;document.getElementById('route-maintenance').click();document.getElementById('route-maintenance-title').value='Planned service upgrade';document.getElementById('route-maintenance-message').value='<script>plain text only</script>';document.getElementById('route-maintenance-retry').value='600';document.getElementById('route-maintenance-message').dispatchEvent(new Event('input'))");
  assert.equal(await evaluate("document.querySelector('#maintenance-preview-message script')"),null,'maintenance preview injected markup');
  assert.equal(await evaluate("document.getElementById('maintenance-preview-message').textContent"),'<script>plain text only</script>');
  await evaluate("document.getElementById('maintenance-fields').scrollIntoView({block:'center'})");
  await screenshot('embergate-maintenance-settings.png');
  await evaluate("document.getElementById('host-form').requestSubmit(document.querySelector('#host-form button[type=submit]'))");
  await wait("!document.getElementById('host-dialog').open && document.getElementById('hosts-body').textContent.includes('Maintenance')");
  assert.equal(config.routes[0].pages.maintenance,true);assert.equal(config.routes[0].pages.retry_after_seconds,600);
  await evaluate("document.querySelector('[data-action=edit]').click()");
  assert.equal(await evaluate("document.getElementById('route-maintenance-title').value"),'Planned service upgrade');
  assert.equal(await evaluate("document.getElementById('route-maintenance').checked"),true);
  await evaluate("document.getElementById('host-dialog').close();document.querySelector('[data-action=maintenance]').click()");
  assert.equal(await evaluate("document.getElementById('confirm-title').textContent"),'End maintenance?');
  await evaluate("document.getElementById('confirm-action').click()");
  await wait("!document.getElementById('confirm-dialog').open && !document.getElementById('hosts-body').textContent.includes('Maintenance')");
  assert.equal(config.routes[0].pages.maintenance,false);assert.equal(config.routes[0].pages.title,'Planned service upgrade');
  await evaluate("document.querySelector('[data-action=maintenance]').click();document.getElementById('confirm-action').click()");
  await wait("!document.getElementById('confirm-dialog').open && document.getElementById('hosts-body').textContent.includes('Maintenance')");
  await evaluate("document.querySelector('[data-action=maintenance]').click();document.getElementById('confirm-action').click()");
  await wait("!document.getElementById('confirm-dialog').open && !document.getElementById('hosts-body').textContent.includes('Maintenance')");
  await evaluate("document.querySelector('[data-view=traffic]').click()");
  assert.equal(await evaluate("document.querySelectorAll('#logs-body script').length"),0);
  assert.ok(await evaluate("document.getElementById('logs-body').textContent.includes('<script>')"));
  assert.ok(await evaluate("document.getElementById('logs-body').textContent.includes('Gateway limit')"));
  assert.ok(await evaluate("document.getElementById('logs-body').textContent.includes('203.0.113.5')"));
  assert.ok(await evaluate("document.getElementById('logs-body').textContent.includes('Cache HIT')"));
  await evaluate("document.querySelector('[data-view=overview]').click()");
  assert.equal(await evaluate("document.getElementById('hosts-section').hidden && !document.getElementById('overview-view').hidden"),true);
  await evaluate("document.querySelector('[data-view=hosts]').click()");
  assert.equal(await evaluate("!document.getElementById('hosts-section').hidden && document.getElementById('overview-view').hidden"),true);
  await evaluate("document.querySelector('[data-view=overview]').click()");
  const overviewScreenshot=await call('Page.captureScreenshot',{format:'png',captureBeyondViewport:true});
  const screenshotPath=process.env.SCREENSHOT_PATH || join(tmpdir(),'embergate-dashboard.png');
  writeFileSync(screenshotPath,Buffer.from(overviewScreenshot.data,'base64'));
  await evaluate("document.getElementById('theme').click()");
  assert.equal(await evaluate("getComputedStyle(document.documentElement).backgroundColor"),'rgb(24, 24, 27)','dark page canvas');
  assert.equal(await evaluate("getComputedStyle(document.body).backgroundColor"),'rgb(24, 24, 27)','dark body canvas');
  assert.equal(await evaluate("getComputedStyle(document.getElementById('page-title')).color"),'rgb(242, 242, 243)','dark heading color');
  await evaluate("document.getElementById('add-host').click()");
  assert.equal(await evaluate("getComputedStyle(document.getElementById('host-dialog')).backgroundColor"),'rgb(34, 34, 37)','dark dialog');
  assert.equal(await evaluate("getComputedStyle(document.getElementById('route-name')).backgroundColor"),'rgb(34, 34, 37)','dark input');
  await evaluate("document.getElementById('host-dialog').close()");
  await reload();
  await wait("document.getElementById('app') && !document.getElementById('app').hidden && document.getElementById('stat-requests').textContent === '2'");
  assert.equal(await evaluate("document.documentElement.dataset.theme"),'dark','theme survives reload');
  await evaluate("document.querySelector('[data-view=certificates]').click();document.getElementById('add-certificate').click();document.getElementById('certificate-name').value='Browser certificate'");
  const certificateFile=join(profile,'certificate.pem'), keyFile=join(profile,'private.key');
  writeFileSync(certificateFile,'PEM certificate fixture'); writeFileSync(keyFile,'PEM key fixture');
  async function attachFiles() {
    const {root}=await call('DOM.getDocument');
    for(const [selector,path] of [['#certificate-chain',certificateFile],['#certificate-key',keyFile]]) {
      const {nodeId}=await call('DOM.querySelector',{nodeId:root.nodeId,selector});
      await call('DOM.setFileInputFiles',{nodeId,files:[path]});
    }
  }
  await attachFiles();
  await evaluate("document.getElementById('certificate-form').requestSubmit(document.querySelector('#certificate-form button[type=submit]'))");
  // The dialog's close event resets file inputs asynchronously after open becomes false.
  await wait("!document.getElementById('certificate-dialog').open && document.getElementById('nav-cert-count').textContent==='1' && document.getElementById('certificate-key').files.length===0 && document.getElementById('certificate-chain').files.length===0");
  assert.equal(certificateInput.private_key_pem,'PEM key fixture','key file sent to API');
  assert.equal(await evaluate("document.getElementById('certificate-key').files.length"),0,'key selection cleared after save');
  assert.ok(await evaluate("document.getElementById('certificates-body').textContent.includes('Browser certificate')"));
  await screenshot('embergate-certificates-dark.png');
  await evaluate("document.querySelector('[data-cert-action=replace]').click();document.getElementById('certificate-name').value='Renewed certificate'");
  await attachFiles();
  await evaluate("document.getElementById('certificate-form').requestSubmit(document.querySelector('#certificate-form button[type=submit]'))");
  await wait("!document.getElementById('certificate-dialog').open && document.getElementById('certificates-body').textContent.includes('Renewed certificate') && document.getElementById('certificate-key').files.length===0 && document.getElementById('certificate-chain').files.length===0");
  await evaluate("document.querySelector('[data-cert-action=delete]').click();document.getElementById('confirm-action').click()");
  await wait("!document.getElementById('confirm-dialog').open && document.getElementById('nav-cert-count').textContent==='0'");
  await evaluate("document.getElementById('request-certificate').click();document.getElementById('acme-name').value='Automatic certificate';document.getElementById('acme-domains').value='example.test, *.example.test';document.getElementById('acme-email').value='admin@example.test';document.getElementById('acme-terms').checked=true;document.getElementById('acme-form').requestSubmit(document.querySelector('#acme-form button[type=submit]'))");
  await wait("!document.getElementById('acme-dialog').open && document.getElementById('managed-count').textContent==='1'");
  assert.deepEqual(managedOrders[0].domains,['example.test','*.example.test']);
  assert.equal(managedOrders[0].environment,'staging');
  assert.equal(managedOrders[0].auto_renew,true);
  managedOrders[0].status='ready';managedOrders[0].phase='Certificate active';managedOrders[0].renew_at=Date.now()/1000+86400;
  await evaluate("document.dispatchEvent(new Event('visibilitychange'))");
  await wait("document.getElementById('managed-body').textContent.includes('Active')");
  await evaluate("document.querySelector('[data-acme-action=production]').click();document.getElementById('confirm-action').click()");
  await wait("!document.getElementById('confirm-dialog').open && document.getElementById('managed-body').textContent.includes('Production')");
  managedOrders[0].status='ready';managedOrders[0].phase='Certificate active';
  await evaluate("document.dispatchEvent(new Event('visibilitychange'))");
  await wait("document.getElementById('managed-body').textContent.includes('Active')");
  await evaluate("document.querySelector('[data-acme-action=renew]').click();document.getElementById('confirm-action').click()");
  await wait("!document.getElementById('confirm-dialog').open && document.getElementById('managed-body').textContent.includes('Queued')");
  await evaluate("document.querySelector('[data-acme-action=stop]').click();document.getElementById('confirm-action').click()");
  await wait("!document.getElementById('confirm-dialog').open && document.getElementById('managed-count').textContent==='0'");
  await evaluate("document.querySelector('[data-view=overview]').click()");
  const darkScreenshot=await call('Page.captureScreenshot',{format:'png',captureBeyondViewport:true});
  writeFileSync(join(tmpdir(),'embergate-dashboard-dark.png'),Buffer.from(darkScreenshot.data,'base64'));
  await openSettings('cloudflare');
  await wait("document.getElementById('cloudflare-token-status').textContent.includes('No token configured')");
  await evaluate("document.getElementById('cloudflare-token').value='browser-private-token';document.getElementById('cloudflare-token-form').requestSubmit(document.getElementById('save-cloudflare-token'))");
  await wait("document.getElementById('cloudflare-token-status').textContent.includes('A saved token')");
  assert.equal(cloudflareToken,'browser-private-token');
  assert.equal(await evaluate("document.getElementById('cloudflare-token').value"),'');
  await screenshot('embergate-settings-dark.png');
  await evaluate("document.getElementById('remove-cloudflare-token').click();document.getElementById('confirm-action').click()");
  await wait("!document.getElementById('confirm-dialog').open && document.getElementById('cloudflare-token-status').textContent.includes('No token configured')");
  assert.equal(cloudflareToken,null);
  await evaluate("document.querySelector('[data-view=overview]').click()");
  await call('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:true});
  assert.equal(await evaluate('document.documentElement.scrollWidth <= 390'),true,'page overflow on mobile');
  await screenshot('embergate-dashboard-mobile.png');
  await evaluate("document.querySelector('[data-view=analytics]').click()");
  await wait("document.getElementById('history-requests').textContent==='12'");
  assert.equal(await evaluate('document.documentElement.scrollWidth <= 390'),true,'analytics overflow on mobile');
  await screenshot('embergate-analytics-mobile-dark.png');
  await evaluate("document.querySelector('[data-view=cache]').click()");
  assert.equal(await evaluate('document.documentElement.scrollWidth <= 390'),true,'cache page overflow on mobile');
  await screenshot('embergate-caching-mobile-dark.png');
  await openSettings('cloudflare');
  await wait("document.getElementById('cloudflare-token-status').textContent.includes('No token configured')");
  assert.equal(await evaluate('document.documentElement.scrollWidth <= 390'),true,'credential settings overflow on mobile');
  await openSettings('backups');
  await evaluate("document.getElementById('download-full-backup').click()");
  assert.equal(await evaluate("document.getElementById('backup-dialog').scrollWidth<=document.getElementById('backup-dialog').clientWidth"),true,'backup dialog overflow on mobile');
  await screenshot('embergate-backup-mobile-dark.png');
  await evaluate("document.getElementById('backup-dialog').close()");
  await openSettings('cloudflare');
  assert.equal(await evaluate("getComputedStyle(document.getElementById('settings-sidebar')).display==='none' && getComputedStyle(document.querySelector('.settings-mobile-navigation')).display!=='none'"),true);
  await screenshot('embergate-credentials-mobile-dark.png');
  await evaluate("document.querySelector('[data-view=help]').click()");
  await wait("!document.getElementById('help-article').hidden");
  assert.equal(await evaluate("getComputedStyle(document.querySelector('.help-mobile-topics')).display!=='none' && getComputedStyle(document.getElementById('help-navigation')).display==='none'"),true);
  await evaluate("document.getElementById('help-topic-select').value='getting-started';document.getElementById('help-topic-select').dispatchEvent(new Event('change'))");
  await wait("location.hash==='#/help/getting-started'");
  assert.equal(await evaluate("document.documentElement.scrollWidth<=innerWidth"),true,'help must not overflow on mobile');
  await screenshot('embergate-help-mobile-dark.png');
  await openSettings('instances');await wait("!document.getElementById('cluster-editor').disabled");assert.equal(await evaluate("document.documentElement.scrollWidth<=innerWidth"),true,'instance settings must fit mobile');await screenshot('embergate-instances-mobile-dark.png');

  await evaluate("document.querySelector('[data-view=hosts]').click();document.querySelector('[data-action=edit]').click();document.getElementById('advanced-options').open=true;document.getElementById('forward-auth-options').open=true;document.getElementById('route-forward-auth').click()");
  assert.equal(await evaluate("document.getElementById('host-dialog').scrollWidth<=document.getElementById('host-dialog').clientWidth"),true,'application login controls must fit mobile');
  await screenshot('embergate-forward-auth-mobile-dark.png');
  await evaluate("document.getElementById('host-dialog').close()");


  await evaluate("document.querySelector('[data-view=hosts]').click();document.querySelector('[data-action=edit]').click();document.getElementById('advanced-options').open=true;document.getElementById('pool-options').open=true;document.getElementById('advanced-options').open=true;document.getElementById('reliability-options').open=true;document.getElementById('advanced-options').open=true;document.getElementById('routing-options').open=true;document.getElementById('advanced-options').open=true;document.getElementById('pages-options').open=true;document.getElementById('route-maintenance').click()");
  assert.equal(await evaluate("document.getElementById('host-dialog').scrollWidth<=document.getElementById('host-dialog').clientWidth"),true,'backend controls overflow on mobile');
  await screenshot('embergate-reliability-mobile-dark.png');
  await evaluate("document.getElementById('routing-fields').scrollIntoView({block:'center'})");
  assert.equal(await evaluate("document.getElementById('route-preview').scrollWidth<=document.getElementById('route-preview').clientWidth"),true,'routing preview overflow on mobile');
  assert.equal(await evaluate("getComputedStyle(document.querySelector('.routing-preview')).backgroundColor"),'rgb(24, 24, 27)','dark routing preview');
  await screenshot('embergate-routing-mobile-dark.png');
  await evaluate("document.getElementById('maintenance-fields').scrollIntoView({block:'center'})");
  assert.equal(await evaluate("document.querySelector('.maintenance-preview').scrollWidth<=document.querySelector('.maintenance-preview').clientWidth"),true,'maintenance preview overflow on mobile');
  assert.equal(await evaluate("getComputedStyle(document.querySelector('.maintenance-preview')).backgroundColor"),'rgb(24, 24, 27)','dark maintenance preview');
  await screenshot('embergate-maintenance-mobile-dark.png');
  await evaluate("document.getElementById('pages-options').open=false;document.getElementById('compression-options').open=true;document.getElementById('compression-options').scrollIntoView({block:'start'})");
  assert.equal(await evaluate("document.getElementById('route-compression').checked"),true);
  await screenshot('embergate-compression-mobile-dark.png');
  await evaluate("document.getElementById('host-dialog').close()");

  await evaluate("document.querySelector('[data-view=overview]').click()");
  await evaluate("document.getElementById('mobile-menu').click()");
  assert.equal(await evaluate("document.getElementById('mobile-menu').getAttribute('aria-expanded')"),'true');
  await evaluate("document.querySelector('[data-view=hosts]').click();document.querySelector('[data-action=diagnostics]').click();document.getElementById('diagnostics-form').requestSubmit(document.getElementById('diagnostics-run'))");
  await wait("document.querySelectorAll('.diagnostic-backend').length===2 && document.getElementById('diagnostics-progress').hidden");
  assert.equal(await evaluate('document.documentElement.scrollWidth <= 390'),true,'diagnostics overflow on mobile');
  await screenshot('embergate-diagnostics-mobile-dark.png');
  const templateSource=structuredClone(config.routes[0]),beforeTemplate=config.version;
  await openSettings('cloudflare');
  await openSettings('templates');
  await wait("!document.getElementById('create-template').disabled");
  await evaluate("document.getElementById('create-template').click();document.querySelector('[data-settings-link=instance]').click()");
  await delay(200);
  assert.equal(await evaluate("document.getElementById('template-dialog').open"),false,'a template request must not open a modal after leaving its page');
  await openSettings('templates');

  await evaluate("document.getElementById('create-template').click()");
  await wait("document.getElementById('template-dialog').open");
  await evaluate("document.getElementById('template-name').value='Public <img src=x>';document.getElementById('template-description').value='Shared browser policies';document.getElementById('template-source').selectedIndex=1;document.getElementById('template-form').requestSubmit(document.getElementById('template-save'))");
  await wait("!document.getElementById('template-dialog').open && document.querySelectorAll('[data-edit-template]').length===1");
  assert.equal(config.version,beforeTemplate);assert.equal(templateStore.templates.length,1);
  assert.equal(await evaluate("document.querySelector('#templates-list img')===null"),true);
  assert.ok(await evaluate("document.getElementById('templates-list').textContent.includes('Public <img src=x>')"));
  // Deliver the previous dialog close after the next edit has started loading.
  await evaluate("document.querySelector('[data-edit-template]').click();document.getElementById('template-dialog').dispatchEvent(new Event('close'))");
  await wait("document.getElementById('template-dialog').open");
  assert.equal(await evaluate("document.getElementById('template-source').value"),'');
  await evaluate("document.getElementById('template-name').value='Public reusable policies';document.getElementById('template-form').requestSubmit(document.getElementById('template-save'))");
  await wait("!document.getElementById('template-dialog').open && document.getElementById('templates-list').textContent.includes('Public reusable policies')");
  await evaluate("document.querySelector('[data-edit-template]').click()");
  await wait("document.getElementById('template-dialog').open");
  config.version++;
  await evaluate("document.getElementById('template-source').selectedIndex=1;document.getElementById('template-form').requestSubmit(document.getElementById('template-save'))");
  await wait("document.getElementById('template-error').textContent.includes('changed')");
  assert.equal(await evaluate("document.getElementById('template-save').disabled"),true);
  await evaluate("document.querySelector('#template-dialog .close-dialog').click()");
  await wait("!document.getElementById('template-dialog').open");
  assert.equal(await evaluate('document.documentElement.scrollWidth<=390'),true,'template library overflows on mobile');
  await evaluate("document.getElementById('host-templates-card').scrollIntoView({block:'start'})");
  await screenshot('embergate-host-templates-mobile-dark.png');
  await evaluate("document.dispatchEvent(new Event('visibilitychange'))");
  await wait("document.getElementById('config-version').textContent==='Revision "+config.version+"'");
  await evaluate("document.querySelector('[data-view=hosts]').click();document.querySelector('[data-action=duplicate]').click()");
  await wait("document.getElementById('host-dialog').open && document.getElementById('host-preset-templates').children.length===1");
  assert.equal(await evaluate("document.getElementById('route-host').value"),'');
  assert.equal(await evaluate("document.getElementById('route-status').value"),'paused');
  assert.notEqual(await evaluate("document.getElementById('route-id').value"),templateSource.id);
  assert.equal(await evaluate("document.getElementById('duplicate-host-note').hidden"),false);
  await evaluate("document.getElementById('route-name').value='Browser duplicate';document.getElementById('route-host').value='copy.test.local';document.getElementById('route-limit-burst').value='3';document.getElementById('host-next').click();document.getElementById('host-next').click();document.getElementById('advanced-options').open=true;document.getElementById('host-preset').value=document.getElementById('host-preset-templates').children[0].value;document.getElementById('host-preset').dispatchEvent(new Event('change'));document.getElementById('host-preset-apply').click()");
  await wait("document.getElementById('confirm-dialog').open");
  await screenshot('embergate-template-review-mobile-dark.png');
  const beforeApplyVersion=config.version;
  await evaluate("document.getElementById('confirm-action').click()");
  await wait("!document.getElementById('confirm-dialog').open");
  assert.equal(config.version,beforeApplyVersion,'applying a template must only edit the draft');
  assert.equal(await evaluate("document.getElementById('route-host').value"),'copy.test.local');
  assert.equal(await evaluate("document.getElementById('route-name').value"),'Browser duplicate');
  assert.equal(await evaluate("document.getElementById('route-limit-burst').value"),String(templateSource.rate_limit.burst));
  assert.equal(await evaluate("document.getElementById('route-additional').value"),templateSource.additional_upstreams.join('\n'));
  assert.equal(await evaluate("document.getElementById('route-maintenance').checked"),Boolean(templateSource.pages?.maintenance));
  assert.equal(await evaluate("document.getElementById('host-save-check').hidden"),true,'paused copies should not offer a live backend check');
  await evaluate("document.getElementById('host-form').requestSubmit(document.querySelector('#host-form button[type=submit]'))");
  await wait("!document.getElementById('host-dialog').open && document.querySelectorAll('[data-action=duplicate]').length===2");
  assert.equal(config.routes.length,2);assert.equal(config.routes[1].enabled,false);assert.deepEqual(config.routes[0],templateSource);
  assert.ok(await evaluate("document.getElementById('toast').textContent.includes('paused mode')"));
  assert.deepEqual(config.routes[1].balancing,templateSource.balancing);assert.deepEqual(config.routes[1].routing,templateSource.routing);
  assert.deepEqual(config.routes[1].compression,templateSource.compression);
  await evaluate("Array.from(document.querySelectorAll('[data-action=delete]')).at(-1).click();document.getElementById('confirm-action').click()");
  await wait("!document.getElementById('confirm-dialog').open && document.querySelectorAll('[data-action=duplicate]').length===1");
  await openSettings('cloudflare');
  await openSettings('templates');
  await wait("Boolean(document.querySelector('[data-delete-template]'))");
  const beforeDeleteTemplate=config.version;
  await evaluate("document.querySelector('[data-delete-template]').click();document.getElementById('confirm-action').click()");
  await wait("!document.getElementById('confirm-dialog').open && document.getElementById('templates-list').textContent.includes('No templates yet')");
  assert.equal(config.version,beforeDeleteTemplate);assert.deepEqual(config.routes[0],templateSource);
  await evaluate("document.querySelector('[data-view=hosts]').click();document.querySelector('[data-action=delete]').click();document.getElementById('confirm-action').click()");
  await wait("!document.getElementById('confirm-dialog').open && document.getElementById('nav-count').textContent==='0'");
  assert.equal(config.routes.length,0);
  await openSettings('cloudflare');
  await wait("document.getElementById('backup-status').textContent.includes('No restore')");
  await call('Page.setDownloadBehavior',{behavior:'allow',downloadPath:profile});
  await openSettings('backups');
  await evaluate("document.getElementById('download-full-backup').click();document.getElementById('backup-passphrase').value='fixture-backup-passphrase';document.getElementById('backup-passphrase-confirm').value='mismatched-fixture';document.getElementById('backup-form').requestSubmit(document.getElementById('backup-submit'))");
  await wait("document.getElementById('backup-dialog-error').textContent.includes('do not match')");
  assert.equal(await evaluate("document.getElementById('backup-passphrase-confirm').getAttribute('aria-describedby')"),'backup-dialog-error');
  assert.equal(backupExportInput,null);
  await evaluate("document.getElementById('backup-passphrase').value='fixture-backup-passphrase';document.getElementById('backup-passphrase-confirm').value='fixture-backup-passphrase';document.getElementById('backup-form').requestSubmit(document.getElementById('backup-submit'))");
  await wait("!document.getElementById('backup-dialog').open");
  assert.equal(backupExportInput.passphrase,'fixture-backup-passphrase');
  assert.equal(await evaluate("document.getElementById('backup-passphrase').value"),'');
  await openSettings('security');
  await wait("document.getElementById('mfa-status').textContent.includes('Not enabled')");
  await evaluate("document.getElementById('mfa-enable').click();document.getElementById('mfa-password').value='setup-password-123';document.getElementById('mfa-form').requestSubmit(document.getElementById('mfa-submit'))");
  await wait("!document.getElementById('mfa-enrollment-fields').hidden");
  assert.equal(await evaluate("document.getElementById('mfa-password').value"),'');
  assert.equal(await evaluate("document.getElementById('mfa-secret').value"),'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567');
  await evaluate("document.getElementById('mfa-confirm-code').value='123456';document.getElementById('mfa-form').requestSubmit(document.getElementById('mfa-submit'))");
  await wait("!document.getElementById('mfa-recovery-result').hidden");
  const onceOnlyCodes=await evaluate("document.getElementById('mfa-recovery-codes').textContent");
  await evaluate("location.hash='#/settings/cloudflare'");
  await wait("!document.getElementById('settings-page-cloudflare').hidden");
  assert.equal(await evaluate("document.getElementById('mfa-dialog').open"),true,'navigation must preserve the recovery-code acknowledgement');
  assert.equal(await evaluate("document.getElementById('mfa-recovery-codes').textContent"),onceOnlyCodes);

  assert.equal(await evaluate("document.getElementById('mfa-recovery-codes').textContent.split('\\n').length"),10);
  assert.equal(await evaluate("document.getElementById('mfa-dialog').scrollWidth<=document.getElementById('mfa-dialog').clientWidth"),true,'MFA dialog overflow on mobile');
  await screenshot('embergate-mfa-recovery-mobile-dark.png');
  await evaluate("document.getElementById('mfa-form').requestSubmit(document.getElementById('mfa-submit'))");
  assert.equal(await evaluate("document.getElementById('mfa-dialog').open"),true,'recovery codes require confirmation');
  await evaluate("document.getElementById('mfa-saved-codes').checked=true;document.getElementById('mfa-form').requestSubmit(document.getElementById('mfa-submit'))");
  await wait("!document.getElementById('mfa-dialog').open && document.getElementById('mfa-status').textContent.includes('Enabled') && document.getElementById('mfa-recovery-codes').textContent===''");
  assert.equal(await evaluate("document.getElementById('mfa-recovery-codes').textContent"),'');
  await openSettings('security');
  await evaluate("document.getElementById('mfa-policy').click();document.getElementById('mfa-password').value='setup-password-123';document.getElementById('mfa-existing-code').value='123456';document.getElementById('mfa-require-admins').checked=true;document.getElementById('mfa-form').requestSubmit(document.getElementById('mfa-submit'))");
  await wait("!document.getElementById('mfa-dialog').open && document.getElementById('mfa-disable').disabled");
  assert.equal(mfaPolicy,true);
  await openSettings('history');
  await wait("Boolean(document.querySelector('[data-review-config]'))");
  await evaluate("document.querySelector('[data-review-config]').click();document.querySelector('[data-settings-link=instance]').click()");
  await delay(200);
  assert.equal(await evaluate("document.getElementById('config-history-dialog').open"),false,'a comparison must not open after leaving its page');
  await openSettings('history');

  await evaluate("document.querySelector('[data-review-config]').click()");
  await wait("document.getElementById('config-history-dialog').open");
  assert.equal(await evaluate("document.querySelector('#config-history-diff script, #config-history-diff img')===null"),true,'history comparisons escape markup');
  await evaluate("document.querySelectorAll('#config-history-diff details').forEach(el=>el.open=true)");
  assert.ok(await evaluate("document.getElementById('config-history-diff').textContent.includes('Host <script>bad</script>')"));
  assert.equal(await evaluate("document.getElementById('config-history-dialog').scrollWidth<=document.getElementById('config-history-dialog').clientWidth"),true);
  assert.ok(await evaluate("document.getElementById('config-history-diff').textContent.includes('Restored host')"));
  await screenshot('embergate-config-history-mobile-dark.png');
  await evaluate("document.querySelector('#config-history-dialog .close-dialog').click()");
  await wait("!document.getElementById('config-history-dialog').open && document.getElementById('config-history-diff').textContent===''");
  await evaluate("document.querySelector('[data-review-config]').click()");
  await wait("document.getElementById('config-history-dialog').open");
  config.version++;
  await evaluate("document.getElementById('config-history-apply').click()");
  await wait("document.getElementById('config-history-review-error').textContent.includes('changed since')");
  assert.equal(await evaluate("document.getElementById('config-history-apply').disabled"),true);
  await evaluate("document.getElementById('config-history-dialog').close()");
  await delay(100);
  await evaluate("document.querySelector('[data-review-config]').click()");
  await wait("document.getElementById('config-history-dialog').open");
  const historyVersion=config.version;
  await evaluate("document.getElementById('config-history-apply').click()");
  await wait("!document.getElementById('config-history-dialog').open");
  assert.equal(config.version,historyVersion+1);
  await openSettings('automatic-backups');
  await wait("document.getElementById('backup-schedule-badge').textContent==='Disabled'");
  assert.equal(await evaluate("document.getElementById('backup-schedule-run').disabled"),true);
  await evaluate("document.getElementById('backup-schedule-enabled').click();document.getElementById('backup-schedule-form').requestSubmit(document.getElementById('backup-schedule-save'))");
  assert.equal(await evaluate("document.getElementById('backup-schedule-passphrase').closest('details').open"),true,'invalid schedule passphrase should open its section');
  assert.equal(scheduleLastInput,null);
  await evaluate("document.getElementById('backup-schedule-passphrase').value='automatic-fixture-passphrase';document.getElementById('backup-schedule-confirm').value='automatic-fixture-passphrase';document.getElementById('backup-schedule-hours').value='6';document.getElementById('backup-schedule-retain').value='3';document.getElementById('backup-schedule-form').requestSubmit(document.getElementById('backup-schedule-save'))");
  await wait("document.getElementById('backup-schedule-badge').textContent==='Enabled' && !document.getElementById('backup-schedule-run').disabled");
  assert.equal(scheduleLastInput.passphrase,'automatic-fixture-passphrase');assert.equal(schedule.settings.interval_hours,6);assert.equal(schedule.settings.retain_count,3);
  assert.equal(await evaluate("document.getElementById('backup-schedule-passphrase').value"),'');
  await evaluate("document.getElementById('backup-schedule-offsite').closest('details').open=true;document.getElementById('backup-schedule-offsite').click();document.getElementById('backup-schedule-url').value='https://backup.example.com/private/';document.getElementById('backup-schedule-auth').value='bearer';document.getElementById('backup-schedule-auth').dispatchEvent(new Event('change'));document.getElementById('backup-schedule-secret').value='fixture-upload-secret';document.getElementById('backup-schedule-form').requestSubmit(document.getElementById('backup-schedule-save'))");
  await wait("document.getElementById('backup-schedule-destination-status').textContent.includes('https://backup.example.com')");
  assert.equal(scheduleLastInput.auth.secret,'fixture-upload-secret');assert.equal(await evaluate("document.getElementById('backup-schedule-secret').value"),'');
  await evaluate("document.getElementById('backup-schedule-run').click()");
  await wait("document.querySelectorAll('[data-scheduled-download]').length===1");
  assert.equal(await evaluate('document.documentElement.scrollWidth <= 390'),true,'scheduled backups overflow on mobile');
  await evaluate("document.getElementById('backup-schedule-card').scrollIntoView({block:'start'})");
  await screenshot('embergate-scheduled-backups-mobile-dark.png');
  await evaluate("document.querySelector('[data-scheduled-download]').click()");
  await evaluate("document.querySelector('[data-scheduled-remove]').click();document.getElementById('confirm-action').click()");
  await wait("!document.getElementById('confirm-dialog').open && document.getElementById('backup-schedule-empty').hidden===false");
  assert.equal(schedule.files.length,0);
  const backupFile=join(profile,'fixture.embergate');writeFileSync(backupFile,'EMBERGATE-BACKUP fixture');
  await openSettings('backups');
  await evaluate("document.getElementById('upload-full-backup').click()");
  {const {root}=await call('DOM.getDocument');const {nodeId}=await call('DOM.querySelector',{nodeId:root.nodeId,selector:'#full-backup-file'});await call('DOM.setFileInputFiles',{nodeId,files:[backupFile]});}
  await evaluate("document.getElementById('backup-passphrase').value='fixture-backup-passphrase';document.getElementById('backup-form').requestSubmit(document.getElementById('backup-submit'))");
  await wait("document.getElementById('restore-review-dialog').open");
  assert.ok(await evaluate("document.getElementById('restore-review-summary').textContent.includes('Fixture certificate')"));
  assert.equal(await evaluate("document.getElementById('backup-passphrase').value"),'');
  assert.equal(await evaluate("document.getElementById('restore-review-dialog').scrollWidth<=document.getElementById('restore-review-dialog').clientWidth"),true,'restore dialog overflow on mobile');
  await screenshot('embergate-restore-review.png');
  await evaluate("document.getElementById('restore-confirm-text').value='RESTORE';document.getElementById('restore-review-form').requestSubmit(document.getElementById('restore-review-submit'))");
  await wait("!document.getElementById('restore-review-dialog').open && document.getElementById('backup-status').textContent.startsWith('Restore queued.')");
  assert.equal(backupPending,true);
  assert.equal(await evaluate("document.getElementById('backup-schedule-fields').disabled"),true);
  await evaluate("document.getElementById('cancel-full-restore').click();document.getElementById('confirm-action').click()");
  await wait("!document.getElementById('confirm-dialog').open && document.getElementById('backup-status').textContent.includes('No restore')");
  assert.equal(backupPending,false);
  await evaluate("document.querySelector('[data-view=accounts]').click()");
  await wait("document.getElementById('users-body').textContent.includes('admin')");
  await evaluate("document.getElementById('add-user').click();document.getElementById('user-name').value='team-member';document.getElementById('user-password').value='team-password-123';document.getElementById('user-form').requestSubmit(document.querySelector('#user-form button[type=submit]'))");
  await wait("!document.getElementById('user-dialog').open && document.getElementById('users-body').textContent.includes('team-member')");
  await evaluate("document.querySelector('[data-edit-user]').click();document.getElementById('user-name').value='renamed-member';document.getElementById('user-form').requestSubmit(document.querySelector('#user-form button[type=submit]'))");
  await wait("!document.getElementById('user-dialog').open && document.getElementById('users-body').textContent.includes('renamed-member')");
  await screenshot('embergate-accounts-mobile-dark.png');
  await evaluate("document.querySelector('[data-view=audit]').click()");
  await wait("document.getElementById('audit-body').textContent.includes('/api/config')");
  await evaluate("document.querySelector('[data-view=alerts]').click()");
  await wait("document.getElementById('alerts-active').textContent==='1'");
  await evaluate("document.querySelector('[data-ack-alert]').click()");
  await wait("document.getElementById('alerts-active').textContent==='0'");
  await evaluate("document.getElementById('alert-threshold').value='25';document.getElementById('alert-settings-form').dispatchEvent(new Event('input'));document.getElementById('alert-settings-form').requestSubmit(document.getElementById('save-alert-settings'))");
  await wait("document.getElementById('alert-settings-form').dataset.version==='1'");
  assert.equal(alertSettings.error_threshold_percent,25);
  assert.equal(await evaluate('document.documentElement.scrollWidth <= 390'),true,'alerts overflow on mobile');
  await screenshot('embergate-alerts-mobile-dark.png');
  await evaluate("document.getElementById('alert-webhook-format').value='discord';document.getElementById('webhook-url').value='https://discord.com/api/webhooks/123/browser-fixture';document.getElementById('webhook-destination-form').requestSubmit(document.getElementById('save-webhook-destination'))");
  await wait("document.getElementById('webhook-url').value==='' && document.getElementById('alert-settings-form').dataset.version==='2'");
  assert.equal(alertSettings.webhook_format,'discord');assert.ok(webhookDestination.includes('browser-fixture'));
  await evaluate("document.getElementById('generate-prometheus-token').click()");
  await wait("!document.getElementById('prometheus-token-result').hidden");
  assert.equal(await evaluate("document.getElementById('prometheus-token').value"),'a'.repeat(64));
  await evaluate("document.getElementById('dismiss-prometheus-token').click()");
  assert.equal(await evaluate("document.getElementById('prometheus-token').value"),'');
  await evaluate("document.getElementById('generate-prometheus-token').click();document.getElementById('confirm-action').click()");
  await wait("!document.getElementById('confirm-dialog').open && !document.getElementById('prometheus-token-result').hidden");
  await evaluate("document.getElementById('disable-prometheus').click();document.getElementById('confirm-action').click()");
  await wait("!document.getElementById('confirm-dialog').open && document.getElementById('prometheus-token-result').hidden");
  assert.equal(prometheusConfigured,false);
  assert.equal(await evaluate('document.documentElement.scrollWidth <= 390'),true,'integrations overflow on mobile');
  await screenshot('embergate-monitoring-mobile-dark.png');

  await evaluate("document.getElementById('logout').click()");
  await wait("document.getElementById('app').hidden");
  await call('Emulation.setDeviceMetricsOverride',{width:1440,height:1080,deviceScaleFactor:1,mobile:false});
  await screenshot('embergate-login-dark.png');
  await evaluate("document.getElementById('login-username').value='reader';document.getElementById('password').value='reader-password-123';document.getElementById('login-form').requestSubmit(document.querySelector('#login-form button[type=submit]'))");
  await wait("document.getElementById('app') && !document.getElementById('app').hidden && document.getElementById('profile-name').textContent==='reader'");
  await evaluate("document.querySelector('[data-view=overview]').click()");
  assert.equal(await evaluate("document.getElementById('add-host').disabled"),true);
  assert.equal(await evaluate("document.querySelector('[data-view=audit]').hidden"),true);
  assert.equal(await evaluate("document.querySelector('[data-view=diagnostics]').hidden"),true);
  await evaluate("document.querySelector('[data-view=accounts]').click()");
  await wait("document.getElementById('sessions-body').textContent.includes('reader')");
  assert.equal(await evaluate("document.getElementById('users-card').hidden"),true);
  await evaluate("document.querySelector('[data-view=alerts]').click()");
  await wait("document.getElementById('webhook-destination-fields').disabled");
  assert.equal(await evaluate("document.getElementById('generate-prometheus-token').hidden"),true);

  await openSettings('cloudflare');
  await wait("document.getElementById('cloudflare-token-status').textContent.includes('No token configured')");
  assert.equal(await evaluate("document.getElementById('cloudflare-token-fields').disabled"),true);
  assert.equal(await evaluate("document.getElementById('full-backup-card').hidden"),true);
  assert.equal(await evaluate("document.getElementById('backup-schedule-card').hidden"),true);
  assert.equal(await evaluate("document.getElementById('config-history-card').hidden"),true);
  assert.equal(await evaluate("document.getElementById('host-templates-card').hidden"),true);
  await openSettings('threat-protection');
  await wait("!document.getElementById('settings-page-threat-protection').hidden");
  assert.equal(await evaluate("document.getElementById('crowdsec-state').textContent"),'Not connected');
  assert.equal(await evaluate("document.getElementById('crowdsec-url').disabled"),true,'read-only users cannot configure CrowdSec');
  assert.deepEqual(await evaluate("Array.from(document.querySelectorAll('[data-settings-link]')).filter(el=>!el.hidden).map(el=>el.dataset.settingsLink)"),['instance','security','cloudflare','threat-protection','trusted-proxies','configuration']);
  await evaluate("location.hash='#/settings/history'");
  await wait("location.hash==='#/settings/instance' && !document.getElementById('settings-page-instance').hidden");
  assert.equal(await evaluate("document.getElementById('settings-section').querySelector('option[value=history]')===null"),true);


  await evaluate("location.hash='#/help/backups/full-backup-and-restore'");
  await wait("!document.getElementById('help-article').hidden && document.getElementById('help-article-title').textContent==='Backups & restore'");
  assert.equal(await evaluate("location.hash"),'#/help/backups/full-backup-and-restore','read-only users can read every guide');
  assert.equal(await evaluate("Array.from(document.querySelectorAll('[data-action=duplicate]')).every(el=>el.disabled)"),true);
  await evaluate("document.querySelector('[data-view=accounts]').click()");
  await evaluate("document.getElementById('change-password').click();document.getElementById('current-password').value='reader-password-123';document.getElementById('new-password').value='new-reader-password';document.getElementById('password-form').requestSubmit(document.querySelector('#password-form button[type=submit]'))");
  await wait("document.getElementById('app').hidden");
  await evaluate("document.getElementById('login-username').value='admin';document.getElementById('password').value='setup-password-123';document.getElementById('login-form').requestSubmit(document.querySelector('#login-form button[type=submit]'))");
  await wait("!document.getElementById('login-mfa-field').hidden");
  assert.equal(await evaluate("document.getElementById('app').hidden"),true,'MFA challenge must not reveal dashboard');
  await evaluate("document.getElementById('login-mfa-code').value='654321';document.getElementById('login-form').requestSubmit(document.querySelector('#login-form button[type=submit]'))");
  await wait("document.getElementById('app') && !document.getElementById('app').hidden && document.getElementById('profile-name').textContent==='admin'");
  assert.equal(await evaluate("document.getElementById('login-mfa-code').value"),'');
  await evaluate("document.getElementById('logout').click()");await wait("!document.getElementById('login').hidden");
  await evaluate("document.getElementById('login-username').value='new-admin';document.getElementById('password').value='setup-password-123';document.getElementById('login-form').requestSubmit(document.querySelector('#login-form button[type=submit]'))");
  await wait("document.getElementById('mfa-dialog').open");
  assert.equal(await evaluate("document.getElementById('app').hidden"),true,'enforced enrollment must hide dashboard');
  assert.equal(await evaluate("document.getElementById('mfa-cancel').textContent"),'Sign out');
  await evaluate("document.getElementById('mfa-password').value='setup-password-123';document.getElementById('mfa-form').requestSubmit(document.getElementById('mfa-submit'))");
  await wait("!document.getElementById('mfa-enrollment-fields').hidden");
  await evaluate("document.getElementById('mfa-confirm-code').value='123456';document.getElementById('mfa-form').requestSubmit(document.getElementById('mfa-submit'))");
  await wait("!document.getElementById('mfa-recovery-result').hidden");
  await evaluate("document.getElementById('mfa-saved-codes').checked=true;document.getElementById('mfa-form').requestSubmit(document.getElementById('mfa-submit'))");
  await wait("!document.getElementById('mfa-dialog').open && !document.getElementById('app').hidden && document.getElementById('profile-name').textContent==='new-admin'");
  await evaluate("localStorage.removeItem('embergate-theme');localStorage.setItem('current-theme','dark')");
  await reload();
  await wait("document.documentElement?.dataset.theme==='dark' && localStorage.getItem('embergate-theme')==='dark'");
  await evaluate("localStorage.removeItem('embergate-theme');localStorage.removeItem('current-theme')");
  await call('Emulation.setEmulatedMedia',{features:[{name:'prefers-color-scheme',value:'dark'}]});
  await reload();
  await wait("document.documentElement?.dataset.theme==='dark'");
  assert.equal(await evaluate("localStorage.getItem('embergate-theme')"),null,'system theme is not persisted');
  assert.deepEqual(errors,[],'browser errors');
  console.log(`Browser checks passed: host wizard steps/validation/preset picker/policy badges/session ordering/certificate warnings/review/escaping/mobile/optional saved-backend check/direct editing, instance roles/confirmation/token clearing/follower controls, forward-auth controls/validation/persistence/mobile, Help guides/search/escaping/retry/contextual links/deep links/back-forward/reload/mobile/read-only access, separate Settings pages/secondary navigation/URLs/back-forward/reload/mobile dropdown/role guards, compression enable/mode/validation/persistence/templates/duplication/mobile, host duplication/template create/edit/conflicts/review/draft-only apply/delete/mobile/roles, configuration history comparisons/escaping/stale review/rollback/mobile, scheduled backup setup/credentials/run/download/delete/restore pause/roles/mobile, diagnostics preview/probes/failures/escaping/mobile/roles, hosts, pools, reliability timeouts/retries, weights/draining, routing rewrites/headers/previews, maintenance editing/toggling/previews, caching/purges, rate/access/response policies, trusted proxies, analytics, login/logout, logs, themes, manual certificates, ACME request/renew/stop, mobile navigation, first-run setup, Cloudflare token save/remove, account create/edit, roles, own password, MFA enrollment/recovery confirmation/policy/mobile layout, audit, alerts/preferences/acknowledgement, full encrypted backup download/review/queue/cancel, role restrictions, and passphrase clearing. Screenshot: ${screenshotPath}`);
} finally {
  // Let Chromium flush its profile and stop child processes before removing it.
  if (socket?.readyState === WebSocket.OPEN) {
    socket.send(JSON.stringify({id:999999,method:'Browser.close'}));
    if (browser?.exitCode === null && browser.signalCode === null) {
      await Promise.race([new Promise(resolve=>browser.once('exit',resolve)),delay(5000)]);
    }
  }
  socket?.close();
  browser?.kill('SIGTERM');
  if(browser?.pid && browser.exitCode === null && browser.signalCode === null) await new Promise(resolve=>browser.once('exit',resolve));
  await new Promise(resolve=>server.close(resolve));
  rmSync(profile,{recursive:true,force:true,maxRetries:10,retryDelay:200});
}

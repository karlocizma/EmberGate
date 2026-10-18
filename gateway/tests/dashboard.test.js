import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {escapeHtml, matchingHosts, chartPoints, importConfig, validateRouting, previewRouting, validatePages, validateCompression, settingsPages, dashboardRoute, helpTopics, searchGuides, duplicateHost, applyHostTemplate} from '../web/app.js';

const routes = [{id:'a', name:'API', host:'api.test', path_prefix:'/v1', upstream:'http://localhost:9000', enabled:true, preserve_host:false},
  {id:'b', name:'Blog', host:'blog.test', path_prefix:'/', upstream:'https://example.com', enabled:false, preserve_host:true}];
test('untrusted hosts and logs cannot inject markup', () => {
  assert.equal(escapeHtml('<img src=x onerror="alert(1)">'), '&lt;img src=x onerror=&quot;alert(1)&quot;&gt;');
  assert.equal(escapeHtml("'&"), '&#39;&amp;');
});
test('host search matches upstream and path with status filtering', () => {
  assert.deepEqual(matchingHosts(routes, 'LOCALHOST', 'active'), [routes[0]]);
  assert.deepEqual(matchingHosts(routes, '/v1', 'all'), [routes[0]]);
  assert.deepEqual(matchingHosts(routes, '', 'paused'), [routes[1]]);
  assert.deepEqual(matchingHosts(routes, 'blog', 'active'), []);
});
test('empty charts stay finite and request spikes remain inside plot', () => {
  for (const buckets of [[], [{requests:0}], [{requests:0},{requests:200},{requests:1}]]) {
    const chart = chartPoints(buckets);
    assert.ok(!chart.line.includes('NaN') && !chart.line.includes('Infinity'));
    assert.ok(chart.max >= Math.max(10, ...buckets.map(b => b.requests)));
  }
  assert.equal(chartPoints([{requests:0},{requests:200}]).line, 'M0.00,159.00 L600.00,9.00');
});
test('imports keep the current version and reject invalid shapes', () => {
  assert.deepEqual(importConfig(JSON.stringify({version:900,routes}), 4), {version:4,routes});
  for (const input of ['null','{}','{"routes":[null]}','{"routes":[{}]}','bad json']) assert.throws(() => importConfig(input, 4));
});
test('dashboard references existing elements and local assets', () => {
  const html = readFileSync(new URL('../web/index.html', import.meta.url), 'utf8');
  const js = readFileSync(new URL('../web/app.js', import.meta.url), 'utf8');
  const ids = new Set([...html.matchAll(/\bid="([^"]+)"/g)].map(m => m[1]));
  for (const [, id] of js.matchAll(/\$\('([^']+)'\)/g)) assert.ok(ids.has(id), `Missing element ${id}`);
  assert.equal(ids.size, [...html.matchAll(/\bid="([^"]+)"/g)].length, 'duplicate element IDs');
  assert.ok(!html.includes('https://fonts.') && !html.includes('cdn.'));
});

test('pool states distinguish enabled routes from verified health', async () => {
  const {poolState, upstreamOrigin} = await import('../web/app.js');
  const route = {...routes[0],additional_upstreams:['http://localhost:9001'],health_check:{path:'/health'}};
  assert.equal(poolState(route).label,'Checking');
  assert.equal(poolState(route,[{status:'healthy'},{status:'unhealthy'}]).label,'Degraded · 1/2');
  assert.equal(poolState(route,[{status:'unhealthy'},{status:'unhealthy'}]).label,'Unavailable');
  assert.equal(poolState(route,[{status:'healthy'},{status:'healthy'}]).label,'Healthy');
  assert.equal(poolState({...route,enabled:false}).label,'Paused');
  assert.equal(poolState(routes[0]).label,'Active');
  assert.equal(upstreamOrigin(' https://EXAMPLE.com:443/ '),'https://example.com');
  for (const origin of ['ftp://example.com','http://user:pass@example.com','https://example.com/path','https://example.com/?secret=1']) assert.throws(()=>upstreamOrigin(origin));
  assert.deepEqual(matchingHosts([route],'9001','all'),[route]);
  assert.throws(()=>importConfig(JSON.stringify({routes:[{...route,additional_upstreams:'invalid'}]}),0));
  assert.throws(()=>importConfig(JSON.stringify({routes:[{...route,health_check:{}}]}),0));
});

test('rate policies validate imports and express sustained rate plus burst', async () => {
  const {validateRateLimit,rateLimitSummary} = await import('../web/app.js');
  const limit = {requests:60,window_seconds:60,burst:20};
  assert.deepEqual(validateRateLimit(limit),limit);
  assert.equal(rateLimitSummary(limit),'60 / 60s · burst 20');
  const configured = {...routes[0],rate_limit:limit};
  assert.deepEqual(importConfig(JSON.stringify({routes:[configured]}),5).routes[0].rate_limit,limit);
  for (const invalid of [null,[],{}, {...limit,requests:0},{...limit,window_seconds:3601},
    {...limit,burst:61},{...limit,burst:1.5},{...limit,requests:'60'},{...limit,burst:0}]) {
    assert.throws(()=>validateRateLimit(invalid));
    if (invalid !== null) assert.throws(()=>importConfig(JSON.stringify({routes:[{...routes[0],rate_limit:invalid}]}),0));
  }
});


test('imports preserve global trust and per-route policies without inheriting trust implicitly', () => {
  const configured={...routes[0],access:{mode:'allow',networks:['203.0.113.0/24']},response:{redirect_https:true,https_port:443,custom_headers:[{name:'X-App',value:'EmberGate'}]}};
  const trusted_proxies=[{network:'173.245.48.0/20',header:'cloudflare',trust_proto:true}];
  assert.deepEqual(importConfig(JSON.stringify({version:99,routes:[configured],trusted_proxies}),8),{version:8,routes:[configured],trusted_proxies});
  assert.equal(importConfig(JSON.stringify({routes}),8).trusted_proxies,undefined);
  for (const trusted of [null,{},[{network:'127.0.0.1',header:'arbitrary',trust_proto:true}]]) assert.throws(()=>importConfig(JSON.stringify({routes,trusted_proxies:trusted}),1));
  assert.throws(()=>importConfig(JSON.stringify({routes:[{...routes[0],access:{mode:'unknown',networks:[]}}]}),1));
});


test('cache policy imports keep conservative defaults and reject invalid storage limits', async () => {
  const {validateCachePolicy}=await import('../web/app.js');
  const cache={max_ttl_seconds:300,max_object_bytes:1048576,cache_query_strings:false};
  assert.deepEqual(validateCachePolicy(cache),cache);
  assert.deepEqual(importConfig(JSON.stringify({routes:[{...routes[0],cache}]}),2).routes[0].cache,cache);
  for (const invalid of [{...cache,max_ttl_seconds:0},{...cache,max_object_bytes:4194305},{...cache,max_object_bytes:1},{...cache,cache_query_strings:'yes'}]) {
    assert.throws(()=>validateCachePolicy(invalid));
    assert.throws(()=>importConfig(JSON.stringify({routes:[{...routes[0],cache:invalid}]}),0));
  }
});

const {validateReliability,validateBalancing,poolState}=await import('../web/app.js');
test('reliability and balancing imports preserve policies and reject unsafe bounds',()=>{
  const origins=['http://localhost:9000','http://localhost:9001'];
  const reliability={connect_timeout_seconds:2,read_timeout_seconds:3,write_timeout_seconds:4,retries:1};
  const balancing={strategy:'client_ip_hash',weights:[3,1],draining:[origins[1]]};
  const route={...routes[0],upstream:origins[0],additional_upstreams:[origins[1]],reliability,balancing};
  const imported=importConfig(JSON.stringify({routes:[route]}),7);assert.deepEqual(imported.routes[0].reliability,reliability);assert.deepEqual(imported.routes[0].balancing,balancing);
  assert.throws(()=>validateReliability({...reliability,retries:4}));assert.throws(()=>validateReliability({...reliability,read_timeout_seconds:0}));
  assert.throws(()=>validateBalancing({...balancing,strategy:'__proto__'},origins));assert.throws(()=>validateBalancing({...balancing,weights:[1]},origins));assert.throws(()=>validateBalancing({...balancing,draining:['http://another.test']},origins));
  assert.equal(poolState({...route,health_check:{}},[{upstream:origins[0],status:'healthy',draining:false},{upstream:origins[1],status:'draining',draining:true}]).label,'Healthy');
  assert.equal(poolState(route,[{draining:true},{draining:true}]).label,'Drained');
});

test('routing preview keeps literal encoded paths, queries, and slash boundaries', () => {
  for(const [source,prefix,replacement,expected] of [
    ['/api','/api',null,'/'],['/api/v1%2Ftwo?x=%2f&x=2','/api',null,'/v1%2Ftwo?x=%2f&x=2'],
    ['/api/','/api/','/internal','/internal'],['/api/items','/api/','/internal','/internal/items'],
    ['/api/items?','/api','/internal/','/internal/items?'],['/apiv2','/api',null,'/v2'],['/api//x','/api',null,'//x']
  ]) assert.equal(previewRouting(source,prefix,{strip_prefix:replacement===null,rewrite_prefix:replacement}),expected);
  assert.equal(previewRouting('/api?q=%20','/api'),'/api?q=%20');
  assert.throws(()=>previewRouting('/other','/api'));
});
test('routing rejects injection, reserved headers, conflicts, and unsafe prefixes on import', () => {
  for(const name of ['Host','Content-Length','Connection','X-Forwarded-For','Sec-WebSocket-Key','Authorization','Cookie','Cache-Control','If-None-Match','Accept-Encoding','bad name']) assert.throws(()=>validateRouting({remove_headers:[name]}));
  for(const rewrite_prefix of ['https://evil.test','//evil','/x?y','/x#y','/x\\y','/x\ny','/é']) assert.throws(()=>validateRouting({rewrite_prefix}));
  for(const policy of [{strip_prefix:true,rewrite_prefix:'/x'},{remove_headers:['X-Test'],set_headers:[{name:'x-test',value:'ok'}]},{set_headers:[{name:'x-test',value:'ok\r\nInjected: bad'}]}]) {
    assert.throws(()=>validateRouting(policy));
    assert.throws(()=>importConfig(JSON.stringify({routes:[{...routes[0],routing:policy}]}),1));
  }
  assert.equal(validateRouting({set_headers:[{name:'X-App',value:'embergate'}]}).set_headers[0].name,'x-app');
});

test('page policies validate imports, status, timing, Unicode limits, and plain text',()=>{
  assert.equal(validatePages({}).status,503);
  assert.equal(validatePages({title:' 🛠 '.trim()}).title,'🛠');
  for(const policy of [{status:302},{retry_after_seconds:0},{retry_after_seconds:86401},{title:' '},{message:'bad\u0000'},{title:'x'.repeat(121)},{maintenance:'yes'},{branded_errors:0}]) {
    assert.throws(()=>validatePages(policy));
    assert.throws(()=>importConfig(JSON.stringify({routes:[{...routes[0],pages:policy}]}),1));
  }
  const config=importConfig(JSON.stringify({routes:[{...routes[0],pages:{maintenance:true,status:200,title:'<script>plain text</script>'}}]}),1);
  assert.equal(config.routes[0].pages.status,200);
});

test('host duplication creates a bounded independent paused draft',()=>{
  const original={...routes[0],name:'🌍'.repeat(20),pages:{maintenance:false,title:'Custom maintenance',message:'Scheduled work'},balancing:{strategy:'weighted_round_robin',weights:[3,1],draining:['http://localhost:9001']},additional_upstreams:['http://localhost:9001'],cache:{max_ttl_seconds:60,max_object_bytes:1024}};
  const before=structuredClone(original),draft=duplicateHost(original,'new-id');
  assert.equal(draft.id,'new-id');assert.equal(draft.host,'');assert.equal(draft.enabled,false);assert.ok(new TextEncoder().encode(draft.name).length<=80);
  assert.deepEqual(draft.pages,original.pages);assert.deepEqual(draft.balancing,original.balancing);
  draft.cache.max_ttl_seconds=900;draft.balancing.weights[0]=100;assert.deepEqual(original,before);
});
test('policy templates replace reusable fields without changing host identity or maintenance',()=>{
  const original={...routes[0],additional_upstreams:['http://localhost:9001'],balancing:{weights:[2,1]},pages:{maintenance:true,title:'Custom maintenance',message:'Scheduled work',branded_errors:false},cache:{max_ttl_seconds:10,max_object_bytes:1024},access:{mode:'block',networks:['127.0.0.1']}};
  const policies={preserve_host:true,branded_errors:true,rate_limit:{requests:60,window_seconds:60,burst:10},cache:null};
  const before=structuredClone(original),result=applyHostTemplate(original,policies);
  for(const key of ['id','name','host','path_prefix','upstream','additional_upstreams','balancing','enabled'])assert.deepEqual(result[key],original[key]);
  assert.equal(result.pages.maintenance,true);assert.equal(result.pages.title,'Custom maintenance');assert.equal(result.pages.branded_errors,true);assert.equal(result.cache,undefined);assert.equal(result.access,undefined);assert.equal(result.preserve_host,true);
  result.rate_limit.burst=20;assert.equal(policies.rate_limit.burst,10);assert.deepEqual(original,before);
});

test('compression policies import with defaults and survive templates and duplication',()=>{
  const route={...routes[0],compression:{mode:'auto',level:4,min_bytes:1024}};
  assert.deepEqual(importConfig(JSON.stringify({version:0,routes:[route]}),9).routes[0].compression,route.compression);
  assert.deepEqual(duplicateHost(route,'new-id').compression,route.compression);
  assert.deepEqual(applyHostTemplate(routes[1],{compression:route.compression}).compression,route.compression);
  assert.equal(applyHostTemplate(route,{}).compression,undefined);
  for(const patch of [{mode:'zstd'},{level:0},{level:7},{level:1.5},{min_bytes:255},{min_bytes:1048577}])assert.throws(()=>validateCompression({...route.compression,...patch}));
  assert.deepEqual(validateCompression({mode:'gzip',level:1,min_bytes:256}),{mode:'gzip',level:1,min_bytes:256});
  assert.throws(()=>importConfig(JSON.stringify({routes:[{...route,compression:{level:7}}]}),0));
});

test('dashboard URLs resolve settings bookmarks without accepting unknown routes',()=>{
  assert.deepEqual(dashboardRoute('#/settings/history'),{view:'settings',section:'history'});
  assert.deepEqual(dashboardRoute('#/settings'),{view:'settings',section:'instance'});
  assert.deepEqual(dashboardRoute('#/settings/not-a-page'),{view:'settings',section:'instance'});
  assert.deepEqual(dashboardRoute('#/hosts'),{view:'hosts',section:'instance'});
  for(const hash of ['', '#/<img>', '#/https://evil.test', '#/settings/%3Cscript%3E']) {
    const route=dashboardRoute(hash);assert.ok(['overview','settings'].includes(route.view));assert.equal(route.section,'instance');
  }
  const html=readFileSync(new URL('../web/index.html',import.meta.url),'utf8');
  assert.equal(settingsPages.length,9);assert.equal(new Set(settingsPages.map(p=>p.id)).size,9);
  for(const page of settingsPages)assert.equal(html.split('data-settings-page="'+page.id+'"').length-1,1);
});

test('help bookmarks keep known topics and bounded section anchors',()=>{
  assert.deepEqual(dashboardRoute('#/help/certificates/automatic-certificates-with-cloudflare-dns'),{view:'help',section:'certificates',anchor:'automatic-certificates-with-cloudflare-dns'});
  assert.deepEqual(dashboardRoute('#/help/missing'),{view:'help',section:'getting-started',anchor:''});
  assert.deepEqual(dashboardRoute('#/help/security/<script>'),{view:'help',section:'security',anchor:''});
  assert.equal(helpTopics.length,8);assert.equal(new Set(helpTopics).size,8);
});
test('documentation search matches all words across title and article text',()=>{
  const guides=[{id:'a',title:'Certificates',description:'Cloudflare',text:'Renew with DNS challenges.'},{id:'b',title:'Backups',description:'Encrypted copies',text:'Scheduled snapshots.'}];
  assert.deepEqual(searchGuides(guides,'  CLOUDFLARE dns '),[guides[0]]);
  assert.deepEqual(searchGuides(guides,'backups snapshots'),[guides[1]]);
  assert.deepEqual(searchGuides(guides,'missing'),[]);
  assert.deepEqual(searchGuides(guides,''),guides);
  assert.deepEqual(searchGuides(guides,'<img onerror=alert(1)>'),[]);
});

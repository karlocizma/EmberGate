"""Real Pingora cache check. Uses only temporary data and local HTTP listeners.
Run from gateway/: cargo build --locked && python3 tests/cache-smoke.py
"""
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import importlib.util,json,os,signal,subprocess,tempfile,threading,time,uuid
from pathlib import Path
spec=importlib.util.spec_from_file_location('smoke',Path(__file__).with_name('proxy-smoke.py'))
smoke=importlib.util.module_from_spec(spec);spec.loader.exec_module(smoke)
class Origin(BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def do_HEAD(self):self.serve(True)
    def do_GET(self):self.serve(False)
    def do_POST(self):self.serve(False)
    def serve(self,head):
        length=int(self.headers.get("Content-Length","0"))
        if length:self.rfile.read(length)
        with self.server.lock:
            self.server.count+=1;sequence=self.server.count
        path=self.path.split('?')[0]
        if path=='/slow' and not self.server.release.is_set():
            self.server.started.set();self.server.release.wait(10)
        if path=='/collapse':time.sleep(.15)
        body=json.dumps({'sequence':sequence,'path':self.path,'host':self.headers.get('Host'),'encoding':self.headers.get('Accept-Encoding')}).encode()
        if path in ['/large','/chunked-large']:body=b'x'*8192
        if path=='/empty':body=b''
        status=self.server.health if path=='/health' else 500 if path=='/error' else 200
        self.send_response(status)
        cc={'/private':'private, max-age=60','/no-store':'no-store, max-age=60','/no-cache':'no-cache, max-age=60','/duplicate':'max-age=60, max-age=600','/smaxzero':'max-age=60, s-maxage=0'}.get(path,'public, max-age=60')
        if path!='/no-freshness':self.send_header('Cache-Control',cc)
        if path=='/cookie':self.send_header('Set-Cookie','session=secret')
        if path=='/vary-star':self.send_header('Vary','*')
        if path=='/vary-language':self.send_header('Vary','Accept-Language')
        if path=='/encoding':self.send_header('Vary','Accept-Encoding')
        if path=='/old':self.send_header('Age','60')
        chunked=path=='/chunked-large'
        if chunked:self.send_header('Transfer-Encoding','chunked')
        else:self.send_header('Content-Length',str(len(body)))
        self.end_headers()
        if not head:
            if chunked:self.wfile.write(f'{len(body):x}\r\n'.encode()+body+b'\r\n0\r\n\r\n')
            else:self.wfile.write(body)
        self.wfile.flush()
    def log_message(self,*args):pass

def run():
    backend=ThreadingHTTPServer(('127.0.0.1',0),Origin)
    backend.count,backend.lock=0,threading.Lock();backend.health=200;backend.started,backend.release=threading.Event(),threading.Event()
    threading.Thread(target=backend.serve_forever,daemon=True).start()
    proxy,admin=smoke.free_port(),smoke.free_port()
    while proxy==admin:admin=smoke.free_port()
    with tempfile.TemporaryDirectory(prefix='gateway-cache-') as directory:
        env={**os.environ,'GATEWAY_ADMIN_PASSWORD':'cache-smoke-password','GATEWAY_DATA_DIR':directory,'GATEWAY_PROXY_ADDR':f'127.0.0.1:{proxy}','GATEWAY_ADMIN_ADDR':f'127.0.0.1:{admin}'}
        for key in ['GATEWAY_ALERT_WEBHOOK_URL','GATEWAY_HTTPS_ADDR','GATEWAY_CLOUDFLARE_API_TOKEN','GATEWAY_CLOUDFLARE_API_TOKEN_FILE']:env.pop(key,None)
        binary=str(Path('target/debug/embergate').resolve());process=subprocess.Popen([binary],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        version,headers=0,{}
        route={'id':str(uuid.uuid4()),'name':'Cache','host':'*','path_prefix':'/','upstream':f'http://127.0.0.1:{backend.server_port}','enabled':True,'preserve_host':False,'cache':{'max_ttl_seconds':60,'max_object_bytes':4096,'cache_query_strings':False}}
        def login():
            status,response,body=smoke.request(admin,'POST','/api/login',{'password':'cache-smoke-password'},{'X-Gateway-Request':'1'});assert status==200,body
            headers.update({'Cookie':response['set-cookie'].split(';')[0],'X-Gateway-Request':'1'})
        def save():
            nonlocal version
            status,_,body=smoke.request(admin,'PUT','/api/config',{'version':version,'routes':[route]},headers);assert status==200,body
            version=json.loads(body)['version']
        def traffic(path='/',extra=None,method='GET',host='cache.test'):
            status,response,body=smoke.request(proxy,method,path,headers={'Host':host,**(extra or {})})
            response={k.lower():v for k,v in response.items()}
            if 'x-current-cache' in response:assert response['x-embergate-cache']==response['x-current-cache']
            return status,response,body
        def state():
            status,_,body=smoke.request(admin,'GET','/api/cache',headers=headers);assert status==200,body
            return json.loads(body)
        def purge(url=None):
            status,_,body=smoke.request(admin,'POST','/api/cache/purge',{'route_id':route['id'],'url':url},headers);assert status==200,body
            return json.loads(body)
        def twice(path,extra=None,expected='BYPASS'):
            first,second=traffic(path,extra),traffic(path,extra)
            assert first[1].get('x-current-cache')==expected and second[1].get('x-current-cache')==expected,(path,first[:2],second[:2])
            return first,second
        try:
            smoke.await_ready(process,admin);login();save()
            assert smoke.request(admin,'GET','/api/cache')[0]==401
            assert smoke.request(admin,'POST','/api/cache/purge',{}, {'Cookie':headers['Cookie']})[0]==403
            first=traffic('/public');second=traffic('/public')
            assert first[1].get('x-current-cache')=='MISS' and second[1].get('x-current-cache')=='HIT',(first[:2],second[:2])
            assert first[2]==second[2] and 'age' in second[1]
            head=traffic('/public',method='HEAD');assert head[0]==200 and head[2]==b'' and head[1]['x-current-cache']=='HIT'
            assert traffic('/public',host='another.test')[1]['x-current-cache']=='MISS','wildcard hosts collided'
            assert traffic('/public',{'X-Forwarded-Proto':'https'})[1]['x-current-cache']=='HIT','untrusted protocol changed key'
            for path in ['/cookie','/private','/no-store','/no-cache','/duplicate','/vary-star','/vary-language','/no-freshness','/old','/smaxzero','/error','/large']:twice(path)
            one,two=twice('/chunked-large',expected='MISS');assert len(one[2])==8192 and len(two[2])==8192,'oversized streaming response was truncated'
            for extra in [{'Cookie':'session=private'},{'Authorization':'Bearer secret'},{'Range':'bytes=0-2'},{'Cache-Control':'no-cache'},{'Cache-Control':'no-store'},{'If-None-Match':'"etag"'}]:twice('/public',extra)
            assert traffic('/public')[1]['x-current-cache']=='HIT','bypass request polluted existing entry'
            status,response,_=smoke.request(proxy,'GET','/public',{'body':'private'},{'Host':'cache.test'})
            assert status==200 and {k.lower():v for k,v in response.items()}['x-current-cache']=='BYPASS'

            twice('/query?token=secret')
            route['cache']['cache_query_strings']=True;save()
            a=traffic('/query?a=1');b=traffic('/query?a=2');assert a[2]!=b[2]
            assert traffic('/query?a=1')[1]['x-current-cache']=='HIT'
            assert traffic('/encoding',{'Accept-Encoding':'gzip'})[1]['x-current-cache']=='MISS'
            assert traffic('/encoding',{'Accept-Encoding':'br'})[1]['x-current-cache']=='MISS'
            assert traffic('/encoding',{'Accept-Encoding':'gzip'})[1]['x-current-cache']=='HIT'
            assert traffic('/missing',{'Cache-Control':'only-if-cached'})[0]==504
            assert traffic('/query?a=1',{'Cache-Control':'only-if-cached'})[1]['x-current-cache']=='HIT'
            before=backend.count
            with ThreadPoolExecutor(max_workers=4) as pool:results=list(pool.map(lambda _:traffic('/collapse'),range(4)))
            assert backend.count==before+1,[r[:2] for r in results]
            assert sum(r[1]['x-current-cache']=='HIT' for r in results)==3
            # A path purge removes all its variants while leaving other paths warm.
            removed=purge('/encoding')['removed'];assert removed==2,removed
            assert traffic('/encoding',{'Accept-Encoding':'gzip'})[1]['x-current-cache']=='MISS'
            assert traffic('/query?a=1')[1]['x-current-cache']=='HIT'
            # A request that began before a purge must not re-admit a late origin response.
            with ThreadPoolExecutor(max_workers=1) as pool:
                pending=pool.submit(traffic,'/slow');assert backend.started.wait(5)
                purge('/slow');backend.release.set();assert pending.result()[0]==200
            assert traffic('/slow')[1]['x-current-cache']=='MISS','late fill repopulated a purged URL'
            assert traffic('/slow')[1]['x-current-cache']=='HIT'
            assert purge('http://cache.test/slow')['removed']==1
            # Successful unsafe writes invalidate all cached representations in the route.
            assert traffic('/query?a=1',method='POST')[0]==200
            assert traffic('/query?a=1')[1]['x-current-cache']=='MISS'
            # Freshness cap is honored and expired data is never served stale.
            route['cache']['max_ttl_seconds']=2;save()
            traffic('/expiry');assert traffic('/expiry')[1]['x-current-cache']=='HIT'
            time.sleep(2.2);assert traffic('/expiry')[1]['x-current-cache']=='MISS'
            # Access and rate policies run before cache lookups.
            route['cache']['max_ttl_seconds']=60
            route['rate_limit']={'requests':1,'window_seconds':3600,'burst':1};save()
            traffic('/protected');assert traffic('/protected')[0]==429
            route.pop('rate_limit');route['access']={'mode':'block','networks':['127.0.0.0/8']};save()
            assert traffic('/protected')[0]==403
            route.pop('access');save();traffic('/persist');assert traffic('/persist')[1]['x-current-cache']=='HIT'
            logs=json.loads(smoke.request(admin,'GET','/api/logs',headers=headers)[2])['logs']
            assert any(log['cache_status']=='HIT' and log['upstream'] is None for log in logs)
            assert all('token=' not in log['path'] for log in logs)
            summary=state();assert summary['entries']>0 and summary['used_bytes']<=summary['capacity_bytes']
            assert summary['routes'][0]['hits']>0
            # Config persists, cached bodies do not survive a process restart.
            process.send_signal(signal.SIGINT);process.wait(timeout=15)
            process=subprocess.Popen([binary],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);smoke.await_ready(process,admin);login()
            assert state()['entries']==0 and traffic('/persist')[1]['x-current-cache']=='MISS'
            assert traffic('/persist')[1]['x-current-cache']=='HIT'
            purge();assert state()['entries']==0
            # Fresh hits remain usable when health monitoring excludes every origin.
            route['health_check']={'path':'/health','interval_seconds':5,'timeout_seconds':1,'failure_threshold':1,'recovery_threshold':1};save()
            def wait_health(expected):
                for _ in range(120):
                    data=json.loads(smoke.request(admin,'GET','/api/upstreams',headers=headers)[2])
                    if data['routes'][route['id']][0]['status']==expected:return
                    time.sleep(.1)
                raise AssertionError(f'Expected backend {expected}: {data}')
            wait_health('healthy');traffic('/health-cached');assert traffic('/health-cached')[1]['x-current-cache']=='HIT'
            backend.health=503;wait_health('unhealthy')
            assert traffic('/health-cached')[1]['x-current-cache']=='HIT'
            assert traffic('/not-cached')[0]==503
            for bad in [{'max_ttl_seconds':0,'max_object_bytes':4096},{'max_ttl_seconds':60,'max_object_bytes':4194305}]:
                invalid={**route,'cache':bad}
                assert smoke.request(admin,'PUT','/api/config',{'version':version,'routes':[invalid]},headers)[0]==422
            assert smoke.request(admin,'POST','/api/cache/purge',{'route_id':route['id'],'url':'ftp://example.com/file'},headers)[0]==422

            print('Cache checks passed: MISS/HIT/Age/HEAD, key isolation, privacy/directive bypasses, Vary, size/streaming bounds, query opt-in, only-if-cached, collapsed fills, race-safe URL/route purge, write invalidation, expiry, policy precedence, origin-down hits, logs/counters, restart persistence.')
        finally:
            backend.release.set()
            if process.poll() is None:
                process.send_signal(signal.SIGINT)
                try:process.wait(timeout=15)
                except subprocess.TimeoutExpired:process.kill();process.wait()
            backend.shutdown();backend.server_close()
if __name__=='__main__':run()

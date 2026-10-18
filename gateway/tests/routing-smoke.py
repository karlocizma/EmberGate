"""Upstream routing transformations through real Pingora, using temporary local fixtures."""
import importlib.util,json,os,signal,subprocess,tempfile,threading,time,uuid
from pathlib import Path
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
spec=importlib.util.spec_from_file_location('smoke',Path(__file__).with_name('proxy-smoke.py'))
smoke=importlib.util.module_from_spec(spec);spec.loader.exec_module(smoke)
class Origin(BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def do_GET(self): self.serve()
    def do_POST(self): self.serve()
    def serve(self):
        body=self.rfile.read(int(self.headers.get('Content-Length','0')))
        with self.server.lock:self.server.count+=1
        if self.path.startswith('/reset') and self.server.reset:
            self.close_connection=True;return
        payload=json.dumps({'path':self.path,'method':self.command,'headers':dict((k.lower(),v) for k,v in self.headers.items()),'body':body.decode()}).encode()
        self.send_response(200);self.send_header('Content-Length',str(len(payload)));self.send_header('Cache-Control','public, max-age=60');self.end_headers();self.wfile.write(payload)
    def log_message(self,*args):pass

def run():
    servers=[]
    for reset in [True,False]:
        server=ThreadingHTTPServer(('127.0.0.1',0),Origin);server.reset=reset;server.count=0;server.lock=threading.Lock()
        threading.Thread(target=server.serve_forever,daemon=True).start();servers.append(server)
    a,b=servers;primary=f'http://127.0.0.1:{a.server_port}';secondary=f'http://127.0.0.1:{b.server_port}'
    proxy,admin=smoke.free_port(),smoke.free_port()
    while admin==proxy:admin=smoke.free_port()
    with tempfile.TemporaryDirectory(prefix='embergate-routing-') as data_dir:
        env={**os.environ,'GATEWAY_DATA_DIR':data_dir,'GATEWAY_ADMIN_PASSWORD':'routing-password-123','GATEWAY_PROXY_ADDR':f'127.0.0.1:{proxy}','GATEWAY_ADMIN_ADDR':f'127.0.0.1:{admin}'}
        for key in ['GATEWAY_ALERT_WEBHOOK_URL','GATEWAY_HTTPS_ADDR','GATEWAY_CLOUDFLARE_API_TOKEN','GATEWAY_CLOUDFLARE_API_TOKEN_FILE']:env.pop(key,None)
        binary=str(Path('target/debug/embergate').resolve());process=None;headers={};version=0
        route={'id':str(uuid.uuid4()),'name':'Routing','host':'routing.test','path_prefix':'/api','upstream':secondary,'enabled':True,'preserve_host':False,
               'routing':{'strip_prefix':True,'set_headers':[{'name':'X-App','value':'EmberGate'}],'remove_headers':['X-Debug']}}
        def start():
            nonlocal process,headers
            process=subprocess.Popen([binary],env=env,stdout=subprocess.DEVNULL);smoke.await_ready(process,admin)
            status,h,_=smoke.request(admin,'POST','/api/login',{'password':env['GATEWAY_ADMIN_PASSWORD']},{'X-Gateway-Request':'1'});assert status==200
            headers={'Cookie':h['set-cookie'].split(';')[0],'X-Gateway-Request':'1'}
        def stop():
            nonlocal process
            if process and process.poll() is None:process.send_signal(signal.SIGINT);process.wait(timeout=15)
        def save(expected=200):
            nonlocal version
            status,_,body=smoke.request(admin,'PUT','/api/config',{'version':version,'routes':[route]},headers);assert status==expected,body
            if status==200:version=json.loads(body)['version']
        def traffic(path,method='GET',body=None,extra=None):
            return smoke.request(proxy,method,path,body,{'Host':'routing.test',**(extra or {})})
        def received(response):
            assert response[0]==200,response;return json.loads(response[2])
        try:
            start();save()
            result=received(traffic('/api/v1%2Ftwo?x=%2f&x=2',extra={'X-App':'old','X-Debug':'remove','X-Forwarded-For':'forged'}))
            assert result['path']=='/v1%2Ftwo?x=%2f&x=2',result
            assert result['headers']['x-app']=='EmberGate' and 'x-debug' not in result['headers']
            assert result['headers']['host']==f'127.0.0.1:{b.server_port}' and result['headers']['x-forwarded-for']=='127.0.0.1'
            assert received(traffic('/api'))['path']=='/'
            assert received(traffic('/apiv2'))['path']=='/v2'
            assert traffic('/internal')[0]==404,'rewrites affected public routing'
            result=received(traffic('/api/upload?raw=%2B','POST',{'content':'unchanged'}))
            assert result['method']=='POST' and json.loads(result['body'])=={'content':'unchanged'} and result['path']=='/upload?raw=%2B'
            route['routing']['strip_prefix']=False;route['routing']['rewrite_prefix']='/internal/';route['preserve_host']=True;save()
            result=received(traffic('/api/items?q=%20'));assert result['path']=='/internal/items?q=%20' and result['headers']['host']=='routing.test'
            # A reset after the first rewritten request must derive the retry from the original public URL.
            route['upstream']=primary;route['additional_upstreams']=[secondary];route['routing']={'strip_prefix':True};route['reliability']={'retries':1};save()
            result=received(traffic('/api/reset?keep=%2f'));assert result['path']=='/reset?keep=%2f',result
            time.sleep(.1)
            logs=json.loads(smoke.request(admin,'GET','/api/logs',headers=headers)[2])['logs'];entry=next(log for log in logs if log['path']=='/api/reset')
            assert entry['attempted_upstreams']==[primary,secondary],entry
            assert all('?' not in log['path'] for log in logs)
            route['upstream']=secondary;route.pop('additional_upstreams');route.pop('reliability');route['cache']={'max_ttl_seconds':60,'max_object_bytes':4096,'cache_query_strings':True};save()
            first=traffic('/api/cache?q=1');second=traffic('/api/cache?q=1');assert received(first)['path']=='/cache?q=1'
            assert {k.lower():v for k,v in second[1].items()}['x-embergate-cache']=='HIT',second
            assert received(traffic('/api/cache?q=2'))['path']=='/cache?q=2'
            route['routing']={'rewrite_prefix':'/new'};save();changed=traffic('/api/cache?q=1');assert received(changed)['path']=='/new/cache?q=1'
            assert {k.lower():v for k,v in changed[1].items()}['x-embergate-cache']!='HIT'
            # Redirects preserve the public target; policies are evaluated before upstream transformations.
            route['response']={'redirect_https':True};save();response=traffic('/api/items?x=%2f')
            assert response[0]==308 and {k.lower():v for k,v in response[1].items()}['location']=='https://routing.test/api/items?x=%2f'
            route.pop('response');route['access']={'mode':'block','networks':['127.0.0.1/32']};save();assert traffic('/api/items')[0]==403;route.pop('access')
            route['routing']={'rewrite_prefix':'/persist','set_headers':[{'name':'X-Persist','value':'yes'}]};save()
            for policy in [{'strip_prefix':True,'rewrite_prefix':'/x'},{'rewrite_prefix':'//evil'},{'remove_headers':['Host']},{'set_headers':[{'name':'x-test','value':'ok\r\nInjected: bad'}]},{'remove_headers':['X-Test'],'set_headers':[{'name':'x-test','value':'value'}]}]:
                route['routing']=policy;save(422)
            persisted=json.loads(Path(data_dir,'routes.json').read_text());assert persisted['version']==version and persisted['routes'][0]['routing']['rewrite_prefix']=='/persist'
            stop();start();result=received(traffic('/api/after?raw=%2F'));assert result['path']=='/persist/after?raw=%2F' and result['headers']['x-persist']=='yes'
        finally:
            stop()
            for server in servers:server.shutdown();server.server_close()
    print('Routing integration passed: encoded targets, queries, literal prefix semantics, headers, bodies, failover, cache invalidation, public access/redirect/logs, validation, and persistence.')
if __name__=='__main__':run()

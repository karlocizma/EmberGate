"""Real Pingora failover/timeouts and load balancing using temporary data/local HTTP servers."""
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import http.client,importlib.util,json,os,signal,socket,socketserver,ssl,subprocess,tempfile,threading,time,uuid
from pathlib import Path
spec=importlib.util.spec_from_file_location('smoke',Path(__file__).with_name('proxy-smoke.py'))
smoke=importlib.util.module_from_spec(spec);spec.loader.exec_module(smoke)
class Origin(BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def do_GET(self):self.serve()
    def do_HEAD(self):self.serve(True)
    def do_POST(self):self.serve()
    def do_PUT(self):self.serve()
    def serve(self,head=False):
        size=int(self.headers.get('Content-Length','0'))
        if size:self.rfile.read(size)
        with self.server.lock:self.server.count+=1
        path=self.path.split('?')[0]
        if path=='/partial' and self.server.name=='A':
            self.send_response(200);self.send_header('Content-Length','20');self.end_headers();self.wfile.write(b'partial');self.wfile.flush();self.close_connection=True;return
        if path=='/reset' and self.server.name=='A':self.close_connection=True;return
        if path=='/slow' and self.server.name=='A':time.sleep(1.6)
        if path=='/held' and self.server.name=='A':self.server.started.set();self.server.release.wait(10)
        body=json.dumps({'backend':self.server.name,'method':self.command,'host':self.headers.get('Host')}).encode()
        self.send_response(503 if path=='/error' and self.server.name=='A' else 200)
        self.send_header('Content-Length',str(len(body)));self.send_header('Cache-Control','public, max-age=60');self.end_headers()
        try:
            if not head:self.wfile.write(body)
            self.wfile.flush()
        except (BrokenPipeError,ConnectionResetError):pass
    def log_message(self,*args):pass

def run():
    servers=[]
    for name in ['A','B']:
        server=ThreadingHTTPServer(('127.0.0.1',0),Origin);server.name=name;server.count=0;server.lock=threading.Lock();server.started=threading.Event();server.release=threading.Event()
        threading.Thread(target=server.serve_forever,daemon=True).start();servers.append(server)
    a,b=servers;primary=f'http://127.0.0.1:{a.server_port}';secondary=f'http://127.0.0.1:{b.server_port}';dead=f'http://127.0.0.1:{smoke.free_port()}'
    admin,proxy=smoke.free_port(),smoke.free_port()
    with tempfile.TemporaryDirectory(prefix='embergate-reliability-') as directory:
        env={**os.environ,'GATEWAY_ADMIN_PASSWORD':'reliability-test-password','GATEWAY_DATA_DIR':directory,'GATEWAY_ADMIN_ADDR':f'127.0.0.1:{admin}','GATEWAY_PROXY_ADDR':f'127.0.0.1:{proxy}'}
        for key in ['GATEWAY_ALERT_WEBHOOK_URL','GATEWAY_CLOUDFLARE_API_TOKEN','GATEWAY_CLOUDFLARE_API_TOKEN_FILE','GATEWAY_HTTPS_ADDR']:env.pop(key,None)
        process=subprocess.Popen([str(Path('target/debug/embergate').resolve())],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        headers={};version=0;trusted=[]
        route={'id':str(uuid.uuid4()),'name':'Reliable host','host':'*','path_prefix':'/','upstream':dead,'additional_upstreams':[secondary],'enabled':True,'preserve_host':False,'reliability':{'connect_timeout_seconds':1,'read_timeout_seconds':1,'write_timeout_seconds':1,'retries':1}}
        def api(path,method='GET',body=None,expected=200):
            status,_,data=smoke.request(admin,method,'/api/'+path,body,headers);assert status==expected,(path,status,data);return json.loads(data) if data else {}
        def save(first=True):
            nonlocal version
            if first:route['host']=f'step-{version}.test'
            version=api('config','PUT',{'version':version,'routes':[route],'trusted_proxies':trusted})['version']
        def traffic(path='/',method='GET',body=None,extra=None):
            status,response,data=smoke.request(proxy,method,path,body,{'Host':route['host'] if route['host']!='*' else 'reliable.test',**(extra or {})});return status,{key.lower():value for key,value in response.items()},data
        def body(response):return json.loads(response[2])
        def count(server):
            with server.lock:return server.count
        def wait(predicate,seconds=10):
            deadline=time.monotonic()+seconds
            while time.monotonic()<deadline:
                result=predicate()
                if result:return result
                time.sleep(.05)
            raise AssertionError('Timed out waiting for proxy state')
        try:
            smoke.await_ready(process,admin)
            status,response,_=smoke.request(admin,'POST','/api/login',{'password':'reliability-test-password'},{'X-Gateway-Request':'1'});assert status==200
            headers.update({'Cookie':response['set-cookie'].split(';')[0],'X-Gateway-Request':'1'})
            save();response=traffic('/connect');assert response[0]==200,response;assert body(response)['backend']=='B' and body(response)['host']==f'127.0.0.1:{b.server_port}'
            entry=wait(lambda:next((log for log in api('logs')['logs'] if log['path']=='/connect'),None));assert entry['attempted_upstreams']==[dead,secondary],entry
            for method,request_body,extra in [('POST',{'value':'write'},None),('PUT',None,None),('GET',{'value':'body'},None),('GET',None,{'Connection':'Upgrade','Upgrade':'websocket'})]:
                save();before=count(b);response=traffic('/unsafe',method,request_body,extra);assert response[0]==502,(method,response);assert count(b)==before,'unsafe request was replayed'
            save();assert traffic('/head',method='HEAD')[0]==200
            route['upstream']=primary;save();before=count(b);response=traffic('/slow');assert response[0]==200 and body(response)['backend']=='B',response;assert count(b)==before+1
            save();response=traffic('/reset');assert response[0]==200 and body(response)['backend']=='B',response
            save();before=count(b);assert traffic('/error')[0]==503;assert count(b)==before,'HTTP error response was retried'
            save();before=count(b)
            try:traffic('/partial');raise AssertionError('partial response was replayed or completed')
            except http.client.IncompleteRead:pass
            assert count(b)==before,'partial response was replayed'
            route['reliability']['retries']=0;save();started=time.monotonic();assert traffic('/slow')[0]==504;assert .7<time.monotonic()-started<2.5
            route['reliability']['retries']=3;save();before=count(b);assert traffic('/slow','POST',{'write':'do not replay'})[0]==504;assert count(b)==before
            route['upstream']=dead;route['additional_upstreams']=[f'http://127.0.0.1:{smoke.free_port()}'];save();assert traffic('/exhausted')[0]==502
            entry=wait(lambda:next((log for log in api('logs')['logs'] if log['path']=='/exhausted'),None));assert len(entry['attempted_upstreams'])==2 and len(set(entry['attempted_upstreams']))==2
            # Failover continues to use Pingora caching correctly.
            route['additional_upstreams']=[secondary];route['rate_limit']={'requests':1,'window_seconds':60,'burst':1};save();assert traffic('/budget')[0]==200;assert traffic('/budget')[0]==429;route.pop('rate_limit')
            route['additional_upstreams']=[secondary];route['cache']={'max_ttl_seconds':60,'max_object_bytes':4096,'cache_query_strings':False};save()
            first=traffic('/cached');second=traffic('/cached');assert first[0]==second[0]==200
            assert first[1]['x-embergate-cache']=='MISS' and second[1]['x-embergate-cache']=='HIT',(first,second)
            route.pop('cache')
            # A stalled TLS handshake must fit inside the connect budget; invalid certificates do not retry.
            class Stall(socketserver.BaseRequestHandler):
                def handle(self):time.sleep(3)
            stall=socketserver.ThreadingTCPServer(('127.0.0.1',0),Stall);stall.daemon_threads=True
            threading.Thread(target=stall.serve_forever,daemon=True).start()
            try:
                route['upstream']=f'https://127.0.0.1:{stall.server_address[1]}';route['reliability']['retries']=0;save();started=time.monotonic();response=traffic('/tls-timeout');assert response[0]==504,response;assert time.monotonic()-started<2.5
                route['reliability']['retries']=1;save();assert body(traffic('/tls-failover'))['backend']=='B'
            finally:stall.shutdown();stall.server_close()
            cert,key=Path(directory)/'origin.pem',Path(directory)/'origin.key'
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-keyout',str(key),'-out',str(cert),'-subj','/CN=untrusted.test'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            tls=ThreadingHTTPServer(('127.0.0.1',0),Origin);tls.name='TLS';tls.count=0;tls.lock=threading.Lock();tls.started=threading.Event();tls.release=threading.Event()
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,key);tls.socket=context.wrap_socket(tls.socket,server_side=True)
            threading.Thread(target=tls.serve_forever,daemon=True).start()
            try:
                route['upstream']=f'https://127.0.0.1:{tls.server_port}';save();before=count(b);assert traffic('/invalid-cert')[0]==502;assert count(b)==before,'certificate verification failure was retried'
            finally:tls.shutdown();tls.server_close()
            route['upstream']=primary;route['additional_upstreams']=[secondary];route['reliability'].update(read_timeout_seconds=5,retries=1)
            route['balancing']={'strategy':'weighted_round_robin','weights':[3,1],'draining':[]};save()
            results=[body(traffic('/weights'))['backend'] for _ in range(40)];assert results.count('A')==30 and results.count('B')==10,results
            route['balancing']={'strategy':'client_ip_hash','weights':[1,1],'draining':[]};trusted=[{'network':'127.0.0.1/32','header':'x_forwarded_for','trust_proto':False}];save()
            fixed=[body(traffic('/affinity',extra={'X-Forwarded-For':'203.0.113.5'}))['backend'] for _ in range(8)];assert len(set(fixed))==1
            choices={body(traffic('/affinity',extra={'X-Forwarded-For':f'203.0.113.{i}'}))['backend'] for i in range(1,24)};assert choices=={'A','B'},choices
            trusted=[];save();spoofed=[body(traffic('/affinity',extra={'X-Forwarded-For':f'203.0.113.{i}'}))['backend'] for i in range(1,8)];assert len(set(spoofed))==1,'untrusted forwarding changed affinity'
            route['balancing']={'strategy':'least_connections','weights':[1,1],'draining':[secondary]};save()
            with ThreadPoolExecutor(max_workers=1) as pool:
                held=pool.submit(traffic,'/held');assert a.started.wait(5)
                route['balancing']['draining']=[];save(first=False);assert body(traffic('/least'))['backend']=='B'
                route['balancing']['draining']=[primary];save(first=False);snapshot=api('upstreams')['routes'][route['id']];status=next(s for s in snapshot if s['upstream']==primary);assert status['draining'] and status['active_requests']==1,status
                assert all(body(traffic('/draining'))['backend']=='B' for _ in range(6))
                a.release.set();assert body(held.result(timeout=5))['backend']=='A'
            wait(lambda:all(s['active_requests']==0 for s in api('upstreams')['routes'][route['id']]))
            route['balancing']['draining']=[primary,secondary];save();assert traffic('/all-drained')[0]==503
            route['balancing']['draining']=[primary];save()
            process.send_signal(signal.SIGINT);process.wait(timeout=15);process=subprocess.Popen([str(Path('target/debug/embergate').resolve())],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);smoke.await_ready(process,admin)
            status,response,_=smoke.request(admin,'POST','/api/login',{'password':'reliability-test-password'},{'X-Gateway-Request':'1'});assert status==200;headers['Cookie']=response['set-cookie'].split(';')[0]
            saved=api('config')['routes'][0];assert saved['reliability']==route['reliability'] and saved['balancing']==route['balancing'];assert body(traffic('/restart'))['backend']=='B'
            print('Reliability/balancing passed: bounded distinct-backend failover, unsafe/body/upgrade exclusions, no HTTP-response retries, read timeout/504, cache failover, attempt logs, 3:1 weighting, trusted-IP affinity, least-active selection, graceful draining/counts, all-drained 503, and persistence.')
        finally:
            a.release.set()
            if process.poll() is None:process.send_signal(signal.SIGINT);process.wait(timeout=15)
            for server in servers:server.shutdown();server.server_close()
if __name__=='__main__':run()

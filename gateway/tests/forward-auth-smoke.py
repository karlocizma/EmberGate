"""Real proxy + isolated authorization service: fail-closed policy and identity handling."""
import http.client, importlib.util, json, os, signal, subprocess, tempfile, threading, time, uuid
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
spec=importlib.util.spec_from_file_location('smoke',Path(__file__).with_name('proxy-smoke.py'));smoke=importlib.util.module_from_spec(spec);spec.loader.exec_module(smoke)
class Auth(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.requests.append({k.lower():v for k,v in self.headers.items()});self.server.paths.append(self.path)
        if self.path=='/slow':time.sleep(2)
        if self.path=='/redirect':self.send_response(302);self.send_header('Location','http://127.0.0.1:1/');self.end_headers();return
        status=200 if self.headers.get('Cookie')=='session=valid' else 403 if self.headers.get('Cookie')=='session=forbidden' else 401
        self.send_response(status)
        if status==200:self.send_header('Remote-User','verified');self.send_header('Remote-Email','verified@example.test')
        self.send_header('Set-Cookie','must-not-be-forwarded=secret');self.send_header('Content-Length','0');self.end_headers()
    def log_message(self,*args):pass
class App(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.requests+=1;body=json.dumps({'path':self.path,'headers':dict(self.headers)}).encode();self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Cache-Control','public, max-age=60');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    def do_POST(self):
        self.server.requests+=1;body=self.rfile.read(int(self.headers.get('Content-Length','0')));self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    def log_message(self,*args):pass

def run():
    auth=ThreadingHTTPServer(('127.0.0.1',0),Auth);auth.requests=[];auth.paths=[]
    app=ThreadingHTTPServer(('127.0.0.1',0),App);app.requests=0
    for server in [auth,app]:threading.Thread(target=server.serve_forever,daemon=True).start()
    proxy,admin=smoke.free_port(),smoke.free_port()
    with tempfile.TemporaryDirectory(prefix='embergate-auth-') as directory:
        env={'PATH':os.environ['PATH'],'GATEWAY_ADMIN_PASSWORD':'forward-auth-fixture-password','GATEWAY_DATA_DIR':directory,'GATEWAY_PROXY_ADDR':f'127.0.0.1:{proxy}','GATEWAY_ADMIN_ADDR':f'127.0.0.1:{admin}'}
        binary=str((Path(__file__).resolve().parents[1]/'target/debug/embergate'));proc=subprocess.Popen([binary],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);version=0;headers={}
        route={'id':str(uuid.uuid4()),'name':'Protected app','host':'app.test','path_prefix':'/','upstream':f'http://127.0.0.1:{app.server_port}','enabled':True,'preserve_host':False,'cache':{'max_ttl_seconds':60,'max_object_bytes':4096,'cache_query_strings':False},'compression':{'mode':'auto','level':4,'min_bytes':256},'forward_auth':{'url':f'http://127.0.0.1:{auth.server_port}/check','timeout_seconds':1}}
        def login():
            status,response,_=smoke.request(admin,'POST','/api/login',{'password':'forward-auth-fixture-password'},{'X-Gateway-Request':'1'});assert status==200;headers.update({'Cookie':response['set-cookie'].split(';')[0],'X-Gateway-Request':'1'})
        def save():
            nonlocal version
            status,_,body=smoke.request(admin,'PUT','/api/config',{'version':version,'routes':[route]},headers);assert status==200,body;version=json.loads(body)['version']
        def traffic(extra=None,method='GET',path='/private?x=1'):
            status,h,b=smoke.request(proxy,method,path,headers={'Host':'app.test','Remote-User':'forged','X-Auth-Request-User':'forged','X-Forwarded-For':'198.51.100.1',**(extra or {})});return status,{k.lower():v for k,v in h.items()},b
        try:
            smoke.await_ready(proc,admin);login();save()
            assert traffic()[0]==401 and app.requests==0
            assert auth.requests[-1]['x-forwarded-for']=='127.0.0.1' and auth.requests[-1]['x-forwarded-uri']=='/private?x=1' and auth.requests[-1]['x-forwarded-method']=='GET'
            assert not any(k.lower()=='remote-user' for k in auth.requests[-1])
            assert traffic({'Cookie':'session=forbidden'})[0]==403 and app.requests==0
            assert traffic(method='HEAD')[0]==401
            for _ in range(2):
                status,response,body=traffic({'Cookie':'session=valid','Accept-Encoding':'gzip'});assert status==200 and response['x-embergate-cache']=='BYPASS' and 'content-encoding' not in response and 'set-cookie' not in response
                origin=json.loads(body)['headers'];assert origin['remote-user']=='verified' and 'x-auth-request-user' not in {k.lower():v for k,v in origin.items()}
            assert app.requests==2
            route['forward_auth']['sign_in_url']='https://login.test/?theme=dark';save();status,h,_=traffic();assert status==303 and h['location'].startswith('https://login.test/') and 'rd=' in h['location'];assert traffic(method='POST')[0]==401
            route['forward_auth']['url']=f'http://127.0.0.1:{auth.server_port}/redirect';save();assert traffic({'Cookie':'session=valid'})[0]==503
            route['forward_auth']['url']=f'http://127.0.0.1:{auth.server_port}/slow';save();started=time.monotonic();assert traffic({'Cookie':'session=valid'})[0]==503 and time.monotonic()-started<1.8
            route['forward_auth']['url']=f'http://127.0.0.1:{auth.server_port}/check';save()
            conn=http.client.HTTPConnection('127.0.0.1',proxy,timeout=5);conn.request('POST','/submit',b'original-request-body',{'Host':'app.test','Cookie':'session=valid','Content-Type':'text/plain'});r=conn.getresponse();assert r.status==200 and r.read()==b'original-request-body';conn.close();assert auth.requests[-1]['x-forwarded-method']=='POST'
            status,_,body=smoke.request(admin,'POST','/api/host-templates',{'name':'Protected template','source_route_id':route['id'],'expected_version':0,'expected_config_version':version},headers);assert status==200,body
            status,_,body=smoke.request(admin,'GET','/api/host-templates',headers=headers);assert status==200 and json.loads(body)['templates'][0]['policies']['forward_auth']['url']==route['forward_auth']['url']
            proc.send_signal(signal.SIGINT);proc.wait(timeout=15);proc=subprocess.Popen([binary],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);smoke.await_ready(proc,admin);login();assert traffic()[0]==303;assert traffic({'Cookie':'session=valid'})[0]==200
            assert smoke.request(admin,'GET','/api/config')[0]==401
            print('Forward-auth checks passed: allow/deny/login redirect, original URL/method/verified IP, identity spoof removal, cache/compression bypass, body preservation, timeout/redirect failures, templates, and restart persistence.')
        finally:
            proc.send_signal(signal.SIGINT);proc.wait(timeout=15)
            for server in [auth,app]:server.shutdown()
if __name__=='__main__':run()

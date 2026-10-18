"""Real Pingora maintenance/error response checks with isolated local origins/data."""
import importlib.util,json,os,signal,subprocess,tempfile,threading,time,uuid
from pathlib import Path
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
spec=importlib.util.spec_from_file_location('smoke',Path(__file__).with_name('proxy-smoke.py'))
smoke=importlib.util.module_from_spec(spec);spec.loader.exec_module(smoke)
class Origin(BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def do_GET(self):
        with self.server.lock:self.server.count+=1
        body=b'<html>Application-owned failure</html>' if self.path=='/origin-error' else b'public cached content'
        self.send_response(503 if self.path=='/origin-error' else 200);self.send_header('Content-Type','text/html');self.send_header('Content-Length',str(len(body)));self.send_header('Cache-Control','public, max-age=60');self.end_headers();self.wfile.write(body)
    def log_message(self,*args):pass

def run():
    origin=ThreadingHTTPServer(('127.0.0.1',0),Origin);origin.count=0;origin.lock=threading.Lock();threading.Thread(target=origin.serve_forever,daemon=True).start()
    proxy,admin=smoke.free_port(),smoke.free_port()
    while admin==proxy:admin=smoke.free_port()
    with tempfile.TemporaryDirectory(prefix='embergate-pages-') as data_dir:
        env={**os.environ,'GATEWAY_DATA_DIR':data_dir,'GATEWAY_ADMIN_PASSWORD':'pages-password-123','GATEWAY_PROXY_ADDR':f'127.0.0.1:{proxy}','GATEWAY_ADMIN_ADDR':f'127.0.0.1:{admin}'}
        for key in ['GATEWAY_ALERT_WEBHOOK_URL','GATEWAY_HTTPS_ADDR','GATEWAY_CLOUDFLARE_API_TOKEN','GATEWAY_CLOUDFLARE_API_TOKEN_FILE']:env.pop(key,None)
        process=None;headers={};version=0;route={'id':str(uuid.uuid4()),'name':'Maintenance host','host':'pages.test','path_prefix':'/','upstream':f'http://127.0.0.1:{origin.server_port}','enabled':True,'preserve_host':False,'cache':{'max_ttl_seconds':60,'max_object_bytes':4096}}
        def start():
            nonlocal process,headers
            process=subprocess.Popen([str(Path('target/debug/embergate').resolve())],env=env,stdout=subprocess.DEVNULL);smoke.await_ready(process,admin)
            status,h,_=smoke.request(admin,'POST','/api/login',{'password':env['GATEWAY_ADMIN_PASSWORD']},{'X-Gateway-Request':'1'});assert status==200
            headers={'Cookie':h['set-cookie'].split(';')[0],'X-Gateway-Request':'1'}
        def stop():
            if process and process.poll() is None:process.send_signal(signal.SIGINT);process.wait(timeout=15)
        def save(expected=200):
            nonlocal version
            status,_,body=smoke.request(admin,'PUT','/api/config',{'version':version,'routes':[route]},headers);assert status==expected,(status,body)
            if status==200:version=json.loads(body)['version']
        def traffic(path='/',method='GET',accept=None,body=None):
            h={'Host':'pages.test'}
            if accept is not None:h['Accept']=accept
            status,headers,body=smoke.request(proxy,method,path,body,h);return status,{k.lower():v for k,v in headers.items()},body
        def count():
            with origin.lock:return origin.count
        try:
            start();save();assert traffic()[0]==200;assert traffic()[1]['x-embergate-cache']=='HIT';before=count()
            route['pages']={'maintenance':True,'title':'<script>Planned work</script>','message':'We are upgrading 🛠.\nTry again later. <img src=x onerror=alert(1)>','retry_after_seconds':600};save()
            html=traffic('/?secret=never-reflect',accept='text/html');assert html[0]==503,html
            assert html[1]['content-type']=='text/html; charset=utf-8' and html[1]['retry-after']=='600' and html[1]['cache-control']=='no-store' and html[1]['vary']=='Accept'
            assert int(html[1]['content-length'])==len(html[2]);assert b'Powered by Pingora' in html[2] and b'&lt;script&gt;' in html[2] and b'&lt;img' in html[2]
            assert b'<script>' not in html[2] and b'<img' not in html[2] and b'secret=' not in html[2]
            assert "default-src 'none'" in html[1]['content-security-policy'] and html[1]['x-content-type-options']=='nosniff'
            Path('/tmp/embergate-maintenance.html').write_bytes(html[2])
            head=traffic('/',method='HEAD',accept='text/html');assert head[0]==503 and head[2]==b'' and head[1]['content-length']==html[1]['content-length']
            for accept in [None,'application/json','*/*','text/html;q=0,*/*;q=1']:
                response=traffic(accept=accept);assert response[0]==503 and response[1]['content-type']=='text/plain; charset=utf-8' and response[2].decode()==route['pages']['message']
            for method in ['POST','PUT','DELETE','OPTIONS']:
                response=traffic(method=method,body={'untouched':'write'} if method=='POST' else None);assert response[0]==503
            assert count()==before,'maintenance reached an origin or served its cached content'
            time.sleep(.1);logs=json.loads(smoke.request(admin,'GET','/api/logs',headers=headers)[2])['logs'];entry=next(l for l in logs if l.get('maintenance'))
            assert entry['upstream'] is None and entry['attempted_upstreams']==[] and entry['cache_status']=='OFF'
            assert all('?' not in l['path'] for l in logs)
            # Response policies cannot mislabel generated HTML or override its no-store/framing/security headers.
            route['response']={'nosniff':True,'custom_headers':[{'name':'Content-Type','value':'application/json'},{'name':'Cache-Control','value':'public, max-age=3600'}]};save()
            response=traffic(accept='text/html');assert response[1]['content-type']=='text/html; charset=utf-8' and response[1]['cache-control']=='no-store'
            route['response']={'redirect_https':True};save();response=traffic('/public?raw=%2f',accept='text/html');assert response[0]==308 and response[1]['location']=='https://pages.test/public?raw=%2f' and 'retry-after' not in response[1]
            route.pop('response');route['access']={'mode':'block','networks':['127.0.0.1/32']};save();assert traffic(accept='text/html')[0]==403;route.pop('access')
            route['rate_limit']={'requests':1,'window_seconds':3600,'burst':1};save();assert traffic()[0]==503;assert traffic(accept='text/html')[0]==429;route.pop('rate_limit')
            route['pages']['status']=200;save();assert traffic(accept='text/html')[0]==200 and count()==before
            status,_,body=smoke.request(admin,'POST','/api/users',{'username':'reader','password':'reader-pages-password','role':'read_only'},headers);assert status==201,(status,body)
            status,h,_=smoke.request(admin,'POST','/api/login',{'username':'reader','password':'reader-pages-password'},{'X-Gateway-Request':'1'});assert status==200
            reader={'Cookie':h['set-cookie'].split(';')[0],'X-Gateway-Request':'1'}
            assert smoke.request(admin,'PUT','/api/config',{'version':version,'routes':[]},reader)[0]==403
            assert json.loads(Path(data_dir,'routes.json').read_text())['version']==version
            stop();start();response=traffic(accept='text/html');assert response[0]==200 and b'&lt;script&gt;' in response[2]
            # Ending maintenance resumes forwarding and resets the route cache namespace.
            route['pages']['maintenance']=False;save();assert traffic()[0]==200 and count()==before+1
            upstream_error=traffic('/origin-error',accept='text/html');assert upstream_error[0]==503 and upstream_error[2]==b'<html>Application-owned failure</html>'
            route['upstream']=f'http://127.0.0.1:{smoke.free_port()}';route.pop('cache');save()
            error=traffic(accept='text/html');assert error[0]==502 and b'Unable to reach this service' in error[2] and b'SCHEDULED MAINTENANCE' not in error[2]
            Path('/tmp/embergate-error.html').write_bytes(error[2])
            route['pages']['branded_errors']=False;save();assert traffic(accept='text/html')[1]['content-type']=='text/plain; charset=utf-8'
            route['enabled']=False;save();response=traffic(accept='text/html');assert response[0]==404 and b'Page not found' in response[2]
            # Invalid edits never replace persisted valid configuration.
            for pages in [{'status':301},{'retry_after_seconds':0},{'title':' '},{'message':'bad\x00'},{'message':'x'*2001}]:route['pages']=pages;save(422)
            assert json.loads(Path(data_dir,'routes.json').read_text())['version']==version
            assert count()==before+2
        finally:
            stop();origin.shutdown();origin.server_close()
    print('Pages integration passed: maintenance before cache/origins, HTML/plain negotiation, escaped text, HEAD/bodies, security/framing, policy precedence, logs, status 200/503, recovery, application errors, gateway errors, validation, and persistence.')
if __name__=='__main__':run()

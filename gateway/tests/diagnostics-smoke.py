"""Isolated diagnostics checks: routing, transport, TLS, bounded probes, roles and audit."""
from http.client import HTTPConnection
import concurrent.futures,importlib.util,json,os,signal,ssl,subprocess,tempfile,threading,time,uuid
from pathlib import Path
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
spec=importlib.util.spec_from_file_location('smoke',Path(__file__).with_name('proxy-smoke.py'));smoke=importlib.util.module_from_spec(spec);spec.loader.exec_module(smoke)
requests=[];slow=threading.Event()
class Origin(BaseHTTPRequestHandler):
    def do_HEAD(self):
        requests.append({'method':'HEAD','path':self.path,'headers':dict(self.headers)})
        if self.path.startswith('/slow'):slow.set();time.sleep(6)
        self.send_response(302 if self.path.startswith('/redirect') else 405 if self.path.startswith('/unsupported') else 200)
        self.send_header('Content-Length','999999');self.send_header('Set-Cookie','private-upstream-cookie')
        if self.path.startswith('/redirect'):self.send_header('Location',f'http://127.0.0.1:{self.server.trap}/must-not-follow')
        self.end_headers()
    def do_GET(self):requests.append({'method':'GET','path':self.path});self.send_response(200);self.send_header('Content-Length','0');self.end_headers()
    def log_message(self,*args):pass

def run():
    servers=[];process=None
    with tempfile.TemporaryDirectory(prefix='embergate-diagnostics-') as directory:
        data=Path(directory)
        def openssl(*args):subprocess.run(['openssl',*args],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        openssl('req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN=Diagnostic Root','-keyout',str(data/'root.key'),'-out',str(data/'root.pem'))
        def certificate(label,san):
            openssl('req','-new','-newkey','rsa:2048','-nodes','-subj',f'/CN={label}','-keyout',str(data/(label+'.key')),'-out',str(data/(label+'.csr')))
            (data/(label+'.ext')).write_text(f'subjectAltName={san}\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
            openssl('x509','-req','-in',str(data/(label+'.csr')),'-CA',str(data/'root.pem'),'-CAkey',str(data/'root.key'),'-CAcreateserial','-days','2','-extfile',str(data/(label+'.ext')),'-out',str(data/(label+'.pem')))
        certificate('valid','IP:127.0.0.1,DNS:diagnostic.test');certificate('wrong-name','DNS:wrong.test')
        openssl('req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN=Untrusted','-addext','subjectAltName=IP:127.0.0.1','-keyout',str(data/'untrusted.key'),'-out',str(data/'untrusted.pem'))
        def server(label=None):
            srv=ThreadingHTTPServer(('127.0.0.1',0),Origin);srv.trap=0
            if label:
                ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(str(data/(label+'.pem')),str(data/(label+'.key')));srv.socket=ctx.wrap_socket(srv.socket,server_side=True)
            servers.append(srv);threading.Thread(target=srv.serve_forever,daemon=True).start();return srv
        http,valid,wrong,untrusted,trap=server(),server('valid'),server('wrong-name'),server('untrusted'),server();http.trap=trap.server_port
        admin,proxy,tls=smoke.free_port(),smoke.free_port(),smoke.free_port()
        env={k:v for k,v in os.environ.items() if not k.startswith('GATEWAY_')}
        env.update(GATEWAY_ADMIN_PASSWORD='diagnostic-admin-password',GATEWAY_DATA_DIR=directory,GATEWAY_ADMIN_ADDR=f'127.0.0.1:{admin}',GATEWAY_PROXY_ADDR=f'127.0.0.1:{proxy}',GATEWAY_HTTPS_ADDR=f'127.0.0.1:{tls}',SSL_CERT_FILE=str(data/'root.pem'))
        def api(path,method='GET',body=None,auth=None,expected=200):
            conn=HTTPConnection('127.0.0.1',admin,timeout=40);conn.request(method,'/api/'+path,json.dumps(body) if body is not None else None,{'Content-Type':'application/json',**(auth or {})});response=conn.getresponse();status,h,result=response.status,dict(response.getheaders()),response.read();conn.close();assert status==expected,(path,status,result[:500]);
            try:parsed=json.loads(result)
            except json.JSONDecodeError:parsed={'error':result.decode()}
            return parsed,h
        def call(path,method='GET',body=None,auth=None,expected=200):return api(path,method,body,auth,expected)[0]
        def login(username='admin',password='diagnostic-admin-password'):
            _,h=api('login','POST',{'username':username,'password':password},{'X-Gateway-Request':'1'});return {'Cookie':h['set-cookie'].split(';')[0],'X-Gateway-Request':'1'}
        def route(name,host,prefix,origin,**extra):return {'id':str(uuid.uuid4()),'name':name,'host':host,'path_prefix':prefix,'upstream':origin,'enabled':True,'preserve_host':False,**extra}
        def diagnose(host='DIAGNOSTIC.test:8443',path='/api/items?probe-secret=%2f&x=2',probe=False):return call('diagnostics','POST',{'host':host,'path':path,'probe':probe},owner)
        try:
            process=subprocess.Popen([str(Path('target/debug/embergate').resolve())],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);smoke.await_ready(process,admin);owner=login()
            origin=f'http://127.0.0.1:{http.server_port}'
            wildcard=route('Wildcard','*','/',origin);api_route=route('API','diagnostic.test','/api',origin,routing={'rewrite_prefix':'/internal','set_headers':[{'name':'X-Probe','value':'configured-value'}]},additional_upstreams=[f'https://127.0.0.1:{valid.server_port}',f'https://127.0.0.1:{wrong.server_port}',f'https://127.0.0.1:{untrusted.server_port}',f'http://127.0.0.1:{smoke.free_port()}'])
            api_route['balancing']={'strategy':'round_robin','weights':[1]*5,'draining':[api_route['additional_upstreams'][0]]}
            nested=route('Nested','diagnostic.test','/api/v1',origin);paused=route('Paused','diagnostic.test','/paused',origin,enabled=False)
            routes=[wildcard,api_route,nested,paused];version=call('config','PUT',{'version':0,'routes':routes},owner)['version']
            call('users','POST',{'username':'reader','password':'reader-password-123','role':'read_only'},owner,201);reader=login('reader','reader-password-123')
            call('diagnostics','POST',{'host':'diagnostic.test','path':'/','probe':True},reader,403)
            call('diagnostics','POST',{'host':'diagnostic.test','path':'/','probe':True},{'Cookie':owner['Cookie']},403)
            call('diagnostics','POST',{'host':'diagnostic.test','path':'/','probe':True},expected=401)
            for value in [{'host':'https://evil.test','path':'/'},{'host':'evil.test','path':'https://elsewhere.test/'},{'host':'user@evil.test','path':'/'},{'host':'diagnostic.test','path':'/\r\nInjected: bad'},{'host':'diagnostic.test','path':'/','origin':'http://arbitrary.test'}]:call('diagnostics','POST',value,owner,422)
            before=call('stats',auth=owner)['requests'];revision=call('config',auth=owner)['version']
            preview=diagnose();assert preview['route']['id']==api_route['id'];assert preview['route']['upstream_path']=='/internal/items?probe-secret=%2f&x=2';assert not requests and not preview['backends']
            assert diagnose(path='/api/v1/item')['route']['id']==nested['id'];assert diagnose(host='other.test')['route']['id']==wildcard['id'];assert diagnose(path='/paused')['paused_matches'][0]['id']==paused['id']
            health_before=call('upstreams',auth=owner)
            report=diagnose(probe=True);assert len(report['backends'])==5
            normal,trusted,mismatch,unknown,refused=report['backends']
            assert normal['dns']['status']=='passed' and normal['tcp']['status']=='passed' and normal['http_status']==200 and normal['tls']['status']=='skipped'
            assert trusted['tls']['status']=='passed' and trusted['certificate']['days_remaining']>=1 and trusted['draining']
            for result in [mismatch,unknown]:assert result['tcp']['status']=='passed' and result['tls']['status']=='failed' and result['http']['status']=='skipped'
            assert refused['tcp']['status']=='failed' and refused['http']['status']=='skipped'
            assert all(r['method']=='HEAD' for r in requests)
            assert all(r['path']=='/internal/items?probe-secret=%2f&x=2' and r['headers'].get('x-probe')=='configured-value' for r in requests)
            assert all('cookie' not in {k.lower() for k in r['headers']} and 'authorization' not in {k.lower() for k in r['headers']} for r in requests)
            assert 'private-upstream-cookie' not in json.dumps(report) and 'BEGIN' not in json.dumps(report)
            assert call('stats',auth=owner)['requests']==before and call('config',auth=owner)['version']==revision
            assert call('logs',auth=owner)['logs']==[] and call('upstreams',auth=owner)==health_before
            # Visitor certificate selection is local and distinct from backend verification.
            call('certificates','POST',{'name':'Proxy certificate','certificate_pem':(data/'valid.pem').read_text()+(data/'root.pem').read_text(),'private_key_pem':(data/'valid.key').read_text()},owner)
            assert diagnose()['public_certificate']['name']=='Proxy certificate'
            routes=[route('Direct','diagnostic.test','/',origin,preserve_host=True)];version=call('config','PUT',{'version':version,'routes':routes},owner)['version']
            redirect=diagnose(path='/redirect',probe=True);assert redirect['backends'][0]['http_status']==302;assert requests[-1]['headers']['host']=='DIAGNOSTIC.test:8443';assert not any(r['path']=='/must-not-follow' for r in requests)
            assert diagnose(path='/unsupported',probe=True)['backends'][0]['http_status']==405
            # Slow probing cannot block configuration changes. Results identify an older snapshot.
            with concurrent.futures.ThreadPoolExecutor() as pool:
                pending=pool.submit(diagnose,'diagnostic.test','/slow',True);assert slow.wait(3)
                start=time.monotonic();routes[0]['name']='Edited during probe';version=call('config','PUT',{'version':version,'routes':routes},owner)['version'];assert time.monotonic()-start<2
                timed=pending.result(timeout=8);assert timed['configuration_changed'];assert timed['backends'][0]['http']['status']=='failed' and 'timed out' in timed['backends'][0]['http']['detail']
            # Concurrent reports are bounded independently of configuration writes.
            with concurrent.futures.ThreadPoolExecutor() as pool:
                first=pool.submit(diagnose,'diagnostic.test','/slow-limit',True);second=pool.submit(diagnose,'diagnostic.test','/slow-limit',True)
                deadline=time.monotonic()+3
                while len([r for r in requests if r['path']=='/slow-limit'])<2 and time.monotonic()<deadline:time.sleep(.02)
                assert len([r for r in requests if r['path']=='/slow-limit'])==2
                call('diagnostics','POST',{'host':'diagnostic.test','path':'/slow-limit','probe':True},owner,429)
                assert first.result(timeout=8)['backends'][0]['http']['status']=='failed';assert second.result(timeout=8)['backends'][0]['http']['status']=='failed'
            # Paused-only requests produce a useful unmatched report and send nothing.
            routes[0]['enabled']=False;call('config','PUT',{'version':version,'routes':routes},owner);count=len(requests)
            assert diagnose(probe=True)['route'] is None and len(requests)==count
            # Diagnostic reads neither stale a backup review nor stop while restore is queued.
            status,_,archive=smoke.request(admin,'POST','/api/backups/export',{'passphrase':'diagnostic-backup-passphrase'},owner);assert status==200
            review=call('backups/preview','POST',{'archive':__import__('base64').b64encode(archive).decode(),'passphrase':'diagnostic-backup-passphrase'},owner)
            diagnose();call('backups/restore','POST',{'id':review['id'],'confirm':'RESTORE'},owner)
            assert diagnose()['route'] is None
            call('backups/cancel','POST',auth=owner)
            audit=json.dumps(call('audit',auth=owner));assert '/api/diagnostics' in audit
            for secret in ['probe-secret','configured-value','private-upstream-cookie',owner['Cookie']]:assert secret not in audit
            print('Diagnostics passed: exact/wildcard/longest-prefix/paused matching, rewrite/query preservation, preview without network, DNS/TCP/TLS/HEAD stages, trusted and invalid certificates, draining visibility, preserved Host/configured headers, cookie isolation, redirects, 405, timeouts, report concurrency limits, concurrent configuration edits/stale results, backup review/freeze compatibility, roles/CSRF/input limits, audit redaction, and unchanged traffic counters/logs/configuration.')
        finally:
            if process and process.poll() is None:process.send_signal(signal.SIGINT);process.wait(timeout=15)
            for srv in servers:srv.shutdown();srv.server_close()
if __name__=='__main__':run()

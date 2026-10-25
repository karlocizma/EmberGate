"""Private CA bundle: validation, roles, health checks and Diagnostics trusting a private root, removal, restart, and backup."""
import base64, http.server, importlib.util, json, os, signal, ssl, subprocess, tempfile, threading, time, uuid
from pathlib import Path
spec=importlib.util.spec_from_file_location('smoke',Path(__file__).with_name('proxy-smoke.py'));smoke=importlib.util.module_from_spec(spec);spec.loader.exec_module(smoke)
class Health(http.server.BaseHTTPRequestHandler):
    def do_GET(self):self.send_response(200);self.send_header('Content-Length','0');self.end_headers()
    def do_HEAD(self):self.do_GET()
    def log_message(self,*args):pass
def run():
    with tempfile.TemporaryDirectory(prefix='embergate-trust-') as directory:
        data=Path(directory)
        def openssl(*args):subprocess.run(['openssl',*args],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        openssl('req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN=Home Lab Root','-addext','basicConstraints=critical,CA:TRUE','-keyout',str(data/'root.key'),'-out',str(data/'root.pem'))
        openssl('req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=localhost','-keyout',str(data/'server.key'),'-out',str(data/'server.csr'))
        (data/'server.ext').write_text('subjectAltName=IP:127.0.0.1\nbasicConstraints=CA:FALSE\n')
        openssl('x509','-req','-in',str(data/'server.csr'),'-CA',str(data/'root.pem'),'-CAkey',str(data/'root.key'),'-CAcreateserial','-days','2','-extfile',str(data/'server.ext'),'-out',str(data/'server.pem'))
        backend=http.server.ThreadingHTTPServer(('127.0.0.1',0),Health)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(str(data/'server.pem'),str(data/'server.key'));backend.socket=context.wrap_socket(backend.socket,server_side=True)
        threading.Thread(target=backend.serve_forever,daemon=True).start()
        origin=f'https://127.0.0.1:{backend.server_address[1]}'
        admin,proxy=smoke.free_port(),smoke.free_port();process=None;owner={}
        env={k:v for k,v in os.environ.items() if not k.startswith(('GATEWAY_','SSL_CERT'))};env.update(GATEWAY_ADMIN_PASSWORD='trust-admin-password',GATEWAY_DATA_DIR=directory,GATEWAY_ADMIN_ADDR=f'127.0.0.1:{admin}',GATEWAY_PROXY_ADDR=f'127.0.0.1:{proxy}')
        def call(path,method='GET',body=None,auth=None,expected=200):
            status,_,result=smoke.request(admin,method,'/api/'+path,body,owner if auth is None else auth);assert status==expected,(path,status,result[:400])
            return json.loads(result) if result else None
        def login(username='admin',password='trust-admin-password'):
            status,h,_=smoke.request(admin,'POST','/api/login',{'username':username,'password':password},{'X-Gateway-Request':'1'});assert status==200
            return {'Cookie':h['set-cookie'].split(';')[0],'X-Gateway-Request':'1'}
        def start():
            nonlocal process,owner
            process=subprocess.Popen([str(Path('target/debug/embergate').resolve())],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);smoke.await_ready(process,admin);owner=login()
        def stop():
            if process and process.poll() is None:process.send_signal(signal.SIGINT);process.wait(timeout=15)
        def health(expected,timeout=20):
            deadline=time.time()+timeout
            while time.time()<deadline:
                statuses=call('upstreams')['routes'][route['id']]
                if statuses and statuses[0]['status']==expected:return statuses[0]
                time.sleep(0.3)
            raise AssertionError(f'health never became {expected}: {statuses}')
        def tls_stage():
            report=call('diagnostics','POST',{'host':'private.test','path':'/','probe':True})
            return report['backends'][0]['tls']['status']
        route={'id':str(uuid.uuid4()),'name':'Private','host':'private.test','path_prefix':'/','upstream':origin,'enabled':True,'preserve_host':False,'health_check':{'path':'/health','interval_seconds':5,'timeout_seconds':2,'failure_threshold':1,'recovery_threshold':1}}
        try:
            start()
            assert call('trust')=={'configured':False,'certificates':[]}
            call('config','PUT',{'version':0,'routes':[route]})
            failing=health('unhealthy');assert tls_stage()=='failed','an unknown private root is not trusted'
            root=(data/'root.pem').read_text()
            for bad in ['not pem',(data/'server.pem').read_text(),root+(data/'root.key').read_text(),root*40]:
                call('trust','PUT',{'pem':bad},expected=422)
            call('users','POST',{'username':'reader','password':'trust-reader-password','role':'read_only'},expected=201);reader=login('reader','trust-reader-password')
            assert call('trust',auth=reader)['configured'] is False
            call('trust','PUT',{'pem':root},reader,403);call('trust','DELETE',None,reader,403)
            call('trust','PUT',{'pem':root},{'Cookie':owner['Cookie']},403)
            saved=call('trust','PUT',{'pem':root})
            assert saved['configured'] and saved['certificates'][0]['subject']=='Home Lab Root' and len(saved['certificates'][0]['sha256'])==95
            health('healthy');assert tls_stage()=='passed','checks trust the private root right away'
            stop();start()
            assert call('trust')['configured'];health('healthy')
            status,_,blob=smoke.request(admin,'POST','/api/backups/export',{'passphrase':'trust-backup-passphrase'},owner);assert status==200
            review=call('backups/preview','POST',{'archive':base64.b64encode(blob).decode(),'passphrase':'trust-backup-passphrase'})
            assert 'private_ca_bundle' in review['summary']['credential_types']
            call('trust','DELETE');assert call('trust')['configured'] is False
            health('unhealthy');assert tls_stage()=='failed'
            print('Private CA checks passed: validation, roles, health and Diagnostics trust, restart, backup, and removal.')
        finally:
            stop();backend.shutdown()
if __name__=='__main__':run()

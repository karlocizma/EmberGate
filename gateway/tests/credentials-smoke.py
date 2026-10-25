"""Fresh WebGUI setup, credential persistence, redaction, and override checks using local servers."""
from concurrent.futures import ThreadPoolExecutor
import importlib.util,json,os,re,signal,sqlite3,subprocess,tempfile,time
from pathlib import Path
spec=importlib.util.spec_from_file_location('smoke',Path(__file__).with_name('proxy-smoke.py'))
smoke=importlib.util.module_from_spec(spec);spec.loader.exec_module(smoke)
def run():
    admin,proxy=smoke.free_port(),smoke.free_port()
    with tempfile.TemporaryDirectory(prefix='gateway-credentials-') as directory:
        env={**os.environ,'GATEWAY_DATA_DIR':directory,'GATEWAY_ADMIN_ADDR':f'127.0.0.1:{admin}','GATEWAY_PROXY_ADDR':f'127.0.0.1:{proxy}'}
        for key in ['GATEWAY_ADMIN_PASSWORD','GATEWAY_CLOUDFLARE_API_TOKEN','GATEWAY_CLOUDFLARE_API_TOKEN_FILE','GATEWAY_ALERT_WEBHOOK_URL','GATEWAY_HTTPS_ADDR']:env.pop(key,None)
        binary=str(Path('target/debug/embergate').resolve());log_path=Path(directory)/'startup.log';log=None;process=None
        def start():
            nonlocal process,log
            log=open(log_path,'w');process=subprocess.Popen([binary],env=env,stdout=log,stderr=log);smoke.await_ready(process,admin)
        def stop():
            if process and process.poll() is None:process.send_signal(signal.SIGINT);process.wait(timeout=15)
            if log:log.close()
        def call(path,method='GET',body=None,headers=None,expected=200):
            status,_,data=smoke.request(admin,method,'/api/'+path,body,headers or {});assert status==expected,(path,status,data);return json.loads(data) if data else {}
        verified={'X-Gateway-Request':'1'}
        def login(password,username='admin'):
            status,response,data=smoke.request(admin,'POST','/api/login',{'username':username,'password':password},verified);assert status==200,(status,data)
            return {**verified,'Cookie':response['set-cookie'].split(';')[0]}
        token='a-private-cloudflare-token-never-displayed';replacement='a-replacement-cloudflare-token-never-displayed'
        try:
            start();assert call('setup')['setup_required']
            code=re.search(r'one-time setup code: ([a-f0-9-]+)',log_path.read_text()).group(1)
            call('credentials',expected=401)
            call('setup','POST',{'setup_code':code,'password':'first-admin-password'},expected=403)
            call('setup','POST',{'setup_code':'wrong','password':'first-admin-password'},verified,403)
            call('setup','POST',{'setup_code':code,'password':'short'},verified,422)
            passwords=['first-admin-password','other-admin-password']
            def initialize(password):
                status,_,_=smoke.request(admin,'POST','/api/setup',{'setup_code':code,'password':password},verified);return status
            with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(initialize,passwords))
            assert sorted(results)==[201,409],results
            password=passwords[results.index(201)];owner=login(password)
            assert not call('setup')['setup_required'];call('setup','POST',{'setup_code':code,'password':'overwrite-admin-password'},verified,409)
            assert call('session',headers=owner)['password_editable']
            call('credentials/cloudflare','PUT',{'token':token},verified,401)
            call('credentials/cloudflare','PUT',{'token':token},{'Cookie':owner['Cookie']},403)
            reader=call('users','POST',{'username':'reader','password':'reader-password-123','role':'read_only'},owner,201)['user'];readonly=login('reader-password-123','reader')
            call('credentials/cloudflare','PUT',{'token':token},readonly,403);call('credentials/cloudflare','DELETE',headers=readonly,expected=403)
            call('credentials/cloudflare','PUT',{'token':'bad\r\ntoken'},owner,409)
            assert not call('credentials',headers=owner)['cloudflare']['configured']
            call('credentials/cloudflare','PUT',{'token':token},owner)
            status=call('credentials',headers=owner)['cloudflare'];assert {k:status[k] for k in ['configured','source','editable','provider']}=={'configured':True,'source':'database','editable':True,'provider':'cloudflare'}
            assert {p['id'] for p in status['providers']}=={'cloudflare','acme-dns','rfc2136','hetzner','desec','digitalocean','porkbun','gandi','ionos'}
            assert call('acme',headers=owner)['configured']
            call('credentials/cloudflare','PUT',{'token':replacement},owner)
            assert len([u for u in call('users',headers=owner)['users'] if u['username']=='admin'])==1
            call('password','POST',{'current_password':password,'new_password':'changed-admin-password'},owner);call('session',headers=owner,expected=401)
            owner=login('changed-admin-password')
            for endpoint in ['credentials','session','users','audit','config','acme']:
                text=json.dumps(call(endpoint,headers=owner))
                for secret in [token,replacement,password,'changed-admin-password',code,'$argon2']:assert secret not in text,(endpoint,secret)
            with sqlite3.connect(Path(directory)/'management.sqlite3') as db:
                hash=db.execute("SELECT password_hash FROM users WHERE id='bootstrap'").fetchone()[0];assert hash.startswith('$argon2') and 'changed-admin-password' not in hash
                assert db.execute("SELECT value FROM secrets WHERE key='cloudflare_token'").fetchone()[0]==replacement
            stop();start();assert not call('setup')['setup_required'];assert 'one-time setup code:' not in log_path.read_text()
            owner=login('changed-admin-password');assert call('credentials',headers=owner)['cloudflare']['configured'];assert call('acme',headers=owner)['configured']
            # Other providers: secrets stay private, switching replaces the Cloudflare row.
            call('credentials/dns','PUT',{'provider':'porkbun','credentials':{'api_key':'pk1_public'}},owner,409)
            call('credentials/dns','PUT',{'provider':'porkbun','credentials':{'api_key':'pk1_public','secret_key':'sk1_private-value','extra':'x'}},owner,409)
            readonly=login('reader-password-123','reader');call('credentials/dns','PUT',{'provider':'porkbun','credentials':{'api_key':'pk1_public','secret_key':'sk1_private-value'}},readonly,403)
            status=call('credentials/dns','PUT',{'provider':'porkbun','credentials':{'api_key':'pk1_public','secret_key':'sk1_private-value'}},owner)
            assert status['provider']=='porkbun' and status['settings']=={'api_key':'pk1_public'}
            assert call('acme',headers=owner)['provider_name']=='Porkbun'
            # A blank secret keeps the saved value.
            call('credentials/dns','PUT',{'provider':'porkbun','credentials':{'api_key':'pk1_changed','secret_key':''}},owner)
            with sqlite3.connect(Path(directory)/'management.sqlite3') as db:
                rows=dict(db.execute("SELECT key,value FROM secrets WHERE key IN ('cloudflare_token','dns_provider')").fetchall())
            assert list(rows)==['dns_provider'] and json.loads(rows['dns_provider'])=={'provider':'porkbun','credentials':{'api_key':'pk1_changed','secret_key':'sk1_private-value'}}
            for endpoint in ['credentials','audit','acme']:assert 'sk1_private' not in json.dumps(call(endpoint,headers=owner)),endpoint
            stop();start();owner=login('changed-admin-password');assert call('credentials',headers=owner)['cloudflare']['provider']=='porkbun'
            call('credentials/dns','PUT',{'provider':'cloudflare','credentials':{'token':replacement}},owner)
            with sqlite3.connect(Path(directory)/'management.sqlite3') as db:
                assert db.execute("SELECT key FROM secrets WHERE key IN ('cloudflare_token','dns_provider')").fetchall()==[('cloudflare_token',)]
            call('credentials/dns','DELETE',headers=owner);assert not call('acme',headers=owner)['configured']
            stop();env['GATEWAY_ADMIN_PASSWORD']='recovery-override-password';env['GATEWAY_CLOUDFLARE_API_TOKEN']='environment-override-token';start();owner=login('recovery-override-password')
            assert not call('session',headers=owner)['password_editable'];assert call('credentials',headers=owner)['cloudflare']['source']=='environment'
            call('password','POST',{'current_password':'recovery-override-password','new_password':'ignored-admin-password'},owner,422)
            call('credentials/cloudflare','DELETE',headers=owner,expected=409)
            call('credentials/cloudflare','PUT',{'token':replacement},owner,409)
            stop();env.pop('GATEWAY_ADMIN_PASSWORD');env.pop('GATEWAY_CLOUDFLARE_API_TOKEN');start();owner=login('changed-admin-password');assert not call('credentials',headers=owner)['cloudflare']['configured']
            print('Credential checks passed: setup-code/CSRF protection, atomic first-run setup, database login, admin password rotation/revocation, live token save/replace/remove, DNS provider save/switch/secret retention/restart, read-only restrictions, persistence, redaction, and environment recovery overrides.')
        finally:stop()
if __name__=='__main__':run()

"""Complete encrypted backups and restart restores with isolated local fixtures."""
import base64,hashlib,http.client,importlib.util,json,os,signal,sqlite3,ssl,subprocess,tempfile,threading,time,uuid
from pathlib import Path
from http.server import ThreadingHTTPServer
spec=importlib.util.spec_from_file_location('smoke',Path(__file__).with_name('proxy-smoke.py'));smoke=importlib.util.module_from_spec(spec);spec.loader.exec_module(smoke)
def run():
    upstream=ThreadingHTTPServer(('127.0.0.1',0),smoke.Upstream);threading.Thread(target=upstream.serve_forever,daemon=True).start()
    ports=[]
    while len(ports)<3:
        p=smoke.free_port()
        if p not in ports:ports.append(p)
    proxy,admin,tls=ports
    with tempfile.TemporaryDirectory(prefix='embergate-backups-') as data_dir:
        data=Path(data_dir);env={**os.environ,'GATEWAY_DATA_DIR':data_dir,'GATEWAY_ADMIN_PASSWORD':'backup-admin-password','GATEWAY_PROXY_ADDR':f'127.0.0.1:{proxy}','GATEWAY_ADMIN_ADDR':f'127.0.0.1:{admin}','GATEWAY_HTTPS_ADDR':f'127.0.0.1:{tls}'}
        for key in ['GATEWAY_ALERT_WEBHOOK_URL','GATEWAY_CLOUDFLARE_API_TOKEN','GATEWAY_CLOUDFLARE_API_TOKEN_FILE']:env.pop(key,None)
        process=None;headers={};binary=str(Path('target/debug/embergate').resolve());passphrase='a-safe-backup-passphrase-123';version=0
        def start():
            nonlocal process,headers
            process=subprocess.Popen([binary],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);smoke.await_ready(process,admin);headers=login()
        def stop():
            if process and process.poll() is None:process.send_signal(signal.SIGINT);process.wait(timeout=15)
        def login(username='admin',password='backup-admin-password'):
            status,h,body=smoke.request(admin,'POST','/api/login',{'username':username,'password':password},{'X-Gateway-Request':'1'});assert status==200,(status,body)
            return {'Cookie':h['set-cookie'].split(';')[0],'X-Gateway-Request':'1'}
        def api(path,method='GET',body=None,expected=200,auth=None):
            status,_,body=smoke.request(admin,method,'/api/'+path,body,headers if auth is None else auth);assert status==expected,(path,status,body[:300]);return json.loads(body) if body else None
        def save():
            nonlocal version
            version=api('config','PUT',{'version':version,'routes':[route]})['version']
        def export(recovery=False):
            status,h,body=smoke.request(admin,'POST','/api/backups/export',{'passphrase':passphrase,'recovery':recovery},headers);assert status==200,(status,body[:300]);assert h['content-type']=='application/octet-stream';assert body.startswith(b'EMBERGATE-BACKUP\0\x01');return body
        def preview(blob,password=passphrase,expected=200,auth=None):return api('backups/preview','POST',{'archive':base64.b64encode(blob).decode(),'passphrase':password},expected,auth)
        def query(filename,sql,params=()):
            with sqlite3.connect(data/filename) as db:return db.execute(sql,params).fetchall()
        def certificate(label):
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN=backup.test','-addext','subjectAltName=DNS:backup.test','-keyout',str(data/(label+'.key')),'-out',str(data/(label+'.pem'))],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            return {'name':label,'certificate_pem':(data/(label+'.pem')).read_text(),'private_key_pem':(data/(label+'.key')).read_text()}
        def handshake_pem():
            ctx=ssl._create_unverified_context()
            with ctx.wrap_socket(__import__('socket').create_connection(('127.0.0.1',tls)),server_hostname='backup.test') as conn:return conn.getpeercert(binary_form=True)
        try:
            start();assert api('backups/status')['encrypted'];assert not api('backups/status')['pending']
            route={'id':str(uuid.uuid4()),'name':'Original host','host':'backup.test','path_prefix':'/','upstream':f'http://127.0.0.1:{upstream.server_port}','enabled':True,'preserve_host':False,'routing':{'rewrite_prefix':'/old'}};save()
            reader=api('users','POST',{'username':'reader','password':'original-reader-password','role':'read_only'},201)['user'];read_auth=login('reader','original-reader-password')
            api('backups/status',expected=403,auth=read_auth);api('backups/export','POST',{'passphrase':passphrase},403,read_auth)
            assert smoke.request(admin,'POST','/api/backups/export',{'passphrase':passphrase},{'Cookie':headers['Cookie']})[0]==403
            api('credentials/cloudflare','PUT',{'token':'original-cloudflare-secret'})
            alert_version=api('alerts')['settings']['version'];api('alerts/destination','PUT',{'url':'http://127.0.0.1:1/original-webhook-secret','webhook_format':'generic','version':alert_version})
            old_metrics_token=api('integrations/prometheus','POST')['token']
            old_cert=certificate('Original certificate');cert=api('certificates','POST',old_cert)['certificates'][0];original_cert=handshake_pem()
            # A real PKCS8 ACME account fixture must be included without contacting a CA.
            der=subprocess.check_output(['openssl','pkey','-in',str(data/'Original certificate.key'),'-outform','DER'],stderr=subprocess.DEVNULL)
            account_file='acme-account-'+'a'*64+'.json';account=json.dumps({'id':'https://acme.test/account/fixture','key_pkcs8':base64.urlsafe_b64encode(der).decode().rstrip('='),'directory':'https://acme.test/directory'}).encode();(data/account_file).write_bytes(account);(data/account_file).chmod(0o600)
            assert smoke.request(proxy,'GET','/original-log',headers={'Host':'backup.test'})[0]==200;time.sleep(.15)
            # Exercise an upload larger than the management API's ordinary 1 MiB body limit.
            with sqlite3.connect(data/'analytics.sqlite3') as db:
                db.executemany('INSERT INTO logs(timestamp,payload) VALUES(?,?)',[(int(time.time()),json.dumps({'timestamp':int(time.time()),'method':'GET','host':'backup.test','path':'/filler-'+str(i),'status':200,'latency_ms':0,'padding':'x'*4096})) for i in range(350)])
            blob=export();assert len(blob)>1024*1024
            for secret in [b'original-cloudflare-secret',b'original-webhook-secret',b'BEGIN PRIVATE KEY',b'original-reader-password',passphrase.encode()]:assert secret not in blob
            preview(blob,password='wrong-backup-password',expected=422);damaged=bytearray(blob);damaged[-1]^=1;preview(damaged,expected=422)
            assert not api('backups/status')['pending'];assert api('config')['routes'][0]['name']=='Original host'
            review=preview(blob);assert len(review['summary']['accounts'])==2 and len(review['summary']['certificates'])==1;assert 'cloudflare_token' in review['summary']['credential_types'];assert 'original-cloudflare-secret' not in json.dumps(review)
            # A review becomes stale when another management edit commits.
            route['name']='Changed host';route['routing']={'rewrite_prefix':'/new'};save();api('backups/restore','POST',{'id':review['id'],'confirm':'RESTORE'},422)
            api('users/'+reader['id'],'PUT',{**reader,'password':'changed-reader-password'})
            api('credentials/cloudflare','PUT',{'token':'changed-cloudflare-secret'});new_metrics_token=api('integrations/prometheus','POST')['token']
            new_cert=certificate('Replacement certificate');api('certificates/'+cert['id'],'PUT',new_cert);assert handshake_pem()!=original_cert
            review=preview(blob);another=login();api('backups/restore','POST',{'id':review['id'],'confirm':'RESTORE'},422,another)
            api('backups/restore','POST',{'id':review['id'],'confirm':'wrong'},422)
            api('backups/restore','POST',{'id':review['id'],'confirm':'RESTORE'});assert api('backups/status')['pending']
            api('config','PUT',{'version':version,'routes':[]},409)
            # Another process using the same data directory must not apply the pending restore.
            other=subprocess.Popen([binary],env={**env,'GATEWAY_ADMIN_ADDR':f'127.0.0.1:{smoke.free_port()}'},stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);assert other.wait(timeout=5)!=0
            assert api('config')['routes'][0]['name']=='Changed host'
            traffic=smoke.request(proxy,'GET','/still-live',headers={'Host':'backup.test'});assert traffic[0]==200 and json.loads(traffic[2])['path']=='/new/still-live'
            api('backups/cancel','POST');assert not api('backups/status')['pending']
            review=preview(blob);api('backups/restore','POST',{'id':review['id'],'confirm':'RESTORE'})
            old_session=headers.copy();stop();start();assert smoke.request(admin,'GET','/api/config',headers=old_session)[0]==401
            restored=api('config');assert restored['routes'][0]['name']=='Original host' and restored['routes'][0]['routing']['rewrite_prefix']=='/old'
            assert json.loads((data/'routes.previous.json').read_text())['routes']==[]
            login('reader','original-reader-password');assert query('management.sqlite3',"SELECT value FROM secrets WHERE key='cloudflare_token'")[0][0]=='original-cloudflare-secret'
            assert handshake_pem()==original_cert and (data/account_file).read_bytes()==account
            assert smoke.request(admin,'GET','/metrics',headers={'Authorization':'Bearer '+old_metrics_token})[0]==200;assert smoke.request(admin,'GET','/metrics',headers={'Authorization':'Bearer '+new_metrics_token})[0]==401
            assert query('analytics.sqlite3',"SELECT COUNT(*) FROM logs WHERE payload LIKE '%original-log%'")[0][0]>=1
            status=api('backups/status');assert status['recovery_available'] and not status['pending'];assert status['last_restore']['restored_at']
            recovery=export(recovery=True);review=preview(recovery);assert review['summary']['routes'][0]['name']=='Changed host'
            # Keep the original restored installation; reviewing recovery does not replace it.
            assert api('config')['routes'][0]['name']=='Original host'
            text=json.dumps(api('audit'))+json.dumps(api('backups/status'))
            for secret in [passphrase,'original-cloudflare-secret','changed-cloudflare-secret','BEGIN PRIVATE KEY']:assert secret not in text
            base=data/'.embergate-backups';assert base.stat().st_mode&0o777==0o700
            assert all(p.stat().st_mode&0o777==0o600 for p in base.rglob('*') if p.is_file() and not p.name.endswith('-shm'))
        finally:
            stop();upstream.shutdown();upstream.server_close()
    print('Backup integration passed: encrypted >1 MiB snapshots, roles/CSRF, wrong-passphrase/tamper rejection, review ownership/staleness, queue/cancel/freeze, data-directory lock, restart restoration, accounts/routes/TLS keys/ACME credentials/secrets/analytics, token restoration, session invalidation, recovery export, and private permissions.')
if __name__=='__main__':run()

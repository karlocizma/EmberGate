"""Automatic encrypted backups, retention, offsite copies, notifications, and restart restore."""
import base64,http.client,importlib.util,json,os,signal,sqlite3,subprocess,tempfile,threading,time,uuid
from pathlib import Path
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
spec=importlib.util.spec_from_file_location('smoke',Path(__file__).with_name('proxy-smoke.py'));smoke=importlib.util.module_from_spec(spec);spec.loader.exec_module(smoke)
copies=[];notifications=[];upload_started=threading.Event();release_upload=threading.Event();release_upload.set()
class Storage(BaseHTTPRequestHandler):
    def do_PUT(self):
        body=self.rfile.read(int(self.headers['Content-Length']));copies.append((self.path,dict(self.headers),body));upload_started.set();release_upload.wait(25)
        self.send_response(self.server.status)
        if self.server.status==302:self.send_header('Location',f'http://127.0.0.1:{self.server.server_port}/redirect-trap/')
        self.send_header('Content-Length','0');self.end_headers()
    def do_POST(self):
        notifications.append(json.loads(self.rfile.read(int(self.headers['Content-Length']))));self.send_response(204);self.end_headers()
    def log_message(self,*args):pass

def run():
    storage=ThreadingHTTPServer(('127.0.0.1',0),Storage);storage.status=201;threading.Thread(target=storage.serve_forever,daemon=True).start()
    with tempfile.TemporaryDirectory(prefix='embergate-scheduled-') as directory:
        data=Path(directory);admin,proxy=smoke.free_port(),smoke.free_port();process=None;owner={}
        env={k:v for k,v in os.environ.items() if not k.startswith('GATEWAY_')};env.update(GATEWAY_ADMIN_PASSWORD='scheduled-admin-password',GATEWAY_DATA_DIR=directory,GATEWAY_ADMIN_ADDR=f'127.0.0.1:{admin}',GATEWAY_PROXY_ADDR=f'127.0.0.1:{proxy}')
        binary=str(Path('target/debug/embergate').resolve());passphrase='private-automatic-backup-passphrase';offsite_token='private-offsite-bearer-token';manual_passphrase='manual-export-passphrase'
        def request(path,method='GET',body=None,auth=None):
            conn=http.client.HTTPConnection('127.0.0.1',admin,timeout=40);conn.request(method,'/api/'+path,json.dumps(body) if body is not None else None,{'Content-Type':'application/json',**(owner if auth is None else auth)});response=conn.getresponse();result=(response.status,dict(response.getheaders()),response.read());conn.close();return result
        def api(path,method='GET',body=None,auth=None,expected=200):
            status,_,body=request(path,method,body,auth);assert status==expected,(path,status,body[:300]);return json.loads(body)
        def login(name='admin',password='scheduled-admin-password'):
            status,h,b=request('login','POST',{'username':name,'password':password},{'X-Gateway-Request':'1'});assert status==200,(status,b);return {'Cookie':h['set-cookie'].split(';')[0],'X-Gateway-Request':'1'}
        def start():
            nonlocal process,owner
            process=subprocess.Popen([binary],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);smoke.await_ready(process,admin);owner=login()
        def stop():
            if process and process.poll() is None:process.send_signal(signal.SIGINT);process.wait(timeout=15)
        def state():return api('backups/schedule')
        def wait(predicate,seconds=30):
            deadline=time.monotonic()+seconds
            while time.monotonic()<deadline:
                value=predicate()
                if value:return value
                time.sleep(.1)
            raise AssertionError('Timed out waiting for scheduler: '+json.dumps(state()))
        def saved(**updates):
            body={**state()['settings'],'passphrase':None,'remove_passphrase':False,'offsite_url':None,'auth':None,**updates};api('backups/schedule','PUT',body);return body
        def run_now():
            previous=state()['runtime']['last_attempt'];api('backups/schedule/run','POST',expected=202)
            def done():
                s=state();return s if not s['runtime']['requested'] and not s['running'] and s['runtime']['last_attempt']!=previous else None
            wait(done,40)
            return state()
        def mutate_runtime(**updates):
            with sqlite3.connect(data/'management.sqlite3') as db:
                value=json.loads(db.execute("SELECT value FROM secrets WHERE key='backup_schedule_state'").fetchone()[0]);value.update(updates);db.execute("UPDATE secrets SET value=? WHERE key='backup_schedule_state'",(json.dumps(value),))
        def preview(blob,password):return api('backups/preview','POST',{'archive':base64.b64encode(blob).decode(),'passphrase':password})
        try:
            start();initial=state();assert not initial['settings']['enabled'] and not initial['passphrase_configured'] and initial['files']==[]
            api('users','POST',{'username':'reader','password':'reader-password-123','role':'read_only'},expected=201);reader=login('reader','reader-password-123')
            for endpoint,method in [('backups/schedule','GET'),('backups/schedule','PUT'),('backups/schedule/run','POST'),('backups/scheduled/no-file','GET'),('backups/scheduled/no-file','DELETE')]:api(endpoint,method,{},reader,403)
            api('backups/schedule','PUT',{}, {'Cookie':owner['Cookie']},403);api('backups/schedule/run','POST',expected=409)
            valid={**initial['settings'],'enabled':True,'passphrase':passphrase,'retain_count':2,'interval_hours':1,'offsite_url':None,'auth':None}
            for wrong in [{**valid,'passphrase':'short'},{**valid,'interval_hours':0},{**valid,'retain_count':31},{**valid,'offsite_url':'http://not-local.test/','auth':{'kind':'none'}},{**valid,'offsite_url':'https://storage.test/?token=secret','auth':{'kind':'none'}}]:api('backups/schedule','PUT',wrong,expected=422)
            api('backups/schedule','PUT',valid);api('backups/schedule','PUT',valid,expected=422)
            result=run_now();assert not result['runtime']['last_error'] and len(result['files'])==1
            first=result['files'][0]['name'];status,h,blob=request('backups/scheduled/'+first);assert status==200 and blob.startswith(b'EMBERGATE-BACKUP\0\x01') and 'attachment' in h['content-disposition']
            assert passphrase.encode() not in blob;review=preview(blob,passphrase);assert 'backup_schedule' in review['summary']['credential_types'];assert 'backup_schedule_passphrase' not in json.dumps(review)
            api('backups/preview','POST',{'archive':base64.b64encode(blob).decode(),'passphrase':'incorrect-passphrase'},expected=422)
            run_now();result=run_now();assert len(result['files'])==2 and first not in [f['name'] for f in result['files']]
            assert api('config')['routes']==[]
            # Directory permissions and unknown files: retention owns only canonical archive names.
            folder=data/'.embergate-backups'/'scheduled';(folder/'keep-me.txt').write_text('unrelated')
            assert folder.stat().st_mode&0o777==0o700;assert all(p.stat().st_mode&0o777==0o600 for p in folder.glob('*.embergate'))
            future=folder/('embergate-auto-00000009999999999999-'+str(uuid.uuid4())+'.embergate');future.write_bytes(blob);future.chmod(0o600)
            saved(offsite_url=f'http://127.0.0.1:{storage.server_port}/private-folder/',auth={'kind':'bearer','secret':offsite_token},retain_count=1)
            result=run_now();assert len(copies)==1 and result['runtime']['last_offsite_success'];remote_path,headers,remote_blob=copies[-1]
            assert remote_path.startswith('/private-folder/embergate-auto-') and headers['authorization']=='Bearer '+offsite_token and headers['if-none-match']=='*'
            assert remote_blob.startswith(b'EMBERGATE-BACKUP\0\x01') and passphrase.encode() not in remote_blob and (folder/'keep-me.txt').exists() and not future.exists()
            public=json.dumps(state());assert passphrase not in public and offsite_token not in public and 'private-folder' not in public
            # Open/recovery alerts use the existing opt-in durable delivery queue.
            preferences=api('alerts')['settings'];api('alerts/destination','PUT',{'url':f'http://127.0.0.1:{storage.server_port}/notify','webhook_format':'generic','version':preferences['version']});preferences=api('alerts')['settings'];preferences['webhook_enabled']=True;api('alerts/settings','PUT',preferences)
            storage.status=500;result=run_now();assert 'HTTP 500' in result['runtime']['last_error'] and result['files']
            opened=wait(lambda:next((a for a in api('alerts')['alerts'] if a['source']=='backup' and not a['resolved_at']),None));wait(lambda:any(n['event']=='opened' and n['alert']['source']=='backup' for n in notifications))
            # During retry the old failure stays open; management remains available while uploading.
            storage.status=201;release_upload.clear();upload_started.clear();api('backups/schedule/run','POST',expected=202);assert upload_started.wait(8)
            assert state()['running'];api('backups/schedule','PUT',{**valid,'version':state()['settings']['version']},expected=409)
            start_time=time.monotonic();api('config','PUT',{'version':0,'routes':[]});assert time.monotonic()-start_time<2
            time.sleep(11);assert any(a['id']==opened['id'] and not a['resolved_at'] for a in api('alerts')['alerts'])
            release_upload.set();wait(lambda:not state()['running']);wait(lambda:any(a['id']==opened['id'] and a['resolved_at'] for a in api('alerts')['alerts']));wait(lambda:any(n['event']=='resolved' and n['alert']['source']=='backup' for n in notifications))
            # Redirects do not receive forwarded credentials; a local backup remains on failure.
            storage.status=302;before=len(copies);result=run_now();assert 'HTTP 302' in result['runtime']['last_error'] and len(copies)==before+1
            storage.status=201
            saved(offsite_url=f'http://127.0.0.1:{storage.server_port}/basic/',auth={'kind':'basic','username':'backup-user','secret':'private-app-password'})
            run_now();assert copies[-1][1]['authorization']=='Basic '+base64.b64encode(b'backup-user:private-app-password').decode()
            # One missed scheduled interval catches up after restart; no client-side timer is needed.
            before=state()['runtime']['last_file'];stop();mutate_runtime(next_run_at=int(time.time())-1,requested=False);start();wait(lambda:state()['runtime']['last_file']!=before and not state()['running']);assert state()['passphrase_configured']
            # Interrupted jobs get a durable retry deadline rather than remaining stuck as running.
            stop();mutate_runtime(running=True,next_run_at=int(time.time())-1);start();wait(lambda:'interrupted' in (state()['runtime']['last_error'] or ''));assert not state()['running'] and state()['runtime']['requested'] and state()['runtime']['next_run_at']>time.time()
            # Every full export, including recovery export, can restore without importing the automation passphrase.
            status,_,manual=request('backups/export','POST',{'passphrase':manual_passphrase});assert status==200
            review=preview(manual,manual_passphrase);api('backups/restore','POST',{'id':review['id'],'confirm':'RESTORE'});api('backups/schedule/run','POST',expected=409)
            before=len(copies);time.sleep(6);assert len(copies)==before;stop();start();assert state()['settings']['enabled'] and not state()['passphrase_configured'];assert not state()['runtime']['requested'] and not state()['runtime']['running']
            status,_,recovery=request('backups/export','POST',{'passphrase':manual_passphrase,'recovery':True});assert status==200;preview(recovery,manual_passphrase)
            assert all(secret not in json.dumps(api('audit'))+json.dumps(state()) for secret in [passphrase,offsite_token,'private-app-password',manual_passphrase])
            saved(enabled=False,offsite_url='',remove_passphrase=True)
            for file in state()['files']:api('backups/scheduled/'+file['name'],'DELETE')
            assert not state()['files'] and (folder/'keep-me.txt').exists()
            api('backups/scheduled/%2e%2e%2fmanagement.sqlite3',expected=404)
            print('Scheduled backup checks passed: encryption/download/restore, key exclusion/recovery exports, private storage, safe retention, immediate/due/restart/interrupted execution, roles/CSRF/validation/versions, bearer/Basic offsite uploads, redirects, local fallback, failure/recovery notifications, in-flight management access, restore pause, and credential/audit redaction.')
        finally:
            release_upload.set();stop();storage.shutdown();storage.server_close()
if __name__=='__main__':run()

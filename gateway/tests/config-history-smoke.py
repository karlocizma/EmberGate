"""Configuration revision durability, reviewed rollback, permissions and backup compatibility."""
import base64, copy, importlib.util, json, os, signal, subprocess, tempfile, threading, uuid
from pathlib import Path
from http.server import ThreadingHTTPServer
spec=importlib.util.spec_from_file_location('smoke',Path(__file__).with_name('proxy-smoke.py'));smoke=importlib.util.module_from_spec(spec);spec.loader.exec_module(smoke)
def run():
    origin=ThreadingHTTPServer(('127.0.0.1',0),smoke.Upstream);threading.Thread(target=origin.serve_forever,daemon=True).start()
    with tempfile.TemporaryDirectory(prefix='embergate-history-') as directory:
        data=Path(directory);admin,proxy=smoke.free_port(),smoke.free_port();process=None;headers={}
        env={k:v for k,v in os.environ.items() if not k.startswith('GATEWAY_')}
        env.update(GATEWAY_ADMIN_PASSWORD='history-admin-password',GATEWAY_DATA_DIR=directory,GATEWAY_ADMIN_ADDR=f'127.0.0.1:{admin}',GATEWAY_PROXY_ADDR=f'127.0.0.1:{proxy}')
        def api(path,method='GET',body=None,expected=200,auth=None):
            status,h,result=smoke.request(admin,method,'/api/'+path,body,headers if auth is None else auth);assert status==expected,(path,status,result[:500]);return json.loads(result) if result else None
        def login(username='admin',password='history-admin-password'):
            status,h,_=smoke.request(admin,'POST','/api/login',{'username':username,'password':password},{'X-Gateway-Request':'1'});assert status==200
            return {'Cookie':h['set-cookie'].split(';')[0],'X-Gateway-Request':'1'}
        def start():
            nonlocal process,headers
            process=subprocess.Popen([str(Path('target/debug/embergate').resolve())],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);smoke.await_ready(process,admin);headers=login()
        def stop():
            if process and process.poll() is None:process.send_signal(signal.SIGINT);process.wait(timeout=15)
        def save(config):return api('config','PUT',config)
        def backup():
            status,_,blob=smoke.request(admin,'POST','/api/backups/export',{'passphrase':'history-backup-passphrase'},headers);assert status==200,(status,blob[:300]);return blob
        def restore(blob):
            review=api('backups/preview','POST',{'archive':base64.b64encode(blob).decode(),'passphrase':'history-backup-passphrase'})
            api('backups/restore','POST',{'id':review['id'],'confirm':'RESTORE'});stop();start()
        try:
            start();assert api('config/history')['revisions']==[]
            first=save({'version':0,'routes':[{'id':str(uuid.uuid4()),'name':'Original <host>','host':'history.test','path_prefix':'/','upstream':f'http://127.0.0.1:{origin.server_port}','enabled':True,'preserve_host':False,'routing':{'rewrite_prefix':'/old'}}]})
            second=copy.deepcopy(first);second['routes'][0]['routing']['rewrite_prefix']='/new';second['routes'][0]['enabled']=False
            second['trusted_proxies']=[{'network':'127.0.0.1/32','header':'x_forwarded_for','trust_proto':False}];second=save(second)
            revisions=api('config/history')['revisions'];assert [r['version'] for r in revisions]==[1,0];target=revisions[0]['id'];assert revisions[0]['archived_by']=='admin'
            review=api('config/history/'+target);assert review['expected_version']==2
            assert {c['field'] for c in review['comparison']['routes'][0]['changes']}=={'/enabled','/routing/rewrite_prefix'}
            assert review['comparison']['trusted_proxies']['after']==[]
            api('users','POST',{'username':'reader','password':'history-reader-password','role':'read_only'},201);reader=login('reader','history-reader-password')
            for path in ['config/history','config/history/'+target]:api(path,expected=403,auth=reader)
            api('config/history',expected=401,auth={})
            api('config/history/'+target+'/rollback','POST',{'expected_version':2,'confirm':'ROLLBACK'},403,reader)
            api('config/history/'+target+'/rollback','POST',{'expected_version':2,'confirm':'ROLLBACK'},403,{'Cookie':headers['Cookie']})
            api('config/history/'+target+'/rollback','POST',{'expected_version':2,'confirm':''},422)
            third=save(second)
            api('config/history/'+target+'/rollback','POST',{'expected_version':2,'confirm':'ROLLBACK'},409)
            assert api('config')['version']==3
            restored=api('config/history/'+target+'/rollback','POST',{'expected_version':3,'confirm':'ROLLBACK'})
            assert restored['version']==4 and restored['routes']==first['routes'] and restored.get('trusted_proxies',[])==[]
            status,_,body=smoke.request(proxy,'GET','/hello',headers={'Host':'history.test'});assert status==200 and json.loads(body)['path']=='/old/hello'
            # A failed route commit only archives a previously active configuration, never its failed candidate.
            previous=data/'routes.previous.json';previous.unlink();previous.mkdir();failed=copy.deepcopy(restored);failed['routes'][0]['name']='Failed candidate'
            save_result=api('config','PUT',failed,500);assert api('config')['version']==4
            assert all(entry['config']['routes'][0]['name']!='Failed candidate' for entry in json.loads((data/'configuration-history.json').read_text()) if entry['config']['routes'])
            assert all(entry['version']!=4 for entry in api('config/history')['revisions']);previous.rmdir()
            assert (data/'configuration-history.json').stat().st_mode&0o777==0o600
            before=api('config/history');stop();start();assert api('config/history')==before
            blob=backup();changed=api('config');changed['routes']=[];save(changed);restore(blob)
            assert api('config')['version']==4 and api('config/history')==before
            # Archives from older releases without a history file remain valid and remove newer history on restore.
            (data/'configuration-history.json').unlink();legacy=backup();save(api('config'));assert (data/'configuration-history.json').exists();restore(legacy)
            assert not (data/'configuration-history.json').exists() and api('config/history')['revisions']==[]
            # Bounded retention persists and drops selectors that have expired.
            current=api('config')
            for _ in range(54):current=save(current)
            entries=api('config/history')['revisions'];assert len(entries)==50 and entries[0]['version']==current['version']-1
            api('config/history/'+target,expected=404)
            # Damaged history cannot silently erase the retained record or permit an untracked edit.
            history=data/'configuration-history.json';original=history.read_bytes();value=json.loads(original);value[0]['config']['version']=999;history.write_text(json.dumps(value))
            api('config/history',expected=503);api('config','PUT',current,500);assert api('config')['version']==current['version'];history.write_bytes(original)
            events=api('audit')['events'];assert any(e['path'].endswith('/rollback') and e['phase']=='success' and e['details']['rollback_source_version']==1 and e['details']['rollback_source_id']==target for e in events)
            print('Configuration history passed: field comparisons, live rollback, stale review/CSRF/roles, failed saves, restart, private retention, corrupt data, encrypted restore and legacy backup compatibility.')
        finally:stop();origin.shutdown();origin.server_close()
if __name__=='__main__':run()

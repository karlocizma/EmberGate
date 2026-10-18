"""Private template CRUD, independent copies, versioning and complete backup compatibility."""
import base64, copy, importlib.util, json, os, signal, subprocess, tempfile, time, uuid
from pathlib import Path
spec=importlib.util.spec_from_file_location('smoke',Path(__file__).with_name('proxy-smoke.py'));smoke=importlib.util.module_from_spec(spec);spec.loader.exec_module(smoke)
def run():
    with tempfile.TemporaryDirectory(prefix='embergate-templates-') as directory:
        data=Path(directory);admin,proxy=smoke.free_port(),smoke.free_port();process=None;headers={}
        env={k:v for k,v in os.environ.items() if not k.startswith('GATEWAY_')};env.update(GATEWAY_ADMIN_PASSWORD='template-admin-password',GATEWAY_DATA_DIR=directory,GATEWAY_ADMIN_ADDR=f'127.0.0.1:{admin}',GATEWAY_PROXY_ADDR=f'127.0.0.1:{proxy}')
        def api(path,method='GET',body=None,expected=200,auth=None):
            status,_,result=smoke.request(admin,method,'/api/'+path,body,headers if auth is None else auth);assert status==expected,(path,status,result[:500])
            try:return json.loads(result) if result else None
            except json.JSONDecodeError:return {'error':result.decode()}
        def login(username='admin',password='template-admin-password'):
            status,h,_=smoke.request(admin,'POST','/api/login',{'username':username,'password':password},{'X-Gateway-Request':'1'});assert status==200
            return {'Cookie':h['set-cookie'].split(';')[0],'X-Gateway-Request':'1'}
        def start():
            nonlocal process,headers
            process=subprocess.Popen([str(Path('target/debug/embergate').resolve())],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);smoke.await_ready(process,admin);headers=login()
        def stop():
            if process and process.poll() is None:process.send_signal(signal.SIGINT);process.wait(timeout=15)
        def export():
            status,_,blob=smoke.request(admin,'POST','/api/backups/export',{'passphrase':'template-backup-passphrase'},headers);assert status==200,(status,blob[:300]);return blob
        def preview(blob):return api('backups/preview','POST',{'archive':base64.b64encode(blob).decode(),'passphrase':'template-backup-passphrase'})
        def restore(blob):
            review=preview(blob);api('backups/restore','POST',{'id':review['id'],'confirm':'RESTORE'});stop();start()
        try:
            start();assert api('host-templates')=={'version':0,'templates':[]}
            route={'id':str(uuid.uuid4()),'name':'Reusable source','host':'source.test','path_prefix':'/app','upstream':'http://127.0.0.1:9000','enabled':True,'preserve_host':True,'additional_upstreams':['http://127.0.0.1:9001'],'balancing':{'strategy':'weighted_round_robin','weights':[3,1],'draining':['http://127.0.0.1:9001']},'cache':{'max_ttl_seconds':30,'max_object_bytes':1024},'access':{'mode':'block','networks':['192.0.2.1']},'response':{'nosniff':True,'custom_headers':[{'name':'X-App','value':'header-private-fixture'}]},'routing':{'rewrite_prefix':'/internal','set_headers':[{'name':'X-Private','value':'template-private-fixture'}]},'rate_limit':{'requests':60,'window_seconds':60,'burst':10},'reliability':{'connect_timeout_seconds':3,'read_timeout_seconds':4,'write_timeout_seconds':5,'retries':1},'health_check':{'path':'/health','interval_seconds':30,'timeout_seconds':1,'failure_threshold':2,'recovery_threshold':1},'pages':{'maintenance':True,'branded_errors':False}}
            config=api('config','PUT',{'version':0,'routes':[route]})
            request={'name':'Public <template>','description':'Reusable settings','source_route_id':route['id'],'expected_config_version':config['version'],'expected_version':0}
            api('host-templates',expected=401,auth={});api('host-templates','POST',request,403,{'Cookie':headers['Cookie']})
            api('users','POST',{'username':'reader','password':'template-reader-password','role':'read_only'},201);reader=login('reader','template-reader-password')
            api('host-templates',expected=403,auth=reader);api('host-templates','POST',request,403,reader)
            for wrong in [{**request,'name':''},{**request,'name':'x'*81},{**request,'description':'bad\ntext'},{**request,'source_route_id':None},{**request,'policies':{'enabled':True}}]:api('host-templates','POST',wrong,422)
            api('host-templates','POST',{**request,'expected_config_version':0},409)
            store=api('host-templates','POST',request);assert store['version']==1 and len(store['templates'])==1
            template=store['templates'][0];target=template['id'];policies=template['policies'];assert template['updated_by']=='admin'
            assert policies['preserve_host'] and not policies['branded_errors']
            for key in ['cache','access','response','routing','rate_limit','reliability','health_check']:assert policies[key]==config['routes'][0][key]
            for key in ['id','name','host','path_prefix','upstream','additional_upstreams','balancing','pages','enabled']:assert key not in policies
            assert api('config')==config
            assert (data/'host-templates.json').stat().st_mode&0o777==0o600
            api('host-templates/'+target,'DELETE',{'expected_version':1},403,reader)
            api('host-templates','POST',request,409)
            api('host-templates','POST',{**request,'expected_version':1,'name':' public <TEMPLATE> '},422)
            # A template is a copy; source edits cannot change it, and metadata edits need no source host.
            changed=copy.deepcopy(config);changed['routes'][0]['cache']['max_ttl_seconds']=900;changed=api('config','PUT',changed)
            assert api('host-templates')['templates'][0]['policies']==policies
            store=api('host-templates','POST',{'id':target,'name':'Renamed template','description':'Keep saved policies','expected_version':1});assert store['templates'][0]['policies']==policies and api('config')==changed
            api('host-templates','POST',{**request,'id':target,'expected_version':2},409)
            update={**request,'id':target,'name':'Updated template','expected_version':2,'expected_config_version':changed['version']}
            store=api('host-templates','POST',update);assert store['templates'][0]['policies']['cache']['max_ttl_seconds']==900
            before=api('host-templates');stop();start();assert api('host-templates')==before
            # Automatic snapshots use the same owned-file capture and retain template policies.
            schedule=api('backups/schedule')['settings']
            api('backups/schedule','PUT',{**schedule,'passphrase':'template-backup-passphrase','remove_passphrase':False,'offsite_url':None,'auth':None})
            api('backups/schedule/run','POST',expected=202)
            deadline=time.monotonic()+20
            while time.monotonic()<deadline:
                automatic=api('backups/schedule')
                if automatic['files'] and not automatic['running']:break
                time.sleep(.1)
            assert automatic['files'] and not automatic['runtime']['last_error']
            status,_,automatic_blob=smoke.request(admin,'GET','/api/backups/scheduled/'+automatic['files'][0]['name'],headers=headers);assert status==200
            assert preview(automatic_blob)['summary']['host_templates']==1
            blob=export();review=preview(blob);assert review['summary']['host_templates']==1
            # Template changes invalidate a previously reviewed complete restore.
            store=api('host-templates','POST',{'id':target,'name':'Changed after review','expected_version':store['version']})
            api('backups/restore','POST',{'id':review['id'],'confirm':'RESTORE'},422)
            review=preview(blob);api('backups/restore','POST',{'id':review['id'],'confirm':'RESTORE'})
            api('host-templates','POST',{'id':target,'name':'Frozen','expected_version':store['version']},409)
            api('host-templates/'+target,'DELETE',{'expected_version':store['version']},409)
            assert api('host-templates')['version']==store['version'];stop();start()
            assert api('host-templates')==before and api('config')==changed
            # Earlier backup versions without templates remain supported and clear newer template files.
            (data/'host-templates.json').unlink();legacy=export();assert preview(legacy)['summary']['host_templates']==0
            store=api('host-templates','POST',{**request,'expected_config_version':changed['version']});restore(legacy)
            assert api('host-templates')=={'version':0,'templates':[]} and not (data/'host-templates.json').exists()
            store=api('host-templates','POST',{**request,'expected_config_version':changed['version']});target=store['templates'][0]['id']
            api('host-templates/'+target,'DELETE',{'expected_version':0},409)
            api('host-templates/'+str(uuid.uuid4()),'DELETE',{'expected_version':1},404)
            store=api('host-templates/'+target,'DELETE',{'expected_version':1});assert store['templates']==[] and store['version']==2 and api('config')==changed
            # Corrupt or symlinked storage is rejected rather than silently reset.
            file=data/'host-templates.json';valid=file.read_bytes();file.write_text('{"version":2,"templates":[],"unknown":true}');api('host-templates',expected=503);file.write_bytes(valid)
            file.unlink();file.symlink_to(data/'routes.json');api('host-templates',expected=503);file.unlink();file.write_bytes(valid)
            audit=json.dumps(api('audit'));assert 'template-private-fixture' not in audit and 'header-private-fixture' not in audit
            assert any(event['details'].get('template_version_after')==2 for event in api('audit')['events'])
            print('Host templates passed: validated independent policy copies, create/edit/replace/delete, names, source/store conflicts, roles/CSRF, private durability, corrupt/link rejection, audit redaction, manual/automatic encrypted snapshots, complete restoration and legacy compatibility.')
        finally:stop()
if __name__=='__main__':run()

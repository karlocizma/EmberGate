"""API tokens and embergate-cli against a real gateway: scopes, host commands, exit codes, and backup export."""
import importlib.util, json, os, signal, subprocess, tempfile, uuid
from pathlib import Path
spec=importlib.util.spec_from_file_location('smoke',Path(__file__).with_name('proxy-smoke.py'));smoke=importlib.util.module_from_spec(spec);spec.loader.exec_module(smoke)
CLI=str(Path('target/debug/embergate-cli').resolve())
def run():
    with tempfile.TemporaryDirectory(prefix='embergate-cli-') as directory:
        data=Path(directory);admin,proxy=smoke.free_port(),smoke.free_port()
        env={k:v for k,v in os.environ.items() if not k.startswith(('GATEWAY_','EMBERGATE_'))};env.update(GATEWAY_ADMIN_PASSWORD='cli-admin-password',GATEWAY_DATA_DIR=directory,GATEWAY_ADMIN_ADDR=f'127.0.0.1:{admin}',GATEWAY_PROXY_ADDR=f'127.0.0.1:{proxy}')
        process=subprocess.Popen([str(Path('target/debug/embergate').resolve())],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            smoke.await_ready(process,admin)
            status,h,_=smoke.request(admin,'POST','/api/login',{'username':'admin','password':'cli-admin-password'},{'X-Gateway-Request':'1'});assert status==200
            session={'Cookie':h['set-cookie'].split(';')[0],'X-Gateway-Request':'1'}
            def token(scope):
                status,_,body=smoke.request(admin,'POST','/api/tokens',{'name':'cli '+scope,'scope':scope,'expires_in_days':7},session);assert status==201,body
                return json.loads(body)['token']
            full,read=token('full'),token('read_only')
            def cli(*args,secret=full,expected=0,extra=None):
                environment={'PATH':os.environ['PATH'],'EMBERGATE_URL':f'http://127.0.0.1:{admin}','EMBERGATE_TOKEN':secret,**(extra or {})}
                result=subprocess.run([CLI,*args],env=environment,capture_output=True,text=True,timeout=60)
                assert result.returncode==expected,(args,result.returncode,result.stdout,result.stderr)
                return result.stdout
            assert 'EmberGate ' in cli('status') and json.loads(cli('--json','status'))['version']
            assert cli('hosts','list').strip()=='No hosts yet.'
            routes=data/'routes.json'
            route={'id':str(uuid.uuid4()),'name':'Photos','host':'photos.test','path_prefix':'/','upstream':'http://127.0.0.1:9','enabled':True,'preserve_host':True}
            routes.write_text(json.dumps([route,{**route,'id':'','name':'Wiki','host':'wiki.test'}]))
            assert cli('hosts','apply',str(routes)).strip()=='Applied: 2 created, 0 replaced.'
            listing=cli('hosts','list');assert listing.splitlines()[0].split()==['ID','NAME','HOST','UPSTREAM','STATUS'] and 'photos.test' in listing and 'wiki.test' in listing
            assert json.loads(cli('hosts','show','photos.test'))['id']==route['id']
            assert cli('hosts','disable','Photos').strip()=='Photos is now paused.'
            assert json.loads(cli('--json','hosts','list'))[0]['enabled'] is False
            assert 'already paused' in cli('hosts','disable',route['id'])
            assert cli('hosts','enable','photos.test').strip()=='Photos is now active.'
            cli('hosts','delete','wiki.test',expected=2)
            assert cli('hosts','delete','wiki.test','--yes').startswith('Deleted Wiki')
            cli('hosts','show','wiki.test',expected=4)
            assert 'Purged 0' in cli('cache','purge','photos.test')
            assert 'Current revision' in cli('history')
            assert 'Docker is not connected' in cli('containers') or 'containers' in cli('--json','containers')
            # Scope, credentials, and usage errors map to stable exit codes.
            cli('hosts','disable','Photos',secret=read,expected=3)
            assert len(json.loads(cli('--json','hosts','list',secret=read)))==1
            cli('status',secret='eg_'+'0'*16+'_'+'0'*64,expected=3)
            cli('status',secret='',expected=3)
            cli('frobnicate',expected=2)
            assert subprocess.run([CLI,'status'],env={'PATH':os.environ['PATH']},capture_output=True,timeout=10).returncode==2,'missing EMBERGATE_URL is a usage error'
            # Backup export writes a private file and refuses to overwrite.
            backup=data/'out.embergate'
            cli('backup','export','--output',str(backup),expected=2)
            assert 'Saved encrypted backup' in cli('backup','export','--output',str(backup),extra={'EMBERGATE_BACKUP_PASSPHRASE':'cli-backup-passphrase'})
            assert backup.stat().st_size>0 and backup.stat().st_mode&0o777==0o600
            cli('backup','export','-o',str(backup),expected=1,extra={'EMBERGATE_BACKUP_PASSPHRASE':'cli-backup-passphrase'})
            cli('backup','export','-o',str(data/'reader.embergate'),secret=read,expected=3,extra={'EMBERGATE_BACKUP_PASSPHRASE':'cli-backup-passphrase'})
            print('CLI checks passed: status, hosts list/show/apply/enable/disable/delete, cache purge, history, containers, scopes, exit codes, and backup export.')
        finally:
            if process.poll() is None:process.send_signal(signal.SIGINT);process.wait(timeout=15)
if __name__=='__main__':run()

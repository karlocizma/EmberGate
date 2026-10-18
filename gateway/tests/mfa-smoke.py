"""Real-server MFA enrollment, replay protection, roles, policy, and backup integration."""
import base64,hashlib,hmac,importlib.util,json,os,signal,sqlite3,struct,subprocess,tempfile,time
from pathlib import Path
spec=importlib.util.spec_from_file_location('smoke',Path(__file__).with_name('proxy-smoke.py'))
smoke=importlib.util.module_from_spec(spec);spec.loader.exec_module(smoke)
def totp(secret):
    digest=hmac.new(base64.b32decode(secret),struct.pack('>Q',int(time.time())//30),hashlib.sha1).digest();offset=digest[-1]&15
    return f'{(struct.unpack(">I",digest[offset:offset+4])[0]&0x7fffffff)%1000000:06}'
def run():
    admin,proxy=smoke.free_port(),smoke.free_port()
    with tempfile.TemporaryDirectory(prefix='embergate-mfa-') as directory:
        env={k:v for k,v in os.environ.items() if not k.startswith('GATEWAY_')}
        env.update(GATEWAY_ADMIN_PASSWORD='mfa-admin-password',GATEWAY_DATA_DIR=directory,GATEWAY_ADMIN_ADDR=f'127.0.0.1:{admin}',GATEWAY_PROXY_ADDR=f'127.0.0.1:{proxy}')
        binary=str(Path('target/debug/embergate').resolve());process=None
        def launch():
            nonlocal process
            process=subprocess.Popen([binary],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);smoke.await_ready(process,admin)
        def stop():
            if process and process.poll() is None:process.send_signal(signal.SIGINT);process.wait(timeout=15)
        def call(path,method='GET',body=None,auth=None,expected=200):
            status,headers,data=smoke.request(admin,method,'/api/'+path,body,auth or {});assert status==expected,(path,status,data[:500]);return json.loads(data),headers
        def api(path,method='GET',body=None,auth=None,expected=200):return call(path,method,body,auth,expected)[0]
        def login(name='admin',password='mfa-admin-password',code='',expected=200):
            result,headers=call('login','POST',{'username':name,'password':password,'code':code},{'X-Gateway-Request':'1'},expected)
            if expected!=200:assert 'set-cookie' not in headers;return result
            return {'Cookie':headers['set-cookie'].split(';')[0],'X-Gateway-Request':'1'}
        def enroll(auth,password):
            secret=api('mfa/setup','POST',{'current_password':password},auth)['secret']
            result=api('mfa/confirm','POST',{'code':totp(secret)},auth);return secret,result['recovery_codes']
        try:
            launch();owner=login();old_session=login()
            assert not api('mfa',auth=owner)['enabled']
            api('mfa/setup','POST',{'current_password':'wrong'},owner,403)
            secret=api('mfa/setup','POST',{'current_password':'mfa-admin-password'},owner)['secret'];code=totp(secret)
            api('mfa/confirm','POST',{'code':code},old_session,409)
            api('mfa/confirm','POST',{'code':code},{'Cookie':owner['Cookie']},403)
            codes=api('mfa/confirm','POST',{'code':code},owner)['recovery_codes'];assert len(codes)==10
            api('config',auth=old_session,expected=401)
            assert api('mfa',auth=owner)['recovery_codes_remaining']==10
            assert not login(password='wrong-password',expected=401).get('mfa_required')
            assert login(expected=401)['mfa_required'];assert login(code=code,expected=401)['mfa_required']
            authenticated=login(code=codes[0]);assert api('mfa',auth=authenticated)['recovery_codes_remaining']==9
            login(code=codes[0],expected=401)
            api('mfa/policy','PUT',{'require_administrators':True,'current_password':'mfa-admin-password','code':codes[1]},authenticated)
            api('mfa','DELETE',{'current_password':'mfa-admin-password','code':codes[2]},authenticated,409)
            second=api('users','POST',{'username':'second-admin','password':'second-admin-password','role':'administrator'},authenticated,201)['user']
            second_session=login('second-admin','second-admin-password')
            assert api('session',auth=second_session)['mfa_enrollment_required']
            api('config',auth=second_session,expected=403);api('backups/status',auth=second_session,expected=403)
            second_secret,second_codes=enroll(second_session,'second-admin-password');api('config',auth=second_session)
            reader=api('users','POST',{'username':'reader','password':'reader-password-123','role':'read_only'},authenticated,201)['user']
            reader_session=login('reader','reader-password-123');api('config',auth=reader_session)
            reader_secret,reader_codes=enroll(reader_session,'reader-password-123')
            api('mfa/policy','PUT',{'require_administrators':False,'current_password':'reader-password-123','code':reader_codes[0]},reader_session,403)
            # Backup validation includes MFA without exposing secrets/recovery hashes in the review.
            passphrase='mfa-backup-passphrase';status,_,archive=smoke.request(admin,'POST','/api/backups/export',{'passphrase':passphrase},authenticated);assert status==200,(status,archive[:200])
            for value in [secret,*codes,second_secret,reader_secret]:assert value.encode() not in archive
            review=api('backups/preview','POST',{'archive':base64.b64encode(archive).decode(),'passphrase':passphrase},authenticated)
            assert 'two_factor_authentication' in review['summary']['credential_types'];assert 'mfa:' not in json.dumps(review)
            # Restart proves private enrollment and replay/recovery state persists, including env-admin MFA.
            stop();launch();assert login(expected=401)['mfa_required'];login(code=codes[0],expected=401)
            authenticated=login(code=codes[2]);assert api('mfa',auth=authenticated)['require_administrators']
            api('mfa/policy','PUT',{'require_administrators':False,'current_password':'mfa-admin-password','code':codes[3]},authenticated)
            replacement=api('mfa/recovery','POST',{'current_password':'mfa-admin-password','code':codes[4]},authenticated)['recovery_codes']
            login(code=codes[5],expected=401);fresh=login(code=replacement[0]);api('config',auth=fresh)
            api('mfa','DELETE',{'current_password':'mfa-admin-password','code':replacement[1]},fresh)
            api('config',auth=authenticated,expected=401);assert not api('mfa',auth=fresh)['enabled'];login()
            # Deleting an account removes its saved authenticator and invalidates its sessions.
            api('users/'+second['id'],'DELETE',auth=fresh);api('config',auth=second_session,expected=401)
            with sqlite3.connect(Path(directory)/'management.sqlite3') as db:
                assert db.execute('SELECT COUNT(*) FROM secrets WHERE key=?',('mfa:'+second['id'],)).fetchone()[0]==0
                stored=db.execute('SELECT value FROM secrets WHERE key=?',('mfa:'+reader['id'],)).fetchone()[0]
                assert all(c not in stored for c in reader_codes)
            audit=json.dumps(api('audit',auth=fresh))
            for value in [secret,*codes,second_secret,reader_secret,'mfa-admin-password']:assert value not in audit
            review=api('backups/preview','POST',{'archive':base64.b64encode(archive).decode(),'passphrase':passphrase},fresh)
            api('backups/restore','POST',{'id':review['id'],'confirm':'RESTORE'},fresh)
            stop();launch();api('config',auth=fresh,expected=401)
            assert login(expected=401)['mfa_required'];login(code=codes[0],expected=401)
            restored=login(code=codes[5]);assert api('mfa',auth=restored)['require_administrators']
            second_restored=login('second-admin','second-admin-password',second_codes[0]);api('config',auth=second_restored)
            reader_restored=login('reader','reader-password-123',reader_codes[0]);assert api('mfa',auth=reader_restored)['enabled']
            print('MFA integration passed: enrollment ownership, CSRF, password proof, TOTP/recovery replay rejection, session revocation, administrator enforcement, read-only enrollment, persistence, env-admin protection, recovery replacement, disable, deletion, encrypted backup review/restore, and audit redaction.')
        finally:stop()
if __name__=='__main__':run()

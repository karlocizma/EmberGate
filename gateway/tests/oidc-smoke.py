"""Single sign-on against a local OpenID provider: discovery, PKCE, ID token checks, dashboard sign-in, host policy, headers, and backups."""
import base64, hashlib, http.client, http.server, importlib.util, json, os, signal, subprocess, tempfile, threading, time, urllib.parse, uuid
from pathlib import Path
spec=importlib.util.spec_from_file_location('smoke',Path(__file__).with_name('proxy-smoke.py'));smoke=importlib.util.module_from_spec(spec);spec.loader.exec_module(smoke)
def b64(data):return base64.urlsafe_b64encode(data).rstrip(b'=').decode()
class Provider:
    """Signs in whichever user `next_user` names, recording what EmberGate sent."""
    def __init__(self,directory):
        self.key=directory/'provider.key';subprocess.run(['openssl','genrsa','-out',str(self.key),'2048'],check=True,capture_output=True)
        modulus=subprocess.run(['openssl','rsa','-in',str(self.key),'-noout','-modulus'],check=True,capture_output=True,text=True).stdout.strip().split('=')[1]
        self.jwk={'kty':'RSA','kid':'k1','use':'sig','alg':'RS256','n':b64(bytes.fromhex(modulus)),'e':'AQAB'}
        self.codes={};self.next_user={};self.tamper=None;self.token_requests=[];self.authorize_requests=[]
        provider=self
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*a):pass
            def reply(self,status,body,headers=None):
                data=json.dumps(body).encode() if not isinstance(body,bytes) else body
                self.send_response(status)
                for k,v in (headers or {'Content-Type':'application/json'}).items():self.send_header(k,v)
                self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
            def do_GET(self):
                url=urllib.parse.urlparse(self.path);query=dict(urllib.parse.parse_qsl(url.query))
                if url.path=='/.well-known/openid-configuration':
                    return self.reply(200,{'issuer':provider.issuer,'authorization_endpoint':provider.issuer+'/authorize','token_endpoint':provider.issuer+'/token','jwks_uri':provider.issuer+'/jwks','end_session_endpoint':provider.issuer+'/logout'})
                if url.path=='/jwks':return self.reply(200,{'keys':[provider.jwk]})
                if url.path=='/authorize':
                    provider.authorize_requests.append(query);code=uuid.uuid4().hex;provider.codes[code]=query
                    return self.reply(302,b'',{'Location':query['redirect_uri']+'?'+urllib.parse.urlencode({'code':code,'state':query['state']})})
                self.reply(404,{})
            def do_POST(self):
                form=dict(urllib.parse.parse_qsl(self.rfile.read(int(self.headers['Content-Length'])).decode()))
                provider.token_requests.append({'form':form,'auth':self.headers.get('Authorization')})
                request=provider.codes.pop(form.get('code'),None)
                expected='Basic '+base64.b64encode(b'embergate:provider-secret').decode()
                challenge=b64(hashlib.sha256(form.get('code_verifier','').encode()).digest())
                if not request or self.headers.get('Authorization')!=expected or request['code_challenge']!=challenge or request['code_challenge_method']!='S256' or form.get('redirect_uri')!=request['redirect_uri']:
                    return self.reply(400,{'error':'invalid_grant'})
                now=int(time.time());claims={'iss':provider.issuer,'aud':'embergate','sub':'sub-'+provider.next_user['email'],'nonce':request['nonce'],'exp':now+300,'iat':now,**provider.next_user}
                if provider.tamper:provider.tamper(claims)
                self.reply(200,{'id_token':provider.sign(claims),'access_token':'unused','token_type':'Bearer'})
        self.server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);threading.Thread(target=self.server.serve_forever,daemon=True).start()
        self.issuer=f'http://127.0.0.1:{self.server.server_address[1]}'
    def sign(self,claims):
        signing=b64(json.dumps({'alg':'RS256','kid':'k1','typ':'JWT'}).encode())+'.'+b64(json.dumps(claims).encode())
        signature=subprocess.run(['openssl','dgst','-sha256','-sign',str(self.key)],input=signing.encode(),check=True,capture_output=True).stdout
        return signing+'.'+b64(signature)
class App(http.server.BaseHTTPRequestHandler):
    seen=[]
    def do_GET(self):
        App.seen.append(dict(self.headers));body=b'app';self.send_response(200);self.send_header('Content-Length','3');self.end_headers();self.wfile.write(body)
    def log_message(self,*a):pass
def run():
    with tempfile.TemporaryDirectory(prefix='embergate-oidc-') as directory:
        data=Path(directory);provider=Provider(data)
        app=http.server.ThreadingHTTPServer(('127.0.0.1',0),App);threading.Thread(target=app.serve_forever,daemon=True).start()
        admin,proxy=smoke.free_port(),smoke.free_port();owner={}
        env={k:v for k,v in os.environ.items() if not k.startswith('GATEWAY_')};env.update(GATEWAY_ADMIN_PASSWORD='oidc-admin-password',GATEWAY_DATA_DIR=directory,GATEWAY_ADMIN_ADDR=f'127.0.0.1:{admin}',GATEWAY_PROXY_ADDR=f'127.0.0.1:{proxy}')
        def call(path,method='GET',body=None,auth=None,expected=200):
            status,_,result=smoke.request(admin,method,'/api/'+path,body,owner if auth is None else auth);assert status==expected,(path,status,result[:400])
            return json.loads(result) if result else None
        def raw(port,path,headers=None,method='GET'):
            conn=http.client.HTTPConnection('127.0.0.1',port,timeout=10);conn.request(method,path,None,headers or {});r=conn.getresponse()
            result=r.status,{k.lower():v for k,v in r.getheaders()},r.getheaders(),r.read().decode(errors='replace');conn.close();return result
        def cookies(all_headers):return [v.split(';')[0] for k,v in all_headers if k.lower()=='set-cookie']
        def follow_provider(location):
            """Lets the provider 'sign in' and returns its redirect back to EmberGate."""
            url=urllib.parse.urlparse(location);conn=http.client.HTTPConnection(url.hostname,url.port,timeout=10);conn.request('GET',url.path+'?'+url.query);r=conn.getresponse();r.read()
            back=urllib.parse.urlparse(r.getheader('Location'));conn.close();return back.path+'?'+back.query
        process=subprocess.Popen([str(Path('target/debug/embergate').resolve())],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            smoke.await_ready(process,admin)
            status,h,_=smoke.request(admin,'POST','/api/login',{'username':'admin','password':'oidc-admin-password'},{'X-Gateway-Request':'1'});owner.update({'Cookie':h['set-cookie'].split(';')[0],'X-Gateway-Request':'1'})
            assert call('oidc/status',auth={})=={'dashboard':False,'name':None}
            settings={'name':'Local ID','issuer':provider.issuer,'client_id':'embergate','scopes':['openid','email','profile'],'groups_claim':'groups','dashboard_enabled':True,'dashboard_origin':f'http://localhost:{admin}','trust_provider_mfa':False}
            call('integrations/oidc','PUT',settings,expected=422)  # no client secret yet
            call('integrations/oidc','PUT',{**settings,'issuer':'http://127.0.0.1:9/none','client_secret':'provider-secret'},expected=422)
            saved=call('integrations/oidc','PUT',{**settings,'client_secret':'provider-secret'})
            assert saved['configured'] and saved['secret_configured'] and 'provider-secret' not in json.dumps(saved)
            assert saved['dashboard_redirect_uri']==f'http://localhost:{admin}/api/oidc/callback'
            assert call('oidc/status',auth={})=={'dashboard':True,'name':'Local ID'}
            # Dashboard sign-in matches an existing, enabled account by verified email.
            call('users','POST',{'username':'ada@example.com','password':'ada-password-123','role':'read_only'},expected=201)
            def dashboard(user,next_path='/'):
                provider.next_user=user
                status,h,all_h,_=raw(admin,'/api/oidc/login?next='+urllib.parse.quote(next_path));assert status in (302,303,307),status
                state_cookie=cookies(all_h)[0];back=follow_provider(h['location'])
                return raw(admin,back,{'Cookie':state_cookie})
            status,h,all_h,_=dashboard({'email':'ada@example.com','email_verified':True})
            assert status==303 and h['location']=='/',(status,h)
            session=[c for c in cookies(all_h) if c.startswith('gateway_session=')][0]
            assert call('session',auth={'Cookie':session})['user']['username']=='ada@example.com'
            request=provider.authorize_requests[-1]
            assert request['code_challenge_method']=='S256' and request['scope']=='openid email profile' and len(request['state'])>=43 and len(request['nonce'])>=43
            assert dashboard({'email':'ada@example.com','email_verified':False})[1]['location']=='/?sso_error=account','unverified emails never match'
            assert dashboard({'email':'nobody@example.com','email_verified':True})[1]['location']=='/?sso_error=account'
            # Members of the automatic-account group get an account with the chosen role.
            call('integrations/oidc','PUT',{**settings,'auto_create_group':'ops','dashboard_enabled':False},expected=422)
            call('integrations/oidc','PUT',{**settings,'auto_create_group':'ops','auto_create_role':'administrator'})
            assert dashboard({'email':'eve@example.com','email_verified':True,'groups':['staff']})[1]['location']=='/?sso_error=account','non-members are not created'
            assert dashboard({'email':'eve@example.com','email_verified':False,'groups':['ops']})[1]['location']=='/?sso_error=account','unverified emails are not created'
            status,h,all_h,_=dashboard({'email':'Eve@Example.com','email_verified':True,'groups':['ops']})
            assert status==303 and h['location']=='/',(status,h)
            eve=[u for u in call('users')['users'] if u['username']=='eve@example.com']
            assert len(eve)==1 and eve[0]['role']=='administrator' and eve[0]['enabled'],eve
            assert smoke.request(admin,'POST','/api/login',{'username':'eve@example.com','password':''},{'X-Gateway-Request':'1'})[0]!=200
            call(f"users/{eve[0]['id']}",'PUT',{'username':'eve@example.com','role':'administrator','enabled':False,'version':eve[0]['version']})
            assert dashboard({'email':'eve@example.com','email_verified':True,'groups':['ops']})[1]['location']=='/?sso_error=account','disabled accounts stay disabled'
            call('integrations/oidc','PUT',settings)
            provider.tamper=lambda c:c.update(aud='someone-else')
            assert dashboard({'email':'ada@example.com','email_verified':True})[1]['location']=='/?sso_error=rejected'
            provider.tamper=None
            # The state is bound to the browser and usable once.
            provider.next_user={'email':'ada@example.com','email_verified':True}
            status,h,all_h,_=raw(admin,'/api/oidc/login');back=follow_provider(h['location'])
            assert raw(admin,back)[1]['location']=='/?sso_error=expired','no state cookie'
            assert raw(admin,back,{'Cookie':cookies(all_h)[0]})[1]['location']=='/','the right browser completes it'
            assert raw(admin,back,{'Cookie':cookies(all_h)[0]})[1]['location']=='/?sso_error=rejected','a completed sign-in cannot be replayed'
            # Host policy: unauthenticated visitors are sent to the provider; rules and headers apply.
            route={'id':str(uuid.uuid4()),'name':'App','host':'app.test','path_prefix':'/tools','upstream':f'http://127.0.0.1:{app.server_address[1]}','enabled':True,'preserve_host':False,'oidc':{'allowed_domains':['example.com'],'allowed_groups':['ops'],'session_hours':2},'cache':{'max_ttl_seconds':60,'max_object_bytes':1024}}
            config=call('config')
            call('config','PUT',{**config,'routes':[{**route,'forward_auth':{'url':'http://127.0.0.1:9/auth'}}]},expected=422)
            public={'id':str(uuid.uuid4()),'name':'Public','host':'app.test','path_prefix':'/','upstream':route['upstream'],'enabled':True,'preserve_host':False}
            call('config','PUT',{**config,'routes':[route,public]})
            host={'Host':'app.test','Accept':'text/html'}
            assert raw(proxy,'/tools/page',{'Host':'app.test','Accept':'application/json'})[0]==401,'APIs get 401, not a redirect'
            def host_sign_in(user,path='/tools/page?x=1'):
                provider.next_user=user
                status,h,all_h,_=raw(proxy,path,host);assert status==303 and h['location'].startswith(provider.issuer+'/authorize'),(status,h)
                request=dict(urllib.parse.parse_qsl(urllib.parse.urlparse(h['location']).query))
                assert request['redirect_uri']=='http://app.test/tools/.well-known/embergate/oidc/callback',request
                return raw(proxy,follow_provider(h['location']),{'Host':'app.test','Cookie':cookies(all_h)[0]})
            status,h,all_h,body=host_sign_in({'email':'eve@elsewhere.test','email_verified':True,'groups':['staff']})
            assert status==403 and 'not allowed' in body
            status,h,all_h,_=host_sign_in({'email':'grace@example.com','email_verified':True,'groups':['staff'],'preferred_username':'grace'})
            assert status==303 and h['location']=='/tools/page?x=1',(status,h)
            sealed=[c for c in cookies(all_h) if c.startswith('embergate_oidc_')][0]
            assert 'HttpOnly' in [v for k,v in all_h if k.lower()=='set-cookie' and v.startswith('embergate_oidc_') and 'Max-Age=7200' in v][0]
            App.seen.clear()
            status,_,_,body=raw(proxy,'/tools/page',{**host,'Cookie':sealed+'; app_cookie=1','X-Auth-Request-Email':'forged@evil.test','X-Auth-Request-Groups':'admins'})
            assert status==200 and body=='app'
            sent={k.lower():v for k,v in App.seen[-1].items()}
            assert sent['x-auth-request-email']=='grace@example.com' and sent['x-auth-request-groups']=='staff' and sent['x-auth-request-preferred-username']=='grace' and sent['x-auth-request-user']=='sub-grace@example.com',sent
            assert sent['cookie']=='app_cookie=1','sign-in cookies never reach the application'
            assert raw(proxy,'/open',{**host,'Cookie':sealed+'; embergate_captcha=x; app_cookie=1'})[0]==200
            assert {k.lower():v for k,v in App.seen[-1].items()}['cookie']=='app_cookie=1','routes without sign-in on the same host never see the cookies either'
            assert raw(proxy,'/tools/page',{**host,'Cookie':sealed})[1].get('x-embergate-cache')!='HIT','signed-in pages are not cached'
            assert raw(proxy,'/tools/page',{'Host':'other.test','Accept':'text/html','Cookie':sealed})[0]!=200,'cookies belong to one host'
            group_only=host_sign_in({'email':'ops@partner.test','email_verified':True,'groups':['ops']})
            assert group_only[0]==303,'any one matching rule admits'
            # Tightening the policy applies to existing sign-ins.
            call('config','PUT',{**call('config'),'routes':[{**route,'oidc':{'allowed_groups':['ops']}}]})
            assert raw(proxy,'/tools/page',{**host,'Cookie':sealed})[0]==303,'rules are re-checked on every request'
            status,h,all_h,_=raw(proxy,'/tools/.well-known/embergate/oidc/logout',{**host,'Cookie':sealed})
            assert status==303 and h['location']==provider.issuer+'/logout' and any(c.endswith('=') for c in cookies(all_h))
            # Providers cannot be removed while hosts use them; backups carry the settings.
            call('integrations/oidc','DELETE',expected=409)
            status,_,blob=smoke.request(admin,'POST','/api/backups/export',{'passphrase':'oidc-backup-passphrase'},owner);assert status==200
            review=call('backups/preview','POST',{'archive':base64.b64encode(blob).decode(),'passphrase':'oidc-backup-passphrase'})
            assert {'oidc_provider','oidc_client_secret','oidc_session_key'}<=set(review['summary']['credential_types'])
            # Read-only accounts cannot change the provider; host sign-ins survive a restart.
            call('integrations/oidc','PUT',{**settings,'client_secret':'x'},{'Cookie':session,'X-Gateway-Request':'1'},403)
            process.send_signal(signal.SIGINT);process.wait(timeout=15)
            process=subprocess.Popen([str(Path('target/debug/embergate').resolve())],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);smoke.await_ready(process,admin)
            ops=[c for c in cookies(group_only[2]) if c.startswith('embergate_oidc_')][0]
            assert raw(proxy,'/tools/page',{**host,'Cookie':ops})[0]==200,'host sign-ins survive restarts'
            print('OIDC checks passed: discovery, PKCE, state binding, ID token checks, dashboard accounts, host rules, headers, cookies, logout, restart, and backups.')
        finally:
            if process.poll() is None:process.send_signal(signal.SIGINT);process.wait(timeout=15)
            provider.server.shutdown();app.shutdown()
if __name__=='__main__':run()

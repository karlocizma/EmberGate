"""Isolated real-server account, audit, and alert integration checks. No external delivery."""
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import importlib.util,json,os,signal,sqlite3,subprocess,tempfile,threading,time,uuid
from pathlib import Path
spec=importlib.util.spec_from_file_location('smoke',Path(__file__).with_name('proxy-smoke.py'))
smoke=importlib.util.module_from_spec(spec);spec.loader.exec_module(smoke)
notifications=[]
class Origin(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(self.server.health);self.send_header('Content-Length','2');self.end_headers();self.wfile.write(b'ok')
    def do_POST(self):
        notifications.append(json.loads(self.rfile.read(int(self.headers['Content-Length']))));self.send_response(self.server.webhook_status);self.end_headers()
    def log_message(self,*args):pass

def run():
    origin=ThreadingHTTPServer(('127.0.0.1',0),Origin);origin.health=200;origin.webhook_status=204
    threading.Thread(target=origin.serve_forever,daemon=True).start()
    admin,proxy=smoke.free_port(),smoke.free_port()
    with tempfile.TemporaryDirectory(prefix='gateway-accounts-') as directory:
        env={**os.environ,'GATEWAY_ADMIN_PASSWORD':'account-admin-password','GATEWAY_DATA_DIR':directory,'GATEWAY_ADMIN_ADDR':f'127.0.0.1:{admin}','GATEWAY_PROXY_ADDR':f'127.0.0.1:{proxy}','GATEWAY_ALERT_WEBHOOK_URL':f'http://127.0.0.1:{origin.server_port}/hook?secret=never-returned'}
        for key in ['GATEWAY_HTTPS_ADDR','GATEWAY_CLOUDFLARE_API_TOKEN','GATEWAY_CLOUDFLARE_API_TOKEN_FILE']:env.pop(key,None)
        binary=str(Path('target/debug/embergate').resolve())
        def launch():
            process=subprocess.Popen([binary],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);smoke.await_ready(process,admin);return process
        process=launch()
        def call(path,method='GET',body=None,headers=None,expected=200):
            status,_,data=smoke.request(admin,method,'/api/'+path,body,headers or {});assert status==expected,(path,status,data);return json.loads(data) if data else None
        def login(name='admin',password='account-admin-password'):
            status,response,data=smoke.request(admin,'POST','/api/login',{'username':name,'password':password},{'X-Gateway-Request':'1'});assert status==200,(status,data)
            return {'Cookie':response['set-cookie'].split(';')[0],'X-Gateway-Request':'1'}
        def wait(predicate,seconds=35):
            limit=time.monotonic()+seconds
            while time.monotonic()<limit:
                result=predicate()
                if result:return result
                time.sleep(.25)
            raise AssertionError('Timed out waiting for alert transition')
        try:
            owner=login();reader=call('users','POST',{'username':'reader','password':'reader-secret-password','role':'read_only'},owner,201)['user'];readonly=login('reader','reader-secret-password')
            assert call('session',headers=readonly)['user']['role']=='read_only'
            for endpoint in ['config','stats','logs','cache','certificates','acme','upstreams','alerts','sessions']:call(endpoint,headers=readonly)
            for endpoint,method in [('users','GET'),('audit','GET'),('config','PUT'),('cache/purge','POST'),('certificates','POST'),('acme/orders','POST'),('alerts/settings','PUT'),('users','POST'),('users/bootstrap','DELETE')]:call(endpoint,method,{},readonly,403)
            own_sessions=call('sessions',headers=readonly)['sessions'];assert all(s['user']['id']==reader['id'] for s in own_sessions)
            owner_sessions=call('sessions',headers=owner)['sessions'];other=next(s for s in owner_sessions if s['user']['id']=='bootstrap');call('sessions/'+other['id'],'DELETE',headers=readonly,expected=403)
            otherreader=login('reader','reader-secret-password');session=next(s for s in call('sessions',headers=otherreader)['sessions'] if s['current']);call('sessions/'+session['id'],'DELETE',headers=readonly);call('config',headers=otherreader,expected=401)
            call('users/bootstrap','PUT',{'username':'other','role':'read_only','enabled':False,'version':0},owner,422)
            call('users/'+reader['id'],'PUT',{**reader,'enabled':False},owner);call('config',headers=readonly,expected=401)
            updated=next(u for u in call('users',headers=owner)['users'] if u['id']==reader['id']);call('users/'+reader['id'],'PUT',{**updated,'enabled':True},owner)
            readonly=login('reader','reader-secret-password');call('password','POST',{'current_password':'reader-secret-password','new_password':'new-reader-secret-password'},readonly);call('config',headers=readonly,expected=401)
            call('login','POST',{'username':'reader','password':'reader-secret-password'},{'X-Gateway-Request':'1'},401);readonly=login('reader','new-reader-secret-password')
            user_data=json.dumps(call('users',headers=owner));session_data=json.dumps(call('sessions',headers=owner));assert 'password' not in user_data and '$argon2' not in user_data and readonly['Cookie'].split('=')[1] not in session_data
            settings=call('alerts',headers=owner)['settings'];settings.update(error_threshold_percent=1,minimum_requests=1,webhook_enabled=False);call('alerts/settings','PUT',settings,owner)
            route={'id':str(uuid.uuid4()),'name':'Local service','host':'*','path_prefix':'/','upstream':f'http://127.0.0.1:{origin.server_port}','enabled':True,'preserve_host':False,'health_check':{'path':'/health','interval_seconds':5,'timeout_seconds':1,'failure_threshold':1,'recovery_threshold':1}}
            call('config','PUT',{'version':0,'routes':[route]},owner)
            wait(lambda:call('upstreams',headers=owner)['routes'][route['id']][0]['status']=='healthy')
            origin.health=503
            wait(lambda:call('upstreams',headers=owner)['routes'][route['id']][0]['status']=='unhealthy')
            smoke.request(proxy,'GET','/',headers={'Host':'local.test'})
            active=wait(lambda:[a for a in call('alerts',headers=owner)['alerts'] if a['source']=='backend' and not a['resolved_at']]);alert=active[0]
            wait(lambda:any(a['source']=='traffic' and not a['resolved_at'] for a in call('alerts',headers=owner)['alerts']))
            assert notifications==[],notifications
            call('alerts/'+alert['id']+'/ack','POST',headers=readonly,expected=403);call('alerts/'+alert['id']+'/ack','POST',headers=owner)
            settings=call('alerts',headers=owner)['settings'];settings.update(webhook_enabled=True);call('alerts/settings','PUT',settings,owner)
            call('alerts/test','POST',headers=owner,expected=202);wait(lambda:any(n['event']=='test' for n in notifications))
            origin.health=200
            wait(lambda:any(a['id']==alert['id'] and a['resolved_at'] for a in call('alerts',headers=owner)['alerts']))
            wait(lambda:any(n['event']=='resolved' for n in notifications))
            assert 'never-returned' not in json.dumps(call('alerts',headers=owner))
            # Fresh failure creates exactly one open notification, preserved through restart.
            origin.health=503
            new=wait(lambda:[a for a in call('alerts',headers=owner)['alerts'] if a['source']=='backend' and not a['resolved_at'] and a['id']!=alert['id']])[0]
            wait(lambda:any(n['event']=='opened' and n['alert']['id']==new['id'] for n in notifications))
            process.send_signal(signal.SIGINT);process.wait(timeout=15);process=launch();call('config',headers=owner,expected=401)
            owner=login();readonly=login('reader','new-reader-secret-password');call('config',headers=readonly)
            wait(lambda:call('upstreams',headers=owner)['routes'][route['id']][0]['status']=='unhealthy');time.sleep(11)
            assert len([n for n in notifications if n['event']=='opened' and n['alert']['id']==new['id']])==1,notifications
            audit=call('audit',headers=owner);assert any(e['path']=='/api/config' and e['phase']=='success' for e in audit['events'])
            text=json.dumps(audit)
            for secret in ['reader-secret-password','new-reader-secret-password','account-admin-password','$argon2','never-returned',readonly['Cookie'].split('=')[1]]:assert secret not in text,secret
            # Accelerate retry deadlines in this isolated fixture to test all five real failed sends.
            origin.webhook_status=503;call('alerts/test','POST',headers=owner,expected=202)
            def retry_state():
                with sqlite3.connect(Path(directory)/'management.sqlite3') as db:
                    row=db.execute("SELECT state,attempts FROM outbox WHERE event='test' ORDER BY id DESC LIMIT 1").fetchone()
                    if row and row[0]=='pending' and row[1]>0:db.execute("UPDATE outbox SET next_attempt=0 WHERE event='test' AND state='pending'")
                    return row
            wait(lambda:(retry_state() or ('',0))[0]=='failed',seconds=20)
            assert retry_state()[1]==5
            assert call('alerts',headers=owner)['delivery']['failed']>=1
            origin.webhook_status=204
            settings=call('alerts',headers=owner)['settings'];settings.update(webhook_enabled=False,error_rate=False);call('alerts/settings','PUT',settings,owner);call('alerts/test','POST',headers=owner,expected=422)
            call('users/'+reader['id'],'DELETE',headers=owner);call('config',headers=readonly,expected=401)
            print('Accounts/alerts passed: role enforcement, session ownership, password changes, revocation, persistence, audit redaction, backend/error alerts, acknowledgement, recovery, webhook opt-in, local delivery, restart deduplication.')
        finally:
            if process.poll() is None:process.send_signal(signal.SIGINT);process.wait(timeout=15)
            origin.shutdown();origin.server_close()
if __name__=='__main__':run()

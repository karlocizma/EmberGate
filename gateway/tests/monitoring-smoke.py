"""Prometheus scrapes and Discord delivery through the actual binary; local fixtures only."""
import importlib.util,json,os,re,signal,sqlite3,subprocess,tempfile,threading,time,uuid
from pathlib import Path
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
spec=importlib.util.spec_from_file_location('smoke',Path(__file__).with_name('proxy-smoke.py'))
smoke=importlib.util.module_from_spec(spec);spec.loader.exec_module(smoke)
class Origin(BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def do_GET(self):
        body=b'public content';self.send_response(200);self.send_header('Cache-Control','public, max-age=60');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    def log_message(self,*args):pass
class Receiver(BaseHTTPRequestHandler):
    def do_POST(self):
        value=json.loads(self.rfile.read(int(self.headers.get('Content-Length','0'))))
        with self.server.lock:self.server.messages.append((self.path,value))
        self.send_response(self.server.response)
        if self.server.response==429:self.send_header('Retry-After','120.5')
        body=b'{}';self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    def log_message(self,*args):pass

def run():
    origin=ThreadingHTTPServer(('127.0.0.1',0),Origin);receiver=ThreadingHTTPServer(('127.0.0.1',0),Receiver);receiver.messages=[];receiver.lock=threading.Lock();receiver.response=200
    for server in [origin,receiver]:threading.Thread(target=server.serve_forever,daemon=True).start()
    proxy,admin=smoke.free_port(),smoke.free_port()
    while admin==proxy:admin=smoke.free_port()
    with tempfile.TemporaryDirectory(prefix='embergate-monitoring-') as data_dir:
        env={**os.environ,'GATEWAY_DATA_DIR':data_dir,'GATEWAY_ADMIN_PASSWORD':'monitoring-password-123','GATEWAY_PROXY_ADDR':f'127.0.0.1:{proxy}','GATEWAY_ADMIN_ADDR':f'127.0.0.1:{admin}'}
        for key in ['GATEWAY_ALERT_WEBHOOK_URL','GATEWAY_HTTPS_ADDR','GATEWAY_CLOUDFLARE_API_TOKEN','GATEWAY_CLOUDFLARE_API_TOKEN_FILE']:env.pop(key,None)
        process=None;headers={};version=0;route={'id':str(uuid.uuid4()),'name':'Private @everyone host','host':'metrics.test','path_prefix':'/','upstream':f'http://127.0.0.1:{origin.server_port}','enabled':True,'preserve_host':False,'cache':{'max_ttl_seconds':60,'max_object_bytes':4096}}
        def start():
            nonlocal process,headers
            process=subprocess.Popen([str(Path('target/debug/embergate').resolve())],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);smoke.await_ready(process,admin)
            status,h,_=smoke.request(admin,'POST','/api/login',{'password':env['GATEWAY_ADMIN_PASSWORD']},{'X-Gateway-Request':'1'});assert status==200
            headers={'Cookie':h['set-cookie'].split(';')[0],'X-Gateway-Request':'1'}
        def stop():
            if process and process.poll() is None:process.send_signal(signal.SIGINT);process.wait(timeout=15)
        def api(path,method='GET',body=None,expected=200,auth=None):
            status,_,value=smoke.request(admin,method,'/api/'+path,body,headers if auth is None else auth);assert status==expected,(path,status,value)
            return json.loads(value) if value else None
        def save():
            nonlocal version
            result=api('config','PUT',{'version':version,'routes':[route]});version=result['version']
        def traffic(path='/',extra=None):return smoke.request(proxy,'GET',path,headers={'Host':'metrics.test',**(extra or {})})
        def wait(check,timeout=25):
            deadline=time.monotonic()+timeout
            while time.monotonic()<deadline:
                result=check()
                if result:return result
                time.sleep(.15)
            raise AssertionError('Timed out')
        def scrape(token):
            status,h,body=smoke.request(admin,'GET','/metrics',headers={'Authorization':'Bearer '+token});assert status==200,(status,body)
            assert h['content-type']=='text/plain; version=0.0.4; charset=utf-8'
            text=body.decode();assert text.endswith('\n')
            for line in text.splitlines():
                if line.startswith('#'):continue
                assert re.fullmatch(r'[a-zA-Z_:][a-zA-Z0-9_:]*(\{[^\n]*\})? [0-9.eE+\-]+',line),line
                float(line.rsplit(' ',1)[1])
            return text
        def value(text,name):return float(next(line.rsplit(' ',1)[1] for line in text.splitlines() if line.startswith(name+' ')))
        def messages():
            with receiver.lock:return list(receiver.messages)
        def db(query,params=()):
            with sqlite3.connect(Path(data_dir,'management.sqlite3')) as conn:return conn.execute(query,params).fetchall()
        try:
            start();assert smoke.request(admin,'GET','/metrics')[0]==401
            assert not api('integrations/prometheus')['configured'];assert smoke.request(admin,'POST','/api/integrations/prometheus',headers={'Cookie':headers['Cookie']})[0]==403
            token=api('integrations/prometheus','POST')['token'];assert len(token)==64
            assert 'token' not in api('integrations/prometheus');assert token not in str(db('SELECT key,value FROM secrets'))
            save();assert traffic('/?private-token=do-not-export')[0]==200;assert traffic()[0]==200;assert traffic()[0]==200
            wait(lambda:value(scrape(token),'embergate_requests_total')>=3)
            metrics=scrape(token);assert value(metrics,'embergate_requests_total')==3
            assert f'embergate_route_requests_total{{route_id="{route["id"]}"}} 3' in metrics
            assert 'embergate_request_duration_seconds_bucket{le="+Inf"} 3' in metrics
            assert f'embergate_cache_hits_total{{route_id="{route["id"]}"}} 1' in metrics
            for private in ['private-token','metrics.test','@everyone','127.0.0.1',token]:assert private not in metrics,private
            assert value(scrape(token),'embergate_requests_total')==3,'scrapes altered traffic counters'
            reader=api('users','POST',{'username':'reader','password':'reader-monitoring-password','role':'read_only'},201)['user']
            status,h,_=smoke.request(admin,'POST','/api/login',{'username':'reader','password':'reader-monitoring-password'},{'X-Gateway-Request':'1'});assert status==200
            read_auth={'Cookie':h['set-cookie'].split(';')[0],'X-Gateway-Request':'1'}
            api('integrations/prometheus','POST',expected=403,auth=read_auth);api('alerts/destination','PUT',{'url':'http://127.0.0.1/unused','webhook_format':'discord','version':0},403,read_auth)
            assert smoke.request(admin,'GET','/api/metrics',headers=read_auth)[0]==200
            rotated=api('integrations/prometheus','POST')['token'];assert rotated!=token;assert smoke.request(admin,'GET','/metrics',headers={'Authorization':'Bearer '+token})[0]==401;token=rotated
            status=api('alerts');settings=status['settings'];url=f'http://127.0.0.1:{receiver.server_port}/discord-secret'
            api('alerts/destination','PUT',{'url':'https://discord.com.evil.test/api/webhooks/123/token','webhook_format':'discord','version':settings['version']},422)
            api('alerts/destination','PUT',{'url':url,'webhook_format':'discord','version':settings['version']})
            status=api('alerts');assert status['webhook_configured'] and status['webhook_source']=='database' and url not in json.dumps(status)
            settings=status['settings'];settings.update(webhook_enabled=True,error_rate=False,backend_failures=False,certificate_failures=False);api('alerts/settings','PUT',settings)
            api('alerts/test','POST',expected=202);wait(lambda:messages())
            path,body=messages()[-1];assert path=='/discord-secret?wait=true';assert body['allowed_mentions']=={'parse':[]};assert body['embeds'][0]['title']=='Notification test';assert 'event' not in body
            wait(lambda:api('alerts')['delivery'].get('delivered',0)>=1)
            # Trigger/recover a real error-rate alert using maintenance traffic.
            settings=api('alerts')['settings'];settings.update(error_rate=True,minimum_requests=1,error_threshold_percent=1);api('alerts/settings','PUT',settings)
            route['pages']={'maintenance':True};save();assert traffic('/maintenance')[0]==503
            wait(lambda:any(m[1]['embeds'][0]['fields'][0]['value']=='Alert opened' for m in messages()))
            settings=api('alerts')['settings'];settings['error_rate']=False;api('alerts/settings','PUT',settings)
            wait(lambda:any(m[1]['embeds'][0]['fields'][0]['value']=='Recovered' for m in messages()))
            # Retry-After is honored; replacement cancels pending sends and uses the new provider.
            receiver.response=429;api('alerts/test','POST',expected=202)
            wait(lambda:db("SELECT attempts,next_attempt FROM outbox WHERE state='pending' AND attempts=1"))
            retry=db("SELECT next_attempt FROM outbox WHERE state='pending' AND attempts=1")[0][0];assert retry>=int(time.time())+115
            settings=api('alerts')['settings'];api('alerts/destination','PUT',{'url':f'http://127.0.0.1:{receiver.server_port}/generic-new','webhook_format':'generic','version':settings['version']})
            assert not db("SELECT id FROM outbox WHERE state='pending'")
            receiver.response=200;api('alerts/test','POST',expected=202);wait(lambda:any(m[0]=='/generic-new' for m in messages()))
            assert messages()[-1][1]['event']=='test'
            # Secrets and scrape access persist; counters restart and token status remains masked.
            stop();start();metrics=scrape(token);assert value(metrics,'embergate_requests_total')==0;assert api('alerts')['webhook_configured']
            text=json.dumps(api('audit'))+json.dumps(api('config'))+json.dumps(api('alerts'))+json.dumps(api('integrations/prometheus'))
            for secret in [url,'discord-secret',token,rotated]:assert secret not in text
            api('integrations/prometheus','DELETE');assert smoke.request(admin,'GET','/metrics',headers={'Authorization':'Bearer '+token})[0]==401
            api('alerts/destination','DELETE');assert not api('alerts')['webhook_configured'];assert not api('alerts')['settings']['webhook_enabled'];api('alerts/test','POST',expected=422)
            # An explicit environment destination overrides database editing and preserves legacy defaults.
            stop();env['GATEWAY_ALERT_WEBHOOK_URL']=f'http://127.0.0.1:{receiver.server_port}/environment';start()
            assert api('alerts')['webhook_source']=='environment' and not api('alerts')['webhook_editable'];api('alerts/destination','DELETE',expected=422)
            assert Path(data_dir,'management.sqlite3').stat().st_mode&0o777==0o600
        finally:
            stop()
            for server in [origin,receiver]:server.shutdown();server.server_close()
    print('Monitoring integration passed: Prometheus format/labels/histograms/counters, token security/rotation/revocation, roles/CSRF, Discord test/open/recovery payloads, mention suppression, retry delays, queue cancellation, generic compatibility, secret redaction, environment overrides, and persistence.')
if __name__=='__main__':run()

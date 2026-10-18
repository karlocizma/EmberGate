"""Real local checks for trusted identity, access/response policies, durable analytics.
Run from gateway/: cargo build --locked && python3 tests/policy-smoke.py
"""
import http.client, importlib.util, json, os, signal, sqlite3, subprocess, tempfile, threading, time, uuid
from pathlib import Path
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
spec=importlib.util.spec_from_file_location('smoke',Path(__file__).with_name('proxy-smoke.py'))
smoke=importlib.util.module_from_spec(spec);spec.loader.exec_module(smoke)
class Backend(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.received+=1
        body=json.dumps({'ip':self.headers.get('X-Forwarded-For'),'real':self.headers.get('X-Real-IP'),'proto':self.headers.get('X-Forwarded-Proto'),'cf':self.headers.get('CF-Connecting-IP')}).encode()
        self.send_response(200);self.send_header('Content-Length',str(len(body)));self.send_header('X-App','upstream');self.end_headers();self.wfile.write(body)
    def log_message(self,*args):pass

def run():
    upstream=ThreadingHTTPServer(('127.0.0.1',0),Backend);upstream.received=0
    threading.Thread(target=upstream.serve_forever,daemon=True).start()
    proxy,admin=smoke.free_port(),smoke.free_port()
    while admin==proxy:admin=smoke.free_port()
    with tempfile.TemporaryDirectory(prefix='gateway-policy-') as directory:
        env={**os.environ,'GATEWAY_ADMIN_PASSWORD':'policy-smoke-password','GATEWAY_DATA_DIR':directory,'GATEWAY_PROXY_ADDR':f'127.0.0.1:{proxy}','GATEWAY_ADMIN_ADDR':f'127.0.0.1:{admin}'}
        for key in ['GATEWAY_ALERT_WEBHOOK_URL','GATEWAY_HTTPS_ADDR','GATEWAY_CLOUDFLARE_API_TOKEN','GATEWAY_CLOUDFLARE_API_TOKEN_FILE']:env.pop(key,None)
        binary=str(Path('target/debug/embergate').resolve());process=subprocess.Popen([binary],env=env,stdout=subprocess.DEVNULL)
        version,headers=0,{}
        route={'id':str(uuid.uuid4()),'name':'Policy','host':'policy.test','path_prefix':'/','upstream':f'http://127.0.0.1:{upstream.server_port}','enabled':True,'preserve_host':False}
        trusted=[]
        def login():
            status,response,body=smoke.request(admin,'POST','/api/login',{'password':'policy-smoke-password'},{'X-Gateway-Request':'1'})
            assert status==200,body
            headers.update({'Cookie':response['set-cookie'].split(';')[0],'X-Gateway-Request':'1'})
        def save():
            nonlocal version
            status,_,body=smoke.request(admin,'PUT','/api/config',{'version':version,'routes':[route],'trusted_proxies':trusted},headers)
            assert status==200,body
            version=json.loads(body)['version']
        def traffic(extra=None,path='/',method='GET',client='127.0.0.1'):
            connection=http.client.HTTPConnection('127.0.0.1',proxy,timeout=5,source_address=(client,0))
            connection.request(method,path,headers={'Host':'policy.test',**(extra or {})})
            response=connection.getresponse();result=response.status,{k.lower():v for k,v in response.getheaders()},response.read();connection.close();return result
        def analytics(route_id=None):
            endpoint='/api/analytics?hours=24'+(f'&route_id={route_id}' if route_id else '')
            status,_,body=smoke.request(admin,'GET',endpoint,headers=headers);assert status==200,body
            return json.loads(body)
        try:
            smoke.await_ready(process,admin);login();save()
            assert smoke.request(admin,'GET','/api/analytics?hours=24')[0]==401
            fake={'CF-Connecting-IP':'203.0.113.5','X-Forwarded-For':'198.51.100.2','X-Forwarded-Proto':'https'}
            status,_,body=traffic(fake)
            assert status==200 and json.loads(body)=={'ip':'127.0.0.1','real':'127.0.0.1','proto':'http','cf':None}
            route['response']={'redirect_https':True,'https_port':8443,'hsts_max_age':300,'hsts_include_subdomains':True,'nosniff':True,'frame_deny':True,'referrer_policy':True,'custom_headers':[{'name':'X-App','value':'EmberGate'}]}
            save();status,response,_=traffic(fake,'/path?secret=not-logged')
            assert status==308 and response['location']=='https://policy.test:8443/path?secret=not-logged'
            assert 'strict-transport-security' not in response and response['x-content-type-options']=='nosniff'
            assert traffic(fake,method='HEAD')[2]==b''
            route['access']={'mode':'allow','networks':['203.0.113.0/24']};save()
            assert traffic(fake)[0]==403,'untrusted forwarded IP bypassed access rules'
            trusted=[{'network':'127.0.0.1/32','header':'cloudflare','trust_proto':True}];save()
            status,response,body=traffic(fake)
            assert status==200 and json.loads(body)['ip']=='203.0.113.5' and json.loads(body)['proto']=='https'
            assert response['strict-transport-security']=='max-age=300; includeSubDomains'
            assert response['x-app']=='EmberGate' and response['x-frame-options']=='DENY'
            assert response['referrer-policy']=='strict-origin-when-cross-origin'
            route['rate_limit']={'requests':1,'window_seconds':3600,'burst':1};save()
            assert traffic(fake)[0]==200
            received=upstream.received
            assert traffic(fake)[0]==429 and upstream.received==received
            assert traffic({**fake,'CF-Connecting-IP':'203.0.113.6'})[0]==200,'visitors shared edge budget'
            assert traffic({**fake,'CF-Connecting-IP':'198.51.100.2'})[0]==403
            assert traffic(fake,client='127.0.0.2')[0]==403,'untrusted network impersonated Cloudflare'
            assert traffic({**fake,'CF-Connecting-IP':'203.0.113.8, 203.0.113.9'})[0]==403
            route.pop('rate_limit');trusted=[{'network':'127.0.0.0/8','header':'x_forwarded_for','trust_proto':True}];save()
            chain={'X-Forwarded-For':'198.51.100.99, 203.0.113.5, 127.0.0.2','X-Forwarded-Proto':'https'}
            status,_,body=traffic(chain)
            assert status==200 and json.loads(body)['ip']=='203.0.113.5','spoofed left side was trusted'
            assert traffic({**chain,'X-Forwarded-For':'203.0.113.5, invalid'})[0]==403
            trusted[0]['trust_proto']=False;save()
            assert traffic(chain)[0]==308,'untrusted protocol skipped redirect'
            route['response']['redirect_https']=False;route['access']={'mode':'block','networks':['203.0.113.0/24']};save()
            assert traffic(chain)[0]==403
            bad={'version':version,'routes':[route],'trusted_proxies':[{'network':'0.0.0.0/0','header':'cloudflare','trust_proto':True}]}
            assert smoke.request(admin,'PUT','/api/config',bad,headers)[0]==422
            for name,value in [('content-length','1'),('X-Bad','hello\r\nInjected: yes')]:
                badroute={**route,'response':{'custom_headers':[{'name':name,'value':value}]}}
                assert smoke.request(admin,'PUT','/api/config',{'version':version,'routes':[badroute]},headers)[0]==422
            for _ in range(100):
                value=analytics()
                if value['totals']['requests']>=15:break
                time.sleep(.02)
            assert value['totals']['access_denied']>=6 and value['totals']['rate_limited']==1,value
            assert len(value['buckets'])==24 and value['hosts'][0]['route_id']==route['id']
            assert analytics(route['id'])['totals']==value['totals']
            assert analytics(str(uuid.uuid4()))['totals']['requests']==0
            assert smoke.request(admin,'GET','/api/analytics?hours=999',headers=headers)[0]==400
            logs=json.loads(smoke.request(admin,'GET','/api/logs',headers=headers)[2])['logs']
            assert any(log['client_ip']=='203.0.113.5' and log['peer_ip']=='127.0.0.1' for log in logs)
            assert all('secret=' not in log['path'] for log in logs)
            database=Path(directory,'analytics.sqlite3');assert database.stat().st_mode&0o777==0o600
            before=analytics()['totals']['requests']
            process.send_signal(signal.SIGINT);process.wait(timeout=15)
            process=subprocess.Popen([binary],env=env,stdout=subprocess.DEVNULL)
            smoke.await_ready(process,admin);login()
            assert analytics()['totals']['requests']==before
            assert json.loads(smoke.request(admin,'GET','/api/logs',headers=headers)[2])['logs']==logs
            loaded=json.loads(smoke.request(admin,'GET','/api/config',headers=headers)[2])
            assert loaded['trusted_proxies']==trusted and loaded['routes'][0]['access']['mode']=='block'
            with sqlite3.connect(database) as db:assert db.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
            print('Policy checks passed: trust boundaries, XFF chain, spoof resistance, per-visitor limits, allow/block rules, HTTPS redirects, security/custom headers, validation, private durable analytics/logs, filtering, restart persistence.')
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGINT)
                try:process.wait(timeout=15)
                except subprocess.TimeoutExpired:process.kill();process.wait()
            upstream.shutdown();upstream.server_close()
if __name__=='__main__':run()

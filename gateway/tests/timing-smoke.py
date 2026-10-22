"""Real header readiness remains low when a backend sends its body slowly."""
import importlib.util,json,os,signal,subprocess,tempfile,threading,time,uuid
from pathlib import Path
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
spec=importlib.util.spec_from_file_location('smoke',Path(__file__).with_name('proxy-smoke.py'));smoke=importlib.util.module_from_spec(spec);spec.loader.exec_module(smoke)
class Backend(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200);self.send_header('Content-Length','2')
        self.send_header('Content-Type','text/event-stream' if self.path=='/events' else 'text/plain');self.end_headers();self.wfile.flush()
        time.sleep(.6);self.wfile.write(b'ok')
    def log_message(self,*args):pass
server=ThreadingHTTPServer(('127.0.0.1',0),Backend);threading.Thread(target=server.serve_forever,daemon=True).start()
with tempfile.TemporaryDirectory(prefix='embergate-timing-') as directory:
    admin,proxy=smoke.free_port(),smoke.free_port()
    env={k:v for k,v in os.environ.items() if not k.startswith('GATEWAY_')};env.update(GATEWAY_DATA_DIR=directory,GATEWAY_ADMIN_ADDR=f'127.0.0.1:{admin}',GATEWAY_PROXY_ADDR=f'127.0.0.1:{proxy}',GATEWAY_ADMIN_PASSWORD='timing-test-password')
    process=subprocess.Popen([str(Path('target/debug/embergate').resolve())],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        smoke.await_ready(process,admin)
        status,headers,_=smoke.request(admin,'POST','/api/login',{'password':'timing-test-password'},{'X-Gateway-Request':'1'});assert status==200
        auth={'Cookie':headers['set-cookie'].split(';')[0],'X-Gateway-Request':'1'}
        route={'id':str(uuid.uuid4()),'name':'Timing','host':'timing.test','path_prefix':'/','upstream':f'http://127.0.0.1:{server.server_port}','enabled':True,'preserve_host':True}
        assert smoke.request(admin,'PUT','/api/config',{'version':0,'routes':[route]},auth)[0]==200
        for path in ['/slow-body','/events','/Microsoft-Server-ActiveSync']:assert smoke.request(proxy,'GET',path,headers={'Host':'timing.test'})[0]==200
        deadline=time.monotonic()+5
        while True:
            logs=json.loads(smoke.request(admin,'GET','/api/logs',headers=auth)[2])['logs']
            if len(logs)==3:break
            assert time.monotonic()<deadline;time.sleep(.05)
        for entry in logs:
            assert entry['header_latency_ms'] is not None and entry['latency_ms']-entry['header_latency_ms']>=450,entry
        stats=json.loads(smoke.request(admin,'GET','/api/stats',headers=auth)[2])['timing']
        assert stats['success']['requests']==1 and stats['long_lived']['requests']==2,stats
        assert stats['success']['avg_duration_ms']-stats['success']['avg_headers_ms']>=450
        history=json.loads(smoke.request(admin,'GET','/api/analytics?hours=24',headers=auth)[2])['totals']['timing'];assert history==stats,(history,stats)
        print('Timing passed: real headers vs delayed bodies, event streams and mail push grouping, access logs, live and persisted summaries.')
    finally:
        process.send_signal(signal.SIGINT);process.wait(timeout=15);server.shutdown()

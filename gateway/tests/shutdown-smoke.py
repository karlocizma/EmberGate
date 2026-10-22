"""Real SIGTERM preserves a short request and exits within Docker's stop budget."""
import concurrent.futures,importlib.util,json,os,signal,subprocess,tempfile,threading,time,uuid
from pathlib import Path
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
spec=importlib.util.spec_from_file_location('smoke',Path(__file__).with_name('proxy-smoke.py'));smoke=importlib.util.module_from_spec(spec);spec.loader.exec_module(smoke)
started=threading.Event()
class Backend(BaseHTTPRequestHandler):
    def do_GET(self):
        started.set();time.sleep(1)
        self.send_response(200);self.send_header('Content-Length','2');self.end_headers();self.wfile.write(b'ok')
    def log_message(self,*args):pass
server=ThreadingHTTPServer(('127.0.0.1',0),Backend);threading.Thread(target=server.serve_forever,daemon=True).start()
with tempfile.TemporaryDirectory(prefix='embergate-shutdown-') as directory:
    admin,proxy=smoke.free_port(),smoke.free_port()
    env={k:v for k,v in os.environ.items() if not k.startswith('GATEWAY_')};env.update(GATEWAY_DATA_DIR=directory,GATEWAY_ADMIN_ADDR=f'127.0.0.1:{admin}',GATEWAY_PROXY_ADDR=f'127.0.0.1:{proxy}',GATEWAY_ADMIN_PASSWORD='shutdown-test-password')
    route={'id':str(uuid.uuid4()),'name':'Shutdown','host':'shutdown.test','path_prefix':'/','upstream':f'http://127.0.0.1:{server.server_port}','enabled':True,'preserve_host':True}
    Path(directory,'routes.json').write_text(json.dumps({'version':1,'routes':[route]}))
    process=subprocess.Popen([str(Path('target/debug/embergate').resolve())],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        smoke.await_ready(process,admin)
        with concurrent.futures.ThreadPoolExecutor() as pool:
            future=pool.submit(smoke.request,proxy,'GET','/',None,{'Host':'shutdown.test'})
            assert started.wait(5),'Upstream request did not start'
            beginning=time.monotonic();process.send_signal(signal.SIGTERM)
            status,_,body=future.result(timeout=10);assert status==200 and body==b'ok'
            process.wait(timeout=max(1,14-(time.monotonic()-beginning)))
            elapsed=time.monotonic()-beginning
            assert process.returncode==0,(process.returncode,elapsed)
            assert elapsed<15,elapsed
            print(f'SIGTERM passed: in-flight response completed, clean exit in {elapsed:.2f}s.')
    finally:
        if process.poll() is None:process.kill();process.wait(timeout=5)
        server.shutdown()

"""Real proxy integration: round robin, health failure/recovery, live edits and persistence.
Run from gateway/: cargo build --locked && python3 tests/pools-smoke.py
Uses local HTTP servers only; no external DNS or services.
"""
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

spec = importlib.util.spec_from_file_location('proxy_smoke', Path(__file__).with_name('proxy-smoke.py'))
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)
request, free_port, await_ready = smoke.request, smoke.free_port, smoke.await_ready

class Backend(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith('/health'):
            self.server.probes.append(self.headers.get('Host'))
            code = self.server.health
            body = b'health'
        else:
            code = 200
            body = json.dumps({'backend':self.server.server_port, 'host':self.headers.get('Host'), 'path':self.path}).encode()
        self.send_response(code)
        if code == 302:
            self.send_header('Location', '/healthy-redirect-target')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass

def run():
    backends = [ThreadingHTTPServer(('127.0.0.1',0),Backend) for _ in range(2)]
    for backend in backends:
        backend.health, backend.probes = 200, []
        threading.Thread(target=backend.serve_forever,daemon=True).start()
    proxy, admin = free_port(), free_port()
    while admin == proxy:
        admin = free_port()
    with tempfile.TemporaryDirectory(prefix='gateway-pools-') as directory:
        env = {**os.environ,'GATEWAY_ADMIN_PASSWORD':'pools-smoke-password','GATEWAY_DATA_DIR':directory,
               'GATEWAY_PROXY_ADDR':f'127.0.0.1:{proxy}','GATEWAY_ADMIN_ADDR':f'127.0.0.1:{admin}'}
        # This check does not require a client-facing TLS listener or ACME automation.
        for key in ['GATEWAY_ALERT_WEBHOOK_URL','GATEWAY_HTTPS_ADDR','GATEWAY_CLOUDFLARE_API_TOKEN','GATEWAY_CLOUDFLARE_API_TOKEN_FILE']:
            env.pop(key,None)
        binary = str(Path('target/debug/embergate').resolve())
        process = subprocess.Popen([binary],env=env,stdout=subprocess.DEVNULL)
        headers = {}
        version = 0
        route = {'id':str(uuid.uuid4()),'name':'Pool','host':'pool.test','path_prefix':'/',
                 'upstream':f'http://127.0.0.1:{backends[0].server_port}',
                 'additional_upstreams':[f'http://127.0.0.1:{backends[1].server_port}'],
                 'enabled':True,'preserve_host':False}
        def login():
            status, response, body = request(admin,'POST','/api/login',{'password':'pools-smoke-password'},{'X-Gateway-Request':'1'})
            assert status == 200, body
            headers.update({'Cookie':response['set-cookie'].split(';')[0],'X-Gateway-Request':'1'})
        def save():
            nonlocal version
            status, _, body = request(admin,'PUT','/api/config',{'version':version,'routes':[route]},headers)
            assert status == 200, body
            version = json.loads(body)['version']
        def statuses():
            return json.loads(request(admin,'GET','/api/upstreams',headers=headers)[2])['routes'][route['id']]
        def wait_states(expected):
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                current = statuses()
                if [backend['status'] for backend in current] == expected:
                    return current
                time.sleep(.1)
            raise AssertionError(f'Health states did not reach {expected}: {current}')
        def traffic():
            status, _, body = request(proxy,'GET','/hello?q=kept',headers={'Host':'pool.test'})
            assert status == 200, (status, body)
            return json.loads(body)
        try:
            await_ready(process,admin)
            assert request(admin,'GET','/api/upstreams')[0] == 401
            login(); save()
            received = [traffic() for _ in range(8)]
            assert [r['backend'] for r in received] == [backends[i % 2].server_port for i in range(8)]
            assert all(r['host'] == f"127.0.0.1:{r['backend']}" and r['path'] == '/hello?q=kept' for r in received)
            # Failed checks exclude both origins; redirects must not hide an unhealthy endpoint.
            backends[0].health, backends[1].health = 500, 302
            route['health_check'] = {'path':'/health','interval_seconds':5,'timeout_seconds':1,'failure_threshold':1,'recovery_threshold':1}
            save()
            assert request(proxy,'GET','/',headers={'Host':'pool.test'})[0] == 503
            wait_states(['unhealthy','unhealthy'])
            assert request(proxy,'GET','/',headers={'Host':'pool.test'})[0] == 503
            # Only the recovered backend receives requests.
            backends[1].health = 200
            wait_states(['unhealthy','healthy'])
            assert all(traffic()['backend'] == backends[1].server_port for _ in range(8))
            backends[0].health = 200
            wait_states(['healthy','healthy'])
            assert len({traffic()['backend'] for _ in range(4)}) == 2
            backends[0].health = 500
            wait_states(['unhealthy','healthy'])
            assert all(traffic()['backend'] == backends[1].server_port for _ in range(4))
            route['preserve_host'] = True
            backends[0].probes.clear(); backends[1].probes.clear()
            save(); wait_states(['unhealthy','healthy'])
            assert all(host == 'pool.test' for backend in backends for host in backend.probes)
            assert traffic()['host'] == 'pool.test'
            logs = json.loads(request(admin,'GET','/api/logs',headers=headers)[2])['logs']
            assert any(log.get('upstream') == route['additional_upstreams'][0] for log in logs)
            # Hot removal updates selection immediately, and the pool survives restart.
            route['upstream'] = route['additional_upstreams'].pop()
            save(); wait_states(['healthy'])
            assert traffic()['backend'] == backends[1].server_port
            process.send_signal(signal.SIGINT); process.wait(timeout=15)
            process = subprocess.Popen([binary],env=env,stdout=subprocess.DEVNULL)
            await_ready(process,admin); login(); wait_states(['healthy'])
            assert traffic()['backend'] == backends[1].server_port
            loaded = json.loads(request(admin,'GET','/api/config',headers=headers)[2])
            assert loaded['version'] == version and loaded['routes'][0]['health_check'] == route['health_check']
            print('Pool checks passed: round robin, per-origin Host, health gating, redirect rejection, 503, failure/recovery, preserved Host probes, logs, live removal, restart persistence.')
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGINT)
                try: process.wait(timeout=15)
                except subprocess.TimeoutExpired: process.kill(); process.wait()
            for backend in backends:
                backend.shutdown(); backend.server_close()

if __name__ == '__main__':
    run()

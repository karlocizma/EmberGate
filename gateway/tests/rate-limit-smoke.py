"""Real proxy check: rate policy enforcement, concurrency, refill, logs and live changes.
Run from gateway/: cargo build --locked && python3 tests/rate-limit-smoke.py
Only isolated local listeners and a temporary data directory are used.
"""
from concurrent.futures import ThreadPoolExecutor
import http.client
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
        with self.server.counter_lock:
            self.server.received += 1
        body = b'backend response'
        self.send_response(429 if self.path == '/upstream-limit' else 200)
        self.send_header('Content-Length',str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self,*args):
        pass

def run():
    backend = ThreadingHTTPServer(('127.0.0.1',0),Backend)
    backend.received, backend.counter_lock = 0, threading.Lock()
    threading.Thread(target=backend.serve_forever,daemon=True).start()
    proxy, admin = free_port(), free_port()
    while proxy == admin:
        admin = free_port()
    with tempfile.TemporaryDirectory(prefix='gateway-rate-') as directory:
        env = {**os.environ,'GATEWAY_ADMIN_PASSWORD':'rate-smoke-password','GATEWAY_DATA_DIR':directory,
               'GATEWAY_PROXY_ADDR':f'127.0.0.1:{proxy}','GATEWAY_ADMIN_ADDR':f'127.0.0.1:{admin}'}
        for key in ['GATEWAY_ALERT_WEBHOOK_URL','GATEWAY_HTTPS_ADDR','GATEWAY_CLOUDFLARE_API_TOKEN','GATEWAY_CLOUDFLARE_API_TOKEN_FILE']:
            env.pop(key,None)
        binary = str(Path('target/debug/embergate').resolve())
        process = subprocess.Popen([binary],env=env,stdout=subprocess.DEVNULL)
        version, headers = 0, {}
        route = {'id':str(uuid.uuid4()),'name':'Limited','host':'rate.test','path_prefix':'/',
                 'upstream':f'http://127.0.0.1:{backend.server_port}','enabled':True,'preserve_host':False}
        second = {**route,'id':str(uuid.uuid4()),'name':'Separate route','path_prefix':'/other'}
        routes = [route,second]
        def login():
            status,response,body = request(admin,'POST','/api/login',{'password':'rate-smoke-password'},{'X-Gateway-Request':'1'})
            assert status == 200, body
            headers.update({'Cookie':response['set-cookie'].split(';')[0],'X-Gateway-Request':'1'})
        def save():
            nonlocal version
            status,_,body = request(admin,'PUT','/api/config',{'version':version,'routes':routes},headers)
            assert status == 200, body
            version = json.loads(body)['version']
        def traffic(path='/',method='GET',extra=None,client='127.0.0.1'):
            connection = http.client.HTTPConnection('127.0.0.1',proxy,timeout=10,source_address=(client,0))
            connection.request(method,path,b'payload' if method == 'POST' else None,{'Host':'rate.test',**(extra or {})})
            response = connection.getresponse()
            result = response.status,{k.lower():v for k,v in response.getheaders()},response.read()
            connection.close()
            return result
        def stats():
            return json.loads(request(admin,'GET','/api/stats',headers=headers)[2])
        def wait_limited(count):
            for _ in range(50):
                if stats()['rate_limited'] == count:
                    return
                time.sleep(.02)
            raise AssertionError(f'Missing blocked metrics: {stats()}')
        try:
            await_ready(process,admin); login(); save()
            assert [traffic()[0] for _ in range(3)] == [200]*3
            limit = {'requests':2,'window_seconds':3600,'burst':2}
            route['rate_limit'] = limit.copy(); second['rate_limit'] = limit.copy(); save()
            before = backend.received
            assert [traffic()[0] for _ in range(2)] == [200,200]
            status,response,body = traffic()
            assert status == 429 and response['retry-after'] == '1800'
            assert response['cache-control'] == 'no-store' and b'Too many requests' in body
            assert traffic(extra={'CF-Connecting-IP':'1.2.3.4','X-Forwarded-For':'5.6.7.8','Forwarded':'for=9.9.9.9'})[0] == 429
            head = traffic(method='HEAD')
            assert head[0] == 429 and head[2] == b'' and int(head[1]['content-length']) > 0
            assert traffic(method='POST')[0] == 429
            assert backend.received == before + 2, 'blocked requests reached the upstream'
            wait_limited(4)
            assert stats()['errors'] == 0, '429 counted as server errors'
            assert traffic(client='127.0.0.2')[0] == 200, 'different client shares a budget'
            assert traffic('/other/anything')[0] == 200, 'different route shares a budget'
            route['name'] = 'Renamed'; save()
            assert traffic()[0] == 429, 'unrelated save reset the budget'
            wait_limited(5)
            # Refill uses monotonic time and advertises a usable whole-second delay.
            route['rate_limit'] = {'requests':1,'window_seconds':1,'burst':1}; save()
            assert traffic()[0] == 200
            limited = traffic()
            assert limited[0] == 429 and limited[1]['retry-after'] == '1'
            time.sleep(1.1)
            assert traffic()[0] == 200
            wait_limited(6)
            # All workers must agree on the same budget during concurrent traffic.
            route['rate_limit'] = {'requests':5,'window_seconds':3600,'burst':5}; save()
            before = backend.received
            with ThreadPoolExecutor(max_workers=12) as executor:
                codes = list(executor.map(lambda _:traffic()[0],range(24)))
            assert codes.count(200) == 5 and codes.count(429) == 19, codes
            assert backend.received == before+5
            wait_limited(25)
            logs = json.loads(request(admin,'GET','/api/logs',headers=headers)[2])['logs']
            assert any(log['status'] == 429 and log['rate_limited'] and log['upstream'] is None for log in logs)
            # Disabling is live; upstream 429 responses are not classified as gateway blocks.
            route.pop('rate_limit'); save()
            assert [traffic()[0] for _ in range(4)] == [200]*4
            assert traffic('/upstream-limit')[0] == 429
            wait_limited(25)
            # Re-enabling and restarting retain policy and reset only runtime tokens.
            route['rate_limit'] = limit.copy(); save()
            assert [traffic()[0] for _ in range(3)] == [200,200,429]
            process.send_signal(signal.SIGINT); process.wait(timeout=15)
            process = subprocess.Popen([binary],env=env,stdout=subprocess.DEVNULL)
            await_ready(process,admin); login()
            loaded = json.loads(request(admin,'GET','/api/config',headers=headers)[2])
            assert loaded['routes'][0]['rate_limit'] == limit
            assert [traffic()[0] for _ in range(3)] == [200,200,429]
            wait_limited(1)
            print('Rate checks passed: opt-in policies, burst, 429/retry headers, HEAD/POST, spoof resistance, client/route isolation, refill, concurrent budget, live edits/disable, logs/metrics, upstream 429 distinction, restart persistence.')
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGINT)
                try: process.wait(timeout=15)
                except subprocess.TimeoutExpired: process.kill(); process.wait()
            backend.shutdown(); backend.server_close()

if __name__ == '__main__':
    run()

"""Isolated loopback throughput, latency, RSS, cache, and SIGTERM-draining measurement.
Run from gateway/: python3 tests/load-check.py --seconds 30 --concurrency 8
"""
import argparse, hashlib, gzip, http.client, json, os, platform, signal, socket, subprocess, tempfile, threading, time, uuid
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
BODY=b'EmberGate reproducible loopback payload.\n'*128

def port():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
def request(port,method,path,data=None,headers=None):
    c=http.client.HTTPConnection('127.0.0.1',port,timeout=10)
    c.request(method,path,None if data is None else json.dumps(data),headers or {})
    r=c.getresponse();result=r.status,dict(r.getheaders()),r.read();c.close();return result
class Origin(BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def setup(self):
        super().setup();self.connection.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
    def do_GET(self):
        with self.server.lock:self.server.requests+=1
        self.send_response(200);self.send_header('Content-Type','text/plain');self.send_header('Cache-Control','public, max-age=120');self.send_header('Content-Length',str(len(BODY)));self.end_headers()
        if self.path=='/slow':self.server.slow.set();time.sleep(2)
        self.wfile.write(BODY)
    def log_message(self,*args):pass

def run():
    p=argparse.ArgumentParser();p.add_argument('--seconds',type=int,default=30);p.add_argument('--concurrency',type=int,default=8);p.add_argument('--binary',default='target/debug/embergate');p.add_argument('--output',type=Path,default=Path('../docs/benchmarks/local.json'));args=p.parse_args()
    assert 5<=args.seconds<=3600 and 1<=args.concurrency<=128
    origin=ThreadingHTTPServer(('127.0.0.1',0),Origin);origin.lock,origin.requests,origin.slow=threading.Lock(),0,threading.Event();threading.Thread(target=origin.serve_forever,daemon=True).start()
    proxy,admin=port(),port();samples=[];stop=threading.Event()
    report={'binary_sha256':hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),'timestamp_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'platform':platform.platform(),'logical_cpus':os.cpu_count(),'binary':Path(args.binary).name,'concurrency':args.concurrency,'seconds_per_phase':args.seconds,'payload_bytes':len(BODY),'phases':[]}
    with tempfile.TemporaryDirectory(prefix='embergate-load-') as directory:
        env={'PATH':os.environ['PATH'],'GATEWAY_ADMIN_PASSWORD':'load-fixture-password','GATEWAY_DATA_DIR':directory,'GATEWAY_PROXY_ADDR':f'127.0.0.1:{proxy}','GATEWAY_ADMIN_ADDR':f'127.0.0.1:{admin}'}
        proc=subprocess.Popen([str(Path(args.binary).resolve())],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        def memory():
            while not stop.wait(.25):
                try:samples.append(next(int(l.split()[1]) for l in Path(f'/proc/{proc.pid}/status').read_text().splitlines() if l.startswith('VmRSS:')))
                except (OSError,StopIteration):return
        threading.Thread(target=memory,daemon=True).start()
        try:
            for _ in range(150):
                try:
                    if request(admin,'GET','/api/config')[0]==401:break
                except OSError:time.sleep(.1)
            else:raise AssertionError('Gateway did not start')
            status,headers,_=request(admin,'POST','/api/login',{'password':'load-fixture-password'},{'Content-Type':'application/json','X-Gateway-Request':'1'});assert status==200
            cookie=next(v for k,v in headers.items() if k.lower()=='set-cookie').split(';')[0];auth={'Cookie':cookie,'X-Gateway-Request':'1','Content-Type':'application/json'};version=0
            for name in ['uncached','cached','cached-gzip']:
                route={'id':str(uuid.uuid4()),'name':name,'host':'load.test','path_prefix':'/','upstream':f'http://127.0.0.1:{origin.server_port}','enabled':True,'preserve_host':False}
                if name!='uncached':route['cache']={'max_ttl_seconds':120,'max_object_bytes':16384,'cache_query_strings':False}
                if name=='cached-gzip':route['compression']={'mode':'gzip','level':4,'min_bytes':256}
                status,_,body=request(admin,'PUT','/api/config',{'version':version,'routes':[route]},auth);assert status==200,body;version=json.loads(body)['version']
                begin,before=time.monotonic(),origin.requests;deadline=begin+args.seconds
                def worker(_):
                    latency=[];total=failures=hits=wire=0;c=http.client.HTTPConnection('127.0.0.1',proxy,timeout=10)
                    try:
                        while time.monotonic()<deadline:
                            started=time.perf_counter()
                            try:
                                c.request('GET','/payload',headers={'Host':'load.test','Accept-Encoding':'gzip' if name=='cached-gzip' else 'identity'});r=c.getresponse();body=r.read();wire+=len(body)
                                if r.getheader('Content-Encoding')=='gzip':body=gzip.decompress(body)
                                assert r.status==200 and body==BODY
                                hits+=r.getheader('X-EmberGate-Cache')=='HIT';total+=1
                                if len(latency)<25000:latency.append((time.perf_counter()-started)*1000)
                            except Exception:failures+=1;c.close();c=http.client.HTTPConnection('127.0.0.1',proxy,timeout=10)
                    finally:c.close()
                    return latency,total,failures,hits,wire
                with ThreadPoolExecutor(max_workers=args.concurrency) as pool:results=list(pool.map(worker,range(args.concurrency)))
                elapsed=time.monotonic()-begin;latency=sorted(v for result in results for v in result[0]);total,failures,hits,wire=(sum(r[i] for r in results) for i in range(1,5));assert total>0 and failures==0,(name,total,failures)
                if name!='uncached':assert hits>total*.9 and origin.requests-before<total*.1,(name,hits,total)
                phase={'name':name,'requests':total,'errors':failures,'elapsed_seconds':round(elapsed,3),'requests_per_second':round(total/elapsed,2),'latency_sample_count':len(latency),'latency_ms':{key:round(latency[min(len(latency)-1,int(len(latency)*q))],3) for key,q in [('p50',.5),('p95',.95),('p99',.99)]},'origin_requests':origin.requests-before,'cache_hits':hits,'response_body_wire_bytes':wire,'rss_kib_at_phase_end':samples[-1] if samples else None};report['phases'].append(phase);print(json.dumps(phase),flush=True)
            with ThreadPoolExecutor(max_workers=1) as pool:
                future=pool.submit(request,proxy,'GET','/slow',None,{'Host':'load.test'});assert origin.slow.wait(10);started=time.monotonic();proc.send_signal(signal.SIGTERM);status,_,body=future.result(timeout=15);assert status==200 and body==BODY
                print('SIGTERM preserved an in-flight response; waiting for the default shutdown grace period.',flush=True);proc.wait(timeout=340);assert proc.returncode==0;report['shutdown']={'signal':'SIGTERM','in_flight_response_preserved':True,'exit_code':proc.returncode,'elapsed_seconds':round(time.monotonic()-started,3)}
            report['rss_kib']={'initial_sample':samples[0],'peak':max(samples),'last_sample':samples[-1]};args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(report,indent=2)+'\n');print(f'Load/cache/latency/RSS/shutdown checks passed. Report: {args.output}',flush=True)
        finally:
            stop.set()
            if proc.poll() is None:proc.send_signal(signal.SIGINT);proc.wait(timeout=15)
            origin.shutdown()
if __name__=='__main__':run()

"""Real downstream gzip/Brotli, cache coordination, framing, TLS/H2 and persisted policies."""
import base64, collections, copy, gzip, http.client, importlib.util, json, os, signal, ssl, subprocess, tempfile, threading, time, uuid
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import brotli
spec=importlib.util.spec_from_file_location('smoke',Path(__file__).with_name('proxy-smoke.py'));smoke=importlib.util.module_from_spec(spec);spec.loader.exec_module(smoke)
BODY=(b'{"message":"EmberGate streaming compression fixture","values":[1,2,3,4,5]}\n')*512
GZIP=gzip.compress(BODY,mtime=0);BR=brotli.compress(BODY)
class Origin(BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def do_HEAD(self):self.serve(True)
    def do_GET(self):self.serve(False)
    def do_POST(self):self.serve(False)
    def serve(self,head):
        path=self.path.split('?')[0]
        with self.server.lock:self.server.counts[path]+=1;self.server.requests.append((path,self.headers.get_all('Accept-Encoding')))
        body=BODY;status=200;ctype='application/json; charset=utf-8';encoding=None
        if path=='/small':body=b'under threshold'
        if path=='/empty':body=b''
        if path=='/pre-gzip':body=GZIP;encoding='gzip'
        if path=='/pre-br':body=BR;encoding='br'
        if path=='/encoding-identity':encoding='identity'
        if path in ['/binary','/png','/zip','/event']:ctype={'/binary':'application/octet-stream','/png':'image/png','/zip':'application/zip','/event':'text/event-stream'}[path]
        if path=='/mixed-type':ctype='Application/Problem+Json; charset=UTF-8'
        if path=='/partial':status=206
        if path=='/not-modified' or (path=='/cache' and self.headers.get('If-None-Match') in ['\"fixture\"','W/\"fixture\"']):status=304;body=b''
        if path=='/error':status=500
        if path=='/hints':self.send_response_only(103);self.send_header('Link','</style.css>; rel=preload');self.end_headers();self.wfile.flush()
        self.send_response(status);self.send_header('Content-Type',ctype)
        self.send_header('Cache-Control',{'/no-transform':'public, max-age=60, no-transform','/private-response':'private, max-age=60','/no-store':'no-store'}.get(path,'public, max-age=60'))
        self.send_header('ETag','W/"fixture"' if path=='/weak' else 'invalid' if path=='/bad-etag' else '"fixture"')
        self.send_header('Accept-Ranges','bytes');self.send_header('Digest','sha-256=origin-fixture');self.send_header('Content-MD5','origin-fixture');self.send_header('Content-Digest','sha-256=:origin:');self.send_header('Repr-Digest','sha-256=:origin:')
        if encoding:self.send_header('Content-Encoding',encoding)
        if path=='/cookie':self.send_header('Set-Cookie','session=fixture; HttpOnly')
        if path=='/partial':self.send_header('Content-Range',f'bytes 0-{len(body)-1}/{len(body)}')
        if path=='/vary':self.send_header('Vary','Accept-Language');self.send_header('Vary','Origin')
        if path=='/vary-star':self.send_header('Vary','*')
        chunked=path in ['/stream','/slow-stream','/trailers','/trailers-br']
        if chunked:
            self.send_header('Transfer-Encoding','chunked')
            if path in ['/trailers','/trailers-br']:self.send_header('Trailer','Digest, Content-Digest, ETag, X-Trace')
        else:self.send_header('Content-Length',str(len(body)))
        self.end_headers()
        if head:return
        try:
            if chunked:
                for offset in range(0,len(body),8192):
                    part=body[offset:offset+8192];self.wfile.write(f'{len(part):x}\r\n'.encode()+part+b'\r\n');self.wfile.flush()
                    if path=='/slow-stream' and offset==0:self.server.started.set();self.server.release.wait(10)
                self.wfile.write(b'0\r\n'+(b'Digest: stale\r\nContent-Digest: stale\r\nETag: "stale"\r\nX-Trace: kept\r\n' if path in ['/trailers','/trailers-br'] else b'')+b'\r\n')
            else:self.wfile.write(body)
            self.wfile.flush()
        except (BrokenPipeError,ConnectionResetError):pass
    def log_message(self,*args):pass

def run():
    origin=ThreadingHTTPServer(('127.0.0.1',0),Origin);origin.daemon_threads=True;origin.counts=collections.Counter();origin.requests=[];origin.lock=threading.Lock();origin.started=threading.Event();origin.release=threading.Event();threading.Thread(target=origin.serve_forever,daemon=True).start()
    with tempfile.TemporaryDirectory(prefix='embergate-compression-') as directory:
        data=Path(directory);admin,proxy,tls=smoke.free_port(),smoke.free_port(),smoke.free_port();process=None;auth={}
        env={k:v for k,v in os.environ.items() if not k.startswith('GATEWAY_')};env.update(GATEWAY_ADMIN_PASSWORD='compression-admin-password',GATEWAY_DATA_DIR=directory,GATEWAY_ADMIN_ADDR=f'127.0.0.1:{admin}',GATEWAY_PROXY_ADDR=f'127.0.0.1:{proxy}',GATEWAY_HTTPS_ADDR=f'127.0.0.1:{tls}')
        def api(path,method='GET',body=None,expected=200):
            status,h,result=smoke.request(admin,method,'/api/'+path,body,auth);assert status==expected,(path,status,result[:300])
            try:return json.loads(result)
            except json.JSONDecodeError:return {'error':result.decode()}
        def start():
            nonlocal process,auth
            process=subprocess.Popen([str(Path('target/debug/embergate').resolve())],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);smoke.await_ready(process,admin)
            status,h,_=smoke.request(admin,'POST','/api/login',{'username':'admin','password':'compression-admin-password'},{'X-Gateway-Request':'1'});assert status==200;auth={'Cookie':h['set-cookie'].split(';')[0],'X-Gateway-Request':'1'}
        def stop():
            if process and process.poll() is None:process.send_signal(signal.SIGINT);process.wait(timeout=15)
        def fetch(path='/body',encoding='gzip',headers=None,method='GET',status=200):
            conn=http.client.HTTPConnection('127.0.0.1',proxy,timeout=15);conn.putrequest(method,path,skip_host=True,skip_accept_encoding=True);conn.putheader('Host','compression.test')
            if encoding is not None:
                for value in encoding if isinstance(encoding,list) else [encoding]:conn.putheader('Accept-Encoding',value)
            for k,v in (headers or {}).items():conn.putheader(k,v)
            conn.endheaders();response=conn.getresponse();actual=response.status;h=response.getheaders();body=response.read();conn.close();assert actual==status,(path,actual,h,body[:100]);return {k.lower():v for k,v in h},body,h
        def encoded(path='/body',encoding='gzip',expected='gzip',headers=None):
            h,body,all_headers=fetch(path,encoding,headers);assert h.get('content-encoding')==expected,(path,encoding,h)
            assert (gzip.decompress(body) if expected=='gzip' else brotli.decompress(body))==BODY
            assert len(body)<len(BODY) and 'content-length' not in h and h.get('etag')=='W/"fixture"'
            assert 'accept-ranges' not in h and not any(name in h for name in ['content-md5','digest','content-digest','repr-digest'])
            assert 'accept-encoding' in ','.join(v for k,v in all_headers if k.lower()=='vary').lower()
            return h,body
        try:
            start();route={'id':str(uuid.uuid4()),'name':'Compression fixture','host':'compression.test','path_prefix':'/','upstream':f'http://127.0.0.1:{origin.server_port}','enabled':True,'preserve_host':False}
            config=api('config','PUT',{'version':0,'routes':[route]});assert 'content-encoding' not in fetch()[0]
            route=config['routes'][0];route['compression']={'mode':'auto','level':4,'min_bytes':1024};config=api('config','PUT',config)
            for wrong in [{'level':0},{'level':7},{'min_bytes':255},{'min_bytes':1048577},{'mode':'zstd'},{'unknown':True}]:
                invalid=copy.deepcopy(config);invalid['routes'][0]['compression'].update(wrong);api('config','PUT',invalid,422)
            encoded();encoded(encoding='br',expected='br');encoded('/weighted','gzip;q=0.8, br;q=0.3');encoded('/weighted-br',['gzip;q=0.2','BR;q=1'],expected='br');encoded('/wildcard','*;q=1, gzip;q=0',expected='br');encoded('/mixed-type');encoded('/stream');encoded('/stream-br','br','br')
            assert next(values for path,values in origin.requests if path=='/weighted-br')==['gzip;q=0.2','BR;q=1']
            hints=subprocess.check_output(['/usr/bin/curl','--silent','--show-error','--noproxy','*','-H','Host: compression.test','-H','Accept-Encoding: gzip',f'http://127.0.0.1:{proxy}/hints']);assert gzip.decompress(hints)==BODY
            for value in [None,'','identity','gzip;q=0,br;q=0','gzip;q=0.5,identity;q=1','gzip;q=NaN','gzip;q=1.001',['gzip;q=0','gzip;q=1']]:assert 'content-encoding' not in fetch('/identity',value)[0]
            for path in ['/small','/empty','/binary','/png','/zip','/event','/no-transform','/private-response','/no-store','/cookie']:
                h,body,_=fetch(path);assert 'content-encoding' not in h,(path,h);assert h['etag']=='"fixture"'
            for headers in [{'Cookie':'session=private'},{'Authorization':'Bearer private'},{'Range':'bytes=0-99'},{'If-Range':'"fixture"'},{'Cache-Control':'no-transform'}]:assert 'content-encoding' not in fetch('/private-request',headers=headers)[0]
            h,body,_=fetch('/partial',status=206);assert 'content-encoding' not in h and h['content-range'].startswith('bytes ')
            for path,status in [('/not-modified',304),('/error',500)]:assert 'content-encoding' not in fetch(path,status=status)[0]
            h,body,_=fetch(method='HEAD');assert body==b'' and 'content-encoding' not in h and int(h['content-length'])==len(BODY)
            assert 'content-encoding' not in fetch(method='POST')[0]
            for path,encoding,original in [('/pre-gzip','gzip',GZIP),('/pre-br','br',BR),('/encoding-identity','identity',BODY)]:
                h,body,_=fetch(path);assert h['content-encoding']==encoding and body==original and h['etag']=='"fixture"'
            encoded('/vary');h,_,all_headers=fetch('/vary');assert all(name in ','.join(v for k,v in all_headers if k.lower()=='vary').lower() for name in ['accept-language','origin','accept-encoding'])
            h,_,all_headers=fetch('/vary-star');assert [v for k,v in all_headers if k.lower()=='vary']==['*']
            assert fetch('/weak')[0]['etag']=='W/"fixture"';assert 'etag' not in fetch('/bad-etag')[0]
            for value in ['identity;q=0, gzip;q=0, br;q=0','*;q=0']:
                h,body,_=fetch('/not-acceptable',value,status=406);assert body==b'' and h['content-length']=='0' and h['cache-control']=='no-store'
            # A rejected response drains cleanly before the next request on the same connection.
            conn=http.client.HTTPConnection('127.0.0.1',proxy,timeout=5);conn.request('GET','/not-acceptable',headers={'Host':'compression.test','Accept-Encoding':'*;q=0'});response=conn.getresponse();assert response.status==406 and response.read()==b''
            conn.request('GET','/body',headers={'Host':'compression.test','Accept-Encoding':'gzip'});response=conn.getresponse();assert response.status==200 and gzip.decompress(response.read())==BODY;conn.close()
            conn=http.client.HTTPConnection('127.0.0.1',proxy,timeout=5);conn._http_vsn=10;conn._http_vsn_str='HTTP/1.0';conn.request('GET','/body',headers={'Host':'compression.test','Accept-Encoding':'gzip'});response=conn.getresponse();assert response.getheader('Content-Encoding') is None and response.read()==BODY;conn.close()
            # Both codecs emit bytes before the blocked origin finishes, and close their streams.
            for codec in ['gzip','br']:
                origin.release.clear();origin.started.clear()
                conn=http.client.HTTPConnection('127.0.0.1',proxy,timeout=3);conn.request('GET','/slow-stream',headers={'Host':'compression.test','Accept-Encoding':codec});response=conn.getresponse();assert origin.started.wait(2);first=response.read(1);assert first and not origin.release.is_set();origin.release.set();compressed=first+response.read();assert (gzip.decompress(compressed) if codec=='gzip' else brotli.decompress(compressed))==BODY;conn.close()
            h,_=encoded('/trailers');assert h.get('trailer','').lower()=='x-trace'
            encoded('/trailers-br','br','br')
            for codec in ['gzip','br']:
                raw=subprocess.check_output(['/usr/bin/curl','--silent','--show-error','--raw','--noproxy','*','-H','Host: compression.test','-H','Accept-Encoding: '+codec,f'http://127.0.0.1:{proxy}/trailers']);assert b'\r\ndigest: stale' not in raw.lower() and b'\r\ncontent-digest: stale' not in raw.lower() and b'\r\netag: \"stale\"' not in raw.lower()
            # Gzip and Brotli are applied after the cache; cache headers retain original validators/digests.
            config['routes'][0]['cache']={'max_ttl_seconds':60,'max_object_bytes':1048576,'cache_query_strings':False};config=api('config','PUT',config)
            h,_=encoded('/cache');assert h['x-embergate-cache']=='MISS';count=origin.counts['/cache'];h,_=encoded('/cache');assert h['x-embergate-cache']=='HIT' and origin.counts['/cache']==count
            h,body,_=fetch('/cache',method='HEAD');assert h['x-embergate-cache']=='HIT' and 'content-encoding' not in h and h['etag']=='\"fixture\"' and int(h['content-length'])==len(BODY) and origin.counts['/cache']==count
            h,body,_=fetch('/cache',headers={'If-None-Match':'W/\"fixture\"'},status=304);assert body==b'' and 'content-encoding' not in h and h['x-embergate-cache']=='BYPASS' and 'accept-encoding' in h.get('vary','').lower() and origin.counts['/cache']==count+1
            h,body,_=fetch('/cache',None);assert 'content-encoding' not in h and h['etag']=='"fixture"' and h['digest']=='sha-256=origin-fixture' and body==BODY
            h,_=encoded('/cache','br','br');assert h['x-embergate-cache']=='MISS';h,_=encoded('/cache','br','br');assert h['x-embergate-cache']=='HIT'
            config['routes'][0]['compression']['mode']='gzip';config=api('config','PUT',config);h,body,_=fetch('/cache','br');assert 'content-encoding' not in h and body==BODY and h['x-embergate-cache']=='MISS';encoded('/gzip-fallback','br, gzip')
            # Template capture, history, restart and encrypted full restore preserve the new policy.
            template=api('host-templates','POST',{'name':'Compression','source_route_id':route['id'],'expected_config_version':config['version'],'expected_version':0});assert template['templates'][0]['policies']['compression']==config['routes'][0]['compression']
            earlier=next(r for r in api('config/history')['revisions'] if r['version']==config['version']-1);comparison=api('config/history/'+earlier['id']);assert any(c['field']=='/compression/mode' for r in comparison['comparison']['routes'] for c in r['changes'])
            stop();start();assert api('config')['routes'][0]['compression']['mode']=='gzip';encoded('/restart')
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN=compression.test','-addext','subjectAltName=DNS:compression.test','-keyout',str(data/'tls.key'),'-out',str(data/'tls.pem')],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            api('certificates','POST',{'name':'Compression TLS','certificate_pem':(data/'tls.pem').read_text(),'private_key_pem':(data/'tls.key').read_text()})
            header_file=data/'h2-headers';args=['/usr/bin/curl','--silent','--show-error','--fail','--http2','--noproxy','*','--cacert',str(data/'tls.pem'),'--resolve',f'compression.test:{tls}:127.0.0.1','-H','Accept-Encoding: gzip','-D',str(header_file),f'https://compression.test:{tls}/h2']
            for _ in range(2):assert gzip.decompress(subprocess.check_output(args))==BODY;assert 'HTTP/2 200' in header_file.read_text() and 'content-encoding: gzip' in header_file.read_text().lower() and 'transfer-encoding:' not in header_file.read_text().lower()
            current=api('config');current['routes'][0]['compression']['mode']='auto';api('config','PUT',current)
            br_args=args.copy();br_args[br_args.index('Accept-Encoding: gzip')]='Accept-Encoding: br'
            for _ in range(2):assert brotli.decompress(subprocess.check_output(br_args))==BODY;assert 'HTTP/2 200' in header_file.read_text() and 'content-encoding: br' in header_file.read_text().lower() and 'transfer-encoding:' not in header_file.read_text().lower()
            status,_,archive=smoke.request(admin,'POST','/api/backups/export',{'passphrase':'compression-backup-passphrase'},auth);assert status==200
            review=api('backups/preview','POST',{'archive':base64.b64encode(archive).decode(),'passphrase':'compression-backup-passphrase'});assert review['summary']['host_templates']==1
            current=api('config');current['routes'][0].pop('compression');api('config','PUT',current);assert 'content-encoding' not in fetch('/off')[0]
            review=api('backups/preview','POST',{'archive':base64.b64encode(archive).decode(),'passphrase':'compression-backup-passphrase'});api('backups/restore','POST',{'id':review['id'],'confirm':'RESTORE'});stop();start();encoded('/restored');assert api('host-templates')['templates'][0]['policies']['compression']['mode']=='gzip'
            print('Compression passed: streaming gzip/Brotli, weighted/wildcard/multiple-field negotiation, exclusions/406, framing/validators/digests/trailers, private/range/SSE/no-transform bypasses, no double encoding, cache hits/invalidation, H2/TLS, policy validation, templates/history, restart and encrypted restore.')
        finally:origin.release.set();stop();origin.shutdown();origin.server_close()
if __name__=='__main__':run()

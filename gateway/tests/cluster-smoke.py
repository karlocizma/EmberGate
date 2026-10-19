"""Paired gateways + real HAProxy: encrypted replication, TLS, stale gating, and failover."""
import argparse, base64, http.client, importlib.util, json, os, signal, ssl, subprocess, tempfile, threading, time, uuid
from pathlib import Path
from http.server import ThreadingHTTPServer
spec=importlib.util.spec_from_file_location('smoke',Path(__file__).with_name('proxy-smoke.py'));smoke=importlib.util.module_from_spec(spec);spec.loader.exec_module(smoke)
def wait(check,seconds=20):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        try:
            if check():return
        except (OSError,AssertionError,http.client.HTTPException):pass
        time.sleep(.2)
    raise AssertionError('Timed out waiting for replication/failover condition')
def run():
    p=argparse.ArgumentParser();p.add_argument('--engine',default='docker');args=p.parse_args()
    origin=ThreadingHTTPServer(('127.0.0.1',0),smoke.Upstream);threading.Thread(target=origin.serve_forever,daemon=True).start()
    with tempfile.TemporaryDirectory(prefix='embergate-cluster-') as directory:
        root=Path(directory);nodes=[];edge=None;edge_name='embergate-edge-'+uuid.uuid4().hex[:12]
        binary=str(Path(__file__).resolve().parents[1]/'target/debug/embergate')
        class Node:
            def __init__(self,name):
                self.name=name;self.admin,self.proxy,self.tls=smoke.free_port(),smoke.free_port(),smoke.free_port();self.data=root/name;self.data.mkdir();self.env={'PATH':os.environ['PATH'],'GATEWAY_ADMIN_PASSWORD':'cluster-fixture-password','GATEWAY_DATA_DIR':str(self.data),'GATEWAY_ADMIN_ADDR':f'127.0.0.1:{self.admin}','GATEWAY_PROXY_ADDR':f'127.0.0.1:{self.proxy}','GATEWAY_HTTPS_ADDR':f'127.0.0.1:{self.tls}'};self.proc=None;self.headers={};self.start();nodes.append(self)
            def start(self):
                self.proc=subprocess.Popen([binary],env=self.env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);smoke.await_ready(self.proc,self.admin);status,h,_=smoke.request(self.admin,'POST','/api/login',{'password':'cluster-fixture-password'},{'X-Gateway-Request':'1'});assert status==200;self.headers={'Cookie':h['set-cookie'].split(';')[0],'X-Gateway-Request':'1'}
            def stop(self):
                if self.proc and self.proc.poll() is None:self.proc.send_signal(signal.SIGINT);self.proc.wait(timeout=15)
            def api(self,path,method='GET',body=None,expected=200):
                status,_,body=smoke.request(self.admin,method,'/api/'+path,body,self.headers);assert status==expected,(self.name,path,status,body[:200]);return json.loads(body)
            def configure(self,role,**extra):
                settings=self.api('cluster')['settings'];settings.update({'role':role,**extra});return self.api('cluster','PUT',{'settings':settings,'current_password':'cluster-fixture-password','confirm_replace':True})
            def healthy(self):return smoke.request(self.admin,'GET','/healthz/ready')[0]==200
            def traffic(self):return smoke.request(self.proxy,'GET','/resource',headers={'Host':'cluster.test'})[0]
        try:
            primary,follower=Node('primary'),Node('follower')
            primary.api('users','POST',{'username':'primary-only','password':'source-fixture-password','role':'read_only'},201);follower.api('users','POST',{'username':'follower-only','password':'target-fixture-password','role':'read_only'},201)
            primary.configure('primary');shared=primary.api('cluster/token','POST',{'current_password':'cluster-fixture-password'})['token'];identity=primary.api('cluster')['instance_id']
            route={'id':str(uuid.uuid4()),'name':'Replicated host','host':'cluster.test','path_prefix':'/','upstream':f'http://127.0.0.1:{origin.server_port}','enabled':True,'preserve_host':False}
            primary.api('config','PUT',{'version':0,'routes':[route]})
            key,cert=root/'fixture.key',root/'fixture.pem';subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=cluster.test','-addext','subjectAltName=DNS:cluster.test','-keyout',str(key),'-out',str(cert)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            primary.api('certificates','POST',{'name':'Shared certificate','certificate_pem':cert.read_text(),'private_key_pem':key.read_text()})
            assert smoke.request(primary.admin,'GET','/api/cluster/snapshot')[0]==401
            status,_,encrypted=smoke.request(primary.admin,'GET','/api/cluster/snapshot',headers={'Authorization':'Bearer '+shared,'X-EmberGate-Challenge':str(uuid.uuid4())});assert status==200 and b'PRIVATE KEY' not in encrypted and b'Replicated host' not in encrypted
            settings=follower.api('cluster')['settings'];settings.update({'role':'follower','peer_url':f'http://127.0.0.1:{primary.admin}','expected_primary_id':identity,'interval_seconds':2,'stale_after_seconds':10})
            follower.api('cluster','PUT',{'settings':settings,'token':shared,'current_password':'cluster-fixture-password'},409)
            wrong={**settings,'expected_primary_id':str(uuid.uuid4())}
            follower.api('cluster','PUT',{'settings':wrong,'token':shared,'current_password':'cluster-fixture-password','confirm_replace':True})
            wait(lambda:bool(follower.api('cluster')['last_error']));assert not follower.healthy() and follower.traffic()==503
            settings['version']=follower.api('cluster')['settings']['version']
            follower.api('cluster','PUT',{'settings':settings,'token':shared,'current_password':'cluster-fixture-password','confirm_replace':True})
            wait(lambda:follower.healthy() and follower.traffic()==200)
            assert follower.api('config')==primary.api('config')
            context=ssl._create_unverified_context()
            with context.wrap_socket(__import__('socket').create_connection(('127.0.0.1',follower.tls)),server_hostname='cluster.test') as connection:assert ssl.DER_cert_to_PEM_cert(connection.getpeercert(binary_form=True)).strip()==cert.read_text().strip()
            assert [u['username'] for u in follower.api('users')['users']]==['admin','follower-only']
            follower.api('config','PUT',follower.api('config'),409)
            follower.api('credentials/cloudflare','PUT',{'token':'must-not-change'},409)
            wait(lambda:len(primary.api('cluster')['followers'])==1)
            # A changed route is applied live and keeps the primary revision.
            changed=primary.api('config');changed['routes'][0]['name']='Live update';primary.api('config','PUT',changed);wait(lambda:follower.api('config')['routes'][0]['name']=='Live update')
            # Replace the certificate on the primary and observe a new follower handshake without restarting it.
            cert_id=primary.api('certificates')['certificates'][0]['id']
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=cluster.test','-addext','subjectAltName=DNS:cluster.test','-keyout',str(key),'-out',str(cert)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            primary.api('certificates/'+cert_id,'PUT',{'name':'Renewed shared certificate','certificate_pem':cert.read_text(),'private_key_pem':key.read_text()})
            def renewed():
                with context.wrap_socket(__import__('socket').create_connection(('127.0.0.1',follower.tls)),server_hostname='cluster.test') as connection:return ssl.DER_cert_to_PEM_cert(connection.getpeercert(binary_form=True)).strip()==cert.read_text().strip()
            wait(renewed)
            status,_,blob=smoke.request(primary.admin,'POST','/api/backups/export',{'passphrase':'cluster-fixture-backup-password'},primary.headers);assert status==200 and shared.encode() not in blob
            preview=primary.api('backups/preview','POST',{'archive':base64.b64encode(blob).decode(),'passphrase':'cluster-fixture-backup-password'});assert 'cluster_token' in preview['summary']['credential_types']
            follower.stop();follower.start();wait(lambda:follower.healthy() and follower.traffic()==200)
            # HAProxy checks readiness on management ports, and falls back to an existing follower.
            edge_port=smoke.free_port();haproxy=root/'haproxy.cfg';haproxy.write_text(f'''global\n  maxconn 256\ndefaults\n  mode http\n  timeout connect 2s\n  timeout client 10s\n  timeout server 10s\nfrontend edge\n  bind 127.0.0.1:{edge_port}\n  default_backend gateways\nbackend gateways\n  option httpchk GET /healthz/ready\n  http-check expect status 200\n  server primary 127.0.0.1:{primary.proxy} check port {primary.admin} inter 200ms fall 1 rise 1\n  server follower 127.0.0.1:{follower.proxy} backup check port {follower.admin} inter 200ms fall 1 rise 1\n''')
            edge=subprocess.Popen([args.engine,'run','--rm','--name',edge_name,'--network','host','-v',f'{haproxy}:/usr/local/etc/haproxy/haproxy.cfg:ro','docker.io/library/haproxy:3.2-alpine'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            wait(lambda:smoke.request(edge_port,'GET','/via-edge',headers={'Host':'cluster.test'})[0]==200,60)
            primary.stop();wait(lambda:smoke.request(edge_port,'GET','/via-edge',headers={'Host':'cluster.test'})[0]==200,5);assert follower.healthy();primary.start();wait(lambda:follower.healthy())
            # Token rotation deliberately stops old followers; stale traffic fails closed.
            replacement=primary.api('cluster/token','POST',{'current_password':'cluster-fixture-password'})['token'];assert replacement!=shared
            wait(lambda:not follower.healthy(),16);assert follower.traffic()==503
            settings=follower.api('cluster')['settings'];follower.api('cluster','PUT',{'settings':settings,'token':replacement,'current_password':'cluster-fixture-password'});wait(lambda:follower.healthy() and follower.traffic()==200)
            audit=json.dumps(primary.api('audit'));assert shared not in audit and replacement not in audit and 'PRIVATE KEY' not in audit
            assert not (follower.data/'cluster-pending.json').exists()
            if os.name=='posix':assert (follower.data/'certificates.json').stat().st_mode & 0o777==0o600
            print('Cluster checks passed: encrypted authenticated snapshots, pinned primary identity, live routes/TLS, independent accounts, follower write restrictions, receipts/restart, real HAProxy failover, token rotation, stale fail-closed gating, private files, and audit redaction.')
        finally:
            if edge:
                subprocess.run([args.engine,'rm','--force',edge_name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20);edge.wait(timeout=15)
            for node in nodes:node.stop()
            origin.shutdown()
if __name__=='__main__':run()

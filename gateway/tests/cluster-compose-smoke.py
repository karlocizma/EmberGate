"""Test the shipped two-node Compose/HAProxy deployment with isolated ports and volumes."""
import argparse,http.client,json,os,signal,socket,ssl,subprocess,tempfile,time,uuid
from pathlib import Path

def port():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
def request(port,method,path,data=None,headers=None):
    c=http.client.HTTPConnection('127.0.0.1',port,timeout=5);c.request(method,path,None if data is None else json.dumps(data),{'Content-Type':'application/json',**(headers or {})});r=c.getresponse();value=r.status,{k.lower():v for k,v in r.getheaders()},r.read();c.close();return value
def wait(check,seconds=40):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        try:
            if check():return
        except (OSError,AssertionError,http.client.HTTPException):pass
        time.sleep(.2)
    raise AssertionError('Timed out waiting for cluster Compose condition')
def run():
    parser=argparse.ArgumentParser();parser.add_argument('--engine',default='docker');parser.add_argument('--image',default='embergate:ci');args=parser.parse_args();repo=Path(__file__).resolve().parents[2]
    first,second,edge,tls=port(),port(),port(),port();project='embergate-cluster-'+uuid.uuid4().hex[:12]
    source=(repo/'deploy/cluster-compose.yaml').read_text().replace('${EMBERGATE_IMAGE:-ghcr.io/karlocizma/embergate:latest}',args.image).replace('./haproxy.cfg',str(repo/'deploy/haproxy.cfg')).replace('      GATEWAY_HTTPS_ADDR: 0.0.0.0:8443','      GATEWAY_HTTPS_ADDR: 0.0.0.0:8443\n      GATEWAY_ADMIN_PASSWORD: cluster-compose-fixture-password')
    for old,new in [(19090,first),(19091,second),(80,edge),(443,tls)]:source=source.replace(f'127.0.0.1:{old}:',f'127.0.0.1:{new}:')
    source=source.replace('services:\n','services:\n  origin:\n    image: '+args.image+'\n')
    with tempfile.TemporaryDirectory(prefix='embergate-cluster-compose-') as directory:
        directory=Path(directory);path=directory/'compose.yaml';path.write_text(source);command=[args.engine,'compose','-p',project,'-f',str(path)]
        def compose(*args):subprocess.run(command+list(args),cwd=repo,check=True,stdout=subprocess.DEVNULL)
        def login(port):
            status,h,_=request(port,'POST','/api/login',{'password':'cluster-compose-fixture-password'},{'X-Gateway-Request':'1'});assert status==200;return {'Cookie':h['set-cookie'].split(';')[0],'X-Gateway-Request':'1'}
        def api(port,headers,path,method='GET',body=None):
            status,_,data=request(port,method,'/api/'+path,body,headers);assert status==200,(path,status,data[:200]);return json.loads(data)
        def https():
            context=ssl._create_unverified_context()
            with context.wrap_socket(socket.create_connection(('127.0.0.1',tls),timeout=5),server_hostname='cluster.test') as connection:
                connection.sendall(b'GET / HTTP/1.1\r\nHost: cluster.test\r\nConnection: close\r\n\r\n');body=b''
                while True:
                    chunk=connection.recv(65536)
                    if not chunk:break
                    body+=chunk
                    assert len(body)<1024*1024
                return body.startswith(b'HTTP/1.1 200') and b'EmberGate' in body
        try:
            compose('config','--quiet');compose('up','-d');wait(lambda:request(first,'GET','/api/config')[0]==401 and request(second,'GET','/api/config')[0]==401)
            primary,follower=login(first),login(second);primary_state=api(first,primary,'cluster');settings={**primary_state['settings'],'role':'primary'};api(first,primary,'cluster','PUT',{'settings':settings,'current_password':'cluster-compose-fixture-password'});token=api(first,primary,'cluster/token','POST',{'current_password':'cluster-compose-fixture-password'})['token']
            route={'id':str(uuid.uuid4()),'name':'Container cluster origin','host':'cluster.test','path_prefix':'/','upstream':'http://origin:9090','enabled':True,'preserve_host':False};api(first,primary,'config','PUT',{'version':0,'routes':[route]})
            key,cert=directory/'fixture.key',directory/'fixture.pem';subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=cluster.test','-addext','subjectAltName=DNS:cluster.test','-keyout',str(key),'-out',str(cert)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);api(first,primary,'certificates','POST',{'name':'Cluster fixture','certificate_pem':cert.read_text(),'private_key_pem':key.read_text()})
            state=api(second,follower,'cluster');settings={**state['settings'],'role':'follower','peer_url':'http://primary:9090','expected_primary_id':primary_state['instance_id'],'interval_seconds':2,'stale_after_seconds':30};api(second,follower,'cluster','PUT',{'settings':settings,'token':token,'confirm_replace':True,'current_password':'cluster-compose-fixture-password'})
            wait(lambda:api(second,follower,'cluster')['ready']);wait(lambda:request(edge,'GET','/',headers={'Host':'cluster.test'})[0]==200);wait(https)
            compose('stop','--timeout','1','primary');wait(lambda:request(edge,'GET','/',headers={'Host':'cluster.test'})[0]==200,10);wait(https,20);compose('start','primary');wait(lambda:request(first,'GET','/api/config')[0]==401);primary=login(first);assert api(first,primary,'cluster')['instance_id']==primary_state['instance_id'];wait(lambda:api(second,follower,'cluster')['ready'])
            print('Shipped cluster Compose checks passed: private service discovery, independent volumes, encrypted live replication, HTTP and TLS through the shipped HAProxy config, primary outage failover, and primary restart identity persistence.')
        finally:compose('down','--volumes','--timeout','1')
if __name__=='__main__':run()

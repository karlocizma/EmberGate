"""CrowdSec remediation and log shipping: ban page, captcha challenges with a local Turnstile stand-in, unknown types, access log, backups."""
import base64, http.client, http.server, importlib.util, json, os, signal, subprocess, tempfile, threading, time, urllib.parse, uuid
from pathlib import Path
spec=importlib.util.spec_from_file_location('smoke',Path(__file__).with_name('proxy-smoke.py'));smoke=importlib.util.module_from_spec(spec);spec.loader.exec_module(smoke)
STREAM={'startup':{'new':None,'deleted':None},'next':[]}
VERIFIED=[]
class Lapi(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        assert self.headers['X-Api-Key']=='bouncer-key'
        startup='startup=true' in self.path
        body=json.dumps(STREAM['startup'] if startup else (STREAM['next'].pop(0) if STREAM['next'] else {'new':None,'deleted':None})).encode()
        self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    def do_POST(self):
        form=urllib.parse.parse_qs(self.rfile.read(int(self.headers['Content-Length'])).decode());VERIFIED.append(form)
        body=json.dumps({'success':form.get('response')==['good-token'] and form.get('secret')==['0x4AAAAAAA-secret']}).encode()
        self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    def log_message(self,*a):pass
class Origin(http.server.BaseHTTPRequestHandler):
    def do_GET(self):self.send_response(200);self.send_header('Content-Length','6');self.end_headers();self.wfile.write(b'origin')
    def log_message(self,*a):pass
def serve(handler):
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),handler);threading.Thread(target=server.serve_forever,daemon=True).start();return server
def run():
    lapi,origin=serve(Lapi),serve(Origin)
    with tempfile.TemporaryDirectory(prefix='embergate-crowdsec-') as directory:
        data=Path(directory);admin,proxy=smoke.free_port(),smoke.free_port();owner={}
        env={k:v for k,v in os.environ.items() if not k.startswith('GATEWAY_')};env.update(GATEWAY_ADMIN_PASSWORD='crowdsec-admin-password',GATEWAY_DATA_DIR=directory,GATEWAY_ADMIN_ADDR=f'127.0.0.1:{admin}',GATEWAY_PROXY_ADDR=f'127.0.0.1:{proxy}',GATEWAY_TURNSTILE_VERIFY_URL=f'http://127.0.0.1:{lapi.server_address[1]}/siteverify')
        def call(path,method='GET',body=None,auth=None,expected=200):
            status,_,result=smoke.request(admin,method,'/api/'+path,body,owner if auth is None else auth);assert status==expected,(path,status,result[:400])
            return json.loads(result) if result else None
        def visit(ip,path='/',method='GET',body=None,headers=None):
            conn=http.client.HTTPConnection('127.0.0.1',proxy,timeout=10)
            conn.request(method,path,body,{'X-Forwarded-For':ip,'Accept':'text/html',**(headers or {})});response=conn.getresponse()
            result=response.status,{k.lower():v for k,v in response.getheaders()},response.read().decode(errors='replace');conn.close();return result
        def wait(condition,what):
            for _ in range(80):
                if condition():return
                time.sleep(0.25)
            raise AssertionError(what)
        process=subprocess.Popen([str(Path('target/debug/embergate').resolve())],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            smoke.await_ready(process,admin)
            assert (data/'access-log/access.log').exists(),'the log file exists before CrowdSec starts'
            status,h,_=smoke.request(admin,'POST','/api/login',{'username':'admin','password':'crowdsec-admin-password'},{'X-Gateway-Request':'1'});owner.update({'Cookie':h['set-cookie'].split(';')[0],'X-Gateway-Request':'1'})
            route={'id':str(uuid.uuid4()),'name':'Site','host':'*','path_prefix':'/','upstream':f'http://127.0.0.1:{origin.server_address[1]}','enabled':True,'preserve_host':False}
            call('config','PUT',{'version':0,'routes':[route],'trusted_proxies':[{'network':'127.0.0.1/32','header':'x_forwarded_for'}]})
            # Log shipping writes nginx combined lines with the trusted visitor address.
            assert call('integrations/access-log','PUT',{'enabled':True})['enabled']
            visit('198.51.100.20','/page?secret=1',headers={'User-Agent':'smoke "agent"','Referer':'https://ref.test/x?token=2'})
            log=data/'access-log/access.log'
            wait(lambda:'198.51.100.20' in log.read_text(),'access log line')
            line=log.read_text().splitlines()[-1]
            assert line.startswith('198.51.100.20 - - [') and '"GET /page HTTP/1.1" 200 6 "https://ref.test/x" "smoke \\x22agent\\x22"' in line,line
            assert 'secret' not in log.read_text() and 'token=2' not in log.read_text()
            assert call('credentials')['access_log']['enabled']
            # Ban decisions show the configured message; captcha without a provider is a ban.
            STREAM['startup']={'new':[{'scope':'Ip','value':'203.0.113.1','type':'ban'},{'scope':'Ip','value':'203.0.113.2','type':'captcha'},{'scope':'Ip','value':'203.0.113.3','type':'throttle'}],'deleted':None}
            call('integrations/crowdsec','PUT',{'url':f'http://127.0.0.1:{lapi.server_address[1]}','api_key':'bouncer-key'})
            wait(lambda:call('integrations/crowdsec')['decisions']==2,'decisions synced')
            cs=call('integrations/crowdsec');assert (cs['bans'],cs['captchas'],cs['unknown_types'])==(1,1,{'throttle':1}),cs
            assert visit('203.0.113.3')[0]==200,'unknown decision types are not enforced'
            call('integrations/crowdsec/remediation','PUT',{'ban_message':'Blocked <by> the lab.','provider':'none','site_key':''})
            for ip in ['203.0.113.1','203.0.113.2']:
                status,_,body=visit(ip);assert status==403 and 'Blocked &lt;by&gt; the lab.' in body,(ip,status,body[:300])
            # With Turnstile configured, captcha visitors get a challenge and a pass cookie.
            call('integrations/crowdsec/remediation','PUT',{'ban_message':'Blocked.','provider':'turnstile','site_key':'0x4AAAAAAA-site'},expected=422)
            saved=call('integrations/crowdsec/remediation','PUT',{'ban_message':'Blocked.','provider':'turnstile','site_key':'0x4AAAAAAA-site','secret_key':'0x4AAAAAAA-secret'})
            assert saved['challenges'] and saved['secret_configured'] and 'secret' not in json.dumps(saved['settings'])
            assert '0x4AAAAAAA-secret' not in json.dumps(call('integrations/crowdsec/remediation'))
            status,h,body=visit('203.0.113.2','/photos?id=7')
            assert status==403 and 'data-sitekey="0x4AAAAAAA-site"' in body and 'value="/photos?id=7"' in body,(status,body[:300])
            assert "script-src https://challenges.cloudflare.com" in h['content-security-policy'] and h['cache-control']=='no-store'
            assert visit('203.0.113.1')[1].get('content-security-policy','').startswith('default-src'),'bans keep the plain page'
            form=lambda token,rd:urllib.parse.urlencode({'cf-turnstile-response':token,'rd':rd})
            status,_,body=visit('203.0.113.2','/.well-known/embergate/captcha','POST',form('bad-token','/photos'),{'Content-Type':'application/x-www-form-urlencoded'})
            assert status==403 and 'did not succeed' in body
            status,h,_=visit('203.0.113.2','/.well-known/embergate/captcha','POST',form('good-token','https://evil.test/'),{'Content-Type':'application/x-www-form-urlencoded'})
            assert status==303 and h['location']=='/' and VERIFIED[-1]['remoteip']==['203.0.113.2'],(status,h)
            status,h,_=visit('203.0.113.2','/.well-known/embergate/captcha','POST',form('good-token','/photos?id=7'),{'Content-Type':'application/x-www-form-urlencoded'})
            assert status==303 and h['location']=='/photos?id=7' and 'HttpOnly' in h['set-cookie'] and 'SameSite=Lax' in h['set-cookie']
            cookie=h['set-cookie'].split(';')[0]
            assert visit('203.0.113.2','/photos',headers={'Cookie':cookie})[2]=='origin','a solved challenge lets the visitor through'
            assert visit('203.0.113.9','/photos',headers={'Cookie':cookie})[0]==200,'other visitors are unaffected'
            STREAM['next'].append({'new':[{'scope':'Ip','value':'203.0.113.9','type':'captcha'}],'deleted':None})
            wait(lambda:call('integrations/crowdsec')['captchas']==2,'second captcha')
            assert visit('203.0.113.9','/photos',headers={'Cookie':cookie})[0]==403,'pass cookies are bound to the address'
            assert visit('203.0.113.1','/',headers={'Cookie':cookie})[0]==403,'pass cookies never lift bans'
            # Read-only accounts can see but not change remediation; backups carry CrowdSec settings.
            call('users','POST',{'username':'reader','password':'crowdsec-reader-password','role':'read_only'},expected=201)
            status,h,_=smoke.request(admin,'POST','/api/login',{'username':'reader','password':'crowdsec-reader-password'},{'X-Gateway-Request':'1'});reader={'Cookie':h['set-cookie'].split(';')[0],'X-Gateway-Request':'1'}
            call('integrations/crowdsec/remediation',auth=reader)
            call('integrations/crowdsec/remediation','PUT',{'ban_message':'x','provider':'none','site_key':''},reader,403)
            call('integrations/access-log','PUT',{'enabled':False},reader,403)
            status,_,blob=smoke.request(admin,'POST','/api/backups/export',{'passphrase':'crowdsec-backup-passphrase'},owner);assert status==200
            review=call('backups/preview','POST',{'archive':base64.b64encode(blob).decode(),'passphrase':'crowdsec-backup-passphrase'})
            assert {'crowdsec_url','crowdsec_bouncer_key','crowdsec_remediation','crowdsec_captcha_secret','access_log_enabled'}<=set(review['summary']['credential_types']),review['summary']['credential_types']
            print('CrowdSec checks passed: access log format/privacy, typed decisions, ban page, captcha challenge/verification/pass cookies, unknown types, roles, and backups.')
        finally:
            if process.poll() is None:process.send_signal(signal.SIGINT);process.wait(timeout=15)
            lapi.shutdown();origin.shutdown()
if __name__=='__main__':run()

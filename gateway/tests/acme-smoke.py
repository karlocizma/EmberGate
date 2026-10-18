"""Real ACME DNS-01 test against Pebble with an isolated Cloudflare/DNS fixture.

Set PEBBLE_BIN to the official Pebble executable, then run after cargo build.
No public CA, public DNS, or real Cloudflare account is used.
"""
import http.client
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import stat
import struct
import subprocess
import tempfile
import threading
import time
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

spec = importlib.util.spec_from_file_location("proxy_smoke", Path(__file__).with_name("proxy-smoke.py"))
helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)


class DNSFixture:
    def __init__(self):
        self.records = [{"id":"foreign", "type":"TXT", "name":"_acme-challenge.example.test", "content":"unrelated-record", "comment":"another ACME client"}]
        self.fail_create = False
        self.created = 0
        self.deleted = []
        self.lock = threading.Lock()
        fixture = self

        class API(BaseHTTPRequestHandler):
            def do_GET(self):
                path = urllib.parse.urlsplit(self.path)
                params = urllib.parse.parse_qs(path.query)
                name = params.get("name", [""])[0]
                with fixture.lock:
                    if path.path == "/zones":
                        result = [{"id":"test-zone", "name":name}] if name == "example.test" else []
                    elif path.path.endswith("/dns_records"):
                        result = [record for record in fixture.records if record["name"] == name and record["type"] == params.get("type", [""])[0]]
                    elif path.path == "/dns-query":
                        return self.send_json({"Status":0,"Answer":[{"type":16,"data":json.dumps(record["content"])} for record in fixture.records if record["name"] == name]})
                    else:
                        return self.send_json({"success":False}, 404)
                assert self.headers.get("Authorization") == "Bearer test-token-not-a-secret"
                self.send_json({"success":True,"result":result})

            def do_POST(self):
                assert self.headers.get("Authorization") == "Bearer test-token-not-a-secret"
                data = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                with fixture.lock:
                    if fixture.fail_create:
                        return self.send_json({"success":False,"errors":[{"code":9109}]}, 403)
                    assert data["name"].startswith("_acme-challenge.")
                    data["id"] = str(uuid.uuid4())
                    fixture.records.append(data)
                    fixture.created += 1
                self.send_json({"success":True,"result":data})

            def do_DELETE(self):
                record_id = self.path.rsplit("/",1)[-1]
                with fixture.lock:
                    assert record_id != "foreign", "Unrelated DNS record was deleted"
                    fixture.records = [record for record in fixture.records if record["id"] != record_id]
                    fixture.deleted.append(record_id)
                self.send_json({"success":True,"result":{"id":record_id}})

            def send_json(self, payload, status=200):
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type","application/json")
                self.send_header("Content-Length",str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        self.http = ThreadingHTTPServer(("127.0.0.1",0), API)
        threading.Thread(target=self.http.serve_forever,daemon=True).start()
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1",0))
        self.dns_port = self.udp.getsockname()[1]
        self.udp.settimeout(0.25)
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.bind(("127.0.0.1",self.dns_port))
        self.tcp.listen(16)
        self.tcp.settimeout(0.25)
        self.running = True
        threading.Thread(target=self.serve_dns,daemon=True).start()
        threading.Thread(target=self.serve_tcp_dns,daemon=True).start()

    def answer(self, query):
        index = 12
        labels = []
        while query[index]:
            length = query[index]
            labels.append(query[index+1:index+1+length].decode())
            index += length+1
        index += 1
        kind, _ = struct.unpack("!HH",query[index:index+4])
        name = ".".join(labels).lower()
        with self.lock:
            values = [record["content"].encode() for record in self.records if record["name"] == name] if kind == 16 else []
        question = query[12:index+4]
        answers = b""
        for value in values:
            content = bytes([len(value)])+value
            answers += b"\xc0\x0c"+struct.pack("!HHIH",16,1,30,len(content))+content
        return query[:2]+struct.pack("!HHHHH",0x8180,1,len(values),0,0)+question+answers

    def serve_tcp_dns(self):
        while self.running:
            try:
                connection, _ = self.tcp.accept()
                with connection:
                    connection.settimeout(2)
                    def read_n(length):
                        result = b""
                        while len(result) < length:
                            chunk = connection.recv(length-len(result))
                            if not chunk: raise OSError("DNS connection closed")
                            result += chunk
                        return result
                    length = struct.unpack("!H",read_n(2))[0]
                    response = self.answer(read_n(length))
                    connection.sendall(struct.pack("!H",len(response))+response)
            except (OSError, socket.timeout):
                pass

    def serve_dns(self):
        while self.running:
            try:
                query, address = self.udp.recvfrom(4096)
                self.udp.sendto(self.answer(query),address)
            except socket.timeout:
                pass
            except OSError:
                break

    def close(self):
        self.running = False
        self.http.shutdown()
        self.udp.close()
        self.tcp.close()


def run():
    pebble = os.environ.get("PEBBLE_BIN")
    if not pebble or not Path(pebble).is_file():
        raise SystemExit("Set PEBBLE_BIN to the official Pebble ACME test server executable.")
    binary = Path("target/debug/embergate").resolve()
    with tempfile.TemporaryDirectory(prefix="embergate-acme-") as temporary:
        directory = Path(temporary)
        fixture = DNSFixture()
        upstream = ThreadingHTTPServer(("127.0.0.1",0),helpers.Upstream)
        threading.Thread(target=upstream.serve_forever,daemon=True).start()
        ports = set()
        while len(ports) < 5:
            ports.add(helpers.free_port())
        ca_port, management_port, admin_port, proxy_port, https_port = ports
        def openssl(*args):
            subprocess.run(["openssl",*args],cwd=directory,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        openssl("req","-x509","-newkey","rsa:2048","-nodes","-days","2","-keyout","transport-root.key","-out","transport-root.pem","-subj","/CN=ACME transport root","-addext","basicConstraints=critical,CA:TRUE","-addext","keyUsage=critical,keyCertSign,cRLSign")
        openssl("req","-new","-newkey","rsa:2048","-nodes","-keyout","transport.key","-out","transport.csr","-subj","/CN=localhost")
        (directory/"transport.ext").write_text("basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature,keyEncipherment\nauthorityKeyIdentifier=keyid,issuer\n")
        openssl("x509","-req","-in","transport.csr","-CA","transport-root.pem","-CAkey","transport-root.key","-set_serial","2","-days","2","-extfile","transport.ext","-out","transport.pem")
        config = {"pebble":{"listenAddress":f"127.0.0.1:{ca_port}","managementListenAddress":f"127.0.0.1:{management_port}","certificate":str(directory/"transport.pem"),"privateKey":str(directory/"transport.key"),"httpPort":5002,"tlsPort":5001,"retryAfter":{"authz":1,"order":1},"profiles":{"default":{"description":"test","validityPeriod":7776000}}}}
        (directory/"pebble.json").write_text(json.dumps(config))
        ca_log = open(directory/"pebble.log","w+")
        app_log = open(directory/"gateway.log","w+")
        ca = subprocess.Popen([str(Path(pebble).resolve()),"-config",str(directory/"pebble.json"),"-dnsserver",f"127.0.0.1:{fixture.dns_port}"],env={**os.environ,"PEBBLE_VA_NOSLEEP":"1","PEBBLE_AUTHZREUSE":"0","PEBBLE_WFE_NONCEREJECT":"0"},stdout=ca_log,stderr=ca_log)
        env = {**os.environ,"GATEWAY_ADMIN_PASSWORD":"test-acme-password-123","GATEWAY_DATA_DIR":str(directory/"data"),"GATEWAY_ADMIN_ADDR":f"127.0.0.1:{admin_port}","GATEWAY_PROXY_ADDR":f"127.0.0.1:{proxy_port}","GATEWAY_HTTPS_ADDR":f"127.0.0.1:{https_port}","GATEWAY_CLOUDFLARE_API_TOKEN":"test-token-not-a-secret","GATEWAY_CLOUDFLARE_API_BASE":f"http://127.0.0.1:{fixture.http.server_port}","GATEWAY_DNS_CHECK_URL":f"http://127.0.0.1:{fixture.http.server_port}/dns-query","GATEWAY_ACME_DIRECTORY":f"https://127.0.0.1:{ca_port}/dir","GATEWAY_ACME_CA_ROOT":str(directory/"transport-root.pem"),"GATEWAY_DNS_PROPAGATION_TIMEOUT":"5","RUST_LOG":"info"}
        app = None
        env.pop("GATEWAY_ALERT_WEBHOOK_URL",None)
        env.pop("GATEWAY_CLOUDFLARE_API_TOKEN_FILE",None)
        try:
            for _ in range(60):
                try:
                    connection = http.client.HTTPSConnection("127.0.0.1",ca_port,context=ssl._create_unverified_context(),timeout=1)
                    connection.request("GET","/dir"); connection.getresponse().read(); connection.close(); break
                except OSError:
                    if ca.poll() is not None:
                        raise AssertionError("Pebble exited during startup")
                    time.sleep(.1)
            app = subprocess.Popen([str(binary)],env=env,stdout=app_log,stderr=app_log)
            helpers.await_ready(app,admin_port)

            def login():
                status, headers, _ = helpers.request(admin_port,"POST","/api/login",{"password":"test-acme-password-123"},{"X-Gateway-Request":"1"})
                assert status == 200
                return {"Cookie":headers["set-cookie"].split(";")[0],"X-Gateway-Request":"1"}

            headers = login()
            route = {"id":str(uuid.uuid4()),"name":"ACME test","host":"example.test","path_prefix":"/","upstream":f"http://127.0.0.1:{upstream.server_port}","enabled":True,"preserve_host":False}
            assert helpers.request(admin_port,"PUT","/api/config",{"version":0,"routes":[route]},headers)[0] == 200
            requested = {"name":"Managed test","domains":["example.test","*.example.test"],"email":"admin@example.test","environment":"staging","auto_renew":True,"agree_to_terms":True}
            assert helpers.request(admin_port,"POST","/api/acme/orders",{**requested,"agree_to_terms":False},headers)[0] == 422
            status, _, body = helpers.request(admin_port,"POST","/api/acme/orders",requested,headers)
            assert status == 202, body
            order_id = json.loads(body)["id"]

            def wait_for_status(expected, fingerprint=None):
                for _ in range(300):
                    status, _, body = helpers.request(admin_port,"GET","/api/acme",headers=headers)
                    assert status == 200
                    assert b"test-token-not-a-secret" not in body and b"PRIVATE KEY" not in body
                    job = json.loads(body)["orders"][0]
                    if expected != "error" and job["status"] == "error":
                        raise AssertionError(job)
                    if job["status"] == expected:
                        if fingerprint:
                            certs = json.loads(helpers.request(admin_port,"GET","/api/certificates",headers=headers)[2])["certificates"]
                            if not certs or certs[0]["fingerprint"] == fingerprint:
                                time.sleep(.2); continue
                        return job
                    time.sleep(.2)
                raise AssertionError(f"ACME did not reach {expected}")

            job = wait_for_status("ready")
            assert job["renew_at"] > time.time()+86400 and not job["cleanup_pending"]
            assert fixture.created == 2 and len(fixture.records) == 1 and fixture.records[0]["id"] == "foreign"
            certificates = json.loads(helpers.request(admin_port,"GET","/api/certificates",headers=headers)[2])["certificates"]
            original = certificates[0]["fingerprint"]
            assert certificates[0]["id"] == order_id
            assert helpers.request(admin_port,"DELETE",f"/api/certificates/{order_id}",headers=headers)[0] == 409
            issued = json.loads((directory/"data"/"certificates.json").read_text())[0]
            assert helpers.request(admin_port,"POST","/api/certificates",{key:issued[key] for key in ["name","certificate_pem","private_key_pem"]},headers)[0] == 409
            assert helpers.request(admin_port,"POST",f"/api/acme/orders/{order_id}/production",{"agree_to_terms":False},headers)[0] == 409
            assert helpers.request(admin_port,"POST",f"/api/acme/orders/{order_id}/production",{"agree_to_terms":True},headers)[0] == 202
            promoted = wait_for_status("ready",original)
            assert promoted["environment"] == "production"
            original = json.loads(helpers.request(admin_port,"GET","/api/certificates",headers=headers)[2])["certificates"][0]["fingerprint"]
            for file in (directory/"data").glob("acme*.json"):
                assert stat.S_IMODE(file.stat().st_mode) == 0o600

            # Retrieve Pebble's issuer root and verify the installed certificate over TLS.
            connection = http.client.HTTPSConnection("127.0.0.1",management_port,context=ssl._create_unverified_context())
            connection.request("GET","/roots/0"); root = connection.getresponse().read(); connection.close()
            (directory/"issuer.pem").write_bytes(root)
            context = ssl.create_default_context(cafile=str(directory/"issuer.pem"))
            connection = http.client.HTTPSConnection("example.test",https_port,context=context,timeout=5)
            connection._create_connection = lambda address,timeout,source_address: socket.create_connection(("127.0.0.1",https_port),timeout)
            connection.request("GET","/",headers={"Host":"example.test"})
            assert connection.getresponse().status == 200
            connection.close()

            # Simulate a restart with a due renewal and an interrupted DNS cleanup.
            app.send_signal(signal.SIGINT); app.wait(timeout=15)
            state_file = directory/"data"/"acme.json"
            jobs = json.loads(state_file.read_text())
            orphan = {"zone":"test-zone","name":"_acme-challenge.example.test","value":"orphaned-value","comment":f"Current ACME {order_id}"}
            jobs[0]["pending_dns"] = [orphan]
            jobs[0]["next_attempt"] = int(time.time())-1
            jobs[0]["renew_at"] = int(time.time())-1
            state_file.write_text(json.dumps(jobs))
            with fixture.lock:
                fixture.records.append({"id":"orphan","type":"TXT","name":orphan["name"],"content":orphan["value"],"comment":orphan["comment"]})
            app = subprocess.Popen([str(binary)],env=env,stdout=app_log,stderr=app_log)
            helpers.await_ready(app,admin_port); headers = login()
            wait_for_status("ready", original)
            assert "orphan" in fixture.deleted and len(fixture.records) == 1
            assert len(list((directory/"data").glob("acme-account-*.json"))) == 1
            current = json.loads(helpers.request(admin_port,"GET","/api/certificates",headers=headers)[2])["certificates"][0]["fingerprint"]

            # A DNS failure keeps the active certificate and schedules backoff.
            fixture.fail_create = True
            assert helpers.request(admin_port,"POST",f"/api/acme/orders/{order_id}/renew",headers=headers)[0] == 202
            failed = wait_for_status("error")
            assert failed["next_attempt"] >= int(time.time())+3500
            assert not failed["cleanup_pending"] and len(fixture.records) == 1
            assert json.loads(helpers.request(admin_port,"GET","/api/certificates",headers=headers)[2])["certificates"][0]["fingerprint"] == current
            assert helpers.request(admin_port,"DELETE",f"/api/acme/orders/{order_id}",headers=headers)[0] == 200
            assert helpers.request(admin_port,"DELETE",f"/api/certificates/{order_id}",headers=headers)[0] == 200
            print("ACME checks passed: real DNS-01 issuance, apex + wildcard TXT coexistence, TLS activation, scheduled renewal, account reuse, restart cleanup, failure backoff, credential redaction, managed-certificate controls.")
        except Exception:
            ca_log.flush(); app_log.flush()
            print("ACME test failed. Gateway log:")
            print((directory/"gateway.log").read_text()[-7000:])
            print("Pebble log:")
            print((directory/"pebble.log").read_text()[-4000:])
            raise
        finally:
            if app and app.poll() is None:
                app.send_signal(signal.SIGINT)
                try: app.wait(timeout=15)
                except subprocess.TimeoutExpired: app.kill(); app.wait()
            ca.terminate()
            try: ca.wait(timeout=5)
            except subprocess.TimeoutExpired: ca.kill(); ca.wait()
            fixture.close(); upstream.shutdown(); ca_log.close(); app_log.close()


if __name__ == "__main__":
    run()
